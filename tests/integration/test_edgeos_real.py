"""The edgeos adapter against the real VyOS (rolling ISO in QEMU, #432).

tools/integration/edgeos/vm.py boots the official live ISO, creates the key-only read user
``signalbox`` (level operator where the version has levels) and a small lab: eth1 LAN
192.0.2.1/24 with a DHCP server and DNS forwarding, VLAN 20 on eth2 (203.0.113.1/24), LLDP,
source NAT. Only reads; the router has no neighbours, leases or tunnels.

    IT_EDGEOS_URL        ssh://127.0.0.1:<port>
    IT_EDGEOS_USER       the read user, IT_EDGEOS_KEY_FILE its private key
    IT_EDGEOS_HOST_KEY   SHA-256 of the ed25519 host key (hex), IT_EDGEOS_HOSTNAME its name
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from signalbox.adapters import AdapterContext
from signalbox.adapters.edgeos import EdgeosAdapter, EdgeosConfig
from signalbox.model import DeviceRole, DeviceStatus, Snapshot
from signalbox.testing import problems

from .conftest import Target

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def vy(target: Callable[[str], Target]) -> Target:
    t = target("edgeos")
    for key in ("KEY_FILE", "HOST_KEY", "HOSTNAME"):
        assert t.extra.get(key), f"IT_EDGEOS_{key}"
    return t


def context(t: Target, **cfg: Any) -> AdapterContext:
    settings: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": t.port,
        "username": t.username,
        "private_key": Path(t.extra["KEY_FILE"]).read_text(),
    } | cfg
    return AdapterContext(
        site_id="it",
        device_id="vy1",
        device_name="vy1",
        role=DeviceRole.GATEWAY,
        config=EdgeosConfig(**settings),
        pinned_fingerprint=t.extra["HOST_KEY"],
        timeout=30,
    )


async def observe(ctx: AdapterContext, contract: bool = True) -> Snapshot:
    """Observe once; with ``contract`` the adapter contract must hold except for the one known
    gap: the rule-sets of VyOS 1.4 and newer (firewall ipv4/ipv6) are not read, so the
    status is partial and the gap says so."""
    adapter = EdgeosAdapter(ctx)
    try:
        snap = await adapter.observe()
        if contract:
            found = [p for p in problems(adapter, snap) if "firewall" not in p]
            found = [p for p in found if not p.startswith("status partial")]
            assert not found, found
            assert {e.capability for e in snap.errors} <= {"firewall"}, snap.errors
        return snap
    finally:
        await adapter.close()


async def test_untrusted_first(vy: Target) -> None:
    snap = await observe(dataclasses.replace(context(vy), pinned_fingerprint=None), False)
    assert snap.status is DeviceStatus.UNTRUSTED


async def test_system_and_ports(vy: Target) -> None:
    snap = await observe(context(vy))
    d = snap.device
    assert d.vendor == "VyOS" and d.os == "VyOS" and d.hostname == vy.extra["HOSTNAME"]
    assert d.firmware is not None and "VyOS" in (d.firmware.current or ""), d.firmware
    assert d.transport_encrypted is True
    ports = {p.name: p for p in snap.ports}
    assert {"eth0", "eth1", "eth2", "eth2.20"} <= set(ports), sorted(ports)
    assert "lo" not in ports
    assert ports["eth1"].description == "LAN"
    assert {str(s.interface) for s in snap.subnets} >= {"192.0.2.1/24", "203.0.113.1/24"}


async def test_dhcp_and_dns(vy: Target) -> None:
    snap = await observe(context(vy), False)
    (server,) = snap.dhcp_servers
    assert [(str(p.start), str(p.end)) for p in server.pools] == [("192.0.2.100", "192.0.2.150")]
    assert str(server.router) == "192.0.2.1" and server.domain == "lan.example"
    assert [str(a) for a in server.dns_servers] == ["192.0.2.1"]
    (dns,) = snap.dns_services
    assert "192.0.2.1" in [str(a) for a in dns.listen]
    assert "203.0.113.53" in [str(f) for f in dns.forwarders]


async def test_nat_routes_health_and_time(vy: Target) -> None:
    snap = await observe(context(vy), False)
    (fw,) = snap.firewalls
    assert any(n.masquerade and n.zones == ["eth0"] for n in fw.nat), fw.nat
    assert any(str(r.destination) == "0.0.0.0/0" for r in snap.routes)
    assert snap.device.time is not None
    assert snap.device.health is not None and snap.device.health.uptime_seconds is not None


async def test_wrong_pin(vy: Target) -> None:
    snap = await observe(dataclasses.replace(context(vy), pinned_fingerprint="00" * 32), False)
    assert snap.status is DeviceStatus.UNTRUSTED
