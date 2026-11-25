"""The edgeos adapter against the real VyOS (rolling ISO in QEMU, #432).

tools/integration/edgeos/vm.py boots the official live ISO, creates the key-only read user
``signalbox`` (level operator where the version has levels) and a small lab: eth1 LAN
192.0.2.1/24 with a DHCP server and DNS forwarding, VLAN 20 on eth2 (203.0.113.1/24), LLDP,
source NAT and a firewall (``firewall ipv4`` forward and input chains, a named chain entered by a
jump, IPv6) and a zone-based firewall (``firewall zone``). The reads change nothing; the router
has no neighbours, leases or tunnels. One test runs the automatic setup with the live ``vyos``
login for a second user (#495).

    IT_EDGEOS_URL        ssh://127.0.0.1:<port>
    IT_EDGEOS_USER       the read user, IT_EDGEOS_KEY_FILE its private key
    IT_EDGEOS_HOST_KEY   SHA-256 of the ed25519 host key (hex), IT_EDGEOS_HOSTNAME its name
    IT_EDGEOS_LEVEL      operator | none: whether the router accepted the user level
    IT_EDGEOS_ADMIN_USER / _PASSWORD   the login of the live system, for the automatic setup
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext, SetupRequest, StepState
from signalbox.adapters.edgeos import EdgeosAdapter, EdgeosConfig
from signalbox.adapters.ssh import sha256_hex
from signalbox.model import (
    DeviceRole,
    DeviceStatus,
    FirewallAction,
    FirewallChain,
    Snapshot,
)
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
    """Observe once; with ``contract`` the adapter contract must hold."""
    adapter = EdgeosAdapter(ctx)
    try:
        snap = await adapter.observe()
        if contract:
            found = problems(adapter, snap)
            assert not found, found
            assert not snap.errors, snap.errors
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


async def test_firewall_of_the_lab(vy: Target) -> None:
    """VyOS 1.4 and newer name the rule-sets ``firewall ipv4`` / ``ipv6`` (#495): the base
    chains, the jump into the named chain and the IPv6 chain are read."""
    snap = await observe(context(vy), False)
    (fw,) = snap.firewalls
    assert fw.rules_complete is True, snap.errors
    by_name = {r.name: r for r in fw.rules}
    web = by_name["Web from the LAN"]  # unrolled from the jump rule of eth1
    assert web.chain is FirewallChain.FORWARD and web.action is FirewallAction.ACCEPT
    assert web.source.zones == ["eth1"] and web.family == 4
    assert sorted(p.start for p in web.destination.ports) == [80, 443]
    closing = by_name["LAN_OUT default"]
    assert closing.action is FirewallAction.DROP and closing.source.zones == ["eth1"]
    ssh = by_name["SSH from the LAN"]
    assert ssh.chain is FirewallChain.INPUT and ssh.source.zones == ["eth1"]
    assert [p.start for p in ssh.destination.ports] == [22]
    assert by_name["ipv4 forward default"].action is FirewallAction.DROP
    assert by_name["ipv4 input default"].action is FirewallAction.ACCEPT
    assert by_name["ipv6 forward default"].family == 6
    # the state-only rules are no rules for new connections
    assert "ipv4 forward 10" not in by_name and "ipv6 forward 10" not in by_name
    # NAT is read next to it
    assert any(n.masquerade for n in fw.nat)


async def test_zone_based_firewall_of_the_lab(vy: Target) -> None:
    """``firewall zone`` (VyOS 1.4 and newer, #504) is read into zones, the rules of the rule-set
    between two zones and the default policies of the zones; it is no longer a finding."""
    snap = await observe(context(vy), False)
    (fw,) = snap.firewalls
    assert not [e for e in snap.errors if e.message_id == "edgeos.firewallUnsupported"]
    assert fw.rules_complete is True, snap.errors
    zones = {z.name: z for z in fw.zones}
    assert zones["LAN"].ports or zones["LAN"].segments, zones["LAN"]
    assert zones["IOT"].segments or zones["IOT"].ports, zones["IOT"]
    assert zones["LAN"].complete and zones["IOT"].complete
    by_name = {r.name: r for r in fw.rules}
    dns = by_name["DNS from the LAN to IoT"]
    assert dns.chain is FirewallChain.FORWARD and dns.action is FirewallAction.ACCEPT
    assert dns.source.zones == ["LAN"] and dns.destination.zones == ["IOT"]
    assert [p.start for p in dns.destination.ports] == [53]
    closing = by_name["LAN_IOT default"]
    assert closing.action is FirewallAction.DROP and closing.destination.zones == ["IOT"]
    # no rule-set from IoT to the LAN: the default action of the LAN zone (VyOS: drop)
    assert fw.policy("IOT", "LAN") is FirewallAction.DROP
    assert fw.policy("LAN", "LAN") is FirewallAction.ACCEPT


async def test_automatic_setup_names_the_rights_of_the_user(vy: Target) -> None:
    """The version is read before the plan: the level where the router has it, else a plan that
    says the user has full rights. The setup creates a second user, Signalbox reads as that user,
    a second run changes nothing, the removal deletes it (#495)."""
    for key in ("ADMIN_USER", "ADMIN_PASSWORD", "LEVEL"):
        assert vy.extra.get(key), f"IT_EDGEOS_{key}"
    login = "sbauto"

    def request(trust: str | None, **kw: Any) -> SetupRequest:
        return SetupRequest(
            config={"host": "127.0.0.1", "username": login},
            admin_user=vy.extra["ADMIN_USER"],
            admin_secret=SecretStr(vy.extra["ADMIN_PASSWORD"]),
            port=vy.port,
            trust=trust,
            timeout=60,
            **kw,
        )

    first = await EdgeosAdapter.plan_setup(request(None))
    assert not first.trusted and sha256_hex(first.fingerprint) == vy.extra["HOST_KEY"]
    fp = first.fingerprint
    plan = await EdgeosAdapter.plan_setup(request(fp))
    ids = [s.id for s in plan.steps]
    has_level = vy.extra["LEVEL"] == "operator"
    assert ids == (
        ["user", "key", "host-key"] if has_level else ["user", "key", "full-rights", "host-key"]
    ), plan.steps
    assert ("level operator" in plan.steps[0].detail) is has_level
    if not has_level:
        assert "full rights" in plan.steps[2].title
    result = await EdgeosAdapter.apply_setup(request(fp))
    assert result.ok, result.steps
    assert result.settings["username"] == login and result.certificate == vy.extra["HOST_KEY"]
    key = result.secrets["private_key"].get_secret_value()
    snap = await observe(
        dataclasses.replace(
            context(vy, username=login, private_key=key), pinned_fingerprint=result.certificate
        )
    )
    assert snap.device.hostname == vy.extra["HOSTNAME"]
    again = await EdgeosAdapter.apply_setup(request(fp))
    assert again.ok, again.steps
    removed = await EdgeosAdapter.apply_setup(request(fp, remove=True))
    assert removed.ok, removed.steps
    nothing = await EdgeosAdapter.plan_setup(request(fp, remove=True))
    assert {s.state for s in nothing.steps} == {StepState.UNCHANGED}
