"""The OPNsense adapter against an older real OPNsense in QEMU (#390): 25.1 (and 24.7 once its
image is set up, see docs/adapters/opnsense.md, "Versions").

Same VM setup as test_opnsense_real.py (tools/integration/opnsense/vm.py with
OPNSENSE_VERSION), read only: what 25.1 answers is compared with the sources of the tags
(controllers and models of opnsense/core 24.7.12, 25.1.12, 25.7.11). Whatever a release does not
have must come out as an optional gap, never as a failed read. Failures print the snapshot's
errors, so the first run on a new release shows what differs.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import SecretStr

from factories import SITE
from integration.conftest import Target
from signalbox.adapters import AdapterContext
from signalbox.adapters.opnsense import OpnsenseAdapter, OpnsenseConfig, compat
from signalbox.merge import merge
from signalbox.model import DeviceRole, Network, Snapshot, UplinkKind
from signalbox.model import DeviceStatus as ReadStatus
from signalbox.testing import assert_contract

LAN, IOT = "home/segment/native", "home/segment/20"
TIMEOUT = 60.0
VERSION = os.environ.get("IT_OPNSENSE_VERSION", "26.7")
RELEASE = compat.parse_version(VERSION) or (0, 0, 0)

pytestmark = pytest.mark.skipif(
    RELEASE >= (26, 7, 0), reason="the 26.7 VM is covered by test_opnsense_real.py"
)


@pytest.fixture(scope="session")
def fw(target: Callable[[str], Target]) -> dict[str, str]:
    t = target("opnsense")
    assert t.pin, "IT_OPNSENSE_PIN"
    return {"URL": t.url, "FINGERPRINT": t.pin, "KEY": t.username, "SECRET": t.password}


def adapter(fw: dict[str, str], secret: str | None = None) -> OpnsenseAdapter:
    return OpnsenseAdapter(
        AdapterContext(
            site_id="home",
            device_id="fw",
            device_name="fw",
            role=DeviceRole.GATEWAY,
            config=OpnsenseConfig(
                url=fw["URL"],
                api_key=SecretStr(fw["KEY"]),
                api_secret=SecretStr(secret if secret is not None else fw["SECRET"]),
            ),
            pinned_fingerprint=fw["FINGERPRINT"],
            timeout=TIMEOUT,
        )
    )


async def observe(fw: dict[str, str]) -> Snapshot:
    a = adapter(fw)
    try:
        return await assert_contract(a)
    finally:
        await a.close()


def describe(snap: Snapshot) -> str:
    return "\n".join(f"{e.capability}: {e.message} (optional={e.optional})" for e in snap.errors)


async def test_read_contract_and_gaps(fw: dict[str, str]) -> None:
    snap = await observe(fw)
    assert snap.device.firmware is not None
    assert snap.device.firmware.current.startswith(VERSION), snap.device.firmware
    # a feature this release does not have is an optional gap; anything else is a failed read
    assert [e for e in snap.errors if not e.optional] == [], describe(snap)
    ids = {e.message_id for e in snap.errors}
    if RELEASE < compat.DNAT_API:
        assert "opnsense.forwardsUnread" in ids, describe(snap)
    assert snap.device.transport_encrypted is True


async def test_mapping(fw: dict[str, str]) -> None:
    a = adapter(fw)
    try:
        net: Network = merge([SITE], [await a.observe()])
    finally:
        await a.close()
    ports = {p.name: p for p in net.ports}
    assert {"vtnet0", "vtnet1", "vtnet2"} <= set(ports), sorted(ports)
    assert ports["vtnet0"].mac == "02:00:00:00:01:00"
    lan, iot = net.segment(LAN), net.segment(IOT)
    assert lan is not None and lan.name == "LAN", [s.id for s in net.segments]
    assert iot is not None and iot.vlan == 20, [s.id for s in net.segments]
    [wan] = net.uplinks
    assert (wan.port_id, wan.kind) == ("fw/port/vtnet1", UplinkKind.DHCP)
    subnets = {(s.segment_id, str(s.interface)) for s in net.subnets}
    assert {(LAN, "192.0.2.1/24"), (IOT, "198.51.100.1/24")} <= subnets, subnets
    kea = next(s for s in net.dhcp_servers if s.segment_id == LAN)
    assert kea.enabled and kea.vendor_extra["server"] == "kea"
    assert [(str(p.start), str(p.end)) for p in kea.pools] == [("192.0.2.100", "192.0.2.199")]
    assert [(r.mac, str(r.address), r.hostname) for r in kea.reservations] == [
        ("02:00:00:00:00:10", "192.0.2.10", "printer")
    ]
    assert any(d.id.endswith("/dns/unbound") and d.port == 53 for d in net.dns_services)


async def test_firewall_lists_the_mvc_rule(fw: dict[str, str]) -> None:
    """The rule of vm.py's firewall_setup is a rule of the "new" model: every release lists it.
    Before 26.1 there is no port forward API; 25.x lists no legacy rule (#379)."""
    snap = await observe(fw)
    [firewall] = snap.firewalls
    names = [r.name or "" for r in firewall.rules]
    assert "Signalbox CI: NAS" in names, (names, firewall.rules_complete, describe(snap))
    if RELEASE < compat.DNAT_API:
        assert not firewall.port_forwards_complete and firewall.port_forwards == []


async def test_health_and_time(fw: dict[str, str]) -> None:
    """``system_disk`` is the table of ``df -h`` before 26.7: sizes like ``1.8G`` (guess until
    this ran), ``system_time`` words follow the interface language (English here)."""
    snap = await observe(fw)
    h = snap.device.health
    assert h is not None and h.uptime_seconds is not None and h.uptime_seconds > 0, h
    assert h.load_average is not None and h.memory_total_bytes, h
    root = next((s for s in h.storage if s.name == "/"), None)
    assert root is not None and root.total_bytes and root.total_bytes > 10**8, h.storage
    assert root.used_bytes is not None and root.used_bytes <= root.total_bytes, h.storage
    t = snap.device.time
    assert t is not None and t.clock is not None, t
    if RELEASE < compat.NTPD_API:
        assert t.ntp_client is None, t  # no ntpd API before 25.7: no NTP state


async def test_wireguard_instance_and_peer(fw: dict[str, str]) -> None:
    """Before 25.7 the read user needs the full *VPN: WireGuard* page for ``service/show``
    (vm.py gives it ``page-wireguard-config``)."""
    snap = await observe(fw)
    (t,) = snap.tunnels
    assert (t.name, t.listen_port, t.up) == ("wg0", 51820, True), t
    assert t.public_key == os.environ["IT_OPNSENSE_WG_SERVER"], t


async def test_certificates_and_users(fw: dict[str, str]) -> None:
    snap = await observe(fw)
    assert snap.certificates, "the web interface certificate is listed"
    # the read user must not list accounts (no read-only privilege): a gap, not an error
    accounts: Any = [e for e in snap.errors if e.capability == "accounts"]
    assert all(e.optional for e in accounts), accounts


async def test_refused_api_key_is_auth_failed(fw: dict[str, str]) -> None:
    a = adapter(fw, secret="not-the-secret")
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is ReadStatus.AUTH_FAILED, snap.errors
