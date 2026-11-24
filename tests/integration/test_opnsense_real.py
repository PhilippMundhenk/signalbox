"""The OPNsense adapter against the real OPNsense in QEMU (#138).

The VM (tools/integration/opnsense/vm.py) is preseeded with: LAN vtnet0 192.0.2.1/24 +
2001:db8:1::1/64, WAN vtnet1 (DHCP), VLAN 20 "IoT" on the trunk vtnet2 assigned as opt1
198.51.100.1/24, Kea DHCPv4 on LAN (pool 192.0.2.100-199, reservation 02:00:00:00:00:10 ->
192.0.2.10 "printer"), an Unbound host override nas.home.example -> 192.0.2.10 with the alias
storage.home.example and "Register DHCP static mappings / leases" on (#386), a WireGuard
instance "s2s" with a peer "site-b" (#239), and two API
users with the read and write privileges of docs/adapters/opnsense.md.

Every write test ends with the firewall as it started (revert or restore through the
Deployer), so the tests can run in any order against one VM.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from factories import SITE
from integration.conftest import Target
from signalbox.adapters import AdapterContext, AdapterError, AuthFailed
from signalbox.adapters.https import fingerprint, peer_certificate
from signalbox.adapters.opnsense import OpnsenseAdapter, OpnsenseConfig
from signalbox.changes import Change, ChangeKind, ReservationValue, plan
from signalbox.deploy import Deployer
from signalbox.desired import parse
from signalbox.history import ChangeStatus, DeviceStatus
from signalbox.merge import merge
from signalbox.model import (
    DeviceRole,
    FirewallAction,
    FirewallChain,
    FirewallProtocol,
    Flow,
    NatClass,
    Network,
    PortRange,
    UplinkKind,
    Verdict,
)
from signalbox.model import DeviceStatus as ReadStatus
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.store import DeviceRecord
from signalbox.testing import assert_contract, secret_problems

LAN, IOT, LAB = "home/segment/native", "home/segment/20", "home/segment/60"
TIMEOUT = 60.0  # interface and Kea reconfigure calls take seconds on the real firewall


@pytest.fixture(scope="session")
def fw(target: Callable[[str], Target]) -> dict[str, str]:
    """The OPNsense VM: IT_OPNSENSE_USER/PASSWORD are the read user's API key and secret,
    WRITE_USER/WRITE_PASSWORD the write user's, PIN the web interface's certificate."""
    t = target("opnsense")
    assert t.write_username and t.write_password and t.pin, "IT_OPNSENSE_WRITE_* and PIN"
    return {
        "URL": t.url,
        "FINGERPRINT": t.pin,
        "KEY": t.username,
        "SECRET": t.password,
        "WRITE_KEY": t.write_username,
        "WRITE_SECRET": t.write_password,
    }


def adapter(
    fw: dict[str, str], write: bool = False, pin: str | None = "", secret: str | None = None
) -> OpnsenseAdapter:
    prefix = "WRITE_" if write else ""
    config = OpnsenseConfig(
        url=fw["URL"],
        api_key=SecretStr(fw[f"{prefix}KEY"]),
        api_secret=SecretStr(secret if secret is not None else fw[f"{prefix}SECRET"]),
    )
    ctx = AdapterContext(
        site_id="home",
        device_id="fw",
        device_name="fw",
        role=DeviceRole.GATEWAY,
        config=config,
        pinned_fingerprint=fw["FINGERPRINT"] if pin == "" else pin,
        timeout=TIMEOUT,
    )
    return OpnsenseAdapter(ctx)


async def network(fw: dict[str, str]) -> Network:
    a = adapter(fw)
    try:
        return merge([SITE], [await a.observe()])
    finally:
        await a.close()


def configuration(net: Network) -> Any:
    """What a deployment may change, without times and live data (clients, leases, links)."""

    def strip(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                k: strip(v) for k, v in value.items() if k not in ("observed_at", "up", "leases")
            }
        if isinstance(value, list):
            return [strip(v) for v in value]
        return value

    dump = net.model_dump(mode="json")
    keep = ("ports", "segments", "subnets", "dhcp_servers", "dns_services")
    return {k: strip(dump[k]) for k in keep}


def differences(a: Any, b: Any, path: str = "") -> list[str]:
    """Where two configurations differ, as short readable lines (lists of objects by id)."""
    if isinstance(a, dict) and isinstance(b, dict):
        return [
            line
            for k in sorted(set(a) | set(b))
            for line in differences(a.get(k), b.get(k), f"{path}.{k}")
        ]
    if (
        isinstance(a, list)
        and isinstance(b, list)
        and all(isinstance(x, dict) and "id" in x for x in [*a, *b])
    ):
        return differences({x["id"]: x for x in a}, {x["id"]: x for x in b}, path)
    return [] if a == b else [f"{path}: {a!r} -> {b!r}"]


def assert_unchanged(before: Any, after: Any) -> None:
    found = differences(before, after)
    assert not found, "the firewall did not return to its configuration:\n" + "\n".join(found)


# --- reading -------------------------------------------------------------------------------


async def test_certificate_pinning_with_the_real_certificate(fw: dict[str, str]) -> None:
    host = fw["URL"].split("://", 1)[1]
    name, port = host.rsplit(":", 1)
    seen = fingerprint(await peer_certificate(name, int(port), TIMEOUT))
    assert seen == fw["FINGERPRINT"]
    for pin in (None, "00" * 32):
        a = adapter(fw, pin=pin)
        try:
            snap = await a.observe()
        finally:
            await a.close()
        assert snap.status is ReadStatus.UNTRUSTED, snap.errors
        assert seen in snap.errors[0].message


async def test_read_contract(fw: dict[str, str]) -> None:
    a = adapter(fw)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    assert snap.device.firmware is not None
    assert snap.device.firmware.current.startswith("26.7"), snap.device.firmware
    # management services (#173): only the web interface of the address in use; the base system
    # has no os-net-snmp, and the backup (SSH, web interface settings) is not downloaded
    assert [(s.name, s.kind.value, s.enabled) for s in snap.services] == [
        ("webgui", "https", True)
    ], snap.services
    assert snap.device.transport_encrypted is True


async def test_routes(fw: dict[str, str]) -> None:
    """Routes (#149): the WAN default route from the interface overview when the lab's WAN has
    a gateway, and whatever static routes the API user may read (the grids need the privileges
    ``page-system-staticroutes`` and ``page-system-gateways``, *guess* until this runs); a
    refused grid is an optional gap, never a failed read."""
    a = adapter(fw)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    assert snap.status.value == "ok", snap.errors
    [wan] = [u for u in snap.uplinks if u.name]
    if wan.upstream_gateway is not None and wan.up:
        defaults = [r for r in snap.routes if r.default]
        assert [r.gateway for r in defaults] == [wan.upstream_gateway], snap.routes
    for e in snap.errors:
        if "routes" in e.message or "gateways" in e.message:
            assert e.optional, e


async def test_mapping_of_the_preseeded_firewall(fw: dict[str, str]) -> None:
    net = await network(fw)
    ports = {p.name: p for p in net.ports}
    assert {"vtnet0", "vtnet1", "vtnet2"} <= set(ports), sorted(ports)
    assert ports["vtnet0"].mac == "02:00:00:00:01:00"
    # port details (#156): the assignment's description and enable flag, ifconfig's MTU
    lan_port = ports["vtnet0"]
    assert (lan_port.description, lan_port.admin_up, lan_port.mtu) == ("LAN", True, 1500), lan_port
    assert ports["vtnet2"].description is None  # the trunk is not assigned itself
    # port structure (#252): NICs are jacks, a VLAN device runs on its parent NIC
    assert [
        ports[n].role.value if ports[n].role else None for n in ("vtnet0", "vtnet1", "vtnet2")
    ] == ["jack"] * 3, [ports[n].role for n in ("vtnet0", "vtnet1", "vtnet2")]
    vlan_ports = [p for p in ports.values() if p.role and p.role.value == "vlan"]
    assert vlan_ports and all(p.lower == ["fw/port/vtnet2"] for p in vlan_ports), vlan_ports
    assert all(p.external is False for p in vlan_ports)
    assert {p.name for p in net.external_ports("fw")} >= {"vtnet0", "vtnet1", "vtnet2"}
    lan = net.segment(LAN)
    assert lan is not None and lan.name == "LAN"
    assert [(m.port_id, m.mode.value) for m in lan.members] == [("fw/port/vtnet0", "untagged")]
    iot = net.segment(IOT)
    assert iot is not None and iot.name == "IoT" and iot.vlan == 20
    assert [(m.port_id, m.mode.value) for m in iot.members] == [("fw/port/vtnet2", "tagged")]
    assert not any(s.id.endswith("/wan") for s in net.segments)  # the WAN is the uplink
    [wan] = net.uplinks
    assert (wan.id, wan.port_id, wan.kind) == ("fw/uplink/wan", "fw/port/vtnet1", UplinkKind.DHCP)
    v4 = wan.ipv4()
    if v4:  # QEMU's user network answers DHCP with 10.0.2.15, behind its own NAT
        assert wan.up is True, wan
        assert all(a.ip in ip_network("10.0.2.0/24") for a in v4), v4
        assert wan.nat_class() is NatClass.PRIVATE
        assert wan.upstream_gateway is None or wan.upstream_gateway in ip_network("10.0.2.0/24")
    subnets = {(s.segment_id, str(s.interface)) for s in net.subnets}
    assert {
        (LAN, "192.0.2.1/24"),
        (LAN, "2001:db8:1::1/64"),
        (IOT, "198.51.100.1/24"),
    } <= subnets, subnets
    kea = next(s for s in net.dhcp_servers if s.segment_id == LAN)
    assert kea.enabled and kea.vendor_extra["server"] == "kea"
    assert [(str(p.start), str(p.end)) for p in kea.pools] == [("192.0.2.100", "192.0.2.199")]
    assert str(kea.router) == "192.0.2.1"  # option autocollect: the interface address
    assert kea.lease_seconds == 4000
    assert kea.leases is not None  # #183: the lease table was read (nobody leased yet: maybe empty)
    assert net.dhcp_relays == []  # dhcrelay answers (privilege page-services-dhcprelay), no relay
    assert [(r.mac, str(r.address), r.hostname) for r in kea.reservations] == [
        ("02:00:00:00:00:10", "192.0.2.10", "printer")
    ]
    dns = next(d for d in net.dns_services if d.id.endswith("/dns/unbound"))
    assert dns.enabled and dns.port == 53  # #241: Unbound's port is read
    assert all(d.config_read for d in net.dns_services)  # Unbound answers on 53 itself
    assert dns.host_records_read
    # the override, its alias and (registration on) the Kea reservation as a DHCP static mapping
    assert {(h.name, str(h.address), h.source) for h in dns.host_records} >= {
        ("nas.home.example", "192.0.2.10", "host-override"),
        ("storage.home.example", "192.0.2.10", "alias"),
        ("printer.lan.example", "192.0.2.10", "dhcp-static"),
    }
    assert ip_address("192.0.2.1") in dns.listen
    # option_data.ntp_servers is empty, but with autocollect OPNsense fills in the interface
    # address on the next Kea save (seen after a deployment): read as that address
    assert [str(a) for a in kea.ntp_servers] == ["192.0.2.1"]


async def test_health_and_time(fw: dict[str, str]) -> None:
    """The dashboard widgets (uptime, load, memory, the nano image's UFS root and tmpfs, no
    temperature sensors in QEMU), the CPU type, the clock (``Date`` header, UTC) and ntpd's
    peers, with the read user's privileges (#178, #179)."""
    a = adapter(fw)
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is ReadStatus.OK, snap.errors
    h = snap.device.health
    assert h is not None and h.uptime_seconds is not None and h.uptime_seconds > 0, h
    assert h.load_average is not None and h.cpu_count and h.cpu_count >= 1, h
    assert h.memory_total_bytes and h.memory_used_bytes, h
    assert 0 < h.memory_used_bytes < h.memory_total_bytes, h
    kinds = {s.name: s.kind.value for s in h.storage}
    assert kinds.get("/") == "system" and kinds.get("/tmp") == "temporary", h.storage
    assert h.temperatures == [], h  # QEMU has no sensors
    t = snap.device.time
    assert t is not None and t.clock is not None, t
    offset = t.offset_seconds()
    assert offset is not None and abs(offset) < 600, t
    assert t.utc_offset_minutes == 0, t  # the image runs on UTC
    assert t.ntp_client is not None and t.ntp_client.servers, t
    assert any(s.endswith("opnsense.pool.ntp.org") for s in t.ntp_client.servers), t


async def test_wireguard_instance_and_peer(fw: dict[str, str]) -> None:
    """The WireGuard instance "s2s" set up by vm.py (#239), read with *VPN: WireGuard: Status*
    only: wg0 up on 51820 with its address, the peer site-b with its allowed IPs, configured
    endpoint and keepalive, no handshake (the endpoint never answers). The configuration
    grids, which hold the private keys, stay closed to the read user."""
    a = adapter(fw)
    try:
        snap = await a.observe()
        for grid in ("server/search_server", "client/search_client"):
            with pytest.raises(AdapterError, match="HTTP 403"):
                await a.http.get_json(f"/api/wireguard/{grid}")
    finally:
        await a.close()
    assert snap.status is ReadStatus.OK, snap.errors
    (t,) = snap.tunnels
    assert (t.name, t.description, t.listen_port, t.up) == ("wg0", "s2s", 51820, True), t
    assert t.public_key == os.environ["IT_OPNSENSE_WG_SERVER"], t
    # configured as 2001:db8:ff::1/64; FreeBSD's ifconfig (the interface overview) shows /128
    assert "2001:db8:ff::1" in [str(x.ip) for x in t.addresses], t
    assert t.port_id == "fw/port/wg0" and t.port_id in {p.id for p in snap.ports}
    (p,) = t.peers
    assert (p.name, p.public_key) == ("site-b", os.environ["IT_OPNSENSE_WG_PEER"]), p
    assert sorted(str(n) for n in p.allowed_ips) == ["2001:db8:20::/64", "2001:db8:ff::2/128"]
    assert [str(n) for n in t.remote_networks(p)] == ["2001:db8:20::/64"]
    assert (p.endpoint_host, p.endpoint_port) == ("2001:db8:ffff:20::1", 51820), p
    assert (p.keepalive_seconds, p.latest_handshake) == (25, None), p
    assert secret_problems(snap) == []
    net = merge([SITE], [snap])
    assert [(t.id, peer.name) for t, peer in net.remote_sites()] == [("fw/tunnel/wg0", "site-b")]


async def test_firewall_rules_and_port_forward(fw: dict[str, str]) -> None:
    """The rule and the port forward vm.py adds (#135), read with the read user's firewall
    privileges: the "new" model's rule (alias resolved), the automatic and default rules around
    it, the destination NAT and the automatic outbound NAT of the WAN."""
    a = adapter(fw)
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is ReadStatus.OK, snap.errors
    [fwl] = snap.firewalls
    zones = {z.name: z for z in fwl.zones}
    assert zones["lan"].segments == [LAN] and zones["wan"].uplinks == ["fw/uplink/wan"], zones
    assert fwl.input_policy is FirewallAction.DROP
    assert fwl.rules_complete  # legacy and automatic rows listed (#379)
    ours = next(r for r in fwl.rules if r.name == "Signalbox CI: NAS")
    assert ours.action is FirewallAction.ACCEPT and ours.source.zones == ["lan"], ours
    assert [str(n) for n in ours.destination.networks] == ["192.0.2.10/32"], ours
    assert ours.destination.ports == [PortRange(start=8443)] and ours.exact, ours
    assert ours.protocols == [FirewallProtocol.TCP], ours
    # the web interface is reachable from LAN (anti-lockout rule) and not from WAN
    to_ui = Flow(
        chain=FirewallChain.INPUT,
        protocol=FirewallProtocol.TCP,
        port=443,
        family=4,
        source=ip_network("192.0.2.50/32"),
        destination=ip_network("192.0.2.1/32"),
    )
    assert (
        fwl.evaluate(to_ui.model_copy(update={"source_zones": {"lan"}})).verdict is Verdict.ALLOWED
    )
    assert (
        fwl.evaluate(to_ui.model_copy(update={"source_zones": {"wan"}})).verdict is Verdict.DENIED
    )
    [pf] = [f for f in fwl.port_forwards if f.name == "Signalbox CI: NAS web"]
    assert pf.zones == ["wan"] and pf.external_ports == [PortRange(start=8443)], pf
    assert str(pf.target_address) == "192.0.2.10" and pf.target_port == 443 and pf.exact, pf
    assert any(n.masquerade and "wan" in n.zones for n in fwl.nat), fwl.nat


async def test_log_targets(fw: dict[str, str]) -> None:
    """The syslog destination and the NetFlow export of the LAN that vm.py adds (#180), read
    with the read user's privileges (System: Settings: Logging, Diagnostics: Netflow)."""
    a = adapter(fw)
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is ReadStatus.OK, snap.errors
    rows = [
        (t.kind.value, t.endpoint(), t.transport.value if t.transport else None, t.enabled)
        for t in snap.device.log_targets or []
    ]
    assert rows == [
        ("syslog", "192.0.2.5:514", "udp", True),
        ("netflow", "192.0.2.5:2055", "udp", True),
    ], snap.device.log_targets
    syslog = (snap.device.log_targets or [])[0]
    assert syslog.name == "collector" and "info" in syslog.topics, syslog


async def test_stored_certificates(fw: dict[str, str]) -> None:
    """The firewall's own web interface certificate (#330) through the grids the read user may
    call (System: Certificate Manager and Authority Manager): listed with its dates, no key."""
    a = adapter(fw)
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is ReadStatus.OK, snap.errors  # no privilege gap
    assert snap.certificates, "the web interface certificate is listed"
    assert all(c.not_after > c.not_before and c.name for c in snap.certificates), snap.certificates
    assert any(c.in_use for c in snap.certificates), snap.certificates
    dump = snap.model_dump_json()
    assert "PRIVATE KEY" not in dump and "BEGIN" not in dump
    assert all(c.vendor_extra == {} for c in snap.certificates)


async def test_refused_api_key_is_auth_failed(fw: dict[str, str]) -> None:
    a = adapter(fw, secret="not-the-secret")
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is ReadStatus.AUTH_FAILED, snap.errors


async def test_read_user_has_no_write_privileges(fw: dict[str, str]) -> None:
    """The documented read privileges do not include the configuration history."""
    a = adapter(fw)
    try:
        with pytest.raises(AdapterError, match="HTTP 403"):
            await a.backup()
    finally:
        await a.close()


# --- writing through the Deployer ----------------------------------------------------------


@pytest.fixture
def svc(tmp_path: Path, fw: dict[str, str]) -> Iterator[Services]:
    env = {
        "SIGNALBOX_AUTH_PASSWORD": "x" * 12,
        "SIGNALBOX_DEPLOY_ENABLED": "true",
        "SIGNALBOX_OBSERVE_TIMEOUT_SECONDS": str(TIMEOUT),
    }
    s = build(
        tmp_path, env=env, adapters={"opnsense": OpnsenseAdapter}, rules=RULES, link_sources=[]
    )
    s.store.put_site(SITE)
    rec = DeviceRecord(
        id="fw",
        site_id="home",
        name="fw",
        role=DeviceRole.GATEWAY,
        adapter="opnsense",
        allow_writes=True,
        pinned_fingerprint=fw["FINGERPRINT"],
    )
    cfg = {"url": fw["URL"], "api_key": fw["WRITE_KEY"]}
    cfg["api_secret"] = fw["WRITE_SECRET"]
    s.store.put_device(rec, cfg, OpnsenseConfig)
    yield s
    s.close()


def events(svc: Services, cid: str) -> list[str]:
    return [f"{e.event} {e.detail}" for e in svc.store.events(cid)]


async def deploy(svc: Services, want: str, kinds: set[ChangeKind]) -> tuple[Deployer, str]:
    await svc.runner.observe_all()
    p = plan(parse(want), svc.runner.network(), RULES)
    assert {c.kind for c in p.changes} == kinds, [c.describe() for c in p.changes]
    d = Deployer(svc.runner)
    rec = await d.prepare(p, "integration test", "ci")
    d.approve(rec.id, "ci", override="integration test" if rec.plan.blocking else None)
    done = await d.deploy(rec.id)
    assert done.status is ChangeStatus.APPLIED, events(svc, rec.id)
    assert done.devices[0].status is DeviceStatus.CONFIRMED
    assert plan(parse(want), svc.runner.network(), RULES).changes == []
    return d, rec.id


async def revert(svc: Services, d: Deployer, cid: str) -> None:
    back = await d.revert(cid, "integration test done", "ci")
    d.approve(back.id, "ci", override="integration test" if back.plan.blocking else None)
    done = await d.deploy(back.id)
    assert done.status is ChangeStatus.APPLIED, events(svc, back.id)


NEW_NETWORK = """
sites:
  home:
    segments:
      - vlan: 60
        name: Lab6
        gateway: {device: fw, address: 203.0.113.1/24}
        dhcp:
          enabled: true
          pool: [203.0.113.100, 203.0.113.199]
          dns: [203.0.113.1]
          lease_seconds: 3600
        reservations:
          - {mac: "02:00:00:00:00:60", address: 203.0.113.60, hostname: cam}
"""


async def test_new_network_with_dhcp_and_reservation_then_revert(
    svc: Services, fw: dict[str, str]
) -> None:
    before = configuration(await network(fw))
    kinds = {ChangeKind.ROUTER, ChangeKind.DHCP, ChangeKind.RESERVATION}
    d, cid = await deploy(svc, NEW_NETWORK, kinds)
    after = await network(fw)
    seg = after.segment(LAB)
    assert seg is not None and seg.name == "Lab6"
    assert [(m.port_id, m.mode.value) for m in seg.members] == [("fw/port/vtnet0", "tagged")]
    kea = next(s for s in after.dhcp_servers if s.segment_id == LAB)
    assert kea.enabled and kea.lease_seconds == 3600
    assert [(r.mac, str(r.address)) for r in kea.reservations] == [
        ("02:00:00:00:00:60", "203.0.113.60")
    ]
    await revert(svc, d, cid)
    assert_unchanged(before, configuration(await network(fw)))


CHANGE_EXISTING = """
sites:
  home:
    segments:
      - vlan: 20
        name: IoT_net
        gateway: {device: fw, address: 198.51.100.2/24}
      - vlan: native
        dhcp:
          enabled: true
          pool: [192.0.2.120, 192.0.2.180]
          dns: [192.0.2.1]
          lease_seconds: 7200
        reservations:
          - {mac: "02:00:00:00:00:10", address: 192.0.2.11, hostname: printer}
    ports:
      - {device: fw, port: vtnet2, tagged: [20, 70]}
"""


async def test_change_router_dhcp_reservation_and_port_then_revert(
    svc: Services, fw: dict[str, str]
) -> None:
    before = configuration(await network(fw))
    kinds = {ChangeKind.ROUTER, ChangeKind.DHCP, ChangeKind.RESERVATION, ChangeKind.PORT}
    d, cid = await deploy(svc, CHANGE_EXISTING, kinds)
    after = await network(fw)
    assert (IOT, "198.51.100.2/24") in {(s.segment_id, str(s.interface)) for s in after.subnets}
    assert any(str(s.interface) == "2001:db8:1::1/64" for s in after.subnets)  # IPv6 kept
    trunk = {
        seg.vlan
        for seg in after.segments
        for m in seg.members
        if m.port_id == "fw/port/vtnet2" and m.mode.value == "tagged"
    }
    assert trunk == {20, 70}
    await revert(svc, d, cid)
    assert_unchanged(before, configuration(await network(fw)))


PORT_ONLY = "sites:\n  home:\n    ports:\n      - {device: fw, port: vtnet2, tagged: [20, 80]}\n"
ROUTER_ONLY = """
sites:
  home:
    segments:
      - vlan: 90
        name: Lab9
        gateway: {device: fw, address: 203.0.113.129/25}
"""


FIREWALL_WANT = """
sites:
  home:
    firewalls:
      - device: fw
        rules:
          - name: ci-web
            from: {zone: lan}
            to: {network: 192.0.2.77}
            protocol: tcp
            family: 4
            port: 8080
            action: accept
        forwards:
          - name: ci-fwd
            protocol: tcp
            port: 8444
            to: {address: 192.0.2.77, port: 80}
"""


async def test_firewall_rule_and_port_forward_then_revert(
    svc: Services, fw: dict[str, str]
) -> None:
    """One rule and one port forward (#295): written through the API of the new rules and
    destination NAT pages, read back as what was declared, then reverted. 26.7 has no savepoint
    and rollback timer for them: the deployment is confirmed at once and its safety net is the
    backup."""

    async def firewall() -> Any:
        [snap] = (await network(fw)).firewalls
        return snap

    before = await firewall()
    kinds = {ChangeKind.FIREWALL_RULE, ChangeKind.PORT_FORWARD}
    d, cid = await deploy(svc, FIREWALL_WANT, kinds)
    after = await firewall()
    [rule] = [r for r in after.rules if r.signalbox_key == "ci_web"]
    assert rule.name == "ci-web" and rule.action is FirewallAction.ACCEPT, rule
    assert rule.source.zones == ["lan"] and rule.protocols == [FirewallProtocol.TCP], rule
    assert [str(n) for n in rule.destination.networks] == ["192.0.2.77/32"], rule
    assert rule.destination.ports == [PortRange(start=8080)] and rule.exact, rule
    [pf] = [f for f in after.port_forwards if f.signalbox_key == "ci_fwd"]
    assert pf.zones == ["wan"] and pf.external_ports == [PortRange(start=8444)], pf
    assert str(pf.target_address) == "192.0.2.77" and pf.target_port == 80, pf
    # the owner's own rule and forward are as they were
    own = [r.name for r in after.rules if r.signalbox_key is None]
    assert own == [r.name for r in before.rules], own
    assert [f.name for f in after.port_forwards if f.signalbox_key is None] == [
        f.name for f in before.port_forwards
    ]
    await revert(svc, d, cid)
    final = await firewall()
    assert not [r for r in final.rules if r.signalbox_key]
    assert not [f for f in final.port_forwards if f.signalbox_key]
    assert [r.name for r in final.rules] == [r.name for r in before.rules]
    assert [f.name for f in final.port_forwards] == [f.name for f in before.port_forwards]


@pytest.mark.parametrize(
    ("want", "kinds"),
    [(PORT_ONLY, {ChangeKind.PORT}), (ROUTER_ONLY, {ChangeKind.ROUTER})],
    ids=["vlan-on-a-port", "new-router-interface"],
)
async def test_backup_and_restore_through_the_configuration_history(
    svc: Services, fw: dict[str, str], want: str, kinds: set[ChangeKind]
) -> None:
    """A deployment, then the restore of its backup (revert_backup and the reconfigures)."""
    before = configuration(await network(fw))
    _, cid = await deploy(svc, want, kinds)
    rec = svc.store.change(cid)
    assert rec is not None and rec.devices[0].backup_id
    backup = svc.store.backup(rec.devices[0].backup_id)
    assert backup is not None and backup.format == "opnsense-config-xml"
    assert "<opnsense>" in backup.content and "vlan0.20" in backup.content
    d = Deployer(svc.runner)
    restore = await d.restore_backup(rec.devices[0].backup_id, "integration test", "ci")
    d.approve(restore.id, "ci")
    done = await d.deploy(restore.id)
    assert done.status is ChangeStatus.APPLIED, events(svc, restore.id)
    assert_unchanged(before, configuration(await network(fw)))


async def test_validation_error_of_the_firewall_names_the_field(fw: dict[str, str]) -> None:
    """A reservation outside its subnet: the planner sends it, Kea's model refuses it."""
    c = Change(
        kind=ChangeKind.RESERVATION,
        device_id="fw",
        site_id="home",
        key=f"{LAN}/02:00:00:00:00:99",
        old=None,
        new=ReservationValue(mac="02:00:00:00:00:99", address=ip_address("198.51.100.99")),
    )
    a = adapter(fw, write=True)
    try:
        with pytest.raises(AdapterError, match=r"the firewall refused the change \(reservation\."):
            await a.apply([c], {}, 60)
    finally:
        await a.close()
    after = await network(fw)
    lan = next(s for s in after.dhcp_servers if s.segment_id == LAN)
    assert "02:00:00:00:00:99" not in {r.mac for r in lan.reservations}


async def test_trace_refused_for_the_read_user(fw: dict[str, str]) -> None:
    """Path traces (#253): the read user has no Diagnostics: Traceroute: HTTP 403, with the
    privilege named and Fix it offered."""
    a = adapter(fw)
    try:
        with pytest.raises(AuthFailed) as err:
            await a.trace(ip_address("192.0.2.1"), 4, 1)
    finally:
        await a.close()
    assert err.value.remedy == "privileges" and "page-diagnostics-traceroute" in (
        err.value.fix or ""
    )


def test_vm_still_answers(fw: dict[str, str]) -> None:
    """Last: the firewall survived the suite (no lock-out through a write)."""
    r = httpx.get(
        fw["URL"] + "/api/core/firmware/status",
        auth=(fw["KEY"], fw["SECRET"]),
        verify=False,
        timeout=TIMEOUT,
        trust_env=False,
    )
    assert r.status_code == 200


async def test_read_user_cannot_list_accounts(fw: dict[str, str]) -> None:
    """The user manager has no read-only privilege (#175): the guide's read user does not get
    it. Not readable is not "no accounts" (#349): accounts stay unset and an optional gap
    names the privilege; the read stays ok."""
    a = adapter(fw)
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is ReadStatus.OK, snap.errors
    assert snap.device.accounts is None and snap.device.signalbox_account_privilege is None
    (gap,) = [e for e in snap.errors if e.message.startswith("accounts")]
    assert gap.optional and "page-system-usermanager" in (gap.fix or ""), gap
