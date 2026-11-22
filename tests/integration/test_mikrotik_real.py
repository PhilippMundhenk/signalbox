"""The MikroTik adapter against the real RouterOS CHR in QEMU (#139).

The VM (tools/integration/mikrotik/vm.py) is set up with: ether1 the uplink (DHCP client,
interface list WAN, www-ssl with a self-signed certificate), the bridge ``bridge`` (comment
"LAN", vlan-filtering) with ether2 (pvid 1) and ether3 (pvid 1, VLAN 20 tagged), the VLAN
interface ``iot`` (VLAN 20, "IoT"), addresses 192.0.2.1/24 + 2001:db8:1::1/64 on the bridge and
198.51.100.1/24 on iot, the DHCP server ``lan`` on the bridge (pool 192.0.2.100-199, 30m,
gateway and DNS 192.0.2.1, domain home.example, static lease 02:00:00:00:00:10 -> 192.0.2.10
"printer"), DNS with remote requests (forwarder 192.0.2.53, static nas.home.example A and
AAAA), and the users ``signalbox`` (group signalbox-read) and ``signalbox-write`` (group
signalbox-write) with the policies of docs/adapters/mikrotik.md. CHR has no radios.

Every write test ends with the router as it started (revert or restore through the Deployer),
so the tests can run in any order against one VM.
"""

from __future__ import annotations

import asyncio
import json
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
from signalbox.adapters.https import NotFound, fingerprint, peer_certificate
from signalbox.adapters.mikrotik import (
    ROUTERBOARD,
    WIFI,
    WIRELESS,
    MikrotikAdapter,
    MikrotikConfig,
    get_menu,
)
from signalbox.adapters.mikrotik.write import _label, _Op, _writable
from signalbox.changes import Change, ChangeKind, ReservationValue, plan
from signalbox.deploy import Deployer
from signalbox.desired import parse
from signalbox.history import ChangeStatus, DeviceStatus
from signalbox.merge import merge
from signalbox.model import DeviceRole, FrameTypes, NatClass, Network, UplinkKind
from signalbox.model import DeviceStatus as ReadStatus
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.store import DeviceRecord
from signalbox.testing import assert_contract

LAN, IOT, LAB = "home/segment/native", "home/segment/20", "home/segment/60"
TIMEOUT = 30.0


@pytest.fixture(scope="session")
def rt(target: Callable[[str], Target]) -> dict[str, str]:
    """The CHR VM: IT_MIKROTIK_USER/PASSWORD the read user, WRITE_USER/WRITE_PASSWORD the
    write user, PIN the www-ssl certificate, VERSION the RouterOS version it runs."""
    t = target("mikrotik")
    assert t.write_username and t.write_password and t.pin, "IT_MIKROTIK_WRITE_* and PIN"
    return {
        "URL": t.url,
        "FINGERPRINT": t.pin,
        "USER": t.username,
        "PASSWORD": t.password,
        "WRITE_USER": t.write_username,
        "WRITE_PASSWORD": t.write_password,
        "VERSION": t.extra.get("VERSION", ""),
    }


def adapter(
    rt: dict[str, str], write: bool = False, pin: str | None = "", password: str | None = None
) -> MikrotikAdapter:
    prefix = "WRITE_" if write else ""
    config = MikrotikConfig(
        url=rt["URL"],
        username=rt[f"{prefix}USER"],
        password=SecretStr(password if password is not None else rt[f"{prefix}PASSWORD"]),
    )
    ctx = AdapterContext(
        site_id="home",
        device_id="rt",
        device_name="rt",
        role=DeviceRole.GATEWAY,
        config=config,
        pinned_fingerprint=rt["FINGERPRINT"] if pin == "" else pin,
        timeout=TIMEOUT,
    )
    return MikrotikAdapter(ctx)


async def network(rt: dict[str, str]) -> Network:
    a = adapter(rt)
    try:
        return merge([SITE], [await a.observe()])
    finally:
        await a.close()


def configuration(net: Network) -> Any:
    """What a deployment may change, without times and live data (clients, leases, links)."""

    def strip(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: strip(v) for k, v in value.items() if k not in ("observed_at", "up")}
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
    assert not found, "the router did not return to its configuration:\n" + "\n".join(found)


def menus(rt: dict[str, str], *paths: str) -> dict[str, Any]:
    """Raw menus as the read user sees them (to compare the device itself, not the model):
    the static entries by label, with the properties a restore would write (no counters)."""
    out: dict[str, Any] = {}
    for path in paths:
        r = httpx.get(
            rt["URL"] + path,
            auth=(rt["USER"], rt["PASSWORD"]),
            verify=False,
            timeout=TIMEOUT,
            trust_env=False,
        )
        r.raise_for_status()
        rows = [row for row in r.json() if row.get("dynamic") != "true"]
        out[path] = {_label(row): _writable(path, row) for row in rows}
    return out


def assert_same_menus(before: dict[str, Any], after: dict[str, Any]) -> None:
    found = differences(before, after)
    assert not found, "the router's menus did not return:\n" + "\n".join(found)


#: the menus a deployment changes, compared entry by entry after a revert or restore
WRITTEN = (
    "/rest/interface/vlan",
    "/rest/interface/bridge/vlan",
    "/rest/interface/bridge/port",
    "/rest/ip/address",
    "/rest/ip/pool",
    "/rest/ip/dhcp-server",
    "/rest/ip/dhcp-server/network",
    "/rest/ip/dhcp-server/lease",
)


# --- reading -------------------------------------------------------------------------------


async def test_certificate_pinning_with_the_real_certificate(rt: dict[str, str]) -> None:
    host = rt["URL"].split("://", 1)[1]
    name, port = host.rsplit(":", 1)
    seen = fingerprint(await peer_certificate(name, int(port), TIMEOUT))
    assert seen == rt["FINGERPRINT"]
    for pin in (None, "00" * 32):
        a = adapter(rt, pin=pin)
        try:
            snap = await a.observe()
        finally:
            await a.close()
        assert snap.status is ReadStatus.UNTRUSTED, snap.errors
        assert seen in snap.errors[0].message


async def test_read_contract(rt: dict[str, str]) -> None:
    a = adapter(rt)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    assert snap.device.firmware is not None
    assert snap.device.firmware.current.startswith("7."), snap.device.firmware
    assert rt["VERSION"].startswith(snap.device.firmware.current), rt["VERSION"]
    # no /system/routerboard on CHR (HTTP 400): the model is the board name
    assert (snap.device.model or "").startswith("CHR"), snap.device.model


async def test_wireless_on_chr(rt: dict[str, str]) -> None:
    """RouterOS 7.25 CHR has the ``wifi`` menu without radios (an empty list, no finding);
    the legacy ``wireless`` package and the routerboard menu are missing (HTTP 400 "no such
    command or directory"), which the adapter reads as "not on this device"."""
    a = adapter(rt)
    try:
        snap = await a.observe()
        for menu in (WIRELESS, ROUTERBOARD):
            with pytest.raises(NotFound, match="no such command or directory"):
                await get_menu(a.http, menu)
        assert await get_menu(a.http, WIFI) == []
    finally:
        await a.close()
    assert snap.status is ReadStatus.OK, snap.errors
    assert snap.radios == [] and snap.wlans == []
    assert snap.subnets and snap.dhcp_servers and snap.dns_services


async def test_mapping_of_the_configured_router(rt: dict[str, str]) -> None:
    net = await network(rt)
    ports = {p.name: p for p in net.ports}
    assert {"ether1", "ether2", "ether3", "bridge"} <= set(ports), sorted(ports)
    assert "iot" not in ports  # a VLAN interface is a segment, not a port
    assert ports["ether2"].mac == "02:00:00:00:01:02"
    assert ports["ether2"].kind.value == "ethernet"
    assert ports["bridge"].kind.value == "bridge"
    # port details (#156): RouterOS defaults of the setup (MTU 1500, enabled, pvid 1, admit-all)
    e2, e3 = ports["ether2"], ports["ether3"]
    assert (e2.admin_up, e2.mtu, e2.pvid, e2.description) == (True, 1500, 1, None), e2
    assert (e3.pvid, e3.frame_types) == (1, FrameTypes.ALL), e3
    assert ports["bridge"].description == "LAN" and ports["ether1"].pvid is None
    lan = net.segment(LAN)
    assert lan is not None and lan.name == "LAN", lan
    assert [(m.port_id, m.mode.value) for m in lan.members] == [
        ("rt/port/ether2", "untagged"),
        ("rt/port/ether3", "untagged"),
    ]
    iot = net.segment(IOT)
    assert iot is not None and iot.name == "IoT" and iot.vlan == 20, iot
    assert [(m.port_id, m.mode.value) for m in iot.members] == [("rt/port/ether3", "tagged")]
    assert not any(s.id.endswith("/ether1") for s in net.segments)  # the WAN is the uplink
    [wan] = net.uplinks  # ether1: list WAN, DHCP client on QEMU's user network
    assert (wan.id, wan.port_id, wan.kind) == (
        "rt/uplink/ether1",
        "rt/port/ether1",
        UplinkKind.DHCP,
    )
    if wan.up:
        assert any(a.ip in ip_network("10.0.2.0/24") for a in wan.ipv4()), wan.addresses
        assert wan.nat_class() is NatClass.PRIVATE
        assert wan.upstream_gateway is not None
        assert wan.upstream_gateway in ip_network("10.0.2.0/24"), wan.upstream_gateway
    assert wan.public_ipv4 is None or wan.public_ipv4 not in ip_network("10.0.0.0/8")
    subnets = {(s.segment_id, str(s.interface)) for s in net.subnets}
    assert subnets == {
        (LAN, "192.0.2.1/24"),
        (LAN, "2001:db8:1::1/64"),
        (IOT, "198.51.100.1/24"),
    }, subnets
    (dhcp,) = net.dhcp_servers
    assert dhcp.segment_id == LAN and dhcp.enabled
    assert [(str(p.start), str(p.end)) for p in dhcp.pools] == [("192.0.2.100", "192.0.2.199")]
    assert dhcp.lease_seconds == 1800
    assert str(dhcp.router) == "192.0.2.1"
    assert [str(a) for a in dhcp.dns_servers] == ["192.0.2.1"]
    assert dhcp.domain == "home.example"
    assert [(r.mac, str(r.address), r.hostname) for r in dhcp.reservations] == [
        ("02:00:00:00:00:10", "192.0.2.10", "printer")
    ]
    (dns,) = net.dns_services
    assert dns.enabled
    assert [str(a) for a in dns.forwarders] == ["192.0.2.53"]
    assert sorted((h.name, str(h.address)) for h in dns.host_records) == [
        ("nas.home.example", "192.0.2.10"),
        ("nas.home.example", "2001:db8:1::10"),
    ]
    assert ip_address("192.0.2.1") in dns.listen
    assert ip_address("198.51.100.1") in dns.listen
    assert dhcp.ntp_servers == []  # "ntp-server": "" on the network


async def test_health_and_time_of_chr(rt: dict[str, str]) -> None:
    """``/system/resource`` (uptime, CPU, memory, the virtual disk), ``/system/health`` (no
    sensors on CHR: empty, not an error), ``/system/clock`` and the NTP client and server, as
    the read user sees them (#178, #179)."""
    a = adapter(rt)
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is ReadStatus.OK, snap.errors
    h = snap.device.health
    assert h is not None
    assert h.uptime_seconds is not None and h.uptime_seconds > 0, h
    assert h.cpu_count is not None and h.cpu_count >= 1 and h.cpu_load_pct is not None, h
    assert h.memory_total_bytes and h.memory_used_bytes, h
    assert 0 < h.memory_used_bytes < h.memory_total_bytes, h
    (disk,) = h.storage
    assert disk.kind.value == "system" and disk.total_bytes and disk.used_bytes, disk
    assert h.temperatures == h.fans == h.power_supplies == [], h
    t = snap.device.time
    assert t is not None and t.clock is not None and t.read_at is not None, t
    offset = t.offset_seconds()
    assert offset is not None and abs(offset) < 600, t  # QEMU starts with the host's clock
    assert t.utc_offset_minutes is not None, t
    assert t.ntp_client is not None and t.ntp_server is not None, t


async def test_refused_password_is_auth_failed(rt: dict[str, str]) -> None:
    a = adapter(rt, password="not-the-password")
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is ReadStatus.AUTH_FAILED, snap.errors


async def test_read_user_cannot_write(rt: dict[str, str]) -> None:
    """The documented read group has no ``write``: RouterOS itself refuses the change."""
    before = menus(rt, "/rest/ip/dhcp-server/lease")
    c = Change(
        kind=ChangeKind.RESERVATION,
        device_id="rt",
        site_id="home",
        key=f"{LAN}/02:00:00:00:00:99",
        old=None,
        new=ReservationValue(mac="02:00:00:00:00:99", address=ip_address("192.0.2.99")),
    )
    a = adapter(rt)
    try:
        with pytest.raises(AuthFailed, match=r"access denied \(not enough permissions"):
            await a.apply([c], {}, 60)
    finally:
        await a.close()
    assert menus(rt, "/rest/ip/dhcp-server/lease") == before


async def test_refused_change_shows_the_routers_detail(rt: dict[str, str]) -> None:
    """RouterOS refuses a request with HTTP 400 and a ``detail``; the error shows it."""
    a = adapter(rt, write=True)
    try:
        op = _Op(
            "PUT",
            "/rest/ip/address",
            "new-1",
            {"address": "203.0.113.1/24", "interface": "nothere"},
            "add 203.0.113.1/24 to nothere",
        )
        with pytest.raises(
            AdapterError,
            match=r"^add 203\.0\.113\.1/24 to nothere: the router refused the change: "
            r"input does not match any value of interface$",
        ):
            await a._send([op], {})
    finally:
        await a.close()


async def test_backup_of_the_write_user_has_the_export(rt: dict[str, str]) -> None:
    a = adapter(rt, write=True)
    try:
        backup = await a.backup()
    finally:
        await a.close()
    content = json.loads(backup.content)
    assert backup.format == "routeros-export"
    assert content["menus"]["/rest/interface/wifi"] == []  # the menu exists, no radios
    assert isinstance(content["menus"]["/rest/ip/dhcp-server/lease"], list)
    export = content["export"]
    assert isinstance(export, str) and "/interface bridge" in export, export
    assert "printer" in export


# --- writing through the Deployer ----------------------------------------------------------


@pytest.fixture
def svc(tmp_path: Path, rt: dict[str, str]) -> Iterator[Services]:
    env = {
        "SIGNALBOX_AUTH_PASSWORD": "x" * 12,
        "SIGNALBOX_DEPLOY_ENABLED": "true",
        "SIGNALBOX_OBSERVE_TIMEOUT_SECONDS": str(TIMEOUT),
    }
    s = build(
        tmp_path, env=env, adapters={"mikrotik": MikrotikAdapter}, rules=RULES, link_sources=[]
    )
    s.store.put_site(SITE)
    rec = DeviceRecord(
        id="rt",
        site_id="home",
        name="rt",
        role=DeviceRole.GATEWAY,
        adapter="mikrotik",
        allow_writes=True,
        pinned_fingerprint=rt["FINGERPRINT"],
    )
    cfg = {"url": rt["URL"], "username": rt["WRITE_USER"], "password": rt["WRITE_PASSWORD"]}
    s.store.put_device(rec, cfg, MikrotikConfig)
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
        gateway: {device: rt, address: 203.0.113.1/24}
        dhcp:
          enabled: true
          pool: [203.0.113.100, 203.0.113.199]
          dns: [203.0.113.1]
          lease_seconds: 3600
        reservations:
          - {mac: "02:00:00:00:00:60", address: 203.0.113.60, hostname: cam}
"""


async def test_adapter_apply_read_back_and_restore(rt: dict[str, str]) -> None:
    """The adapter alone (no Deployer): apply, read every value back, restore the backup."""
    raw = menus(rt, *WRITTEN)
    net = await network(rt)
    changes = plan(parse(NEW_NETWORK), net, RULES).changes
    a = adapter(rt, write=True)
    try:
        backup = await a.backup()
        try:
            await a.apply(changes, {}, 60)
            timeline = []
            for _ in range(20):
                rows = httpx.get(
                    rt["URL"] + "/rest/ip/dhcp-server",
                    auth=(rt["USER"], rt["PASSWORD"]),
                    verify=False,
                    timeout=TIMEOUT,
                    trust_env=False,
                ).json()
                state = [(r.get("name"), r.get("invalid"), r.get(".about")) for r in rows]
                timeline.append(state)
                if all(r.get("invalid") != "true" for r in rows):
                    break
                await asyncio.sleep(1)
            assert len(timeline) == 1, timeline
            after = merge([SITE], [await a.observe()])
            dhcp = [s for s in after.dhcp_servers if s.segment_id == LAB]
            seen = {
                "dhcp": [s.model_dump(mode="json") for s in dhcp],
                "menus": menus(
                    rt, "/rest/ip/dhcp-server", "/rest/ip/pool", "/rest/ip/dhcp-server/network"
                ),
            }
            assert len(dhcp) == 1, seen
            (s,) = dhcp
            assert s.enabled and s.lease_seconds == 3600, seen
            assert [(str(p.start), str(p.end)) for p in s.pools] == [
                ("203.0.113.100", "203.0.113.199")
            ], seen
            assert [str(x) for x in s.dns_servers] == ["203.0.113.1"], seen
            assert [(r.mac, str(r.address)) for r in s.reservations] == [
                ("02:00:00:00:00:60", "203.0.113.60")
            ], seen
        finally:
            await a.restore(backup)
    finally:
        await a.close()
    assert_same_menus(raw, menus(rt, *WRITTEN))


async def test_new_network_with_dhcp_and_reservation_then_revert(
    svc: Services, rt: dict[str, str]
) -> None:
    before = configuration(await network(rt))
    raw = menus(rt, *WRITTEN)
    kinds = {ChangeKind.ROUTER, ChangeKind.DHCP, ChangeKind.RESERVATION}
    d, cid = await deploy(svc, NEW_NETWORK, kinds)
    after = await network(rt)
    seg = after.segment(LAB)
    assert seg is not None and seg.name == "Lab6" and seg.vlan == 60, seg
    assert (LAB, "203.0.113.1/24") in {(s.segment_id, str(s.interface)) for s in after.subnets}
    dhcp = next(s for s in after.dhcp_servers if s.segment_id == LAB)
    assert dhcp.enabled and dhcp.lease_seconds == 3600
    assert [(str(p.start), str(p.end)) for p in dhcp.pools] == [("203.0.113.100", "203.0.113.199")]
    assert str(dhcp.router) == "203.0.113.1"
    assert [(r.mac, str(r.address), r.hostname) for r in dhcp.reservations] == [
        ("02:00:00:00:00:60", "203.0.113.60", "cam")
    ]
    await revert(svc, d, cid)
    assert_unchanged(before, configuration(await network(rt)))
    assert_same_menus(raw, menus(rt, *WRITTEN))


CHANGE_EXISTING = """
sites:
  home:
    segments:
      - vlan: 20
        name: IoT_net
        gateway: {device: rt, address: 198.51.100.2/24}
      - vlan: native
        dhcp:
          enabled: true
          pool: [192.0.2.120, 192.0.2.180]
          dns: [192.0.2.1]
          lease_seconds: 7200
        reservations:
          - {mac: "02:00:00:00:00:10", address: 192.0.2.11, hostname: printer}
    ports:
      - {device: rt, port: ether3, untagged: native, tagged: [20, 70]}
"""


async def test_change_router_dhcp_reservation_and_port_then_revert(
    svc: Services, rt: dict[str, str]
) -> None:
    before = configuration(await network(rt))
    raw = menus(rt, *WRITTEN)
    kinds = {ChangeKind.ROUTER, ChangeKind.DHCP, ChangeKind.RESERVATION, ChangeKind.PORT}
    d, cid = await deploy(svc, CHANGE_EXISTING, kinds)
    after = await network(rt)
    iot = after.segment(IOT)
    assert iot is not None and iot.name == "IoT_net", iot
    assert (IOT, "198.51.100.2/24") in {(s.segment_id, str(s.interface)) for s in after.subnets}
    lan = next(s for s in after.dhcp_servers if s.segment_id == LAN)
    assert [(str(p.start), str(p.end)) for p in lan.pools] == [("192.0.2.120", "192.0.2.180")]
    assert lan.lease_seconds == 7200
    assert [(r.mac, str(r.address)) for r in lan.reservations] == [
        ("02:00:00:00:00:10", "192.0.2.11")
    ]
    trunk = {
        seg.vlan
        for seg in after.segments
        for m in seg.members
        if m.port_id == "rt/port/ether3" and m.mode.value == "tagged"
    }
    assert trunk == {20, 70}
    await revert(svc, d, cid)
    assert_unchanged(before, configuration(await network(rt)))
    assert_same_menus(raw, menus(rt, *WRITTEN))


PORT_ONLY = (
    "sites:\n  home:\n    ports:\n"
    "      - {device: rt, port: ether2, untagged: native, tagged: [20, 80]}\n"
)
ROUTER_ONLY = """
sites:
  home:
    segments:
      - vlan: 90
        name: Lab9
        gateway: {device: rt, address: 203.0.113.129/25}
"""


@pytest.mark.parametrize(
    ("want", "kinds"),
    [(PORT_ONLY, {ChangeKind.PORT}), (ROUTER_ONLY, {ChangeKind.ROUTER})],
    ids=["vlan-on-a-port", "new-router-interface"],
)
async def test_backup_and_restore(
    svc: Services, rt: dict[str, str], want: str, kinds: set[ChangeKind]
) -> None:
    """A deployment, then the restore of its backup (the menu snapshot, not the inverse)."""
    before = configuration(await network(rt))
    raw = menus(rt, *WRITTEN)
    _, cid = await deploy(svc, want, kinds)
    rec = svc.store.change(cid)
    assert rec is not None and rec.devices[0].backup_id
    backup = svc.store.backup(rec.devices[0].backup_id)
    assert backup is not None and backup.format == "routeros-export"
    assert "/interface bridge" in json.loads(backup.content)["export"]
    d = Deployer(svc.runner)
    restore = await d.restore_backup(rec.devices[0].backup_id, "integration test", "ci")
    d.approve(restore.id, "ci")
    done = await d.deploy(restore.id)
    assert done.status is ChangeStatus.APPLIED, events(svc, restore.id)
    assert_unchanged(before, configuration(await network(rt)))
    assert_same_menus(raw, menus(rt, *WRITTEN))


def test_vm_still_answers(rt: dict[str, str]) -> None:
    """Last: the router survived the suite (no lock-out through a write)."""
    r = httpx.get(
        rt["URL"] + "/rest/system/resource",
        auth=(rt["USER"], rt["PASSWORD"]),
        verify=False,
        timeout=TIMEOUT,
        trust_env=False,
    )
    assert r.status_code == 200
