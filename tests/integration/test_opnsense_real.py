"""The OPNsense adapter against the real OPNsense in QEMU (#138).

The VM (tools/integration/opnsense/vm.py) is preseeded with: LAN vtnet0 192.0.2.1/24 +
2001:db8:1::1/64, WAN vtnet1 (DHCP), VLAN 20 "IoT" on the trunk vtnet2 assigned as opt1
198.51.100.1/24, Kea DHCPv4 on LAN (pool 192.0.2.100-199, reservation 02:00:00:00:00:10 ->
192.0.2.10 "printer"), an Unbound host override nas.home.example -> 192.0.2.10, and two API
users with the read and write privileges of docs/adapters/opnsense.md.

Every write test ends with the firewall as it started (revert or restore through the
Deployer), so the tests can run in any order against one VM.
"""

from __future__ import annotations

from collections.abc import Iterator
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from factories import SITE
from integration.conftest import env_target
from signalbox.adapters import AdapterContext, AdapterError
from signalbox.adapters.https import fingerprint, peer_certificate
from signalbox.adapters.opnsense import OpnsenseAdapter, OpnsenseConfig
from signalbox.changes import Change, ChangeKind, ReservationValue, plan
from signalbox.deploy import Deployer
from signalbox.desired import parse
from signalbox.history import ChangeStatus, DeviceStatus
from signalbox.merge import merge
from signalbox.model import DeviceRole, Network
from signalbox.model import DeviceStatus as ReadStatus
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.store import DeviceRecord
from signalbox.testing import assert_contract

LAN, IOT, LAB = "home/segment/native", "home/segment/20", "home/segment/60"
TIMEOUT = 60.0  # interface and Kea reconfigure calls take seconds on the real firewall


@pytest.fixture(scope="module")
def target() -> dict[str, str]:
    return env_target(
        "OPNSENSE", "URL", "FINGERPRINT", "KEY", "SECRET", "WRITE_KEY", "WRITE_SECRET"
    )


def adapter(
    target: dict[str, str], write: bool = False, pin: str | None = "", secret: str | None = None
) -> OpnsenseAdapter:
    prefix = "WRITE_" if write else ""
    config = OpnsenseConfig(
        url=target["URL"],
        api_key=SecretStr(target[f"{prefix}KEY"]),
        api_secret=SecretStr(secret if secret is not None else target[f"{prefix}SECRET"]),
    )
    ctx = AdapterContext(
        site_id="home",
        device_id="fw",
        device_name="fw",
        role=DeviceRole.GATEWAY,
        config=config,
        pinned_fingerprint=target["FINGERPRINT"] if pin == "" else pin,
        timeout=TIMEOUT,
    )
    return OpnsenseAdapter(ctx)


async def network(target: dict[str, str]) -> Network:
    a = adapter(target)
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
    assert not found, "the firewall did not return to its configuration:\n" + "\n".join(found)


# --- reading -------------------------------------------------------------------------------


async def test_certificate_pinning_with_the_real_certificate(target: dict[str, str]) -> None:
    host = target["URL"].split("://", 1)[1]
    name, port = host.rsplit(":", 1)
    seen = fingerprint(await peer_certificate(name, int(port), TIMEOUT))
    assert seen == target["FINGERPRINT"]
    for pin in (None, "00" * 32):
        a = adapter(target, pin=pin)
        try:
            snap = await a.observe()
        finally:
            await a.close()
        assert snap.status is ReadStatus.UNTRUSTED, snap.errors
        assert seen in snap.errors[0].message


async def test_read_contract(target: dict[str, str]) -> None:
    a = adapter(target)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    assert snap.device.firmware is not None
    assert snap.device.firmware.current.startswith("26.7"), snap.device.firmware


async def test_mapping_of_the_preseeded_firewall(target: dict[str, str]) -> None:
    net = await network(target)
    ports = {p.name: p for p in net.ports}
    assert {"vtnet0", "vtnet1", "vtnet2"} <= set(ports), sorted(ports)
    assert ports["vtnet0"].mac == "02:00:00:00:01:00"
    lan = net.segment(LAN)
    assert lan is not None and lan.name == "LAN"
    assert [(m.port_id, m.mode.value) for m in lan.members] == [("fw/port/vtnet0", "untagged")]
    iot = net.segment(IOT)
    assert iot is not None and iot.name == "IoT" and iot.vlan == 20
    assert [(m.port_id, m.mode.value) for m in iot.members] == [("fw/port/vtnet2", "tagged")]
    assert not any(s.id.endswith("/wan") for s in net.segments)  # the WAN is the uplink
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
    assert [(r.mac, str(r.address), r.hostname) for r in kea.reservations] == [
        ("02:00:00:00:00:10", "192.0.2.10", "printer")
    ]
    (dns,) = net.dns_services
    assert dns.enabled
    assert [(h.name, str(h.address)) for h in dns.host_records] == [
        ("nas.home.example", "192.0.2.10")
    ]
    assert ip_address("192.0.2.1") in dns.listen


async def test_refused_api_key_is_auth_failed(target: dict[str, str]) -> None:
    a = adapter(target, secret="not-the-secret")
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is ReadStatus.AUTH_FAILED, snap.errors


async def test_read_user_has_no_write_privileges(target: dict[str, str]) -> None:
    """The documented read privileges do not include the configuration history."""
    a = adapter(target)
    try:
        with pytest.raises(AdapterError, match="HTTP 403"):
            await a.backup()
    finally:
        await a.close()


# --- writing through the Deployer ----------------------------------------------------------


@pytest.fixture
def svc(tmp_path: Path, target: dict[str, str]) -> Iterator[Services]:
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
        pinned_fingerprint=target["FINGERPRINT"],
    )
    cfg = {"url": target["URL"], "api_key": target["WRITE_KEY"]}
    cfg["api_secret"] = target["WRITE_SECRET"]
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
    svc: Services, target: dict[str, str]
) -> None:
    before = configuration(await network(target))
    kinds = {ChangeKind.ROUTER, ChangeKind.DHCP, ChangeKind.RESERVATION}
    d, cid = await deploy(svc, NEW_NETWORK, kinds)
    after = await network(target)
    seg = after.segment(LAB)
    assert seg is not None and seg.name == "Lab6"
    assert [(m.port_id, m.mode.value) for m in seg.members] == [("fw/port/vtnet0", "tagged")]
    kea = next(s for s in after.dhcp_servers if s.segment_id == LAB)
    assert kea.enabled and kea.lease_seconds == 3600
    assert [(r.mac, str(r.address)) for r in kea.reservations] == [
        ("02:00:00:00:00:60", "203.0.113.60")
    ]
    await revert(svc, d, cid)
    assert_unchanged(before, configuration(await network(target)))


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
    svc: Services, target: dict[str, str]
) -> None:
    before = configuration(await network(target))
    kinds = {ChangeKind.ROUTER, ChangeKind.DHCP, ChangeKind.RESERVATION, ChangeKind.PORT}
    d, cid = await deploy(svc, CHANGE_EXISTING, kinds)
    after = await network(target)
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
    assert_unchanged(before, configuration(await network(target)))


async def test_backup_and_restore_through_the_configuration_history(
    svc: Services, target: dict[str, str]
) -> None:
    before = configuration(await network(target))
    want = "sites:\n  home:\n    ports:\n      - {device: fw, port: vtnet2, tagged: [20, 80]}\n"
    _, cid = await deploy(svc, want, {ChangeKind.PORT})
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
    assert_unchanged(before, configuration(await network(target)))


async def test_validation_error_of_the_firewall_names_the_field(target: dict[str, str]) -> None:
    """A reservation outside its subnet: the planner sends it, Kea's model refuses it."""
    c = Change(
        kind=ChangeKind.RESERVATION,
        device_id="fw",
        site_id="home",
        key=f"{LAN}/02:00:00:00:00:99",
        old=None,
        new=ReservationValue(mac="02:00:00:00:00:99", address=ip_address("198.51.100.99")),
    )
    a = adapter(target, write=True)
    try:
        with pytest.raises(AdapterError, match=r"the firewall refused the change \(reservation\."):
            await a.apply([c], {}, 60)
    finally:
        await a.close()
    after = await network(target)
    lan = next(s for s in after.dhcp_servers if s.segment_id == LAN)
    assert "02:00:00:00:00:99" not in {r.mac for r in lan.reservations}


def test_vm_still_answers(target: dict[str, str]) -> None:
    """Last: the firewall survived the suite (no lock-out through a write)."""
    r = httpx.get(
        target["URL"] + "/api/core/firmware/status",
        auth=(target["KEY"], target["SECRET"]),
        verify=False,
        timeout=TIMEOUT,
        trust_env=False,
    )
    assert r.status_code == 200
