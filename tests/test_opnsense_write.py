"""OPNsense write side against the simulator: every kind, plans, backup/restore, deployments."""

from __future__ import annotations

import json
from collections.abc import Iterator
from ipaddress import ip_address, ip_interface
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from factories import SITE
from signalbox.adapters import AdapterContext, AdapterError, Backup
from signalbox.adapters.opnsense import KEA, OpnsenseAdapter, OpnsenseConfig
from signalbox.adapters.opnsense import write as w
from signalbox.changes import (
    AnyValue,
    Change,
    ChangeKind,
    DhcpValue,
    PortValue,
    ReservationValue,
    RouterValue,
    plan,
)
from signalbox.deploy import Deployer, current_value, matches
from signalbox.desired import parse
from signalbox.history import ChangeStatus, DeviceStatus
from signalbox.merge import merge
from signalbox.model import DeviceRole, Network
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.sim.opnsense import (
    INTERFACES,
    KEY,
    SECRET,
    VLANS,
    OpnsenseSimulator,
    from_xml,
    to_xml,
)
from signalbox.sim.server import serve
from signalbox.store import DeviceRecord

SIM = OpnsenseSimulator()
IOT, GUEST, LAB, NEW = (f"home/segment/{v}" for v in (20, 30, 40, 60))
LAN = "home/segment/native"


@pytest.fixture(scope="module")
def url() -> Iterator[str]:
    with serve(SIM.app()) as u:
        yield u


@pytest.fixture(autouse=True)
def sim() -> OpnsenseSimulator:
    SIM.__dict__.update(OpnsenseSimulator().__dict__)
    return SIM


def without_guest(sim: OpnsenseSimulator) -> None:
    """Free 203.0.113.0/24 for a new network: drop the Guest VLAN and the ISC server."""
    rows = sim.data[INTERFACES]["rows"]
    rows[:] = [r for r in rows if r["identifier"] != "opt2"]
    vlans = sim.data[VLANS]["rows"]
    vlans[:] = [v for v in vlans if v["tag"] != "30"]
    del sim.data["/api/dhcpv4/service/status"], sim.data["/api/dhcpv4/leases/search_lease"]
    del sim.data[KEA]["dhcpv4"]["general"]["interfaces"]["opt2"]


def adapter(url: str) -> OpnsenseAdapter:
    config = OpnsenseConfig(
        url=url, api_key=SecretStr(KEY), api_secret=SecretStr(SECRET), allow_insecure_http=True
    )
    ctx = AdapterContext(
        site_id="home", device_id="fw", device_name="fw", role=DeviceRole.GATEWAY, config=config
    )
    return OpnsenseAdapter(ctx)


async def network(url: str) -> Network:
    a = adapter(url)
    try:
        return merge([SITE], [await a.observe()])
    finally:
        await a.close()


def shape(net: Network) -> Any:
    """The network without observation times (to compare two reads)."""

    def strip(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: strip(v) for k, v in value.items() if k != "observed_at"}
        if isinstance(value, list):
            return [strip(v) for v in value]
        return value

    return strip(net.model_dump(mode="json"))


def change(net: Network, kind: ChangeKind, key: str, new: AnyValue | None) -> Change:
    probe = Change.model_construct(kind=kind, device_id="fw", site_id="home", key=key)
    old = current_value(net, probe)
    if kind is ChangeKind.PORT and new is None:
        new = PortValue()
    return Change(kind=kind, device_id="fw", site_id="home", key=key, old=old, new=new)


async def apply(url: str, *changes: Change) -> Network:
    a = adapter(url)
    try:
        result = await a.apply(list(changes), {}, 60)
        assert result.confirm_deadline is None
    finally:
        await a.close()
    after = await network(url)
    for c in changes:
        assert matches(after, c, c.new, {}), (c.describe(), current_value(after, c))
    return after


async def refused(url: str, c: Change, match: str) -> None:
    a = adapter(url)
    try:
        with pytest.raises(AdapterError, match=match):
            await a.plan_changes([c], {})
        with pytest.raises(AdapterError, match=match):
            await a.apply([c], {}, 60)
    finally:
        await a.close()


def router(vlan: int | None, address: str, name: str | None) -> RouterValue:
    return RouterValue(vlan=vlan, name=name, address=ip_interface(address))


def dhcp(pool: tuple[str, str] | None, dns: list[str] | None, lease: int | None) -> DhcpValue:
    return DhcpValue(
        enabled=True,
        pool=(ip_address(pool[0]), ip_address(pool[1])) if pool else None,
        dns=[ip_address(d) for d in dns] if dns is not None else None,
        lease_seconds=lease,
    )


def res(mac: str, address: str, hostname: str | None = None) -> ReservationValue:
    return ReservationValue(mac=mac, address=ip_address(address), hostname=hostname)


def test_manifest_declares_writes() -> None:
    assert OpnsenseAdapter.manifest.writes == {
        ChangeKind.ROUTER,
        ChangeKind.DHCP,
        ChangeKind.RESERVATION,
        ChangeKind.PORT,
    }


# --- router interfaces -----------------------------------------------------------------------


async def test_router_update_existing_interface(url: str, sim: OpnsenseSimulator) -> None:
    net = await network(url)
    c = change(net, ChangeKind.ROUTER, IOT, router(20, "198.51.100.2/24", "IoT_net"))
    await apply(url, c)
    assert ("/api/interfaces/assignment/set_item/opt1") in [p for p, _ in sim.posts]
    # IPv6 of the LAN survives an IPv4 change
    lan = change(net, ChangeKind.ROUTER, LAN, router(None, "192.0.2.254/24", "LAN"))
    after = await apply(url, lan)
    assert any(str(s.interface) == "2001:db8:1::1/64" for s in after.subnets)


async def test_router_create_new_vlan_and_remove_it_again(url: str, sim: OpnsenseSimulator) -> None:
    without_guest(sim)
    before = await network(url)
    c = change(before, ChangeKind.ROUTER, NEW, router(60, "203.0.113.1/24", "Lab6"))
    after = await apply(url, c)
    vlan = next(v for v in sim.data[VLANS]["rows"] if v["tag"] == "60")
    assert vlan["vlanif"] == "vlan0.60" and vlan["if"] == "igb0"
    seg = after.segment(NEW)
    assert seg is not None and seg.name == "Lab6"
    assert "opt2" in {r["identifier"] for r in sim.data[INTERFACES]["rows"]}  # first free optN
    await apply(url, c.inverse())
    assert "60" not in {v["tag"] for v in sim.data[VLANS]["rows"]}
    assert shape(await network(url)) == shape(before)


async def test_router_create_on_an_unassigned_vlan(url: str, sim: OpnsenseSimulator) -> None:
    net = await network(url)
    await apply(url, change(net, ChangeKind.ROUTER, LAB, router(40, "192.0.2.129/25", "Lab")))
    assert not any(p.endswith("vlan_settings/add_item") for p, _ in sim.posts)


async def test_router_remove_vlan_network(url: str, sim: OpnsenseSimulator) -> None:
    net = await network(url)
    await apply(url, change(net, ChangeKind.ROUTER, IOT, None))
    assert "20" not in {v["tag"] for v in sim.data[VLANS]["rows"]}
    # removing what is not there is a no-op
    a = adapter(url)
    try:
        gone = Change(
            kind=ChangeKind.ROUTER,
            device_id="fw",
            site_id="home",
            key=IOT,
            old=router(20, "198.51.100.1/24", "IoT"),
        )
        assert await a.plan_changes([gone], {}) == []
    finally:
        await a.close()


async def test_router_refusals(url: str, sim: OpnsenseSimulator) -> None:
    net = await network(url)
    await refused(url, change(net, ChangeKind.ROUTER, LAN, None), "removes only VLAN networks")
    await refused(
        url,
        change(net, ChangeKind.ROUTER, IOT, router(20, "198.51.100.1/24", "IoT devices")),
        "letters, digits and _",
    )
    await refused(
        url,
        change(net, ChangeKind.ROUTER, NEW, router(60, "203.0.113.1/24", None)),
        "give the network a name",
    )
    await refused(
        url,
        change(net, ChangeKind.ROUTER, "home/segment/dmz", router(None, "203.0.113.1/24", "D")),
        "assign its port in the web interface",
    )
    await refused(
        url,
        change(net, ChangeKind.ROUTER, IOT, router(21, "198.51.100.1/24", "IoT")),
        "VLAN 21 does not belong",
    )
    await refused(
        url,
        change(net, ChangeKind.ROUTER, IOT, router(20, "2001:db8:20::1/64", "IoT")),
        "only IPv4",
    )
    sim.data[INTERFACES]["rows"] = [
        r for r in sim.data[INTERFACES]["rows"] if r["identifier"] != "lan"
    ]
    await refused(
        url,
        change(net, ChangeKind.ROUTER, NEW, router(60, "203.0.113.1/24", "X")),
        "no LAN port",
    )
    sim.fail[w.ASSIGN_SEARCH] = 404
    await refused(
        url,
        change(net, ChangeKind.ROUTER, IOT, router(20, "198.51.100.1/24", "IoT")),
        "26.7 or newer",
    )


async def test_locked_interface_is_not_removed(url: str, sim: OpnsenseSimulator) -> None:
    sim.locked.add("opt1")
    net = await network(url)
    a = adapter(url)
    try:
        with pytest.raises(AdapterError, match="Interface locked"):
            await a.apply([change(net, ChangeKind.ROUTER, IOT, None)], {}, 60)
    finally:
        await a.close()


# --- Kea DHCP --------------------------------------------------------------------------------


async def test_dhcp_update_pool_dns_and_lease(url: str, sim: OpnsenseSimulator) -> None:
    net = await network(url)
    new = dhcp(("198.51.100.50", "198.51.100.99"), ["192.0.2.1"], 7200)
    await apply(url, change(net, ChangeKind.DHCP, IOT, new))
    subnet = sim.data[KEA]["dhcpv4"]["subnets"]["subnet4"]["s-iot"]
    assert subnet["pools"] == "198.51.100.50-198.51.100.99"
    assert "/api/kea/service/reconfigure" in [p for p, _ in sim.posts]


async def test_dhcp_without_dns_on_an_autocollect_subnet(url: str, sim: OpnsenseSimulator) -> None:
    net = await network(url)
    lan = current_value(
        net,
        Change(
            kind=ChangeKind.DHCP,
            device_id="fw",
            site_id="home",
            key=LAN,
            new=DhcpValue(enabled=True),
        ),
    )
    assert lan is not None and lan.dns == [ip_address("192.0.2.1")]  # collected
    new = lan.model_copy(update={"dns": None})
    await apply(url, change(net, ChangeKind.DHCP, LAN, new))
    subnet = sim.data[KEA]["dhcpv4"]["subnets"]["subnet4"]["s-lan"]
    assert subnet["option_data_autocollect"] == "0"
    assert subnet["option_data"]["routers"] == "192.0.2.1"


async def test_dhcp_disable_and_remove(url: str, sim: OpnsenseSimulator) -> None:
    net = await network(url)
    off = DhcpValue(
        enabled=False,
        pool=(ip_address("198.51.100.129"), ip_address("198.51.100.190")),
        dns=[ip_address("198.51.100.1"), ip_address("192.0.2.1")],
        lease_seconds=4000,
    )
    after = await apply(url, change(net, ChangeKind.DHCP, IOT, off))
    await apply(url, change(after, ChangeKind.DHCP, IOT, None))
    assert "s-iot" not in sim.data[KEA]["dhcpv4"]["subnets"]["subnet4"]
    # turning Kea on for a network also switches the service on
    sim.data[KEA]["dhcpv4"]["general"]["enabled"] = "0"
    net = await network(url)
    lan = DhcpValue(enabled=True, pool=None, dns=None, lease_seconds=4000)
    await apply(url, change(net, ChangeKind.DHCP, LAN, lan))
    assert sim.data[KEA]["dhcpv4"]["general"]["enabled"] == "1"


async def test_dhcp_refusals(url: str, sim: OpnsenseSimulator) -> None:
    net = await network(url)
    pool = ("203.0.113.100", "203.0.113.199")
    await refused(url, change(net, ChangeKind.DHCP, GUEST, dhcp(pool, None, 60)), "ISC DHCP")
    await refused(url, change(net, ChangeKind.DHCP, NEW, dhcp(pool, None, 60)), "no IPv4 interface")
    await refused(
        url, change(net, ChangeKind.DHCP, IOT, dhcp(None, None, None)), "give lease_seconds"
    )
    await refused(
        url,
        change(
            net,
            ChangeKind.RESERVATION,
            f"{GUEST}/00:00:5e:00:53:30",
            res("00:00:5e:00:53:30", "203.0.113.11"),
        ),
        "ISC DHCP",
    )
    del sim.data[KEA]
    await refused(url, change(net, ChangeKind.DHCP, IOT, dhcp(None, None, 60)), "Kea DHCP is not")


# --- reservations ----------------------------------------------------------------------------


async def test_reservations_add_change_remove(url: str, sim: OpnsenseSimulator) -> None:
    net = await network(url)
    add = change(
        net,
        ChangeKind.RESERVATION,
        f"{LAN}/02:00:00:00:00:44",
        res("02:00:00:00:00:44", "192.0.2.44", "tv"),
    )
    move = change(
        net,
        ChangeKind.RESERVATION,
        f"{LAN}/00:00:5e:00:53:10",
        res("00:00:5e:00:53:10", "192.0.2.11"),
    )
    drop = change(net, ChangeKind.RESERVATION, f"{IOT}/00:00:5e:00:53:20", None)
    await apply(url, add, move, drop)
    assert "r-2" not in sim.data[KEA]["dhcpv4"]["reservations"]["reservation"]
    a = adapter(url)
    try:  # removing again, or without a subnet: nothing to do
        assert await a.plan_changes([drop], {}) == []
        none = Change(
            kind=ChangeKind.RESERVATION,
            device_id="fw",
            site_id="home",
            key=f"{LAB}/02:00:00:00:00:44",
            old=res("02:00:00:00:00:44", "192.0.2.44"),
        )
        assert await a.plan_changes([none], {}) == []
    finally:
        await a.close()
    await refused(
        url,
        change(
            net,
            ChangeKind.RESERVATION,
            f"{LAB}/02:00:00:00:00:45",
            res("02:00:00:00:00:45", "192.0.2.45"),
        ),
        "no Kea subnet",
    )


# --- ports -----------------------------------------------------------------------------------


async def test_port_tagged_vlans(url: str, sim: OpnsenseSimulator) -> None:
    net = await network(url)
    port = "fw/port/igb0"
    new = PortValue(untagged="native", tagged=[20, 30, 50])  # VLAN 40 goes, 50 comes
    await apply(url, change(net, ChangeKind.PORT, port, new))
    tags = {v["tag"] for v in sim.data[VLANS]["rows"]}
    assert tags == {"20", "30", "50"}
    # a second VLAN 50 elsewhere gets another device name
    sim.data[INTERFACES]["rows"][4]["is_physical"] = True  # igb2
    net = await network(url)
    await apply(url, change(net, ChangeKind.PORT, "fw/port/igb2", PortValue(tagged=[50])))
    assert "igb2_vlan50" in {v["vlanif"] for v in sim.data[VLANS]["rows"]}


async def test_port_refusals(url: str) -> None:
    net = await network(url)
    port = "fw/port/igb0"
    await refused(
        url,
        change(net, ChangeKind.PORT, port, PortValue(untagged="native", tagged=[30, 40])),
        "VLAN 20 carries the network IoT",
    )
    await refused(
        url, change(net, ChangeKind.PORT, port, PortValue(untagged=20, tagged=[])), "untagged"
    )
    await refused(url, change(net, ChangeKind.PORT, "fw/port/igb9", PortValue()), "no such port")


async def test_wlan_is_not_writable(url: str) -> None:
    from signalbox.changes import WlanValue
    from signalbox.model import Security

    c = Change(
        kind=ChangeKind.WLAN,
        device_id="fw",
        site_id="home",
        key="x",
        new=WlanValue(ssid="x", security=Security.OPEN),
    )
    a = adapter(url)
    try:
        with pytest.raises(AdapterError, match="cannot change wlan"):
            await a.plan_changes([c], {})
    finally:
        await a.close()


# --- plans -----------------------------------------------------------------------------------


async def test_plan_lists_the_exact_calls(url: str, sim: OpnsenseSimulator) -> None:
    without_guest(sim)
    net = await network(url)
    changes = [
        change(net, ChangeKind.ROUTER, NEW, router(60, "203.0.113.1/24", "Lab6")),
        change(net, ChangeKind.DHCP, NEW, dhcp(("203.0.113.100", "203.0.113.199"), None, 3600)),
        change(
            net,
            ChangeKind.RESERVATION,
            f"{NEW}/02:00:00:00:00:60",
            res("02:00:00:00:00:60", "203.0.113.60", "cam"),
        ),
    ]
    a = adapter(url)
    try:
        calls = await a.plan_changes(changes, {"unused": "secret value"})
    finally:
        await a.close()
    assert [(c.method, c.target) for c in calls] == [
        ("POST", w.VLAN_ADD),
        ("POST", w.VLAN_APPLY),
        ("POST", w.ASSIGN_ADD),
        ("POST", w.ASSIGN_APPLY),
        ("POST", w.KEA_ADD_SUBNET),
        ("POST", w.KEA_SET),
        ("POST", w.KEA_ADD_RES),
        ("POST", w.KEA_APPLY),
    ]
    assert calls[0].payload == {
        "vlan": {
            "if": "igb0",
            "tag": "60",
            "pcp": "0",
            "proto": "",
            "descr": "Lab6",
            "vlanif": "vlan0.60",
        }
    }
    assert calls[2].payload == {
        "interface": {
            "if": "vlan0.60",
            "lock": "0",
            "enable": "1",
            "type4": "staticv4",
            "ipaddr": "203.0.113.1/24",
            "descr": "Lab6",
        }
    }
    assert calls[4].payload["subnet4"]["option_data"] == {
        "domain_name_servers": "",
        "routers": "203.0.113.1",
    }
    assert calls[5].payload == {
        "dhcpv4": {
            "general": {"enabled": "1", "interfaces": "lan,opt1,{new interface on vlan0.60}"}
        }
    }
    assert calls[6].payload["reservation"]["subnet"] == "{new subnet 203.0.113.0/24}"
    text = json.dumps([c.model_dump() for c in calls])
    assert KEY not in text and SECRET not in text and "secret value" not in text
    assert sim.posts == []  # planning sends nothing


# --- answers and errors ----------------------------------------------------------------------


async def test_validation_errors_name_the_field(url: str, sim: OpnsenseSimulator) -> None:
    net = await network(url)
    sim.invalid[w.VLAN_ADD] = {"vlan.tag": "Tag for this device must be unique."}
    port = change(
        net, ChangeKind.PORT, "fw/port/igb0", PortValue(untagged="native", tagged=[20, 30, 40, 50])
    )
    a = adapter(url)
    try:
        with pytest.raises(AdapterError, match=r"refused the change \(vlan.tag: Tag for this"):
            await a.apply([port], {}, 60)
        # the firewall's own checks
        outside = change(
            net,
            ChangeKind.RESERVATION,
            f"{LAN}/02:00:00:00:00:44",
            res("02:00:00:00:00:44", "198.51.100.44"),
        )
        with pytest.raises(AdapterError, match=r"reservation\.ip_address: Address not in subnet"):
            await a.apply([outside], {}, 60)
    finally:
        await a.close()


@pytest.mark.parametrize(
    ("answer", "match"),
    [
        ([], "not an object"),
        ({"result": "weird"}, "result 'weird'"),
        ({"result": "failed"}, "refused the change$"),
    ],
)
async def test_unexpected_write_answers(
    url: str, sim: OpnsenseSimulator, monkeypatch: pytest.MonkeyPatch, answer: Any, match: str
) -> None:
    monkeypatch.setattr(OpnsenseSimulator, "write", lambda self, path, body: answer)
    a = adapter(url)
    try:
        with pytest.raises(AdapterError, match=match):
            await a._send(w.Call("x", w.KEA_APPLY))
    finally:
        await a.close()


async def test_write_endpoint_missing(url: str, sim: OpnsenseSimulator) -> None:
    sim.fail[w.KEA_APPLY] = 404
    a = adapter(url)
    try:
        with pytest.raises(AdapterError, match="not available on this firewall"):
            await a._send(w.Call("x", w.KEA_APPLY))
    finally:
        await a.close()


# --- backup and restore ----------------------------------------------------------------------


async def test_backup_and_restore_round_trip(url: str, sim: OpnsenseSimulator) -> None:
    before_state, before_net = sim.state(), await network(url)
    a = adapter(url)
    try:
        backup = await a.backup()
        assert backup.format == "opnsense-config-xml" and backup.device_id == "fw"
        assert backup.content.startswith("<?xml") and "<revision>" in backup.content
        assert from_xml(backup.content) == before_state
        await a.apply(
            [
                change(
                    before_net,
                    ChangeKind.PORT,
                    "fw/port/igb0",
                    PortValue(untagged="native", tagged=[20, 30]),
                )
            ],
            {},
            60,
        )
        assert sim.state() != before_state
        await a.restore(backup)
        await a.restore(backup)  # idempotent
    finally:
        await a.close()
    assert sim.state() == before_state
    assert shape(await network(url)) == shape(before_net)


async def test_restore_refusals(
    url: str, sim: OpnsenseSimulator, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = adapter(url)
    try:
        backup = await a.backup()
        with pytest.raises(AdapterError, match="not an OPNsense backup"):
            await a.restore(backup.model_copy(update={"format": "fake"}))
        with pytest.raises(AdapterError, match=r"not a config\.xml"):
            await a.restore(backup.model_copy(update={"content": "<broken"}))
        with pytest.raises(AdapterError, match="no revision time"):
            await a.restore(backup.model_copy(update={"content": "<other/>"}))
        lost = to_xml(sim.state(), "1600000000.0000", "pruned")
        with pytest.raises(AdapterError, match="no longer in the configuration history"):
            await a.restore(backup.model_copy(update={"content": lost}))
        # one revision with the same time but other bytes (re-encoded): still used
        same = backup.content.replace('<?xml version="1.0"?>\n', "")
        await a.restore(backup.model_copy(update={"content": same}))
        monkeypatch.setattr(OpnsenseSimulator, "revert", lambda self, rid: {"status": "not_found"})
        with pytest.raises(AdapterError, match="revert refused"):
            await a.restore(backup)
        monkeypatch.setattr(OpnsenseSimulator, "backups", lambda self: {"items": []})
        with pytest.raises(AdapterError, match="history is empty"):
            await a.backup()
        monkeypatch.setattr(OpnsenseSimulator, "backups", lambda self: {"nope": 1})
        with pytest.raises(AdapterError, match="no list of items"):
            await a.backup()
    finally:
        await a.close()


async def test_restore_tolerates_missing_components(url: str, sim: OpnsenseSimulator) -> None:
    a = adapter(url)
    try:
        backup = await a.backup()
        sim.fail[w.KEA_APPLY] = 404
        await a.restore(backup)
        sim.fail[w.KEA_APPLY] = 500
        with pytest.raises(AdapterError, match="HTTP 500"):
            await a.restore(backup)
    finally:
        await a.close()


async def test_confirm_is_a_no_op(url: str) -> None:
    a = adapter(url)
    try:
        await a.confirm()
    finally:
        await a.close()


def test_simulator_xml_round_trip() -> None:
    state = {"a": [1, 2.5, True, None, "x", {"b": ""}]}
    assert from_xml(to_xml(state, "1", "d")) == state
    with pytest.raises(ValueError, match=r"not a config\.xml"):
        from_xml("<opnsense/>")


# --- a whole deployment ----------------------------------------------------------------------

WANT = """
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


@pytest.fixture
def svc(tmp_path: Path, url: str, sim: OpnsenseSimulator) -> Iterator[Services]:
    without_guest(sim)
    env = {"SIGNALBOX_AUTH_PASSWORD": "x" * 12, "SIGNALBOX_DEPLOY_ENABLED": "true"}
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
    )
    cfg = {"url": url, "api_key": KEY, "api_secret": SECRET, "allow_insecure_http": True}
    s.store.put_device(rec, cfg, OpnsenseConfig)
    yield s
    s.close()


async def deploy(svc: Services, text: str = WANT) -> tuple[Deployer, str, ChangeStatus]:
    await svc.runner.observe_all()
    p = plan(parse(text), svc.runner.network(), RULES)
    assert [c.kind for c in p.changes] == [
        ChangeKind.ROUTER,
        ChangeKind.DHCP,
        ChangeKind.RESERVATION,
    ]
    d = Deployer(svc.runner)
    rec = await d.prepare(p, "a network for the lab", "tester")
    d.approve(rec.id, "tester", override="lab test" if rec.plan.blocking else None)
    return d, rec.id, (await d.deploy(rec.id)).status


async def test_deployment_applies_and_reverts(
    svc: Services, sim: OpnsenseSimulator, url: str
) -> None:
    before_net = await network(url)
    d, cid, status = await deploy(svc)
    rec = svc.store.change(cid)
    assert rec is not None
    assert status is ChangeStatus.APPLIED, [e.detail for e in svc.store.events(cid)]
    assert rec.devices[0].status is DeviceStatus.CONFIRMED and rec.devices[0].backup_id
    assert plan(parse(WANT), svc.runner.network(), RULES).changes == []
    back = await d.revert(cid, "lab closed", "tester")
    d.approve(back.id, "tester", override="x" if back.plan.blocking else None)
    assert (await d.deploy(back.id)).status is ChangeStatus.APPLIED
    assert shape(await network(url)) == shape(before_net)


async def test_failure_after_apply_restores_the_backup(
    svc: Services, sim: OpnsenseSimulator
) -> None:
    before = sim.state()
    sim.invalid[w.KEA_ADD_RES] = {"reservation.hw_address": "Duplicate entry exists."}
    _, cid, status = await deploy(svc)
    assert status is ChangeStatus.ROLLED_BACK
    rec = svc.store.change(cid)
    assert rec is not None
    assert "reservation.hw_address" in (rec.devices[0].error or "")
    assert rec.devices[0].status is DeviceStatus.ROLLED_BACK
    assert sim.state() == before
    assert any(p.startswith(w.REVERT) for p, _ in sim.posts)


async def test_backup_object_is_plain_text(url: str) -> None:
    a = adapter(url)
    try:
        b = await a.backup()
    finally:
        await a.close()
    assert isinstance(Backup.model_validate_json(b.model_dump_json()).content, str)


# --- the simulated firewall's own checks -----------------------------------------------------

VLAN = {"if": "igb0", "tag": "50", "vlanif": "vlan0.50"}
SUBNET = {"subnet": "203.0.113.0/25", "pools": ""}
RES = {"subnet": "s-lan", "ip_address": "192.0.2.50", "hw_address": "02:00:00:00:00:50"}


@pytest.mark.parametrize(
    ("path", "body", "field"),
    [
        (w.VLAN_ADD, {"vlan": {**VLAN, "tag": "0"}}, "vlan.tag"),
        (w.VLAN_ADD, {"vlan": {**VLAN, "if": "igb7"}}, "vlan.if"),
        (w.VLAN_ADD, {"vlan": {**VLAN, "tag": "20"}}, "vlan.tag"),
        (w.VLAN_ADD, {"vlan": {**VLAN, "vlanif": "vlan01"}}, "vlan.vlanif"),
        (w.VLAN_DEL + "v-20", {}, "vlan.vlanif"),
        (w.ASSIGN_ADD, {"interface": {"if": "vlan03", "ipaddr": "x"}}, "interface.ipaddr"),
        (w.ASSIGN_ADD, {"interface": {"if": "vlan03", "ipaddr": "192.0.2.1"}}, "interface.ipaddr"),
        (w.ASSIGN_ADD, {"interface": {"if": "vlan03", "descr": "a b"}}, "interface.descr"),
        (w.ASSIGN_ADD, {"interface": {"if": "nope"}}, "interface.if"),
        (w.ASSIGN_ADD, {"interface": {"if": "vlan01"}}, "interface.if"),
        (w.KEA_SET, {"dhcpv4": {"general": {"interfaces": "wan"}}}, "dhcpv4.general.interfaces"),
        (w.KEA_ADD_SUBNET, {"subnet4": {"subnet": "x"}}, "subnet4.subnet"),
        (w.KEA_ADD_SUBNET, {"subnet4": {**SUBNET, "pools": "x-y"}}, "subnet4.pools"),
        (
            w.KEA_ADD_SUBNET,
            {"subnet4": {**SUBNET, "pools": "192.0.2.1-192.0.2.9"}},
            "subnet4.pools",
        ),
        (
            w.KEA_ADD_SUBNET,
            {"subnet4": {**SUBNET, "valid_lifetime": "x"}},
            "subnet4.valid_lifetime",
        ),
        (w.KEA_ADD_SUBNET, {"subnet4": {"subnet": "192.0.2.0/24"}}, "subnet4.subnet"),
        (w.KEA_ADD_RES, {"reservation": {**RES, "subnet": "s-x"}}, "reservation.subnet"),
        (w.KEA_ADD_RES, {"reservation": {**RES, "ip_address": "x"}}, "reservation.ip_address"),
        (w.KEA_ADD_RES, {"reservation": {**RES, "hw_address": "x"}}, "reservation.hw_address"),
        (
            w.KEA_ADD_RES,
            {"reservation": {**RES, "hw_address": "00:00:5e:00:53:10"}},
            "reservation.hw_address",
        ),
    ],
)
def test_simulator_validations(path: str, body: dict[str, Any], field: str) -> None:
    sim = OpnsenseSimulator()
    answer = sim.write(path, body)
    assert answer["result"] == "failed" and field in answer["validations"]


@pytest.mark.parametrize(
    ("path", "result"),
    [
        (w.VLAN_DEL + "v-x", "not found"),
        (w.ASSIGN_SET + "opt9", "failed"),
        (w.ASSIGN_DEL + "opt9", "not found"),
        (w.KEA_SET_SUBNET + "s-x", "failed"),
        (w.KEA_DEL_SUBNET + "s-x", "not found"),
        (w.KEA_SET_RES + "r-x", "failed"),
        (w.KEA_DEL_RES + "r-x", "not found"),
    ],
)
def test_simulator_unknown_items(path: str, result: str) -> None:
    assert OpnsenseSimulator().write(path, {})["result"] == result


def test_simulator_odds_and_ends() -> None:
    sim = OpnsenseSimulator()
    assert sim.write("/api/kea/dhcpv4/nothing", {}) is None
    assert sim.write("/api/other", {}) is None
    assert sim.revert("config-x.xml") == {"status": "not_found"}
    answer = sim.write(w.ASSIGN_ADD, {"interface": {"if": "vlan03"}})
    assert answer["uuid"] == "opt3" and "opt3" in sim.locked  # locked by default
    assert sim.write(w.KEA_SET_RES + "r-1", {"reservation": RES})["result"] == "saved"
    del sim.data[KEA]
    assert sim.write(w.KEA_SET, {}) is None
    with pytest.raises(KeyError):
        sim._kea()


async def test_download_of_an_unknown_revision_is_empty(url: str) -> None:
    a = adapter(url)
    try:
        with pytest.raises(AdapterError, match=r"not a config\.xml"):
            await a._download("config-0.xml")
    finally:
        await a.close()


def test_write_helpers() -> None:
    assert w._tag({"tag": "x"}) is None
    assert w._refers("s-1,s-2", "s-2") and not w._refers(None, "s-1")
    assert w._refers({"s-1": "192.0.2.0/24"}, "s-1")
    assert not w._same_mac("nonsense", "02:00:00:00:00:01")


async def test_planner_state_edges(url: str, sim: OpnsenseSimulator) -> None:
    sim.data[KEA]["dhcpv4"]["subnets"]["subnet4"]["s-bad"] = {"subnet": "not a network"}
    a = adapter(url)
    try:
        st = await a._write_state()
    finally:
        await a.close()
    lan = st.iface(LAN)
    assert lan is not None and st.subnet_of(lan) is not None
    guest = st.iface(GUEST)  # ISC: no Kea subnet; every subnet is looked at, the broken one too
    assert guest is not None and st.subnet_of(guest) is None
    st.layout.ifaces.remove(lan)
    assert st.lan_parent(required=False) is None
