"""Topology, inventory and the VLAN-scope rules on small hand-built networks."""

from __future__ import annotations

from typing import Any

import pytest

from factories import SITE, annotated, annotation, device, iface, ip, port
from signalbox.model import (
    Band,
    Client,
    DeviceRole,
    Link,
    LinkKind,
    LinkOrigin,
    Membership,
    Neighbour,
    Network,
    Port,
    PortKind,
    PortMembership,
    Radio,
    ReadError,
    Security,
    Segment,
    SegmentPurpose,
    Site,
    Subnet,
    Wlan,
    port_id,
    segment_id,
)
from signalbox.rules import Finding, RuleSettings, Severity, evaluate, rule_enabled
from signalbox.rules.builtin import RULES
from signalbox.rules.topology_checks import (
    duplicate_device,
    hidden_device,
    lag_consistent,
    management_separate,
    single_point,
    unknown_neighbour,
    unknown_network_device,
)
from signalbox.rules.vlan import address_segment, slow, trunk_scope
from signalbox.sim.openwrt import OpenWrtSim

T, U = Membership.TAGGED, Membership.UNTAGGED
LAN = segment_id(SITE.id, None)
IOT = segment_id(SITE.id, 20)
CAMS = segment_id(SITE.id, 40)
MGMT = segment_id(SITE.id, 99)
NAMES = {None: "LAN", 20: "IoT", 40: "Cameras", 99: "Management"}


def link(a: str, b: str, **kw: Any) -> Link:
    return Link(
        id=kw.pop("id", f"{a}~{b}"), a=a, b=b, origin=kw.pop("origin", LinkOrigin.LLDP), **kw
    )


def seg(vlan: int | None, members: dict[str, Membership], site: str = SITE.id) -> Segment:
    return Segment(
        id=segment_id(site, vlan),
        site_id=site,
        vlan=vlan,
        name=NAMES.get(vlan),
        members=[PortMembership(port_id=p, mode=m) for p, m in members.items()],
    )


def subnet(vlan: int | None, cidr: str, dev: str = "gw") -> Subnet:
    sid = segment_id(SITE.id, vlan)
    return Subnet(id=f"{dev}/subnet/{sid}", segment_id=sid, interface=iface(cidr), device_id=dev)


def wlan(dev: str, ssid: str, segment: str | None, **kw: Any) -> Wlan:
    return Wlan(
        id=f"{dev}/wlan/{ssid}",
        device_id=dev,
        ssid=ssid,
        radio_id=f"{dev}/radio/0",
        security=Security.WPA2,
        segment_id=segment,
        **kw,
    )


def client(mac: str, seen_on: str | None, segment: str | None = LAN, **kw: Any) -> Client:
    return Client(id=f"c/{mac}", mac=mac, seen_on=seen_on, segment_id=segment, **kw)


def run(net: Network, *rules: Any, **settings: RuleSettings) -> list[Finding]:
    return evaluate(net, rules, settings)


def test_rules_are_registered_and_management_is_opt_in() -> None:
    ids = {r.id for r in RULES}
    assert {
        "vlan.trunk-scope",
        "link.slow",
        "lag.consistent",
        "topology.hidden-device",
        "inventory.unknown-neighbour",
        "inventory.unknown-network-device",
        "vlan.management-separate",
        "inventory.duplicate-device",
        "redundancy.single-point",
    } <= ids
    assert not management_separate.default_enabled
    assert not rule_enabled(management_separate, {})
    # a severity alone does not switch an opt-in rule on; enabled does
    off = {management_separate.id: RuleSettings(severity=Severity.WARNING)}
    assert not rule_enabled(management_separate, off)
    on = {management_separate.id: RuleSettings.model_validate({"enabled": True})}
    assert rule_enabled(management_separate, on)
    assert rule_enabled(slow, {}) and not rule_enabled(slow, {slow.id: RuleSettings(enabled=False)})


# --- vlan.trunk-scope (#105) -----------------------------------------------------------------

UP, APE = port_id("sw", "5"), port_id("ap", "eth0")
AP_LINK = link(UP, APE, id="link/sw-ap")
GW_LINK = link(port_id("gw", "1"), port_id("sw", "1"), id="link/gw-sw")


def ap_net(**kw: Any) -> Network:
    ap_kw = kw.pop("ap", {})
    segments = kw.pop(
        "segments",
        [
            seg(None, {UP: U, APE: U, port_id("gw", "1"): U, port_id("sw", "1"): U}),
            seg(20, {UP: T, APE: T, port_id("sw", "1"): T}),
            seg(40, {UP: T, port_id("sw", "1"): T}),
            seg(99, {UP: T, APE: T, port_id("sw", "1"): T}),
        ],
    )
    return Network(
        sites=[SITE],
        devices=[
            device("gw"),
            device("sw", DeviceRole.SWITCH, management_address="203.0.113.131"),
            device(
                "ap",
                DeviceRole.AP,
                management_address=ap_kw.pop("management_address", "203.0.113.130"),
                **ap_kw,
            ),
        ],
        ports=[
            port("gw", "1"),
            port("sw", "1"),
            port("sw", "5"),
            port("ap", "eth0", mac="02:00:00:00:0a:01"),
            port("ap", "lan1"),
        ],
        segments=segments,
        subnets=kw.pop(
            "subnets",
            [
                subnet(None, "192.0.2.1/24"),
                subnet(20, "198.51.100.1/24"),
                subnet(40, "203.0.113.1/25"),
                subnet(99, "203.0.113.129/25"),
            ],
        ),
        radios=[Radio(id="ap/radio/0", device_id="ap", name="radio0", band=Band.GHZ_5)],
        wlans=kw.pop("wlans", [wlan("ap", "iot", IOT), wlan("ap", "old", CAMS, enabled=False)]),
        links=kw.pop("links", [GW_LINK, AP_LINK]),
        neighbours=kw.pop("neighbours", []),
        errors=kw.pop("errors", []),
    )


def test_trunk_scope_reports_unused_vlans_on_the_ap_link() -> None:
    (f,) = run(ap_net(), trunk_scope)
    assert f.severity == "info" and f.objects == [AP_LINK.id, UP]
    assert f.message == (
        "The link to ap carries Cameras (VLAN 40), but ap only uses IoT (VLAN 20), "
        "Management (VLAN 99)."
    )
    assert f.fix == "Remove Cameras (VLAN 40) from sw port 5."
    # the switch-to-switch (here: router) link is not checked
    assert all(GW_LINK.id not in x.objects for x in run(ap_net(), trunk_scope))


def test_trunk_scope_counts_access_ports_and_own_subnets() -> None:
    lan1 = port_id("ap", "lan1")
    segments = [
        seg(None, {UP: U, APE: U}),
        seg(20, {UP: T, APE: T}),
        seg(40, {UP: T, APE: T, lan1: U}),
        seg(99, {UP: T, APE: T}),
    ]
    assert run(ap_net(segments=segments), trunk_scope) == []
    # management address unknown, but the AP reports its own address on the management VLAN
    own = [subnet(99, "203.0.113.130/25", dev="ap"), subnet(40, "203.0.113.1/25")]
    (f,) = run(ap_net(ap={"management_address": "ap.example"}, subnets=own), trunk_scope)
    assert "Cameras" in f.message and "Management" not in f.message.split("carries")[1][:20]


def test_trunk_scope_fits_exactly() -> None:
    segments = [seg(None, {UP: U, APE: U}), seg(20, {UP: T, APE: T}), seg(99, {UP: T, APE: T})]
    assert run(ap_net(segments=segments), trunk_scope) == []


def _quiet(**kw: Any) -> None:
    assert [f for f in run(ap_net(**kw), trunk_scope) if f.rule_id == trunk_scope.id] == []


def test_trunk_scope_stays_quiet_when_it_cannot_know() -> None:
    _quiet(ap={"managed_by": "ctrl"})  # controller may move SSIDs
    _quiet(errors=[ReadError(device_id="ap", capability="wireless", message="x")])
    _quiet(wlans=[])
    _quiet(wlans=[wlan("ap", "iot", IOT), wlan("ap", "lan", None)])
    _quiet(ap={"management_address": "ap.example"})  # management VLAN unknown
    _quiet(ap={"management_address": None})
    # the AP forwards to a further device
    _quiet(links=[GW_LINK, AP_LINK, link(port_id("ap", "lan1"), "pc/port/0")])
    other = Neighbour(id="n1", local_port_id=port_id("ap", "lan1"), chassis_id="02:00:00:00:77:01")
    _quiet(neighbours=[other])
    # something else (an unmanaged switch) is on the cable
    hidden = Neighbour(id="n2", local_port_id=APE, chassis_id="02:00:00:00:77:02")
    _quiet(neighbours=[hidden])
    # the switch does not report VLANs: unknown, not "carries nothing"
    _quiet(segments=[seg(20, {APE: T})])
    _quiet(links=[GW_LINK, AP_LINK.model_copy(update={"kind": LinkKind.WIRELESS})])


def test_trunk_scope_with_lldp_confirming_the_cable() -> None:
    by_name = Neighbour(id="n", local_port_id=APE, chassis_id="x", system_name="SW")
    by_mac = Neighbour(id="m", local_port_id=UP, chassis_id="02:00:00:00:0a:01")
    assert len(run(ap_net(neighbours=[by_name, by_mac]), trunk_scope)) == 1


def test_trunk_scope_skips_ap_to_ap_links() -> None:
    net = ap_net()
    sw_as_ap = net.devices[1].model_copy(update={"role": DeviceRole.AP})
    net = net.model_copy(update={"devices": [net.devices[0], sw_as_ap, net.devices[2]]})
    assert run(net, trunk_scope) == []


def test_address_segment() -> None:
    net = ap_net()
    assert address_segment(net, net.devices[2]) == MGMT
    other_site = net.devices[2].model_copy(update={"site_id": "elsewhere"})
    assert address_segment(net, other_site) is None
    v6 = net.devices[2].model_copy(update={"management_address": "[2001:db8::1]"})
    assert address_segment(net, v6) is None


# --- link.slow (#108) ------------------------------------------------------------------------


def slow_net(a: dict[str, Any], b: dict[str, Any], **kw: Any) -> Network:
    roles = kw.pop("roles", (DeviceRole.GATEWAY, DeviceRole.SWITCH))
    return Network(
        sites=[SITE],
        devices=[device("gw", roles[0]), device("sw", roles[1])],
        ports=[port("gw", "1", **a), port("sw", "1", **b), *kw.pop("ports", [])],
        links=kw.pop("links", [GW_LINK]),
    )


GOOD = {"up": True, "speed_mbps": 1000, "full_duplex": True}


def test_slow_link_between_network_devices() -> None:
    (f,) = run(slow_net(GOOD, GOOD | {"speed_mbps": 100}), slow)
    assert f.severity == "warning" and f.objects == [GW_LINK.id]
    assert f.message == "The link gw port 1 ↔ sw port 1 runs at 100 Mbit/s."
    assert "two pairs" in (f.fix or "")
    (d,) = run(slow_net(GOOD, GOOD | {"full_duplex": False}), slow)
    assert d.message == "The link gw port 1 ↔ sw port 1 runs in half duplex on sw port 1."
    # only one end known (the other device does not report ports)
    one = slow_net(GOOD | {"speed_mbps": 100}, GOOD)
    one = one.model_copy(update={"ports": one.ports[:1]})
    assert len(run(one, slow)) == 1


def test_slow_stays_quiet() -> None:
    assert run(slow_net(GOOD, GOOD), slow) == []
    assert run(slow_net(GOOD | {"speed_mbps": 2500}, GOOD | {"speed_mbps": None}), slow) == []
    assert run(slow_net(GOOD, {"up": False, "speed_mbps": 10}), slow) == []
    lag = slow_net(GOOD | {"kind": PortKind.LAG, "speed_mbps": 100}, GOOD)
    assert run(lag, slow) == []
    wireless = [GW_LINK.model_copy(update={"kind": LinkKind.WIRELESS})]
    assert run(slow_net(GOOD, GOOD | {"speed_mbps": 100}, links=wireless), slow) == []
    to_pc = slow_net(GOOD, GOOD | {"speed_mbps": 100}, roles=(DeviceRole.SWITCH, DeviceRole.OTHER))
    assert run(to_pc, slow) == []
    unknown = slow_net(GOOD, GOOD, links=[link("x/port/1", "y/port/1")])
    assert run(unknown, slow) == []


def test_slow_single_ports() -> None:
    extra = [
        port("sw", "2", up=True, full_duplex=False, speed_mbps=100),
        port("sw", "3", up=True, speed_mbps=10, full_duplex=True),
        port("sw", "4", up=True, speed_mbps=100),
        port("sw", "5", up=False, full_duplex=False),
        port("sw", "wlan0", kind=PortKind.WIRELESS, up=True, full_duplex=False),
    ]
    out = {f.objects[0]: f for f in run(slow_net(GOOD, GOOD, ports=extra), slow)}
    assert set(out) == {port_id("sw", "2"), port_id("sw", "3")}
    assert out[port_id("sw", "2")].message == "sw port 2 runs in half duplex."
    assert out[port_id("sw", "2")].severity == "warning"
    assert out[port_id("sw", "3")].message == "sw port 3 runs at 10 Mbit/s."
    assert out[port_id("sw", "3")].severity == "info"
    pc = slow_net(GOOD, GOOD, ports=[port("pc", "0", up=True, full_duplex=False)])
    assert run(pc, slow) == []


# --- lag.consistent (#107) -------------------------------------------------------------------

S7, S8 = port_id("sw", "7"), port_id("sw", "8")
R1, R2 = port_id("sw2", "1"), port_id("sw2", "2")


def lag_net(
    members: list[Port] | None = None, remote: list[Port] | None = None, **kw: Any
) -> Network:
    up = {"up": True, "speed_mbps": 1000, "full_duplex": True}
    return Network(
        sites=[SITE],
        devices=[device("sw", DeviceRole.SWITCH), device("sw2", DeviceRole.SWITCH)],
        ports=[
            *(members if members is not None else [port("sw", n, lag="lag1", **up) for n in "78"]),
            port("sw", "lag1", kind=PortKind.LAG, lag="lag1"),
            *(remote if remote is not None else [port("sw2", n, lag="ae0") for n in "12"]),
        ],
        segments=kw.pop("segments", []),
        links=kw.pop("links", [link(S7, R1), link(S8, R2)]),
    )


def test_lag_consistent_on_both_ends() -> None:
    assert run(lag_net(), lag_consistent) == []


def test_lag_far_end_is_not_a_lag() -> None:
    (f,) = run(lag_net(remote=[port("sw2", "1"), port("sw2", "2")]), lag_consistent)
    assert f.severity == "error" and f.objects == ["sw", S7, S8]
    assert f.message == (
        "sw lag1 [7, 8] is connected to sw2 port 1, sw2 port 2, which are not in a LAG."
    )
    assert f.fix == "Configure a LAG on sw2 or remove all but one cable."
    (m,) = run(lag_net(remote=[port("sw2", "1", lag="ae0"), port("sw2", "2")]), lag_consistent)
    assert "not all in the same LAG" in m.message


def test_lag_members_to_several_devices() -> None:
    net = lag_net(links=[link(S7, R1), link(S8, port_id("sw3", "1"))])
    (f,) = run(net, lag_consistent)
    assert f.severity == "error" and "connected to several devices" in f.message


def test_lag_far_end_unknown_is_incomplete() -> None:
    (f,) = run(lag_net(remote=[]), lag_consistent)
    assert f.incomplete and "sw2 does not report its ports" in f.message
    # one known cable says nothing about the far end
    assert run(lag_net(remote=[], links=[link(S7, R1)]), lag_consistent) == []


def test_lag_members_differ() -> None:
    members = [
        port("sw", "7", lag="lag1", up=True, speed_mbps=1000, full_duplex=True),
        port("sw", "8", lag="lag1", up=True, speed_mbps=100, full_duplex=False),
    ]
    out = {f.message: f for f in run(lag_net(members), lag_consistent)}
    speed = out[
        "sw lag1 [7, 8]: the members run at different speeds (7: 1000 Mbit/s, 8: 100 Mbit/s)."
    ]
    assert speed.severity == "warning"
    assert out["sw lag1 [7, 8]: some members run in half duplex."].severity == "warning"


def test_lag_member_vlans() -> None:
    differ = [seg(None, {S7: U, S8: U}), seg(20, {S7: T})]
    (f,) = run(lag_net(segments=differ), lag_consistent)
    assert f.severity == "error" and "carry different VLANs" in f.message
    same = [seg(None, {S7: U, S8: U}), seg(20, {S7: T, S8: T})]
    assert run(lag_net(segments=same), lag_consistent) == []
    # VLANs configured on the LAG itself, not per member
    assert run(lag_net(segments=[seg(20, {port_id("sw", "lag1"): T})]), lag_consistent) == []


def test_lag_single_member_up() -> None:
    members = [port("sw", "7", lag="lag1", up=True), port("sw", "8", lag="lag1", up=False)]
    (f,) = run(lag_net(members, links=[link(S7, R1)]), lag_consistent)
    assert f.severity == "info" and f.message == "sw lag1 [7, 8]: only one member is up."
    unknown = [port("sw", "7", lag="lag1", up=True), port("sw", "8", lag="lag1")]
    assert run(lag_net(unknown, links=[]), lag_consistent) == []


# --- topology.hidden-device (#109) -----------------------------------------------------------

P4 = port_id("sw", "4")


def hidden_net(clients: list[Client], **kw: Any) -> Network:
    return Network(
        sites=[SITE],
        devices=[
            device("sw", DeviceRole.SWITCH),
            device("ap", DeviceRole.AP, management_address="192.0.2.9"),
            device("pc", DeviceRole.OTHER),
        ],
        ports=[
            port("sw", "4"),
            port("sw", "1"),
            port("ap", "wlan0", kind=PortKind.WIRELESS),
            port("ap", "eth0", mac="02:00:00:00:0a:01"),
            port("pc", "0"),
        ],
        segments=kw.pop("segments", [seg(None, {P4: U})]),
        clients=clients,
        links=kw.pop("links", []),
    )


def many(on: str, n: int = 4, segment: str | None = LAN) -> list[Client]:
    return [client(f"02:00:00:00:50:{i:02x}", on, segment) for i in range(n)]


def test_hidden_device_behind_port() -> None:
    (f,) = run(hidden_net(many(P4)), hidden_device)
    assert f.severity == "info" and f.objects == [P4]
    assert f.message == "4 devices are seen behind sw port 4, which has no known neighbour."
    assert "Topology page" in (f.fix or "") and "tagged" not in (f.fix or "")


def test_hidden_device_on_tagged_port_or_several_networks() -> None:
    two = [client("02:00:00:00:50:01", P4, LAN), client("02:00:00:00:50:02", P4, IOT)]
    (f,) = run(hidden_net(two, segments=[seg(None, {P4: U}), seg(20, {P4: T})]), hidden_device)
    assert f.severity == "warning"
    assert (
        f.message
        == "2 devices in 2 networks are seen behind sw port 4, which has no known neighbour."
    )
    assert "should not be on a port with tagged VLANs" in (f.fix or "")


def test_hidden_device_stays_quiet() -> None:
    assert run(hidden_net(many(P4, 3)), hidden_device) == []
    assert run(hidden_net(many(P4), links=[link(P4, port_id("ap", "eth0"))]), hidden_device) == []
    # a known device behind the port (by MAC, or by address) explains the clients
    ap_mac = [*many(P4), client("02:00:00:00:0a:01", P4)]
    assert run(hidden_net(ap_mac), hidden_device) == []
    ap_ip = [*many(P4), client("02:00:00:00:51:01", P4, addresses=[ip("192.0.2.9")])]
    assert run(hidden_net(ap_ip), hidden_device) == []
    assert run(hidden_net(many(port_id("ap", "wlan0"))), hidden_device) == []
    assert run(hidden_net(many(port_id("pc", "0"))), hidden_device) == []
    assert run(hidden_net(many("gone/port/1") + many("")), hidden_device) == []


# --- inventory.unknown-neighbour (#113) ------------------------------------------------------


def nb_net(*neighbours: Neighbour) -> Network:
    return Network(
        sites=[SITE],
        devices=[
            device("sw", DeviceRole.SWITCH, management_address="198.51.100.5"),
            device("ap", DeviceRole.AP, name="AP Hall"),
        ],
        ports=[port("sw", "9"), port("sw", "10"), port("ap", "eth0", mac="02:00:00:00:0a:01")],
        subnets=[subnet(None, "192.0.2.1/24", dev="sw")],
        neighbours=list(neighbours),
    )


def nb(local: str = "9", chassis: str = "02:00:00:00:99:01", **kw: Any) -> Neighbour:
    return Neighbour(
        id=f"n/{local}/{chassis}",
        local_port_id=port_id("sw", local),
        chassis_id=chassis,
        management_address=kw.pop("management_address", "198.51.100.2"),
        **kw,
    )


def test_unknown_neighbour() -> None:
    (f,) = run(nb_net(nb(system_name="sw-attic")), unknown_neighbour)
    assert f.severity == "info" and f.objects == [port_id("sw", "9")]
    assert f.message == (
        "sw port 9 sees a device announcing itself as sw-attic (198.51.100.2) that is not in "
        "Signalbox."
    )
    assert "add it under Devices" in (f.fix or "")
    (two,) = run(nb_net(nb(), nb("10", "02-00-00-00-99-01")), unknown_neighbour)
    assert two.message.startswith(
        "sw port 10, sw port 9 see a device announcing itself as 198.51.100.2 "
    )
    # a chassis id that is not a MAC (a name) still identifies the device
    (named,) = run(nb_net(nb(chassis="attic-switch")), unknown_neighbour)
    assert named.objects == [port_id("sw", "9")]


def test_unknown_neighbour_stays_quiet() -> None:
    assert run(nb_net(nb(chassis="02:00:00:00:0a:01")), unknown_neighbour) == []
    assert run(nb_net(nb(system_name="ap hall")), unknown_neighbour) == []
    assert run(nb_net(nb(management_address="198.51.100.5")), unknown_neighbour) == []
    assert run(nb_net(nb(management_address="192.0.2.1")), unknown_neighbour) == []
    assert run(nb_net(nb(management_address=None)), unknown_neighbour) == []
    assert run(nb_net(nb(management_address="127.0.0.1")), unknown_neighbour) == []
    assert run(nb_net(nb(local="99")), unknown_neighbour) == []


def test_unknown_neighbour_leaves_classified_neighbours_to_the_other_rule() -> None:
    assert run(nb_net(nb(capabilities=["bridge"])), unknown_neighbour) == []
    assert run(nb_net(nb(capabilities=["telephone"])), unknown_neighbour) == []
    assert run(nb_net(nb(description="MikroTik RouterOS 7.15")), unknown_neighbour) == []
    assert len(run(nb_net(nb(description="Debian 12 on a server")), unknown_neighbour)) == 1


# --- inventory.unknown-network-device (#113) -------------------------------------------------


def test_unknown_network_device() -> None:
    (f,) = run(
        nb_net(nb(system_name="sw-attic", capabilities=["bridge", "router"])),
        unknown_network_device,
    )
    assert f.severity == "warning" and f.objects == [port_id("sw", "9")]
    assert f.message == (
        "sw port 9 sees a network device announcing itself as sw-attic (198.51.100.2, bridge, "
        "router) that is not in Signalbox."
    )
    assert "Add it under Devices" in (f.fix or "") and "Find devices" in (f.fix or "")
    assert f.message_id == "topology.unknownNetworkDevice"
    assert f.fix_id == "topology.unknownNetworkDevice.fixFind"
    # an access point, seen on two ports, without a name
    (two,) = run(
        nb_net(
            nb(capabilities=["wlan-access-point"]),
            nb("10", "02-00-00-00-99-01", capabilities=["wlan-access-point"]),
        ),
        unknown_network_device,
    )
    assert two.message.startswith(
        "sw port 10, sw port 9 see a network device announcing itself as 198.51.100.2 "
        "(wlan-access-point) "
    )
    # no capabilities, but a description of network equipment; no address: no search hint
    (desc,) = run(
        nb_net(nb(management_address=None, description="OpenWrt 24.10 Linux 6.6")),
        unknown_network_device,
    )
    assert desc.fix_id == "topology.unknownNetworkDevice.fix" and "Find devices" not in desc.fix
    assert desc.message.startswith("sw port 9 sees a network device announcing itself as 02:")


def test_unknown_network_device_stays_quiet() -> None:
    gear = {"capabilities": ["bridge"]}
    # known by MAC, name or address
    assert run(nb_net(nb(chassis="02:00:00:00:0a:01", **gear)), unknown_network_device) == []
    assert run(nb_net(nb(system_name="ap hall", **gear)), unknown_network_device) == []
    assert run(nb_net(nb(management_address="198.51.100.5", **gear)), unknown_network_device) == []
    assert run(nb_net(nb(local="99", **gear)), unknown_network_device) == []
    # phones, stations, other, nothing announced
    for caps in (["telephone"], ["station"], ["other"], ["telephone", "station"], []):
        assert run(nb_net(nb(capabilities=caps)), unknown_network_device) == []
    # a phone that mentions a vendor in its description
    phone = nb(capabilities=["telephone"], description="Cisco IP Phone 8851 switch port")
    assert run(nb_net(phone), unknown_network_device) == []
    assert run(nb_net(nb(description="Debian 12 server")), unknown_network_device) == []
    assert run(nb_net(nb(description="")), unknown_network_device) == []
    # one the user knows and left out on purpose
    known = nb_net(nb(capabilities=["bridge"]))
    known.annotations.append(
        annotation("client/02:00:00:00:99:01", expected={"known_neighbour": True})
    )
    assert run(known, unknown_network_device) == []
    # a bridge that also is a phone is still network gear
    both = nb(capabilities=["bridge", "telephone"])
    assert len(run(nb_net(both), unknown_network_device)) == 1


# --- vlan.management-separate (#117) ---------------------------------------------------------

ON = {"vlan.management-separate": RuleSettings.model_validate({"enabled": True})}


def mgmt_net(**kw: Any) -> Network:
    return Network(
        sites=[SITE],
        devices=[
            device("gw", management_address="192.0.2.1"),
            device("sw", DeviceRole.SWITCH, management_address="192.0.2.2"),
            device("ap", DeviceRole.AP, management_address=kw.pop("ap_address", "192.0.2.3")),
            device("pc", DeviceRole.OTHER, management_address="192.0.2.50"),
        ],
        ports=[port("sw", "1", mac="02:00:00:00:02:01")],
        segments=kw.pop("segments", [seg(None, {}), seg(20, {})]),
        subnets=[subnet(None, "192.0.2.1/24"), subnet(20, "198.51.100.1/24")],
        wlans=kw.pop("wlans", []),
        clients=kw.pop(
            "clients",
            [
                client("02:00:00:00:50:01", None),
                client("02:00:00:00:50:02", None),
                client("02:00:00:00:02:01", None),  # the switch itself
                client("02:00:00:00:50:03", None, addresses=[ip("192.0.2.3")]),  # the AP
                client("02:00:00:00:50:04", None, IOT),
            ],
        ),
    )


def test_management_separate_is_off_by_default() -> None:
    assert [f for f in evaluate(mgmt_net(), RULES) if f.rule_id == "vlan.management-separate"] == []


def test_management_in_client_network() -> None:
    (f,) = evaluate(mgmt_net(), [management_separate], ON)
    assert f.severity == "info" and f.objects == [LAN]
    assert (
        f.message == "ap, gw, sw are managed in LAN (untagged network), which also has clients: 2."
    )
    assert "management VLAN" in (f.fix or "")
    wlans = [wlan("ap", "Home", LAN), wlan("ap", "Off", LAN, enabled=False)]
    (w,) = evaluate(mgmt_net(clients=[], wlans=wlans), [management_separate], ON)
    assert w.message.endswith("which also has SSIDs: Home.")
    one = mgmt_net(
        clients=[client("02:00:00:00:50:01", None)],
        wlans=[wlan("ap", "A", LAN), wlan("ap", "B", LAN)],
    )
    (o,) = evaluate(one, [management_separate], ON)
    assert o.message.endswith("which also has clients: 1; SSIDs: A, B.")


def test_management_separate_stays_quiet() -> None:
    # no VLANs at the site
    assert evaluate(mgmt_net(segments=[seg(None, {})]), [management_separate], ON) == []
    # only network devices in the management network
    assert evaluate(mgmt_net(clients=[]), [management_separate], ON) == []
    # the AP is managed in a network without clients: only the others are reported
    (f,) = evaluate(
        mgmt_net(ap_address="198.51.100.3", clients=many("", 1)), [management_separate], ON
    )
    assert f.message.startswith("gw, sw are managed")


# --- inventory.duplicate-device (#118) -------------------------------------------------------


def inv(*devices: Any, ports: list[Port] | None = None) -> Network:
    return Network(sites=[SITE], devices=list(devices), ports=ports or [])


def test_duplicate_by_address() -> None:
    net = inv(
        device("a", management_address="192.0.2.2"), device("b", management_address="192.0.2.2 ")
    )
    (f,) = run(net, duplicate_device)
    assert f.severity == "warning" and f.objects == ["a", "b"]
    assert f.message == "a, b look like the same device (shared: 192.0.2.2)."


def test_duplicate_reported_by_controller() -> None:
    sw = device("sw-a", DeviceRole.SWITCH)
    ctrl = device("omada", DeviceRole.OTHER)
    managed = device("omada/0200", DeviceRole.SWITCH, name="switch A", managed_by="omada")
    ports = [
        port("sw-a", "1", mac="02:00:00:00:01:00"),
        port("omada/0200", "1", mac="02:00:00:00:01:00"),
        port("omada/0200", "2", mac="02:00:00:00:01:00"),
    ]
    (f,) = run(inv(sw, ctrl, managed, ports=ports), duplicate_device)
    assert f.objects == ["omada/0200", "sw-a"]
    assert f.message == (
        "omada/switch A, sw-a look like the same device (shared: 02:00:00:00:01:00)."
    )


def test_duplicate_chain_is_one_finding() -> None:
    devices = [
        device("a", management_address="192.0.2.2"),
        device("b", management_address="192.0.2.2"),
        device("c", management_address="sw.example"),
    ]
    ports = [port("b", "1", mac="02:00:00:00:0b:01"), port("c", "1", mac="02:00:00:00:0b:01")]
    (f,) = run(inv(*devices, ports=ports), duplicate_device)
    assert f.objects == ["a", "b", "c"]
    assert "shared: 02:00:00:00:0b:01, 192.0.2.2" in f.message


def test_duplicate_stays_quiet() -> None:
    vrrp = [port("a", "1", mac="00:00:5e:00:01:01"), port("b", "1", mac="00:00:5e:00:01:01")]
    local = [
        device("a", management_address="127.0.0.1"),
        device("b", management_address="localhost"),
    ]
    assert run(inv(*local, ports=vrrp), duplicate_device) == []
    assert (
        run(
            inv(device("a", management_address="::1"), device("b", management_address="::1")),
            duplicate_device,
        )
        == []
    )
    orphan = [port("gone", "1", mac="02:00:00:00:0c:01"), port("a", "1", mac="02:00:00:00:0c:01")]
    assert run(inv(device("a"), ports=orphan), duplicate_device) == []


# --- redundancy.single-point (#119) ----------------------------------------------------------


def tree(*links: tuple[str, str], extra: list[Any] | None = None) -> Network:
    devices = [
        device("gw", name="Router"),
        device("sw1", DeviceRole.SWITCH, name="Core"),
        device("sw2", DeviceRole.SWITCH, name="Desk"),
        device("ap1", DeviceRole.AP),
        device("ap2", DeviceRole.AP),
        *(extra or []),
    ]
    out = [
        link(port_id(a, f"to-{b}-{i}"), port_id(b, f"to-{a}-{i}")) for i, (a, b) in enumerate(links)
    ]
    return Network(sites=[SITE], devices=devices, links=out)


CHAIN = (("gw", "sw1"), ("sw1", "sw2"), ("sw2", "ap1"), ("sw2", "ap2"))


def test_single_points_in_a_chain() -> None:
    (f,) = run(tree(*CHAIN), single_point)
    assert f.severity == "info" and f.objects == [SITE.id, "sw1", "sw2"]
    assert f.message == (
        "Single points of failure towards Router (what is cut off): Core: 2 AP, 1 SW; "
        "Desk: 2 AP; Core \u2194 Router: 2 AP, 2 SW; Core \u2194 Desk: 2 AP, 1 SW."
    )
    assert "second uplink" in (f.fix or "")


def test_lag_uplink_is_not_a_single_link() -> None:
    (f,) = run(
        tree(("gw", "sw1"), ("gw", "sw1"), ("sw1", "ap1"), ("sw1", "ap2"), ("gw", "sw2")),
        single_point,
    )
    assert f.objects == [SITE.id, "sw1"]
    assert "link between" not in f.message


def test_single_point_stays_quiet() -> None:
    # a ring: every device has a second path
    ring = (
        ("gw", "sw1"),
        ("gw", "sw2"),
        ("sw1", "sw2"),
        ("sw1", "ap1"),
        ("sw2", "ap1"),
        ("sw1", "ap2"),
        ("sw2", "ap2"),
    )
    assert run(tree(*ring), single_point) == []
    # every AP directly on the router
    star = (("gw", "sw1"), ("gw", "sw2"), ("gw", "ap1"), ("gw", "ap2"))
    assert run(tree(*star), single_point) == []
    # incomplete topology: ap2 has no known path
    assert run(tree(*CHAIN[:3]), single_point) == []
    # fewer than three network devices, or no router
    small = Network(sites=[SITE], devices=[device("gw"), device("ap", DeviceRole.AP)])
    assert run(small, single_point) == []
    no_gw = tree(*CHAIN).model_copy(update={"devices": tree().devices[1:]})
    assert run(no_gw, single_point) == []


def test_single_point_per_site() -> None:
    away = Site(id="away", name="Away")
    extra = [device("gw-b", site_id=away.id), device("ap-b", DeviceRole.AP, site_id=away.id)]
    net = tree(*CHAIN, extra=extra)
    (f,) = run(net.model_copy(update={"sites": [SITE, away]}), single_point)
    assert f.objects[0] == SITE.id


# --- the second OpenWrt simulator of the demo has MACs of its own ----------------------------


def test_openwrt_sim_mac_base() -> None:
    def macs(sim: OpenWrtSim) -> set[str]:
        data = sim._data("", "network.device", "status", {})
        assert data is not None
        return {e["macaddr"] for e in data[1].values() if "macaddr" in e}

    plain, second = macs(OpenWrtSim()), macs(OpenWrtSim(mac_base=2))
    assert plain and second and not plain & second
    assert all(m.startswith("02:00:00:02:") for m in second)


@pytest.mark.parametrize(
    "rule_",
    [
        trunk_scope,
        slow,
        lag_consistent,
        hidden_device,
        unknown_neighbour,
        duplicate_device,
        single_point,
    ],
)
def test_empty_network_is_quiet(rule_: Any) -> None:
    assert run(Network(), rule_) == []


def test_management_separate_knows_purposes() -> None:
    # the network with the purpose management is the management VLAN: not reported
    mgmt = [seg(None, {}).model_copy(update={"purpose": SegmentPurpose.MANAGEMENT}), seg(20, {})]
    assert evaluate(mgmt_net(segments=mgmt), [management_separate], ON) == []
    # guest and IoT networks are security.management-exposure's finding
    iot = [seg(None, {}).model_copy(update={"purpose": SegmentPurpose.IOT}), seg(20, {})]
    assert evaluate(mgmt_net(segments=iot), [management_separate], ON) == []
    # with a management network elsewhere, the fix names it
    other = [seg(None, {}), seg(20, {}).model_copy(update={"purpose": SegmentPurpose.MANAGEMENT})]
    (f,) = evaluate(mgmt_net(segments=other), [management_separate], ON)
    assert f.fix == "Move the management addresses to IoT (VLAN 20), the management network."


def test_unknown_neighbour_known_neighbour() -> None:
    net = nb_net(nb(), nb("10", "02:00:00:00:99:02"))
    known = annotation("02:00:00:00:99:01", expected={"known_neighbour": True})
    (f,) = run(annotated(net, known), unknown_neighbour)
    assert f.objects == [port_id("sw", "10")]
    other = annotation("02:00:00:00:99:03", expected={"known_neighbour": True})
    assert len(run(annotated(nb_net(nb(chassis="attic-switch")), other), unknown_neighbour)) == 1
