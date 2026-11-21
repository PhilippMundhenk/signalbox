"""VLAN and link rules on small gateway - switch - AP topologies."""

from __future__ import annotations

from typing import Any

from factories import SITE, device, iface, port, snapshot
from signalbox.merge import merge
from signalbox.model import (
    Band,
    DeviceRole,
    Link,
    LinkKind,
    LinkOrigin,
    Membership,
    Network,
    PortMembership,
    Radio,
    Security,
    Segment,
    Snapshot,
    Subnet,
    Wlan,
    port_id,
    segment_id,
)
from signalbox.rules import Finding, evaluate
from signalbox.rules.builtin import RULES
from signalbox.rules.vlan import RULES as VLAN_RULES
from signalbox.rules.vlan import (
    native_mismatch,
    path_to_gateway,
    speed_duplex,
    tagged_both_ends,
    unused,
)

LAN = segment_id(SITE.id, None)
IOT = segment_id(SITE.id, 20)
GUEST = segment_id(SITE.id, 30)
T, U = Membership.TAGGED, Membership.UNTAGGED

# gw/1 -- sw/1   sw/2 -- ap/eth0   sw/3 is an access port, ap/wlan0 carries the SSIDs
GW_SW = Link(id="link/gw-sw", a=port_id("gw", "1"), b=port_id("sw", "1"), origin=LinkOrigin.LLDP)
SW_AP = Link(id="link/sw-ap", a=port_id("sw", "2"), b=port_id("ap", "eth0"), origin=LinkOrigin.LLDP)


def seg(dev: str, vlan: int | None, **ports: Membership) -> Segment:
    return Segment(
        id=segment_id(SITE.id, vlan),
        site_id=SITE.id,
        vlan=vlan,
        name={None: "LAN", 20: "IoT", 30: "Guest"}.get(vlan),
        members=[PortMembership(port_id=port_id(dev, p), mode=m) for p, m in ports.items()],
    )


def subnet(vlan: int | None, cidr: str) -> Subnet:
    sid = segment_id(SITE.id, vlan)
    return Subnet(id=f"gw/subnet/{sid}", segment_id=sid, interface=iface(cidr), device_id="gw")


def gateway(**kw: Any) -> Snapshot:
    return snapshot(
        device("gw"),
        ports=[port("gw", "1", **kw.pop("port", {}))],
        segments=kw.pop("segments", [seg("gw", None, **{"1": U}), seg("gw", 20, **{"1": T})]),
        subnets=kw.pop("subnets", [subnet(None, "192.0.2.1/24"), subnet(20, "198.51.100.1/24")]),
    )


def switch(**kw: Any) -> Snapshot:
    return snapshot(
        device("sw", DeviceRole.SWITCH),
        ports=[port("sw", "1", **kw.pop("port", {})), port("sw", "2"), port("sw", "3")],
        segments=kw.pop(
            "segments",
            [seg("sw", None, **{"1": U, "2": U}), seg("sw", 20, **{"1": T, "2": T, "3": U})],
        ),
    )


def ap(segments: list[Segment] | None = None, wlan_segment: str | None = IOT) -> Snapshot:
    radio = Radio(id="ap/radio/0", device_id="ap", name="radio0", band=Band.GHZ_5)
    return snapshot(
        device("ap", DeviceRole.AP),
        ports=[port("ap", "eth0", mac="02:00:00:00:00:01")],
        segments=segments
        if segments is not None
        else [seg("ap", None, eth0=U), seg("ap", 20, eth0=T)],
        radios=[radio],
        wlans=[
            Wlan(
                id="ap/wlan/iot",
                device_id="ap",
                ssid="iot",
                radio_id=radio.id,
                security=Security.WPA2,
                segment_id=wlan_segment,
            )
        ],
    )


def net(*snaps: Snapshot, links: tuple[Link, ...] = (GW_SW, SW_AP)) -> Network:
    return merge([SITE], snaps, links)


def run(n: Network, *rules: Any) -> list[Finding]:
    return evaluate(n, rules or VLAN_RULES)


def test_consistent_topology_has_no_findings() -> None:
    assert run(net(gateway(), switch(), ap())) == []


def test_rules_are_registered() -> None:
    ids = {r.id for r in RULES}
    assert {
        "vlan.path-to-gateway",
        "vlan.native-mismatch",
        "vlan.tagged-both-ends",
        "vlan.unused",
        "link.speed-duplex",
    } <= ids


def test_ssid_vlan_missing_on_uplink() -> None:
    sw = switch(segments=[seg("sw", None, **{"1": U, "2": U}), seg("sw", 20, **{"2": T})])
    out = run(net(gateway(), sw, ap()), path_to_gateway)
    (f,) = out
    assert f.severity == "error" and not f.incomplete
    assert f.objects == [IOT, GW_SW.id, port_id("sw", "1")]
    assert f.message == (
        "IoT (VLAN 20), used on ap, is not carried on the link gw port 1 to sw port 1 "
        "(missing on sw port 1)."
    )
    assert f.fix == "Add IoT (VLAN 20) as tagged VLAN to sw port 1."
    # the same gap is also visible per link, and stays one finding per missing end
    (t,) = run(net(gateway(), sw, ap()), tagged_both_ends)
    assert t.objects == [IOT, GW_SW.id, port_id("sw", "1")]
    assert "tagged on gw port 1 but not configured on sw port 1" in t.message


def test_vlan_missing_on_both_ends_is_one_finding() -> None:
    gw = gateway(segments=[seg("gw", None, **{"1": U})])
    sw = switch(segments=[seg("sw", None, **{"1": U, "2": U}), seg("sw", 20, **{"2": T})])
    (f,) = run(net(gw, sw, ap()), path_to_gateway)
    assert f.objects == [IOT, GW_SW.id, port_id("gw", "1"), port_id("sw", "1")]
    assert "missing on gw port 1 and sw port 1" in f.message
    # the segment exists without members on the gateway: not "unused", the AP uses it
    assert run(net(gw, sw, ap()), unused) == []


def test_access_port_vlan_is_checked() -> None:
    sw = switch(segments=[seg("sw", None, **{"1": U, "2": U}), seg("sw", 30, **{"3": U})])
    gw = gateway(
        segments=[seg("gw", None, **{"1": U}), seg("gw", 30, **{"1": T})],
        subnets=[subnet(None, "192.0.2.1/24"), subnet(30, "203.0.113.1/24")],
    )
    (f,) = run(
        net(gw, sw, ap(segments=[seg("ap", None, eth0=U)], wlan_segment=None)), path_to_gateway
    )
    assert f.objects == [GUEST, GW_SW.id, port_id("sw", "1")]
    assert "used on sw" in f.message and "Guest (VLAN 30)" in f.message


def test_missing_link_is_incomplete_once_per_device() -> None:
    gw = gateway(
        segments=[seg("gw", None, **{"1": U}), seg("gw", 20, **{"1": T})],
    )
    a = ap(segments=[seg("ap", None, eth0=U), seg("ap", 20, eth0=T)])
    out = run(net(gw, switch(), a, links=(GW_SW,)), path_to_gateway)
    (f,) = out
    assert f.incomplete and f.severity == "info" and f.objects == ["ap"]
    assert f.message.startswith("ap is not connected to the gateway in the known topology")


def test_unmanaged_switch_is_incomplete_not_an_error() -> None:
    dumb = snapshot(device("sw", DeviceRole.SWITCH), ports=[port("sw", "1"), port("sw", "2")])
    out = run(net(gateway(), dumb, ap()))
    assert all(f.incomplete for f in out)
    assert sorted(tuple(f.objects) for f in out) == [
        (GW_SW.id, port_id("sw", "1")),
        (SW_AP.id, port_id("sw", "2")),
    ]
    assert "sw does not report VLAN memberships" in out[0].message


def test_segment_without_router_and_gateway_itself_are_skipped() -> None:
    # VLAN 40 has no subnet anywhere: pure layer 2, nothing to check
    sw = switch(
        segments=[
            seg("sw", None, **{"1": U, "2": U}),
            seg("sw", 20, **{"1": T, "2": T}),
            seg("sw", 40, **{"3": U}),
        ]
    )
    assert run(net(gateway(), sw, ap()), path_to_gateway) == []
    # an AP that routes its SSID's network itself needs no path to the gateway
    routed = Subnet(
        id="ap/subnet/iot",
        segment_id=IOT,
        interface=iface("198.51.100.2/24"),
        device_id="ap",
        gateway=True,
    )
    own = ap(segments=[]).model_copy(update={"subnets": [routed]})
    assert run(net(gateway(), own, links=()), path_to_gateway) == []


def test_native_mismatch() -> None:
    sw = switch(segments=[seg("sw", 20, **{"1": U, "2": T}), seg("sw", None, **{"2": U})])
    out = run(net(gateway(), sw, ap()), native_mismatch)
    (f,) = out
    assert f.severity == "error" and f.objects == [GW_SW.id, port_id("gw", "1"), port_id("sw", "1")]
    assert f.message == (
        "gw port 1 to sw port 1: gw port 1 sends LAN untagged, sw port 1 sends IoT (VLAN 20) "
        "untagged."
    )
    sw2 = switch(segments=[seg("sw", None, **{"2": U}), seg("sw", 20, **{"1": T, "2": T})])
    (g,) = run(net(gateway(), sw2, ap()), native_mismatch)
    assert "sw port 1 sends nothing untagged" in g.message


def test_tagged_on_one_end_only() -> None:
    a = ap(segments=[seg("ap", None, eth0=U)], wlan_segment=None)
    (f,) = run(net(gateway(), switch(), a), tagged_both_ends)
    assert f.objects == [IOT, SW_AP.id, port_id("ap", "eth0")]
    assert f.fix == (
        "Add IoT (VLAN 20) as tagged VLAN to ap port eth0, or remove it from sw port 2."
    )


def test_unused_vlan() -> None:
    gw = gateway(
        segments=[
            seg("gw", None, **{"1": U}),
            seg("gw", 20, **{"1": T}),
            seg("gw", 30, **{"1": T}),
        ],
        subnets=[
            subnet(None, "192.0.2.1/24"),
            subnet(20, "198.51.100.1/24"),
            subnet(30, "203.0.113.1/24"),
        ],
    )
    out = run(net(gw, switch(), ap()), unused)
    (f,) = out
    assert f.severity == "info" and not f.incomplete and f.objects == [GUEST]
    assert f.message == "Guest (VLAN 30) has a subnet on gw but no other port and no SSID uses it."
    # a subnet whose segment is not even reported counts as unused, too
    lone = gateway(segments=[], subnets=[subnet(None, "192.0.2.1/24")])
    (g,) = run(net(lone, links=()), unused)
    assert g.objects == [LAN] and g.message.startswith(f"{LAN} has a subnet on gw")


def test_vlan_used_only_by_wlan_is_not_unused() -> None:
    gw = gateway(
        segments=[seg("gw", None, **{"1": U})],
        subnets=[subnet(None, "192.0.2.1/24"), subnet(20, "198.51.100.1/24")],
    )
    assert [f.objects for f in run(net(gw, links=()), unused)] == [[LAN], [IOT]]
    # the SSID on the AP uses VLAN 20; the untagged LAN stays unused
    assert [f.objects for f in run(net(gw, ap(segments=[]), links=()), unused)] == [[LAN]]


def test_speed_and_duplex_mismatch() -> None:
    gw = gateway(port={"speed_mbps": 1000, "full_duplex": True})
    sw = switch(port={"speed_mbps": 100, "full_duplex": False})
    out = run(net(gw, sw, ap()), speed_duplex)
    assert [f.severity for f in out] == ["warning", "warning"]
    assert len({f.id for f in out}) == 2
    assert {f.message for f in out} == {
        "gw port 1 to sw port 1: gw port 1 runs at 1000 Mbit/s, sw port 1 at 100 Mbit/s.",
        "gw port 1 to sw port 1: gw port 1 runs full duplex, sw port 1 half duplex.",
    }


def test_speed_duplex_skips_unknown_down_and_wireless() -> None:
    gw = gateway(port={"speed_mbps": 1000, "full_duplex": True})
    assert run(net(gw, switch(), ap()), speed_duplex) == []  # sw reports nothing
    down = switch(port={"speed_mbps": 100, "up": False})
    assert run(net(gw, down, ap()), speed_duplex) == []
    radio = GW_SW.model_copy(update={"kind": LinkKind.WIRELESS})
    sw = switch(port={"speed_mbps": 100})
    assert run(net(gw, sw, ap(), links=(radio, SW_AP)), speed_duplex) == []
    ghost = Link(id="link/ghost", a=port_id("gw", "1"), b="other/port/9", origin=LinkOrigin.MANUAL)
    assert run(net(gw, sw, ap(), links=(ghost,)), speed_duplex) == []


def test_findings_are_stable() -> None:
    sw = switch(
        segments=[seg("sw", 20, **{"1": U, "2": T})],
        port={"speed_mbps": 100},
    )
    n = net(gateway(port={"speed_mbps": 1000}), sw, ap())
    assert run(n) == run(n)
    assert len({f.id for f in run(n)}) == len(run(n))


def test_unknown_ports_and_unnamed_vlans_are_described() -> None:
    plain = Segment(
        id=segment_id(SITE.id, 40),
        site_id=SITE.id,
        vlan=40,
        members=[PortMembership(port_id="other/port/9", mode=T)],
    )
    ghost = Link(id="link/ghost", a=port_id("gw", "1"), b="other/port/9", origin=LinkOrigin.MANUAL)
    n = net(
        gateway(), snapshot(device("other", DeviceRole.SWITCH), segments=[plain]), links=(ghost,)
    )
    out = run(n, tagged_both_ends)
    assert [f.message for f in out] == [
        "IoT (VLAN 20) is tagged on gw port 1 but not configured on other port 9 "
        "(gw port 1 to other port 9).",
        "VLAN 40 is tagged on other port 9 but not configured on gw port 1 "
        "(gw port 1 to other port 9).",
    ]
