"""Two routers in a row (#205, #60): separate untagged networks, consistent WAN cable, no errors
from partly read devices, and the double NAT itself as information.

The site of the report, with documentation addresses: an ISP router ``isp`` (LAN 192.0.2.0/24,
DHCP) and a firewall ``fw`` behind it (WAN ``em0`` in the ISP router's LAN, LAN ``em1``
198.51.100.0/24, DHCP), an access point ``ap`` managed in the firewall's LAN that was only partly
read (its interfaces failed), and a switch ``sw`` between them that is not read at all.
"""

from __future__ import annotations

from typing import Any

import pytest

from factories import SITE, device, iface, ip, port, snapshot, uplink
from signalbox.changes import ChangeKind, PortValue, WlanValue, apply_change
from signalbox.desired import drift_rules, from_network, parse
from signalbox.merge import merge
from signalbox.model import (
    Band,
    Client,
    DeviceRole,
    DeviceStatus,
    DhcpPool,
    DhcpServer,
    Link,
    LinkOrigin,
    Membership,
    Network,
    PortMembership,
    Radio,
    ReadError,
    Security,
    Segment,
    Snapshot,
    Subnet,
    Wlan,
    is_native_segment,
    native_segment_id,
    port_id,
    segment_id,
)
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.addressing import double_nat, one_gateway
from signalbox.rules.builtin import RULES
from signalbox.rules.dhcp import one_server
from signalbox.rules.vlan import native_mismatch, path_to_gateway, tagged_both_ends, trunk_scope
from signalbox.topology import discovered_links, view

MAIN = segment_id(SITE.id, None)
ISP_LAN = native_segment_id(SITE.id, "isp")
U, T = Membership.UNTAGGED, Membership.TAGGED
ISP_MAC, WAN_MAC, LAN_MAC, AP_MAC = (f"02:00:00:00:00:{n:02x}" for n in (1, 2, 3, 4))


def native(dev: str, *ports: str, name: str = "lan") -> Segment:
    return Segment(
        id=MAIN,
        site_id=SITE.id,
        name=name,
        members=[PortMembership(port_id=port_id(dev, p), mode=U) for p in ports],
    )


def router_lan(dev: str, cidr: str, **kw: Any) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/lan",
        segment_id=MAIN,
        interface=iface(cidr),
        device_id=dev,
        gateway=kw.pop("gateway", True),
    )


def dhcp(dev: str, start: str, end: str) -> DhcpServer:
    return DhcpServer(
        id=f"{dev}/dhcp/lan",
        device_id=dev,
        segment_id=MAIN,
        enabled=True,
        pools=[DhcpPool(start=ip(start), end=ip(end))],
    )


def isp(**kw: Any) -> Snapshot:
    """The ISP router: it sees the firewall's WAN MAC on its LAN port."""
    return snapshot(
        device("isp", name="Fritz!Box", management_address="192.0.2.1"),
        ports=[port("isp", "lan", mac=ISP_MAC)],
        segments=[native("isp", "lan")],
        subnets=[router_lan("isp", "192.0.2.1/24")],
        dhcp_servers=[dhcp("isp", "192.0.2.20", "192.0.2.200")],
        clients=[
            Client(
                id="c/fw",
                mac=WAN_MAC,
                addresses=[ip("192.0.2.2")],
                segment_id=MAIN,
                seen_on=port_id("isp", "lan"),
            ),
            Client(
                id="c/phone", mac="02:00:00:00:01:01", addresses=[ip("192.0.2.50")], segment_id=MAIN
            ),
        ],
        **kw,
    )


def firewall(uplinks: bool = True, **kw: Any) -> Snapshot:
    """The firewall: WAN em0 is in no segment (WAN interfaces are left out on purpose)."""
    return snapshot(
        device("fw", name="OPNsense", management_address="198.51.100.1"),
        ports=[port("fw", "em0", mac=WAN_MAC), port("fw", "em1", mac=LAN_MAC)],
        segments=[native("fw", "em1")],
        subnets=[router_lan("fw", "198.51.100.1/24")],
        uplinks=[uplink("fw", addresses=[iface("192.0.2.2/24")], port="em0")] if uplinks else [],
        dhcp_servers=[dhcp("fw", "198.51.100.100", "198.51.100.200")],
        clients=[
            # the access point, seen through the unread switch on em1
            Client(
                id="c/ap",
                mac=AP_MAC,
                addresses=[ip("198.51.100.5")],
                segment_id=MAIN,
                seen_on=port_id("fw", "em1"),
            ),
            Client(
                id="c/laptop",
                mac="02:00:00:00:01:02",
                addresses=[ip("198.51.100.60")],
                segment_id=MAIN,
            ),
        ],
        **kw,
    )


def access_point(status: DeviceStatus = DeviceStatus.PARTIAL) -> Snapshot:
    """Partly read: interfaces failed, so only the wireless side and the port MAC are known."""
    radio = Radio(id="ap/radio/0", device_id="ap", name="radio0", band=Band.GHZ_5)
    return snapshot(
        device("ap", DeviceRole.AP, management_address="198.51.100.5"),
        status=status,
        ports=[port("ap", "eth0", mac=AP_MAC), port("ap", "wlan0")],
        segments=[native("ap", "wlan0", name="")],
        radios=[radio],
        wlans=[
            Wlan(
                id="ap/wlan/home",
                device_id="ap",
                ssid="home",
                radio_id=radio.id,
                security=Security.WPA2,
                segment_id=MAIN,
            )
        ],
        errors=[ReadError(device_id="ap", capability="interfaces", message="timed out")],
    )


def unread_switch() -> Snapshot:
    return snapshot(
        device("sw", DeviceRole.SWITCH, management_address="198.51.100.4"),
        status=DeviceStatus.UNREACHABLE,
        errors=[ReadError(device_id="sw", capability="system", message="no answer")],
    )


def site(*snaps: Snapshot, links: tuple[Link, ...] = ()) -> Network:
    """Merge like the runner: once, discover links, merge again with them."""
    first = merge([SITE], snaps, links)
    manual = {frozenset((link.a, link.b)) for link in links}
    found = [x for x in discovered_links(first) if frozenset((x.a, x.b)) not in manual]
    return merge([SITE], snaps, [*links, *found])


def reported(uplinks: bool = True) -> Network:
    return site(isp(), firewall(uplinks), access_point(), unread_switch())


def run(net: Network, *rules: Rule) -> list[Finding]:
    """Findings of these rules only (read errors of the partly read devices left out)."""
    wanted = {r.id for r in rules}
    return [f for f in evaluate(net, list(rules)) if f.rule_id in wanted]


def ids(findings: list[Finding], *, errors: bool = False) -> list[str]:
    return sorted(
        f.rule_id for f in findings if not errors or (f.severity == "error" and not f.incomplete)
    )


WAN_LINK = f"mac:{port_id('fw', 'em0')}~{port_id('isp', 'lan')}"
AP_LINK = f"mac:{port_id('ap', 'eth0')}~{port_id('fw', 'em1')}"


# --- merge ---


@pytest.mark.parametrize("uplinks", [True, False])
def test_two_routers_get_two_untagged_networks(uplinks: bool) -> None:
    net = reported(uplinks)
    assert [s.id for s in net.segments] == [MAIN, ISP_LAN]
    main, outer = net.segments
    assert [m.port_id for m in main.members] == [port_id("ap", "wlan0"), port_id("fw", "em1")]
    assert [m.port_id for m in outer.members] == [port_id("isp", "lan")]
    # the further network is named after its router, the main one keeps its name
    assert (main.name, outer.name) == ("lan", "lan (Fritz!Box)")
    assert {s.device_id: s.segment_id for s in net.subnets} == {"fw": MAIN, "isp": ISP_LAN}
    assert {s.device_id: s.segment_id for s in net.dhcp_servers} == {"fw": MAIN, "isp": ISP_LAN}
    assert [w.segment_id for w in net.wlans] == [MAIN]
    # clients follow their addresses, not the device that reported them
    by_mac = {c.mac: c.segment_id for c in net.clients}
    assert by_mac == {
        WAN_MAC: ISP_LAN,
        AP_MAC: MAIN,
        "02:00:00:00:01:01": ISP_LAN,
        "02:00:00:00:01:02": MAIN,
    }
    assert {d: net.native_segment(d) for d in ("isp", "fw", "ap", "sw")} == {
        "isp": ISP_LAN,
        "fw": MAIN,
        "ap": MAIN,
        "sw": MAIN,
    }
    assert net.native_segment("nope") is None
    assert sorted(link.id for link in net.links) == [AP_LINK, WAN_LINK]


def test_main_network_is_the_one_not_in_front_of_another_router() -> None:
    # no switches or access points: the uplink decides (the ISP router's LAN is in front)
    net = site(isp(), firewall())
    assert {s.device_id: s.segment_id for s in net.subnets} == {"fw": MAIN, "isp": ISP_LAN}

    def router(dev: str, cidr: str, **kw: Any) -> Snapshot:
        return snapshot(device(dev), subnets=[router_lan(dev, cidr)], segments=[native(dev)], **kw)

    outer = router("a-outer", "192.0.2.1/24")
    inner = router(
        "z-inner", "198.51.100.1/24", uplinks=[uplink("z-inner", addresses=[iface("192.0.2.9/24")])]
    )
    assert site(outer, inner).native_segment("z-inner") == MAIN
    # without uplinks the lowest router id keeps the main id ...
    plain = router("z-inner", "198.51.100.1/24")
    assert site(outer, plain).native_segment("a-outer") == MAIN
    # ... unless more switches and access points are managed in another network
    sw = snapshot(device("sw", DeviceRole.SWITCH, management_address="198.51.100.4"))
    net = site(outer, plain, sw)
    assert net.native_segment("z-inner") == MAIN
    assert net.native_segment("a-outer") == native_segment_id(SITE.id, "a-outer")


def test_native_segment_id_scheme() -> None:
    assert native_segment_id("home") == "home/segment/native"
    assert native_segment_id("home", "ctrl/gw 1") == "home/segment/native-ctrl-gw-1"
    assert is_native_segment("home/segment/native") and is_native_segment(ISP_LAN)
    assert not is_native_segment("home/segment/20")


def test_single_router_site_is_unchanged() -> None:
    ap = access_point(DeviceStatus.OK).model_copy(update={"errors": []})
    net = site(firewall(), ap)
    assert [s.id for s in net.segments] == [MAIN]
    assert net.segments[0].name == "lan"
    assert {c.segment_id for c in net.clients} == {MAIN}
    assert net.native_segment("ap") == MAIN


def test_overlapping_routers_share_one_network() -> None:
    # a second router in the same LAN (an old router left in router mode) is one network
    other = snapshot(
        device("old"),
        ports=[port("old", "lan")],
        segments=[native("old", "lan")],
        subnets=[router_lan("old", "198.51.100.2/24")],
        dhcp_servers=[dhcp("old", "198.51.100.10", "198.51.100.50")],
    )
    net = site(firewall(), other)
    assert [s.id for s in net.segments] == [MAIN]
    assert ids(run(net, one_gateway, one_server)) == ["addr.one-gateway", "dhcp.one-server"]


def test_a_cable_between_two_lans_joins_them() -> None:
    # the ISP router's LAN port cabled to a switch port that sends the firewall's LAN untagged:
    # one layer-2 network with two routers, as the old merge said
    sw = snapshot(
        device("sw", DeviceRole.SWITCH, management_address="198.51.100.4"),
        ports=[port("sw", "1"), port("sw", "2")],
        segments=[native("sw", "1", "2")],
    )
    # and a switch without a usable management address takes its neighbour's network
    dumb = snapshot(
        device("dumb", DeviceRole.SWITCH),
        ports=[port("dumb", "1")],
        segments=[native("dumb", "1")],
    )
    cables = (
        Link(id="m:1", a=port_id("sw", "1"), b=port_id("fw", "em1"), origin=LinkOrigin.MANUAL),
        Link(id="m:2", a=port_id("sw", "2"), b=port_id("isp", "lan"), origin=LinkOrigin.MANUAL),
        Link(id="m:3", a=port_id("dumb", "1"), b=port_id("isp", "lan"), origin=LinkOrigin.MANUAL),
    )
    net = site(isp(), firewall(), sw, dumb, links=cables)
    assert [s.id for s in net.segments] == [MAIN]
    assert "addr.one-gateway" in ids(run(net, one_gateway))
    # without the switch cable they stay apart, and the plain switch follows the ISP router
    net = site(isp(), firewall(), sw, dumb, links=(cables[0], cables[2]))
    assert net.native_segment("dumb") == ISP_LAN and net.native_segment("sw") == MAIN


def test_sites_are_split_on_their_own() -> None:
    away = device("away", site_id="branch", management_address="203.0.113.1")
    other = snapshot(
        away,
        segments=[Segment(id=segment_id("branch", None), site_id="branch", name="lan", members=[])],
        subnets=[
            Subnet(
                id="away/subnet/lan",
                segment_id=segment_id("branch", None),
                interface=iface("203.0.113.1/24"),
                device_id="away",
                gateway=True,
            )
        ],
    )
    net = site(isp(), firewall(), other)
    assert sorted(s.id for s in net.segments) == sorted([MAIN, ISP_LAN, "branch/segment/native"])


def test_controller_devices_and_ntp_segments_follow_their_device() -> None:
    from factories import device_time, ntp_server

    ctrl = device("ctrl", DeviceRole.OTHER, management_address="198.51.100.9")
    managed = device("ctrl/ap2", DeviceRole.AP, management_address="192.0.2.7", managed_by="ctrl")
    snap = snapshot(
        ctrl,
        extra_devices=[managed],
        ports=[port("ctrl/ap2", "eth0")],
        segments=[native("ctrl/ap2", "eth0")],
        clients=[Client(id="c/x", mac="02:00:00:00:02:01", segment_id=MAIN, seen_on=None)],
    )
    fw = firewall()
    timed = isp().model_copy(
        update={
            "device": isp().device.model_copy(
                update={"time": device_time(ntp_server=ntp_server(MAIN))}
            )
        }
    )
    net = site(timed, fw, snap)
    seg = {s.id: [m.port_id for m in s.members] for s in net.segments}
    assert seg[ISP_LAN] == [port_id("ctrl/ap2", "eth0"), port_id("isp", "lan")]
    assert next(c for c in net.clients if c.mac == "02:00:00:00:02:01").segment_id == MAIN
    isp_dev = net.device("isp")
    assert isp_dev and isp_dev.time and isp_dev.time.ntp_server
    assert isp_dev.time.ntp_server.segments == [ISP_LAN]


# --- the findings of the report ---


@pytest.mark.parametrize("uplinks", [True, False])
def test_reported_case_has_no_errors(uplinks: bool) -> None:
    net = reported(uplinks)
    out = evaluate(net, RULES)
    assert ids(out, errors=True) == []
    for rule in (one_gateway, one_server, native_mismatch, tagged_both_ends, trunk_scope):
        assert run(net, rule) == [], rule
    # the access point's link cannot be checked: incomplete, not an error
    paths = run(net, path_to_gateway)
    assert [(f.incomplete, f.objects) for f in paths] == [(True, [AP_LINK, port_id("ap", "eth0")])]
    assert paths[0].message == (
        "ap was not fully read, so OPNsense port em1 to ap port eth0 could not be checked."
    )


def test_double_nat_is_information_naming_both_routers() -> None:
    (f,) = run(reported(), double_nat)
    assert f.severity == "info" and not f.incomplete
    assert f.objects == ["fw", "isp", "fw/uplink/wan"]
    assert f.message == (
        "OPNsense gets its WAN address 192.0.2.2 from Fritz!Box (lan (Fritz!Box) (untagged "
        "network), 192.0.2.1/24): two routers in a row (cable Fritz!Box port lan to OPNsense "
        "port em0)."
    )
    assert f.fix is not None
    assert "bridge (modem) mode" in f.fix and "exposed host" in f.fix
    assert f.fix.startswith("Nothing to do if everything works.")


def test_double_nat_without_uplink_data_uses_the_cable() -> None:
    (f,) = run(reported(uplinks=False), double_nat)
    assert f.severity == "info" and f.objects == ["fw", "isp", WAN_LINK]
    assert f.message.startswith(
        "OPNsense port em0 is in no network of OPNsense and is cabled to Fritz!Box port lan"
    )
    assert "sits behind Fritz!Box" in f.message


def test_double_nat_private_and_cgnat_uplinks() -> None:
    private = uplink("fw", addresses=[iface("10.0.0.2/24")])
    cgnat = uplink("gw", addresses=[iface("100.64.0.23/10")])
    public = uplink("pub")
    net = merge(
        [SITE],
        [
            snapshot(device("fw"), uplinks=[private]),
            snapshot(device("gw"), uplinks=[cgnat]),
            snapshot(device("pub"), uplinks=[public]),
        ],
    )
    out = {f.objects[0]: f for f in run(net, double_nat)}
    assert sorted(out) == ["fw", "gw"]
    assert "private WAN address 10.0.0.2" in out["fw"].message
    assert out["fw"].fix is not None and "Add that router to Signalbox" in out["fw"].fix
    assert "carrier-grade NAT" in out["gw"].message
    assert all(f.severity == "info" for f in out.values())


def test_double_nat_fallback_needs_a_router_lan_on_the_other_end() -> None:
    # the other end sends a network it does not route (a gateway in access-point mode)
    ap_mode = isp().model_copy(update={"subnets": []})
    assert run(site(ap_mode, firewall(uplinks=False)), double_nat) == []


# --- link rules on uncertain data ---


def _ap_lldp(status: DeviceStatus, errors: bool) -> Network:
    """The firewall and the access point on one LLDP cable; the AP sends nothing untagged."""
    ap = access_point(status)
    if not errors:
        ap = ap.model_copy(update={"errors": []})
    cable = Link(id="lldp:1", a=port_id("fw", "em1"), b=port_id("ap", "eth0"), origin="lldp")
    return site(firewall(), ap, links=(cable,))


def test_partly_read_end_is_not_an_error() -> None:
    for status, errors in ((DeviceStatus.PARTIAL, True), (DeviceStatus.UNREACHABLE, False)):
        net = _ap_lldp(status, errors)
        assert run(net, native_mismatch) == []
        assert all(f.incomplete for f in run(net, path_to_gateway))
    # fully read, the same cable is a real mismatch
    (f,) = run(_ap_lldp(DeviceStatus.OK, False), native_mismatch)
    assert f.severity == "error" and not f.incomplete


def test_mac_inferred_link_disagreement_is_incomplete() -> None:
    ap = access_point(DeviceStatus.OK).model_copy(update={"errors": []})
    ap = ap.model_copy(
        update={
            "segments": [
                native("ap", "wlan0", name=""),
                Segment(
                    id=segment_id(SITE.id, 20),
                    site_id=SITE.id,
                    vlan=20,
                    members=[PortMembership(port_id=port_id("ap", "eth0"), mode=T)],
                ),
            ],
            "wlans": [ap.wlans[0].model_copy(update={"segment_id": segment_id(SITE.id, 20)})],
        }
    )
    fw = firewall()
    fw = fw.model_copy(
        update={
            "subnets": [
                *fw.subnets,
                Subnet(
                    id="fw/subnet/iot",
                    segment_id=segment_id(SITE.id, 20),
                    interface=iface("203.0.113.1/24"),
                    device_id="fw",
                    gateway=True,
                ),
            ]
        }
    )
    net = site(fw, ap)
    (m,) = run(net, native_mismatch)
    assert m.incomplete and m.objects == [AP_LINK, port_id("fw", "em1"), port_id("ap", "eth0")]
    assert "only inferred from a MAC table" in m.message
    (t,) = run(net, tagged_both_ends)
    assert t.incomplete and "only inferred from a MAC table" in t.message
    paths = run(net, path_to_gateway)
    assert all(p.incomplete for p in paths)
    assert [p.objects for p in paths] == [
        [segment_id(SITE.id, 20), AP_LINK, port_id("fw", "em1")],
        [MAIN, AP_LINK, port_id("ap", "eth0")],
    ]
    assert paths[0].message.startswith(
        "VLAN 20, used on ap, is not configured on OPNsense port em1. The link OPNsense port "
        "em1 to ap port eth0 is only inferred from a MAC table"
    )


def test_uplink_port_carries_the_upstream_network() -> None:
    # an entered (manual) cable to the WAN port: compared against the ISP router's LAN
    cable = Link(
        id="manual:wan", a=port_id("isp", "lan"), b=port_id("fw", "em0"), origin=LinkOrigin.MANUAL
    )
    net = site(isp(), firewall(), links=(cable,))
    assert run(net, native_mismatch, tagged_both_ends) == []
    edge = next(e for e in view(net)["edges"] if e["id"] == "manual:wan")
    assert edge["b"]["uplink"] is True and edge["a"]["uplink"] is False
    assert edge["segments"] == [
        {
            "segment_id": ISP_LAN,
            "name": "lan (Fritz!Box)",
            "a": "untagged",
            "b": "untagged",
            "consistent": True,
        }
    ]
    # an uplink in front of a router Signalbox does not know: nothing to compare
    lone = site(
        isp(), firewall().model_copy(update={"uplinks": [uplink("fw", port="em0")]}), links=(cable,)
    )
    assert run(lone, native_mismatch) == []
    # the ISP router's LAN port sends a different network than the one the WAN is in
    wrong = isp().model_copy(
        update={
            "segments": [
                native("isp"),
                Segment(
                    id=segment_id(SITE.id, 30),
                    site_id=SITE.id,
                    vlan=30,
                    name="Guest",
                    members=[PortMembership(port_id=port_id("isp", "lan"), mode=U)],
                ),
            ]
        }
    )
    (f,) = run(site(wrong, firewall(), links=(cable,)), native_mismatch)
    assert f.severity == "error"
    assert "OPNsense port em0 sends lan (Fritz!Box) untagged" in f.message


# --- desired state and plans ---


def test_desired_state_native_means_the_devices_own_untagged_network() -> None:
    net = reported()
    state = from_network(net, SITE.id)
    spec = state.sites[SITE.id]
    # only the main untagged network is exported as "native"; the ISP router's is not declared
    assert [(s.vlan, s.gateway.device if s.gateway else None) for s in spec.segments] == [
        ("native", "fw")
    ]
    ports = {(p.device, p.port): p.untagged for p in spec.ports}
    assert ports == {("ap", "wlan0"): "native", ("fw", "em1"): "native", ("isp", "lan"): "native"}
    # the exported state has no drift against the network it came from
    assert [f for r in drift_rules(state) for f in run(net, r)] == []
    declared = parse(
        "sites: {home: {wlans: [{ssid: home, security: wpa2-psk, devices: [ap]}],"
        " ports: [{device: isp, port: lan, untagged: native}]}}"
    )
    assert [f for r in drift_rules(declared) for f in run(net, r)] == []


def test_planned_native_port_and_ssid_stay_in_the_devices_network() -> None:
    from signalbox.changes import Change

    net = reported()
    port_change = Change(
        kind=ChangeKind.PORT,
        site_id=SITE.id,
        device_id="isp",
        key=port_id("isp", "lan"),
        old=PortValue(untagged="native"),
        new=PortValue(untagged="native"),
    )
    after = apply_change(net, port_change)
    assert after.untagged_segments(port_id("isp", "lan")) == [ISP_LAN]
    wlan_change = Change(
        kind=ChangeKind.WLAN,
        site_id=SITE.id,
        device_id="isp",
        key="guest",
        old=None,
        new=WlanValue(ssid="guest", security=Security.WPA2),
    )
    after = apply_change(net, wlan_change)
    assert {w.segment_id for w in after.wlans if w.ssid == "guest"} == {ISP_LAN}


def test_pvid_one_lands_in_the_devices_untagged_network() -> None:
    snap = isp().model_copy(update={"ports": [port("isp", "lan", mac=ISP_MAC, pvid=1)]})
    net = site(snap, firewall())
    assert net.pvid_segment(port_id("isp", "lan")) == ISP_LAN
