from factories import SITE, device, port, snapshot
from signalbox.merge import merge
from signalbox.model import (
    Client,
    DeviceRole,
    Link,
    LinkOrigin,
    Membership,
    Neighbour,
    PortKind,
    PortMembership,
    Segment,
    port_id,
    segment_id,
)
from signalbox.rules import evaluate
from signalbox.topology import (
    discovered_links,
    lldp_links,
    mac_links,
    manual_conflict,
    untagged_only,
    view,
)

GW_MAC, SW_MAC, AP_MAC = "02:00:00:00:01:01", "02:00:00:00:02:01", "02:00:00:00:03:01"


def seg(vlan: int | None, members: dict[str, Membership], name: str | None = None) -> Segment:
    return Segment(
        id=segment_id("home", vlan),
        site_id="home",
        vlan=vlan,
        name=name,
        members=[PortMembership(port_id=p, mode=m) for p, m in members.items()],
    )


def network(links: list[Link] = (), vlans: bool = True):  # type: ignore[assignment,no-untyped-def]
    gw = snapshot(
        device("gw", DeviceRole.GATEWAY, name="Gateway"),
        ports=[port("gw", "lan", mac=GW_MAC)],
        neighbours=[
            Neighbour(
                id="gw/nb/1", local_port_id="gw/port/lan", chassis_id=SW_MAC, remote_port="1"
            ),
            Neighbour(id="gw/nb/2", local_port_id="gw/port/lan", chassis_id="02:ff:ff:ff:ff:ff"),
            Neighbour(id="gw/nb/3", local_port_id="gw/port/ghost", chassis_id=SW_MAC),
        ],
        segments=[seg(20, {"gw/port/lan": Membership.TAGGED}, "IoT")] if vlans else [],
    )
    sw = snapshot(
        device("sw", DeviceRole.SWITCH, name="Switch"),
        ports=[port("sw", "1", mac=SW_MAC), port("sw", "2"), port("sw", "3")],
        neighbours=[
            # by system name, remote port given as MAC
            Neighbour(
                id="sw/nb/1",
                local_port_id="sw/port/1",
                chassis_id="not-a-mac",
                system_name="gateway",
                remote_port=GW_MAC,
            ),
            # neighbour pointing at itself, and one with an unknown remote port
            Neighbour(id="sw/nb/2", local_port_id="sw/port/2", chassis_id=SW_MAC, remote_port="1"),
            Neighbour(id="sw/nb/3", local_port_id="sw/port/2", chassis_id=GW_MAC, remote_port="x"),
            Neighbour(id="sw/nb/4", local_port_id="sw/port/2", chassis_id=GW_MAC),
        ],
        clients=[
            # the AP's port MAC seen on switch port 2: a MAC-table link
            Client(id="sw/c/1", mac=AP_MAC, seen_on="sw/port/2"),
            # the gateway seen on port 1: LLDP already covers that port
            Client(id="sw/c/2", mac=GW_MAC, seen_on="sw/port/1"),
            Client(id="sw/c/3", mac="02:00:00:00:09:09", seen_on="sw/port/3", hostname="tv"),
        ],
        segments=[
            seg(
                20,
                {"sw/port/1": Membership.TAGGED, "sw/port/2": Membership.UNTAGGED},
            )
        ]
        if vlans
        else [],
    )
    ap = snapshot(
        device("ap", DeviceRole.AP, name="AP"),
        ports=[port("ap", "lan", mac=AP_MAC), port("ap", "wlan0", kind=PortKind.WIRELESS)],
        clients=[Client(id="ap/c/1", mac=SW_MAC, seen_on="ap/port/wlan0")],
        segments=[seg(20, {"ap/port/lan": Membership.UNTAGGED})] if vlans else [],
    )
    net = merge([SITE], [gw, sw, ap], links)
    return merge([SITE], [gw, sw, ap], [*links, *discovered_links(net)])


def test_lldp_and_mac_links() -> None:
    net = network()
    lldp = {(link.a, link.b) for link in lldp_links(net)}
    assert lldp == {("gw/port/lan", "sw/port/1"), ("sw/port/1", "gw/port/lan")}
    macs = {(link.a, link.b, link.kind.value) for link in mac_links(net)}
    assert ("sw/port/2", "ap/port/lan", "cable") in macs
    assert ("ap/port/wlan0", "sw/port/1", "wireless") in macs
    found = {(link.origin.value, *sorted((link.a, link.b))) for link in discovered_links(net)}
    assert found == {
        ("lldp", "gw/port/lan", "sw/port/1"),
        ("mac", "ap/port/lan", "sw/port/2"),
    }


def test_view() -> None:
    v = view(network())
    nodes = {n["id"]: n for n in v["nodes"]}
    assert set(nodes) == {"ap", "gw", "sw"}
    sw_ports = {p["name"]: p for p in nodes["sw"]["ports"]}
    assert sw_ports["1"]["tagged"] == ["home/segment/20"]
    assert sw_ports["2"]["untagged"] == ["home/segment/20"]
    edge = next(e for e in v["edges"] if e["origin"] == "lldp")
    (s,) = edge["segments"]
    assert s["name"] == "IoT" and s["consistent"]
    mac_edge = next(e for e in v["edges"] if e["origin"] == "mac")
    assert mac_edge["segments"][0]["consistent"] is True
    assert v["clients"]["sw/port/3"][0]["hostname"] == "tv"


def test_view_with_unknown_port_and_unnamed_segment() -> None:
    link = Link(id="m", a="gw/port/lan", b="nas/port/eth0", origin=LinkOrigin.MANUAL)
    net = network([link], vlans=False)
    net = net.model_copy(update={"segments": [seg(None, {"gw/port/lan": Membership.UNTAGGED})]})
    v = view(net)
    edge = next(e for e in v["edges"] if e["id"] == "m")
    assert edge["b"] == {
        "port_id": "nas/port/eth0",
        "device_id": "nas",
        "port": "eth0",
        "known": False,
        "speed_mbps": None,
        "max_speed_mbps": None,
        "mtu": None,
        "up": None,
        "uplink": False,
    }
    assert edge["segments"][0]["consistent"] is False
    assert v["segments"] == {"home/segment/native": "untagged"}


def test_manual_conflict() -> None:
    right = Link(id="m1", a="sw/port/1", b="gw/port/lan", origin=LinkOrigin.MANUAL)
    wrong = Link(id="m2", a="gw/port/lan", b="ap/port/lan", origin=LinkOrigin.MANUAL)
    assert list(manual_conflict.check(network([right]))) == []
    results = list(manual_conflict.check(network([wrong])))
    messages = " | ".join(r.message for r in results)
    assert "LLDP sees gw/port/lan ↔ sw/port/1" in messages
    assert "MAC sees ap/port/lan ↔ sw/port/2" in messages


def test_untagged_only_links() -> None:
    gwp = port_id("gw", "lan")
    net = network()
    assert list(untagged_only.check(network(vlans=False))) == []
    # LLDP link gw-sw carries VLAN 20 tagged; the MAC link sw/2-ap carries only untagged
    msgs = [r.message for r in untagged_only.check(net)]
    assert msgs == ["sw/port/2 ↔ ap/port/lan carries no tagged VLAN"]
    assert gwp not in msgs[0]


def test_rules_registered() -> None:
    from signalbox.rules.builtin import RULES

    ids = {r.id for r in RULES}
    assert {"topology.manual-conflict", "topology.untagged-only-link"} <= ids
    assert evaluate(network(), [manual_conflict, untagged_only])


def test_wireless_links_are_not_trunks_and_empty_mac() -> None:
    from signalbox.model import LinkKind
    from signalbox.topology import _mac

    assert _mac(None) is None and _mac("") is None
    radio = Link(
        id="w", a="sw/port/3", b="ap/port/lan", kind=LinkKind.WIRELESS, origin=LinkOrigin.MANUAL
    )
    msgs = [r.message for r in untagged_only.check(network([radio]))]
    assert all("sw/port/3" not in m for m in msgs)
