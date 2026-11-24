"""A switch chain without LLDP (#378): gateway (ARP table only) - server switch (OpenWrt DSA,
bridge MAC table) = trunk = distribution switch (NETGEAR Plus: no table, no MAC per port) -
two OpenWrt access points (bridge MAC tables). The cables are inferred from the tables of the
devices around the switch that has none; no cable is claimed between the gateway and an AP."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from factories import SITE, client, device, port, snapshot
from signalbox.fdb import adjacencies, index
from signalbox.merge import merge
from signalbox.model import (
    DeviceRole,
    EvidenceSource,
    FdbEntry,
    FdbKind,
    Link,
    LinkOrigin,
    Membership,
    Network,
    PortKind,
    PortMembership,
    PortRole,
    Segment,
    Snapshot,
    fdb_id,
    port_id,
    segment_id,
)
from signalbox.rules import Rule, Severity, evaluate
from signalbox.topology import discovered_links, view

sys.path.insert(0, str(Path(__file__).parent))

GW, SRV, DIST, AP1, AP2 = (
    "02:00:00:00:01:01",
    "02:00:00:00:02:01",
    "02:00:00:00:03:01",
    "02:00:00:00:04:01",
    "02:00:00:00:05:01",
)
LAPTOP = "02:00:00:00:09:01"
NATIVE, MGMT, IOT = segment_id(SITE.id, None), segment_id(SITE.id, 10), segment_id(SITE.id, 20)


def entry(dev: str, name: str, mac: str, kind: FdbKind = FdbKind.DYNAMIC) -> FdbEntry:
    return FdbEntry(
        id=fdb_id(dev, name, mac), device_id=dev, port_id=port_id(dev, name), mac=mac, kind=kind
    )


def segments(members: dict[str, list[tuple[str, Membership]]]) -> list[Segment]:
    """Segments of one device: segment id -> (port id, mode)."""
    vlans = {NATIVE: None, MGMT: 10, IOT: 20}
    return [
        Segment(
            id=seg,
            site_id=SITE.id,
            vlan=vlans[seg],
            members=[PortMembership(port_id=p, mode=m) for p, m in ms],
        )
        for seg, ms in members.items()
    ]


U, T = Membership.UNTAGGED, Membership.TAGGED


def chain(tables: bool = True, dist_mac: bool = True) -> Network:
    """The chain of the issue. ``tables``: the OpenWrt devices report their bridge tables
    (False: an older ACL, today's state); ``dist_mac``: the plus switch reports its MAC (False:
    only the gateway's ARP entry for its management address names it)."""
    gw = snapshot(
        device("gw", DeviceRole.GATEWAY),
        ports=[
            port("gw", "igb1", mac=GW, role=PortRole.JACK, speed_mbps=1000, pvid=1),
            port(
                "gw",
                "vlan10",
                mac=GW,
                kind=PortKind.VIRTUAL,
                role=PortRole.VLAN,
                lower=[port_id("gw", "igb1")],
            ),
        ],
        # the ARP/NDP table: the management network is VLAN 10, AP 1 sits in the native one
        clients=[
            client(SRV, "192.0.2.2", seen_on="gw/port/vlan10"),
            client(DIST, "192.0.2.3", seen_on="gw/port/vlan10"),
            client(AP1, "198.51.100.4", seen_on="gw/port/igb1"),
            client(AP2, "192.0.2.5", seen_on="gw/port/vlan10"),
        ],
    )
    srv_jacks = [f"lan{n}" for n in range(1, 6)]
    srv = snapshot(
        device("srv", DeviceRole.SWITCH, management_address="192.0.2.2"),
        ports=[
            port("srv", "eth0", mac=SRV, role=PortRole.CPU),
            *[
                port(
                    "srv",
                    j,
                    mac=SRV,
                    role=PortRole.JACK,
                    lower=[port_id("srv", "eth0")],
                    speed_mbps=1000,
                    pvid=1,
                    up=True,
                )
                for j in srv_jacks
            ],
            port(
                "srv",
                "br-lan",
                mac=SRV,
                kind=PortKind.BRIDGE,
                role=PortRole.BRIDGE,
                lower=[port_id("srv", j) for j in srv_jacks],
            ),
        ],
        segments=segments(
            {
                NATIVE: [("srv/port/lan1", U), ("srv/port/lan5", U)],
                MGMT: [("srv/port/lan1", T), ("srv/port/lan5", T)],
                IOT: [("srv/port/lan5", T)],
            }
        ),
        fdb=[
            *[entry("srv", j, SRV, FdbKind.SELF) for j in srv_jacks],
            entry("srv", "lan1", GW),
            entry("srv", "lan5", DIST),
            entry("srv", "lan5", AP1),
            entry("srv", "lan5", AP2),
            entry("srv", "lan5", LAPTOP),
        ]
        if tables
        else [],
    )

    def dist_port(n: int, speed: int, up: bool = True) -> Any:
        return port("dist", str(n), speed_mbps=speed, pvid=1, up=up)

    dist = snapshot(
        device(
            "dist",
            DeviceRole.SWITCH,
            management_address="192.0.2.3",
            mac=DIST if dist_mac else None,
        ),
        ports=[
            dist_port(1, 1000),
            dist_port(2, 1000, up=False),
            dist_port(3, 1000),
            dist_port(4, 1000),
            dist_port(5, 100),
        ],
        segments=segments(
            {
                NATIVE: [(f"dist/port/{n}", U) for n in (1, 2, 3, 4, 5)],
                MGMT: [("dist/port/1", T), ("dist/port/2", T), ("dist/port/3", T)],
                IOT: [("dist/port/1", T)],
            }
        ),
    )

    def ap(name: str, mac: str, speed: int, vlans: list[str], others: list[str]) -> Snapshot:
        return snapshot(
            device(name, DeviceRole.AP),
            ports=[
                port(name, "lan", mac=mac, role=PortRole.JACK, speed_mbps=speed, pvid=1),
                port(
                    name,
                    "phy0-ap0",
                    mac=mac[:-2] + "02",
                    kind=PortKind.WIRELESS,
                    role=PortRole.WIRELESS,
                ),
                port(
                    name,
                    "br-lan",
                    mac=mac,
                    kind=PortKind.BRIDGE,
                    role=PortRole.BRIDGE,
                    lower=[port_id(name, "lan"), port_id(name, "phy0-ap0")],
                ),
            ],
            segments=segments(
                {seg: [(f"{name}/port/lan", U if seg == NATIVE else T)] for seg in vlans}
            ),
            fdb=[
                entry(name, "lan", mac, FdbKind.SELF),
                *[entry(name, "lan", m) for m in (GW, SRV, DIST, *others)],
            ]
            if tables
            else [],
        )

    ap1 = ap("ap1", AP1, 1000, [NATIVE, MGMT], [AP2, LAPTOP])
    ap2 = ap("ap2", AP2, 100, [NATIVE], [AP1])
    if tables:
        ap2 = ap2.model_copy(update={"fdb": [*ap2.fdb, entry("ap2", "phy0-ap0", LAPTOP)]})
    return merge([SITE], [gw, srv, dist, ap1, ap2])


def pairs(links: list[Link]) -> set[frozenset[str]]:
    return {frozenset((link.a, link.b)) for link in links}


def test_the_chain_is_inferred_from_every_table() -> None:
    links = discovered_links(chain())
    assert all(link.origin is LinkOrigin.MAC for link in links)
    assert pairs(links) == {
        frozenset(("gw/port/igb1", "srv/port/lan1")),
        # the plus switch has no table: its ports are chosen by VLANs, PVID and speed
        frozenset(("srv/port/lan5", "dist/port/1")),
        frozenset(("ap1/port/lan", "dist/port/3")),
        frozenset(("ap2/port/lan", "dist/port/5")),
    }
    by_pair = {frozenset((link.a, link.b)): link for link in links}
    direct = by_pair[frozenset(("gw/port/igb1", "srv/port/lan1"))]
    assert not direct.inferred  # the server switch's table confirms it
    trunk = by_pair[frozenset(("srv/port/lan5", "dist/port/1"))]
    assert trunk.inferred
    seen = {(e.port_id, e.source) for e in trunk.evidence}
    # the server switch sees the plus switch behind its trunk, both APs see the server switch
    # and the plus switch behind their uplinks
    assert ("srv/port/lan5", EvidenceSource.FDB) in seen
    assert {("ap1/port/lan", EvidenceSource.FDB), ("ap2/port/lan", EvidenceSource.FDB)} <= seen
    assert {("gw/port/igb1", EvidenceSource.ARP), ("srv/port/lan1", EvidenceSource.FDB)} <= {
        (e.port_id, e.source) for e in direct.evidence
    }


def test_no_cable_from_the_gateway_to_an_ap() -> None:
    """Today's state: no table anywhere, only the gateway's ARP table. The switches it sees
    are taken to sit before the APs, and every link is inferred."""
    links = discovered_links(chain(tables=False))
    ends = {e for link in links for e in (link.a, link.b)}
    assert not any(e.startswith(("ap1/", "ap2/")) for e in ends)
    assert links and all(link.inferred for link in links)
    assert {"srv", "dist"} == {e.split("/")[0] for e in ends} - {"gw"}


def test_the_plus_switch_found_by_its_management_address() -> None:
    """An Easy Smart switch does not even report its MAC: the gateway's ARP entry for its
    management address names it."""
    net = chain(dist_mac=False)
    assert index(net).owner[DIST] == "dist"
    links = discovered_links(net)
    trunk = next(link for link in links if "dist/port/1" in (link.a, link.b))
    assert trunk.a == "srv/port/lan5" or trunk.b == "srv/port/lan5"
    assert ("gw/port/vlan10", EvidenceSource.ADDRESS) in {
        (e.port_id, e.source) for e in trunk.evidence
    }


def test_known_cables_are_not_guessed_twice() -> None:
    net = chain()
    manual = Link(id="manual:x", a="dist/port/1", b="sw/port/9", origin=LinkOrigin.MANUAL)
    net = net.model_copy(update={"links": [manual]})
    guessed = {a.remote for a in adjacencies(net) if a.inferred}
    assert "dist/port/1" not in guessed


def test_checks_do_not_use_inferred_links() -> None:
    net = chain()
    net = net.model_copy(update={"links": discovered_links(net)})
    seen: list[list[Link]] = []

    def check(n: Network) -> list[Any]:
        seen.append(list(n.links))
        return []

    evaluate(net, [Rule("test.links", "Links", Severity.INFO, "links", check)])
    assert seen and seen[0] and not any(link.inferred for link in seen[0])


def test_view_marks_inferred_links() -> None:
    net = chain()
    net = net.model_copy(update={"links": discovered_links(net)})
    edges = view(net)["edges"]
    trunk = next(e for e in edges if "dist/port/1" in (e["a"]["port_id"], e["b"]["port_id"]))
    assert trunk["inferred"] is True
    assert {"port_id": "srv/port/lan5", "source": "fdb"} in trunk["evidence"]
    assert any(e["inferred"] is False for e in edges)
