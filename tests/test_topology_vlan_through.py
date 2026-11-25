"""One jack, one cable to a device (#545), with the OpenWrt simulator as the switch.

A router with one physical port and an ARP table only (as OPNsense reports it) is cabled to an
OpenWrt switch (DSA bridge table): its LAN untagged, a WAN VLAN 20 tagged. The WAN VLAN runs
through the switch and its trunk to a second switch without a table, and on to the upstream
router (the modem). The switch learns the router's MAC behind its own port, behind the trunk
and behind the port of the WAN VLAN: only the first is a cable.

Documentation addresses (LAN 192.0.2.0/24, WAN 198.51.100.0/24), MACs 02:...
"""

from __future__ import annotations

from ipaddress import ip_interface

import pytest
from pydantic import SecretStr

from factories import SITE, client, device, port, snapshot
from signalbox.adapters import AdapterContext
from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.fdb import adjacencies, index
from signalbox.merge import merge
from signalbox.model import (
    DeviceRole,
    FdbEntry,
    Link,
    LinkOrigin,
    Membership,
    Network,
    PortKind,
    PortMembership,
    PortRole,
    Segment,
    Snapshot,
    Subnet,
    fdb_id,
    port_id,
    segment_id,
)
from signalbox.sim.openwrt import OpenWrtSim
from signalbox.sim.openwrt import create_app as openwrt_app
from signalbox.sim.server import serve
from signalbox.topology import discovered_links

ROUTER_MAC = "02:00:00:00:45:01"
MODEM_MAC = "02:00:00:00:45:03"
DUMB_MAC = "02:00:00:00:45:04"
HOSTS = [f"02:00:00:00:46:{i:02x}" for i in range(8)]
SWITCH_MAC = "02:00:00:01:00:01"  # OpenWrtSim(mac_base=1): bridge and jacks
LAN = segment_id(SITE.id, None)
WAN = segment_id(SITE.id, 20)


async def _switch(sim: OpenWrtSim) -> Snapshot:
    with serve(openwrt_app(sim)) as url:
        config = OpenWrtConfig(
            url=f"{url}/ubus", password=SecretStr(sim.password), allow_insecure_http=True
        )
        ctx = AdapterContext(
            site_id=SITE.id,
            device_id="sw",
            device_name="Switch",
            role=DeviceRole.SWITCH,
            config=config,
        )
        adapter = OpenWrtAdapter(ctx)
        try:
            return await adapter.observe()
        finally:
            await adapter.close()


def _switch_sim() -> OpenWrtSim:
    """lan1: the router (VLAN 1 untagged, VLAN 20 tagged); lan2: the trunk (VLAN 1 untagged,
    VLAN 20 tagged); lan3: VLAN 20 untagged. The bridge learns the router behind all three
    (brforward has no VLAN), the modem, the dumb switch and LAN hosts behind the trunk."""
    sim = OpenWrtSim(mac_base=1)
    network = sim.state["network"]
    network["cfg040f15"]["ports"] = ["lan1:u*", "lan2:u*"]
    network["cfg050f15"]["ports"] = ["lan1:t", "lan2:t", "lan3:u*"]
    sim.learned = [
        ("lan1", ROUTER_MAC, 2),
        ("lan2", ROUTER_MAC, 30),
        ("lan2", MODEM_MAC, 4),
        ("lan2", DUMB_MAC, 9),
        *[("lan2", mac, 12) for mac in HOSTS],
        ("lan3", ROUTER_MAC, 50),
    ]
    return sim


def _router() -> Snapshot:
    """One jack ``igb0`` (LAN untagged) and ``igb0.20`` (WAN VLAN): an ARP table only."""
    rid = "fw"
    igb0, wan = port_id(rid, "igb0"), port_id(rid, "igb0.20")
    return snapshot(
        device(rid, DeviceRole.GATEWAY, management_address="192.0.2.1"),
        ports=[
            port(rid, "igb0", mac=ROUTER_MAC, role=PortRole.JACK, kind=PortKind.ETHERNET, up=True),
            port(rid, "igb0.20", mac=ROUTER_MAC, role=PortRole.VLAN, lower=[igb0]),
        ],
        subnets=[
            Subnet(
                id=f"{rid}/subnet/lan",
                segment_id=LAN,
                interface=ip_interface("192.0.2.1/24"),
                device_id=rid,
                gateway=True,
                interface_name="igb0",
            ),
            Subnet(
                id=f"{rid}/subnet/wan",
                segment_id=WAN,
                interface=ip_interface("198.51.100.2/24"),
                device_id=rid,
                interface_name="igb0.20",
            ),
        ],
        segments=[
            Segment(
                id=LAN,
                site_id=SITE.id,
                members=[PortMembership(port_id=igb0, mode=Membership.UNTAGGED)],
            ),
            Segment(
                id=WAN,
                site_id=SITE.id,
                vlan=20,
                members=[PortMembership(port_id=wan, mode=Membership.TAGGED)],
            ),
        ],
        clients=[
            client(SWITCH_MAC, "192.0.2.2", seen_on=igb0),
            client(HOSTS[0], "192.0.2.50", seen_on=igb0),
            client(MODEM_MAC, "198.51.100.1", seen_on=wan),
        ],
    )


def _modem() -> Snapshot:
    """The upstream router: an ARP table that sees the router on its LAN port."""
    return snapshot(
        device("modem", DeviceRole.GATEWAY, management_address="198.51.100.1"),
        ports=[
            port("modem", "lan", mac=MODEM_MAC, role=PortRole.JACK, kind=PortKind.ETHERNET),
        ],
        subnets=[
            Subnet(
                id="modem/subnet/lan",
                segment_id=WAN,
                interface=ip_interface("198.51.100.1/24"),
                device_id="modem",
                gateway=True,
            )
        ],
        clients=[client(ROUTER_MAC, "198.51.100.2", seen_on=port_id("modem", "lan"))],
    )


def _dumb() -> Snapshot:
    """The second switch: known, but it reports no table."""
    return snapshot(
        device("dumb", DeviceRole.SWITCH),
        ports=[port("dumb", "1", mac=DUMB_MAC, role=PortRole.JACK, kind=PortKind.ETHERNET)],
    )


def _between(net: Network, links: list[Link], a: str, b: str) -> list[Link]:
    def dev(p: str) -> str | None:
        found = net.port(p)
        return found.device_id if found is not None else None

    return [
        link
        for link in links
        if link.origin is LinkOrigin.MAC and {dev(link.a), dev(link.b)} == {a, b}
    ]


async def test_one_port_router_gets_one_link_to_the_switch() -> None:
    switch = await _switch(_switch_sim())
    net = merge([SITE], [_router(), switch, _modem(), _dumb()])
    links = discovered_links(net)

    [cable] = _between(net, links, "fw", "sw")
    assert {cable.a, cable.b} == {"fw/port/igb0", "sw/port/lan1"}
    # the switch sees the router behind its trunk and the WAN VLAN port: no cable there
    for adj in adjacencies(net):
        assert {adj.local, adj.remote} != {"fw/port/igb0", "sw/port/lan2"}
        assert {adj.local, adj.remote} != {"fw/port/igb0", "sw/port/lan3"}


def _entry(port: str, mac: str, vlan: int) -> FdbEntry:
    return FdbEntry(
        id=fdb_id("sw", port, mac, vlan),
        device_id="sw",
        port_id=port_id("sw", port),
        mac=mac,
        vlan=vlan,
    )


def _vlan_switch(trunk_untagged: bool = True) -> Snapshot:
    """The same switch, with a table that names the VLAN of each entry (as a managed switch
    does): the router untagged in VLAN 1 on lan1, in VLAN 20 behind the trunk (tagged there)
    and on lan3 (untagged there)."""

    def member(name: str, mode: Membership) -> PortMembership:
        return PortMembership(port_id=port_id("sw", name), mode=mode)

    lan_members = [member("lan1", Membership.UNTAGGED)]
    if trunk_untagged:
        lan_members.append(member("lan2", Membership.UNTAGGED))
    return snapshot(
        device("sw", DeviceRole.SWITCH, management_address="192.0.2.2"),
        ports=[
            port("sw", n, mac=SWITCH_MAC, role=PortRole.JACK, kind=PortKind.ETHERNET, up=True)
            for n in ("lan1", "lan2", "lan3")
        ],
        segments=[
            Segment(id=LAN, site_id=SITE.id, members=lan_members),
            Segment(
                id=WAN,
                site_id=SITE.id,
                vlan=20,
                members=[
                    member("lan1", Membership.TAGGED),
                    member("lan2", Membership.TAGGED),
                    member("lan3", Membership.UNTAGGED),
                ],
            ),
        ],
        fdb=[
            _entry("lan1", ROUTER_MAC, 1),
            _entry("lan2", ROUTER_MAC, 20),
            _entry("lan3", ROUTER_MAC, 20),
            _entry("lan2", MODEM_MAC, 20),
            _entry("lan2", DUMB_MAC, 1),
            *[_entry("lan2", mac, 1) for mac in HOSTS],
        ],
    )


@pytest.mark.parametrize("trunk_untagged", [True, False])
def test_vlans_of_the_table_pick_the_cable(trunk_untagged: bool) -> None:
    net = merge([SITE], [_router(), _vlan_switch(trunk_untagged), _modem(), _dumb()])
    links = discovered_links(net)

    [cable] = _between(net, links, "fw", "sw")
    assert {cable.a, cable.b} == {"fw/port/igb0", "sw/port/lan1"}
    # learned only in VLAN 20, tagged on the trunk, and untagged on lan3: not a sighting
    ix = index(net)
    assert ROUTER_MAC not in ix.tables["sw"]["sw/port/lan2"]
    assert ROUTER_MAC in ix.tables["sw"]["sw/port/lan3"]
    # the switch learns the router and the modem on different ports: it sits between them
    assert not _between(net, links, "fw", "modem")


def test_separate_cables_between_two_switches_stay() -> None:
    """Two cables between two switches whose tables learn each other's jack MACs on the jack
    each cable ends on (a static LAG, or two VLANs on two cables): both stay."""
    macs = {("a", "1"): "02:00:00:00:47:01", ("a", "2"): "02:00:00:00:47:02"}
    macs |= {("b", "1"): "02:00:00:00:48:01", ("b", "2"): "02:00:00:00:48:02"}

    def switch(dev: str, other: str) -> Snapshot:
        return snapshot(
            device(dev, DeviceRole.SWITCH),
            ports=[
                port(dev, n, mac=macs[dev, n], role=PortRole.JACK, kind=PortKind.ETHERNET)
                for n in ("1", "2")
            ],
            fdb=[
                FdbEntry(
                    id=fdb_id(dev, n, macs[other, n]),
                    device_id=dev,
                    port_id=port_id(dev, n),
                    mac=macs[other, n],
                )
                for n in ("1", "2")
            ],
        )

    net = merge([SITE], [switch("a", "b"), switch("b", "a")])
    pairs = {frozenset((link.a, link.b)) for link in discovered_links(net)}
    assert pairs == {
        frozenset(("a/port/1", "b/port/1")),
        frozenset(("a/port/2", "b/port/2")),
    }
