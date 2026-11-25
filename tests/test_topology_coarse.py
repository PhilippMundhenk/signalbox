"""A coarse host list is no per-port table (#529), with the simulators of the devices.

The FRITZ!Box host list puts every wired host of its LAN on one port (``lan``, ``Port.coarse``).

1. A router that only has an ARP table, cabled to the FRITZ!Box, and an OpenWrt access point
   (bridge table) cabled to another FRITZ!Box port: one link router - FRITZ!Box, one link
   access point - FRITZ!Box, none between the access point and the router.
2. A Wi-Fi mesh: one OpenWrt access point cabled to the FRITZ!Box, two mesh access points
   reaching it over their Wi-Fi station (the STP root port of their bridge): one wired link
   FRITZ!Box - wired AP, the mesh links, no FRITZ!Box - mesh AP link.

Documentation addresses (the FRITZ!Box LAN is 192.0.2.0/24), MACs 02:...
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from ipaddress import ip_address, ip_network

import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from factories import SITE, client, device, port, snapshot
from signalbox.adapters import AdapterContext
from signalbox.adapters.fritzbox import FritzboxAdapter, FritzboxConfig
from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.fdb import adjacencies
from signalbox.merge import merge
from signalbox.model import (
    DeviceRole,
    EvidenceSource,
    FdbEntry,
    FdbKind,
    Link,
    LinkKind,
    LinkOrigin,
    Network,
    Port,
    PortKind,
    PortRole,
    Route,
    Snapshot,
    StpPortRole,
    fdb_id,
    port_id,
    route_id,
)
from signalbox.sim.fritzbox import FritzboxSim
from signalbox.sim.fritzbox import create_app as fritzbox_app
from signalbox.sim.openwrt import OpenWrtSim
from signalbox.sim.openwrt import create_app as openwrt_app
from signalbox.sim.server import serve
from signalbox.topology import discovered_links

FRITZ_MAC = "02:00:00:00:52:01"
ROUTER_MAC = "02:00:00:00:52:02"
FRITZ_LAN = "192.0.2.1"


@contextmanager
def _served(app: FastAPI) -> Iterator[str]:
    with serve(app) as url:
        yield url


async def _fritz(sim: FritzboxSim) -> Snapshot:
    with _served(fritzbox_app(sim)) as url:
        config = FritzboxConfig(
            url=url,
            username=sim.username,
            password=SecretStr(sim.password),
            allow_insecure_http=True,
        )
        ctx = AdapterContext(
            site_id=SITE.id,
            device_id="fritz",
            device_name="FRITZ!Box",
            role=DeviceRole.GATEWAY,
            config=config,
        )
        adapter = FritzboxAdapter(ctx)
        try:
            return await adapter.observe()
        finally:
            await adapter.close()


async def _openwrt(sim: OpenWrtSim, device_id: str) -> Snapshot:
    with _served(openwrt_app(sim)) as url:
        config = OpenWrtConfig(
            url=f"{url}/ubus", password=SecretStr(sim.password), allow_insecure_http=True
        )
        ctx = AdapterContext(
            site_id=SITE.id,
            device_id=device_id,
            device_name=device_id.upper(),
            role=DeviceRole.AP,
            config=config,
        )
        adapter = OpenWrtAdapter(ctx)
        try:
            return await adapter.observe()
        finally:
            await adapter.close()


def _port(snap: Snapshot, pid: str) -> Port | None:
    return next((p for p in snap.ports if p.id == pid), None)


def _ap_mac(base: int) -> str:
    """The bridge (and jack) MAC of an OpenWrt simulator with ``mac_base``."""
    return f"02:00:00:{base:02x}:00:01"


def _fritz_sim(*hosts: tuple[str, str]) -> FritzboxSim:
    sim = FritzboxSim()
    sim.ethernet["NewMACAddress"] = FRITZ_MAC
    sim.extra_hosts = [(mac, ip, "DHCP", "Ethernet", "1", "") for mac, ip in hosts]
    return sim


def _router(rid: str) -> Snapshot:
    """A router whose integration reports an ARP table only (no bridge table, as OPNsense
    does; the Linux integration reads no ARP table at all), cabled to the FRITZ!Box: it sees
    the box and the access point on its one port; its default route points to the box."""
    eth0 = port_id(rid, "eth0")
    default = ip_network("0.0.0.0/0")
    return snapshot(
        device(rid, DeviceRole.GATEWAY),
        ports=[port(rid, "eth0", mac=ROUTER_MAC, role=PortRole.JACK, up=True)],
        clients=[
            client(FRITZ_MAC, FRITZ_LAN, seen_on=eth0),
            client(_ap_mac(1), "192.0.2.2", seen_on=eth0),
        ],
        routes=[
            Route(
                id=route_id(rid, "main", default, ip_address(FRITZ_LAN)),
                device_id=rid,
                destination=default,
                gateway=ip_address(FRITZ_LAN),
                interface=eth0,
            )
        ],
    )


def _pairs(links: list[Link]) -> set[frozenset[str]]:
    return {frozenset((link.a, link.b)) for link in links if link.origin is LinkOrigin.MAC}


def _devices(net: Network, link: Link) -> frozenset[str]:
    return frozenset(p.device_id for x in (link.a, link.b) if (p := net.port(x)) is not None)


def _network(*snaps: Snapshot) -> tuple[Network, list[Link]]:
    net = merge([SITE], list(snaps))
    return net, discovered_links(net)


# the merged client keeps the sighting of the first gateway by id: "edge" sorts before the
# box (the router's ARP table names the AP), "router" after it (the box's host list does)
@pytest.mark.parametrize("rid", ["router", "edge"])
@pytest.mark.parametrize("ap_learns_router", [True, False])
async def test_router_with_arp_only_is_linked_to_the_box_not_to_the_ap(
    rid: str, ap_learns_router: bool
) -> None:
    fritz = await _fritz(_fritz_sim((ROUTER_MAC, "192.0.2.10"), (_ap_mac(1), "192.0.2.2")))
    lan = _port(fritz, port_id("fritz", "lan"))
    assert lan is not None and lan.coarse
    ap_sim = OpenWrtSim(mac_base=1)
    # the AP's bridge learns the box (and, while they talk, the router) on its uplink lan1;
    # a DSA bridge only knows what reached the CPU, so the router may be missing (#378)
    ap_sim.learned = [("lan1", FRITZ_MAC, 3)]
    if ap_learns_router:
        ap_sim.learned.append(("lan1", ROUTER_MAC, 40))
    ap = await _openwrt(ap_sim, "ap")
    net, links = _network(fritz, ap, _router(rid))

    assert _pairs(links) == {
        frozenset(("fritz/port/lan", f"{rid}/port/eth0")),
        frozenset(("fritz/port/lan", "ap/port/lan1")),
    }
    for link in links:
        assert _devices(net, link) != {"ap", rid}
    if ap_learns_router:
        # from the AP: the box and the router on lan1, nothing tells them apart; the box holds
        # the default next hop, so it is the nearest (a LAN is a star around its gateway)
        from_ap = [a for a in adjacencies(net) if a.local == "ap/port/lan1"]
        assert [(a.remote, a.inferred) for a in from_ap] == [("fritz/port/lan", True)]
        assert EvidenceSource.GATEWAY in {e.source for e in from_ap[0].evidence}


@pytest.mark.parametrize("mesh_tables", [True, False])
async def test_mesh_aps_get_no_wired_link_to_the_box(mesh_tables: bool) -> None:
    wired_sim = OpenWrtSim(mac_base=1)
    wired = await _openwrt(wired_sim, "wired")
    backhaul = _port(wired, port_id("wired", "phy1-ap0"))
    assert backhaul is not None and backhaul.mac
    mesh_macs = {"mesh1": _ap_mac(2), "mesh2": _ap_mac(3)}

    meshes: list[Snapshot] = []
    for (name, mac), base in zip(mesh_macs.items(), (2, 3), strict=True):
        sim = OpenWrtSim(mac_base=base)
        uplink = sim.state["wireless"]["uplink"]
        uplink.update({"disabled": "0", "network": "lan", "wds": "1"})
        sim.state["network"]["cfg030f15"]["stp"] = "1"
        sim.stations = {"uplink": [backhaul.mac]}
        sim.stp_root_port = "phy1-sta0"
        others = [m for m in mesh_macs.values() if m != mac]
        if mesh_tables:  # the bridge learns the LAN behind its Wi-Fi station
            sim.learned = [
                ("phy1-sta0", FRITZ_MAC, 5),
                ("phy1-sta0", _ap_mac(1), 5),
                *[("phy1-sta0", m, 9) for m in others],
            ]
        else:  # learned on WDS interfaces the integration has no port for
            sim.learned = [("phy1-ap0.sta2", FRITZ_MAC, 5)]
        snap = await _openwrt(sim, name)
        [bridge] = [b for b in snap.device.stp_bridges or [] if b.name == "br-lan"]
        assert bridge.root_port_id == port_id(name, "phy1-sta0")
        sta = _port(snap, port_id(name, "phy1-sta0"))
        assert sta is not None and sta.stp is not None and sta.stp.role is StpPortRole.ROOT
        meshes.append(snap)
    # the wired AP learns the box on lan1; the mesh APs on WDS interfaces it has no port for
    wired_sim.learned = [
        ("lan1", FRITZ_MAC, 3),
        *[("phy1-ap0.sta1", m, 4) for m in mesh_macs.values()],
    ]
    wired = await _openwrt(wired_sim, "wired")
    # the box lists every AP as a wired host of its LAN
    fritz = await _fritz(
        _fritz_sim(
            (_ap_mac(1), "192.0.2.2"),
            (mesh_macs["mesh1"], "192.0.2.3"),
            (mesh_macs["mesh2"], "192.0.2.4"),
        )
    )
    net, links = _network(fritz, wired, *meshes)

    cables = [x for x in links if x.kind is LinkKind.CABLE]
    assert [frozenset((x.a, x.b)) for x in cables] == [
        frozenset(("fritz/port/lan", "wired/port/lan1"))
    ]
    mesh = {_devices(net, x) for x in links if x.origin is LinkOrigin.MESH}
    assert mesh == {frozenset({"wired", "mesh1"}), frozenset({"wired", "mesh2"})}
    for x in links:
        assert _devices(net, x) not in ({"fritz", "mesh1"}, {"fritz", "mesh2"})


def test_coarse_port_only_links_devices_whose_table_learns_it_on_a_wired_port() -> None:
    """Without simulators: the box's coarse port learns two APs; one learns the box on its
    jack, the other only on its Wi-Fi interface: only the first is linked."""

    def entry(dev: str, name: str, mac: str) -> FdbEntry:
        return FdbEntry(
            id=fdb_id(dev, name, mac),
            device_id=dev,
            port_id=port_id(dev, name),
            mac=mac,
            kind=FdbKind.DYNAMIC,
        )

    box = snapshot(
        device("box", DeviceRole.GATEWAY),
        ports=[port("box", "lan", mac=FRITZ_MAC, kind=PortKind.BRIDGE, coarse=True)],
        clients=[
            client(_ap_mac(1), seen_on="box/port/lan"),
            client(_ap_mac(2), seen_on="box/port/lan"),
        ],
    )

    def ap(name: str, mac: str, toward: str) -> Snapshot:
        return snapshot(
            device(name, DeviceRole.AP),
            ports=[
                port(name, "lan1", mac=mac, role=PortRole.JACK),
                port(
                    name,
                    "wlan0",
                    mac=mac[:-2] + "02",
                    kind=PortKind.WIRELESS,
                    role=PortRole.WIRELESS,
                ),
            ],
            fdb=[entry(name, toward, FRITZ_MAC)],
        )

    net = merge([SITE], [box, ap("a1", _ap_mac(1), "lan1"), ap("a2", _ap_mac(2), "wlan0")])
    from_box = [(a.local, a.remote) for a in adjacencies(net) if a.local == "box/port/lan"]
    assert from_box == [("box/port/lan", "a1/port/lan1")]
