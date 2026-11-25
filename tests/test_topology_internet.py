"""The Internet cloud of the topology view (#534): one cloud for the whole topology, an edge per
uplink that has no known router in front of it, started at the uplink port."""

from __future__ import annotations

from typing import Any

from factories import SITE, device, iface, port, uplink
from signalbox.model import (
    GatewayGroup,
    GatewayGroupMember,
    GroupMode,
    Network,
    Site,
    Subnet,
    UplinkHealth,
    UplinkState,
    object_id,
    segment_id,
)
from signalbox.topology import INTERNET_ID, view

SITE2 = Site(id="branch", name="Branch")


def lan(dev: str, address: str, site: Site = SITE) -> Subnet:
    return Subnet(
        id=object_id(dev, "subnet", "lan"),
        segment_id=segment_id(site.id, None),
        interface=iface(address),
        device_id=dev,
        gateway=True,
    )


def net(**kw: Any) -> Network:
    return Network(**({"sites": [SITE]} | kw))


def wan(topo: dict[str, Any]) -> list[dict[str, Any]]:
    assert topo["internet"] is not None
    result: list[dict[str, Any]] = topo["internet"]["edges"]
    return result


def test_one_gateway_has_one_edge_to_the_cloud() -> None:
    n = net(
        devices=[device("gw")],
        ports=[port("gw", "wan")],
        uplinks=[uplink("gw", port="wan")],
    )
    topo = view(n)
    (edge,) = wan(topo)
    assert topo["internet"]["id"] == INTERNET_ID
    assert edge["a"]["port_id"] == "gw/port/wan" and edge["a"]["uplink"] is True
    assert edge["b"]["device_id"] == INTERNET_ID
    assert edge["wan"]["kind"] == "dhcp" and edge["wan"]["state"] == "online"
    assert edge["wan"]["nat"] == "public" and edge["wan"]["address"] == "198.51.100.23"
    assert edge["wan"]["role"] == "single" and edge["wan"]["down"] is False
    # the cloud is no device: not a node, not an edge of the links
    assert INTERNET_ID not in {x["id"] for x in topo["nodes"]}
    assert all(e["kind"] != "wan" for e in topo["edges"])


def test_no_uplink_no_cloud() -> None:
    assert view(net(devices=[device("sw")]))["internet"] is None


def test_a_double_nat_router_has_no_cloud_edge() -> None:
    n = net(
        devices=[device("outer"), device("inner")],
        subnets=[lan("outer", "192.0.2.1/24"), lan("inner", "198.51.100.1/24")],
        uplinks=[
            uplink("outer"),
            uplink("inner", addresses=[iface("192.0.2.7/24")]),
        ],
    )
    topo = view(n)
    assert [e["a"]["device_id"] for e in wan(topo)] == ["outer"]
    # the inner router is drawn to the router in front of it instead (#375)
    assert [e["origin"] for e in topo["edges"]] == ["address"]


def test_two_sites_share_one_cloud() -> None:
    n = net(
        sites=[SITE, SITE2],
        devices=[device("gw1"), device("gw2", site_id=SITE2.id)],
        uplinks=[uplink("gw1"), uplink("gw2", addresses=[iface("100.64.0.9/10")])],
    )
    topo = view(n)
    edges = wan(topo)
    assert sorted(e["a"]["device_id"] for e in edges) == ["gw1", "gw2"]
    assert {e["b"]["device_id"] for e in edges} == {INTERNET_ID}
    cgnat = next(e for e in edges if e["a"]["device_id"] == "gw2")
    assert cgnat["wan"]["nat"] == "cgnat" and cgnat["wan"]["address"] is None


def test_a_down_uplink_is_down() -> None:
    n = net(devices=[device("gw")], uplinks=[uplink("gw", up=False, since=None)])
    (edge,) = wan(view(n))
    assert edge["wan"]["down"] is True and edge["wan"]["state"] == "down"
    assert edge["a"]["port_id"].startswith("gw/")  # no port: the wire starts at the device box


def test_health_decides_the_state() -> None:
    health = UplinkHealth(state=UplinkState.DEGRADED)
    n = net(devices=[device("gw")], uplinks=[uplink("gw", health=health)])
    assert wan(view(n))[0]["wan"]["state"] == "degraded"


def test_multi_wan_marks_active_and_backup() -> None:
    primary, spare = uplink("gw", "wan1"), uplink("gw", "wan2", addresses=[iface("203.0.113.9/24")])
    members = [
        GatewayGroupMember(name="wan1", uplink_id=primary.id, tier=1),
        GatewayGroupMember(name="wan2", uplink_id=spare.id, tier=2, state=UplinkState.STANDBY),
    ]
    group = GatewayGroup(
        id=object_id("gw", "gateway-group", "wan"),
        device_id="gw",
        name="wan",
        mode=GroupMode.FAILOVER,
        members=members,
        active="wan1",
    )
    n = net(devices=[device("gw")], uplinks=[primary, spare], gateway_groups=[group])
    roles = {e["wan"]["name"]: (e["wan"]["role"], e["wan"]["state"]) for e in wan(view(n))}
    assert roles == {"wan1": ("active", "online"), "wan2": ("backup", "standby")}
    # without a reported active member the first tier is the active one; balancing: all of them
    group.active = None
    roles = {e["wan"]["name"]: e["wan"]["role"] for e in wan(view(n))}
    assert roles == {"wan1": "active", "wan2": "backup"}
    group.mode = GroupMode.BALANCE
    members[1].state = None
    roles = {e["wan"]["name"]: e["wan"]["role"] for e in wan(view(n))}
    assert roles == {"wan1": "active", "wan2": "active"}


def test_an_uplink_of_a_device_that_is_not_a_node_is_left_out() -> None:
    host = device("host")
    guest = device("guest", hosted_on="host")
    n = net(devices=[host, guest], uplinks=[uplink("guest")])
    assert view(n)["internet"] is None
