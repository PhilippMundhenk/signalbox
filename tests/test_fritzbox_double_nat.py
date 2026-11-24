"""A Fritz!Box behind another router (double NAT, #375): the inner box reaches the internet over
LAN 1 ("existing access via LAN"), its uplink is read, the front router is found by addresses and
the topology draws the inferred link, for every integration (the link comes from the topology).

Documentation addresses: the front box's LAN is 192.0.2.0/24, the inner box has 192.0.2.20 on
LAN 1 and its own LAN 198.51.100.0/24.
"""

from __future__ import annotations

from collections.abc import Iterator
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any

import pytest
from pydantic import SecretStr

from factories import SITE, client, device, iface, port, snapshot, uplink
from signalbox.adapters import AdapterContext
from signalbox.adapters.fritzbox import FritzboxAdapter, FritzboxConfig, wan_uplink
from signalbox.adapters.fritzbox.routes import default_gateway
from signalbox.merge import merge
from signalbox.model import (
    DeviceRole,
    FdbEntry,
    Link,
    LinkOrigin,
    Membership,
    Neighbour,
    Network,
    PortMembership,
    Segment,
    Snapshot,
    Subnet,
    UplinkKind,
    segment_id,
)
from signalbox.sim.fritzbox import FritzboxSim, forwarding_entry
from signalbox.sim.fritzbox import create_app as fritzbox_app
from signalbox.sim.server import serve
from signalbox.testing import assert_contract
from signalbox.topology import ADDRESS_ORIGIN, discovered_links, front_links, view

FRONT_LAN = "192.0.2.1"
INNER_WAN = "192.0.2.20"
INNER_LAN = "198.51.100.1"


@pytest.fixture
def boxes() -> Iterator[tuple[FritzboxSim, str, FritzboxSim, str]]:
    front, inner = FritzboxSim(), FritzboxSim()
    inner.behind(INNER_WAN, FRONT_LAN, INNER_LAN)
    inner.ethernet["NewMACAddress"] = "02:00:00:00:37:05"
    with serve(fritzbox_app(front)) as front_url, serve(fritzbox_app(inner)) as inner_url:
        yield front, front_url, inner, inner_url


def _adapter(url: str, device_id: str) -> FritzboxAdapter:
    sim = FritzboxSim()
    config = FritzboxConfig(
        url=url, username=sim.username, password=SecretStr(sim.password), allow_insecure_http=True
    )
    context = AdapterContext(
        site_id=SITE.id,
        device_id=device_id,
        device_name=device_id.title(),
        role=DeviceRole.GATEWAY,
        config=config,
    )
    return FritzboxAdapter(context)


async def _read(url: str, device_id: str) -> Snapshot:
    adapter = _adapter(url, device_id)
    try:
        return await assert_contract(adapter)
    finally:
        await adapter.close()


def _network(*snaps: Snapshot) -> Network:
    net = merge([SITE], snaps)
    return merge([SITE], snaps, discovered_links(net))


def _address_edges(net: Network) -> list[dict[str, Any]]:
    return [e for e in view(net)["edges"] if e["origin"] == ADDRESS_ORIGIN]


@pytest.mark.parametrize("enabled", [False, True])
async def test_inner_box_over_lan1_is_drawn_below_the_front_box(
    boxes: tuple[FritzboxSim, str, FritzboxSim, str], enabled: bool
) -> None:
    _, front_url, inner_sim, inner_url = boxes
    # FRITZ!OS may report the LAN 1 connection disabled (address only from
    # GetExternalIPAddress) or enabled with the address in GetInfo (*guess*, #21)
    inner_sim.lan1_enabled = enabled
    front, inner = await _read(front_url, "front"), await _read(inner_url, "inner")
    [up] = inner.uplinks
    assert (up.kind, up.up, up.port_id) == (UplinkKind.OTHER, True, None)
    assert up.addresses == [ip_interface(f"{INNER_WAN}/32")]
    assert up.upstream_gateway == ip_address(FRONT_LAN)
    assert up.vendor_extra["service"] == "WANIPConnection:1"
    calls = [a for s, a, _ in inner_sim.calls if s == "WANIPConnection:1"]
    assert ("GetExternalIPAddress" in calls) is not enabled
    # the default route through the front box, once (the table's default entry is the same)
    defaults = [r for r in inner.routes if r.destination == ip_network("0.0.0.0/0")]
    assert [(r.gateway, r.enabled) for r in defaults] == [(ip_address(FRONT_LAN), True)]

    net = _network(front, inner)
    upstream = net.upstream_router(up)
    assert upstream is not None and upstream.device_id == "front"
    [edge] = _address_edges(net)
    assert (edge["a"]["device_id"], edge["a"]["uplink"], edge["a"]["known"]) == (
        "inner",
        True,
        False,
    )
    # the front box's host table does not list the inner box: the link ends at the device
    assert (edge["b"]["device_id"], edge["b"]["port_id"], edge["b"]["known"]) == (
        "front",
        "front",
        False,
    )
    assert edge["kind"] == "cable" and edge["addresses"] == [INNER_WAN]
    [carried] = edge["segments"]
    assert carried["segment_id"] == upstream.segment_id and carried["consistent"]
    # only the view draws it: the checks see no link the devices did not report
    assert net.links == []


async def test_box_without_access_over_lan1_has_no_uplink(
    boxes: tuple[FritzboxSim, str, FritzboxSim, str],
) -> None:
    _, _, inner_sim, inner_url = boxes
    inner_sim.lan1_address = ""  # neither connection enabled and no address: no access set up
    assert (await _read(inner_url, "inner")).uplinks == []


def test_lan1_values() -> None:
    from datetime import UTC, datetime

    now = datetime(2026, 1, 1, tzinfo=UTC)
    off = {"NewEnable": "0", "NewConnectionStatus": "Connected", "NewExternalIPAddress": INNER_WAN}
    up = wan_uplink("gw", {"NewEnable": "0"}, off, {}, now, ip_address(FRONT_LAN))
    assert up is not None and up.upstream_gateway == ip_address(FRONT_LAN)
    assert wan_uplink("gw", None, off | {"NewExternalIPAddress": "0.0.0.0"}, {}, now) is None
    # a PPP peer stays the upstream gateway
    ppp = {"NewEnable": "1", "NewRemoteIPAddress": "203.0.113.1"}
    up = wan_uplink("gw", ppp, None, {}, now, ip_address(FRONT_LAN))
    assert up is not None and up.upstream_gateway == ip_address("203.0.113.1")
    assert default_gateway([]) is None
    assert default_gateway(
        [
            forwarding_entry("198.18.20.0", "255.255.255.0", "192.0.2.254"),
            forwarding_entry("0.0.0.0", "0.0.0.0", "192.0.2.9", enabled=False),
            forwarding_entry("0.0.0.0", "0.0.0.0", "0.0.0.0"),
            forwarding_entry("0.0.0.0", "", FRONT_LAN),
        ]
    ) == ip_address(FRONT_LAN)


# --- generic: any integration's uplink in another known router's network -------------------


FRONT_MAC, INNER_MAC = "02:00:00:00:37:01", "02:00:00:00:37:02"


def _front(**kw: Any) -> Snapshot:
    return snapshot(
        device("front", DeviceRole.GATEWAY, name="Front"),
        ports=[port("front", "lan1", mac=FRONT_MAC), port("front", "lan2")],
        segments=[
            Segment(
                id=segment_id(SITE.id, None),
                site_id=SITE.id,
                members=[
                    PortMembership(port_id=f"front/port/{p}", mode=Membership.UNTAGGED)
                    for p in ("lan1", "lan2")
                ],
            )
        ],
        subnets=[
            Subnet(
                id="front/subnet/lan",
                segment_id=segment_id(SITE.id, None),
                interface=iface("192.0.2.1/24"),
                device_id="front",
                gateway=True,
            )
        ],
        **kw,
    )


def _inner(adapter: str) -> Snapshot:
    """A gateway of another integration with its WAN port in the front router's LAN."""
    return snapshot(
        device("inner", DeviceRole.GATEWAY, name="Inner", adapter=adapter),
        ports=[port("inner", "wan", mac=INNER_MAC), port("inner", "lan")],
        uplinks=[
            uplink(
                "inner",
                port="wan",
                addresses=[iface("192.0.2.20/24")],
                upstream_gateway=ip_address(FRONT_LAN),
            )
        ],
        subnets=[
            Subnet(
                id="inner/subnet/lan",
                segment_id=segment_id(SITE.id, None),
                interface=iface("198.51.100.1/24"),
                device_id="inner",
                gateway=True,
            )
        ],
    )


@pytest.mark.parametrize("adapter", ["openwrt", "opnsense", "linux", "mikrotik"])
def test_every_integration_gets_the_link_to_the_device(adapter: str) -> None:
    net = _network(_front(), _inner(adapter))
    [found] = front_links(net)
    assert (found.uplink.device_id, found.front.device_id, found.port_id) == (
        "inner",
        "front",
        None,
    )
    [edge] = _address_edges(net)
    assert (edge["a"]["port_id"], edge["a"]["uplink"], edge["a"]["known"]) == (
        "inner/port/wan",
        True,
        True,
    )
    assert (edge["b"]["port_id"], edge["b"]["port"]) == ("front", "Front")
    assert edge["id"] == "address:inner/uplink/wan"


@pytest.mark.parametrize(
    "tables",
    [
        # the front router's host table: the inner gateway's address on port lan2
        {"clients": [client("02:00:00:00:99:01", "192.0.2.20", seen_on="front/port/lan2")]},
        # or its MAC address
        {"clients": [client(INNER_MAC, seen_on="front/port/lan2")]},
        # its forwarding database
        {
            "fdb": [
                FdbEntry(
                    id="front/fdb/1", device_id="front", port_id="front/port/lan2", mac=INNER_MAC
                )
            ]
        },
        # an LLDP neighbour on the front router's port that is the inner gateway
        {
            "neighbours": [
                Neighbour(id="front/nb/1", local_port_id="front/port/lan2", chassis_id=INNER_MAC)
            ]
        },
    ],
)
def test_the_port_the_tables_name(tables: dict[str, Any]) -> None:
    net = _network(_front(**tables), _inner("openwrt"))
    if net.links:  # a MAC table or LLDP joined the two: drawn as that link, nothing inferred
        assert _address_edges(net) == []
        return
    [found] = front_links(net)
    assert found.port_id == "front/port/lan2"
    [edge] = _address_edges(net)
    assert (edge["b"]["port_id"], edge["b"]["known"]) == ("front/port/lan2", True)
    assert edge["segments"][0]["consistent"]


def test_no_inferred_link_where_devices_report_one() -> None:
    cable = Link(id="m", a="inner/port/wan", b="front/port/lan1", origin=LinkOrigin.MANUAL)
    net = merge([SITE], [_front(), _inner("openwrt")], [cable])
    assert front_links(net) == [] and _address_edges(net) == []


def test_no_link_for_a_public_uplink_or_an_unknown_front() -> None:
    lone = snapshot(
        device("inner", DeviceRole.GATEWAY, name="Inner"),
        ports=[port("inner", "wan")],
        uplinks=[uplink("inner", port="wan")],
    )
    assert front_links(_network(_front(), lone)) == []
