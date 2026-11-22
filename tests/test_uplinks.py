"""WAN uplinks (#148): model, NAT class, merge, contract, MQTT."""

import asyncio
from datetime import datetime
from ipaddress import IPv4Address

import pytest
from pydantic import ValidationError

from factories import SITE, device, iface, ip, port, snapshot, uplink
from signalbox.adapters import Observation, check_manifest
from signalbox.merge import merge
from signalbox.model import (
    NatClass,
    Snapshot,
    Subnet,
    Uplink,
    UplinkKind,
    address_nat_class,
    json_schema,
    segment_id,
)
from signalbox.testing import assert_contract, problems, uplink_problems
from test_adapters import Fake, ctx


def test_defaults_are_unknown_and_lists_empty() -> None:
    u = Uplink(id="gw/uplink/wan", device_id="gw")
    assert (u.kind, u.up, u.since, u.port_id, u.public_ipv4) == (
        UplinkKind.OTHER,
        None,
        None,
        None,
        None,
    )
    assert u.addresses == u.dns_servers == u.delegated_prefixes == []
    assert u.nat_class() is None
    assert Snapshot(device=device("gw"), observed_at=datetime.now()).uplinks == []
    with pytest.raises(ValidationError):
        Uplink(id="gw/uplink/wan", device_id="gw", downstream_kbps=-1)


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("198.51.100.23", NatClass.PUBLIC),  # documentation prefixes stand in for public ones
        ("192.0.2.20", NatClass.PUBLIC),
        ("100.64.0.23", NatClass.CGNAT),
        ("100.127.255.254", NatClass.CGNAT),
        ("10.0.0.2", NatClass.PRIVATE),  # RFC 1918, the classifier must know it
        ("172.16.0.2", NatClass.PRIVATE),
        ("192.168.0.2", NatClass.PRIVATE),
        ("192.0.0.2", NatClass.NONE),  # DS-Lite B4 address
        ("169.254.1.1", NatClass.NONE),
    ],
)
def test_address_nat_class(address: str, expected: NatClass) -> None:
    assert address_nat_class(IPv4Address(address)) is expected


def test_uplink_nat_class() -> None:
    assert uplink("gw").nat_class() is NatClass.PUBLIC
    assert uplink("gw", addresses=[iface("100.64.0.23/10")]).nat_class() is NatClass.CGNAT
    assert uplink("gw", addresses=[iface("10.0.0.2/24")]).nat_class() is NatClass.PRIVATE
    # the best own address decides; public_ipv4 only without an own IPv4
    both = uplink("gw", addresses=[iface("10.0.0.2/24"), iface("198.51.100.23/24")])
    assert both.nat_class() is NatClass.PUBLIC
    behind = uplink("gw", addresses=[iface("10.0.0.2/24")], public_ipv4=ip("203.0.113.9"))
    assert behind.nat_class() is NatClass.PRIVATE
    only_public = uplink("gw", addresses=[], public_ipv4=ip("203.0.113.9"))
    assert only_public.nat_class() is NatClass.PUBLIC
    assert uplink("gw", kind=UplinkKind.DSLITE).nat_class() is NatClass.NONE
    assert uplink("gw", kind=UplinkKind.MAP_E).nat_class() is NatClass.NONE
    v6_only = uplink("gw", addresses=[iface("2001:db8:ffff::2/64"), iface("fe80::1/64")])
    assert v6_only.nat_class() is NatClass.NONE
    assert v6_only.ipv4() == [] and [str(a) for a in v6_only.ipv6()] == ["2001:db8:ffff::2/64"]
    assert uplink("gw", addresses=[iface("192.0.0.2/29")]).nat_class() is NatClass.NONE
    assert uplink("gw", kind=UplinkKind.BRIDGE, addresses=[]).nat_class() is None


def test_merge_keeps_uplinks_and_finds_the_router_in_front() -> None:
    front, back = device("front"), device("back")
    lan = Subnet(
        id="front/subnet/lan",
        segment_id=segment_id(SITE.id, None),
        interface=iface("192.0.2.1/24"),
        device_id="front",
        gateway=True,
    )
    behind = uplink("back", addresses=[iface("192.0.2.20/24")], port="wan")
    net = merge(
        [SITE],
        [
            snapshot(front, subnets=[lan], uplinks=[uplink("front")]),
            snapshot(back, ports=[port("back", "wan")], uplinks=[behind]),
        ],
    )
    assert [u.id for u in net.uplinks] == ["back/uplink/wan", "front/uplink/wan"]
    assert net.uplinks_of("back") == [behind]
    assert net.upstream_router(behind) == lan
    assert net.upstream_router(net.uplinks_of("front")[0]) is None
    # its own subnet does not count, nor one that is not a gateway's
    own = lan.model_copy(update={"device_id": "back"})
    plain = lan.model_copy(update={"gateway": False})
    for sub in (own, plain):
        assert net.model_copy(update={"subnets": [sub]}).upstream_router(behind) is None


def test_ui_network_carries_the_derived_values() -> None:
    from signalbox.web.app import public_network

    lan = Subnet(
        id="front/subnet/lan",
        segment_id=segment_id(SITE.id, None),
        interface=iface("192.0.2.1/24"),
        device_id="front",
        gateway=True,
    )
    behind = uplink("back", addresses=[iface("192.0.2.20/24")])
    bridge = uplink("modem", kind=UplinkKind.BRIDGE, addresses=[], upstream_gateway=None)
    net = merge(
        [SITE],
        [
            snapshot(device("front"), subnets=[lan]),
            snapshot(device("back"), uplinks=[behind]),
            snapshot(device("modem"), uplinks=[bridge]),
        ],
    )
    back, modem = public_network(net)["uplinks"]
    assert (back["nat_class"], back["upstream_device"]) == ("public", "front")
    assert (modem["nat_class"], modem["upstream_device"]) == (None, None)


def test_schema_has_uplinks() -> None:
    defs = json_schema()["$defs"]
    assert "Uplink" in defs and "NatClass" not in defs  # derived, not reported
    assert defs["UplinkKind"]["enum"] == [
        "dhcp",
        "static",
        "pppoe",
        "dslite",
        "map-e",
        "lte",
        "bridge",
        "other",
    ]


def test_contract_finds_inconsistent_uplinks() -> None:
    naive = datetime(2026, 1, 1)
    ports = {"gw/port/wan"}
    assert uplink_problems(uplink("gw", port="wan"), ports) == []
    found = "\n".join(
        uplink_problems(uplink("gw", port="eth9"), ports)
        + uplink_problems(uplink("gw", since=naive), ports)
        + uplink_problems(uplink("gw", up=False), ports)
        + uplink_problems(uplink("gw", kind=UplinkKind.BRIDGE), ports)
        + uplink_problems(uplink("gw", public_ipv4=ip("100.64.0.1")), ports)
        + uplink_problems(uplink("gw").model_copy(update={"id": "gw/wan"}), ports)
    )
    for needle in [
        "on unknown port gw/port/eth9",
        "since 2026-01-01 00:00:00 has no time zone",
        "down but connected since",
        "a bridge has no addresses or gateway",
        "public_ipv4 100.64.0.1 is not a public address",
        "uplink id gw/wan is not gw/uplink/<name>",
    ]:
        assert needle in found, needle


class WithUplink(Fake):
    """An adapter on API 1.0 that reports an uplink with ``interfaces``: no new capability."""

    async def read_interfaces(self) -> Observation:
        base = await super().read_interfaces()
        d = self.context.device_id
        return base.model_copy(update={"uplinks": [uplink(d, port="lan")]})


async def test_observe_stamps_uplinks_and_passes_the_contract() -> None:
    check_manifest(WithUplink.manifest)
    assert WithUplink.manifest.api_version == "1.0"
    snap = await assert_contract(WithUplink(ctx()))
    (u,) = snap.uplinks
    assert u.source is not None and u.source.adapter == "fake"
    assert u.observed_at == snap.observed_at


def test_contract_needs_interfaces_and_own_ids() -> None:
    adapter = WithUplink(ctx())
    good = asyncio.run(adapter.observe())
    (u,) = good.uplinks
    stranger = u.model_copy(update={"id": "other/uplink/wan", "device_id": "other"})
    text = "\n".join(problems(adapter, good.model_copy(update={"uplinks": [u, stranger]})))
    assert "uplinks id other/uplink/wan does not start with" in text
    no_caps = good.device.model_copy(update={"capabilities": ["wireless"]})
    text = "\n".join(problems(adapter, good.model_copy(update={"device": no_caps})))
    assert "uplinks reported without declaring interfaces" in text


def test_mqtt_publishes_connectivity_and_nat_but_no_addresses() -> None:
    import json

    from signalbox.config import MqttConfig
    from signalbox.mqtt import Discovery, device_state

    down = uplink("gw", "lte", kind=UplinkKind.LTE, up=False, since=None)
    cgnat = uplink("gw", addresses=[iface("100.64.0.23/10")])
    n = merge(
        [SITE],
        [
            snapshot(device("gw"), uplinks=[down, cgnat]),
            snapshot(device("off"), uplinks=[uplink("off", up=False, since=None, addresses=[])]),
            snapshot(device("sw")),
        ],
    )
    gw = device_state(n, [], "gw")
    assert (gw["internet"], gw["nat"]) == ("ON", "cgnat")
    off = device_state(n, [], "off")
    assert off["internet"] == "OFF" and "nat" not in off
    assert "internet" not in device_state(n, [], "sw")
    configs = Discovery(MqttConfig()).configs(n)
    nat = configs["homeassistant/sensor/device_gw/nat/config"]
    assert nat["options"] == ["public", "cgnat", "private", "none"]
    assert configs["homeassistant/binary_sensor/device_off/internet/config"]["device_class"] == (
        "connectivity"
    )
    assert "homeassistant/sensor/device_off/nat/config" not in configs
    assert not [t for t in configs if "device_sw/internet" in t]
    published = json.dumps(Discovery(MqttConfig()).states(n, [])) + json.dumps(configs)
    for private in ("100.64.0.23", "2001:db8", "198.51.100"):
        assert private not in published
