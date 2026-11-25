"""Follow-ups of the per-device views (#511): interfaces per VLAN, rules on sightings, declared
names as an overlay."""

from __future__ import annotations

from factories import SITE, client, device, port, snapshot
from signalbox.desired import apply_declared, drift_rules, parse
from signalbox.merge import merge
from signalbox.model import (
    ClientSighting,
    DeviceRole,
    Membership,
    Port,
    PortMembership,
    PortRole,
    Segment,
    segment_id,
)
from signalbox.rules import evaluate
from signalbox.rules._names import segment_name
from signalbox.rules.ports import client_port_mismatch
from signalbox.sightings import client_segment

MAC = "02:00:00:00:00:61"


def seg(vlan: int | None, name: str | None, *members: PortMembership) -> Segment:
    return Segment(
        id=segment_id(SITE.id, vlan),
        site_id=SITE.id,
        vlan=vlan,
        name=name,
        members=list(members),
    )


def interface_of(ports: list[Port], vlan: int | None, *members: PortMembership) -> str | None:
    n = merge(
        [SITE], [snapshot(device("gw"), ports=ports, segments=[seg(vlan, "IoT", *members)])], ()
    )
    return n.segments[0].views[0].interface


def member(name: str) -> PortMembership:
    return PortMembership(port_id=f"gw/port/{name}", mode=Membership.UNTAGGED)


def test_interface_prefers_the_vlan_interface_over_its_bridge() -> None:
    ports = [
        port("gw", "br-lan", role=PortRole.BRIDGE),
        port("gw", "br-lan.20", role=PortRole.VLAN),
    ]
    assert interface_of(ports, 20, member("br-lan"), member("br-lan.20")) == "br-lan.20"


def test_interface_is_unknown_for_several_vlan_interfaces() -> None:
    ports = [port("gw", "a.20", role=PortRole.VLAN), port("gw", "b.20", role=PortRole.VLAN)]
    assert interface_of(ports, 20, member("a.20"), member("b.20")) is None


def test_interface_from_the_vlan_name_without_membership() -> None:
    ports = [port("gw", "br0.20", role=PortRole.VLAN), port("gw", "br0.30", role=PortRole.VLAN)]
    assert interface_of(ports, 20) == "br0.20"
    assert interface_of([port("gw", "vlan20", role=PortRole.VLAN)], 20) == "vlan20"
    assert interface_of(ports, None) is None
    assert interface_of(ports, 40) is None


def test_client_segment_falls_back_to_the_sightings() -> None:
    n = merge(
        [SITE],
        [snapshot(device("gw"), clients=[client(MAC, "192.0.2.50")])],
        (),
    )
    (c,) = n.clients
    one = c.model_copy(update={"segment_id": None})
    assert client_segment(n, one) == c.sightings[0].segment_id
    two = one.model_copy(
        update={
            "sightings": [
                ClientSighting(device_id="a", segment_id=segment_id(SITE.id, 10)),
                ClientSighting(device_id="b", segment_id=segment_id(SITE.id, 20)),
            ],
        }
    )
    assert client_segment(n, two) is None


def test_mismatch_uses_the_addresses_of_the_router() -> None:
    from ipaddress import ip_interface

    from signalbox.model import Subnet

    def subnet(vlan: int | None, cidr: str) -> Subnet:
        return Subnet(
            id=f"gw/subnet/{vlan}",
            segment_id=segment_id(SITE.id, vlan),
            interface=ip_interface(cidr),
            device_id="gw",
            gateway=True,
        )

    sw_port = port("sw", "5", kind="ethernet", role=PortRole.JACK, pvid=10)
    n = merge(
        [SITE],
        [
            snapshot(
                device("gw", DeviceRole.GATEWAY),
                segments=[seg(None, "LAN"), seg(10, "IoT")],
                subnets=[subnet(None, "192.0.2.1/24"), subnet(10, "198.51.100.1/24")],
                clients=[client(MAC, "192.0.2.50", segment_id=segment_id(SITE.id, None))],
            ),
            snapshot(
                device("sw", DeviceRole.SWITCH),
                ports=[sw_port],
                segments=[
                    seg(10, "IoT", PortMembership(port_id=sw_port.id, mode=Membership.UNTAGGED))
                ],
                clients=[
                    client(
                        MAC, "198.51.100.77", segment_id=segment_id(SITE.id, 10), seen_on=sw_port.id
                    )
                ],
            ),
        ],
        (),
    )
    (c,) = n.clients
    assert len(c.addresses) == 2
    # the router's lease (192.0.2.50, the main network) decides, not the stale switch address
    findings = evaluate(n, [client_port_mismatch])
    assert len(findings) == 1 and "192.0.2.50" in findings[0].message


def test_declared_name_is_an_overlay_and_drift_still_sees_the_reported_one() -> None:
    n = merge([SITE], [snapshot(device("gw"), segments=[seg(20, "IoT")])], ())
    state = parse("sites: {home: {segments: [{vlan: 20, name: Smart Home}]}}")
    shown = apply_declared(n, state)
    (s,) = shown.segments
    assert (s.name, s.declared_name, s.shown_name) == ("IoT", "Smart Home", "Smart Home")
    assert s.views[0].name == "IoT"
    assert segment_name(shown, s.id) == "Smart Home (VLAN 20)"
    assert segment_name(n, s.id) == "IoT (VLAN 20)"
    assert apply_declared(n, parse("sites: {home: {segments: [{vlan: 30}]}}")) == n
    assert [f for f in evaluate(shown, drift_rules(state)) if "name" in f.message]
