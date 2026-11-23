"""Internal ports (CPU port, bridge; #252) are never treated as the end of a cable.

Every case runs twice: with the port reported as a jack the finding is there, as an internal
port it is gone. Old data without roles keeps the jack behaviour.
"""

from __future__ import annotations

from typing import Any

import pytest

from factories import SITE, client, device, iface, port, snapshot
from signalbox.merge import merge
from signalbox.model import (
    DeviceRole,
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
    port_id,
    segment_id,
)
from signalbox.rules import Finding, evaluate
from signalbox.rules.builtin import RULES
from signalbox.rules.topology_checks import HIDDEN_THRESHOLD

T, U = Membership.TAGGED, Membership.UNTAGGED
LAN, IOT, GUEST = (segment_id(SITE.id, v) for v in (None, 20, 30))
LINK = Link(id="link/gw-sw", a=port_id("gw", "1"), b=port_id("sw", "1"), origin=LinkOrigin.LLDP)
ROLES = [None, PortRole.JACK, PortRole.CPU]


def seg(vlan: int | None, members: dict[str, Membership]) -> Segment:
    return Segment(
        id=segment_id(SITE.id, vlan),
        site_id=SITE.id,
        vlan=vlan,
        members=[PortMembership(port_id=p, mode=m) for p, m in members.items()],
    )


def subnet(vlan: int | None, cidr: str) -> Subnet:
    sid = segment_id(SITE.id, vlan)
    return Subnet(id=f"gw/subnet/{vlan}", segment_id=sid, interface=iface(cidr), device_id="gw")


def gateway(**port_kw: Any) -> Snapshot:
    gw1 = port_id("gw", "1")
    return snapshot(
        device("gw"),
        ports=[port("gw", "1", **port_kw)],
        segments=[seg(None, {gw1: U}), seg(20, {gw1: T}), seg(30, {gw1: T})],
        subnets=[
            subnet(None, "192.0.2.1/24"),
            subnet(20, "198.51.100.1/24"),
            subnet(30, "203.0.113.1/24"),
        ],
    )


def ids(found: list[Finding], rule: str) -> list[Finding]:
    return [f for f in found if f.rule_id == rule]


def check(role: PortRole | None, rule: str, snaps: list[Snapshot], links: list[Link]) -> bool:
    found = evaluate(merge([SITE], snaps, links), RULES)
    return bool(ids(found, rule))


@pytest.mark.parametrize("role", ROLES)
def test_cpu_port_at_a_link_end(role: PortRole | None) -> None:
    """LLDP seen on a CPU port: it carries every VLAN tagged and runs at its own speed, which
    says nothing about a cable."""
    sw1 = port_id("sw", "1")
    sw = snapshot(
        device("sw", DeviceRole.SWITCH),
        ports=[port("sw", "1", role=role, up=True, speed_mbps=2500, mtu=9000)],
        segments=[seg(None, {sw1: T}), seg(20, {sw1: T})],
    )
    gw = gateway(up=True, speed_mbps=1000, mtu=1500)
    snaps, links = [gw, sw], [LINK]
    expected = role is not PortRole.CPU
    for rule in ("vlan.native-mismatch", "link.speed-duplex", "link.mtu", "vlan.tagged-both-ends"):
        assert check(role, rule, snaps, links) is expected, rule


@pytest.mark.parametrize("role", ROLES)
def test_cpu_port_with_several_untagged_vlans(role: PortRole | None) -> None:
    p = port_id("sw", "9")
    sw = snapshot(
        device("sw", DeviceRole.SWITCH),
        ports=[port("sw", "9", role=role, up=True, speed_mbps=10, full_duplex=False)],
        segments=[seg(None, {p: U}), seg(20, {p: U})],
    )
    expected = role is not PortRole.CPU
    assert check(role, "vlan.single-untagged", [gateway(), sw], []) is expected
    assert check(role, "link.slow", [gateway(), sw], []) is expected


@pytest.mark.parametrize("role", ROLES)
def test_clients_behind_a_cpu_port(role: PortRole | None) -> None:
    """A CPU port sees every client of the switch: no hidden switch, no VLAN mismatch."""
    p = port_id("sw", "9")
    many = [
        client(f"02:00:00:00:01:{i:02x}", f"192.0.2.{50 + i}", seen_on=p)
        for i in range(HIDDEN_THRESHOLD + 1)
    ]
    sw = snapshot(
        device("sw", DeviceRole.SWITCH),
        ports=[port("sw", "9", role=role)],
        segments=[seg(None, {}), seg(20, {p: U})],
        clients=many,
    )
    expected = role is not PortRole.CPU
    assert check(role, "topology.hidden-device", [gateway(), sw], []) is expected
    one = sw.model_copy(update={"clients": many[:1]})
    assert check(role, "vlan.client-port-mismatch", [gateway(), one], []) is expected


@pytest.mark.parametrize("role", [None, PortRole.BRIDGE])
def test_bridge_membership_is_no_access_port(role: PortRole | None) -> None:
    """An access point's bridge in the guest VLAN is not an access port that needs the VLAN on
    its uplink (the bridge itself is no place a client plugs in)."""
    ap1, br = port_id("ap", "eth0"), port_id("ap", "br-lan")
    ap = snapshot(
        device("ap", DeviceRole.AP),
        ports=[port("ap", "eth0"), port("ap", "br-lan", kind=PortKind.BRIDGE, role=role)],
        segments=[seg(None, {ap1: U}), seg(20, {ap1: T}), seg(30, {br: U})],
    )
    link = Link(id="link/gw-ap", a=port_id("gw", "1"), b=ap1, origin=LinkOrigin.LLDP)
    gw = gateway()
    gw = gw.model_copy(
        update={"segments": [s for s in gw.segments if s.vlan != 30] + [seg(30, {})]}
    )
    assert check(role, "vlan.path-to-gateway", [gw, ap], [link]) is (role is None)


def test_old_network_without_roles_is_unchanged() -> None:
    n = Network(ports=[port("sw", "1")])
    assert n.external_ports("sw") == n.ports
