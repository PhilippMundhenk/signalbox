"""Routing tables and policy routing (#149, ADR 0024): model, next_hop, reachability, rules and
the pure parts of the readers."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from factories import (
    SITE,
    device,
    firewall,
    iface,
    ip,
    peer,
    policy,
    site_link,
    uplink,
    zone,
)
from factories import net as cidr
from signalbox.adapters import Observation
from signalbox.adapters.fritzbox import routes as fritz
from signalbox.adapters.linux import routes as linux
from signalbox.adapters.linux.collect import Answer
from signalbox.adapters.mikrotik import routes as mikrotik
from signalbox.adapters.openwrt import routes as openwrt
from signalbox.adapters.opnsense import routes as opnsense
from signalbox.firewall import reach
from signalbox.merge import merge
from signalbox.model import (
    DeviceRole,
    DeviceStatus,
    FirewallAction,
    NatRule,
    Network,
    Route,
    RouteKind,
    RouteOrigin,
    RoutingRule,
    RuleAction,
    Segment,
    Subnet,
    UplinkKind,
    Verdict,
    port_id,
    route_id,
    routing_rule_id,
    segment_id,
)
from signalbox.routing import HopKind, connected_networks, has_routes, next_hop, path
from signalbox.rules import Finding, evaluate
from signalbox.rules.routing_checks import (
    asymmetric,
    default_missing,
    multiple_default,
    no_return,
    unreachable_gateway,
    vpn_return,
)
from test_adapters import Fake, ctx

LAN = segment_id(SITE.id, None)
GUEST = segment_id(SITE.id, 30)
LAB = segment_id(SITE.id, 20)


def sub(dev: str, seg: str, text: str) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{text}",
        segment_id=seg,
        interface=iface(text),
        device_id=dev,
        gateway=True,
    )


def rt(dev: str, dest: str, gw: str | None = None, **kw: Any) -> Route:
    destination = cidr(dest)
    gateway = ip(gw) if gw else None
    kind = kw.get("kind", RouteKind.UNICAST)
    return Route(
        id=route_id(dev, kw.get("table", "main"), destination, gateway, kw.get("interface"), kind),
        device_id=dev,
        destination=destination,
        gateway=gateway,
        origin=kw.pop("origin", RouteOrigin.STATIC),
        **kw,
    )


def rule_of(dev: str, text: str, **kw: Any) -> RoutingRule:
    return RoutingRule(id=routing_rule_id(dev, text), device_id=dev, **kw)


def lab(**kw: Any) -> Network:
    """A router ``gw`` (LAN 192.0.2.1/24, guest 203.0.113.1/24, uplink 198.51.100.23/24) and a
    second router ``r2`` (LAN 192.0.2.254/24, lab 198.18.20.1/24). ``gw`` sends the lab network
    to ``r2``; ``r2`` sends everything to ``gw``."""
    values: dict[str, Any] = {
        "sites": [SITE],
        "devices": [device("gw"), device("r2")],
        "segments": [
            Segment(id=LAN, site_id=SITE.id),
            Segment(id=GUEST, site_id=SITE.id, vlan=30),
            Segment(id=LAB, site_id=SITE.id, vlan=20),
        ],
        "subnets": [
            sub("gw", LAN, "192.0.2.1/24"),
            sub("gw", GUEST, "203.0.113.1/24"),
            sub("r2", LAN, "192.0.2.254/24"),
            sub("r2", LAB, "198.18.20.1/24"),
        ],
        "uplinks": [uplink("gw")],
        "routes": [
            rt("gw", "0.0.0.0/0", "198.51.100.1", origin=RouteOrigin.DHCP, metric=10),
            rt("gw", "198.18.20.0/24", "192.0.2.254"),
            rt("r2", "0.0.0.0/0", "192.0.2.1"),
        ],
    }
    return Network(**(values | kw))


def with_routes(n: Network, dev: str, *routes: Route) -> Network:
    """*n* with the routes of *dev* replaced."""
    keep = [r for r in n.routes if r.device_id != dev]
    return n.model_copy(update={"routes": [*keep, *routes]})


def plus(n: Network, *routes: Route) -> Network:
    return n.model_copy(update={"routes": [*n.routes, *routes]})


# --- model -------------------------------------------------------------------------------------


def test_route_ids_ignore_the_metric_and_tell_routes_apart() -> None:
    a = route_id("gw", "main", cidr("192.0.2.0/24"), ip("192.0.2.9"))
    assert a == route_id("gw", "main", cidr("192.0.2.0/24"), ip("192.0.2.9"))
    assert a.startswith("gw/route/")
    assert a != route_id("gw", "100", cidr("192.0.2.0/24"), ip("192.0.2.9"))
    assert a != route_id("gw", "main", cidr("192.0.2.0/24"), None, "gw/port/lan")
    assert a != route_id("gw", "main", cidr("192.0.2.0/24"), None, kind=RouteKind.BLACKHOLE)
    assert rt("gw", "0.0.0.0/0", "192.0.2.1").default
    assert not rt("gw", "192.0.2.0/24").default


def test_a_gateway_must_be_of_the_family_of_the_destination() -> None:
    with pytest.raises(ValidationError, match="same address family"):
        Route(
            id="x/route/1", device_id="x", destination=cidr("192.0.2.0/24"), gateway=ip("fe80::1")
        )
    rule = rule_of("gw", "a", priority=100, src=cidr("192.0.2.0/24"), table="100")
    assert rule.action is RuleAction.LOOKUP and rule.dst is None
    assert Network(routes=[rt("gw", "0.0.0.0/0", "192.0.2.1")]).knows(
        route_id("gw", "main", cidr("0.0.0.0/0"), ip("192.0.2.1"))
    )


def test_network_lists_routes_and_rules_of_a_device_in_order() -> None:
    n = lab(
        routing_rules=[
            rule_of("gw", "b", priority=200, table="main"),
            rule_of("gw", "a", priority=100, table="100"),
            rule_of("gw", "c", table="main"),
        ]
    )
    assert [r.priority for r in n.routing_rules_of("gw")] == [100, 200, None]
    assert len(n.routes_of("gw")) == 2 and has_routes(n, "r2") and not has_routes(n, "nobody")


def test_connected_networks_come_from_subnets_uplinks_and_tunnels() -> None:
    one, _ = site_link("gw", "r2")
    n = lab(tunnels=[one])
    nets = {str(x) for x, _ in connected_networks(n, "gw")}
    assert {"192.0.2.0/24", "203.0.113.0/24", "198.51.100.0/24", "2001:db8:ff::/64"} <= nets
    assert not any(x.is_link_local for x, _ in connected_networks(n, "gw"))


# --- next_hop ----------------------------------------------------------------------------------


def test_next_hop_connected_gateway_and_default() -> None:
    n = lab()
    here = next_hop(n, "gw", "192.0.2.77")
    assert here.kind is HopKind.CONNECTED and here.segment_id == LAN
    lab_hop = next_hop(n, "gw", ip("198.18.20.5"))
    assert (lab_hop.kind, lab_hop.gateway, lab_hop.device_id) == (
        HopKind.GATEWAY,
        ip("192.0.2.254"),
        "r2",
    )
    out = next_hop(n, "gw", "203.0.113.200")
    assert out.kind is HopKind.CONNECTED  # the guest network, not the default route
    internet = next_hop(n, "gw", "[2001:db8::1]")
    assert internet.kind is HopKind.NO_ROUTE  # IPv6 has no default here
    far = next_hop(n, "gw", "192.0.9.9")
    assert far.kind is HopKind.GATEWAY and far.device_id is None and far.route is not None
    up = next_hop(n, "gw", "198.51.100.50")
    assert up.kind is HopKind.CONNECTED and up.segment_id == n.uplinks[0].id


def test_next_hop_unknown_without_routes_but_connected_still_answers() -> None:
    n = lab()
    assert next_hop(n, "sw", "192.0.2.5").kind is HopKind.UNKNOWN
    bare = Network(sites=[SITE], devices=[device("gw")], subnets=[sub("gw", LAN, "192.0.2.1/24")])
    assert next_hop(bare, "gw", "192.0.2.9").kind is HopKind.CONNECTED
    assert next_hop(bare, "gw", "198.18.20.9").kind is HopKind.UNKNOWN


def test_next_hop_prefers_the_longest_prefix_then_the_lower_metric() -> None:
    n = with_routes(
        lab(),
        "gw",
        rt("gw", "0.0.0.0/0", "198.51.100.1", metric=20),
        rt("gw", "0.0.0.0/0", "198.51.100.2", metric=10),
        rt("gw", "198.18.0.0/16", "192.0.2.253"),
        rt("gw", "198.18.20.0/25", "192.0.2.254"),
    )
    assert next_hop(n, "gw", "198.18.20.5").gateway == ip("192.0.2.254")
    assert next_hop(n, "gw", "198.18.99.5").gateway == ip("192.0.2.253")
    assert next_hop(n, "gw", "192.0.9.9").gateway == ip("198.51.100.2")


def test_next_hop_ignores_disabled_and_not_installed_routes_and_follows_drops() -> None:
    n = with_routes(
        lab(),
        "gw",
        rt("gw", "198.18.20.0/24", "192.0.2.254", enabled=False),
        rt("gw", "198.18.21.0/24", "192.0.2.254", active=False),
        rt("gw", "198.18.22.0/24", kind=RouteKind.BLACKHOLE),
        rt("gw", "198.18.23.0/24", interface="gw/port/wg0"),
        rt("gw", "2001:db8:50::/64", "2001:db8:1::fe"),
    )
    assert next_hop(n, "gw", "198.18.20.5").kind is HopKind.NO_ROUTE  # no default route either
    assert next_hop(n, "gw", "198.18.21.5").kind is HopKind.NO_ROUTE
    dropped = next_hop(n, "gw", "198.18.22.5")
    assert dropped.kind is HopKind.DROPPED and dropped.route is not None
    out = next_hop(n, "gw", "198.18.23.5")
    assert (out.kind, out.segment_id) == (HopKind.INTERFACE, "gw/port/wg0")
    assert next_hop(n, "gw", "2001:db8:50::7").gateway == ip("2001:db8:1::fe")


def test_next_hop_follows_policy_rules_on_the_destination_only() -> None:
    n = with_routes(
        lab(),
        "gw",
        rt("gw", "0.0.0.0/0", "198.51.100.1"),
        rt("gw", "0.0.0.0/0", "192.0.2.253", table="100"),
        rt("gw", "198.18.99.0/24", kind=RouteKind.BLACKHOLE, table="200"),
    )
    n = n.model_copy(
        update={
            "routing_rules": [
                rule_of("gw", "to-lab", priority=100, dst=cidr("192.0.9.0/24"), table="100"),
                rule_of("gw", "main", priority=32766, table="main"),
            ]
        }
    )
    assert next_hop(n, "gw", "192.0.9.9").gateway == ip("192.0.2.253")  # table 100 first
    assert next_hop(n, "gw", "192.0.10.9").gateway == ip("198.51.100.1")  # main
    assert not next_hop(n, "gw", "192.0.9.9").uncertain
    dropped = n.model_copy(
        update={
            "routing_rules": [
                rule_of(
                    "gw", "no", priority=5, dst=cidr("192.0.9.0/24"), action=RuleAction.PROHIBIT
                )
            ]
        }
    )
    assert next_hop(dropped, "gw", "192.0.9.9").kind is HopKind.DROPPED
    assert next_hop(dropped, "gw", "192.0.8.9").kind is HopKind.GATEWAY


def test_next_hop_marks_source_based_rules_uncertain_and_skips_disabled_ones() -> None:
    n = lab(
        routing_rules=[
            rule_of("gw", "iot", priority=100, src=cidr("203.0.113.0/24"), table="100"),
            rule_of("gw", "seg", priority=101, segment_id=GUEST, action=RuleAction.BLACKHOLE),
            rule_of("gw", "off", priority=102, table="300", enabled=False),
            rule_of("gw", "main", priority=32766, table="main"),
        ]
    )
    hop = next_hop(n, "gw", "198.18.20.5")
    assert hop.kind is HopKind.GATEWAY and hop.uncertain
    plain = lab(routing_rules=[rule_of("gw", "main", priority=32766, table="main")])
    assert not next_hop(plain, "gw", "198.18.20.5").uncertain
    no_main = lab(routing_rules=[rule_of("gw", "t", priority=100, table="100")])
    assert next_hop(no_main, "gw", "198.18.20.5").kind is HopKind.GATEWAY  # main is appended


def test_path_follows_the_gateways_it_knows_and_stops_at_loops() -> None:
    n = plus(
        lab(), rt("r2", "198.18.77.0/24", "192.0.2.1"), rt("gw", "198.18.77.0/24", "192.0.2.254")
    )
    assert path(n, "gw", "198.18.20.5") == ["gw", "r2"]
    assert path(n, "gw", "198.18.77.5") == ["gw", "r2", "gw"]
    assert path(n, "gw", "192.0.2.5") == ["gw"]


# --- reachability ------------------------------------------------------------------------------


def chain_net(r2_policy: str = "accept", **kw: Any) -> Network:
    """Guest clients reach the lab through ``gw`` and ``r2``: no router sits in both."""
    n = lab(
        firewalls=[
            firewall(
                "gw",
                zone("guest", GUEST),
                zone("lan", LAN),
                policies=[policy("guest", "lan", "accept")],
                forward_policy=FirewallAction.REJECT,
            ),
            firewall(
                "r2",
                zone("lan", LAN),
                zone("lab", LAB),
                policies=[policy("lan", "lab", r2_policy)],
                forward_policy=FirewallAction.REJECT,
            ),
        ],
        **kw,
    )
    return with_routes(
        n, "gw", rt("gw", "198.18.20.0/24", "192.0.2.254"), rt("gw", "0.0.0.0/0", "198.51.100.1")
    )


def test_reach_follows_a_chain_of_two_routers() -> None:
    assert reach(chain_net(), GUEST, "198.18.20.5").verdict is Verdict.ALLOWED
    assert reach(chain_net("reject"), GUEST, "198.18.20.5").verdict is Verdict.DENIED


def test_reach_stays_unknown_without_a_route_chain() -> None:
    n = chain_net()
    n = with_routes(n, "gw", rt("gw", "0.0.0.0/0", "198.51.100.1"))
    verdict = reach(n, GUEST, "198.18.20.5")
    assert verdict.verdict is Verdict.UNKNOWN and "no single known router" in verdict.reason
    # the next hop is no known router
    n = with_routes(n, "gw", rt("gw", "198.18.20.0/24", "192.0.2.99"))
    assert reach(n, GUEST, "198.18.20.5").verdict is Verdict.UNKNOWN
    # the next hop is the router itself, or sits in no known network
    n = with_routes(n, "gw", rt("gw", "198.18.20.0/24", "192.0.2.1"))
    assert reach(n, GUEST, "198.18.20.5").verdict is Verdict.UNKNOWN
    n = with_routes(n, "gw", rt("gw", "198.18.20.0/24", "100.64.9.9"))
    assert reach(n, GUEST, "198.18.20.5").verdict is Verdict.UNKNOWN


def test_reach_denies_what_a_router_drops_and_skips_routers_that_send_it_elsewhere() -> None:
    n = chain_net()
    n = with_routes(n, "r2", rt("r2", "198.18.20.0/25", kind=RouteKind.BLACKHOLE))
    verdict = reach(n, LAN, "198.18.20.5")
    assert verdict.verdict is Verdict.DENIED and "blackhole" in verdict.reason
    # r2 is the only router in LAN and the lab; a route that sends it elsewhere is not the path
    n = with_routes(chain_net(), "r2", rt("r2", "198.18.20.0/25", "192.0.2.1"))
    assert reach(n, LAN, "198.18.20.5").verdict is Verdict.ALLOWED  # kept: nothing else to ask


# --- rules -------------------------------------------------------------------------------------


def run(rule: Any, n: Network) -> list[Finding]:
    return [f for f in evaluate(n, [rule]) if f.rule_id == rule.id]


def test_default_missing() -> None:
    n = lab()
    assert run(default_missing, n) == []
    bare = with_routes(n, "gw", rt("gw", "198.18.20.0/24", "192.0.2.254"))
    (f,) = run(default_missing, bare)
    assert f.objects == ["gw"] and f.message_id == "route.defaultMissing"
    assert f.params == {"device": "gw"}
    # not read, not a gateway, not read completely, connection down, IPv6 default only
    assert run(default_missing, with_routes(n, "gw")) == []
    switch = bare.model_copy(update={"devices": [device("gw", DeviceRole.SWITCH), device("r2")]})
    assert run(default_missing, switch) == []
    partial = bare.model_copy(update={"statuses": {"gw": DeviceStatus.PARTIAL}})
    assert run(default_missing, partial) == []
    down = bare.model_copy(update={"uplinks": [uplink("gw", up=False)]})
    assert run(default_missing, down) == []
    v6 = with_routes(n, "gw", rt("gw", "::/0", "fe80::1"))
    assert len(run(default_missing, v6)) == 1
    off = with_routes(n, "gw", rt("gw", "0.0.0.0/0", "198.51.100.1", enabled=False))
    assert len(run(default_missing, off)) == 1
    other_table = with_routes(n, "gw", rt("gw", "0.0.0.0/0", "198.51.100.1", table="100"))
    assert len(run(default_missing, other_table)) == 1


def test_multiple_default() -> None:
    twin = with_routes(
        lab(),
        "gw",
        rt("gw", "0.0.0.0/0", "198.51.100.1", metric=10),
        rt("gw", "0.0.0.0/0", "192.0.2.253", metric=10),
        rt("gw", "::/0", "fe80::1", metric=10),
    )
    (f,) = run(multiple_default, twin)
    assert f.params == {"device": "gw", "count": 2, "metric": 10}
    assert f.severity.value == "info" and f.message_id == "route.multipleDefault"
    different = with_routes(
        lab(),
        "gw",
        rt("gw", "0.0.0.0/0", "198.51.100.1", metric=10),
        rt("gw", "0.0.0.0/0", "192.0.2.253", metric=20),
    )
    assert run(multiple_default, different) == []
    unknown = with_routes(
        lab(), "gw", rt("gw", "0.0.0.0/0", "198.51.100.1"), rt("gw", "0.0.0.0/0", "192.0.2.253")
    )
    assert run(multiple_default, unknown) == []
    same_way = with_routes(
        lab(),
        "gw",
        rt("gw", "0.0.0.0/0", "198.51.100.1", metric=10),
        rt("gw", "0.0.0.0/0", "198.51.100.1", metric=10, table="main", active=True),
    )
    assert run(multiple_default, same_way) == []
    inactive = with_routes(
        lab(),
        "gw",
        rt("gw", "0.0.0.0/0", "198.51.100.1", metric=10),
        rt("gw", "0.0.0.0/0", "192.0.2.253", metric=10, active=False),
    )
    assert run(multiple_default, inactive) == []


def test_unreachable_gateway() -> None:
    assert run(unreachable_gateway, lab()) == []
    bad = with_routes(lab(), "gw", rt("gw", "198.18.20.0/24", "203.0.114.9"))
    (f,) = run(unreachable_gateway, bad)
    assert f.params == {"device": "gw", "network": "198.18.20.0/24", "gateway": "203.0.114.9"}
    assert f.message_id == "route.unreachableGateway"
    link_local = with_routes(lab(), "gw", rt("gw", "2001:db8:50::/64", "fe80::1"))
    assert run(unreachable_gateway, link_local) == []
    learned = with_routes(
        lab(), "gw", rt("gw", "198.18.20.0/24", "203.0.114.9", origin=RouteOrigin.DHCP)
    )
    assert run(unreachable_gateway, learned) == []
    off = with_routes(lab(), "gw", rt("gw", "198.18.20.0/24", "203.0.114.9", enabled=False))
    assert run(unreachable_gateway, off) == []
    blind = Network(
        sites=[SITE], devices=[device("gw")], routes=[rt("gw", "198.18.20.0/24", "203.0.114.9")]
    )
    assert run(unreachable_gateway, blind) == []
    via_interface = with_routes(lab(), "gw", rt("gw", "198.18.20.0/24", interface="gw/port/x"))
    assert run(unreachable_gateway, via_interface) == []


def test_no_return_and_asymmetric() -> None:
    assert run(no_return, lab()) == [] and run(asymmetric, lab()) == []
    # r2 has routes, but none back to the guest network
    none = with_routes(lab(), "r2", rt("r2", "198.51.100.0/24", "192.0.2.1"))
    (f,) = run(no_return, none)
    assert f.params == {
        "a": "gw",
        "b": "r2",
        "network": "203.0.113.0/24",
        "destination": "198.18.20.0/24",
    }
    assert f.message_id == "route.noReturn" and f.objects[:2] == ["gw", "r2"]
    # only a default route towards a device Signalbox does not know
    away = with_routes(lab(), "r2", rt("r2", "0.0.0.0/0", "192.0.2.77"))
    assert len(run(no_return, away)) == 1
    # a blackhole for the network
    black = with_routes(
        lab(),
        "r2",
        rt("r2", "0.0.0.0/0", "192.0.2.1"),
        rt("r2", "203.0.113.0/24", kind=RouteKind.BLACKHOLE),
    )
    assert len(run(no_return, black)) == 1
    # r2 not read, or a source-based rule makes the answer uncertain
    unread = with_routes(lab(), "r2")
    assert run(no_return, unread) == []
    uncertain = none.model_copy(
        update={
            "routing_rules": [rule_of("r2", "x", priority=1, src=cidr("192.0.2.0/24"), table="9")]
        }
    )
    assert run(no_return, uncertain) == []
    # the answers go to r2 itself when it masquerades towards the lab
    nat = none.model_copy(
        update={
            "firewalls": [
                firewall("r2", zone("lan", LAN), zone("lab", LAB, masquerade=True)),
            ]
        }
    )
    assert run(no_return, nat) == []
    rule_nat = none.model_copy(
        update={
            "firewalls": [
                firewall(
                    "r2",
                    zone("lan", LAN),
                    zone("lab", LAB),
                    nat=[NatRule(zones=["lab"]), NatRule(zones=["lan"], enabled=False)],
                ),
            ]
        }
    )
    assert run(no_return, rule_nat) == []
    # answers through a third router instead of gw
    third = lab(devices=[device("gw"), device("r2"), device("r3")]).model_copy(
        update={"subnets": [*lab().subnets, sub("r3", LAN, "192.0.2.3/24")]}
    )
    third = with_routes(third, "r2", rt("r2", "0.0.0.0/0", "192.0.2.3"))
    third = with_routes(third, "r3", rt("r3", "0.0.0.0/0", "192.0.2.1"))
    (g,) = run(asymmetric, third)
    assert g.params["c"] == "r3" and g.severity.value == "info"
    assert run(no_return, third) == []
    # a default route, a link-local next hop and a network behind the destination are skipped
    skipped = with_routes(
        lab(), "gw", rt("gw", "0.0.0.0/0", "192.0.2.254"), rt("gw", "2001:db8:9::/64", "fe80::1")
    )
    assert run(no_return, skipped) == []
    overlap = with_routes(lab(), "gw", rt("gw", "203.0.0.0/16", "192.0.2.254"))
    assert run(no_return, overlap) == []


def vpn_net(**kw: Any) -> Network:
    one, two = site_link("fw", "pi")
    away = SITE.model_copy(update={"id": "away", "name": "Away"})
    values: dict[str, Any] = {
        "sites": [SITE, away],
        "devices": [device("fw"), device("pi", site_id="away")],
        "subnets": [
            sub("fw", LAN, "192.0.2.1/24"),
            sub("pi", segment_id("away", None), "198.51.100.1/24"),
        ],
        "tunnels": [one, two],
    }
    return Network(**(values | kw))


def test_vpn_return() -> None:
    assert run(vpn_return, vpn_net()) == []
    one, two = site_link("fw", "pi")
    host_only = two.model_copy(
        update={"peers": [peer("fw", "2001:db8:ff::1/128", keepalive_seconds=25)]}
    )
    (f,) = run(vpn_return, vpn_net(tunnels=[one, host_only]))
    assert f.message_id == "route.vpnReturn" and f.params == {"a": "fw/wg0", "b": "pi/wg0"}
    # the other end is not read, does not list us, is disabled or the site is unknown
    assert run(vpn_return, vpn_net(tunnels=[one])) == []
    stranger = two.model_copy(update={"peers": [peer("somebody", "192.0.2.0/24")]})
    assert run(vpn_return, vpn_net(tunnels=[one, stranger])) == []
    assert run(vpn_return, vpn_net(tunnels=[one.model_copy(update={"up": False}), host_only])) == []
    assert run(vpn_return, vpn_net(tunnels=[one, host_only], subnets=[])) == []
    off = host_only.model_copy(
        update={"peers": [p.model_copy(update={"enabled": False}) for p in host_only.peers]}
    )
    assert run(vpn_return, vpn_net(tunnels=[one, off])) == []


# --- readers -----------------------------------------------------------------------------------


def uci(*sections: tuple[str, str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "values": {
            name: {".type": kind, ".name": name, ".index": i, **opts}
            for i, (kind, name, opts) in enumerate(sections)
        }
    }


def test_openwrt_routes_and_rules() -> None:
    config = uci(
        (
            "route",
            "lab",
            {
                "interface": "lan",
                "target": "198.18.20.0",
                "netmask": "255.255.255.0",
                "gateway": "192.0.2.254",
            },
        ),
        (
            "route",
            "off",
            {
                "interface": "lan",
                "target": "198.18.30.0/24",
                "gateway": "192.0.2.254",
                "disabled": "1",
            },
        ),
        (
            "route",
            "t100",
            {"interface": "lan", "target": "default", "gateway": "192.0.2.254", "table": "100"},
        ),
        ("route", "hole", {"target": "198.18.66.0/24", "type": "blackhole"}),
        ("route", "bad", {"target": "nonsense"}),
        ("route", "mix", {"target": "198.18.40.0/24", "gateway": "fe80::1"}),
        (
            "route6",
            "six",
            {"interface": "lan", "target": "2001:db8:50::/64", "gateway": "2001:db8::fe"},
        ),
        ("rule", "r1", {"src": "192.0.2.128/25", "lookup": "100", "priority": "100", "in": "lan"}),
        ("rule", "r2", {"dest": "198.18.0.0/16", "action": "blackhole"}),
        ("rule", "r3", {"src": "192.0.2.0/24", "lookup": "100", "invert": "1"}),
        ("rule", "r4", {"goto": "5"}),
        ("rule", "r5", {"src": "nonsense", "lookup": "100"}),
        ("rule", "r6", {"lookup": "100", "in": "elsewhere"}),
        ("rule", "r7", {"lookup": "main", "disabled": "1", "priority": "32766"}),
        ("rule6", "r8", {"src": "2001:db8::/32", "lookup": "100"}),
    )
    running = {
        "lan": {
            "proto": "static",
            "route": [
                {"target": "198.18.20.0", "mask": 24, "nexthop": "192.0.2.254"},
                {"target": "0.0.0.0", "mask": 0, "nexthop": "192.0.2.253", "metric": 5},
                {"target": "bad"},
                "junk",
            ],
        },
        "wan": {
            "proto": "dhcp",
            "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": "203.0.113.1"}],
        },
        "wan6": {"proto": "dhcpv6", "route": [{"target": "::", "mask": 0, "nexthop": "fe80::1"}]},
        "wg0": {
            "proto": "wireguard",
            "route": [{"target": "198.18.50.0", "mask": 24, "nexthop": "0.0.0.0"}],
        },
    }
    devices = {"lan": "br-lan", "wan": "eth0", "wan6": "eth0", "wg0": "wg0"}
    routes = {r.id: r for r in openwrt.read_routes("gw", config, running, devices)}
    by = {
        (str(r.destination), r.table, str(r.gateway), r.origin.value, r.active, r.enabled): r
        for r in routes.values()
    }
    assert ("198.18.20.0/24", "main", "192.0.2.254", "static", True, True) in by
    assert ("0.0.0.0/0", "main", "203.0.113.1", "dhcp", True, True) in by
    assert ("::/0", "main", "fe80::1", "ra", True, True) in by
    assert ("198.18.50.0/24", "main", "None", "vpn", True, True) in by
    assert ("198.18.30.0/24", "main", "192.0.2.254", "static", None, False) in by
    assert ("0.0.0.0/0", "100", "192.0.2.254", "static", None, True) in by
    assert any(r.kind is RouteKind.BLACKHOLE for r in routes.values())
    assert not any(
        str(r.gateway) == "fe80::1" and r.destination.version == 4 for r in routes.values()
    )
    configured_only = [
        r
        for r in openwrt.read_routes("gw", config, running, devices)
        if str(r.destination) == "2001:db8:50::/64"
    ]
    assert [r.active for r in configured_only] == [False]
    assert openwrt.read_routes("gw", uci(), {}, {}) == []
    assert openwrt.read_routes("gw", {"values": None}, {}, {}) == []
    rules = openwrt.read_rules("gw", config, lambda n: LAN if n == "lan" else None)
    assert sorted(r.priority or 0 for r in rules) == [0, 0, 100, 32766]
    first = next(r for r in rules if r.priority == 100)
    assert (str(first.src), first.segment_id, first.table) == ("192.0.2.128/25", LAN, "100")
    assert any(r.action is RuleAction.BLACKHOLE and str(r.dst) == "198.18.0.0/16" for r in rules)
    assert any(not r.enabled for r in rules)


def test_mikrotik_routes_and_rules() -> None:
    rows = [
        {
            "dst-address": "0.0.0.0/0",
            "gateway": "203.0.113.1",
            "distance": "1",
            "dhcp": "true",
            "active": "true",
        },
        {
            "dst-address": "198.18.20.0/24",
            "gateway": "192.0.2.254",
            "static": "true",
            "active": "false",
            "disabled": "true",
            "distance": "2",
        },
        {"dst-address": "198.18.66.0/24", "blackhole": "true", "static": "true"},
        {"dst-address": "198.18.67.0/24", "unreachable": "true"},
        {"dst-address": "198.18.68.0/24", "prohibit": "true"},
        {"dst-address": "192.0.2.0/24", "gateway": "bridge", "connect": "true"},
        {"dst-address": "198.18.50.0/24", "gateway": "wg0", "vpn": "true", "routing-table": "vpn"},
        {"dst-address": "198.18.51.0/24", "gateway": "fe80::1%ether1", "ospf": "true"},
        {"dst-address": "2001:db8:50::/64", "gateway": "198.51.100.1", "bgp": "true"},
        {"dst-address": "nonsense"},
        {"dst-address": "198.18.52.0/24", "gateway": ""},
    ]
    routes = mikrotik.read_routes("gw", rows)
    kinds = {str(r.destination): r for r in routes}
    assert kinds["0.0.0.0/0"].origin is RouteOrigin.DHCP and kinds["0.0.0.0/0"].active is True
    assert kinds["198.18.20.0/24"].enabled is False and kinds["198.18.20.0/24"].metric == 2
    assert kinds["198.18.66.0/24"].kind is RouteKind.BLACKHOLE
    assert kinds["198.18.67.0/24"].kind is RouteKind.UNREACHABLE
    assert kinds["198.18.68.0/24"].kind is RouteKind.PROHIBIT
    assert "192.0.2.0/24" not in kinds  # connected: derived from the subnets
    assert (
        kinds["198.18.50.0/24"].origin is RouteOrigin.VPN and kinds["198.18.50.0/24"].table == "vpn"
    )
    assert kinds["198.18.50.0/24"].interface == port_id("gw", "wg0")
    assert (
        kinds["198.18.51.0/24"].origin is RouteOrigin.DYNAMIC
        and kinds["198.18.51.0/24"].gateway is None
    )
    assert kinds["2001:db8:50::/64"].gateway is None  # family mismatch
    rule_rows = [
        {".id": "*1", "src-address": "192.0.2.128/25", "action": "lookup", "table": "100"},
        {".id": "*2", "dst-address": "198.18.0.0/16", "action": "drop"},
        {".id": "*3", "action": "unreachable", "interface": "bridge", "disabled": "true"},
        {".id": "*4", "action": "lookup-only-in-table", "table": "main"},
        {".id": "*5", "action": "weird"},
        {".id": "*6", "src-address": "nonsense"},
        {".id": "*7", "interface": "unknown"},
        {"action": "lookup"},
    ]
    rules = mikrotik.read_rules("gw", rule_rows, lambda n: LAN if n == "bridge" else None)
    assert [r.priority for r in rules] == [0, 1, 2, 3, 7]
    assert rules[1].action is RuleAction.BLACKHOLE and rules[2].segment_id == LAN
    assert not rules[2].enabled and rules[0].table == "100"


def test_linux_routes_and_rules() -> None:
    a = Answer(
        {
            "routes4": json.dumps(
                [
                    {
                        "dst": "default",
                        "gateway": "198.51.100.1",
                        "dev": "eth0",
                        "protocol": "dhcp",
                        "metric": 100,
                        "flags": ["linkdown"],
                    },
                    {"dst": "192.0.2.0/25", "dev": "br0", "protocol": "kernel", "scope": "link"},
                    {
                        "dst": "198.18.20.0/24",
                        "gateway": "192.0.2.254",
                        "dev": "br0",
                        "protocol": "static",
                    },
                    {"dst": "198.18.50.0/24", "dev": "wg0", "protocol": "static", "scope": "link"},
                    {"dst": "198.18.60.0/24", "gateway": "192.0.2.253", "protocol": "bird"},
                    {"dst": "198.18.66.0/24", "type": "blackhole"},
                    {"dst": "198.18.67.0/24", "type": "multicast"},
                    {"dst": "192.0.2.1", "type": "local", "table": "local", "dev": "br0"},
                    {"dst": "default", "gateway": "198.51.100.1", "dev": "eth0", "table": "100"},
                    {"dst": "nonsense"},
                    {"dst": "198.18.70.0/24", "gateway": "fe80::1"},
                ]
            ),
            "routes6": json.dumps(
                [{"dst": "default", "gateway": "fe80::1", "dev": "eth0", "protocol": "ra"}]
            ),
            "rules4": json.dumps(
                [
                    {"priority": 0, "src": "all", "table": "local"},
                    {"priority": 100, "src": "192.0.2.128", "srclen": 25, "table": "100"},
                    {
                        "priority": 200,
                        "src": "all",
                        "dst": "198.18.0.0",
                        "dstlen": 16,
                        "iif": "br0",
                        "action": "blackhole",
                    },
                    {"priority": 300, "src": "all", "fwmark": "0x1", "table": "100"},
                    {"priority": 400, "src": "all", "iif": "nowhere", "table": "100"},
                    {"priority": 500, "src": "bad", "table": "100"},
                    {"priority": 600, "src": "all", "action": "goto"},
                    {"priority": 32766, "src": "all", "table": "main"},
                    {"priority": 32767, "src": "all", "table": "default"},
                    {"src": "all", "table": "100", "action": "lookup"},
                ]
            ),
            "rules6": "not json",
        }
    )
    routes = linux.read_routes("gw", a, frozenset({"wg0"}))
    by = {(str(r.destination), r.table): r for r in routes}
    assert (
        by[("0.0.0.0/0", "main")].origin is RouteOrigin.DHCP
        and by[("0.0.0.0/0", "main")].active is False
    )
    assert by[("198.18.20.0/24", "main")].origin is RouteOrigin.STATIC
    assert by[("198.18.50.0/24", "main")].origin is RouteOrigin.VPN
    assert by[("198.18.60.0/24", "main")].origin is RouteOrigin.DYNAMIC
    assert by[("198.18.66.0/24", "main")].kind is RouteKind.BLACKHOLE
    assert by[("0.0.0.0/0", "100")].table == "100" and by[("::/0", "main")].origin is RouteOrigin.RA
    assert by[("198.18.70.0/24", "main")].gateway is None
    assert not any(
        str(r.destination) in ("192.0.2.0/25", "198.18.67.0/24", "192.0.2.1/32") for r in routes
    )
    assert linux.read_routes("gw", Answer({})) == []
    rules = linux.read_rules("gw", a, lambda n: LAN if n == "br0" else None)
    assert sorted(r.priority or 0 for r in rules) == [0, 100, 200, 32766]
    assert next(r for r in rules if r.priority == 200).action is RuleAction.BLACKHOLE
    assert next(r for r in rules if r.priority == 100).src == cidr("192.0.2.128/25")


def test_opnsense_routes() -> None:
    status = opnsense.gateways(
        [
            {"name": "WAN_DHCP", "address": "198.51.100.1", "status": "none"},
            {"name": "LAB_GW", "address": "192.0.2.254", "status": "online"},
            {"name": "DOWN_GW", "address": "192.0.2.253", "status": "down"},
            {"name": "V6_GW", "address": "2001:db8::1", "status": "Packetloss"},
            {"name": "NEW_GW", "address": "not an address", "status": "pending"},
            {"address": "192.0.2.1"},
        ]
    )
    assert status["LAB_GW"] == (ip("192.0.2.254"), True)
    assert status["DOWN_GW"][1] is False and status["V6_GW"][1] is False
    assert status["NEW_GW"] == (None, None)
    rows = [
        {"network": "198.18.20.0/24", "gateway": "LAB_GW", "descr": "lab"},
        {"network": "198.18.30.0/24", "gateway": "LAB_GW", "disabled": "1"},
        {"network": "198.18.31.0/24", "gateway": "DOWN_GW"},
        {"network": "198.18.32.0/24", "gateway": "V6_GW"},
        {"network": "198.18.33.0/24", "gateway": "MISSING"},
        {"network": "nonsense", "gateway": "LAB_GW"},
    ]
    routes = {str(r.destination): r for r in opnsense.static_routes("gw", rows, status)}
    assert routes["198.18.20.0/24"].gateway == ip("192.0.2.254") and routes["198.18.20.0/24"].active
    assert routes["198.18.30.0/24"].enabled is False and routes["198.18.30.0/24"].active is None
    assert routes["198.18.31.0/24"].active is False
    assert routes["198.18.32.0/24"].gateway is None and routes["198.18.33.0/24"].active is None
    assert routes["198.18.20.0/24"].vendor_extra == {"descr": "lab", "gateway": "LAB_GW"}
    wan = uplink("gw", port="eth1")
    default = opnsense.default_route("gw", wan)
    assert default is not None and default.gateway == ip("198.51.100.1")
    assert default.interface == port_id("gw", "eth1") and default.origin is RouteOrigin.DHCP
    static = uplink("gw", kind=UplinkKind.STATIC, upstream_gateway=ip("fe80::1"))
    assert opnsense.default_route("gw", static).destination == cidr("::/0")  # type: ignore[union-attr]
    assert opnsense.default_route("gw", None) is None
    assert opnsense.default_route("gw", uplink("gw", up=False)) is None
    assert opnsense.default_route("gw", uplink("gw", upstream_gateway=None)) is None


def test_fritzbox_routes() -> None:
    def entry(**kw: str) -> dict[str, str]:
        return {
            "NewEnable": "1",
            "NewType": "Network",
            "NewDestIPAddress": "198.18.20.0",
            "NewDestSubnetMask": "255.255.255.0",
            "NewSourceIPAddress": "0.0.0.0",
            "NewGatewayIPAddress": "192.0.2.254",
            "NewForwardingMetric": "0",
        } | kw

    route = fritz.static_route("gw", entry())
    assert route is not None and str(route.destination) == "198.18.20.0/24" and route.metric == 0
    assert (
        route.gateway == ip("192.0.2.254") and route.enabled and route.origin is RouteOrigin.STATIC
    )
    host = fritz.static_route("gw", entry(NewType="Host", NewDestIPAddress="198.18.9.9"))
    assert host is not None and str(host.destination) == "198.18.9.9/32"
    off = fritz.static_route(
        "gw", entry(NewEnable="0", NewGatewayIPAddress="0.0.0.0", NewForwardingMetric="x")
    )
    assert off is not None and not off.enabled and off.gateway is None and off.metric is None
    assert fritz.static_route("gw", entry(NewSourceIPAddress="192.0.2.5")) is None
    assert fritz.static_route("gw", entry(NewDestIPAddress="nonsense")) is None
    assert fritz.static_route("gw", entry(NewDestSubnetMask="")) is not None
    assert fritz.static_route("gw", entry(NewDestSubnetMask="255.0.255.0")) is None
    wan = uplink("gw")
    default = fritz.default_route("gw", wan, "uuid:1,urn:upnp-org:serviceId:WANIPConn1")
    assert default is not None and default.destination == cidr("0.0.0.0/0")
    assert default.gateway == ip("198.51.100.1") and default.origin is RouteOrigin.DHCP
    assert fritz.default_route("gw", wan, " ") is None
    assert fritz.default_route("gw", None, "x") is None
    assert fritz.default_route("gw", uplink("gw", up=False), "x") is None
    v6 = fritz.default_route("gw", uplink("gw", upstream_gateway=ip("fe80::1")), "x")
    assert v6 is not None and v6.destination == cidr("::/0")


# --- contract and merge ------------------------------------------------------------------------


class Routed(Fake):
    async def read_interfaces(self) -> Observation:
        base = await super().read_interfaces()
        d = self.context.device_id
        return base.model_copy(
            update={
                "routes": [
                    rt(d, "0.0.0.0/0", "192.0.2.1"),
                    rt(d, "198.18.20.0/24", interface=port_id(d, "lan")),
                ],
                "routing_rules": [rule_of(d, "x", priority=1, segment_id=LAN, table="100")],
            }
        )


async def test_contract_checks_routes_and_merge_collects_them() -> None:
    from signalbox.testing import assert_contract

    snap = await assert_contract(Routed(ctx()))
    assert len(snap.routes) == 2 and len(snap.routing_rules) == 1
    n = merge([SITE], [snap])
    assert len(n.routes) == 2 and n.routing_rules[0].segment_id == LAN
    assert n.routes_of(snap.device.id)[0].device_id == snap.device.id


async def test_the_contract_finds_bad_routes() -> None:
    from signalbox.testing import assert_contract

    class Bad(Routed):
        async def read_interfaces(self) -> Observation:
            base = await super().read_interfaces()
            d = self.context.device_id
            twice = rt(d, "198.18.20.0/24", "192.0.2.254")
            odd = twice.model_copy(
                update={"id": f"{d}/route/odd", "interface": port_id(d, "nowhere"), "table": ""}
            )
            other = twice.model_copy(update={"id": "x/route/1", "device_id": "x"})
            gone = rule_of(d, "gone", segment_id="home/segment/99")
            return base.model_copy(
                update={
                    "routes": [twice, twice, odd, other],
                    "routing_rules": [gone, gone],
                }
            )

    with pytest.raises(AssertionError) as err:
        await assert_contract(Bad(ctx()))
    text = str(err.value)
    for part in (
        "reported twice",
        "unknown port",
        "has no table",
        "unknown segment",
        "has device_id",
    ):
        assert part in text
