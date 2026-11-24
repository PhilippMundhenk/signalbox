"""Routing rules: a gateway without a default route, two equal default routes, a static route
whose next hop is not reachable, a route with no way back (#149, ADR 0024).

They read :class:`~signalbox.model.Route` and :class:`~signalbox.model.RoutingRule` and answer
with :func:`signalbox.routing.next_hop`. They stay quiet for a device whose routes were not read
(no route reported): that is "not known", not "no routes".
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from signalbox.model import (
    DeviceRole,
    DeviceStatus,
    IPAddress,
    IPNetwork,
    Network,
    Route,
    RouteKind,
    RouteOrigin,
)
from signalbox.routing import HopKind, address_owner, connected_networks, has_routes, next_hop
from signalbox.rules import Result, Severity, found, rule
from signalbox.rules._names import device_name, site_of_device


def _usable(route: Route) -> bool:
    return route.enabled and route.active is not False and route.kind is RouteKind.UNICAST


def _defaults(net: Network, device_id: str, version: int) -> list[Route]:
    return [
        r
        for r in net.routes_of(device_id)
        if _usable(r) and r.table == "main" and r.default and r.destination.version == version
    ]


@rule(
    "route.default-missing",
    "A router has no default route",
    Severity.WARNING,
    "A router that connects a network to the internet sends everything it has no better "
    "route for to its default route. Without one, no device behind it can reach the "
    "internet, even though the internet connection itself is up.",
)
def default_missing(net: Network) -> Iterator[Result]:
    for dev in sorted(net.devices, key=lambda d: d.id):
        if dev.role is not DeviceRole.GATEWAY or not has_routes(net, dev.id):
            continue
        if net.statuses.get(dev.id, DeviceStatus.OK) is not DeviceStatus.OK:
            continue
        uplinks = net.uplinks_of(dev.id)
        if uplinks and all(u.up is False for u in uplinks):
            continue  # the connection is down: the default route is gone with it
        if _defaults(net, dev.id, 4):
            continue
        name = device_name(net, dev.id)
        yield found(
            f"{name} has no default route: nothing behind it can reach the internet",
            [dev.id],
            fix="Check the internet connection of the router and its gateway setting; on a "
            "router with several connections, make sure one of them is the default.",
            mid="route.defaultMissing",
            fix_id="route.defaultMissing.fix",
            params={"device": name},
        )


@rule(
    "route.multiple-default",
    "A router has two default routes with the same metric",
    Severity.INFO,
    "With equal metrics it is not defined which default route carries a connection, so "
    "traffic may jump between internet connections and break logins and streams. Give the "
    "connection that should win the lower metric.",
)
def multiple_default(net: Network) -> Iterator[Result]:
    for dev in sorted(net.devices, key=lambda d: d.id):
        for version in (4, 6):
            by_metric: dict[int, list[Route]] = defaultdict(list)
            for r in _defaults(net, dev.id, version):
                if r.metric is not None:
                    by_metric[r.metric].append(r)
            for metric, routes in sorted(by_metric.items()):
                ways = {(str(r.gateway), r.interface) for r in routes}
                if len(ways) < 2:
                    continue
                name = device_name(net, dev.id)
                yield found(
                    f"{name} has {len(ways)} default routes with the same metric {metric}: "
                    "it is not defined which one carries the traffic",
                    [dev.id, *(r.id for r in routes)],
                    fix="Give the connection that should be preferred the lower metric (a "
                    "failover pair needs different metrics).",
                    key=f"{version}/{metric}",
                    mid="route.multipleDefault",
                    fix_id="route.multipleDefault.fix",
                    params={"device": name, "count": len(ways), "metric": metric},
                )


def _on_link(net: Network, device_id: str, address: IPAddress) -> bool:
    return any(
        n.version == address.version and address in n for n, _ in connected_networks(net, device_id)
    )


@rule(
    "route.unreachable-gateway",
    "A static route's next hop is outside every network of the router",
    Severity.WARNING,
    "A static route sends traffic to a next hop that the router must reach directly. If "
    "the next hop is in none of the router's own networks, the route cannot be used.",
)
def unreachable_gateway(net: Network) -> Iterator[Result]:
    for dev in sorted(net.devices, key=lambda d: d.id):
        if not connected_networks(net, dev.id):
            continue  # its own networks are not known
        for r in sorted(net.routes_of(dev.id), key=lambda r: r.id):
            if r.origin is not RouteOrigin.STATIC or not _usable(r) or r.gateway is None:
                continue
            if r.gateway.is_link_local or _on_link(net, dev.id, r.gateway):
                continue
            name = device_name(net, dev.id)
            yield found(
                f"On {name}, the static route to {r.destination} uses the next hop "
                f"{r.gateway}, which is in none of its networks",
                [dev.id, r.id],
                fix="Correct the next hop to an address in a network of this router, or give "
                "the router an address in the network of the next hop.",
                mid="route.unreachableGateway",
                fix_id="route.unreachableGateway.fix",
                params={"device": name, "network": str(r.destination), "gateway": str(r.gateway)},
            )


def _back(net: Network, via: str, source: IPNetwork, origin: str) -> tuple[HopKind, str | None]:
    """How *via* sends traffic for an address of *source*: (kind, next device)."""
    hop = next_hop(net, via, source.network_address)
    if hop.uncertain:
        return HopKind.UNKNOWN, None
    if hop.kind is HopKind.GATEWAY and hop.device_id == origin:
        return HopKind.CONNECTED, origin
    return hop.kind, hop.device_id


def _masquerades(net: Network, via: str, destination: IPNetwork) -> bool:
    """*via* translates the source address of traffic it sends into *destination*: the
    answers go to *via* itself and need no route back."""
    fw = net.firewall_of(via)
    hop = next_hop(net, via, destination.network_address)
    if fw is None or hop.segment_id is None:
        return False
    zones = fw.zones_of(hop.segment_id)
    return any(z.masquerade for z in fw.zones if z.name in zones) or any(
        n.enabled and n.masquerade and (not n.zones or zones & set(n.zones)) for n in fw.nat
    )


def _return_cases(net: Network) -> Iterator[tuple[Route, str, str, IPNetwork, HopKind, str | None]]:
    """Static routes through another router of the network, with how that router answers for
    the networks behind the first one: (route, from, via, source network, kind, next device)."""
    for dev in sorted(net.devices, key=lambda d: d.id):
        own = [(x.interface.network, x.segment_id) for x in net.subnets if x.device_id == dev.id]
        for r in sorted(net.routes_of(dev.id), key=lambda r: r.id):
            if r.origin is not RouteOrigin.STATIC or not _usable(r) or r.gateway is None:
                continue
            if r.default or r.gateway.is_link_local:
                continue
            hop = next_hop(net, dev.id, r.gateway)
            if hop.kind is not HopKind.CONNECTED:
                continue
            via = address_owner(net, r.gateway)
            if via is None or via == dev.id or not has_routes(net, via):
                continue
            if _masquerades(net, via, r.destination):
                continue
            for network, segment in own:
                if segment == hop.segment_id or network.version != r.gateway.version:
                    continue
                if network.prefixlen == 0 or network.overlaps(r.destination):
                    continue
                kind, device = _back(net, via, network, dev.id)
                yield r, dev.id, via, network, kind, device


@rule(
    "route.no-return",
    "A router sends traffic to another router that has no way back",
    Severity.WARNING,
    "A static route sends a network to a second router. If that router has no route to "
    "the networks behind the first one, requests arrive and the answers are lost, so the "
    "connection never works.",
)
def no_return(net: Network) -> Iterator[Result]:
    seen: set[tuple[str, str, str]] = set()
    for r, origin, via, network, kind, device in _return_cases(net):
        if kind not in (HopKind.NO_ROUTE, HopKind.DROPPED) and not (
            kind is HopKind.GATEWAY and device is None
        ):
            continue
        if (origin, via, str(network)) in seen:
            continue
        seen.add((origin, via, str(network)))
        a, b = device_name(net, origin), device_name(net, via)
        yield found(
            f"{a} sends {r.destination} to {b}, but {b} has no route back to {network}: "
            "answers do not arrive",
            [origin, via, r.id],
            fix=f"Add a route on {b} for {network} through {a}, or make {a} its default gateway.",
            key=f"{via}/{network}",
            mid="route.noReturn",
            fix_id="route.noReturn.fix",
            params={"a": a, "b": b, "network": str(network), "destination": str(r.destination)},
        )


@rule(
    "route.asymmetric",
    "The way back between two routers differs from the way there",
    Severity.INFO,
    "A static route sends a network to a second router, which answers through a third "
    "router instead of the first. Such an asymmetric path works only while no firewall on "
    "the way tracks connections; most do, and drop the answers.",
)
def asymmetric(net: Network) -> Iterator[Result]:
    seen: set[tuple[str, str, str]] = set()
    for r, origin, via, network, kind, device in _return_cases(net):
        if kind is not HopKind.GATEWAY or device is None or device == origin:
            continue
        if (origin, via, str(network)) in seen:
            continue
        seen.add((origin, via, str(network)))
        a, b, c = device_name(net, origin), device_name(net, via), device_name(net, device)
        yield found(
            f"{a} sends {r.destination} to {b}, but {b} answers {network} through {c}, not "
            f"through {a}",
            [origin, via, device, r.id],
            fix=f"Route {network} on {b} through {a}, or make {c} the next hop of {a} too.",
            key=f"{via}/{network}",
            mid="route.asymmetric",
            fix_id="route.asymmetric.fix",
            params={
                "a": a,
                "b": b,
                "c": c,
                "network": str(network),
                "destination": str(r.destination),
            },
        )


def _site_networks(net: Network, device_id: str) -> list[IPNetwork]:
    site = site_of_device(net, device_id)
    return [
        s.interface.network
        for s in net.subnets
        if site is not None and site_of_device(net, s.device_id) == site
    ]


@rule(
    "route.vpn-return",
    "The other end of a VPN tunnel has no route back",
    Severity.WARNING,
    "A site-to-site tunnel needs routes in both directions. If the other end's peer entry "
    "for this site accepts none of this site's networks, requests arrive and the answers "
    "are dropped.",
)
def vpn_return(net: Network) -> Iterator[Result]:
    for t in sorted(net.tunnels, key=lambda t: t.id):
        if t.public_key is None or not t.enabled or t.up is False:
            continue
        mine = _site_networks(net, t.device_id)
        if not mine:
            continue
        for p in t.site_peers():
            other = net.tunnel_with_key(p.public_key)
            if other is None or other.id == t.id or not p.enabled:
                continue
            there = other.peer(t.public_key)
            if there is None or not there.enabled:
                continue  # vpn.ends-disagree reports a missing peer
            accepted = other.remote_networks(there)
            if any(n.version == m.version and m.overlaps(n) for n in accepted for m in mine):
                continue
            a, b = (
                f"{device_name(net, t.device_id)}/{t.name}",
                f"{device_name(net, other.device_id)}/{other.name}",
            )
            yield found(
                f"Tunnel {a} sends traffic to {b}, but {b} accepts none of the networks of "
                "this site from it: answers are dropped",
                [t.id, other.id],
                fix=f"Add the networks of this site to the allowed IPs of the peer for {a} on "
                f"{b}, and a route for them through the tunnel.",
                key=p.public_key,
                mid="route.vpnReturn",
                fix_id="route.vpnReturn.fix",
                params={"a": a, "b": b},
            )


RULES = [default_missing, multiple_default, unreachable_gateway, no_return, asymmetric, vpn_return]
