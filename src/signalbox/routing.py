"""Routing: which way a device sends traffic to an address (#149, ADR 0022).

:func:`next_hop` answers "where does *device* send a packet for *address*?" from the device's
own networks (:class:`~signalbox.model.Subnet`, tunnel addresses) and the routes and policy
rules its adapter read. It is pure and conservative: a device whose table was not read gives
``unknown``; a policy rule it cannot evaluate (it matches on a source Signalbox does not know)
marks the answer ``uncertain``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import ip_address

from signalbox.model import (
    IPAddress,
    IPNetwork,
    Network,
    Route,
    RouteKind,
    RouteOrigin,
    RuleAction,
)

#: Tables looked up when a rule sends traffic to the same table twice: stops loops.
_MAX_TABLES = 16


def own_addresses(net: Network, device_id: str) -> dict[IPAddress, str]:
    """The device's addresses with the object they are on: a subnet's segment, an uplink, a
    tunnel."""
    out: dict[IPAddress, str] = {}
    for sub in net.subnets:
        if sub.device_id == device_id:
            out.setdefault(sub.interface.ip, sub.segment_id)
    for up in net.uplinks_of(device_id):
        for a in up.addresses:
            out.setdefault(a.ip, up.id)
    for t in net.tunnels_of(device_id):
        for a in t.addresses:
            out.setdefault(a.ip, t.id)
    return out


def address_owner(net: Network, address: IPAddress) -> str | None:
    """The device that has *address* as one of its own (or as its management address)."""
    for dev in sorted(net.devices, key=lambda d: d.id):
        if address in own_addresses(net, dev.id):
            return dev.id
    for dev in sorted(net.devices, key=lambda d: d.id):
        try:
            if ip_address((dev.management_address or "").strip("[]")) == address:
                return dev.id
        except ValueError:
            continue
    return None


def address_segment(net: Network, address: IPAddress) -> str | None:
    """The segment whose subnet holds *address* (the most specific subnet wins)."""
    best: tuple[int, str] | None = None
    for sub in net.subnets:
        n = sub.interface.network
        if (
            n.version == address.version
            and address in n
            and (best is None or n.prefixlen > best[0])
        ):
            best = (n.prefixlen, sub.segment_id)
    return best[1] if best else None


class HopKind(StrEnum):
    #: The address is in a network the device is attached to.
    CONNECTED = "connected"
    #: Sent to a gateway.
    GATEWAY = "gateway"
    #: Sent out of an interface without a gateway (a point-to-point link, a tunnel).
    INTERFACE = "interface"
    #: A blackhole, unreachable or prohibit route (or rule) catches it.
    DROPPED = "dropped"
    #: The table was read and has no route for the address.
    NO_ROUTE = "no-route"
    #: The device's routes were not read.
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class NextHop:
    kind: HopKind
    #: The route that decides; None for connected networks and without an answer.
    route: Route | None = None
    #: The gateway address of a ``gateway`` hop.
    gateway: IPAddress | None = None
    #: The device that owns the gateway address, where Signalbox knows it.
    device_id: str | None = None
    #: Segment (connected) or interface of the way out.
    segment_id: str | None = None
    #: A policy rule matching on a source or interface may send some traffic elsewhere.
    uncertain: bool = False


def _contains(net: IPNetwork, address: IPAddress) -> bool:
    return net.version == address.version and address in net


def connected_networks(net: Network, device_id: str) -> list[tuple[IPNetwork, str]]:
    """Networks the device is attached to, with the segment, uplink or tunnel id: derived from
    its subnets, the addresses of its internet connections and of its tunnels (ADR 0022).
    Link-local networks are left out."""
    out = [(s.interface.network, s.segment_id) for s in net.subnets if s.device_id == device_id]
    out += [
        (a.network, up.id)
        for up in net.uplinks_of(device_id)
        if up.up is not False
        for a in up.addresses
    ]
    out += [
        (a.network, t.id)
        for t in net.tunnels_of(device_id)
        if t.up is not False
        for a in t.addresses
    ]
    return [(n, i) for n, i in out if not n.is_link_local]


def has_routes(net: Network, device_id: str) -> bool:
    """Whether the device's routes were read (the integration reported at least one route)."""
    return any(r.device_id == device_id for r in net.routes)


def _tables(net: Network, device_id: str, address: IPAddress) -> tuple[list[str], bool, bool]:
    """Tables to look up in order; whether a rule may send some traffic elsewhere; whether a
    rule drops it (action ``blackhole`` and the like, with the kind)."""
    rules = net.routing_rules_of(device_id)
    if not rules:
        return ["main"], False, False
    tables: list[str] = []
    uncertain = False
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.dst is not None and not _contains(rule.dst, address):
            continue
        if rule.src is not None or rule.segment_id is not None:
            # depends on who sends: only matters when it leads somewhere else
            if rule.action is not RuleAction.LOOKUP or rule.table not in [*tables, "main"]:
                uncertain = True
            continue
        if rule.action is not RuleAction.LOOKUP:
            return tables, uncertain, True
        if rule.table not in tables:
            tables.append(rule.table)
    if "main" not in tables and not any(r.table == "main" for r in rules):
        tables.append("main")
    return tables[:_MAX_TABLES], uncertain, False


def next_hop(net: Network, device_id: str, address: IPAddress | str) -> NextHop:
    """Where *device_id* sends a packet for *address*.

    The longest matching network wins; at equal length a connected network beats a route, then
    the lower metric. Disabled routes and routes known not to be installed (``active`` False)
    are ignored. Policy rules are followed where they match on the destination only; rules that
    match on a source or an interface set ``uncertain``. A device without any read route:
    its connected networks still answer, anything else is ``unknown``.
    """
    if isinstance(address, str):
        address = ip_address(address.strip("[]"))
    tables, uncertain, dropped = _tables(net, device_id, address)
    if dropped:
        return NextHop(HopKind.DROPPED, uncertain=uncertain)
    own = net.routes_of(device_id)
    connected = [(n, s) for n, s in connected_networks(net, device_id) if _contains(n, address)]
    for table in tables:
        best: Route | None = None
        for route in own:
            if route.table != table or not route.enabled or route.active is False:
                continue
            if not _contains(route.destination, address):
                continue
            if best is None or (
                route.destination.prefixlen,
                -(route.metric or 0),
            ) > (best.destination.prefixlen, -(best.metric or 0)):
                best = route
        if table == "main" and connected:
            net_, seg = max(connected, key=lambda c: c[0].prefixlen)
            if best is None or net_.prefixlen >= best.destination.prefixlen:
                return NextHop(HopKind.CONNECTED, segment_id=seg, uncertain=uncertain)
        if best is not None:
            if best.kind is not RouteKind.UNICAST:
                return NextHop(HopKind.DROPPED, route=best, uncertain=uncertain)
            if best.gateway is not None:
                return NextHop(
                    HopKind.GATEWAY,
                    route=best,
                    gateway=best.gateway,
                    device_id=address_owner(net, best.gateway),
                    uncertain=uncertain,
                )
            if best.origin is RouteOrigin.CONNECTED or best.interface is not None:
                return NextHop(
                    HopKind.INTERFACE, route=best, segment_id=best.interface, uncertain=uncertain
                )
    if connected:
        net_, seg = max(connected, key=lambda c: c[0].prefixlen)
        return NextHop(HopKind.CONNECTED, segment_id=seg, uncertain=uncertain)
    if not own:
        return NextHop(HopKind.UNKNOWN, uncertain=uncertain)
    return NextHop(HopKind.NO_ROUTE, uncertain=uncertain)


def path(net: Network, device_id: str, address: IPAddress | str, limit: int = 8) -> list[str]:
    """The devices a packet for *address* passes, starting with *device_id*, following
    ``next_hop`` through the gateways Signalbox knows; ends when the address is in a connected
    network, at an unknown or unrouted device, or in a loop (the repeated device ends the
    list)."""
    seen = [device_id]
    current = device_id
    for _ in range(limit):
        hop = next_hop(net, current, address)
        if hop.kind is not HopKind.GATEWAY or hop.device_id is None:
            break
        seen.append(hop.device_id)
        if seen.count(hop.device_id) > 1:
            break
        current = hop.device_id
    return seen
