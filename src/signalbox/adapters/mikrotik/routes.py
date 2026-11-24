"""MikroTik routes and routing rules (#149).

- ``/rest/ip/route`` and ``/rest/ipv6/route``: the whole table the router keeps. Connected
  routes (``connect``) are left out (derived from the subnets, ADR 0024). Fields as in RouterOS
  7: ``dst-address``, ``gateway`` (an address, or an interface name for a route without next
  hop), ``distance``, ``routing-table``, ``disabled``, ``active``, ``blackhole``,
  ``unreachable``, ``prohibit``, and the origin flags ``static``, ``dhcp``, ``bgp``, ``ospf``,
  ``rip``, ``vpn``, ``dynamic``. The IPv6 menu has no ``distance`` on older versions.
- ``/rest/routing/rule``: ``src-address``, ``dst-address``, ``interface``, ``action``
  (``lookup``, ``lookup-only-in-table``, ``drop``, ``unreachable``), ``table``, ``disabled``;
  RouterOS has no priority number, the order of the list is the priority.

*Guess until a real device or the CHR image confirms the flag names (#21).*
"""

from __future__ import annotations

from collections.abc import Callable
from ipaddress import ip_address, ip_network
from typing import Any

from signalbox.model import (
    ROUTE_LIMIT,
    IPAddress,
    IPNetwork,
    Route,
    RouteKind,
    RouteOrigin,
    RoutingRule,
    RuleAction,
    port_id,
    route_id,
    routing_rule_id,
)

IP_ROUTE = "/rest/ip/route"
IPV6_ROUTE = "/rest/ipv6/route"
ROUTING_RULE = "/rest/routing/rule"

_ORIGINS = (
    ("dhcp", RouteOrigin.DHCP),
    ("vpn", RouteOrigin.VPN),
    ("bgp", RouteOrigin.DYNAMIC),
    ("ospf", RouteOrigin.DYNAMIC),
    ("rip", RouteOrigin.DYNAMIC),
    ("static", RouteOrigin.STATIC),
)


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return value in (True, "true", "yes")


def _int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _network(value: Any) -> IPNetwork | None:
    try:
        return ip_network(_text(value), strict=False)
    except ValueError:
        return None


def _gateway(value: Any) -> tuple[IPAddress | None, str | None]:
    """The next hop as ``(address, interface name)``: the gateway field holds one or the
    other; RouterOS 7 may append ``%interface`` to an address."""
    text = _text(value).split(",")[0].strip()
    if not text:
        return None, None
    address, _, iface = text.partition("%")
    try:
        return ip_address(address), iface or None
    except ValueError:
        return None, text


def _kind(row: dict[str, Any]) -> RouteKind:
    """A dropping route: the flag of the same name (``blackhole=true``), RouterOS 6's ``type``,
    or the word in place of the gateway (*guess* which one a CHR 7 REST row has, #21)."""
    for word, kind in (
        ("blackhole", RouteKind.BLACKHOLE),
        ("unreachable", RouteKind.UNREACHABLE),
        ("prohibit", RouteKind.PROHIBIT),
    ):
        if (
            _flag(row.get(word))
            or _text(row.get("type")) == word
            or _text(row.get("gateway")) == word
        ):
            return kind
    return RouteKind.UNICAST


def read_routes(device_id: str, rows: list[dict[str, Any]]) -> list[Route]:
    out: dict[str, Route] = {}
    for row in rows:
        dest = _network(row.get("dst-address"))
        if dest is None or _flag(row.get("connect")):
            continue
        gateway, iface = _gateway(row.get("gateway") or row.get("immediate-gw"))
        if gateway is not None and gateway.version != dest.version:
            gateway = None
        kind = _kind(row)
        origin = next((o for key, o in _ORIGINS if _flag(row.get(key))), RouteOrigin.OTHER)
        table = _text(row.get("routing-table") or row.get("routing-mark")) or "main"
        via = port_id(device_id, iface) if iface else None
        active = row.get("active")
        route = Route(
            id=route_id(device_id, table, dest, gateway, via, kind),
            device_id=device_id,
            table=table,
            destination=dest,
            gateway=gateway,
            interface=via,
            metric=_int(row.get("distance")),
            origin=origin,
            kind=kind,
            enabled=not _flag(row.get("disabled")),
            active=None if active is None else _flag(active),
        )
        out[route.id] = route
    return sorted(out.values(), key=lambda r: r.id)[:ROUTE_LIMIT]


def read_rules(
    device_id: str, rows: list[dict[str, Any]], segment_of: Callable[[str], str | None]
) -> list[RoutingRule]:
    out: list[RoutingRule] = []
    for position, row in enumerate(rows):
        action = _text(row.get("action")) or "lookup"
        mapped = {
            "lookup": RuleAction.LOOKUP,
            "lookup-only-in-table": RuleAction.LOOKUP,
            "drop": RuleAction.BLACKHOLE,
            "unreachable": RuleAction.UNREACHABLE,
        }.get(action)
        src_text, dst_text = _text(row.get("src-address")), _text(row.get("dst-address"))
        src, dst = _network(src_text), _network(dst_text)
        iface = _text(row.get("interface"))
        segment = segment_of(iface) if iface else None
        if mapped is None or (src_text and src is None) or (dst_text and dst is None):
            continue
        if iface and segment is None:
            continue  # an incoming interface that is no network of this router
        out.append(
            RoutingRule(
                id=routing_rule_id(device_id, _text(row.get(".id")) or str(position)),
                device_id=device_id,
                priority=position,
                src=src,
                dst=dst,
                segment_id=segment,
                table=_text(row.get("table")) or "main",
                action=mapped,
                enabled=not _flag(row.get("disabled")),
            )
        )
    return out
