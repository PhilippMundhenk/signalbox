"""OpenWrt routes and policy rules (#149).

- ``network.interface dump``: the ``route`` list of every running interface (the routes netifd
  installed: static routes, the default route of DHCP and PPPoE, RA routes). The origin is
  derived from the interface's protocol; the dump does not name it.
- UCI ``network``: ``route`` and ``route6`` sections (``target``, ``netmask``, ``gateway``,
  ``metric``, ``table``, ``interface``, ``disabled``) and ``rule`` and ``rule6`` sections
  (``src``, ``dest``, ``in``, ``lookup``, ``priority``, ``action``, ``disabled``). A configured
  route that is not in the dump is reported with ``active`` False.

Connected networks are not reported: they come from the subnets (ADR 0022). Both reads use data
``read_interfaces`` has already (the ``network`` config and the running interfaces): no extra
ACL entry. The option names of ``rule`` are the netifd ones; *guess* until confirmed on a
device for ``action`` values other than ``blackhole``, ``unreachable`` and ``prohibit`` (#21).
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

_PROTO_ORIGIN = {
    "dhcp": RouteOrigin.DHCP,
    "pppoe": RouteOrigin.DHCP,
    "pppoa": RouteOrigin.DHCP,
    "dhcpv6": RouteOrigin.RA,
}
_VPN_PROTOS = ("wireguard", "openvpn")
_ACTIONS = {
    "blackhole": RuleAction.BLACKHOLE,
    "prohibit": RuleAction.PROHIBIT,
    "unreachable": RuleAction.UNREACHABLE,
}
_KINDS = {
    "blackhole": RouteKind.BLACKHOLE,
    "unreachable": RouteKind.UNREACHABLE,
    "prohibit": RouteKind.PROHIBIT,
}


def _int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _flag(value: Any) -> bool:
    return str(value).lower() in ("1", "true", "yes", "on")


def _address(value: Any) -> IPAddress | None:
    try:
        return ip_address(str(value))
    except ValueError:
        return None


def _network(target: Any, mask: Any = None) -> IPNetwork | None:
    """``192.0.2.0`` with ``255.255.255.0`` or a prefix length, or ``192.0.2.0/24``."""
    text = str(target or "")
    if not text:
        return None
    if text == "default":
        return ip_network("0.0.0.0/0")
    if mask not in (None, "") and "/" not in text:
        text = f"{text}/{mask}"
    try:
        return ip_network(text, strict=False)
    except ValueError:
        return None


def _sections(uci: dict[str, Any], *kinds: str) -> list[tuple[str, dict[str, Any]]]:
    values = uci.get("values")
    if not isinstance(values, dict):
        return []
    found = [
        (str(s.get(".name", name)), s)
        for name, s in values.items()
        if isinstance(s, dict) and s.get(".type") in kinds
    ]
    return sorted(found, key=lambda item: _int(item[1].get(".index")) or 0)


def read_routes(
    device_id: str, uci: dict[str, Any], running: dict[str, dict[str, Any]], devices: dict[str, str]
) -> list[Route]:
    """Installed routes of the running interfaces plus the configured ``route`` sections.

    *devices* maps a UCI interface name to its device (``br-lan``, ``eth1``), which is the
    port the route leaves through."""
    out: dict[str, Route] = {}

    def add(route: Route) -> None:
        old = out.get(route.id)
        if old is None or (route.active and not old.active):
            out[route.id] = route

    def port(name: str) -> str:
        return port_id(device_id, devices.get(name, name))

    for name in sorted(running):
        entry = running[name]
        proto = str(entry.get("proto"))
        for r in entry.get("route") or []:
            if not isinstance(r, dict):
                continue
            dest = _network(r.get("target"), r.get("mask"))
            if dest is None:
                continue
            gateway = _address(r.get("nexthop"))
            if gateway is not None and (gateway.is_unspecified or gateway.version != dest.version):
                gateway = None
            if proto in _VPN_PROTOS:
                origin = RouteOrigin.VPN
            elif dest.prefixlen == 0 and proto in _PROTO_ORIGIN:
                origin = _PROTO_ORIGIN[proto]
            else:
                origin = RouteOrigin.STATIC
            ifname = port(name)
            add(
                Route(
                    id=route_id(device_id, "main", dest, gateway, ifname),
                    device_id=device_id,
                    destination=dest,
                    gateway=gateway,
                    interface=ifname,
                    metric=_int(r.get("metric")),
                    origin=origin,
                    active=True,
                )
            )
    for _, s in _sections(uci, "route", "route6"):
        dest = _network(s.get("target"), s.get("netmask") or s.get("mask"))
        if dest is None:
            continue
        gateway = _address(s.get("gateway"))
        if gateway is not None and gateway.version != dest.version:
            continue
        kind = _KINDS.get(str(s.get("type") or ""), RouteKind.UNICAST)
        iface = str(s.get("interface") or "")
        via = port(iface) if iface else None
        table = str(s.get("table") or "main")
        enabled = not _flag(s.get("disabled"))
        add(
            Route(
                id=route_id(device_id, table, dest, gateway, via, kind),
                device_id=device_id,
                table=table,
                destination=dest,
                gateway=gateway,
                interface=via,
                metric=_int(s.get("metric")),
                origin=RouteOrigin.STATIC,
                kind=kind,
                enabled=enabled,
            )
        )
    # a configured main route the running interfaces do not show: configured only
    for rid, route in list(out.items()):
        if route.active is None and route.table == "main" and route.enabled and running:
            out[rid] = route.model_copy(update={"active": False})
    return sorted(out.values(), key=lambda r: r.id)[:ROUTE_LIMIT]


def read_rules(
    device_id: str, uci: dict[str, Any], segment_of: Callable[[str], str | None]
) -> list[RoutingRule]:
    out: dict[str, RoutingRule] = {}
    for name, s in _sections(uci, "rule", "rule6"):
        action = _ACTIONS.get(str(s.get("action") or ""), RuleAction.LOOKUP)
        if action is RuleAction.LOOKUP and not s.get("lookup"):
            continue  # a jump or another action: not a table lookup
        src = _network(s.get("src"))
        dst = _network(s.get("dest"))
        if (
            _flag(s.get("invert"))
            or (s.get("src") and src is None)
            or (s.get("dest") and dst is None)
        ):
            continue  # a negated or unreadable match cannot be represented
        iface = str(s.get("in") or "")
        segment = segment_of(iface) if iface else None
        if iface and segment is None:
            continue  # incoming interface that is no network of this router: not representable
        rule = RoutingRule(
            id=routing_rule_id(device_id, name),
            device_id=device_id,
            priority=_int(s.get("priority")),
            src=src,
            dst=dst,
            segment_id=segment,
            table=str(s.get("lookup") or "main"),
            action=action,
            enabled=not _flag(s.get("disabled")),
        )
        out[rule.id] = rule
    return list(out.values())
