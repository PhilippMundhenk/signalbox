"""Linux routes and policy rules (#149) from ``ip -j``.

- ``ip -j route show table all`` and ``ip -j -6 route show table all`` (sections ``routes4`` and
  ``routes6``): every table. The ``local`` table (the device's own addresses, broadcast) and
  routes the kernel adds for a connected network (``proto kernel``) are left out: connected
  networks come from the subnets (ADR 0022). A route in a table other than ``main`` carries
  ``"table": "<name or number>"``; ``type`` is absent for ``unicast``.
- ``ip -j rule show`` and ``ip -j -6 rule show`` (sections ``rules4`` and ``rules6``): the
  policy rules. The ``local`` lookup (priority 0) and the empty ``default`` table are left out.

*Guess until a device confirms it (#21)*: the JSON key of a rule's action (``action``, else
``type``) for ``blackhole``, ``prohibit`` and ``unreachable`` rules, and ``iif`` for the incoming
interface. A rule with a key this module does not know (``fwmark``, ``uidrange``, ``not``) is
left out: it cannot be evaluated.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from ipaddress import ip_address, ip_network
from typing import Any

from signalbox.adapters.linux.collect import Answer
from signalbox.adapters.linux.parse import _int, _json
from signalbox.model import (
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

ROUTE_LIMIT = 4096

_SKIP_TABLES = ("local", "default", "255", "253")
_KINDS = {
    "blackhole": RouteKind.BLACKHOLE,
    "unreachable": RouteKind.UNREACHABLE,
    "prohibit": RouteKind.PROHIBIT,
}
_ORIGIN = {
    "dhcp": RouteOrigin.DHCP,
    "ra": RouteOrigin.RA,
    "static": RouteOrigin.STATIC,
    "boot": RouteOrigin.STATIC,
    "bird": RouteOrigin.DYNAMIC,
    "zebra": RouteOrigin.DYNAMIC,
    "babel": RouteOrigin.DYNAMIC,
    "bgp": RouteOrigin.DYNAMIC,
    "ospf": RouteOrigin.DYNAMIC,
    "rip": RouteOrigin.DYNAMIC,
    "isis": RouteOrigin.DYNAMIC,
}
_KNOWN_RULE_KEYS = frozenset(
    {"priority", "src", "srclen", "dst", "dstlen", "iif", "table", "action", "type", "protocol"}
)


def _rows(answer: Answer, name: str) -> list[dict[str, Any]]:
    data = _json(answer.text(name))
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


def read_routes(
    device_id: str, answer: Answer, tunnel_ports: frozenset[str] = frozenset()
) -> list[Route]:
    """*tunnel_ports*: names of the VPN interfaces, whose routes are ``vpn`` routes."""
    out: dict[str, Route] = {}
    for section in ("routes4", "routes6"):
        for row in _rows(answer, section):
            table = str(row.get("table") or "main")
            kind = _KINDS.get(str(row.get("type") or "unicast"))
            if table in _SKIP_TABLES or (row.get("type") not in (None, "unicast") and kind is None):
                continue
            protocol = str(row.get("protocol") or "")
            if protocol == "kernel" and kind is None:
                continue  # connected network
            text = str(row.get("dst") or "")
            dest: IPNetwork | None = None
            with contextlib.suppress(ValueError):
                if text == "default":
                    dest = ip_network("::/0" if section == "routes6" else "0.0.0.0/0")
                else:
                    dest = ip_network(text, strict=False)
            if dest is None:
                continue
            gateway: IPAddress | None = None
            with contextlib.suppress(ValueError):
                gateway = ip_address(str(row.get("gateway")))
            if gateway is not None and gateway.version != dest.version:
                gateway = None
            dev = row.get("dev") if isinstance(row.get("dev"), str) else None
            via = port_id(device_id, dev) if dev else None
            origin = _ORIGIN.get(protocol, RouteOrigin.OTHER)
            if dev in tunnel_ports:
                origin = RouteOrigin.VPN
            flags = [str(f) for f in row.get("flags") or []]
            route = Route(
                id=route_id(device_id, table, dest, gateway, via, kind or RouteKind.UNICAST),
                device_id=device_id,
                table=table,
                destination=dest,
                gateway=gateway,
                interface=via,
                metric=_int(str(row["metric"])) if row.get("metric") is not None else None,
                origin=origin,
                kind=kind or RouteKind.UNICAST,
                active=not ({"dead", "linkdown"} & set(flags)),
            )
            out[route.id] = route
    return sorted(out.values(), key=lambda r: r.id)[:ROUTE_LIMIT]


def _prefix(row: dict[str, Any], key: str) -> tuple[IPNetwork | None, bool]:
    """The ``src``/``dst`` match of a rule: (network or None for any, readable)."""
    text = str(row.get(key) or "all")
    if text == "all":
        return None, True
    length = row.get(f"{key}len")
    try:
        return ip_network(f"{text}/{length}" if length is not None else text, strict=False), True
    except ValueError:
        return None, False


def read_rules(
    device_id: str, answer: Answer, segment_of: Callable[[str], str | None]
) -> list[RoutingRule]:
    out: dict[str, RoutingRule] = {}
    for section in ("rules4", "rules6"):
        for row in _rows(answer, section):
            table = str(row.get("table") or "")
            action_text = str(row.get("action") or row.get("type") or "")
            action = {
                "blackhole": RuleAction.BLACKHOLE,
                "prohibit": RuleAction.PROHIBIT,
                "unreachable": RuleAction.UNREACHABLE,
            }.get(action_text)
            if set(row) - _KNOWN_RULE_KEYS or table in ("local", "default", "253"):
                continue
            if action is None and (action_text not in ("", "to_tbl", "lookup") or not table):
                continue
            src, src_ok = _prefix(row, "src")
            dst, dst_ok = _prefix(row, "dst")
            iif = str(row.get("iif") or "")
            segment = segment_of(iif) if iif else None
            if not (src_ok and dst_ok) or (iif and segment is None):
                continue
            priority = _int(str(row["priority"])) if row.get("priority") is not None else None
            key = f"{section}/{priority}/{src}/{dst}/{iif}/{table}/{action_text}"
            rule = RoutingRule(
                id=routing_rule_id(device_id, key),
                device_id=device_id,
                priority=priority,
                src=src,
                dst=dst,
                segment_id=segment,
                table=table or "main",
                action=action or RuleAction.LOOKUP,
            )
            out[rule.id] = rule
    return list(out.values())
