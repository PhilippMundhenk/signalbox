"""MikroTik RouterOS (write): tiers and monitors of the default routes (#463, ADR 0032).

The gateway group ``default`` is the set of enabled IPv4 default routes of the ``main`` table
(see ``multiwan``); a member is found by its next hop (``gateway``). Signalbox never adds or
removes routes or netwatch entries:

- the tier becomes the route's ``distance``: when the order of the tiers changes, every member
  gets its tier number as distance;
- a monitor that holds the route's gateway is ``check-gateway=ping``; one without it unsets
  ``check-gateway`` (an ``arp`` check is not a monitor address and is left alone);
- another monitor address is the ``host`` of the netwatch entry whose comment is the route's
  comment (the convention scripts that switch routes use, *guess*, #21): its host is changed.
  Without such an entry the change is refused: the up and down scripts of a netwatch entry are
  what moves the traffic, and they are the owner's. Removing the address is refused too.
- Routes a DHCP or PPPoE client adds are dynamic: RouterOS refuses to change them, so the plan
  is refused with the client setting to change instead (``default-route-distance``). RouterOS
  shares the load of one distance equally: a weight is refused.

Every change is undone by the scheduler entry of the firewall changes (``fwwrite``) unless it is
confirmed; the backup keeps ``distance`` and ``check-gateway`` of these routes and the netwatch
hosts (``backup_rows``), and a restore sets them back.
"""

from __future__ import annotations

from ipaddress import ip_address
from typing import TYPE_CHECKING, Any

from signalbox.adapters import AdapterError, Described, Label
from signalbox.adapters.mikrotik.fwwrite import Revert, ros_quote
from signalbox.adapters.mikrotik.multiwan import NETWATCH as NETWATCH
from signalbox.adapters.mikrotik.multiwan import default_routes
from signalbox.adapters.mikrotik.routes import IP_ROUTE as IP_ROUTE
from signalbox.changes import Change, GatewayGroupValue, GatewayMemberValue
from signalbox.model import IPAddress

if TYPE_CHECKING:  # pragma: no cover
    from signalbox.adapters.mikrotik.write import _Config

#: The name the reader gives the group of the default routes.
GROUP = "default"
#: Properties of a route and a netwatch entry the backup keeps.
ROUTE_PROPS = ("distance", "check-gateway")
NETWATCH_PROPS = ("host",)


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return value is True or _text(value).lower() in ("true", "yes", "on")


def _int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _addr(value: Any) -> IPAddress | None:
    try:
        return ip_address(_text(value))
    except ValueError:
        return None


def _ranks(values: list[int]) -> list[int]:
    order = sorted(set(values))
    return [order.index(v) + 1 for v in values]


def _watch(cfg: _Config, row: dict[str, Any]) -> dict[str, Any] | None:
    comment = _text(row.get("comment"))
    if not comment:
        return None
    return next((n for n in cfg.static(NETWATCH) if _text(n.get("comment")) == comment), None)


def _targets(row: dict[str, Any], watch: dict[str, Any] | None) -> set[IPAddress]:
    """The monitor addresses as the reader sees them."""
    hop = _addr(row.get("gateway"))
    out: set[IPAddress] = set()
    if _text(row.get("check-gateway")) == "ping" and hop is not None:
        out.add(hop)
    if watch is not None and (host := _addr(watch.get("host"))) is not None:
        out.add(host)
    return out


def _route(rows: list[dict[str, Any]], want: GatewayMemberValue) -> dict[str, Any]:
    found = [
        r for r in rows if want.gateway is not None and _addr(r.get("gateway")) == want.gateway
    ]
    if len(found) != 1:
        raise AdapterError(
            f"No single default route with the gateway {want.gateway} for the member {want.name}.",
            message_id="mikrotik.noGroupRoute",
            params={"member": want.name, "gateway": str(want.gateway)},
        )
    return found[0]


def gateway_group(cfg: _Config, c: Change, revert: Revert) -> None:
    """Give the default routes the tiers and monitors of ``c.new``."""
    name = c.key.partition("/")[2]
    if name != GROUP or not isinstance(c.new, GatewayGroupValue):
        raise AdapterError(
            f"RouterOS has one gateway group, {GROUP} (its default routes); not {name}.",
            message_id="mikrotik.onlyDefaultGroup",
            params={"group": name},
        )
    rows = default_routes(cfg.rows(IP_ROUTE))
    pairs = [(w, _route(rows, w)) for w in c.new.members]
    distances = [_int(r.get("distance")) or 1 for _, r in pairs]
    reorder = _ranks(distances) != [w.tier for w, _ in pairs]
    label = Label(f"gateway group {name}", "gatewayGroup", name)
    for want, row in pairs:
        if want.weight is not None:
            raise AdapterError(
                f"RouterOS shares the load of default routes with one distance equally; the "
                f"member {want.name} cannot have a weight.",
                message_id="mikrotik.noWeight",
                params={"member": want.name},
            )
        body: dict[str, str] = {}
        if reorder and (_int(row.get("distance")) or 1) != want.tier:
            body["distance"] = str(want.tier)
        hop = _addr(row.get("gateway"))
        watch = _watch(cfg, row)
        wanted = set(want.monitor)
        unset = False
        if wanted != _targets(row, watch):
            ping = _text(row.get("check-gateway")) == "ping"
            if hop in wanted and not ping:
                body["check-gateway"] = "ping"
            elif hop not in wanted and ping:
                unset = True
            others = wanted - {hop} if hop is not None else wanted
            host = _addr(watch.get("host")) if watch is not None else None
            now = {host} - {hop} if host is not None else set()
            if others != now:
                _netwatch(cfg, label, want, row, watch, others, revert)
        if (body or unset) and _flag(row.get("dynamic")):
            raise AdapterError(
                f"The default route of {want.name} is added by a DHCP or PPPoE client, and "
                "RouterOS does not let it be changed; change the client's settings "
                "(default-route-distance) instead.",
                message_id="mikrotik.dynamicRoute",
                params={"member": want.name},
            )
        ref = _text(row.get(".id"))
        if body:
            old = {k: _text(row.get(k)) for k in body}
            cfg.patch(
                IP_ROUTE,
                row,
                body,
                Described(
                    f"{label}: route of {want.name}: "
                    + " ".join(f"{k}={v}" for k, v in body.items()),
                    "plan.mikrotik.routeSet",
                    label=label,
                    member=want.name,
                    options=" ".join(f"{k}={v}" for k, v in body.items()),
                ),
            )
            back = {k: v for k, v in old.items() if v}
            lines = []
            if back:
                lines.append(
                    f"/ip route set {ref} "
                    + " ".join(f"{k}={ros_quote(v)}" for k, v in back.items())
                )
            lines += [f"/ip route unset {ref} {k}" for k, v in old.items() if not v]
            revert.add(*lines)
        if unset:
            cfg.unset(
                IP_ROUTE,
                row,
                "check-gateway",
                Described(
                    f"{label}: route of {want.name}: no gateway check",
                    "plan.mikrotik.routeNoCheck",
                    label=label,
                    member=want.name,
                ),
            )
            revert.add(f"/ip route set {ref} check-gateway=ping")


def _netwatch(
    cfg: _Config,
    label: str,
    want: GatewayMemberValue,
    row: dict[str, Any],
    watch: dict[str, Any] | None,
    others: set[IPAddress],
    revert: Revert,
) -> None:
    if watch is None or len(others) != 1:
        raise AdapterError(
            f"The monitor of {want.name} can hold its gateway and the host of the netwatch "
            "entry with the route's comment; Signalbox does not add or remove netwatch entries "
            "(their scripts are yours). Change the entry on the router, or declare one address "
            "besides the gateway.",
            message_id="mikrotik.netwatchNeeded",
            params={"member": want.name},
        )
    [host] = others
    old = _text(watch.get("host"))
    cfg.patch(
        NETWATCH,
        watch,
        {"host": str(host)},
        Described(
            f"{label}: netwatch of {want.name}: host {host}",
            "plan.mikrotik.netwatchHost",
            label=label,
            member=want.name,
            host=str(host),
        ),
    )
    revert.add(f"/tool netwatch set {_text(watch.get('.id'))} host={ros_quote(old)}")


def backup_rows(menus: dict[str, list[dict[str, Any]]]) -> dict[str, dict[str, dict[str, str]]]:
    """What the backup keeps of the default routes and netwatch entries, by ``.id``."""
    routes = {
        _text(r.get(".id")): {k: _text(r.get(k)) for k in ROUTE_PROPS}
        for r in default_routes(menus.get(IP_ROUTE) or [])
        if not _flag(r.get("dynamic")) and _text(r.get(".id"))
    }
    watch = {
        _text(n.get(".id")): {k: _text(n.get(k)) for k in NETWATCH_PROPS}
        for n in menus.get(NETWATCH) or []
        if not _flag(n.get("dynamic")) and _text(n.get(".id"))
    }
    return {IP_ROUTE: routes, NETWATCH: watch}


def restore_rows(cfg: _Config, saved: Any) -> None:
    """Set ``distance``, ``check-gateway`` and netwatch hosts back as the backup has them."""
    if not isinstance(saved, dict):
        return
    for menu in (IP_ROUTE, NETWATCH):
        by_id = {_text(r.get(".id")): r for r in cfg.static(menu)}
        for ref, values in (saved.get(menu) or {}).items():
            row = by_id.get(ref)
            if row is None or not isinstance(values, dict):
                continue
            item = _text(row.get("comment")) or _text(row.get("gateway")) or ref
            body = {k: str(v) for k, v in values.items() if v and _text(row.get(k)) != v}
            if body:
                cfg.patch(
                    menu,
                    row,
                    body,
                    Described(
                        f"restore: set {menu} {item} back",
                        "plan.mikrotik.restoreSet",
                        menu=menu,
                        item=item,
                    ),
                )
            for k, v in values.items():
                if not v and _text(row.get(k)):
                    cfg.unset(
                        menu,
                        row,
                        k,
                        Described(
                            f"restore: unset {k} of {item}",
                            "plan.mikrotik.restoreUnset",
                            prop=k,
                            item=item,
                        ),
                    )
