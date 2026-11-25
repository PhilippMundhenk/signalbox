"""OPNsense routes (#149): static routes, gateway status and the default route.

- ``/api/routes/routes/searchroute``: the static routes (``network``, ``gateway`` by name,
  ``disabled``, ``descr``). Privilege ``page-system-staticroutes`` (*guess*, #21).
- ``/api/routes/gateway/status``: the gateways with their address and monitoring status; it
  resolves a route's gateway name to an address and tells a gateway that is down (then the
  route is configured but not usable: ``active`` False). Privilege ``page-system-gateways``
  (*guess*, #21).
- The default route comes from the WAN interface's gateway (the uplink), not from a routing
  table read: OPNsense keeps the table in the kernel (``getRoutes`` is not used).

Policy routing on OPNsense is a firewall rule with a gateway; it is not read here (the filter
rules of #135 do not carry the gateway yet), reported as an optional gap.
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Any

from signalbox.model import (
    GatewayGroup,
    GatewayGroupMember,
    GroupMode,
    IPAddress,
    Monitor,
    Route,
    RouteOrigin,
    Uplink,
    UplinkHealth,
    UplinkKind,
    UplinkState,
    object_id,
    route_id,
)

ROUTES_SEARCH = "/api/routes/routes/searchroute"
GATEWAY_STATUS = "/api/routes/gateway/status"
#: Gateway groups (#150): an API of its own since the groups became an MVC model (26.7);
#: before, they live in config.xml only and no API lists them.
GROUPS_SEARCH = "/api/routing/group_settings/search"
GROUPS_PRIVILEGE = "System: Gateway Groups (page-system-gatewaygroups)"
ROUTES_PRIVILEGE = "System: Static Routes (page-system-staticroutes)"
GATEWAY_PRIVILEGE = "System: Gateways (page-system-gateways)"

#: Gateway status words that mean the gateway does not answer.
_DOWN = ("down", "loss", "delay")


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _address(value: Any) -> IPAddress | None:
    try:
        return ip_address(_text(value))
    except ValueError:
        return None


def gateways(items: list[dict[str, Any]]) -> dict[str, tuple[IPAddress | None, bool | None]]:
    """Gateway name -> (address, usable). ``usable`` is None when the status says nothing."""
    out: dict[str, tuple[IPAddress | None, bool | None]] = {}
    for row in items:
        name = _text(row.get("name"))
        if not name:
            continue
        status = _text(row.get("status")).lower()
        usable: bool | None = None
        if any(word in status for word in _DOWN):
            usable = False
        elif status in ("online", "none", "up"):
            usable = True
        out[name] = (_address(row.get("address")), usable)
    return out


def _number(value: Any) -> float | None:
    """``"4.2 ms"`` and ``"0.0 %"`` -> the number; ``"~"`` and anything else -> None."""
    text = _text(value).split(" ")[0] if _text(value) else ""
    try:
        return max(float(text), 0.0)
    except ValueError:
        return None


def with_health(uplink: Uplink, rows: list[dict[str, Any]]) -> Uplink:
    """The uplink with the monitor and health of the gateway status row that has the uplink's
    next hop as its address (#150): ``status`` (``none`` = nothing wrong, ``loss``, ``delay``,
    ``down``, ``force_down``), ``delay`` and ``loss`` as ``"4.2 ms"`` and ``"0.0 %"``,
    ``monitor`` the address pinged (*guess*: the fields of the status answer of 24.7 to 26.1, #21).
    A status the answer does not name leaves the uplink as it is."""
    row = next(
        (
            r
            for r in rows
            if uplink.upstream_gateway is not None
            and _address(r.get("address")) == uplink.upstream_gateway
        ),
        None,
    )
    if row is None:
        return uplink
    status = _text(row.get("status")).lower()
    state: UplinkState | None = None
    if "down" in status:
        state = UplinkState.DOWN
    elif status in ("loss", "delay") or "loss" in status or "delay" in status:
        state = UplinkState.DEGRADED
    elif status in ("none", "online", "up"):
        state = UplinkState.ONLINE
    update: dict[str, Any] = {}
    target = _address(row.get("monitor"))
    if target is not None:
        update["monitor"] = Monitor(targets=[target])
    if state is not None:
        update["health"] = UplinkHealth(
            state=state,
            latency_ms=_number(row.get("delay")),
            loss_pct=min(_number(row.get("loss")) or 0.0, 100.0)
            if _number(row.get("loss")) is not None
            else None,
        )
    return uplink.model_copy(update=update)


def static_routes(
    device_id: str,
    rows: list[dict[str, Any]],
    known: dict[str, tuple[IPAddress | None, bool | None]],
) -> list[Route]:
    out: dict[str, Route] = {}
    for row in rows:
        try:
            dest = ip_network(_text(row.get("network")), strict=False)
        except ValueError:
            continue
        name = _text(row.get("gateway"))
        address, usable = known.get(name, (None, None))
        if address is not None and address.version != dest.version:
            address = None
        enabled = not _flag(row.get("disabled"))
        route = Route(
            id=route_id(device_id, "main", dest, address, None),
            device_id=device_id,
            destination=dest,
            gateway=address,
            origin=RouteOrigin.STATIC,
            enabled=enabled,
            active=usable if enabled else None,
            vendor_extra={k: v for k in ("descr",) if (v := _text(row.get(k)))}
            | ({"gateway": name} if name else {}),
        )
        out[route.id] = route
    return sorted(out.values(), key=lambda r: r.id)


def default_route(device_id: str, uplink: Uplink | None) -> Route | None:
    """The default route through the WAN gateway the interface overview reports."""
    if uplink is None or uplink.upstream_gateway is None or uplink.up is False:
        return None
    gateway = uplink.upstream_gateway
    dest = ip_network("0.0.0.0/0" if gateway.version == 4 else "::/0")
    origin = RouteOrigin.STATIC if uplink.kind is UplinkKind.STATIC else RouteOrigin.DHCP
    interface = uplink.port_id
    return Route(
        id=route_id(device_id, "main", dest, gateway, interface),
        device_id=device_id,
        destination=dest,
        gateway=gateway,
        interface=interface,
        origin=origin,
        active=True,
    )


def _member_state(row: dict[str, Any]) -> UplinkState | None:
    if "status" not in row and "address" not in row:
        return UplinkState.DOWN  # "Disabled or inactive": the API's stand-in row has no status
    status = _text(row.get("status")).lower()
    if "down" in status:
        return UplinkState.DOWN
    if "loss" in status or "delay" in status:
        return UplinkState.DEGRADED
    if status in ("none", "online", "up"):
        return UplinkState.ONLINE
    return None


def _tiers(raw: Any) -> list[list[dict[str, Any]]]:
    """The tiers of a group row: ``gateways`` maps a tier index to the status rows of its
    gateways (a JSON object or a list); empty tiers are dropped, the order of the keys ranks."""
    if isinstance(raw, dict):
        ordered = [v for _, v in sorted(raw.items(), key=lambda kv: str(kv[0]))]
    elif isinstance(raw, list):
        ordered = raw
    else:
        return []
    out: list[list[dict[str, Any]]] = []
    for tier in ordered:
        rows = [r for r in tier if isinstance(r, dict)] if isinstance(tier, list) else []
        if rows:
            out.append(rows)
    return out


def gateway_groups(
    device_id: str, rows: list[dict[str, Any]], uplinks: list[Uplink]
) -> list[GatewayGroup]:
    """The gateway groups of ``/api/routing/group_settings/search`` (26.7; *guess*: the row
    fields ``name`` and ``gateways`` as the controller builds them, #21).

    Each row has the group's ``name`` and ``gateways``: the tiers (the first is the first
    choice) with the status row of every gateway in them (``name``, ``address``, ``status``,
    ``delay``, ``loss``, ``monitor``). Two or more gateways in the first tier share the load
    (balance); otherwise the lowest tier with a gateway that is not down carries the traffic.
    A gateway without a status row is disabled or inactive and counts as down.
    """
    out: list[GatewayGroup] = []
    for row in rows:
        name = _text(row.get("name"))
        tiers = _tiers(row.get("gateways"))
        if not name or not tiers:
            continue
        members: list[GatewayGroupMember] = []
        for tier, gateways in enumerate(tiers, start=1):
            for gw in gateways:
                gw_name = _text(gw.get("name"))
                if not gw_name:
                    continue
                address = _address(gw.get("address"))
                monitor = _address(gw.get("monitor"))
                up = next(
                    (u for u in uplinks if address is not None and u.upstream_gateway == address),
                    None,
                )
                latency, loss = _number(gw.get("delay")), _number(gw.get("loss"))
                members.append(
                    GatewayGroupMember(
                        name=gw_name,
                        uplink_id=up.id if up else None,
                        tier=tier,
                        gateway=address,
                        monitor_targets=[monitor] if monitor is not None else [],
                        state=_member_state(gw),
                        latency_ms=latency,
                        loss_pct=min(loss, 100.0) if loss is not None else None,
                    )
                )
        if not members:
            continue
        balance = sum(1 for m in members if m.tier == 1) > 1
        active = None
        if not balance:
            alive = [m for m in members if m.state in (UplinkState.ONLINE, UplinkState.DEGRADED)]
            if alive:
                active = min(alive, key=lambda m: m.tier).name
        out.append(
            GatewayGroup(
                id=object_id(device_id, "gateway-group", name),
                device_id=device_id,
                name=name,
                mode=GroupMode.BALANCE if balance else GroupMode.FAILOVER,
                members=members,
                active=active,
            )
        )
    return sorted(out, key=lambda g: g.id)
