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
    IPAddress,
    Route,
    RouteOrigin,
    Uplink,
    UplinkKind,
    route_id,
)

ROUTES_SEARCH = "/api/routes/routes/searchroute"
GATEWAY_STATUS = "/api/routes/gateway/status"
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
