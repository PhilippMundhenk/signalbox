"""FRITZ!Box routes (#149) from TR-064 ``Layer3Forwarding:1``.

- ``GetForwardNumberOfEntries`` and ``GetGenericForwardingEntry``: the static IPv4 routes
  (``NewDestIPAddress``, ``NewDestSubnetMask``, ``NewGatewayIPAddress``, ``NewEnable``,
  ``NewForwardingMetric``; a host route has ``NewType`` ``Host``). Source-specific entries
  (``NewSourceIPAddress`` other than ``0.0.0.0``) are policy routes the model cannot hold: left out.
- ``GetDefaultConnectionService``: names the WAN connection the default route uses; the default
  route itself is derived from the uplink (its upstream gateway), only while that service is set.

Not readable: IPv6 routes, the full kernel table and policy routing: TR-064 has no action for
them. A FRITZ!OS without ``Layer3Forwarding`` reports no routes.
"""

from __future__ import annotations

from ipaddress import IPv4Address, ip_address, ip_network
from typing import Any

from signalbox.model import IPNetwork, Route, RouteOrigin, Uplink, route_id

#: Entries read at most (a box has a handful).
ENTRY_LIMIT = 256


def _flag(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes")


def _address(value: Any) -> IPv4Address | None:
    try:
        parsed = ip_address(str(value).strip())
    except ValueError:
        return None
    return parsed if isinstance(parsed, IPv4Address) else None


def static_route(device_id: str, entry: dict[str, str]) -> Route | None:
    dest = _address(entry.get("NewDestIPAddress"))
    source = _address(entry.get("NewSourceIPAddress"))
    if dest is None or (source is not None and int(source) != 0):
        return None
    mask = _address(entry.get("NewDestSubnetMask"))
    network: IPNetwork
    try:
        if entry.get("NewType", "").strip().lower() == "host" or mask is None:
            network = ip_network(f"{dest}/32")
        else:
            network = ip_network(f"{dest}/{mask}", strict=False)
    except ValueError:
        return None
    gateway = _address(entry.get("NewGatewayIPAddress"))
    if gateway is not None and int(gateway) == 0:
        gateway = None
    try:
        metric = int(entry.get("NewForwardingMetric", ""))
    except ValueError:
        metric = None
    enabled = _flag(entry.get("NewEnable"))
    return Route(
        id=route_id(device_id, "main", network, gateway, None),
        device_id=device_id,
        destination=network,
        gateway=gateway,
        metric=metric if metric is not None and metric >= 0 else None,
        origin=RouteOrigin.STATIC,
        enabled=enabled,
    )


def default_route(device_id: str, uplink: Uplink | None, service: str) -> Route | None:
    """The default route through the WAN connection (``GetDefaultConnectionService`` set)."""
    if uplink is None or not service.strip() or uplink.up is False:
        return None
    gateway = uplink.upstream_gateway
    network = ip_network("::/0" if gateway is not None and gateway.version == 6 else "0.0.0.0/0")
    return Route(
        id=route_id(device_id, "main", network, gateway, None),
        device_id=device_id,
        destination=network,
        gateway=gateway,
        origin=RouteOrigin.DHCP if uplink.kind.value == "dhcp" else RouteOrigin.OTHER,
        active=True,
    )
