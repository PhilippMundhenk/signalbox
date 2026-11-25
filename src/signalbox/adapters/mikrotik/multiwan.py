"""MikroTik multi-WAN (#150) and MikroTik Cloud DDNS (#154).

- Default routes: two or more enabled ``0.0.0.0/0`` routes in the ``main`` table with a next hop
  are the members of one gateway group ``default``. Routes of different ``distance`` are the tiers
  of a failover (the lowest distance first), routes of one distance share the load (ECMP).
  ``check-gateway`` (``ping`` or ``arp``) makes RouterOS test the next hop itself: that is the
  monitor, and its target is the gateway of the route. A route's ``gateway-status`` says whether
  that test passes (``... reachable via ether1`` or ``... unreachable``), *guess* for the exact
  wording (#21). RouterOS 7 and 6.49 (REST only from 7.1; older ones are not read at all) use
  the same fields.
- ``/rest/tool/netwatch`` (``host``, ``status`` ``up``/``down``, ``interval``, ``comment``): a
  netwatch entry whose comment equals the comment of a route is that route's monitor, the
  convention scripts that switch routes use (*guess*, #21). Netwatch cannot be tied to a route
  otherwise.
- ``/rest/ip/cloud``: ``ddns-enabled``, ``dns-name`` (``<serial>.sn.mynetname.net``),
  ``public-address`` (the address announced) and ``status`` (``updated``, ``updating...``,
  ``error: ...``). The cloud account needs no credentials; none are read.
"""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any

from signalbox.model import (
    DdnsResult,
    DynamicDns,
    GatewayGroup,
    GatewayGroupMember,
    GroupMode,
    IPAddress,
    Monitor,
    Uplink,
    UplinkHealth,
    UplinkState,
    object_id,
)

NETWATCH = "/rest/tool/netwatch"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return value in (True, "true", "yes")


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


def _state(row: dict[str, Any]) -> UplinkState | None:
    status = _text(row.get("gateway-status")).lower()
    if "unreachable" in status:
        return UplinkState.DOWN
    if "reachable" in status:
        return UplinkState.ONLINE if _flag(row.get("active")) else UplinkState.STANDBY
    return None


def groups(
    device_id: str,
    routes: list[dict[str, Any]],
    uplinks: list[Uplink],
    netwatch: list[dict[str, Any]],
) -> list[GatewayGroup]:
    """The group of the default routes, or none when there is at most one."""
    defaults = [
        r
        for r in routes
        if _text(r.get("dst-address")) == "0.0.0.0/0"
        and _text(r.get("routing-table", "main")) in ("", "main")
        and not _flag(r.get("disabled"))
        and not _flag(r.get("blackhole"))
        and _addr(r.get("gateway")) is not None
    ]
    if len(defaults) < 2:
        return []
    distances = sorted({_int(r.get("distance")) or 1 for r in defaults})
    watch = {_text(n.get("comment")): n for n in netwatch if _text(n.get("comment"))}
    members: list[GatewayGroupMember] = []
    for r in defaults:
        hop = _addr(r.get("gateway"))
        up = next((u for u in uplinks if hop is not None and u.upstream_gateway == hop), None)
        comment = _text(r.get("comment"))
        targets: list[IPAddress] = []
        if _text(r.get("check-gateway")) == "ping" and hop is not None:
            targets.append(hop)
        state = _state(r)
        nw = watch.get(comment)
        if nw is not None:
            host = _addr(nw.get("host"))
            if host is not None and host not in targets:
                targets.append(host)
            seen = _text(nw.get("status")).lower()
            if seen in ("up", "down") and not _flag(nw.get("disabled")):
                state = UplinkState.DOWN if seen == "down" else state or UplinkState.ONLINE
        members.append(
            GatewayGroupMember(
                name=comment or (up.name if up and up.name else str(hop)),
                uplink_id=up.id if up else None,
                tier=distances.index(_int(r.get("distance")) or 1) + 1,
                gateway=hop,
                monitor_targets=targets,
                state=state,
            )
        )
    names = [m.name for m in members]
    members = [  # a name must be unique inside the group
        m if names.count(m.name) == 1 else m.model_copy(update={"name": f"{m.name} {i}"})
        for i, m in enumerate(members, start=1)
    ]
    failover = len(distances) > 1
    online = [m for m in members if m.state is UplinkState.ONLINE]
    active = min(online, key=lambda m: m.tier).name if failover and online else None
    return [
        GatewayGroup(
            id=object_id(device_id, "gateway-group", "default"),
            device_id=device_id,
            name="default",
            mode=GroupMode.FAILOVER if failover else GroupMode.BALANCE,
            members=members,
            active=active,
        )
    ]


def with_members(uplinks: list[Uplink], group: list[GatewayGroup]) -> list[Uplink]:
    """The uplinks of the group with the monitor and state RouterOS has for their route."""
    by_id = {m.uplink_id: m for g in group for m in g.members if m.uplink_id}
    out: list[Uplink] = []
    for up in uplinks:
        m = by_id.get(up.id)
        if m is None:
            out.append(up)
            continue
        update: dict[str, Any] = {}
        if m.monitor_targets:
            update["monitor"] = Monitor(targets=m.monitor_targets)
        if m.state is not None:
            update["health"] = UplinkHealth(state=m.state)
        out.append(up.model_copy(update=update))
    return out


def cloud_ddns(device_id: str, cloud: dict[str, Any], uplink: Uplink | None) -> list[DynamicDns]:
    """The MikroTik Cloud name of the router (IP > Cloud), if it has one."""
    name = _text(cloud.get("dns-name"))
    if not name:
        return []
    status = _text(cloud.get("status")).lower()
    result = DdnsResult.UNKNOWN
    if status.startswith("error"):
        result = DdnsResult.ERROR
    elif status == "updated":
        result = DdnsResult.OK
    enabled = _text(cloud.get("ddns-enabled")).lower() not in ("no", "false", "disabled")
    published = _addr(cloud.get("public-address"))
    return [
        DynamicDns(
            id=object_id(device_id, "ddns", "cloud"),
            device_id=device_id,
            provider="mikrotik-cloud",
            hostname=name,
            uplink_id=uplink.id if uplink else None,
            families=[4],
            enabled=enabled,
            last_result=result,
            published_address=published,
        )
    ]
