"""Omada multi-WAN (#150): the WAN mode of the gateway (load balancing or link backup) and the
ports in it.

The per-port health (``latency`` in ms, ``loss`` in percent) comes with ``wan-status`` and is read
in :func:`signalbox.adapters.omada.wan_uplink`. The mode is a site setting of the controller
(Internet, Load Balancing); its Open API path and fields are a *guess* (#21):
``…/internet/load-balance`` answers
``{"mode": 0 | 1, "ports": [{"port": 1, "weight": 1, "backup": false}]}``, mode 0 being load
balancing and 1 link backup. A controller that does not know the path leaves the group out (an
optional gap where the gateway has two or more WAN ports).
"""

from __future__ import annotations

from typing import Any

from signalbox.model import (
    GatewayGroup,
    GatewayGroupMember,
    GroupMode,
    Uplink,
    UplinkState,
    object_id,
)

#: Under the site path: the WAN mode setting (*guess*).
SETTING = "internet/load-balance"


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _state(up: Uplink) -> UplinkState | None:
    if up.health is not None:
        return up.health.state
    return None if up.up is None else UplinkState.ONLINE if up.up else UplinkState.DOWN


def wan_group(
    device_id: str, setting: dict[str, Any], uplinks: list[Uplink]
) -> GatewayGroup | None:
    """The gateway's WAN group from the mode setting, over the uplinks the controller reports
    (None with fewer than two ports in the setting that are uplinks)."""
    by_port = {_int(u.vendor_extra.get("port")): u for u in uplinks}
    rows = [r for r in setting.get("ports", []) if isinstance(r, dict)]
    backup_mode = _int(setting.get("mode")) == 1
    members: list[GatewayGroupMember] = []
    for row in rows:
        up = by_port.get(_int(row.get("port")))
        if up is None:
            continue
        backup = backup_mode and row.get("backup") is True
        members.append(
            GatewayGroupMember(
                name=up.name or up.id.rsplit("/", 1)[-1],
                uplink_id=up.id,
                tier=2 if backup else 1,
                weight=None if backup_mode else _int(row.get("weight")),
                gateway=up.upstream_gateway,
                state=_state(up),
                latency_ms=up.health.latency_ms if up.health else None,
                loss_pct=up.health.loss_pct if up.health else None,
            )
        )
    if len(members) < 2:
        return None
    names = [m.name for m in members]
    members = [
        m if names.count(m.name) == 1 else m.model_copy(update={"name": f"{m.name} {i}"})
        for i, m in enumerate(members, start=1)
    ]
    active = None
    if backup_mode:
        online = [m for m in members if m.state is UplinkState.ONLINE]
        active = min(online, key=lambda m: m.tier).name if online else None
    return GatewayGroup(
        id=object_id(device_id, "gateway-group", "wan"),
        device_id=device_id,
        name="wan",
        mode=GroupMode.FAILOVER if backup_mode else GroupMode.BALANCE,
        members=members,
        active=active,
    )
