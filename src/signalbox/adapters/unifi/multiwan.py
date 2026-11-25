"""UniFi WAN failover and load balancing (#150) and dynamic DNS (#154).

- ``rest/networkconf`` rows with ``purpose`` ``wan``: ``wan_failover_priority`` (1 is the first
  choice, higher numbers are backups), ``wan_load_balance_type`` (``failover-only`` or
  ``weighted``) and ``wan_load_balance_weight``. *Guess* for the exact spelling on controller
  versions before 7 (#21): a row without them gives no priority and no group.
- The gateway's ``wan1``/``wan2`` entries: ``up``, ``latency`` (ms, where the gateway has
  measured it) and ``is_uplink`` (the connection that carries the traffic now), *guess*.
  UniFi pings its own targets for the failover check and has no setting the model could read as
  a monitor, so no monitor target is reported.
- ``rest/dynamicdns``: ``host_name``, ``service`` (``dyndns``, ``noip``, ``duckdns``, ``custom``,
  ...), ``interface`` (``wan`` or ``wan2``), ``server``. ``login`` and ``x_password`` are never
  read. The controller has no last-update state in this list, so the result is unknown.
"""

from __future__ import annotations

from typing import Any, Literal

from signalbox.model import (
    DdnsResult,
    DynamicDns,
    GatewayGroup,
    GatewayGroupMember,
    GroupMode,
    Uplink,
    UplinkHealth,
    UplinkState,
    object_id,
)


def _int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _num(value: Any) -> float | None:
    try:
        return max(float(value), 0.0)
    except (TypeError, ValueError):
        return None


def priority_weight(conf: dict[str, Any]) -> tuple[int | None, int | None]:
    prio, weight = (
        _int(conf.get("wan_failover_priority")),
        _int(conf.get("wan_load_balance_weight")),
    )
    return (
        prio if prio is not None and prio >= 0 else None,
        weight if weight and weight >= 0 else None,
    )


def health(info: dict[str, Any], up: bool | None) -> UplinkHealth | None:
    if up is None:
        return None
    return UplinkHealth(
        state=UplinkState.ONLINE if up else UplinkState.DOWN, latency_ms=_num(info.get("latency"))
    )


def group(
    device_id: str,
    uplinks: list[Uplink],
    confs: dict[str, dict[str, Any]],
    infos: dict[str, dict[str, Any]],
) -> list[GatewayGroup]:
    """One group of the WAN connections of the gateway when there are two or more.

    ``confs`` and ``infos`` are keyed like the uplink ids end (``wan1``, ``wan2``)."""
    if len(uplinks) < 2:
        return []
    kinds = {_text(c.get("wan_load_balance_type")) for c in confs.values()}
    balance = "weighted" in kinds
    priorities = sorted({u.priority for u in uplinks if u.priority is not None})
    members: list[GatewayGroupMember] = []
    for up in uplinks:
        members.append(
            GatewayGroupMember(
                name=up.name or up.id.rsplit("/", 1)[-1],
                uplink_id=up.id,
                tier=priorities.index(up.priority) + 1 if up.priority in priorities else 1,
                weight=up.weight if balance else None,
                gateway=up.upstream_gateway,
                state=up.health.state if up.health else None,
                latency_ms=up.health.latency_ms if up.health else None,
            )
        )
    names = [m.name for m in members]
    if len(set(names)) != len(names):  # two connections named alike
        members = [m.model_copy(update={"name": f"{m.name} {i}"}) for i, m in enumerate(members, 1)]
    active = next(
        (
            m.name
            for m, u in zip(members, uplinks, strict=True)
            if infos.get(u.id.rsplit("/", 1)[-1], {}).get("is_uplink") is True
        ),
        None,
    )
    return [
        GatewayGroup(
            id=object_id(device_id, "gateway-group", "wan"),
            device_id=device_id,
            name="WAN",
            mode=GroupMode.BALANCE if balance else GroupMode.FAILOVER,
            members=members,
            active=None if balance else active,
        )
    ]


def _text(value: Any) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


_SERVICES = (
    ("duckdns", "duckdns"),
    ("cloudflare", "cloudflare"),
    ("noip", "noip"),
    ("no-ip", "noip"),
    ("dyndns", "dyndns2"),
)


def ddns_clients(device_id: str, rows: list[dict[str, Any]]) -> list[DynamicDns]:
    out: list[DynamicDns] = []
    for n, row in enumerate(rows):
        host = row.get("host_name")
        if not isinstance(host, str) or not host.strip():
            continue
        service = _text(row.get("service"))
        interface = _text(row.get("interface")) or "wan"
        key = "wan1" if interface in ("wan", "wan1") else interface
        families: list[Literal[4, 6]] = [6] if _text(row.get("ip_version")) == "ipv6" else [4]
        out.append(
            DynamicDns(
                id=object_id(device_id, "ddns", str(row.get("_id") or n)),
                device_id=device_id,
                provider=next((p for k, p in _SERVICES if k in service), "other"),
                hostname=host.strip(),
                uplink_id=f"{device_id}/uplink/{key}",
                families=families,
                enabled=row.get("enabled", True) is not False,
                last_result=DdnsResult.UNKNOWN,
            )
        )
    return out
