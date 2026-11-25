"""OpenWrt multi-WAN (mwan3, #150) and dynamic DNS (ddns-scripts, #154).

Both are optional packages: a router without them has no ``mwan3`` or ``ddns`` config, and that
reads as nothing to report.

- UCI ``mwan3``: ``interface`` sections (``enabled``, ``track_ip`` list, ``interval``), ``member``
  sections (``interface``, ``metric``, ``weight``) and ``policy`` sections (``use_member`` list).
  A policy is a gateway group: members of different metrics are tiers of a failover (metric 1 is
  the first choice), members of one metric share the load. Releases 2.x (OpenWrt 21.02 up to
  25.12) all use these options.
- ``ubus call mwan3 status``: the running state, per interface ``status`` (``online``,
  ``offline``, ``notracking``, ``disabled``) and ``track_ip`` entries with ``latency`` and
  ``packetloss``. The ``{"section": "interfaces"}`` argument is what ``mwan3 status`` sends.
  *Guess*: not yet checked on a device (#21); without it, groups come with the configured
  tiers and no state.
- UCI ``ddns`` (ddns-scripts): ``service`` sections with ``enabled``, ``service_name`` (the
  provider), ``lookup_host`` (the name), ``interface``/``ip_network`` and ``use_ipv6``. Account
  data (``username``, ``password``, ``update_url``) is never read. The last update comes from
  ``/var/run/ddns/<section>.update`` (epoch seconds) and the announced address from
  ``/var/run/ddns/<section>.ip`` through ``file read``; *guess*, both optional.
"""

from __future__ import annotations

from datetime import UTC, datetime
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

#: ``mwan3 status`` -> state; ``notracking`` and ``disabled`` say nothing about the line.
_STATES = {"online": UplinkState.ONLINE, "offline": UplinkState.DOWN}


def _sections(uci: dict[str, Any], kind: str) -> list[tuple[str, dict[str, Any]]]:
    values = uci.get("values")
    if not isinstance(values, dict):
        return []
    found = [
        (str(s.get(".name", n)), s)
        for n, s in values.items()
        if isinstance(s, dict) and s.get(".type") == kind
    ]
    return sorted(found, key=lambda i: int(str(i[1].get(".index", 0))))


def _list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)] if value not in (None, "") else []


def _int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _addr(value: Any) -> IPAddress | None:
    try:
        return ip_address(str(value).strip())
    except ValueError:
        return None


def _num(value: Any) -> float | None:
    try:
        return max(float(value), 0.0)
    except (TypeError, ValueError):
        return None


def _interfaces(status: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    data = (status or {}).get("interfaces")
    if not isinstance(data, dict):
        return {}
    return {str(k): v for k, v in data.items() if isinstance(v, dict)}


def _names(up: Uplink) -> list[str]:
    """The netifd interfaces of an uplink (``wan`` and ``wan6`` are one uplink)."""
    names = up.vendor_extra.get("interfaces")
    if isinstance(names, list) and names:
        return [str(n) for n in names]
    return [up.name] if up.name else []


def _state(entry: dict[str, Any] | None) -> UplinkState | None:
    return _STATES.get(str(entry.get("status", "")).lower()) if entry else None


def _worst(entry: dict[str, Any] | None) -> tuple[float | None, float | None]:
    """(latency in ms, loss in percent) over the ``track_ip`` entries that answer."""
    tracks = [t for t in (entry or {}).get("track_ip", []) if isinstance(t, dict)]
    latency = [x for t in tracks if (x := _num(t.get("latency"))) is not None]
    loss = [x for t in tracks if (x := _num(t.get("packetloss"))) is not None]
    return (max(latency) if latency else None, min(max(loss), 100.0) if loss else None)


def _targets(section: dict[str, Any]) -> list[IPAddress]:
    return [a for t in _list(section.get("track_ip")) if (a := _addr(t)) is not None]


def has_groups(uci: dict[str, Any]) -> bool:
    return bool(_sections(uci, "policy") or _sections(uci, "interface"))


def service_sections(uci: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return _sections(uci, "service")


def monitors(uci: dict[str, Any]) -> dict[str, Monitor]:
    """The tracking setup of every enabled mwan3 interface that tracks something."""
    out: dict[str, Monitor] = {}
    for name, s in _sections(uci, "interface"):
        targets = _targets(s)
        if targets and str(s.get("enabled", "1")) != "0":
            out[name] = Monitor(targets=targets, interval_seconds=_int(s.get("interval")))
    return out


def with_health(
    uplinks: list[Uplink], uci: dict[str, Any], status: dict[str, Any] | None
) -> list[Uplink]:
    """The uplinks with the monitor and health mwan3 has for their interfaces (``wan``/``wan6``)."""
    mon = monitors(uci)
    running = _interfaces(status)
    out: list[Uplink] = []
    for up in uplinks:
        names = _names(up)
        name = next((n for n in names if n in mon or n in running), None)
        if name is None:
            out.append(up)
            continue
        update: dict[str, Any] = {}
        if name in mon:
            update["monitor"] = mon[name]
        state = _state(running.get(name))
        if state is not None:
            latency, loss = _worst(running.get(name))
            update["health"] = UplinkHealth(state=state, latency_ms=latency, loss_pct=loss)
        out.append(up.model_copy(update=update))
    return out


def groups(
    device_id: str,
    uci: dict[str, Any],
    status: dict[str, Any] | None,
    uplinks: list[Uplink],
) -> list[GatewayGroup]:
    """One group per ``policy`` section with members."""
    members = dict(_sections(uci, "member"))
    mon = monitors(uci)
    running = _interfaces(status)
    uplink_of = {n: up.id for up in uplinks for n in _names(up)}
    out: list[GatewayGroup] = []
    for name, policy in _sections(uci, "policy"):
        entries = [members[m] for m in _list(policy.get("use_member")) if m in members]
        metrics = sorted({_int(e.get("metric")) or 1 for e in entries})
        built: list[GatewayGroupMember] = []
        for e in entries:
            iface = str(e.get("interface", ""))
            if not iface:
                continue
            entry = running.get(iface)
            latency, loss = _worst(entry)
            up = next((u for u in uplinks if u.id == uplink_of.get(iface)), None)
            built.append(
                GatewayGroupMember(
                    name=iface,
                    uplink_id=uplink_of.get(iface),
                    tier=metrics.index(_int(e.get("metric")) or 1) + 1,
                    weight=_int(e.get("weight")),
                    gateway=up.upstream_gateway if up else None,
                    monitor_targets=mon[iface].targets if iface in mon else [],
                    state=_state(entry),
                    latency_ms=latency,
                    loss_pct=loss,
                )
            )
        if not built:
            continue
        failover = len(metrics) > 1
        active = None
        if failover:
            online = [m for m in built if m.state is UplinkState.ONLINE]
            active = min(online, key=lambda m: m.tier).name if online else None
        out.append(
            GatewayGroup(
                id=object_id(device_id, "gateway-group", name),
                device_id=device_id,
                name=name,
                mode=GroupMode.FAILOVER if failover else GroupMode.BALANCE,
                members=built,
                active=active,
            )
        )
    return out


_PROVIDERS = (
    ("duckdns", "duckdns"),
    ("cloudflare", "cloudflare"),
    ("no-ip", "noip"),
    ("dyndns", "dyndns2"),
)


def provider(service_name: str) -> str:
    low = service_name.lower()
    return next((p for key, p in _PROVIDERS if key in low), "other")


def ddns_clients(
    device_id: str,
    uci: dict[str, Any],
    files: dict[str, str],
    uplinks: list[Uplink],
) -> list[DynamicDns]:
    """The ``service`` sections of ddns-scripts; ``files`` maps ``<section>.update`` and
    ``<section>.ip`` to the file contents."""
    uplink_of = {n: up.id for up in uplinks for n in _names(up)}
    out: list[DynamicDns] = []
    for name, s in _sections(uci, "service"):
        host = str(s.get("lookup_host") or s.get("domain") or "").strip()
        if not host:
            continue
        stamp = _int(files.get(f"{name}.update", "").strip())
        last = datetime.fromtimestamp(stamp, UTC) if stamp else None
        ipv6 = str(s.get("use_ipv6", "0")) == "1"
        iface = str(s.get("interface") or s.get("ip_network") or "")
        out.append(
            DynamicDns(
                id=object_id(device_id, "ddns", name),
                device_id=device_id,
                provider=provider(str(s.get("service_name", ""))),
                hostname=host,
                uplink_id=uplink_of.get(iface) or uplink_of.get(iface.removesuffix("6")),
                families=[6] if ipv6 else [4],
                enabled=str(s.get("enabled", "0")) == "1",
                last_update=last,
                last_result=DdnsResult.OK if last else DdnsResult.UNKNOWN,
                published_address=_addr(files.get(f"{name}.ip", "")),
            )
        )
    return out
