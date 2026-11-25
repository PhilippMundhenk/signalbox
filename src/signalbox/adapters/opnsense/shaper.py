"""OPNsense traffic shaper (#166): *Firewall: Traffic Shaper* pipes, queues and rules.

- ``/api/trafficshaper/settings/search_pipes`` (``searchPipes`` before 24.7, see :mod:`compat`):
  ``uuid``, ``number``, ``enabled``, ``bandwidth`` with ``bandwidthMetric`` (``bit``, ``Kbit``,
  ``Mbit``, ``Gbit``), ``scheduler`` (empty: weighted fair queueing; ``fifo``, ``qfq``, ``rr``,
  ``prio``, ``fq_codel``, ``fq_pie``; the grid may show the label, ``FlowQueue-CoDel``) and
  ``description``.
- ``search_queues``: ``uuid``, ``pipe`` (the pipe's uuid or label), ``weight``; a queue only
  shares a pipe, so it is read only to find the pipe a rule points at.
- ``search_rules``: ``uuid``, ``enabled``, ``interface`` (identifier such as ``wan``),
  ``direction`` (``in``, ``out``, empty: both), ``target`` (a pipe or a queue, uuid or label),
  ``dscp`` (match on DSCP values) and ``description``.

A pipe becomes one shaper. The rules that point at it (directly or through a queue) tell the
interface and the direction. On the WAN interface ``out`` is the upload and ``in`` the download;
on any other interface it is the other way round (traffic that enters the firewall from the LAN
leaves towards the internet). A pipe no rule uses limits nothing and is reported disabled.
Covered: 24.7, 25.1, 25.7 and 26.1 (the model has kept these fields since 18.7, the API since
19.1, *guess*; the shape of the rule rows is a *guess* until seen on a device, #21).

The privilege is *Firewall: Traffic Shaper* (``page-firewall-trafficshaper``, *guess*); a 403 is an
optional gap naming it. The setup does not grant it yet.
"""

from __future__ import annotations

from typing import Any

from signalbox.adapters.shaping import kbps, kind_of
from signalbox.model import Shaper, ShaperKind, Uplink, object_id

PIPES = "/api/trafficshaper/settings/search_pipes"
QUEUES = "/api/trafficshaper/settings/search_queues"
RULES = "/api/trafficshaper/settings/search_rules"
PRIVILEGE = "Firewall: Traffic Shaper (page-firewall-trafficshaper)"


def _text(value: Any) -> str:
    if isinstance(value, dict):  # an option list: {"key": {"value": ..., "selected": 1}}
        return ",".join(
            str(k) for k, o in value.items() if isinstance(o, dict) and o.get("selected")
        )
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return _text(value).lower() in ("1", "true", "yes", "on")


def _refs(row: dict[str, Any], *keys: str) -> set[str]:
    return {t for k in keys if (t := _text(row.get(k)))}


def shapers(
    device_id: str,
    pipes: list[dict[str, Any]],
    queues: list[dict[str, Any]],
    rules: list[dict[str, Any]],
    uplinks: list[Uplink],
    wan_identifier: str = "wan",
) -> list[Shaper]:
    """One shaper per pipe. ``uplinks``: the firewall's uplinks (the WAN interface is the one
    ``wan_identifier`` names)."""
    # what a rule may call a pipe: its uuid, its number, its description
    names: dict[str, int] = {}
    for n, p in enumerate(pipes):
        for ref in _refs(p, "uuid", "number", "description"):
            names.setdefault(ref, n)
    for q in queues:
        pipe = next((names[r] for r in _refs(q, "pipe") if r in names), None)
        if pipe is not None:
            for ref in _refs(q, "uuid", "description"):
                names.setdefault(ref, pipe)
    wan = uplinks[0] if len(uplinks) == 1 else None
    out: list[Shaper] = []
    for n, p in enumerate(pipes):
        used = [
            r
            for r in rules
            if _flag(r.get("enabled", "1")) and any(names.get(t) == n for t in _refs(r, "target"))
        ]
        down = up = False
        interfaces: list[str] = []
        dscp = False
        for r in used:
            iface = _text(r.get("interface"))
            if iface and iface not in interfaces:
                interfaces.append(iface)
            dscp = dscp or bool(_text(r.get("dscp")))
            direction = _text(r.get("direction")).lower()
            wan_side = iface == wan_identifier
            download = (direction == "in") == wan_side if direction in ("in", "out") else None
            if download is None:
                down = up = True
            elif download:
                down = True
            else:
                up = True
        rate = kbps(p.get("bandwidth"), _text(p.get("bandwidthMetric")))
        on_wan = wan_identifier in interfaces
        out.append(
            Shaper(
                id=object_id(device_id, "shaper", _text(p.get("number")) or _text(p.get("uuid"))),
                device_id=device_id,
                name=_text(p.get("description")) or f"pipe {_text(p.get('number')) or n + 1}",
                kind=(
                    ShaperKind.SIMPLE_QUEUE
                    if not _text(p.get("scheduler"))
                    else kind_of(_text(p.get("scheduler")))
                ),
                interface=interfaces[0] if interfaces else None,
                uplink_id=wan.id if wan is not None and on_wan else None,
                download_kbps=rate if down else None,
                upload_kbps=rate if up else None,
                enabled=_flag(p.get("enabled")) and bool(used),
                dscp=dscp or None,
            )
        )
    return out
