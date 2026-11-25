"""Multicast of RouterOS bridges and the services that reflect it (#161, ADR 0028).

``/interface/bridge`` has ``igmp-snooping``, ``multicast-querier``, ``igmp-version`` and
``mld-version``; the bridge ports ``fast-leave`` and ``unknown-multicast-flood``. The IGMP proxy
(``/routing/igmp-proxy/interface``, RouterOS 7; ``/routing/igmp-proxy`` is the settings menu)
lists the interfaces with ``upstream``. The mDNS repeater is ``mdns-repeat-ifaces`` of
``/ip/dns`` (RouterOS 7.16 and later; absent before, then there is no repeater).
"""

from __future__ import annotations

from typing import Any

from signalbox.model import (
    MulticastSettings,
    ReflectorKind,
    ServiceReflector,
    UnknownMulticast,
)

IGMP_PROXY_INTERFACE = "/rest/routing/igmp-proxy/interface"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = _text(value).lower()
    if text in ("true", "yes", "on"):
        return True
    if text in ("false", "no", "off"):
        return False
    return None


def _version(value: Any, top: int) -> int | None:
    try:
        number = int(_text(value))
    except ValueError:
        return None
    return number if 1 <= number <= top else None


def _all(rows: list[dict[str, Any]], key: str) -> bool | None:
    """True when every bridge port that reports ``key`` has it on, False when every one has
    it off, None when they differ or none reports it."""
    values = {v for r in rows if (v := _bool(r.get(key))) is not None}
    return values.pop() if len(values) == 1 else None


def settings(
    row: dict[str, Any], ports: list[dict[str, Any]], segment_id: str | None
) -> MulticastSettings:
    """One bridge row with the rows of its ports. ``igmp-version`` is the version of the
    querier, so it counts only where the bridge is one."""
    querier = _bool(row.get("multicast-querier"))
    snooping = _bool(row.get("igmp-snooping"))
    flood = _all(ports, "unknown-multicast-flood")
    return MulticastSettings(
        name=_text(row.get("name")),
        segment_id=segment_id,
        igmp_snooping=snooping,
        # RouterOS snoops MLD together with IGMP; ``mld-version`` is only the querier's
        mld_snooping=snooping,
        querier=querier,
        querier_version=_version(row.get("igmp-version"), 3) if querier else None,
        fast_leave=_all(ports, "fast-leave"),
        unknown_multicast=None
        if flood is None
        else (UnknownMulticast.FLOOD if flood else UnknownMulticast.DROP),
    )


def _names(value: Any) -> list[str]:
    return [n.strip() for n in _text(value).split(",") if n.strip()]


def mdns_repeater(dns: dict[str, Any], segment_of: dict[str, str]) -> ServiceReflector | None:
    """The repeater of ``/ip/dns``; None where the field does not exist (before 7.16)."""
    if "mdns-repeat-ifaces" not in dns:
        return None
    names = _names(dns.get("mdns-repeat-ifaces"))
    return ServiceReflector(
        kind=ReflectorKind.MDNS,
        enabled=bool(names),
        interfaces=names,
        segments=sorted({segment_of[n] for n in names if n in segment_of}),
    )


def igmp_proxy(rows: list[dict[str, Any]], segment_of: dict[str, str]) -> ServiceReflector | None:
    """The IGMP proxy from its interface rows (disabled rows left out); None without any."""
    live = [r for r in rows if _bool(r.get("disabled")) is not True and _text(r.get("interface"))]
    if not live:
        return None
    names = [_text(r.get("interface")) for r in live]
    upstream = next((_text(r.get("interface")) for r in live if _bool(r.get("upstream"))), None)
    return ServiceReflector(
        kind=ReflectorKind.IGMP_PROXY,
        interfaces=names,
        segments=sorted({segment_of[n] for n in names if n in segment_of}),
        upstream_interface=upstream,
        upstream_segment_id=segment_of.get(upstream) if upstream else None,
    )
