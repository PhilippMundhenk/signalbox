"""OPNsense multicast reflection (#161, ADR 0028): the plugins ``os-mdns-repeater`` and
``os-udpbroadcastrelay``.

* mDNS repeater: ``/api/mdnsrepeater/settings/get`` answers ``{"mdnsrepeater": {"enabled": "1",
  "interfaces": {"lan": {"value": "LAN", "selected": 1}, ...}}}`` (interface identifiers).
* UDP broadcast relay: ``/api/udpbroadcastrelay/settings/search_relay`` lists the relays with
  ``enabled``, ``listenport`` (the UDP port, 5353 is mDNS, 1900 SSDP), ``interfaces``
  (identifiers, comma separated) and the source address. One reflector per kind: the relays of
  a kind are merged.

Both plugins are optional (404: nothing to report); the privileges are a *guess* for their
names and the row fields (#21), a 403 is an optional gap. The IGMP proxy is a legacy page of
the firewall without an API and is not read. Only settings are read, never what is relayed.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from signalbox.model import ReflectorKind, ServiceReflector

MDNS_SETTINGS = "/api/mdnsrepeater/settings/get"
RELAYS = "/api/udpbroadcastrelay/settings/search_relay"
MDNS_PRIVILEGE = "Services: mDNS Repeater (page-services-mdnsrepeater)"
RELAY_PRIVILEGE = "Services: UDP Broadcast Relay (page-services-udpbroadcastrelay)"

_PORT_KINDS = {5353: ReflectorKind.MDNS, 1900: ReflectorKind.SSDP}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _on(value: Any) -> bool:
    return value is True or value == 1 or _text(value) in ("1", "true", "yes")


def _identifiers(value: Any) -> list[str]:
    """Selected keys of an option list, or the identifiers of a comma separated text."""
    if isinstance(value, dict):
        return [k for k, v in value.items() if isinstance(v, dict) and _on(v.get("selected"))]
    return [n for n in re.split(r"[,\s]+", _text(value)) if n]


def _reflector(
    kind: ReflectorKind, enabled: bool, names: list[str], segment_of: Mapping[str, str]
) -> ServiceReflector:
    return ServiceReflector(
        kind=kind,
        enabled=enabled,
        interfaces=names,
        segments=sorted({segment_of[n] for n in names if n in segment_of}),
    )


def mdns_repeater(data: Any, segment_of: Mapping[str, str]) -> ServiceReflector | None:
    """The repeater from the settings answer; None when the answer has no such section."""
    root = data.get("mdnsrepeater") if isinstance(data, dict) else None
    if not isinstance(root, dict):
        return None
    return _reflector(
        ReflectorKind.MDNS,
        _on(root.get("enabled")),
        _identifiers(root.get("interfaces")),
        segment_of,
    )


def relays(rows: list[dict[str, Any]], segment_of: Mapping[str, str]) -> list[ServiceReflector]:
    """The relays, merged per kind (by their UDP port). Disabled relays count as disabled
    reflectors only when no enabled one of the kind exists."""
    by_kind: dict[ReflectorKind, tuple[bool, list[str]]] = {}
    for row in rows:
        try:
            port = int(_text(row.get("listenport") or row.get("port") or row.get("ports")))
        except ValueError:
            port = 0
        kind = _PORT_KINDS.get(port, ReflectorKind.UDP_BROADCAST_RELAY)
        enabled, names = by_kind.get(kind, (False, []))
        names = [*names, *(n for n in _identifiers(row.get("interfaces")) if n not in names)]
        by_kind[kind] = (enabled or _on(row.get("enabled")), names)
    return [_reflector(k, on, names, segment_of) for k, (on, names) in by_kind.items()]
