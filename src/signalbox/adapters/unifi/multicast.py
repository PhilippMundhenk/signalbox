"""Multicast of a UniFi site (#161, ADR 0028), read from ``rest/networkconf``.

Per network of the controller (the settings are the site's, they are reported on the gateway):
``igmp_snooping``, ``igmp_flood_unknown_multicast`` and ``igmp_querier_switches`` (the switches
chosen as querier, each with its ``querier_address``) are the snooping settings; ``mdns_enabled``
(Network application 7 and later) puts the network into the mDNS reflection of the gateway;
``igmp_proxy_upstream`` and ``igmp_proxy_for`` set up the IGMP proxy. Older controllers lack the
newer fields; a missing field is "not reported". The field names are a *guess* from the
controller's JSON (#21); the site-wide mDNS setting of controllers before 7 is not read.
"""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any

from signalbox.model import (
    DeviceMulticast,
    IPAddress,
    MulticastSettings,
    ReflectorKind,
    ServiceReflector,
    UnknownMulticast,
)


def _flag(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    return None


def _address(value: Any) -> IPAddress | None:
    try:
        return ip_address(str(value).strip())
    except ValueError:
        return None


def multicast(nets: list[tuple[str, str, dict[str, Any]]]) -> DeviceMulticast:
    """``nets``: (name, segment id, ``networkconf`` row) of the site's networks."""
    out = DeviceMulticast()
    mdns: list[str] = []
    interfaces: list[str] = []
    proxy_up: str | None = None
    proxy_name: str | None = None
    proxy_for: list[str] = []
    for name, segment, row in nets:
        snooping = _flag(row.get("igmp_snooping"))
        if snooping is not None:
            flood = _flag(row.get("igmp_flood_unknown_multicast"))
            first: IPAddress | None = None
            for q in row.get("igmp_querier_switches") or []:
                if isinstance(q, dict) and (first := _address(q.get("querier_address"))):
                    break
            out.settings.append(
                MulticastSettings(
                    name=name,
                    segment_id=segment,
                    igmp_snooping=snooping,
                    # the controller turns snooping on for IGMP and MLD together
                    mld_snooping=snooping,
                    observed_querier=first,
                    unknown_multicast=None
                    if flood is None
                    else (UnknownMulticast.FLOOD if flood else UnknownMulticast.DROP),
                )
            )
        if _flag(row.get("mdns_enabled")):
            mdns.append(segment)
            interfaces.append(name)
        if _flag(row.get("igmp_proxy_upstream")):
            proxy_up = segment
            proxy_name = name
        if row.get("igmp_proxy_for") not in (None, "", "none"):
            proxy_for.append(segment)
    if mdns:
        out.reflectors.append(
            ServiceReflector(kind=ReflectorKind.MDNS, segments=sorted(mdns), interfaces=interfaces)
        )
    if proxy_up is not None:
        out.reflectors.append(
            ServiceReflector(
                kind=ReflectorKind.IGMP_PROXY,
                segments=sorted({proxy_up, *proxy_for}),
                upstream_segment_id=proxy_up,
                upstream_interface=proxy_name,
            )
        )
    return out
