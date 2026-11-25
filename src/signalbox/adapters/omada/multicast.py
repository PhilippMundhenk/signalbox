"""Multicast of an Omada site (#508, #161, ADR 0028), read from the controller's Open API.

What the controller's own Open API description documents (checked in CI against 6.3, 5.15, 5.14
and 5.13, ``tools/integration/omada/dump.py multicast``):

- every LAN network has ``igmpSnoopEnable`` and ``mldSnoopEnable`` (all releases);
- ``GET .../lan-multicasts`` (controller 6): the multicast snooping configurations, each with the
  ``networks`` it covers, ``protocol`` (0 IGMP, 1 MLD), ``unknownMulticastRule`` (0 forward,
  1 discard, 2 only to router ports), ``querierEnable`` and the ``igmpQueriers``;
- ``GET .../setting/service/igmp`` (and ``mld`` on controller 6): the gateway's IGMP proxy for
  IPTV (``enable``, ``version``, ``wanPortId``);
- ``GET .../setting/service/mdns``: the mDNS rules (Bonjour service profiles passed between
  networks). ``type`` 0 is an access point rule between VLANs (``ap.serviceVlan`` and
  ``ap.clientVlan``), 1 a gateway rule between networks (``osg.serviceNetworks`` and
  ``osg.clientNetworks``); ``status`` is the rule's on/off switch. ``mdns-exception``
  (``mdnsEffect``, controller 6) says whether the rules are in effect at all.

The test site of CI has no snooping configuration, no mDNS rule and a default IGMP proxy, so the
shapes inside the lists (``networks``, the queriers, the VLAN and network lists of a rule) are a
*guess* (#21): ids as strings (or objects with an ``id``), VLANs as numbers, a querier as an
address (or an object with ``ip`` or ``address``). Anything else is left out. Per-port
IGMP fast leave belongs to the port profiles and is not mapped to a network.
"""

from __future__ import annotations

from collections.abc import Iterable
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

#: ``unknownMulticastRule``: 0 forward to all ports, 1 discard; 2 (router ports only) is none of
#: the two.
_UNKNOWN = {0: UnknownMulticast.FLOOD, 1: UnknownMulticast.DROP}


def _flag(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _ids(value: Any, keys: tuple[str, ...] = ("id", "networkId")) -> list[str]:
    """Ids from a list of strings or of objects holding one."""
    out: list[str] = []
    for item in value if isinstance(value, list) else []:
        if isinstance(item, dict):
            item = next((item[k] for k in keys if item.get(k) is not None), None)
        if isinstance(item, str | int) and not isinstance(item, bool) and str(item):
            out.append(str(item))
    return out


def _sub(row: dict[str, Any], key: str) -> dict[str, Any]:
    value = row.get(key)
    return value if isinstance(value, dict) else {}


def _address(value: Any) -> IPAddress | None:
    if isinstance(value, dict):
        value = next((value[k] for k in ("ip", "address", "ipAddress") if k in value), None)
    try:
        return ip_address(str(value).strip())
    except ValueError:
        return None


def _first_querier(value: Any) -> IPAddress | None:
    for item in value if isinstance(value, list) else []:
        if (found := _address(item)) is not None:
            return found
    return None


def snooping(
    nets: Iterable[tuple[str, str, str, dict[str, Any]]], configs: list[dict[str, Any]]
) -> list[MulticastSettings]:
    """``nets``: (network id, name, segment id, ``lan-networks`` row); ``configs``: the rows of
    ``lan-multicasts`` (empty on controllers that lack it)."""
    out: dict[str, MulticastSettings] = {}
    for net_id, name, segment, row in nets:
        igmp, mld = _flag(row.get("igmpSnoopEnable")), _flag(row.get("mldSnoopEnable"))
        if igmp is None and mld is None:
            continue
        out[net_id] = MulticastSettings(
            name=name, segment_id=segment, igmp_snooping=igmp, mld_snooping=mld
        )
    for cfg in configs:
        protocol = _int(cfg.get("protocol"))
        rule = _int(cfg.get("unknownMulticastRule"))
        unknown = None if rule is None else _UNKNOWN.get(rule)
        querier = _flag(cfg.get("querierEnable"))
        seen = _first_querier(cfg.get("igmpQueriers" if protocol != 1 else "mldQueriers"))
        for net_id in _ids(cfg.get("networks")):
            setting = out.get(net_id)
            if setting is None:
                continue
            change: dict[str, Any] = {}
            if unknown is not None and (protocol != 1 or setting.unknown_multicast is None):
                change["unknown_multicast"] = unknown
            if protocol != 1:
                if querier is not None:
                    change["querier"] = querier
                if seen is not None:
                    change["observed_querier"] = seen
            out[net_id] = setting.model_copy(update=change)
    return list(out.values())


def reflectors(
    proxy: dict[str, Any] | None,
    mdns: list[dict[str, Any]],
    effective: bool | None,
    by_net: dict[str, str],
    by_vlan: dict[int, str],
) -> list[ServiceReflector]:
    """The IGMP proxy and the mDNS rules. ``by_net``: network id → segment id, ``by_vlan``: VLAN
    → segment id; ``effective``: ``mdnsEffect`` (None: the controller does not say)."""
    out: list[ServiceReflector] = []
    enabled = _flag((proxy or {}).get("enable"))
    if enabled is not None:
        out.append(ServiceReflector(kind=ReflectorKind.IGMP_PROXY, enabled=enabled))
    for rule in mdns:
        on = _flag(rule.get("status"))
        if on is None:
            continue
        segments: list[str] = []
        if _int(rule.get("type")) == 1:
            side = _sub(rule, "osg")
            for key in ("serviceNetworks", "clientNetworks"):
                segments += [by_net[i] for i in _ids(side.get(key)) if i in by_net]
        else:
            side = _sub(rule, "ap")
            for key in ("serviceVlan", "clientVlan"):
                value = side.get(key)
                vlans = value if isinstance(value, list) else [value]
                segments += [by_vlan[v] for v in vlans if isinstance(v, int) and v in by_vlan]
        out.append(
            ServiceReflector(
                kind=ReflectorKind.MDNS,
                enabled=on and effective is not False,
                segments=sorted(set(segments)),
            )
        )
    return out


def multicast(
    nets: Iterable[tuple[str, str, str, dict[str, Any]]],
    configs: list[dict[str, Any]],
    proxy: dict[str, Any] | None,
    mdns: list[dict[str, Any]],
    effective: bool | None,
) -> DeviceMulticast:
    listed = list(nets)
    by_net = {net_id: segment for net_id, _, segment, _ in listed}
    by_vlan = {
        vlan: segment
        for _, _, segment, row in listed
        if isinstance(vlan := row.get("vlan"), int) and not isinstance(vlan, bool)
    }
    return DeviceMulticast(
        settings=snooping(listed, configs),
        reflectors=reflectors(proxy, mdns, effective, by_net, by_vlan),
    )
