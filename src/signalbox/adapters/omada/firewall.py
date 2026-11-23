"""Omada gateway ACLs and port forwarding as a firewall (#135, ADR 0013).

Mapped from the controller's Open API description, not from a gateway (the CI site has none):
the names of the fields are *(guess)* until a real site is read (#21). Parsing is tolerant: an
unknown shape keeps the rule and makes it ``exact = False``, nothing is invented.

Gateway ACLs (``…/sites/{siteId}/acls``, ``type`` gateway) have a ``policy`` (0 deny, 1 permit),
``protocols`` (IP protocol numbers), a source and a destination (``sourceType`` and
``sourceIds``, ``destinationType`` and ``destinationIds``: 0 LAN networks, anything else an IP
group or IP-port group that is not resolved), a ``direction`` (``lanToWan``, ``lanToLan``,
``wanInIds`` for WAN to LAN) and an ``index`` (the order). The gateway routes between its LAN
networks and lets them out by default and keeps the internet out: those are the zone policies.
"""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any

from signalbox.model import (
    FirewallAction,
    FirewallChain,
    FirewallMatch,
    FirewallProtocol,
    FirewallRule,
    FirewallZone,
    PortForward,
    PortRange,
    ZonePolicy,
)

WAN = "wan"
#: IP protocol numbers of an ACL.
PROTOCOLS = {
    1: FirewallProtocol.ICMP,
    6: FirewallProtocol.TCP,
    17: FirewallProtocol.UDP,
    47: FirewallProtocol.GRE,
    50: FirewallProtocol.ESP,
}
#: Source or destination type: a list of LAN networks.
NETWORKS = 0


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return None


def _flag(value: Any, default: bool = True) -> bool:
    return value if isinstance(value, bool) else default


def zone_names(networks: dict[str, str]) -> dict[str, str]:
    """Zone name per LAN network id: the network's name, made unique with its id."""
    seen: dict[str, int] = {}
    for name in networks.values():
        seen[name] = seen.get(name, 0) + 1
    return {i: n if seen[n] == 1 else f"{n} ({i})" for i, n in networks.items()}


def zones_and_policies(
    segments: dict[str, str], uplinks: list[str]
) -> tuple[list[FirewallZone], list[ZonePolicy]]:
    """One zone per LAN network (name to segment id) and one for the WAN ports; the defaults
    of an Omada gateway: LAN networks reach the gateway, each other and the internet, the
    internet reaches nothing."""
    accept, drop = FirewallAction.ACCEPT, FirewallAction.DROP
    zones = [FirewallZone(name=n, segments=[s]) for n, s in segments.items()]
    policies = [ZonePolicy(source=n, destination=None, action=accept) for n in segments]
    if uplinks:
        zones.append(FirewallZone(name=WAN, uplinks=uplinks, masquerade=True))
        policies.append(ZonePolicy(source=WAN, destination=None, action=drop))
        for n in segments:
            policies.append(ZonePolicy(source=n, destination=WAN, action=accept))
            policies.append(ZonePolicy(source=WAN, destination=n, action=drop))
    return zones, policies


def _ends(row: dict[str, Any], side: str, names: dict[str, str]) -> tuple[list[str] | None, bool]:
    """(zones, exact) of the source or destination of an ACL; ``None``: not restricted."""
    ids = row.get(f"{side}Ids")
    kind = _int(row.get(f"{side}Type"))
    if not isinstance(ids, list) or not ids:
        return None, True
    if kind is not None and kind != NETWORKS:
        return None, False  # an IP group or IP-port group: not resolved
    found = [names[i] for i in ids if isinstance(i, str) and i in names]
    if len(found) != len(ids):
        return None, False
    return found, True


def acl_rules(rows: list[dict[str, Any]], names: dict[str, str]) -> list[FirewallRule]:
    """Gateway ACLs in evaluation order (``index``); one rule for each direction of an ACL."""
    out: list[FirewallRule] = []
    ordered = sorted(rows, key=lambda r: (_int(r.get("index")) is None, _int(r.get("index")) or 0))
    for row in ordered:
        if _int(row.get("type")) not in (None, 0):
            continue  # switch and EAP ACLs belong to those devices
        policy = _int(row.get("policy"))
        if policy not in (0, 1):
            continue
        action = FirewallAction.ACCEPT if policy == 1 else FirewallAction.DROP
        src, src_exact = _ends(row, "source", names)
        dst, dst_exact = _ends(row, "destination", names)
        protos = row.get("protocols")
        protocols: list[FirewallProtocol] = []
        exact = src_exact and dst_exact
        if isinstance(protos, list) and protos and all(isinstance(p, int) for p in protos):
            if not any(p in (0, 256) for p in protos):  # 256: all protocols
                protocols = [PROTOCOLS.get(p, FirewallProtocol.OTHER) for p in protos]
        elif protos not in (None, [], ""):
            exact = False
        raw_direction = row.get("direction")
        direction: dict[str, Any] = raw_direction if isinstance(raw_direction, dict) else {}
        lan = list(names.values())
        wanted: list[tuple[list[str] | None, list[str] | None]] = []
        if _flag(direction.get("lanToWan"), False):
            wanted.append((src or lan, [WAN]))
        if _flag(direction.get("lanToLan"), False):
            wanted.append((src or lan, dst or lan))
        if direction.get("wanInIds"):
            wanted.append(([WAN], dst or lan))
        if not wanted:
            continue  # VPN-in or an unknown direction: not modelled
        for source, destination in wanted:
            out.append(
                FirewallRule(
                    name=row.get("name") if isinstance(row.get("name"), str) else None,
                    order=_int(row.get("index")),
                    enabled=_flag(row.get("status")),
                    chain=FirewallChain.FORWARD,
                    protocols=protocols,
                    source=FirewallMatch(zones=source or []),
                    destination=FirewallMatch(zones=destination or []),
                    action=action,
                    exact=exact,
                )
            )
    return out


def _ports(value: Any) -> list[PortRange] | None:
    """``"8080"`` or ``"8000-8100"`` (or an int); ``None`` when it is neither."""
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str) or not value.strip():
        return None
    out: list[PortRange] = []
    try:
        for part in value.split(","):
            first, _, last = part.strip().partition("-")
            out.append(PortRange(start=int(first), end=int(last) if last else None))
    except ValueError:  # not a number, or out of range (pydantic's error is a ValueError)
        return None
    return out


def port_forwards(rows: list[dict[str, Any]]) -> list[PortForward]:
    """``…/nat/port-forwardings``: ``externalPort``, ``forwardIp``, ``forwardPort``,
    ``protocol`` (``tcp``, ``udp``, ``all``/``tcp/udp``) and ``status``; the filter lets them
    through by itself."""
    out: list[PortForward] = []
    for row in rows:
        try:
            target = ip_address(str(row.get("forwardIp", "")).strip())
        except ValueError:
            continue
        text = str(row.get("protocol", "")).lower().replace(" ", "")
        protocols = {
            "tcp": [FirewallProtocol.TCP],
            "udp": [FirewallProtocol.UDP],
            "tcp/udp": [FirewallProtocol.TCP, FirewallProtocol.UDP],
            "all": [FirewallProtocol.TCP, FirewallProtocol.UDP],
        }.get(text)
        external = _ports(row.get("externalPort"))
        internal = _ports(row.get("forwardPort"))
        out.append(
            PortForward(
                name=row.get("name") if isinstance(row.get("name"), str) else None,
                enabled=_flag(row.get("status")),
                protocols=protocols or [],
                zones=[WAN],
                external_ports=external or [],
                target_address=target,
                target_port=internal[0].start if internal else None,
                passes_filter=True,
                exact=protocols is not None
                and (external is not None or not row.get("externalPort")),
            )
        )
    return out
