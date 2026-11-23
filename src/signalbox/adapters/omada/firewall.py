"""Omada gateway ACLs and port forwarding as a firewall (#135, ADR 0013).

Paths and field names are from the controller's own Open API description (6.3, recorded in CI by
``tools/integration/omada/dump.py firewall``); the test site has no gateway, so no ACL or
forward was ever read from a real one (#21). Parsing is tolerant: an unknown shape keeps the
rule and makes it ``exact = False``, nothing is invented.

``GET …/sites/{siteId}/acls/osg-acls`` (the gateway ACLs of the profile mode): ``description``
(the name), ``status``, ``policy`` (0 drop, 1 allow), ``protocols`` (IP protocol numbers),
``sourceType``/``sourceIds`` and ``destinationType``/``destinationIds`` (0 LAN networks; 1 IP
group, 2 IP-port group, 4 SSID, 6 IPv6 groups are not resolved), ``direction`` (``lanToWan``,
``lanToLan``, ``wanInIds``, ``vpnInIds``), ``timeRangeId`` and ``index`` (the order). In custom
mode (``…/acls/osg-config-mode`` ``mode`` 1) ``…/acls/osg-custom-acls`` applies instead:
``direction`` 0 LAN-LAN, 1 LAN-WAN, 2 WAN-LAN, 3 LOCAL IN, ``protocol``, ``sourceList`` and
``destinationList``, ``sourcePort`` and ``destinationPort``. The gateway routes between its LAN
networks and lets them out by default and keeps the internet out: those are the zone policies.
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network
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
    # the WAN zone exists even when the gateway reported no WAN port: rules and forwards name it
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


def _name(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def custom_acl_rules(rows: list[dict[str, Any]], names: dict[str, str]) -> list[FirewallRule]:
    """``osg-custom-acls`` (custom mode) in evaluation order: one rule each, the direction an
    integer; address lists are only kept when they are addresses or networks."""
    out: list[FirewallRule] = []
    ordered = sorted(rows, key=lambda r: (_int(r.get("index")) is None, _int(r.get("index")) or 0))
    lan = list(names.values())
    for row in ordered:
        policy, direction = _int(row.get("policy")), _int(row.get("direction"))
        if policy not in (0, 1) or direction not in (0, 1, 2, 3):
            continue  # 3: LOCAL IN (to the gateway itself) is below
        exact = True
        nets: dict[str, list[Any]] = {}
        for side in ("source", "destination"):
            found: list[Any] = []
            for text in row.get(f"{side}List") or []:
                try:
                    found.append(ip_network(str(text), strict=False))
                except ValueError:
                    exact = False  # an IP group id or a name
            nets[side] = found
        ports = {side: _ports(row.get(f"{side}Port")) for side in ("source", "destination")}
        protocol = _int(row.get("protocol"))
        protocols = (
            [] if protocol in (None, 0, 256) else [PROTOCOLS.get(protocol, FirewallProtocol.OTHER)]
        )
        if (ports["source"] or ports["destination"]) and not protocols:
            protocols = [FirewallProtocol.TCP, FirewallProtocol.UDP]
        source = [WAN] if direction == 2 else lan
        destination = [WAN] if direction == 1 else lan
        out.append(
            FirewallRule(
                name=_name(row.get("description")),
                order=_int(row.get("index")),
                enabled=_flag(row.get("status")),
                chain=FirewallChain.INPUT if direction == 3 else FirewallChain.FORWARD,
                protocols=protocols,
                source=FirewallMatch(
                    zones=source, networks=nets["source"], ports=ports["source"] or []
                ),
                destination=FirewallMatch(
                    zones=[] if direction == 3 else destination,
                    networks=nets["destination"],
                    ports=ports["destination"] or [],
                ),
                action=FirewallAction.ACCEPT if policy == 1 else FirewallAction.DROP,
                exact=exact,
            )
        )
    return out


def acl_rules(rows: list[dict[str, Any]], names: dict[str, str]) -> list[FirewallRule]:
    """Gateway ACLs in evaluation order (``index``); one rule for each direction of an ACL."""
    out: list[FirewallRule] = []
    ordered = sorted(rows, key=lambda r: (_int(r.get("index")) is None, _int(r.get("index")) or 0))
    for row in ordered:
        policy = _int(row.get("policy"))
        if policy not in (0, 1):
            continue
        action = FirewallAction.ACCEPT if policy == 1 else FirewallAction.DROP
        src, src_exact = _ends(row, "source", names)
        dst, dst_exact = _ends(row, "destination", names)
        protos = row.get("protocols")
        protocols: list[FirewallProtocol] = []
        exact = src_exact and dst_exact and not row.get("timeRangeId")
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
                    name=_name(row.get("description") or row.get("name")),
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
    """``…/nat/port-forwardings``: ``name``, ``status``, ``from`` (0 anywhere, 1 only
    ``limitedAddresses``), ``externalPort`` (``8080`` or ``8000-8100``), ``forwardIp``,
    ``forwardPort``, ``protocol`` (0 all, 1 TCP, 2 UDP) and ``dMZ`` (an exposed host); the
    filter lets them through by itself."""
    out: list[PortForward] = []
    for row in rows:
        try:
            target = ip_address(str(row.get("forwardIp", "")).strip())
        except ValueError:
            continue
        number = _int(row.get("protocol"))
        proto = 0 if row.get("protocol") is None else (-1 if number is None else number)
        protocols = {
            0: [FirewallProtocol.TCP, FirewallProtocol.UDP],
            1: [FirewallProtocol.TCP],
            2: [FirewallProtocol.UDP],
        }.get(proto)
        exposed = row.get("dMZ") is True
        external = _ports(row.get("externalPort"))
        internal = _ports(row.get("forwardPort"))
        sources: list[Any] = []
        exact = protocols is not None
        if _int(row.get("from")) == 1:
            for text in row.get("limitedAddresses") or []:
                try:
                    sources.append(ip_network(str(text), strict=False))
                except ValueError:
                    exact = False
        if not exposed and external is None:
            exact = False
        out.append(
            PortForward(
                name=_name(row.get("name")),
                enabled=_flag(row.get("status")),
                protocols=[] if exposed else protocols or [],
                zones=[WAN],
                external_ports=[] if exposed else external or [],
                sources=sources,
                target_address=target,
                target_port=None if exposed or not internal else internal[0].start,
                passes_filter=True,
                exact=exact,
            )
        )
    return out
