"""OpenWrt firewall (UCI ``firewall`` config of fw4 and fw3) to the model (#135, ADR 0013).

Pure functions: the adapter passes the parsed ``uci get firewall`` answer and a function that
maps a UCI network name (``lan``, ``wan6``) to model objects.

OpenWrt semantics used here (from the documentation of the ``firewall`` config; *(guess)*: not
yet confirmed against a router where marked):

- a ``rule`` without ``dest`` is an *input* rule (traffic to the router), with ``dest`` (a zone
  or ``*``) a *forward* rule, without ``src`` an *output* rule; ``dest_ip`` alone stays input;
- traffic between two zones is allowed only by a ``forwarding`` (else rejected); ``forward``
  of a zone is its intra-zone policy, ``input`` its policy towards the router itself;
- ``redirect`` with target DNAT is let through without a filter rule (``passes_filter``);
- the target of a ``rule`` defaults to DROP.
"""

from __future__ import annotations

from collections.abc import Callable
from ipaddress import ip_address, ip_network
from typing import Any, Literal

from signalbox.model import (
    Firewall,
    FirewallAction,
    FirewallChain,
    FirewallMatch,
    FirewallProtocol,
    FirewallRule,
    FirewallZone,
    IPAddress,
    IPNetwork,
    NatRule,
    PortForward,
    PortRange,
    ZonePolicy,
    firewall_id,
)

#: A UCI network name to ``(segments, uplinks, tunnels)``; ``None``: not mapped to anything.
Mapper = Callable[[str], tuple[list[str], list[str], list[str]] | None]

_ACTIONS = {
    "ACCEPT": FirewallAction.ACCEPT,
    "DROP": FirewallAction.DROP,
    "REJECT": FirewallAction.REJECT,
}
_PROTOCOLS = {
    "tcp": FirewallProtocol.TCP,
    "udp": FirewallProtocol.UDP,
    "icmp": FirewallProtocol.ICMP,
    "ipv6-icmp": FirewallProtocol.ICMP,
    "icmpv6": FirewallProtocol.ICMP,
    "esp": FirewallProtocol.ESP,
    "gre": FirewallProtocol.GRE,
}
#: Options of a rule, redirect or nat section whose conditions the model cannot express.
_INEXACT = (
    "ipset",
    "mark",
    "start_time",
    "stop_time",
    "start_date",
    "stop_date",
    "weekdays",
    "monthdays",
    "utc_time",
    "limit",
    "limit_burst",
    "src_mac",
    "device",
    "direction",
    "helper",
    "dscp",
    "extra",
    "icmp_type",
    "set_mark",
    "set_xmark",
)


def _list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return value.split()
    return []


def _flag(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).lower() in ("1", "true", "yes", "on", "enabled")


def _sections(uci: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    values = uci.get("values")
    if not isinstance(values, dict):
        return []
    found = [s for s in values.values() if isinstance(s, dict) and s.get(".type") == kind]

    def index(s: dict[str, Any]) -> int:
        try:
            return int(str(s.get(".index")))
        except ValueError:
            return 0

    return sorted(found, key=index)


def _action(value: Any, default: FirewallAction) -> FirewallAction:
    return _ACTIONS.get(str(value).upper(), default) if value is not None else default


def ports(value: Any) -> list[PortRange] | None:
    """``80``, ``1000-2000``, ``1000:2000`` (several, space separated); ``None``: unreadable."""
    out: list[PortRange] = []
    for item in _list(value):
        first, sep, last = item.replace(":", "-").partition("-")
        try:
            out.append(PortRange(start=int(first), end=int(last) if sep else None))
        except ValueError:
            return None
    return out


def networks(value: Any) -> tuple[list[IPNetwork], bool, bool]:
    """``(networks, negated, exact)``: addresses and prefixes; a ``!`` prefix negates (a mix
    of both, an unparsable entry or a MAC is not exact)."""
    out: list[IPNetwork] = []
    negated: list[bool] = []
    exact = True
    for item in _list(value):
        try:
            out.append(ip_network(item.lstrip("!"), strict=False))
            negated.append(item.startswith("!"))
        except ValueError:
            exact = False
    if len(set(negated)) > 1:
        return [], False, False
    return out, bool(negated and negated[0]), exact


def _protocols(value: Any) -> list[FirewallProtocol]:
    """Empty: every protocol (``all``). The default of fw4 is ``tcp udp``."""
    if value is None:
        return [FirewallProtocol.TCP, FirewallProtocol.UDP]
    items = [i.lower() for i in _list(value)]
    if "all" in items:
        return []
    return list(dict.fromkeys(_PROTOCOLS.get(i, FirewallProtocol.OTHER) for i in items))


def _family(value: Any) -> Literal[4, 6] | None:
    text = str(value).lower()
    return 4 if text == "ipv4" else 6 if text == "ipv6" else None


def _address(value: Any) -> IPAddress | None:
    try:
        return ip_address(str(value).strip("[]"))
    except ValueError:
        return None


def _has_inexact(s: dict[str, Any], *more: str) -> bool:
    return any(s.get(k) not in (None, "", []) for k in (*_INEXACT, *more))


def _zones(uci: dict[str, Any], mapper: Mapper) -> dict[str, FirewallZone]:
    out: dict[str, FirewallZone] = {}
    for s in _sections(uci, "zone"):
        name = str(s.get("name") or "")
        if not name or name in out:
            continue
        names = _list(s.get("network"))
        # ``device`` and ``subnet`` zones are not whole networks: not mapped
        extra = bool(_list(s.get("device")) or _list(s.get("subnet")) or _list(s.get("extra")))
        if not names and not extra:  # fw4: a zone without any is the network of its own name
            names = [name]
        segments: list[str] = []
        uplinks: list[str] = []
        tunnels: list[str] = []
        complete = not extra
        for n in names:
            found = mapper(n)
            if found is None:
                complete = False
                continue
            segments += [x for x in found[0] if x not in segments]
            uplinks += [x for x in found[1] if x not in uplinks]
            tunnels += [x for x in found[2] if x not in tunnels]
        masq = _flag(s.get("masq"))
        restricted = bool(_list(s.get("masq_src")) or _list(s.get("masq_dest")))
        out[name] = FirewallZone(
            name=name,
            segments=segments,
            uplinks=uplinks,
            tunnels=tunnels,
            masquerade=(None if restricted else masq) if masq else False,
            complete=complete,
        )
    return out


def _match(zone: Any, nets: Any, port: Any) -> tuple[FirewallMatch, bool]:
    n, negated, exact = networks(nets)
    p = ports(port)
    return (
        FirewallMatch(
            zones=[str(zone)] if zone and zone != "*" else [],
            networks=n,
            networks_not=negated,
            ports=p or [],
        ),
        exact and p is not None,
    )


def _rule(s: dict[str, Any], known: set[str]) -> FirewallRule | None:
    target = str(s.get("target") or "DROP").upper()
    if target not in _ACTIONS:
        return None  # MARK, NOTRACK, DSCP, ...: they do not decide
    src, dest = s.get("src"), s.get("dest")
    chain = (
        FirewallChain.OUTPUT if not src else FirewallChain.FORWARD if dest else FirewallChain.INPUT
    )
    source, ok1 = _match(src, s.get("src_ip"), s.get("src_port"))
    destination, ok2 = _match(dest, s.get("dest_ip"), s.get("dest_port"))
    exact = ok1 and ok2 and {*source.zones, *destination.zones} <= known and not _has_inexact(s)
    name = s.get("name")
    return FirewallRule(
        name=str(name) if name else None,
        enabled=_flag(s.get("enabled"), default=True),
        chain=chain,
        family=_family(s.get("family")),
        protocols=_protocols(s.get("proto")),
        source=source,
        destination=destination,
        action=_ACTIONS[target],
        exact=exact,
    )


def _forward(s: dict[str, Any], zones: dict[str, FirewallZone]) -> tuple[PortForward | None, bool]:
    """``(forward, complete)`` of a DNAT ``redirect``. One without ``dest_ip`` goes to the
    router itself: not a forward, and incomplete only when it listens on an uplink zone."""
    src = str(s.get("src") or "")
    target = _address(s.get("dest_ip"))
    zone = zones.get(src)
    if target is None:
        return None, not (zone is not None and zone.uplinks)
    external = ports(s.get("src_dport"))
    internal = ports(s.get("dest_port"))
    sources, negated, ok = networks(s.get("src_ip"))
    exact = ok and external is not None and internal is not None and not negated
    return (
        PortForward(
            name=str(s["name"]) if s.get("name") else None,
            enabled=_flag(s.get("enabled"), default=True),
            protocols=_protocols(s.get("proto")),
            zones=[src] if src and src != "*" else [],
            external_address=_address(s.get("src_dip")),
            external_ports=external or [],
            sources=[] if negated else sources,
            target_address=target,
            target_port=internal[0].start if internal else None,
            passes_filter=True,
            reflection=_flag(s.get("reflection"), default=True),
            exact=exact and not _has_inexact(s, "device"),
        ),
        True,
    )


def _nat(s: dict[str, Any]) -> NatRule | None:
    target = str(s.get("target") or "").upper()
    if target not in ("SNAT", "MASQUERADE"):
        return None
    src = str(s.get("src") or "")
    sources, negated, ok = networks(s.get("src_ip"))
    to = _address(s.get("snat_ip"))
    masquerade = target == "MASQUERADE"
    return NatRule(
        name=str(s["name"]) if s.get("name") else None,
        enabled=_flag(s.get("enabled"), default=True),
        zones=[src] if src and src != "*" else [],
        sources=[] if negated else sources,
        masquerade=masquerade or to is None,
        to_address=None if masquerade else to,
        exact=ok
        and not negated
        and (masquerade or to is not None)
        and not _has_inexact(s, "dest_ip", "dest_port", "src_port"),
    )


def build(uci: dict[str, Any], device_id: str, mapper: Mapper) -> Firewall:
    """The firewall of ``uci get firewall``; an empty config filters nothing."""
    values = uci.get("values")
    if not isinstance(values, dict) or not values:
        return Firewall(id=firewall_id(device_id), device_id=device_id, enabled=False)
    defaults = next(iter(_sections(uci, "defaults")), {})
    d_input = _action(defaults.get("input"), FirewallAction.DROP)
    d_forward = _action(defaults.get("forward"), FirewallAction.DROP)
    zones = _zones(uci, mapper)
    names = set(zones)

    policies: list[ZonePolicy] = []
    for s in _sections(uci, "zone"):
        name = str(s.get("name") or "")
        if name not in zones or any(p.source == name for p in policies):
            continue
        # a zone's own ``input`` and ``forward`` (intra-zone), else the defaults
        policies.append(
            ZonePolicy(source=name, destination=None, action=_action(s.get("input"), d_input))
        )
        policies.append(
            ZonePolicy(source=name, destination=name, action=_action(s.get("forward"), d_forward))
        )
    pairs = {(p.source, p.destination) for p in policies}
    for s in _sections(uci, "forwarding"):
        src, dest = str(s.get("src") or ""), str(s.get("dest") or "")
        if (
            _flag(s.get("enabled"), default=True)
            and src in names
            and dest in names
            and (src, dest) not in pairs
        ):
            pairs.add((src, dest))
            policies.append(ZonePolicy(source=src, destination=dest, action=FirewallAction.ACCEPT))

    rules = [r for s in _sections(uci, "rule") if (r := _rule(s, names)) is not None]
    forwards: list[PortForward] = []
    complete = True
    nat: list[NatRule] = []
    for s in _sections(uci, "redirect"):
        if str(s.get("target") or "DNAT").upper() == "SNAT":
            if (n := _nat(s)) is not None:
                nat.append(n)
            continue
        forward, ok = _forward(s, zones)
        complete = complete and ok
        if forward is not None:
            forwards.append(forward)
    nat += [n for s in _sections(uci, "nat") if (n := _nat(s)) is not None]
    # an ``include`` runs a script or nftables snippet the config does not show; the default
    # /etc/firewall.user is a file of comments *(guess)*
    includes = [
        s
        for s in _sections(uci, "include")
        if str(s.get("path") or "") != "/etc/firewall.user" or s.get("type") == "nftables"
    ]
    return Firewall(
        id=firewall_id(device_id),
        device_id=device_id,
        zones=list(zones.values()),
        policies=policies,
        input_policy=d_input,
        # traffic between two zones without a ``forwarding`` is rejected
        forward_policy=FirewallAction.REJECT,
        rules=rules,
        rules_complete=not includes,
        nat=nat,
        port_forwards=forwards,
        port_forwards_complete=complete and not includes,
    )
