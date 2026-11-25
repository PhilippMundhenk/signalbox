"""Firewall rule-sets, NAT and port forwards of an EdgeOS or VyOS configuration (#403).

EdgeOS 1.x/2.0 and VyOS 1.3 share the classic model: named rule-sets (``firewall name X`` and
``ipv6-name X``) that are applied to an interface in one of three directions
(``interfaces ethernet eth0 firewall in|out|local name X``), with a default action and numbered
rules. Mapped like the other adapters map zones: every interface is a zone; ``in`` is the
forward chain for traffic arriving on it, ``out`` the forward chain for traffic leaving through
it, ``local`` the input chain (traffic to the router). The default action of a set becomes a
last rule of that interface, so the order across interfaces stays right.

Signalbox evaluates new connections only (the model is stateful): rules that only accept
``established``/``related`` or drop ``invalid`` connections are not new-connection rules and are
left out; a rule with any condition the model has no field for (an address group, TCP flags,
a rate limit, time of day) is ``exact = False``. VyOS 1.4 renamed the firewall
(``firewall ipv4 ...``, zones): its rules are not read and a gap names the version (#389).
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Literal

from signalbox.adapters.edgeos.tree import Node
from signalbox.model import (
    FirewallAction,
    FirewallChain,
    FirewallMatch,
    FirewallProtocol,
    FirewallRule,
    IPAddress,
    IPNetwork,
    NatRule,
    PortForward,
    PortRange,
)

#: Service names EdgeOS accepts as ports (the ones in everyday rules).
SERVICES = {
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "domain": 53,
    "dns": 53,
    "bootps": 67,
    "bootpc": 68,
    "tftp": 69,
    "http": 80,
    "ntp": 123,
    "snmp": 161,
    "ldap": 389,
    "https": 443,
    "imaps": 993,
    "openvpn": 1194,
    "mysql": 3306,
    "rdp": 3389,
}
_PROTOCOLS = {
    "tcp": [FirewallProtocol.TCP],
    "udp": [FirewallProtocol.UDP],
    "tcp_udp": [FirewallProtocol.TCP, FirewallProtocol.UDP],
    "icmp": [FirewallProtocol.ICMP],
    "ipv6-icmp": [FirewallProtocol.ICMP],
    "icmpv6": [FirewallProtocol.ICMP],
    "esp": [FirewallProtocol.ESP],
    "gre": [FirewallProtocol.GRE],
    "all": [],
}
_ACTIONS = {
    "accept": FirewallAction.ACCEPT,
    "drop": FirewallAction.DROP,
    "reject": FirewallAction.REJECT,
}
#: Rule options the model has no field for: the rule is then inexact.
_OTHER_CONDITIONS = (
    "limit",
    "recent",
    "time",
    "tcp",
    "icmp",
    "ipv6-route",
    "fragment",
    "ipsec",
    "p2p",
    "mark",
    "dscp",
    "connection-mark",
    "packet-length",
    "queue",
    "random",
)


@dataclass
class Rules:
    rules: list[FirewallRule] = field(default_factory=list)
    zone_names: set[str] = field(default_factory=set)
    #: A rule-set is applied to some interface.
    applied: bool = False
    complete: bool = True
    gaps: list[tuple[str, str, dict[str, str]]] = field(default_factory=list)


def _ports(text: str | None) -> tuple[list[PortRange], bool]:
    """``22``, ``80,443``, ``1000-2000``, ``ssh`` -> ranges and whether all were understood."""
    if text is None:
        return [], True
    out: list[PortRange] = []
    exact = True
    for part in text.split(","):
        item = part.strip()
        if not item or item.startswith("!"):
            exact = False
            continue
        lo, sep, hi = item.partition("-")
        try:
            start = int(lo) if lo.isdigit() else SERVICES[lo]
            end = int(hi) if sep and hi.isdigit() else None
            out.append(PortRange(start=start, end=end if end and end != start else None))
        except (KeyError, ValueError):
            exact = False
    return out, exact


def _networks(text: str | None) -> tuple[list[IPNetwork], bool, bool]:
    """An ``address`` value -> networks, negated, understood. Ranges and ``!`` are inexact."""
    if text is None:
        return [], False, True
    negated = text.startswith("!")
    item = text.lstrip("!")
    try:
        return [ip_network(item, strict=False)], negated, True
    except ValueError:
        return [], False, False


def _end(node: Node | None, rule: Node, zone: str, side: str) -> tuple[FirewallMatch, bool]:
    """Source or destination of a rule (``zone`` is the interface the rule-set is applied to,
    only for the source of an ``in``/``local`` set and the destination of an ``out`` set)."""
    match = FirewallMatch()
    exact = True
    if node is None:
        return match, exact
    networks, negated, ok = _networks(node.first("address"))
    exact &= ok
    ports, ports_ok = _ports(node.first("port"))
    exact &= ports_ok
    if node.has("group") or node.has("mac-address"):
        exact = False
    return (
        match.model_copy(update={"networks": networks, "networks_not": negated, "ports": ports}),
        exact,
    )


def _rule(
    name: str,
    number: str,
    rule: Node,
    chain: FirewallChain,
    family: Literal[4, 6],
    zone: str,
    direction: str,
) -> FirewallRule | None:
    action = _ACTIONS.get(rule.first("action") or "")
    if action is None:  # inspect, modify, queue: not an allow or deny decision
        return None
    states = {s for s, n in rule.items("state") if n.has("enable")}
    if states and "new" not in states:  # established/related/invalid: not a new connection
        return None
    exact = not any(rule.has(word) for word in _OTHER_CONDITIONS) and not (
        states and states != {"new"}
    )
    proto_word = rule.first("protocol") or "all"
    protocols: list[FirewallProtocol] = []
    if proto_word.startswith("!") or proto_word not in _PROTOCOLS:
        if proto_word not in _PROTOCOLS and not proto_word.startswith("!"):
            protocols = [FirewallProtocol.OTHER]
        else:
            exact = False
    else:
        protocols = _PROTOCOLS[proto_word]
    source, src_ok = _end(rule.get("source"), rule, zone, "source")
    destination, dst_ok = _end(rule.get("destination"), rule, zone, "destination")
    if direction == "out":
        destination = destination.model_copy(update={"zones": [zone]})
    else:
        source = source.model_copy(update={"zones": [zone]})
    if (
        destination.ports
        and protocols
        and not set(protocols)
        & {
            FirewallProtocol.TCP,
            FirewallProtocol.UDP,
        }
    ):
        destination = destination.model_copy(update={"ports": []})
        exact = False
    # ports without a protocol: EdgeOS refuses such a rule; treat as TCP and UDP
    if (destination.ports or source.ports) and not protocols:
        protocols = [FirewallProtocol.TCP, FirewallProtocol.UDP]
    return FirewallRule(
        name=rule.first("description") or f"{name} {number}",
        order=int(number) if number.isdigit() else None,
        enabled=not rule.has("disable"),
        chain=chain,
        family=family,
        protocols=protocols,
        source=source,
        destination=destination,
        action=action,
        exact=exact and src_ok and dst_ok,
    )


def _default(
    name: str, node: Node, chain: FirewallChain, family: Literal[4, 6], zone: str, d: str
) -> FirewallRule | None:
    action = _ACTIONS.get(node.first("default-action") or "")
    if action is None:
        return None
    match = FirewallMatch(zones=[zone])
    return FirewallRule(
        name=f"{name} default",
        chain=chain,
        family=family,
        source=match if d != "out" else FirewallMatch(),
        destination=match if d == "out" else FirewallMatch(),
        action=action,
    )


def filter_rules(root: Node, vyos_14: bool) -> Rules:
    """The rule-sets that are applied to an interface, in the order EdgeOS evaluates them."""
    out = Rules()
    if vyos_14:
        out.complete = False
        return out
    sets = {
        4: dict(root.items("firewall", "name")),
        6: dict(root.items("firewall", "ipv6-name")),
    }
    applied: list[tuple[str, str, int, str]] = []  # (interface, direction, family, set name)
    interfaces = root.get("interfaces")
    for kinds in interfaces.children.values() if interfaces else []:
        for ifname, node in kinds.children.items():
            blocks = [(ifname, node)]
            blocks += [(f"{ifname}.{vif}", sub) for vif, sub in node.items("vif")]
            blocks += [(f"pppoe{n}", sub) for n, sub in node.items("pppoe")]
            for name, block in blocks:
                for direction in ("in", "out", "local"):
                    for key, family in (("name", 4), ("ipv6-name", 6)):
                        wanted = block.first("firewall", direction, key)
                        if wanted:
                            applied.append((name, direction, family, wanted))
    # evaluation: traffic to the router (local), then forwarded (in, then out)
    order = {"local": 0, "in": 1, "out": 2}
    for zone, direction, family, wanted in sorted(applied, key=lambda x: order[x[1]]):
        found = sets[family].get(wanted)
        if found is None:
            out.complete = False
            out.gaps.append(
                (
                    f"firewall: {zone} uses the rule-set {wanted}, which is not defined",
                    "edgeos.ruleSetMissing",
                    {"interface": zone, "name": wanted},
                )
            )
            continue
        node = found
        out.applied = True
        out.zone_names.add(zone)
        chain = FirewallChain.INPUT if direction == "local" else FirewallChain.FORWARD
        fam: Literal[4, 6] = 4 if family == 4 else 6
        numbers = sorted((n for n in node.keys("rule")), key=lambda x: (not x.isdigit(), x))
        for number in sorted(numbers, key=lambda x: int(x) if x.isdigit() else 0):
            rule_node = node.get("rule", number)
            assert rule_node is not None
            rule = _rule(wanted, number, rule_node, chain, fam, zone, direction)
            if rule is not None:
                out.rules.append(rule)
        closing = _default(wanted, node, chain, fam, zone, direction)
        if closing is not None:
            out.rules.append(closing)
    return out


@dataclass
class Nat:
    nat: list[NatRule] = field(default_factory=list)
    forwards: list[PortForward] = field(default_factory=list)
    zone_names: set[str] = field(default_factory=set)
    complete: bool = True


def _address(node: Node | None, *path: str) -> IPAddress | None:
    value = node.first(*path) if node is not None else None
    if value is None:
        return None
    with contextlib.suppress(ValueError):
        return ip_address(value)
    return None


def _interface(rule: Node, *names: str) -> str | None:
    """``outbound-interface eth0`` (EdgeOS, VyOS 1.3) or ``outbound-interface name eth0`` (1.4)."""
    for name in names:
        words = rule.keys(name)
        if not words:
            continue
        if words[0] == "name":
            return rule.first(name, "name")
        return words[0]
    return None


def nat(root: Node) -> Nat:
    """``service nat rule`` (EdgeOS), ``nat source|destination rule`` (VyOS), ``port-forward``."""
    out = Nat()
    rules: list[tuple[str, str, Node]] = [
        ("auto", n, node) for n, node in root.items("service", "nat", "rule")
    ]
    rules += [("source", n, node) for n, node in root.items("nat", "source", "rule")]
    rules += [("destination", n, node) for n, node in root.items("nat", "destination", "rule")]
    for style, number, rule in sorted(
        rules, key=lambda x: (x[0], int(x[1]) if x[1].isdigit() else 0)
    ):
        kind = rule.first("type") if style == "auto" else style
        name = rule.first("description") or f"NAT {number}"
        proto_word = rule.first("protocol") or "all"
        protocols = _PROTOCOLS.get(proto_word, [FirewallProtocol.OTHER])
        exact = not proto_word.startswith("!") and not any(
            rule.has(w) for w in ("exclude", "load-balance")
        )
        src_net, _, src_ok = _networks(rule.first("source", "address"))
        enabled = not rule.has("disable")
        if kind in ("masquerade", "source"):
            out_if = _interface(rule, "outbound-interface")
            masq = kind == "masquerade" or rule.first("translation", "address") == "masquerade"
            to_address = (
                None
                if masq
                else _address(rule, "translation", "address")
                or _address(rule, "outside-address", "address")
            )
            if not masq and to_address is None:
                out.complete = False
                continue
            out.nat.append(
                NatRule(
                    name=name,
                    enabled=enabled,
                    zones=[out_if] if out_if else [],
                    sources=src_net,
                    masquerade=masq,
                    to_address=to_address,
                    exact=exact and src_ok,
                )
            )
            if out_if:
                out.zone_names.add(out_if)
        elif kind == "destination":
            target = _address(rule, "inside-address", "address") or _address(
                rule, "translation", "address"
            )
            if target is None:
                out.complete = False
                continue
            in_if = _interface(rule, "inbound-interface")
            ext, ext_ok = _ports(rule.first("destination", "port"))
            tport = rule.first("inside-address", "port") or rule.first("translation", "port")
            target_port = int(tport) if tport and tport.isdigit() else None
            out.forwards.append(
                PortForward(
                    name=name,
                    enabled=enabled,
                    protocols=protocols,
                    zones=[in_if] if in_if else [],
                    external_address=_address(rule, "destination", "address"),
                    external_ports=ext,
                    sources=src_net,
                    target_address=target,
                    target_port=target_port,
                    passes_filter=False,
                    exact=exact and ext_ok and src_ok,
                )
            )
            if in_if:
                out.zone_names.add(in_if)
    # EdgeOS "port-forward" wizard: rule N { forward-to { address, port }, original-port, protocol }
    pf = root.get("port-forward")
    if pf is not None:
        wan = pf.first("wan-interface")
        auto = pf.has("auto-firewall") and pf.first("auto-firewall") == "enable"
        hairpin = pf.first("hairpin-nat") == "enable" if pf.has("hairpin-nat") else None
        for number, rule in pf.items("rule"):
            target = _address(rule, "forward-to", "address")
            if target is None:
                out.complete = False
                continue
            ext, ext_ok = _ports(rule.first("original-port"))
            tport = rule.first("forward-to", "port")
            out.forwards.append(
                PortForward(
                    name=rule.first("description") or f"port-forward {number}",
                    protocols=_PROTOCOLS.get(rule.first("protocol") or "tcp_udp", []),
                    zones=[wan] if wan else [],
                    external_ports=ext,
                    target_address=target,
                    target_port=int(tport) if tport and tport.isdigit() else None,
                    passes_filter=auto,
                    reflection=hairpin,
                    exact=ext_ok,
                )
            )
            if wan:
                out.zone_names.add(wan)
    return out


def unsupported_firewall(root: Node) -> list[str]:
    """Parts of the firewall this reader does not map (named in a gap)."""
    found = []
    if root.has("zone-policy"):
        found.append("zone-policy")
    if root.has("firewall", "zone"):
        found.append("firewall zone")
    for key in ("ipv4", "ipv6"):
        if root.has("firewall", key):
            found.append(f"firewall {key}")
    return found


_RANGE = re.compile(r"^\d+-\d+$")
