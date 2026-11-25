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
a rate limit, time of day) is ``exact = False``. VyOS 1.4 and newer renamed the
firewall: base chains ``firewall ipv4|ipv6 forward|input|output filter`` with numbered rules that
name their interfaces (``inbound-interface name eth0``) and named chains
(``firewall ipv4 name X``) that a rule enters with ``action jump``. They are read into the same
model (:func:`_new_rules`): a base chain is the chain of that name, a jump to a named chain is
unrolled in place under the zones of the jump rule, the default action of a named chain closes
that part. Zone-based firewalls (``firewall zone``) are named in a gap (#389, #495).
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


def _states(rule: Node) -> set[str]:
    """The connection states a rule matches: ``state new enable`` (EdgeOS, VyOS 1.3) or the
    values of ``state new`` (VyOS 1.4 and newer)."""
    return {
        s for s, n in rule.items("state") if n.has("enable") or (not n.children and s != "disable")
    }


def _rule(
    name: str,
    number: str,
    rule: Node,
    chain: FirewallChain,
    family: Literal[4, 6],
    zone: str,
    direction: str,
) -> FirewallRule | None:
    return _build(
        name,
        number,
        rule,
        chain,
        family,
        None if direction == "out" else zone,
        zone if direction == "out" else None,
    )


def _build(
    name: str,
    number: str,
    rule: Node,
    chain: FirewallChain,
    family: Literal[4, 6],
    src_zone: str | None,
    dst_zone: str | None,
    inexact: bool = False,
    other: tuple[str, ...] = _OTHER_CONDITIONS,
) -> FirewallRule | None:
    action = _ACTIONS.get(rule.first("action") or "")
    if action is None:  # inspect, modify, queue: not an allow or deny decision
        return None
    states = _states(rule)
    if states and "new" not in states:  # established/related/invalid: not a new connection
        return None
    exact = (
        not inexact
        and not any(rule.has(word) for word in other)
        and not (states and states != {"new"})
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
    source, src_ok = _end(rule.get("source"), rule, "", "source")
    destination, dst_ok = _end(rule.get("destination"), rule, "", "destination")
    if dst_zone:
        destination = destination.model_copy(update={"zones": [dst_zone]})
    if src_zone:
        source = source.model_copy(update={"zones": [src_zone]})
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
    if vyos_14 or root.has("firewall", "ipv4") or root.has("firewall", "ipv6"):
        return _new_rules(root)
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


#: What a rule of VyOS 1.4 and newer may carry that the model has no field for.
_NEW_OTHER = (
    *_OTHER_CONDITIONS,
    "connection-status",
    "hop-limit",
    "ttl",
    "icmpv6",
    "gre",
    "vlan",
    "conntrack-helper",
    "geoip",
    "synproxy",
)
#: Keys of a jump rule that are not a condition of the traffic.
_NOT_CONDITIONS = {
    "action",
    "jump-target",
    "description",
    "disable",
    "log",
    "log-options",
    "inbound-interface",
    "outbound-interface",
    "state",
}
_BASE_CHAINS = (
    ("forward", FirewallChain.FORWARD),
    ("input", FirewallChain.INPUT),
    ("output", FirewallChain.OUTPUT),
)
_MAX_JUMPS = 4


def _rule_interface(rule: Node, key: str) -> tuple[str | None, bool]:
    """``inbound-interface name eth0`` (1.4 and newer; ``interface-name`` in early 1.4 builds) ->
    (interface, understood). Groups, wildcards and negations name no single zone."""
    node = rule.get(key)
    if node is None:
        return None, True
    if node.has("group"):
        return None, False
    name = node.first("name") or node.first("interface-name")
    if name is None:
        words = [w for w in node.children if w not in ("name", "interface-name", "group")]
        name = words[0] if words else None
    if name is None or name.startswith("!") or "*" in name:
        return None, False
    return name, True


def _new_rules(root: Node) -> Rules:
    """``firewall ipv4|ipv6 forward|input|output filter`` of VyOS 1.4 and newer."""
    out = Rules()
    firewall = root.get("firewall")
    if firewall is None:
        return out
    for family_word, family in (("ipv4", 4), ("ipv6", 6)):
        fam = firewall.get(family_word)
        if fam is None:
            continue
        fam_n: Literal[4, 6] = 4 if family == 4 else 6
        for word, chain in _BASE_CHAINS:
            base = fam.get(word, "filter")
            if base is None:
                continue
            label = f"{family_word} {word}"
            _walk(out, fam, base, label, chain, fam_n, None, None, False, (), 0)
            closing = _ACTIONS.get(base.first("default-action") or "accept")
            if closing is not None:
                out.rules.append(
                    FirewallRule(
                        name=f"{label} default",
                        chain=chain,
                        family=fam_n,
                        action=closing,
                    )
                )
            out.applied = True
    return out


def _walk(
    out: Rules,
    fam: Node,
    chain_node: Node,
    label: str,
    chain: FirewallChain,
    family: Literal[4, 6],
    src: str | None,
    dst: str | None,
    inexact: bool,
    seen: tuple[str, ...],
    depth: int,
) -> None:
    numbers = sorted(chain_node.keys("rule"), key=lambda x: int(x) if x.isdigit() else 0)
    for number in numbers:
        rule = chain_node.get("rule", number)
        assert rule is not None
        action = rule.first("action")
        r_src, ok_in = _rule_interface(rule, "inbound-interface")
        r_dst, ok_out = _rule_interface(rule, "outbound-interface")
        src_zone, dst_zone = r_src or src, r_dst or dst
        for zone in (src_zone, dst_zone):
            if zone:
                out.zone_names.add(zone)
        unsure = inexact or not (ok_in and ok_out)
        if action == "jump":
            _jump(
                out,
                fam,
                rule,
                label,
                number,
                chain,
                family,
                src_zone,
                dst_zone,
                unsure,
                seen,
                depth,
            )
            continue
        if action == "return":
            out.complete = False
            continue
        built = _build(label, number, rule, chain, family, src_zone, dst_zone, unsure, _NEW_OTHER)
        if built is not None:
            out.rules.append(built)


def _jump(
    out: Rules,
    fam: Node,
    rule: Node,
    label: str,
    number: str,
    chain: FirewallChain,
    family: Literal[4, 6],
    src: str | None,
    dst: str | None,
    inexact: bool,
    seen: tuple[str, ...],
    depth: int,
) -> None:
    """Unroll ``action jump`` / ``jump-target X`` in place: the rules of ``firewall ipv4 name X``
    under the interfaces of the jump rule, closed by the chain's default action (drop when the
    chain names none, as VyOS does). A condition of the jump rule the model has no field for
    makes the rules inexact."""
    if rule.has("disable"):
        return
    target = rule.first("jump-target")
    node = fam.get("name", target) if target else None
    if target is None or node is None or target in seen or depth >= _MAX_JUMPS:
        out.complete = False
        out.gaps.append(
            (
                f"firewall: {label} rule {number} jumps to the chain {target or '?'}, which is "
                "not defined or too deeply nested",
                "edgeos.ruleSetMissing",
                {"interface": f"{label} rule {number}", "name": target or "?"},
            )
        )
        return
    conditions = any(k not in _NOT_CONDITIONS for k in rule.children)
    states = _states(rule)
    inexact = inexact or conditions or bool(states and states != {"new"})
    if states and "new" not in states:  # the jump only sees established traffic
        return
    _walk(out, fam, node, target, chain, family, src, dst, inexact, (*seen, target), depth + 1)
    closing = _ACTIONS.get(node.first("default-action") or "drop")
    if closing is None:  # return, jump, queue: the rest of the calling chain decides
        out.complete = False
        return
    out.rules.append(
        FirewallRule(
            name=f"{target} default",
            chain=chain,
            family=family,
            source=FirewallMatch(zones=[src] if src else []),
            destination=FirewallMatch(zones=[dst] if dst else []),
            action=closing,
            exact=not inexact,
        )
    )


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
    return found


_RANGE = re.compile(r"^\d+-\d+$")
