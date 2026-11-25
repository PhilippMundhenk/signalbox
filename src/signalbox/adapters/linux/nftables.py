"""The nftables ruleset (``nft -j list ruleset``) as firewall rules, NAT and port forwards (#135).

Base chains of type ``filter`` on the hooks ``input`` and ``forward`` become the model's rules
in evaluation order (several base chains on one hook are merged where that is exact, else the
rules are incomplete); chains of type ``nat`` on ``prerouting`` (``dnat``) and ``postrouting``
(``masquerade``, ``snat``) become port forwards and NAT rules. ``jump`` and ``goto`` to regular
chains are flattened with the jump's conditions merged into the rules of the target. Every
interface named by ``iifname``/``oifname`` is a zone of its own (the adapter maps it).

Only new connections are modelled: a rule that matches established/related/invalid state only
is left out. A condition the model cannot express (marks, limits, ``xt`` matches of
iptables-nft, a set that is empty or cannot be resolved, ICMP types) keeps the rule but makes
it ``exact = False``; a verdict map, a jump to an unknown chain or a base chain that cannot be
merged make the rules incomplete (``Parsed.complete`` is false and ``gaps`` says why).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from ipaddress import ip_address, ip_network, summarize_address_range
from typing import Any

from pydantic import ValidationError

from signalbox.model import (
    FirewallAction,
    FirewallChain,
    FirewallMatch,
    FirewallProtocol,
    FirewallRule,
    IPNetwork,
    NatRule,
    PortForward,
    PortRange,
)

MAX_DEPTH = 8
TCP, UDP = FirewallProtocol.TCP, FirewallProtocol.UDP
_PROTOCOLS = {
    "tcp": TCP,
    "udp": UDP,
    "icmp": FirewallProtocol.ICMP,
    "icmpv6": FirewallProtocol.ICMP,
    "ipv6-icmp": FirewallProtocol.ICMP,
    "esp": FirewallProtocol.ESP,
    "gre": FirewallProtocol.GRE,
}
_VERDICTS = {
    "accept": FirewallAction.ACCEPT,
    "drop": FirewallAction.DROP,
    "reject": FirewallAction.REJECT,
}
#: Statements without an effect on whether a new connection passes.
_HARMLESS = frozenset({"counter", "log", "mangle", "notrack", "flow", "set", "meter", "comment"})
_NO_NEW = frozenset({"established", "related", "invalid"})

Key = tuple[str, str]  # (family, table)
ChainKey = tuple[str, str, str]  # (family, table, chain)


@dataclass
class Cond:
    """What a rule matches, built up from its expressions (``None``: unconstrained)."""

    family: int | None = None
    protocols: list[FirewallProtocol] | None = None
    src_zones: list[str] | None = None
    src_zones_not: bool = False
    dst_zones: list[str] | None = None
    dst_zones_not: bool = False
    src_nets: list[IPNetwork] | None = None
    src_nets_not: bool = False
    dst_nets: list[IPNetwork] | None = None
    dst_nets_not: bool = False
    src_ports: list[PortRange] | None = None
    dst_ports: list[PortRange] | None = None
    forwarded: bool | None = None
    exact: bool = True
    #: Never matches a new connection (established/related/invalid only, an impossible merge).
    skip: bool = False

    def conditional(self) -> bool:
        return not self.exact or any(
            v is not None
            for v in (
                self.family,
                self.protocols,
                self.src_zones,
                self.dst_zones,
                self.src_nets,
                self.dst_nets,
                self.src_ports,
                self.dst_ports,
                self.forwarded,
            )
        )

    def merge(self, inner: Cond) -> Cond:
        """Both conditions hold (a jump's conditions and a rule of the chain it jumps to)."""
        out = replace(self, exact=self.exact and inner.exact, skip=self.skip or inner.skip)
        if inner.family is not None:
            if out.family not in (None, inner.family):
                out.skip = True
            out.family = inner.family if out.family is None else out.family
        if inner.forwarded is not None:
            if out.forwarded not in (None, inner.forwarded):
                out.skip = True
            out.forwarded = inner.forwarded
        if inner.protocols is not None:
            both = (
                inner.protocols
                if out.protocols is None
                else [p for p in out.protocols if p in inner.protocols]
            )
            out.protocols = both
            out.skip = out.skip or not both
        for attr in ("zones", "nets"):
            for side in ("src", "dst"):
                self._merge_list(out, inner, f"{side}_{attr}", f"{side}_{attr}_not")
        for attr in ("src_ports", "dst_ports"):
            self._merge_list(out, inner, attr, None)
        return out

    @staticmethod
    def _merge_list(out: Cond, inner: Cond, attr: str, negated: str | None) -> None:
        theirs = getattr(inner, attr)
        if theirs is None:
            return
        mine = getattr(out, attr)
        if mine is None:
            setattr(out, attr, theirs)
            if negated:
                setattr(out, negated, getattr(inner, negated))
            return
        same_sign = not negated or getattr(out, negated) == getattr(inner, negated)
        if mine != theirs or not same_sign:
            out.exact = False  # two different conditions on the same field: a maybe
            setattr(out, attr, theirs)
            if negated:
                setattr(out, negated, getattr(inner, negated))

    def inexact(self) -> Cond:
        return replace(self, exact=False)


@dataclass
class Term:
    """The deciding statement of a rule."""

    kind: str  # accept drop reject jump goto return dnat snat masquerade redirect vmap
    arg: Any = None


@dataclass
class Item:
    cond: Cond
    term: Term | None
    comment: str | None = None


@dataclass
class Parsed:
    rules: list[FirewallRule] = field(default_factory=list)
    port_forwards: list[PortForward] = field(default_factory=list)
    nat: list[NatRule] = field(default_factory=list)
    #: Interface names the rules, forwards and NAT rules refer to.
    zone_names: set[str] = field(default_factory=set)
    input_policy: FirewallAction | None = FirewallAction.ACCEPT
    forward_policy: FirewallAction | None = FirewallAction.ACCEPT
    #: Some chain filters (else the box accepts everything).
    enabled: bool = False
    complete: bool = True
    port_forwards_complete: bool = True
    gaps: list[NftGap] = field(default_factory=list)


class NftGap(str):
    """A gap text with its translation id and values (#204); it is the English text as a string."""

    message_id: str
    params: dict[str, str]

    def __new__(cls, message: str, message_id: str, **params: str) -> NftGap:
        gap = super().__new__(cls, message)
        gap.message_id = message_id
        gap.params = {"source": "nftables", **params}
        return gap

    def named(self, source: str) -> NftGap:
        """The same gap naming the real source (``iptables`` for ``iptables-save`` input, #404)."""
        text = source + self[len("nftables") :] if self.startswith("nftables") else str(self)
        return NftGap(text, self.message_id, **{**self.params, "source": source})


@dataclass
class _Chain:
    key: ChainKey
    type: str | None
    hook: str | None
    prio: int
    policy: FirewallAction | None


def _unwrap(x: Any) -> Any:
    if isinstance(x, dict) and "elem" in x:
        x = x["elem"]
        if isinstance(x, dict) and "val" in x:
            x = x["val"]
    return x


def _nets(items: list[Any]) -> list[IPNetwork] | None:
    out: list[IPNetwork] = []
    try:
        for x in items:
            if isinstance(x, str):
                out.append(ip_network(x, strict=False))
            elif isinstance(x, dict) and "prefix" in x:
                p = x["prefix"]
                out.append(ip_network(f"{p['addr']}/{p['len']}", strict=False))
            elif isinstance(x, dict) and "range" in x:
                a, b = x["range"]
                out += list(summarize_address_range(ip_address(a), ip_address(b)))
            else:
                return None
    except (ValueError, KeyError, TypeError):
        return None
    return out


def _ports(items: list[Any]) -> list[PortRange] | None:
    out: list[PortRange] = []
    try:
        for x in items:
            if isinstance(x, int) and not isinstance(x, bool):
                out.append(PortRange(start=x))
            elif isinstance(x, str) and x.isdigit():
                out.append(PortRange(start=int(x)))
            elif isinstance(x, dict) and "range" in x:
                a, b = x["range"]
                out.append(PortRange(start=int(a), end=int(b)))
            else:
                return None
    except (ValueError, TypeError, ValidationError):
        return None
    return out


def _names(items: list[Any]) -> list[str] | None:
    return list(items) if all(isinstance(x, str) and x for x in items) else None


class _Reader:
    def __init__(self, objects: list[dict[str, Any]]) -> None:
        self.chains: dict[ChainKey, _Chain] = {}
        self.rules: dict[ChainKey, list[dict[str, Any]]] = {}
        self.sets: dict[tuple[str, str, str], list[Any]] = {}
        self.gaps: list[NftGap] = []
        self.parsed = Parsed()
        for obj in objects:
            if "chain" in obj:
                c = obj["chain"]
                key = (c["family"], c["table"], c["name"])
                pol = c.get("policy")
                self.chains[key] = _Chain(
                    key,
                    c.get("type"),
                    c.get("hook"),
                    int(c.get("prio", 0)),
                    _VERDICTS.get(pol) if pol else None,
                )
            elif "rule" in obj:
                r = obj["rule"]
                self.rules.setdefault((r["family"], r["table"], r["chain"]), []).append(r)
            elif "set" in obj:
                s = obj["set"]
                self.sets[(s["family"], s["table"], s["name"])] = list(s.get("elem") or [])

    # conditions ------------------------------------------------------------------------------

    def _items(self, right: Any, key: ChainKey) -> list[Any] | None:
        if isinstance(right, dict) and "set" in right:
            raw = right["set"]
        elif isinstance(right, str) and right.startswith("@"):
            raw = self.sets.get((key[0], key[1], right[1:]))
            if not raw:  # unknown, empty or filled at run time
                return None
        else:
            raw = [right]
        return [_unwrap(x) for x in raw]

    def _match(self, m: dict[str, Any], c: Cond, key: ChainKey) -> None:
        op, left = m.get("op", "=="), m.get("left", {})
        items = self._items(m.get("right"), key)
        if op not in ("==", "!=", "in") or items is None or not isinstance(left, dict):
            c.exact = False
            return
        neg = op == "!="
        if "meta" in left:
            self._meta(left["meta"].get("key"), items, neg, c)
        elif "payload" in left:
            self._payload(left["payload"], items, neg, c)
        elif "ct" in left:
            self._ct(left["ct"].get("key"), items, neg, c)
        else:
            c.exact = False

    def _meta(self, key: Any, items: list[Any], neg: bool, c: Cond) -> None:
        if key in ("iifname", "iif", "oifname", "oif"):
            names = _names(items)
            side = "src" if key.startswith("i") else "dst"
            if names is None or getattr(c, f"{side}_zones") is not None:
                c.exact = False
                return
            setattr(c, f"{side}_zones", names)
            setattr(c, f"{side}_zones_not", neg)
        elif key == "l4proto" and not neg:
            protos: list[FirewallProtocol] = []
            for x in items:
                name = str(x).lower()
                protos.append(_PROTOCOLS.get(name, FirewallProtocol.OTHER))
            self._protocols(c, protos)
        elif key == "nfproto" and len(items) == 1 and items[0] in ("ipv4", "ipv6"):
            fam = 4 if items[0] == "ipv4" else 6
            c.family = fam if not neg else 10 - fam
        else:
            c.exact = False

    @staticmethod
    def _protocols(c: Cond, protos: list[FirewallProtocol]) -> None:
        if c.protocols is None:
            c.protocols = protos
        else:
            c.protocols = [p for p in c.protocols if p in protos]
            c.skip = c.skip or not c.protocols

    def _payload(self, p: dict[str, Any], items: list[Any], neg: bool, c: Cond) -> None:
        proto, fld = p.get("protocol"), p.get("field")
        if proto in ("ip", "ip6") and fld in ("saddr", "daddr"):
            nets = _nets(items)
            fam = 4 if proto == "ip" else 6
            side = "src" if fld == "saddr" else "dst"
            if c.family not in (None, fam):
                c.skip = True
            c.family = fam
            if nets is None or getattr(c, f"{side}_nets") is not None:
                c.exact = False
                return
            setattr(c, f"{side}_nets", nets)
            setattr(c, f"{side}_nets_not", neg)
        elif proto in ("tcp", "udp", "th") and fld in ("sport", "dport"):
            ports = _ports(items)
            if proto != "th":
                self._protocols(c, [_PROTOCOLS[proto]])
            attr = "src_ports" if fld == "sport" else "dst_ports"
            if neg or ports is None or getattr(c, attr) is not None:
                c.exact = False
                return
            setattr(c, attr, ports)
        elif proto in ("icmp", "icmpv6"):
            self._protocols(c, [FirewallProtocol.ICMP])
            c.exact = False  # the ICMP type is not modelled
        else:
            c.exact = False

    def _ct(self, key: Any, items: list[Any], neg: bool, c: Cond) -> None:
        names = {str(x).lower() for x in items}
        if key == "state" and not neg:
            if names & {"new", "untracked"}:
                if names - {"new", "untracked", *_NO_NEW}:
                    c.exact = False
            elif names <= _NO_NEW:
                c.skip = True
            else:
                c.exact = False
        elif key == "status" and not neg and names == {"dnat"}:
            c.forwarded = True
        else:
            c.exact = False

    # rules -----------------------------------------------------------------------------------

    def _rule(self, rule: dict[str, Any]) -> Item:
        key = (rule["family"], rule["table"], rule["chain"])
        c = Cond(family={"ip": 4, "ip6": 6}.get(rule["family"]))
        term: Term | None = None
        for e in rule.get("expr", []):
            if "match" in e:
                self._match(e["match"], c, key)
                continue
            name = next(iter(e), None)
            if name in _VERDICTS:
                term = Term(name)
            elif name in ("jump", "goto"):
                term = Term(name, e[name].get("target"))
            elif name == "return":
                term = Term("return")
            elif name in ("dnat", "snat", "redirect"):
                term = Term(name, e[name])
            elif name == "masquerade":
                term = Term("masquerade", e[name])
            elif name == "vmap":
                term = Term("vmap")
            elif name in _HARMLESS:
                continue
            else:  # limit, quota, xt, ...: a condition (or a side effect) the model lacks
                c.exact = False
        return Item(c, term, rule.get("comment"))

    def flatten(self, key: ChainKey, stack: tuple[ChainKey, ...] = ()) -> list[Item]:
        """The rules of a chain with ``jump`` and ``goto`` replaced by the target's rules."""
        out: list[Item] = []
        degraded = False  # after a conditional return or goto: the rest only maybe applies
        for raw in self.rules.get(key, []):
            item = self._rule(raw)
            c = item.cond.inexact() if degraded else item.cond
            t = item.term
            if c.skip or t is None:
                continue
            if t.kind in ("jump", "goto"):
                target = (key[0], key[1], str(t.arg))
                if target in stack or len(stack) >= MAX_DEPTH or target not in self.chains:
                    self.gaps.append(
                        NftGap(
                            f"nftables: {t.kind} to chain {t.arg!r} cannot be followed "
                            "(unknown chain or a loop)",
                            "linux.nft.chainJump",
                            kind=str(t.kind),
                            chain=repr(t.arg),
                        )
                    )
                    self.parsed.complete = False
                    continue
                for inner in self.flatten(target, (*stack, key)):
                    out.append(Item(c.merge(inner.cond), inner.term, inner.comment or item.comment))
                if t.kind == "goto":
                    if not item.cond.conditional():
                        break
                    degraded = True
                continue
            if t.kind == "return":
                if not item.cond.conditional():
                    break
                degraded = True
                continue
            if t.kind == "vmap":
                self.gaps.append(
                    NftGap("nftables: a verdict map (vmap) is not read", "linux.nft.vmap")
                )
                self.parsed.complete = False
                continue
            out.append(Item(c, t, item.comment))
        return out


def _to_rule(item: Item, chain: FirewallChain, order: int) -> FirewallRule:
    c, t = item.cond, item.term
    assert t is not None
    protocols = list(c.protocols or [])
    if (c.src_ports or c.dst_ports) and not protocols:
        protocols = [TCP, UDP]
    if chain is FirewallChain.INPUT and c.dst_zones:
        c = c.inexact()  # an output interface on traffic to the device: cannot match
    return FirewallRule(
        name=item.comment,
        order=order,
        chain=chain,
        family=c.family if c.family in (4, 6) else None,
        protocols=protocols,
        source=FirewallMatch(
            zones=c.src_zones or [],
            zones_not=c.src_zones_not and bool(c.src_zones),
            networks=c.src_nets or [],
            networks_not=c.src_nets_not and bool(c.src_nets),
            ports=c.src_ports or [],
        ),
        destination=FirewallMatch(
            zones=[] if chain is FirewallChain.INPUT else c.dst_zones or [],
            zones_not=c.dst_zones_not and bool(c.dst_zones) and chain is FirewallChain.FORWARD,
            networks=c.dst_nets or [],
            networks_not=c.dst_nets_not and bool(c.dst_nets),
            ports=c.dst_ports or [],
        ),
        action=_VERDICTS[t.kind],
        forwarded=c.forwarded,
        exact=c.exact,
    )


def _families(family: str) -> set[int]:
    return {"ip": {4}, "ip6": {6}, "inet": {4, 6}}.get(family, set())


def parse(text: str, source: str = "nftables") -> Parsed:
    """Rules, forwards and NAT of ``nft -j list ruleset``; ``ValueError`` for anything else.

    ``source`` names where the rules came from in the gap texts (``iptables``: legacy reader).
    """
    try:
        data = json.loads(text)
        objects = [o for o in data["nftables"] if isinstance(o, dict)]
        reader = _Reader(objects)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError(f"not an nftables ruleset: {exc}") from None
    out = reader.parsed
    _filter(reader, out)
    _nat(reader, out)
    out.gaps = [g.named(source) for g in reader.gaps]
    for r in out.rules:
        out.zone_names |= {*r.source.zones, *r.destination.zones}
    for f in out.port_forwards:
        out.zone_names |= set(f.zones)
    for n in out.nat:
        out.zone_names |= set(n.zones)
    return out


def _filter(reader: _Reader, out: Parsed) -> None:
    flattened: dict[ChainKey, list[Item]] = {}
    for hook, chain in (("input", FirewallChain.INPUT), ("forward", FirewallChain.FORWARD)):
        chains = sorted(
            (
                c
                for c in reader.chains.values()
                if c.hook == hook and c.type == "filter" and _families(c.key[0])
            ),
            key=lambda c: (c.prio, c.key),
        )
        live: list[_Chain] = []
        for c in chains:
            flattened[c.key] = [i for i in reader.flatten(c.key) if i.term is not None]
            if flattened[c.key] or c.policy is not FirewallAction.ACCEPT:
                live.append(c)
        for n, c in enumerate(live):
            later = [x for x in live[n + 1 :] if _families(x.key[0]) & _families(c.key[0])]
            only_drops = c.policy is FirewallAction.ACCEPT and all(
                i.term and i.term.kind != "accept" for i in flattened[c.key]
            )
            if later and not only_drops:
                out.complete = False
                reader.gaps.append(
                    NftGap(
                        f"nftables: several base chains on the {hook} hook "
                        f"({c.key[1]} {c.key[2]} and {later[0].key[1]} {later[0].key[2]}) "
                        "cannot be merged",
                        "linux.nft.severalBase",
                        hook=str(hook),
                        first=f"{c.key[1]} {c.key[2]}",
                        second=f"{later[0].key[1]} {later[0].key[2]}",
                    )
                )
                break
        for c in live:
            for i in flattened[c.key]:
                out.rules.append(_to_rule(i, chain, len(out.rules) + 1))
        policies = set()
        for fam in (4, 6):
            covering = [c for c in live if fam in _families(c.key[0])]
            policies.add(covering[-1].policy if covering else FirewallAction.ACCEPT)
        value = policies.pop() if len(policies) == 1 else None
        if hook == "input":
            out.input_policy = value
        else:
            out.forward_policy = value
        out.enabled = out.enabled or bool(live)
    _ignored_hooks(reader, out)


def _ignored_hooks(reader: _Reader, out: Parsed) -> None:
    """Filter chains on other hooks that drop traffic (raw, mangle, ingress) are not modelled."""
    for c in reader.chains.values():
        if c.type != "filter" or c.hook not in ("prerouting", "ingress", "egress"):
            continue
        drops = c.policy not in (None, FirewallAction.ACCEPT) or any(
            i.term and i.term.kind in ("drop", "reject") for i in reader.flatten(c.key)
        )
        if drops:
            out.complete = False
            reader.gaps.append(
                NftGap(
                    f"nftables: the {c.hook} chain {c.key[2]} of table {c.key[1]} drops traffic "
                    "and is not modelled",
                    "linux.nft.dropChain",
                    hook=str(c.hook),
                    chain=str(c.key[2]),
                    table=str(c.key[1]),
                )
            )


def _single(nets: list[IPNetwork] | None, negated: bool) -> IPNetwork | None:
    if nets and len(nets) == 1 and not negated:
        return nets[0]
    return None


def _nat(reader: _Reader, out: Parsed) -> None:
    for c in sorted(reader.chains.values(), key=lambda c: (c.prio, c.key)):
        if (
            c.type != "nat"
            or c.hook not in ("prerouting", "postrouting")
            or not _families(c.key[0])
        ):
            continue
        shadowed = False  # an earlier accept/drop may exempt traffic from the rules after it
        for item in reader.flatten(c.key):
            t, cond = item.term, item.cond
            assert t is not None
            if t.kind in ("accept", "drop", "reject"):
                shadowed = True
                continue
            if shadowed:
                cond = cond.inexact()
            if c.hook == "prerouting" and t.kind == "dnat":
                _forward(out, item, cond, t.arg or {})
            elif c.hook == "prerouting" and t.kind == "redirect":
                out.port_forwards_complete = False  # to the device itself
                reader.gaps.append(
                    NftGap(
                        "nftables: a redirect rule is not read as a port forward",
                        "linux.nft.redirect",
                    )
                )
            elif c.hook == "postrouting" and t.kind in ("masquerade", "snat"):
                _source_nat(out, item, cond, t)


def _forward(out: Parsed, item: Item, c: Cond, arg: dict[str, Any]) -> None:
    addr, port = arg.get("addr"), arg.get("port")
    try:
        target = ip_address(str(addr))
    except (ValueError, TypeError):
        out.port_forwards_complete = False
        out.gaps.append(
            NftGap(
                "nftables: a dnat rule without a plain target address is not read",
                "linux.nft.dnat",
            )
        )
        return
    exact = c.exact and not c.src_zones_not
    external = _single(c.dst_nets, c.dst_nets_not)
    if c.dst_nets and (external is None or external.num_addresses != 1):
        exact = False
    target_port = port if isinstance(port, int) and 1 <= port <= 65535 else None
    if port is not None and target_port is None:
        exact = False
    protocols = list(c.protocols or [])
    if c.dst_ports and not protocols:
        protocols = [TCP, UDP]
    out.port_forwards.append(
        PortForward(
            name=item.comment,
            protocols=protocols,
            zones=[] if c.src_zones_not else list(c.src_zones or []),
            external_address=external.network_address
            if external is not None and external.num_addresses == 1
            else None,
            external_ports=list(c.dst_ports or []),
            sources=[] if c.src_nets_not else list(c.src_nets or []),
            target_address=target,
            target_port=target_port,
            passes_filter=False,
            exact=exact,
        )
    )


def _source_nat(out: Parsed, item: Item, c: Cond, t: Term) -> None:
    address = None
    if t.kind == "snat":
        try:
            address = ip_address(str((t.arg or {}).get("addr")))
        except (ValueError, TypeError):
            out.gaps.append(
                NftGap(
                    "nftables: an snat rule without a plain address is not read", "linux.nft.snat"
                )
            )
            out.complete = False
            return
    out.nat.append(
        NatRule(
            name=item.comment,
            zones=[] if c.dst_zones_not else list(c.dst_zones or []),
            sources=[] if c.src_nets_not else list(c.src_nets or []),
            masquerade=t.kind == "masquerade",
            to_address=address,
            exact=c.exact and not c.dst_zones_not and not c.dst_nets and not c.dst_ports,
        )
    )
