"""Legacy iptables as the firewall model (#394): ``iptables-save`` and ``ip6tables-save``.

Old systems (Debian 10 and 11, Raspberry Pi OS before Bookworm, Arch Linux ARM images before the
nf_tables switch) keep their rules in the legacy iptables backend, which ``nft`` does not show.
This reader turns the text of ``iptables-save`` / ``ip6tables-save`` into the object list of
``nft -j list ruleset`` and lets :mod:`signalbox.adapters.linux.nftables` map it, so both
readers give the same model (ADR 0013): the same zones, the same rule order, the same
completeness gaps. Mapping: ``filter`` (and ``mangle``/``raw``) built-in chains are base chains
on their hook with the policy of the ``:CHAIN POLICY`` line, user chains are regular chains
(``-j chain`` is a ``jump``, ``-g`` a ``goto``), ``nat`` ``PREROUTING`` ``DNAT`` is a port
forward, ``POSTROUTING`` ``MASQUERADE``/``SNAT`` a NAT rule. Modules this reader does not
know keep the rule with ``exact = False``. Nothing is run here: the text comes from the device.

Only reading: ``iptables-save`` prints the rules (no counters, no secrets).
"""

from __future__ import annotations

import json
import shlex
from typing import Any

from signalbox.adapters.linux import nftables

#: Built-in chain -> (hook, priority) per table.
_HOOKS: dict[str, dict[str, tuple[str, int]]] = {
    "filter": {"INPUT": ("input", 0), "FORWARD": ("forward", 0), "OUTPUT": ("output", 0)},
    "nat": {
        "PREROUTING": ("prerouting", -100),
        "INPUT": ("input", 100),
        "OUTPUT": ("output", -100),
        "POSTROUTING": ("postrouting", 100),
    },
    "mangle": {
        "PREROUTING": ("prerouting", -150),
        "INPUT": ("input", -150),
        "FORWARD": ("forward", -150),
        "OUTPUT": ("output", -150),
        "POSTROUTING": ("postrouting", -150),
    },
    "raw": {"PREROUTING": ("prerouting", -300), "OUTPUT": ("output", -300)},
}
_PROTO_NUMBERS = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "58": "ipv6-icmp"}
_TERMINAL = {"ACCEPT": "accept", "DROP": "drop", "REJECT": "reject"}
_ADDRESS_OPTIONS = {"-s": "saddr", "--source": "saddr", "-d": "daddr", "--destination": "daddr"}
_IFACE_OPTIONS = {"-i": "iifname", "--in-interface": "iifname", "-o": "oifname"}
_IFACE_OPTIONS["--out-interface"] = "oifname"


def _match(left: dict[str, Any], right: Any, negated: bool) -> dict[str, Any]:
    return {"match": {"op": "!=" if negated else "==", "left": left, "right": right}}


def _ports(value: str) -> Any:
    """``80``, ``1000:2000`` or a comma list of them (multiport) as nft JSON."""
    items: list[Any] = []
    for part in value.split(","):
        lo, sep, hi = part.partition(":")
        items.append({"range": [int(lo), int(hi)]} if sep else int(lo))
    return items[0] if len(items) == 1 else {"set": items}


def _address(value: str) -> Any:
    items = value.split(",")
    return items[0] if len(items) == 1 else {"set": items}


def _target_address(text: str) -> tuple[str, int | str | None]:
    """``--to-destination`` ``a``, ``a:p``, ``[v6]:p``, ``a-b``, ``a:p1-p2`` -> (address, port)."""
    port: int | str | None = None
    if text.startswith("["):
        addr, _, rest = text[1:].partition("]")
        rest = rest.removeprefix(":")
    elif text.count(":") == 1:
        addr, _, rest = text.partition(":")
    else:
        addr, rest = text, ""
    if rest:
        port = int(rest) if rest.isdigit() else rest
    return addr, port


class _Rule:
    """One ``-A`` line turned into nft expressions."""

    def __init__(self, tokens: list[str], chains: set[str]) -> None:
        self.chains = chains
        self.expr: list[dict[str, Any]] = []
        self.comment: str | None = None
        self.proto = ""
        self.exact = True
        self.tokens = tokens
        self.i = 0
        self.negate = False
        self.target = ""
        self.to: str | None = None

    def value(self) -> str:
        v = self.tokens[self.i] if self.i < len(self.tokens) else ""
        self.i += 1
        return v

    def skip_values(self) -> None:
        """Arguments of an option this reader does not know: up to the next option."""
        while self.i < len(self.tokens) and not self.tokens[self.i].startswith(("-", "!")):
            self.i += 1

    def parse(self, family: str) -> None:
        proto_name = "ip6" if family == "ip6" else "ip"
        while self.i < len(self.tokens):
            opt = self.tokens[self.i]
            self.i += 1
            if opt == "!":
                self.negate = True
                continue
            neg, self.negate = self.negate, False
            if self.target:
                self._target_option(opt)
            elif opt in ("-p", "--protocol"):
                self._protocol(self.value(), neg)
            elif opt in _ADDRESS_OPTIONS:
                left = {"payload": {"protocol": proto_name, "field": _ADDRESS_OPTIONS[opt]}}
                self.expr.append(_match(left, _address(self.value()), neg))
            elif opt in _IFACE_OPTIONS:
                name = self.value().replace("+", "*")
                self.expr.append(_match({"meta": {"key": _IFACE_OPTIONS[opt]}}, name, neg))
            elif opt in ("-m", "--match"):
                module = self.value()
                if module not in ("tcp", "udp", "multiport", "conntrack", "state", "comment"):
                    self.exact = False
                    self.skip_values()
            elif opt in ("-j", "--jump", "-g", "--goto"):
                self.target = self.value()
                if opt in ("-g", "--goto"):
                    self.target = f"goto:{self.target}"
            else:
                self._option(opt, neg)

    def _protocol(self, value: str, neg: bool) -> None:
        name = _PROTO_NUMBERS.get(value, value).lower()
        if name == "all":
            return
        self.proto = name
        self.expr.append(_match({"meta": {"key": "l4proto"}}, name, neg))

    def _option(self, opt: str, neg: bool) -> None:
        proto = self.proto if self.proto in ("tcp", "udp") else "th"
        if opt in ("--dport", "--destination-port", "--dports", "--destination-ports"):
            field = "dport"
        elif opt in ("--sport", "--source-port", "--sports", "--source-ports"):
            field = "sport"
        else:
            field = ""
        if field:
            try:
                right = _ports(self.value())
            except ValueError:
                self.exact = False
                return
            self.expr.append(_match({"payload": {"protocol": proto, "field": field}}, right, neg))
        elif opt in ("--ctstate", "--state"):
            names = [n.lower() for n in self.value().split(",")]
            if names == ["dnat"]:  # the pseudo state of conntrack: ct status dnat
                self.expr.append(_match({"ct": {"key": "status"}}, {"set": names}, neg))
            elif {"snat", "dnat"} & set(names):
                self.exact = False
            else:
                self.expr.append(_match({"ct": {"key": "state"}}, {"set": names}, neg))
        elif opt == "--ctstatus":
            names = [n.lower() for n in self.value().split(",")]
            self.expr.append(_match({"ct": {"key": "status"}}, {"set": names}, neg))
        elif opt == "--comment":
            self.comment = self.value()
        else:  # a condition the model lacks (limit, mark, icmp type, physdev, ...)
            self.exact = False
            self.skip_values()

    def _target_option(self, opt: str) -> None:
        if opt in ("--to-destination", "--to-source"):
            self.to = self.value()
        else:
            self.skip_values()

    def finish(self) -> list[dict[str, Any]]:
        """The expressions with the verdict (or nothing for a target without an effect)."""
        out = list(self.expr)
        if not self.exact:
            out.append({"xt": {"type": "match", "name": "iptables"}})
        t = self.target
        if t in _TERMINAL:
            out.append({_TERMINAL[t]: None})
        elif t == "RETURN":
            out.append({"return": None})
        elif t == "MASQUERADE":
            out.append({"masquerade": {}})
        elif t == "REDIRECT":
            out.append({"redirect": {}})
        elif t in ("DNAT", "SNAT") and self.to:
            addr, port = _target_address(self.to)
            arg: dict[str, Any] = {"addr": addr}
            if port is not None and t == "DNAT":
                arg["port"] = port
            elif port is not None:
                arg["addr"] = self.to  # SNAT with a port: not a plain address
            out.append({t.lower(): arg})
        elif t in ("DNAT", "SNAT"):
            out.append({t.lower(): {}})
        elif t.startswith("goto:"):
            out.append({"goto": {"target": t[5:]}})
        elif t in self.chains:
            out.append({"jump": {"target": t}})
        # LOG, MARK, TCPMSS, NFLOG, ...: no verdict, the rule is without an effect on the path
        return out


def objects(text: str, family: str) -> list[dict[str, Any]]:
    """The nft JSON objects (chains and rules) of one ``iptables-save`` text."""
    out: list[dict[str, Any]] = []
    table = ""
    declared: dict[str, set[str]] = {}
    for raw in text.splitlines():  # the chains of each table, to tell a jump from a target
        line = raw.strip()
        if line.startswith("*"):
            table = line[1:].strip()
        elif line.startswith(":") and table:
            declared.setdefault(table, set()).add(line[1:].split()[0])
    table = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:].strip()
        elif line == "COMMIT":
            table = ""
        elif line.startswith(":") and table:
            name, policy = [*line[1:].split(), "-"][:2]
            hook = _HOOKS.get(table, {}).get(name)
            chain: dict[str, Any] = {"family": family, "table": table, "name": name}
            if hook is not None:
                chain.update(
                    type="nat" if table == "nat" else "filter",
                    hook=hook[0],
                    prio=hook[1],
                    policy=policy.lower() if policy in ("ACCEPT", "DROP") else "accept",
                )
            out.append({"chain": chain})
        elif line.startswith("-A ") and table:
            try:
                tokens = shlex.split(line)
            except ValueError:
                continue
            rule = _Rule(tokens[2:], declared.get(table, set()))
            rule.parse(family)
            item: dict[str, Any] = {
                "family": family,
                "table": table,
                "chain": tokens[1],
                "expr": rule.finish(),
            }
            if rule.comment:
                item["comment"] = rule.comment
            out.append({"rule": item})
    return out


def parse(save4: str, save6: str = "") -> nftables.Parsed:
    """Rules, forwards and NAT of ``iptables-save`` (and ``ip6tables-save``) output."""
    both = objects(save4, "ip") + objects(save6, "ip6")
    return nftables.parse(json.dumps({"nftables": both}), source="iptables")


def has_rules(parsed: nftables.Parsed) -> bool:
    """Something filters or translates (a bare ACCEPT-everything table is no firewall)."""
    return bool(parsed.enabled or parsed.rules or parsed.nat or parsed.port_forwards)
