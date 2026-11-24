"""RouterOS ``/ip/firewall`` (filter, nat) and ``/ipv6/firewall/filter`` to the model (#135).

Pure functions on the rows of the REST API; the adapter fetches them and passes ``members`` (the
interfaces of every interface list) and a function that maps an interface name to model objects.

RouterOS semantics used here (*(guess)*: not yet confirmed against a router):

- the built-in chains ``input``, ``forward`` and ``output`` accept what no rule matches, so
  ``input_policy`` and ``forward_policy`` are ``accept``;
- rules are evaluated in list order, ``jump`` runs the rules of a user chain in place (their
  conditions joined with the jump rule's), ``return`` goes back, ``accept``, ``drop``, ``reject``
  and ``tarpit`` decide, ``passthrough``, ``log``, ``fasttrack-connection`` and the like do not;
- a rule without ``connection-state`` sees new connections; one that names only
  ``established``, ``related``, ``invalid`` or ``untracked`` does not (the model is stateful);
- ``connection-nat-state=dstnat`` is a port-forwarded connection;
- an interface list is a zone, a single interface a rule names is a zone of its own.

What Signalbox created (#295) is tagged by its comment: ``signalbox:<key>[ <name>]`` for a rule or
a port forward (the key is the declared name with ``-`` as ``_``; the name follows when it
differs) and ``signalbox:policy/<from>/<to|device>`` for a zone policy. The readers report the
first as ``signalbox_key`` and the policies as :class:`ZonePolicy`. Only rows of the base chains
``input`` and ``forward`` (of ``dstnat`` for forwards) carry the tag: what the writer
(write.py) produces and what a declared rule is compared with.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network, summarize_address_range
from typing import Any

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

#: Prefix of the comment of what Signalbox created, and of its zone policies after it.
TAG = "signalbox:"
POLICY_MARK = "policy/"

#: ``(segments, uplinks, tunnels, ports)`` of an interface; ``None``: it maps to nothing known.
Mapped = tuple[list[str], list[str], list[str], list[str]]
Mapper = Callable[[str], Mapped | None]

_DECIDING = {
    "accept": FirewallAction.ACCEPT,
    "drop": FirewallAction.DROP,
    "reject": FirewallAction.REJECT,
    "tarpit": FirewallAction.DROP,
}
_PROTOCOLS = {
    "tcp": FirewallProtocol.TCP,
    "6": FirewallProtocol.TCP,
    "udp": FirewallProtocol.UDP,
    "17": FirewallProtocol.UDP,
    "icmp": FirewallProtocol.ICMP,
    "1": FirewallProtocol.ICMP,
    "icmpv6": FirewallProtocol.ICMP,
    "ipv6-icmp": FirewallProtocol.ICMP,
    "58": FirewallProtocol.ICMP,
    "ipsec-esp": FirewallProtocol.ESP,
    "esp": FirewallProtocol.ESP,
    "50": FirewallProtocol.ESP,
    "gre": FirewallProtocol.GRE,
    "47": FirewallProtocol.GRE,
}
#: Conditions of a rule the model cannot express: setting one makes the rule inexact.
_INEXACT = (
    "src-mac-address",
    "limit",
    "dst-limit",
    "connection-limit",
    "connection-mark",
    "connection-bytes",
    "connection-rate",
    "connection-type",
    "packet-mark",
    "routing-mark",
    "time",
    "tls-host",
    "layer7-protocol",
    "content",
    "src-address-type",
    "dst-address-type",
    "hotspot",
    "random",
    "tcp-flags",
    "tcp-mss",
    "icmp-options",
    "port",
    "dscp",
    "ttl",
    "hop-limit",
    "nth",
    "packet-size",
    "psd",
    "per-connection-classifier",
    "ingress-priority",
    "in-bridge-port",
    "in-bridge-port-list",
    "out-bridge-port",
    "out-bridge-port-list",
    "src-port-list",
    "dst-port-list",
    "protocol-list",
    "headers",
    "dst-address-list-not",
)
_MAX_DEPTH = 8


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return value is True or _text(value).lower() in ("true", "yes", "on")


def _names(value: Any) -> list[str]:
    parts = value if isinstance(value, list) else _text(value).split(",")
    return [p.strip() for p in parts if isinstance(p, str) and p.strip()]


def tagged(row: dict[str, Any]) -> str | None:
    """What follows the tag in the comment of a row Signalbox created, else ``None`` (the
    device's own, or a dynamic row)."""
    if _flag(row.get("dynamic")):
        return None
    text = _text(row.get("comment"))
    return text[len(TAG) :] if text.startswith(TAG) and len(text) > len(TAG) else None


def key_of(name: str) -> str:
    """The key of a declared name (desired.firewall_key: ``-`` becomes ``_``)."""
    return name.replace("-", "_")


def describe(key: str, name: str) -> str:
    """The comment of a rule or forward Signalbox creates: ``signalbox:<key>``, and the name
    after a space when it is not the key."""
    return f"{TAG}{key}" + ("" if name == key else f" {name}")


def split_mark(mark: str) -> tuple[str, str]:
    """``(key, name)`` of what :func:`tagged` returns."""
    key, _, name = mark.partition(" ")
    return key, name or key


def _owned(row: dict[str, Any]) -> tuple[str, str] | None:
    """``(key, name)`` of a rule or forward of Signalbox's (not a zone policy)."""
    mark = tagged(row)
    if mark is None or mark.startswith(POLICY_MARK):
        return None
    return split_mark(mark)


def _is_set(row: dict[str, Any], key: str) -> bool:
    return _text(row.get(key)) not in ("", "none")


def _split_not(value: str) -> tuple[str, bool]:
    return (value[1:].strip(), True) if value.startswith("!") else (value, False)


@dataclass
class Lists:
    """Interface lists and address lists, as the router has them."""

    #: Interface list name -> the interface names in it (``include`` and ``exclude`` applied).
    interfaces: dict[str, list[str]] = field(default_factory=dict)
    #: Address list name -> its entries ``(address text, dynamic)``.
    addresses: dict[str, list[tuple[str, bool]]] = field(default_factory=dict)
    #: The router has IPsec policies: ``ipsec-policy`` conditions can match.
    ipsec: bool = False

    @classmethod
    def build(
        cls,
        lists: Iterable[dict[str, Any]],
        members: Iterable[dict[str, Any]],
        entries: Iterable[dict[str, Any]],
    ) -> Lists:
        out = cls()
        direct: dict[str, list[str]] = {}
        for m in members:
            name, iface = _text(m.get("list")), _text(m.get("interface"))
            if name and iface and not _flag(m.get("disabled")) and not _flag(m.get("invalid")):
                direct.setdefault(name, []).append(iface)
        rows = {_text(r.get("name")): r for r in lists if _text(r.get("name"))}

        def expand(name: str, seen: tuple[str, ...]) -> list[str]:
            if name in seen:
                return []
            row = rows.get(name, {})
            found = list(direct.get(name, []))
            for other in _names(row.get("include")):
                found += expand(other, (*seen, name))
            for other in _names(row.get("exclude")):
                gone = set(expand(other, (*seen, name)))
                found = [f for f in found if f not in gone]
            return list(dict.fromkeys(found))

        for name in {*rows, *direct}:
            out.interfaces[name] = expand(name, ())
        for e in entries:
            name, address = _text(e.get("list")), _text(e.get("address"))
            if name and address and not _flag(e.get("disabled")):
                out.addresses.setdefault(name, []).append((address, _flag(e.get("dynamic"))))
        return out


def _ipsec(row: dict[str, Any], lists: Lists) -> bool | None:
    """The ``ipsec-policy`` condition (``in,ipsec``, ``out,none``): ``None``: it can never match
    (no IPsec policy on the router), ``True``: it matches everything or is not set, ``False``:
    it depends on IPsec traffic (inexact)."""
    value = _text(row.get("ipsec-policy"))
    if not value or value == "none":
        return True
    if lists.ipsec:
        return False
    parts = [p.strip() for p in value.replace("!", "").split(",")]
    negated = "!" in value
    wants_ipsec = len(parts) > 1 and parts[1] in ("ipsec", "yes")
    # without any policy no packet is IPsec: "ipsec" never matches, "none" always does
    return True if wants_ipsec == negated else None


def addresses(value: Any, lists: Lists, lists_value: Any = None) -> tuple[list[IPNetwork], bool]:
    """``(networks, exact)`` of an address condition: a comma list of addresses, prefixes and
    ranges plus the entries of the address lists named. A host name, a dynamic entry (they
    come and go) or an unknown list makes it inexact."""
    out: list[IPNetwork] = []
    exact = True

    def add(text: str) -> bool:
        try:
            if "-" in text:
                first, _, last = text.partition("-")
                out.extend(
                    summarize_address_range(ip_address(first.strip()), ip_address(last.strip()))
                )
            else:
                out.append(ip_network(text, strict=False))
        except ValueError:
            return False
        return True

    for item in _names(value):
        exact = add(item) and exact
    for name in _names(lists_value):
        entries = lists.addresses.get(name)
        if entries is None:
            exact = False
            continue
        for text, dynamic in entries:
            exact = add(text) and not dynamic and exact
    return list(dict.fromkeys(out)), exact


def ports(value: Any) -> tuple[list[PortRange], bool]:
    out: list[PortRange] = []
    for item in _names(value):
        first, sep, last = item.partition("-")
        try:
            out.append(PortRange(start=int(first), end=int(last) if sep else None))
        except ValueError:
            return [], False
    return out, True


@dataclass
class _Zones:
    """Zone names used by rules, and what each is made of."""

    lists: Lists
    mapper: Mapper
    #: zone name -> (interface names, complete)
    used: dict[str, list[str]] = field(default_factory=dict)

    def of(self, list_value: Any, iface_value: Any) -> tuple[list[str], bool, bool]:
        """``(zone names, negated, exact)`` of ``in-interface-list`` / ``in-interface``."""
        names: list[str] = []
        negated = False
        exact = True
        for raw, is_list in ((list_value, True), (iface_value, False)):
            for item in _names(raw):
                item, neg = _split_not(item)
                negated = negated or neg
                if is_list:
                    if item == "all":
                        continue  # every interface: no condition
                    if item in ("none", "static", "dynamic"):
                        exact = False
                        continue
                    self.used[item] = list(self.lists.interfaces.get(item, []))
                    names.append(item)
                else:
                    zone = item if item not in self.lists.interfaces else f"{item} (interface)"
                    self.used[zone] = [item]
                    names.append(zone)
        return list(dict.fromkeys(names)), negated, exact


def _rule(
    row: dict[str, Any], zones: _Zones, lists: Lists, ipv6: bool, chain: FirewallChain | None
) -> FirewallRule | None:
    """A filter row as a rule (``None``: it does not filter new connections), ``chain`` the
    base chain it is evaluated in. The action is set by the caller for jumps."""
    action_text = _text(row.get("action"))
    state = _text(row.get("connection-state"))
    if state:
        wanted, neg = _split_not(state)
        states = set(_names(wanted))
        if ("new" in states) == neg:
            return None  # established, related, invalid or untracked only
    ipsec = _ipsec(row, lists)
    if ipsec is None:
        return None
    in_zones, in_neg, ok1 = zones.of(row.get("in-interface-list"), row.get("in-interface"))
    out_zones, out_neg, ok2 = zones.of(row.get("out-interface-list"), row.get("out-interface"))
    src_text, dst_text = _text(row.get("src-address")), _text(row.get("dst-address"))
    src_neg = src_text.startswith("!")
    dst_neg = dst_text.startswith("!")
    src_nets, ok3 = addresses(
        src_text.lstrip("!"), lists, _text(row.get("src-address-list")).lstrip("!")
    )
    dst_nets, ok4 = addresses(
        dst_text.lstrip("!"), lists, _text(row.get("dst-address-list")).lstrip("!")
    )
    src_neg = src_neg or _text(row.get("src-address-list")).startswith("!")
    dst_neg = dst_neg or _text(row.get("dst-address-list")).startswith("!")
    exact = ok1 and ok2 and ok3 and ok4 and ipsec
    protocol = _text(row.get("protocol"))
    protocols: list[FirewallProtocol] = []
    if protocol:
        value, neg = _split_not(protocol)
        known = _PROTOCOLS.get(value.lower())
        if neg:
            exact = False
        elif known is not None:
            protocols = [known]
        elif value.lower() in ("tcp,udp", "udp,tcp"):
            protocols = [FirewallProtocol.TCP, FirewallProtocol.UDP]
        else:
            protocols = [FirewallProtocol.OTHER]
    dport_text, sport_text = _text(row.get("dst-port")), _text(row.get("src-port"))
    dst_ports, ok5 = ports(dport_text.lstrip("!"))
    src_ports, ok6 = ports(sport_text.lstrip("!"))
    exact = (
        exact and ok5 and ok6 and not dport_text.startswith("!") and not sport_text.startswith("!")
    )
    exact = exact and not any(_is_set(row, k) for k in _INEXACT)
    nat_state = _text(row.get("connection-nat-state"))
    forwarded: bool | None = None
    if nat_state:
        value, neg = _split_not(nat_state)
        if value == "dstnat":
            forwarded = not neg
        else:
            exact = False
    owned = _owned(row) if _text(row.get("chain")) in ("input", "forward") else None
    return FirewallRule(
        name=owned[1] if owned else (_text(row.get("comment")) or None),
        signalbox_key=owned[0] if owned else None,
        enabled=not _flag(row.get("disabled")),
        chain=chain,
        family=6 if ipv6 else 4,
        protocols=protocols,
        source=FirewallMatch(
            zones=in_zones,
            zones_not=in_neg,
            networks=src_nets,
            networks_not=src_neg and bool(src_nets),
            ports=src_ports,
        ),
        destination=FirewallMatch(
            zones=out_zones,
            zones_not=out_neg,
            networks=dst_nets,
            networks_not=dst_neg and bool(dst_nets),
            ports=dst_ports,
        ),
        action=_DECIDING.get(action_text, FirewallAction.ACCEPT),
        forwarded=forwarded,
        exact=exact and action_text != "",
    )


def _same(a: list[Any], b: list[Any]) -> tuple[list[Any], bool]:
    """The two conditions of a jump rule and a rule in its chain, joined: ``(list, exact)``."""
    if not a:
        return b, True
    if not b or a == b:
        return a, True
    return b, False  # two different conditions: the narrower is not known, keep the rule's own


def _join(outer: FirewallRule, inner: FirewallRule) -> FirewallRule:
    """The rule ``inner`` of a user chain as seen through the jump rule ``outer``."""
    exact = outer.exact and inner.exact
    update: dict[str, Any] = {}
    for part in ("source", "destination"):
        o, i = getattr(outer, part), getattr(inner, part)
        zones, ok1 = _same(o.zones, i.zones)
        nets, ok2 = _same(o.networks, i.networks)
        ps, ok3 = _same(o.ports, i.ports)
        same_not = (not o.zones or not i.zones or o.zones_not == i.zones_not) and (
            not o.networks or not i.networks or o.networks_not == i.networks_not
        )
        update[part] = FirewallMatch(
            zones=zones,
            zones_not=i.zones_not if i.zones else o.zones_not,
            networks=nets,
            networks_not=i.networks_not if i.networks else o.networks_not,
            ports=ps,
        )
        exact = exact and ok1 and ok2 and ok3 and same_not
    protocols, ok = _same(outer.protocols, inner.protocols)
    forwarded = inner.forwarded if inner.forwarded is not None else outer.forwarded
    if outer.forwarded is not None and inner.forwarded not in (None, outer.forwarded):
        exact = False
    return inner.model_copy(
        update={
            **update,
            "protocols": protocols,
            "forwarded": forwarded,
            "enabled": outer.enabled and inner.enabled,
            "exact": exact and ok,
            "name": inner.name or outer.name,
        }
    )


@dataclass
class _Walk:
    rows: dict[str, list[dict[str, Any]]]
    zones: _Zones
    lists: Lists
    ipv6: bool
    complete: bool = True
    out: list[FirewallRule] = field(default_factory=list)

    def chain(
        self,
        name: str,
        base: FirewallChain | None,
        outer: FirewallRule | None,
        depth: int,
        stack: tuple[str, ...],
    ) -> bool:
        """Append the rules of chain ``name`` (flattened); ``False``: it ended in an
        unconditional ``return`` (the caller continues after the jump)."""
        inexact_after = False
        for row in self.rows.get(name, []):
            if _flag(row.get("invalid")):
                continue
            action = _text(row.get("action"))
            rule = _rule(row, self.zones, self.lists, self.ipv6, base)
            if rule is None:
                continue
            if outer is not None:
                rule = _join(outer, rule)
            if inexact_after:
                rule = rule.model_copy(update={"exact": False})
            if action == "jump":
                target = _text(row.get("jump-target"))
                if target not in self.rows:
                    continue  # a chain without rules: nothing happens
                if target in (*stack, name) or depth >= _MAX_DEPTH:
                    self.complete = False  # a loop
                    continue
                self.chain(target, base, rule, depth + 1, (*stack, name))
            elif action == "return":
                conditional = not _is_unconditional(rule)
                if not conditional and rule.enabled:
                    return False
                inexact_after = inexact_after or conditional
            elif action in _DECIDING:
                self.out.append(rule)
            # passthrough, log, fasttrack, add-src-to-address-list, ...: no decision
        return True


def _is_unconditional(rule: FirewallRule) -> bool:
    return (
        not rule.protocols
        and not rule.source.zones
        and not rule.destination.zones
        and not rule.source.networks
        and not rule.destination.networks
        and not rule.source.ports
        and not rule.destination.ports
        and rule.forwarded is None
        and rule.exact
    )


def filter_rules(
    rows: list[dict[str, Any]], zones: _Zones, lists: Lists, ipv6: bool
) -> tuple[list[FirewallRule], bool]:
    """``(rules, complete)``: the ``input``, ``forward`` and ``output`` chains flattened."""
    by_chain: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_chain.setdefault(_text(row.get("chain")), []).append(row)
    walk = _Walk(by_chain, zones, lists, ipv6)
    for name, base in (
        ("input", FirewallChain.INPUT),
        ("forward", FirewallChain.FORWARD),
        ("output", FirewallChain.OUTPUT),
    ):
        walk.chain(name, base, None, 0, ())
    return walk.out, walk.complete


def _first_address(nets: list[IPNetwork]) -> IPAddress | None:
    if len(nets) == 1 and nets[0].num_addresses == 1:
        return nets[0].network_address
    return None


def nat(
    rows: list[dict[str, Any]], zones: _Zones, lists: Lists
) -> tuple[list[NatRule], list[PortForward], bool]:
    """``(source NAT, port forwards, complete)`` of ``/ip/firewall/nat``."""
    rules: list[NatRule] = []
    forwards: list[PortForward] = []
    complete = True
    exceptions = False
    for row in rows:
        if _flag(row.get("invalid")):
            continue
        chain, action = _text(row.get("chain")), _text(row.get("action"))
        enabled = not _flag(row.get("disabled"))
        ipsec = _ipsec(row, lists)
        if ipsec is None:
            continue  # only for IPsec traffic, which this router does not have
        in_zones, _, ok1 = zones.of(row.get("in-interface-list"), row.get("in-interface"))
        out_zones, _, ok2 = zones.of(row.get("out-interface-list"), row.get("out-interface"))
        src, ok3 = addresses(row.get("src-address"), lists, row.get("src-address-list"))
        dst, ok4 = addresses(row.get("dst-address"), lists, row.get("dst-address-list"))
        dports, ok5 = ports(row.get("dst-port"))
        protocol = _PROTOCOLS.get(_text(row.get("protocol")).lower())
        protocols = [protocol] if protocol else []
        if _is_set(row, "protocol") and protocol is None:
            protocols = [FirewallProtocol.OTHER]
        negated = any(_text(row.get(k)).startswith("!") for k in ("src-address", "dst-address"))
        local = _text(row.get("dst-address-type")) == "local"
        extra = not ipsec or any(
            _is_set(row, k) for k in (*_INEXACT, "src-port") if k != "dst-address-type"
        )
        owned = _owned(row) if chain == "dstnat" else None
        name = owned[1] if owned else (_text(row.get("comment")) or None)
        to_nets, to_ok = addresses(row.get("to-addresses"), lists)
        to = _first_address(to_nets)
        if chain == "srcnat":
            if action in ("masquerade", "src-nat"):
                rules.append(
                    NatRule(
                        name=name,
                        enabled=enabled,
                        zones=out_zones,
                        sources=src,
                        masquerade=action == "masquerade" or to is None,
                        to_address=to if action == "src-nat" else None,
                        exact=ok1
                        and ok2
                        and ok3
                        and ok4
                        and not dst
                        and not negated
                        and not extra
                        and (action == "masquerade" or (to is not None and to_ok)),
                    )
                )
            elif action == "accept":
                exceptions = True
            elif action in ("jump", "netmap"):
                complete = False
        elif chain == "dstnat":
            if action in ("dst-nat", "redirect"):
                if action == "redirect" or to is None:
                    # a redirect goes to the router itself; a target that is no single address
                    # (a range, a name) is not expressed
                    if action == "dst-nat":
                        complete = False
                    continue
                to_port = ports(row.get("to-ports"))[0]
                external = _first_address(dst)
                forwards.append(
                    PortForward(
                        name=name,
                        signalbox_key=owned[0] if owned else None,
                        enabled=enabled,
                        protocols=protocols,
                        zones=in_zones,
                        external_address=external,
                        external_ports=dports,
                        sources=src,
                        target_address=to,
                        target_port=to_port[0].start if to_port else None,
                        passes_filter=False,
                        exact=ok1
                        and ok3
                        and ok4
                        and ok5
                        and to_ok
                        and not negated
                        and not extra
                        and (local or not dst or external is not None)
                        and not _is_set(row, "src-port"),
                    )
                )
            elif action in ("jump", "netmap"):
                complete = False
    if exceptions:  # accept rules in srcnat leave some traffic untranslated
        rules = [r.model_copy(update={"exact": False}) for r in rules]
    return rules, forwards, complete


def policies(rows: list[dict[str, Any]]) -> list[ZonePolicy]:
    """The zone policies Signalbox wrote: tagged rules ``signalbox:policy/<from>/<to|device>``
    (enabled ones; the action accept, drop or reject)."""
    out: dict[tuple[str, str | None], ZonePolicy] = {}
    for row in rows:
        mark = tagged(row)
        action = _DECIDING.get(_text(row.get("action")))
        if mark is None or not mark.startswith(POLICY_MARK) or action is None:
            continue
        if _flag(row.get("disabled")) or _text(row.get("chain")) not in ("input", "forward"):
            continue
        parts = mark[len(POLICY_MARK) :].split("/")
        if len(parts) != 2 or not all(parts):
            continue
        source, dest = parts
        between = dest not in ("device", source)
        out.setdefault(
            (source, None if dest == "device" else dest),
            ZonePolicy(
                source=source,
                destination=None if dest == "device" else dest,
                action=action,
                signalbox_key=f"{source}/{dest}" if between else None,
            ),
        )
    return list(out.values())


def build(
    device_id: str,
    lists: Lists,
    mapper: Mapper,
    filter4: list[dict[str, Any]],
    filter6: list[dict[str, Any]],
    nat_rows: list[dict[str, Any]],
    raw_rows: list[dict[str, Any]],
) -> Firewall:
    zones = _Zones(lists, mapper)
    rules4, complete4 = filter_rules(filter4, zones, lists, False)
    rules6, complete6 = filter_rules(filter6, zones, lists, True)
    nat_rules, forwards, nat_complete = nat(nat_rows, zones, lists)
    # a raw rule that drops traffic is evaluated before the filter: not visible in its rules
    raw_drops = any(
        _text(r.get("action")) == "drop" and not _flag(r.get("disabled")) for r in raw_rows
    )
    out_zones: list[FirewallZone] = []
    for name in sorted(zones.used):
        segments: list[str] = []
        uplinks: list[str] = []
        tunnels: list[str] = []
        bare_ports: list[str] = []
        complete = True
        for iface in zones.used[name]:
            found = mapper(iface)
            if found is None:
                complete = False
                continue
            segments += [x for x in found[0] if x not in segments]
            uplinks += [x for x in found[1] if x not in uplinks]
            tunnels += [x for x in found[2] if x not in tunnels]
            bare_ports += [x for x in found[3] if x not in bare_ports]
        out_zones.append(
            FirewallZone(
                name=name,
                segments=segments,
                uplinks=uplinks,
                tunnels=tunnels,
                ports=bare_ports,
                complete=complete,
            )
        )
    return Firewall(
        id=firewall_id(device_id),
        device_id=device_id,
        zones=out_zones,
        # the built-in chains accept what no rule matches
        input_policy=FirewallAction.ACCEPT,
        forward_policy=FirewallAction.ACCEPT,
        policies=policies([*filter4, *filter6]),
        rules=[*rules4, *rules6],
        rules_complete=complete4 and complete6 and not raw_drops,
        nat=nat_rules,
        port_forwards=forwards,
        port_forwards_complete=nat_complete,
    )


__all__ = [
    "POLICY_MARK",
    "TAG",
    "Lists",
    "Mapper",
    "build",
    "describe",
    "filter_rules",
    "key_of",
    "nat",
    "policies",
    "split_mark",
    "tagged",
]
