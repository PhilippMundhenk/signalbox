"""OPNsense packet filter and NAT to the model (#135, ADR 0013).

Pure functions on the rows of the API (``/api/firewall/filter/search_rule``, ``alias/search_item``,
``group/search_item``, ``d_nat/search_rule``, ``source_nat/search_rule``,
``one_to_one/search_rule``); the adapter fetches them and passes the interface layout.

What OPNsense does and how it maps (from the source of the 26.7 controllers; *(guess)* where
the answer of a real firewall was not seen):

- ``search_rule`` lists the rules of the "new" MVC model, the rules of the legacy pages and the
  automatic ones (anti-lockout, DHCP, ...) in evaluation order (``sort_order``). A release whose
  rows have no ``sort_order`` lists only the MVC rules: ``rules_complete = False``.
- pf takes the first matching ``quick`` rule, else the *last* matching rule. Flattened for the
  model's first-match evaluation: the quick rules in order, then the others in reverse order.
- Everything is blocked that no rule passes (zone policies are the fallbacks ``input_policy``
  and ``forward_policy``: drop). Rules with direction ``out`` filter what the firewall itself
  sends (replies and forwarded traffic ride on the state of the ``in`` rule).
- Zones are the assigned interfaces (identifier ``lan``, ``wan``, ``opt1``) and interface
  groups. Rows of legacy rules name interfaces by their description: mapped back.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from ipaddress import ip_network
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
    IPInterface,
    IPNetwork,
    NatRule,
    PortForward,
    PortRange,
    firewall_id,
)

_ACTIONS = {
    "pass": FirewallAction.ACCEPT,
    "block": FirewallAction.DROP,
    "reject": FirewallAction.REJECT,
}
_PROTOCOLS = {
    "tcp": [FirewallProtocol.TCP],
    "udp": [FirewallProtocol.UDP],
    "tcp/udp": [FirewallProtocol.TCP, FirewallProtocol.UDP],
    "icmp": [FirewallProtocol.ICMP],
    "ipv6-icmp": [FirewallProtocol.ICMP],
    "icmp6": [FirewallProtocol.ICMP],
    "esp": [FirewallProtocol.ESP],
    "gre": [FirewallProtocol.GRE],
}
#: Fields of a filter row that make a rule inexact when they are set.
_INEXACT = (
    "sched",
    "tcpflags1",
    "tcpflags2",
    "tcpflags_any",
    "tagged",
    "tos",
    "max",
    "overload",
    "os",
)


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ("" if value is None else str(value))


def _flag(value: Any) -> bool:
    return value in (True, 1, "1", "true", "yes", "on", "enabled")


def _csv(value: Any) -> list[str]:
    if isinstance(value, list):
        return [_text(v) for v in value if _text(v)]
    return [x for x in re.split(r"[,\s]+", _text(value)) if x]


@dataclass
class Iface:
    """An assigned interface, as the adapter's layout knows it."""

    identifier: str
    description: str
    segments: list[str] = field(default_factory=list)
    uplinks: list[str] = field(default_factory=list)
    tunnels: list[str] = field(default_factory=list)
    addresses: list[IPInterface] = field(default_factory=list)
    #: The interface maps to model objects.
    mapped: bool = True


class Context:
    """Lookups shared by the readers: zones, interface descriptions, aliases."""

    def __init__(
        self,
        ifaces: list[Iface],
        groups: list[dict[str, Any]],
        aliases: list[dict[str, Any]],
    ) -> None:
        self.ifaces = {i.identifier: i for i in ifaces}
        # a legacy row names an interface by its description (ambiguous ones are not mapped)
        counts: dict[str, int] = {}
        for i in ifaces:
            counts[i.description] = counts.get(i.description, 0) + 1
        self.by_description = {
            i.description: i.identifier for i in ifaces if counts[i.description] == 1
        }
        self.groups: dict[str, list[str]] = {}
        for g in groups:
            name = _text(g.get("ifname"))
            if name:
                self.groups[name] = _csv(g.get("members"))
        self.aliases = {
            _text(a.get("name")): a for a in aliases if _text(a.get("name")) and a.get("name")
        }

    # zones ------------------------------------------------------------------------------

    def zone_name(self, token: str) -> str | None:
        if token in self.ifaces or token in self.groups:
            return token
        return self.by_description.get(token)

    def zones(self, value: Any) -> tuple[list[str], bool]:
        """``(zone names, all known)`` of an ``interface`` field (comma separated)."""
        names: list[str] = []
        ok = True
        for token in _csv(value):
            name = self.zone_name(token)
            if name is None:
                ok = False
            elif name not in names:
                names.append(name)
        return names, ok

    # networks ---------------------------------------------------------------------------

    def _interface_networks(self, ident: str) -> list[IPNetwork]:
        return list(dict.fromkeys(a.network for a in self.ifaces[ident].addresses))

    def networks(self, value: Any, depth: int = 0) -> tuple[list[IPNetwork] | None, bool]:
        """``(networks, exact)`` of a source or destination: ``None`` is "any" (every address)."""
        out: list[IPNetwork] = []
        exact = True
        for token in _csv(value):
            if token.lower() == "any":
                return None, exact
            found, ok = self._network(token, depth)
            if found is None:
                return None, False
            out += [n for n in found if n not in out]
            exact = exact and ok
        return (out if out else None), exact

    def _network(self, token: str, depth: int) -> tuple[list[IPNetwork] | None, bool]:
        if token == "(self)":
            return [ip_network(a.ip) for i in self.ifaces.values() for a in i.addresses], True
        try:
            return [ip_network(token, strict=False)], True
        except ValueError:
            pass
        base = token.removesuffix(":network")
        if base in self.ifaces:
            return self._interface_networks(base), True
        if token.endswith("ip") and token[:-2] in self.ifaces:
            return [ip_network(a.ip) for a in self.ifaces[token[:-2]].addresses], True
        if token in self.groups:
            nets = [
                n
                for m in self.groups[token]
                if m in self.ifaces
                for n in self._interface_networks(m)
            ]
            return nets, all(m in self.ifaces for m in self.groups[token])
        alias = self.aliases.get(token)
        if alias is None or depth > 5:
            return None, False
        kind = _text(alias.get("type")).lower()
        if kind not in ("host", "network", "networkgroup"):
            return None, False  # URL tables, GeoIP, dynamic and external aliases
        out: list[IPNetwork] = []
        exact = _flag(alias.get("enabled", "1"))
        for item in _csv(alias.get("content")):
            nets, ok = (
                self._network(item, depth + 1) if kind == "networkgroup" else self._literal(item)
            )
            if nets is None:
                return None, False
            out += nets
            exact = exact and ok
        return out, exact

    @staticmethod
    def _literal(item: str) -> tuple[list[IPNetwork] | None, bool]:
        try:
            return [ip_network(item, strict=False)], True
        except ValueError:
            return None, False  # a host name or an interface-bound entry

    # ports ------------------------------------------------------------------------------

    def ports(self, value: Any, depth: int = 0) -> tuple[list[PortRange], bool]:
        """``(ports, exact)``; empty: any port."""
        out: list[PortRange] = []
        exact = True
        for token in _csv(value):
            if token.lower() == "any":
                return [], True
            found = self._port(token, depth)
            if found is None:
                exact = False
                continue
            out += found
        return out, exact

    def _port(self, token: str, depth: int) -> list[PortRange] | None:
        first, sep, last = token.replace(":", "-").partition("-")
        try:
            return [PortRange(start=int(first), end=int(last) if sep else None)]
        except ValueError:
            pass
        alias = self.aliases.get(token)
        if alias is not None and depth <= 5:
            if _text(alias.get("type")).lower() not in ("port",) or not _flag(
                alias.get("enabled", "1")
            ):
                return None
            out: list[PortRange] = []
            for item in _csv(alias.get("content")):
                got = self._port(item, depth + 1)
                if got is None:
                    return None
                out += got
            return out
        try:
            return [PortRange(start=socket.getservbyname(token))]
        except (OSError, ValueError):
            return None


def _protocols(value: Any) -> tuple[list[FirewallProtocol], bool]:
    text = _text(value).lower()
    if text in ("", "any"):
        return [], True
    if text in _PROTOCOLS:
        return list(_PROTOCOLS[text]), True
    return [FirewallProtocol.OTHER], True


def _family(value: Any) -> Literal[4, 6] | None:
    text = _text(value).lower()
    return 4 if text == "inet" else 6 if text == "inet6" else None


def _match(
    ctx: Context, zones: list[str], zones_not: bool, net: Any, negate: Any, port: Any
) -> tuple[FirewallMatch, bool]:
    nets, ok1 = ctx.networks(net)
    ports, ok2 = ctx.ports(port)
    return (
        FirewallMatch(
            zones=zones,
            zones_not=zones_not and bool(zones),
            networks=nets or [],
            networks_not=_flag(negate) and bool(nets),
            ports=ports,
        ),
        ok1 and ok2,
    )


def rule(ctx: Context, row: dict[str, Any]) -> tuple[FirewallRule, bool] | None:
    """``(rule, quick)`` of one row of ``filter/search_rule``; ``None``: it does not decide
    (action ``match``, an unknown action)."""
    action = _ACTIONS.get(_text(row.get("action")).lower())
    if action is None:
        return None
    legacy = _flag(row.get("legacy"))
    zones, zones_ok = ctx.zones(row.get("interface"))
    quick = (
        _flag(row.get("quick"))
        if row.get("quick") not in (None, "")
        else (legacy and len(zones) == 1) or not legacy
    )
    source, ok1 = _match(
        ctx,
        zones,
        _flag(row.get("interfacenot")),
        row.get("source_net"),
        row.get("source_not"),
        row.get("source_port"),
    )
    destination, ok2 = _match(
        ctx,
        [],
        False,
        row.get("destination_net"),
        row.get("destination_not"),
        row.get("destination_port"),
    )
    direction = _text(row.get("direction")).lower() or "in"
    protocols, _ = _protocols(row.get("protocol"))
    inexact = any(_text(row.get(k)) not in ("", "0", "false") for k in _INEXACT)
    name = _text(row.get("description"))
    try:
        order = int(_text(row.get("sequence")))
    except ValueError:
        order = None
    return (
        FirewallRule(
            name=name or None,
            order=order,
            enabled=_flag(row.get("enabled", "1")),
            # an ``out`` rule filters the firewall's own traffic; ``in`` rules see traffic to
            # the firewall and through it (the destination address tells which)
            chain=FirewallChain.OUTPUT if direction == "out" else None,
            family=_family(row.get("ipprotocol")),
            protocols=protocols,
            source=source,
            destination=destination,
            action=action,
            exact=zones_ok and ok1 and ok2 and not inexact,
        ),
        quick,
    )


def ordered(ctx: Context, rows: list[dict[str, Any]]) -> list[FirewallRule]:
    """The rules in the model's evaluation order (see the module docstring)."""
    quick: list[FirewallRule] = []
    rest: list[FirewallRule] = []
    for row in rows:
        built = rule(ctx, row)
        if built is None:
            continue
        (quick if built[1] else rest).append(built[0])
    return quick + rest[::-1]


def _first_address(nets: list[IPNetwork] | None) -> IPAddress | None:
    if nets is not None and len(nets) == 1 and nets[0].num_addresses == 1:
        return nets[0].network_address
    return None


def _external(ctx: Context, value: Any) -> tuple[IPAddress | None, bool]:
    """``(address, exact)`` of a destination network of a port forward: ``wanip`` and ``any``
    are the firewall's own addresses on the zone."""
    text = _text(value).lower()
    if text in ("", "any") or (text.endswith("ip") and text[:-2] in ctx.ifaces):
        return None, True
    nets, ok = ctx.networks(value)
    address = _first_address(nets)
    return address, ok and address is not None


def port_forward(ctx: Context, row: dict[str, Any]) -> tuple[PortForward | None, bool]:
    """``(forward, complete)`` of a ``d_nat/search_rule`` row (an exception row, ``nordr``, or
    one whose target is not an address leaves the list incomplete)."""
    if _flag(row.get("is_automatic")):
        return None, True
    if _flag(row.get("nordr")):
        return None, False
    nets, _ok = ctx.networks(row.get("target"))
    target = _first_address(nets)
    if target is None:
        return None, False
    zones, zones_ok = ctx.zones(row.get("interface"))
    external, ext_ok = _external(
        ctx, row.get("destination.network") or row.get("destination.address")
    )
    ports, ports_ok = ctx.ports(row.get("destination.port"))
    internal, internal_ok = ctx.ports(row.get("local-port"))
    sources, src_ok = ctx.networks(row.get("source.network") or row.get("source.address"))
    src_ports, _ = ctx.ports(row.get("source.port"))
    protocols, _ = _protocols(row.get("protocol"))
    reflection = _text(row.get("natreflection")).lower()
    name = _text(row.get("descr")) or _text(row.get("description"))
    exact = (
        zones_ok
        and ext_ok
        and ports_ok
        and internal_ok
        and src_ok
        and not src_ports
        and not _flag(row.get("source.not"))
        and not _flag(row.get("destination.not"))
        and not _text(row.get("tagged"))
    )
    return (
        PortForward(
            name=name or None,
            enabled=not _flag(row.get("disabled")),
            protocols=protocols,
            zones=zones,
            external_address=external,
            external_ports=ports,
            sources=sources or [],
            target_address=target,
            target_port=internal[0].start if internal else None,
            passes_filter=_text(row.get("pass")) == "pass",
            reflection=True
            if reflection == "purenat"
            else False
            if reflection == "disable"
            else None,
            exact=exact,
        ),
        True,
    )


def one_to_one(
    ctx: Context, row: dict[str, Any]
) -> tuple[PortForward | None, NatRule | None, bool]:
    """A ``one_to_one/search_rule`` row: a forward without ports (``binat``) and/or source NAT
    (``nat``) for one host. A mapping of whole networks is not expressed: incomplete."""
    zones, zones_ok = ctx.zones(row.get("interface"))
    internal, ok1 = ctx.networks(row.get("source_net"))
    external, ok2 = ctx.networks(row.get("external"))
    inside, outside = _first_address(internal), _first_address(external)
    if inside is None or outside is None:
        return None, None, False
    kind = _text(row.get("type")).lower() or "binat"
    enabled = _flag(row.get("enabled", "1"))
    dest, ok3 = ctx.networks(row.get("destination_net"))
    exact = zones_ok and ok1 and ok2 and ok3 and dest is None and not _flag(row.get("source_not"))
    name = _text(row.get("description"))
    forward = (
        PortForward(
            name=name or None,
            enabled=enabled,
            zones=zones,
            external_address=outside,
            target_address=inside,
            passes_filter=False,
            exact=exact,
        )
        if kind == "binat"
        else None
    )
    nat = NatRule(
        name=name or None,
        enabled=enabled,
        zones=zones,
        sources=[ip_network(inside)],
        masquerade=False,
        to_address=outside,
        exact=exact,
    )
    return forward, nat, True


def source_nat(ctx: Context, row: dict[str, Any]) -> NatRule | None:
    """A ``source_nat/search_rule`` row: no ``target`` is the interface address (masquerade).
    ``nonat`` rows are exceptions: the caller makes the other rules inexact."""
    if _flag(row.get("nonat")):
        return None
    zones, zones_ok = ctx.zones(row.get("interface"))
    sources, ok1 = ctx.networks(row.get("source_net"))
    dest, ok2 = ctx.networks(row.get("destination_net"))
    ports, ok3 = ctx.ports(row.get("destination_port"))
    src_ports, ok4 = ctx.ports(row.get("source_port"))
    protocols, _ = _protocols(row.get("protocol"))
    targets, ok5 = ctx.networks(row.get("target"))
    to = _first_address(targets)
    name = _text(row.get("description"))
    return NatRule(
        name=name or None,
        enabled=_flag(row.get("enabled", "1")),
        zones=zones,
        sources=sources or [],
        masquerade=to is None,
        to_address=to,
        exact=(
            zones_ok
            and ok1
            and ok2
            and ok3
            and ok4
            and ok5
            and dest is None
            and not ports
            and not src_ports
            and not protocols
            and not _flag(row.get("source_not"))
            and (targets is None or to is not None)
        ),
    )


def zones(ctx: Context) -> list[FirewallZone]:
    """One zone per assigned interface and per interface group."""
    out: list[FirewallZone] = []
    for i in ctx.ifaces.values():
        out.append(
            FirewallZone(
                name=i.identifier,
                description=i.description if i.description != i.identifier else None,
                segments=list(i.segments),
                uplinks=list(i.uplinks),
                tunnels=list(i.tunnels),
                complete=i.mapped,
            )
        )
    for name, members in ctx.groups.items():
        known = [ctx.ifaces[m] for m in members if m in ctx.ifaces]
        out.append(
            FirewallZone(
                name=name,
                segments=list(dict.fromkeys(s for i in known for s in i.segments)),
                uplinks=list(dict.fromkeys(s for i in known for s in i.uplinks)),
                tunnels=list(dict.fromkeys(s for i in known for s in i.tunnels)),
                complete=len(known) == len(members) and all(i.mapped for i in known),
            )
        )
    return out


def build(
    device_id: str,
    ctx: Context,
    rules: list[dict[str, Any]],
    forwards: list[dict[str, Any]] | None,
    snat: list[dict[str, Any]] | None,
    binat: list[dict[str, Any]] | None,
) -> Firewall:
    """The firewall; ``forwards`` and the NAT lists are ``None`` when their endpoints are not
    there (a release without the MVC pages: the forwards are then not read)."""
    # a release that lists only the MVC rules has no ``sort_order`` and misses the legacy and
    # automatic rules
    complete = bool(rules) and any("sort_order" in r for r in rules)
    port_forwards: list[PortForward] = []
    forwards_complete = forwards is not None
    for row in forwards or []:
        forward, ok = port_forward(ctx, row)
        forwards_complete = forwards_complete and ok
        if forward is not None:
            port_forwards.append(forward)
    nat: list[NatRule] = []
    for row in snat or []:
        n = source_nat(ctx, row)
        if n is not None:
            nat.append(n)
    exceptions = any(_flag(r.get("nonat")) for r in snat or [])
    if exceptions:
        nat = [n.model_copy(update={"exact": False}) for n in nat]
    for row in binat or []:
        forward, n, ok = one_to_one(ctx, row)
        forwards_complete = forwards_complete and ok
        if forward is not None:
            port_forwards.append(forward)
        if n is not None:
            nat.append(n)
    return Firewall(
        id=firewall_id(device_id),
        device_id=device_id,
        zones=zones(ctx),
        # pf's default deny: whatever no rule passes is blocked
        input_policy=FirewallAction.DROP,
        forward_policy=FirewallAction.DROP,
        rules=ordered(ctx, rules),
        rules_complete=complete,
        nat=nat,
        port_forwards=port_forwards,
        port_forwards_complete=forwards_complete,
    )


__all__ = ["Context", "Iface", "build", "ordered", "rule"]
