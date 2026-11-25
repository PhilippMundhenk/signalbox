"""Router advertisements and DHCPv6 settings agree (#72, #151).

Per network the check compares what the routers announce (flags, prefixes, DNS servers) with
the DHCPv6 servers of the network. It only speaks when a device reported its router
advertisement settings (``Network.router_adverts``); the answers of Signalbox's own probe
(``Network.foreign_servers``) complete the picture: a DHCPv6 server or router seen on the
wire counts, also when no integration reads it.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from ipaddress import IPv6Network

from signalbox.model import (
    Dhcp6Mode,
    Dhcp6Server,
    DhcpServer,
    ForeignServer,
    Network,
    RaMode,
    RouterAdvert,
    ServerKind,
    ra_flags,
)
from signalbox.rules import Result, Severity, found, rule
from signalbox.rules._names import device_name, router_subnets, segment_name

_ONE_ROUTER = (
    "Let one router send the router advertisements of this network and turn them off on the "
    "other (or give both the same prefixes and flags)."
)


def _managed(ra: RouterAdvert) -> bool | None:
    return ra.managed if ra.managed is not None else ra_flags(ra.mode)[0]


def _other(ra: RouterAdvert) -> bool | None:
    return ra.other if ra.other is not None else ra_flags(ra.mode)[1]


def _sending(net: Network) -> dict[str, list[RouterAdvert]]:
    out: dict[str, list[RouterAdvert]] = defaultdict(list)
    for ra in sorted(net.router_adverts, key=lambda r: r.id):
        if ra.mode is not RaMode.OFF:
            out[ra.segment_id].append(ra)
    return out


def _seen(net: Network, kind: ServerKind, segment_id: str) -> list[ForeignServer]:
    return [s for s in net.foreign_servers if s.kind is kind and s.segment_id == segment_id]


def _names(net: Network, ras: list[RouterAdvert]) -> str:
    return ", ".join(sorted({device_name(net, r.device_id) for r in ras}))


@rule(
    "ipv6.ra-consistent",
    "Router advertisements and DHCPv6 settings disagree",
    Severity.WARNING,
    "Clients decide from the flags of the router advertisements whether to ask a DHCPv6 server "
    "for addresses (managed flag) or for other settings such as DNS (other-config flag). When "
    "the flags, the DHCPv6 servers, the announced prefixes or the announced DNS servers of a "
    "network do not fit together, IPv6 works on some operating systems only (Android never "
    "uses DHCPv6), clients get no address, or an IPv6 resolver of the provider bypasses a "
    "filtering resolver. Checked per network: managed or other-config flag without a DHCPv6 "
    "server, a DHCPv6 server whose flag no router sets, DNS servers in the advertisements "
    "that differ from the DHCPv6 ones or bypass the local resolver, and two routers that "
    "advertise different prefixes or flags.",
)
def ra_consistent(net: Network) -> Iterator[Result]:
    by_segment = _sending(net)
    reading = {ra.segment_id for ra in net.router_adverts}
    for seg_id in sorted(set(by_segment) | reading | {s.segment_id for s in net.dhcp6_servers}):
        ras = by_segment.get(seg_id, [])
        label = segment_name(net, seg_id)
        servers = net.dhcp6_on(seg_id)
        yield from _flags(net, seg_id, label, ras, servers)
        yield from _dns(seg_id, label, ras, servers)
        yield from _routers(net, seg_id, label, ras)
        yield from _bypass(net, seg_id, label, ras)


def _flags(
    net: Network, seg_id: str, label: str, ras: list[RouterAdvert], servers: list[Dhcp6Server]
) -> Iterator[Result]:
    seen = _seen(net, ServerKind.DHCPV6, seg_id)
    answering = [x for x in servers if x.pools or not x.prefix_pools]  # not prefix delegation only
    if ras and not answering and not seen and not net.dhcp_relays_on(seg_id):
        managed = [r for r in ras if _managed(r)]
        flagged = managed or [r for r in ras if _other(r)]
        if flagged:
            flag = "managed" if managed else "other-config"
            yield found(
                f"{_names(net, flagged)} announce the {flag} flag on {label}, but no DHCPv6 "
                "server runs there",
                [seg_id, *(r.id for r in flagged)],
                fix="Turn on a DHCPv6 server for this network on its router, or switch the "
                "router advertisements to SLAAC (clear the managed and other-config flags) so "
                "that clients do not wait for a DHCPv6 answer.",
                key=f"no-server:{seg_id}",
                mid="ra.noServer",
                fix_id="ra.noServer.fix",
                params={"routers": _names(net, flagged), "flag": flag, "segment": label},
            )
    if not any(r.segment_id == seg_id for r in net.router_adverts):
        return  # no device reported router advertisements here: nothing to compare with
    for server in servers:
        if server.prefix_pools and not server.pools:
            continue  # delegates prefixes to routers only (MikroTik): clients never ask it
        stateful = server.mode is Dhcp6Mode.STATEFUL
        if not ras:
            yield found(
                f"A DHCPv6 server runs on {label}, but no router sends router advertisements "
                "there; DHCPv6 gives clients no default route",
                [seg_id, server.id],
                fix="Turn on router advertisements for this network on its router (managed "
                "mode when the DHCPv6 server hands out addresses).",
                key=f"no-ra:{server.id}",
                mid="ra.noAdverts",
                fix_id="ra.noAdverts.fix",
                params={"segment": label},
            )
        elif not any(_managed(r) if stateful else (_managed(r) or _other(r)) for r in ras):
            flag = "managed" if stateful else "other-config"
            yield found(
                f"A DHCPv6 server runs on {label}, but the router advertisements of "
                f"{_names(net, ras)} do not set the {flag} flag, so clients never ask it",
                [seg_id, server.id, *(r.id for r in ras)],
                fix=f"Set the {flag} flag in the router advertisements of this network "
                "(mode stateful or stateless), or turn the DHCPv6 server off if SLAAC is "
                "meant to be used.",
                key=f"flag-off:{server.id}",
                mid="ra.flagOff",
                fix_id="ra.flagOff.fix",
                params={"routers": _names(net, ras), "flag": flag, "segment": label},
            )


def _dns(
    seg_id: str, label: str, ras: list[RouterAdvert], servers: list[Dhcp6Server]
) -> Iterator[Result]:
    for ra in ras:
        for server in servers:
            if not ra.rdnss or not server.dns_servers:
                continue
            if set(ra.rdnss) == set(server.dns_servers):
                continue
            in_ra = ", ".join(str(a) for a in ra.rdnss)
            in_dhcp = ", ".join(str(a) for a in server.dns_servers)
            yield found(
                f"On {label}, router advertisements announce DNS {in_ra}, DHCPv6 hands out "
                f"{in_dhcp}",
                [seg_id, ra.id, server.id],
                fix="Announce the same DNS servers in the router advertisements (RDNSS) and in "
                "the DHCPv6 server, so that every client resolves the same way.",
                key=f"dns:{ra.id}:{server.id}",
                mid="ra.dnsDiffers",
                fix_id="ra.dnsDiffers.fix",
                params={"segment": label, "ra": in_ra, "dhcp": in_dhcp},
            )


@dataclass(frozen=True)
class _Advertiser:
    name: str
    ref: str
    prefixes: frozenset[IPv6Network]
    managed: bool | None
    other: bool | None


def _prefixes(net: Network, ra: RouterAdvert) -> frozenset[IPv6Network]:
    """The prefixes with the A flag; without a configured list the router's own networks."""
    if ra.prefixes:
        return frozenset(p.prefix for p in ra.prefixes if p.autonomous is not False)
    return frozenset(
        s.interface.network
        for s in net.subnets
        if s.device_id == ra.device_id
        and s.segment_id == ra.segment_id
        and isinstance(s.interface.network, IPv6Network)
        and not s.interface.ip.is_link_local
    )


def _routers(net: Network, seg_id: str, label: str, ras: list[RouterAdvert]) -> Iterator[Result]:
    adv = [
        _Advertiser(device_name(net, r.device_id), r.id, _prefixes(net, r), _managed(r), _other(r))
        for r in ras
    ]
    # known routers seen by the probe that no integration reports settings for (#292)
    configured = {r.device_id for r in net.router_adverts}
    for srv in _seen(net, ServerKind.RA, seg_id):
        if srv.known_as is None or srv.known_as in configured:
            continue
        adv.append(
            _Advertiser(
                device_name(net, srv.known_as),
                srv.id,
                frozenset(srv.offered.autonomous),
                None,
                None,
            )
        )
    for i, a in enumerate(adv):
        for b in adv[i + 1 :]:
            if a.name == b.name:
                continue
            if a.prefixes and b.prefixes and a.prefixes != b.prefixes:
                pa = ", ".join(sorted(str(p) for p in a.prefixes))
                pb = ", ".join(sorted(str(p) for p in b.prefixes))
                yield found(
                    f"{a.name} and {b.name} advertise different prefixes on {label} "
                    f"({pa} and {pb})",
                    [seg_id, a.ref, b.ref],
                    fix=_ONE_ROUTER,
                    key=f"prefixes:{a.ref}:{b.ref}",
                    mid="ra.prefixesDiffer",
                    fix_id="ra.routersDiffer.fix",
                    params={"a": a.name, "b": b.name, "segment": label, "pa": pa, "pb": pb},
                )
            if (
                a.managed is not None
                and b.managed is not None
                and a.other is not None
                and b.other is not None
                and (a.managed, a.other) != (b.managed, b.other)
            ):
                yield found(
                    f"{a.name} and {b.name} advertise different managed / other-config flags "
                    f"on {label}",
                    [seg_id, a.ref, b.ref],
                    fix=_ONE_ROUTER,
                    key=f"flags:{a.ref}:{b.ref}",
                    mid="ra.flagsDiffer",
                    fix_id="ra.routersDiffer.fix",
                    params={"a": a.name, "b": b.name, "segment": label},
                )


def _known_addresses(net: Network) -> set[object]:
    own: set[object] = {s.interface.ip for s in net.subnets}
    own |= {a for svc in net.dns_services for a in svc.listen}
    own |= {s.interface.ip for s in router_subnets(net)}
    return own


def _local_dns(net: Network, seg_id: str) -> list[DhcpServer]:
    """Enabled IPv4 DHCP servers of the network that hand out only resolvers of known devices."""
    own = _known_addresses(net)
    return [
        s
        for s in net.dhcp_servers
        if s.segment_id == seg_id
        and s.enabled
        and s.dns_servers
        and all(a in own for a in s.dns_servers)
    ]


def _bypass(net: Network, seg_id: str, label: str, ras: list[RouterAdvert]) -> Iterator[Result]:
    local = _local_dns(net, seg_id)
    if not local:
        return
    own = _known_addresses(net)
    provider = {a for u in net.uplinks for a in u.dns_servers}
    for ra in ras:
        outside = [a for a in ra.rdnss if a in provider or a not in own]
        if not outside:
            continue
        text = ", ".join(str(a) for a in outside)
        v4 = ", ".join(str(a) for a in local[0].dns_servers)
        yield found(
            f"{label} announces {text} as DNS in router advertisements, but IPv4 clients use "
            f"the local resolver {v4}; IPv6 clients bypass it",
            [seg_id, ra.id],
            fix=f"Announce the router's own IPv6 address (or none) as DNS in the router "
            f"advertisements of {label}, so that DNS filtering and local names also apply "
            "over IPv6.",
            key=f"bypass:{ra.id}",
            mid="ra.dnsBypass",
            fix_id="ra.dnsBypass.fix",
            params={"segment": label, "dns": text, "local": v4},
        )


RULES = [ra_consistent]
