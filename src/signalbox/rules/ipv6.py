"""IPv6 rules: prefixes clients use, prefix length, IPv6 on every client network (#70, #71, #73)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from ipaddress import IPv6Address, IPv6Network, ip_network

from signalbox.model import Network, Subnet
from signalbox.rules import Result, Rule, Severity, found, incomplete, rule
from signalbox.rules._names import router_subnets, segment_name, site_of_device

_GLOBAL = ip_network("2000::/3")
_ULA = ip_network("fc00::/7")


def _routed_v6(sub: Subnet) -> bool:
    """An IPv6 router subnet that clients could use (not link-local)."""
    return sub.interface.version == 6 and not sub.interface.ip.is_link_local


def _client_segments(net: Network) -> set[str]:
    """Networks that clients use: with an enabled SSID or a client seen on them."""
    out = {w.segment_id for w in net.wlans if w.enabled and w.segment_id}
    return out | {c.segment_id for c in net.clients if c.segment_id}


def _site_of_segment(net: Network, segment_id: str, subs: list[Subnet]) -> str | None:
    seg = net.segment(segment_id)
    if seg is not None:
        return seg.site_id
    return site_of_device(net, subs[0].device_id) if subs else None


def _kind(address: IPv6Address) -> str | None:
    if address in _GLOBAL:
        return "global"
    if address in _ULA:
        return "ula"
    return None


@rule(
    "ipv6.unknown-prefix",
    "Clients use an IPv6 prefix no router announces",
    Severity.WARNING,
    "Clients on this network have IPv6 addresses from a prefix that none of the known routers of "
    "the network has. Another router on the network (an ISP box, a phone hotspot, a virtual "
    "machine host or a misconfigured access point) is sending router advertisements: clients "
    "get an extra address and default route, so traffic bypasses the firewall, or IPv6 "
    "connections fail and apps hang until they fall back to IPv4.",
)
def unknown_prefix(net: Network) -> Iterator[Result]:
    routers = router_subnets(net)
    by_segment: dict[str, list[Subnet]] = defaultdict(list)
    for sub in routers:
        by_segment[sub.segment_id].append(sub)
    v6_sites = {site_of_device(net, s.device_id) for s in routers if _routed_v6(s)}
    users: dict[tuple[str, IPv6Network], set[str]] = defaultdict(set)
    for client in net.clients:
        if not client.segment_id or client.segment_id not in by_segment:
            continue  # network or its router unknown
        for address in client.addresses:
            if isinstance(address, IPv6Address) and _kind(address):
                prefix = IPv6Network((address, 64), strict=False)
                users[(client.segment_id, prefix)].add(client.id)
    unchecked: dict[str, set[str]] = defaultdict(set)
    for (seg_id, prefix), clients in sorted(users.items(), key=lambda i: (i[0][0], str(i[0][1]))):
        subs = by_segment[seg_id]
        nets = [s.interface.network for s in subs if _routed_v6(s)]
        if any(prefix.subnet_of(n) for n in nets if isinstance(n, IPv6Network)):
            continue
        label = segment_name(net, seg_id)
        if not nets and _site_of_segment(net, seg_id, subs) not in v6_sites:
            unchecked[seg_id] |= clients  # the router may simply not report IPv6
            continue
        n = len(clients)
        yield found(
            f"{n} client{'s' if n > 1 else ''} on {label} use{'' if n > 1 else 's'} addresses "
            f"from {prefix}, which no router of {label} announces",
            [seg_id, *sorted(clients)],
            fix="Look for another router, hotspot or virtual machine host on this network that "
            "sends router advertisements, and turn them off there.",
            key=str(prefix),
        )
    for seg_id in sorted(unchecked):
        yield incomplete(
            f"Clients on {segment_name(net, seg_id)} have IPv6 addresses, but no router at the "
            "site reported IPv6 subnets, so it is not known whether a router announces them",
            [seg_id],
        )


@rule(
    "ipv6.prefix-64",
    "IPv6 client network does not use a /64",
    Severity.WARNING,
    "Automatic IPv6 addressing (SLAAC) only works with a /64 prefix. With a /56, /60 or /80 on a "
    "network, clients get no IPv6 address (Android never uses DHCPv6) or only some of them do, "
    "which looks like random IPv6 breakage.",
)
def prefix_64(net: Network) -> Iterator[Result]:
    used = _client_segments(net)
    seen: set[tuple[str, str]] = set()
    for sub in sorted(router_subnets(net), key=lambda s: s.id):
        if not _routed_v6(sub) or sub.segment_id not in used:
            continue
        prefix = sub.interface.network
        if prefix.prefixlen == 64 or (sub.segment_id, str(prefix)) in seen:
            continue
        seen.add((sub.segment_id, str(prefix)))
        yield found(
            f"{segment_name(net, sub.segment_id)} uses {prefix}",
            [sub.segment_id, sub.id],
            fix="Use a /64 per network; split a larger delegated prefix into /64s.",
            key=str(prefix),
        )


@rule(
    "ipv6.partial",
    "IPv6 only on some client networks",
    Severity.INFO,
    "The router has IPv6 on some networks with clients but not on others, or one network has "
    "only a local (ULA) prefix while the others have global ones. Usually a network added later "
    "was forgotten when IPv6 was set up: devices there behave differently (no IPv6 "
    "reachability, other DNS paths). Turn the rule off if IPv6 is disabled there on purpose.",
)
def partial(net: Network) -> Iterator[Result]:
    used = _client_segments(net)
    kinds: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    by_segment: dict[str, list[Subnet]] = defaultdict(list)
    for sub in router_subnets(net):
        if sub.segment_id in used:
            by_segment[sub.segment_id].append(sub)
    for seg_id, subs in by_segment.items():
        site = _site_of_segment(net, seg_id, subs) or ""
        found_kinds = {
            k
            for s in subs
            if _routed_v6(s) and isinstance(s.interface.ip, IPv6Address)
            for k in [_kind(s.interface.ip)]
            if k
        }
        kind = "global" if "global" in found_kinds else ("ula" if found_kinds else "none")
        kinds[site][kind].add(seg_id)
    for _site, groups in sorted(kinds.items()):
        with_v6 = groups["global"] | groups["ula"]
        if not with_v6:
            continue
        others = ", ".join(sorted(segment_name(net, s) for s in with_v6))
        for seg_id in sorted(groups["none"]):
            yield found(
                f"{segment_name(net, seg_id)} has no IPv6 while {others} "
                f"{'do' if len(with_v6) > 1 else 'does'}",
                [seg_id],
                fix="Add a /64 from the delegated prefix to this network, or turn this rule off "
                "if IPv6 is disabled there on purpose.",
                key="none",
            )
        if groups["global"]:
            names = ", ".join(sorted(segment_name(net, s) for s in groups["global"]))
            for seg_id in sorted(groups["ula"]):
                yield found(
                    f"{segment_name(net, seg_id)} has only a local (ULA) IPv6 prefix while "
                    f"{names} {'have' if len(groups['global']) > 1 else 'has'} a global one",
                    [seg_id],
                    fix="Add a /64 from the delegated prefix to this network, or turn this rule "
                    "off if it should stay local on purpose.",
                    key="ula",
                )


RULES: list[Rule] = [unknown_prefix, prefix_64, partial]
