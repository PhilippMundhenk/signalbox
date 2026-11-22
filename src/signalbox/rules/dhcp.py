"""DHCP and addressing rules (issue #6)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from itertools import combinations

from signalbox.adapters import Capability
from signalbox.model import DhcpPool, DhcpServer, IPAddress, Network, Subnet
from signalbox.rules import Result, Rule, Severity, found, incomplete, rule
from signalbox.rules._names import device_name, router_subnets, segment_name, site_of_device


def _enabled_servers(net: Network) -> list[DhcpServer]:
    return [s for s in net.dhcp_servers if s.enabled]


def _gateway_subnets(net: Network, segment_id: str) -> list[Subnet]:
    return [s for s in router_subnets(net) if s.segment_id == segment_id]


def _span(pool: DhcpPool) -> tuple[IPAddress, IPAddress]:
    lo, hi = sorted((pool.start, pool.end))
    return lo, hi


def _in_pool(address: IPAddress, pool: DhcpPool) -> bool:
    if address.version != pool.start.version:
        return False
    lo, hi = _span(pool)
    return lo <= address <= hi  # type: ignore[operator]


def _pool_text(pool: DhcpPool) -> str:
    return f"{pool.start}-{pool.end}"


def _dhcp_unknown_sites(net: Network) -> set[str]:
    """Sites where no device reported DHCP: either none can, or every one that can failed."""
    failed = {e.device_id for e in net.errors if e.capability == Capability.DHCP}
    readers: dict[str, bool] = defaultdict(bool)
    for dev in net.devices:
        readers[dev.site_id] |= Capability.DHCP in dev.capabilities and dev.id not in failed
    return {site for site, ok in readers.items() if not ok}


@rule(
    "dhcp.one-server",
    "One DHCP server per network",
    Severity.ERROR,
    "Every network (VLAN) with a router needs exactly one DHCP server that hands out addresses. "
    "With none, devices that join the network get no address; with two, they answer each other's "
    "clients with different addresses, gateways or DNS servers and connections break at random.",
)
def one_server(net: Network) -> Iterator[Result]:
    servers: dict[str, list[DhcpServer]] = defaultdict(list)
    for srv in _enabled_servers(net):
        servers[srv.segment_id].append(srv)
    # IPv6-only networks often use SLAAC instead of DHCP: only IPv4 routers count here.
    routed = {s.segment_id for s in router_subnets(net) if s.interface.version == 4}
    unknown = _dhcp_unknown_sites(net)
    missing: dict[str, list[str]] = defaultdict(list)
    for seg_id in sorted(routed | set(servers)):
        found_here = servers.get(seg_id, [])
        label = segment_name(net, seg_id)
        if len(found_here) > 1:
            names = ", ".join(sorted(device_name(net, s.device_id) for s in found_here))
            yield found(
                f"{len(found_here)} DHCP servers on {label}: {names}",
                [seg_id, *sorted(s.id for s in found_here)],
                fix="Keep the DHCP server on the router of this network and disable the others.",
            )
        elif not found_here:
            if net.dhcp_relays_on(seg_id):
                continue  # a relay forwards to a server elsewhere (#183)
            seg = net.segment(seg_id)
            gw = _gateway_subnets(net, seg_id)
            site = seg.site_id if seg else site_of_device(net, gw[0].device_id)
            if site in unknown:
                missing[str(site)].append(seg_id)
                continue
            yield found(
                f"No DHCP server on {label}",
                [seg_id],
                fix="Enable a DHCP server for this network on its router, or give every device "
                "on it a fixed address if that is intended.",
                severity=Severity.WARNING,
            )
    for site, seg_ids in sorted(missing.items()):
        yield incomplete(
            f"No device at site {site} reported its DHCP servers, so it is not known whether "
            f"{', '.join(segment_name(net, s) for s in seg_ids)} have one",
            seg_ids,
        )


@rule(
    "dhcp.pools-overlap",
    "DHCP pools overlap",
    Severity.WARNING,
    "Two address pools of the same DHCP server cover the same addresses. The server may hand out "
    "one address twice or refuse to start.",
)
def pools_overlap(net: Network) -> Iterator[Result]:
    for srv in _enabled_servers(net):
        for a, b in combinations(srv.pools, 2):
            if a.start.version != b.start.version:
                continue
            (alo, ahi), (blo, bhi) = _span(a), _span(b)
            if alo <= bhi and blo <= ahi:  # type: ignore[operator]
                yield found(
                    f"DHCP server on {device_name(net, srv.device_id)} for "
                    f"{segment_name(net, srv.segment_id)}: pools {_pool_text(a)} and "
                    f"{_pool_text(b)} overlap",
                    [srv.id],
                    fix="Shrink or merge the pools so that every address is in at most one.",
                    key=f"{_pool_text(a)} {_pool_text(b)}",
                )


@rule(
    "dhcp.pool-fixed-address",
    "Router or device address inside a DHCP pool",
    Severity.WARNING,
    "An address that a router, switch or access point uses on this network lies inside the "
    "range the DHCP server hands out. Sooner or later a client gets the same address and both "
    "stop working.",
)
def pool_fixed_address(net: Network) -> Iterator[Result]:
    for srv in _enabled_servers(net):
        for sub in net.subnets:
            if sub.segment_id != srv.segment_id:
                continue
            address = sub.interface.ip
            for pool in srv.pools:
                if _in_pool(address, pool):
                    yield found(
                        f"{address} of {device_name(net, sub.device_id)} is inside the DHCP pool "
                        f"{_pool_text(pool)} on {segment_name(net, srv.segment_id)}",
                        [srv.id, sub.id],
                        fix="Move the pool so that it starts above the fixed addresses, or give "
                        "the device an address outside the pool.",
                    )


@rule(
    "dhcp.reservation-in-pool",
    "Reserved address inside a DHCP pool",
    Severity.WARNING,
    "A static reservation uses an address from the dynamic pool. Many DHCP servers can hand that "
    "address to another client while the reserved device is offline; keeping reservations "
    "outside the pool avoids the conflict.",
)
def reservation_in_pool(net: Network) -> Iterator[Result]:
    for srv in _enabled_servers(net):
        for res in srv.reservations:
            for pool in srv.pools:
                if _in_pool(res.address, pool):
                    who = res.hostname or res.mac
                    yield found(
                        f"Reservation {res.address} for {who} on "
                        f"{segment_name(net, srv.segment_id)} is inside the pool "
                        f"{_pool_text(pool)}",
                        [srv.id],
                        fix="Pick a reserved address outside the pool, or shrink the pool.",
                        key=f"{res.mac} {res.address}",
                    )


@rule(
    "dhcp.router-option",
    "DHCP hands out the wrong router",
    Severity.WARNING,
    "The router (default gateway) a DHCP server tells its clients must be the address of the "
    "router on that network. Otherwise clients can reach their neighbours but not the internet.",
)
def router_option(net: Network) -> Iterator[Result]:
    for srv in _enabled_servers(net):
        if srv.router is None:
            continue
        label = segment_name(net, srv.segment_id)
        gateways = [
            g
            for g in _gateway_subnets(net, srv.segment_id)
            if g.interface.version == srv.router.version
        ]
        if not gateways:
            yield incomplete(
                f"No router address is known for {label}, so the router option {srv.router} of "
                f"the DHCP server on {device_name(net, srv.device_id)} cannot be checked",
                [srv.id],
            )
            continue
        expected = sorted({str(g.interface.ip) for g in gateways})
        if str(srv.router) not in expected:
            yield found(
                f"DHCP server on {device_name(net, srv.device_id)} tells clients on {label} to use "
                f"router {srv.router}, but the router of this network is {', '.join(expected)}",
                [srv.id, *sorted(g.id for g in gateways)],
                fix=f"Set the router (gateway) option of this DHCP server to {expected[0]}.",
            )


def _resolver_addresses(net: Network) -> set[str]:
    """Listen addresses of enabled DNS services; all interface addresses if none are given."""
    out: set[str] = set()
    for dns in net.dns_services:
        if not dns.enabled:
            continue
        if dns.listen:
            out |= {str(a) for a in dns.listen}
        else:
            out |= {str(s.interface.ip) for s in net.subnets if s.device_id == dns.device_id}
    return out


@rule(
    "dhcp.dns-option",
    "DHCP hands out an unknown DNS server",
    Severity.WARNING,
    "The DNS servers a DHCP server tells its clients should be the resolver of this network "
    "(a DNS service Signalbox knows, or the router). Clients that use another resolver bypass "
    "local names, filtering and ad blocking, or fail if that address does not exist.",
)
def dns_option(net: Network) -> Iterator[Result]:
    resolvers = _resolver_addresses(net)
    for srv in _enabled_servers(net):
        allowed = resolvers | {str(g.interface.ip) for g in _gateway_subnets(net, srv.segment_id)}
        unknown = [str(a) for a in srv.dns_servers if str(a) not in allowed]
        if unknown:
            yield found(
                f"DHCP server on {device_name(net, srv.device_id)} tells clients on "
                f"{segment_name(net, srv.segment_id)} to use DNS server "
                f"{', '.join(unknown)}, which is not a known resolver or the router",
                [srv.id],
                fix="Set the DNS option to the address of your router or local DNS resolver, or "
                "turn this rule off if an outside resolver is intended.",
            )


@rule(
    "addr.subnet-overlap",
    "Subnets overlap",
    Severity.ERROR,
    "Two different networks (VLANs, or networks at different sites) use overlapping address "
    "ranges. Routers cannot tell where to send traffic for those addresses, so some devices "
    "become unreachable.",
)
def subnet_overlap(net: Network) -> Iterator[Result]:
    seen: set[tuple[str, str, str, str]] = set()
    for a, b in combinations(sorted(net.subnets, key=lambda s: s.id), 2):
        if a.segment_id == b.segment_id or a.interface.version != b.interface.version:
            continue
        na, nb = a.interface.network, b.interface.network
        if not na.overlaps(nb):
            continue
        segs = sorted([(a.segment_id, str(na)), (b.segment_id, str(nb))])
        pair = (segs[0][0], segs[0][1], segs[1][0], segs[1][1])
        if pair in seen:
            continue
        seen.add(pair)
        yield found(
            f"{segs[0][1]} on {segment_name(net, segs[0][0])} overlaps {segs[1][1]} on "
            f"{segment_name(net, segs[1][0])}",
            [segs[0][0], segs[1][0]],
            fix="Give each network its own, non-overlapping address range.",
            key=f"{segs[0][1]} {segs[1][1]}",
        )


@rule(
    "addr.duplicate-ip",
    "Address used by more than one device",
    Severity.ERROR,
    "The same IP address belongs to devices with different MAC addresses (seen as clients or "
    "set as DHCP reservations). Only one of them can work at a time.",
)
def duplicate_ip(net: Network) -> Iterator[Result]:
    users: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for client in net.clients:
        for address in client.addresses:
            if not address.is_link_local:
                users[str(address)][client.mac].add(client.id)
    for srv in net.dhcp_servers:
        for res in srv.reservations:
            users[str(res.address)][res.mac].add(srv.id)
    for text, by_mac in sorted(users.items()):
        if len(by_mac) < 2:
            continue
        objects = sorted({o for ids in by_mac.values() for o in ids})
        yield found(
            f"{text} is used by {len(by_mac)} devices: {', '.join(sorted(by_mac))}",
            objects,
            fix="Give each device its own address: change the reservation or the fixed address "
            "of one of them.",
            key=text,
        )


RULES: list[Rule] = [
    one_server,
    pools_overlap,
    pool_fixed_address,
    reservation_in_pool,
    router_option,
    dns_option,
    subnet_overlap,
    duplicate_ip,
]
