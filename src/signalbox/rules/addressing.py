"""Addressing and DHCP checks beyond the basic DHCP rules (issues #53-#69).

Clients against their subnets, router addresses, pool size and position, reservations, lease
times, DHCP domains and management addresses. Every rule stays quiet when the data it needs was
not reported, and reports an incomplete finding only where the gap is worth knowing.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from ipaddress import IPv4Interface, ip_address

from signalbox.firewall import forward_target_ports, port_ranges_overlap
from signalbox.model import (
    Client,
    DeviceRole,
    DhcpPool,
    DhcpServer,
    IPAddress,
    Membership,
    NatClass,
    Network,
    SegmentPurpose,
    Subnet,
    Uplink,
)
from signalbox.rules import Result, Rule, Severity, found, incomplete, rule
from signalbox.rules._names import device_name, router_subnets, segment_name, site_of_device

# --- helpers -------------------------------------------------------------------------------------


def _enabled(net: Network) -> list[DhcpServer]:
    return [s for s in net.dhcp_servers if s.enabled]


def _usable(address: IPAddress) -> bool:
    """An address a client really uses: not link-local, loopback, multicast or unspecified."""
    return not (
        address.is_link_local
        or address.is_loopback
        or address.is_multicast
        or address.is_unspecified
    )


def _contains(sub: Subnet, address: IPAddress) -> bool:
    return address.version == sub.interface.version and address in sub.interface.network


def _segments_of(net: Network, address: IPAddress) -> set[str]:
    return {s.segment_id for s in net.subnets if _contains(s, address)}


def _in_pool(address: IPAddress, pool: DhcpPool) -> bool:
    if address.version != pool.start.version or pool.start.version != pool.end.version:
        return False
    lo, hi = sorted((int(pool.start), int(pool.end)))
    return lo <= int(address) <= hi


def _pool_text(pool: DhcpPool) -> str:
    return f"{pool.start}-{pool.end}"


def _client_name(c: Client) -> str:
    return f"{c.hostname} ({c.mac})" if c.hostname else c.mac


def _plural(n: int, word: str, plural: str = "") -> str:
    return f"{n} {word}" if n == 1 else f"{n} {plural or word + 's'}"


def _server_name(net: Network, srv: DhcpServer, article: str = "the") -> str:
    return f"{article} DHCP server on {device_name(net, srv.device_id)}"


def _join(items: Iterable[str]) -> str:
    return ", ".join(items)


# --- addr.client-subnet (#53) --------------------------------------------------------------------


@rule(
    "addr.client-subnet",
    "Client address outside its network",
    Severity.WARNING,
    "A client uses an address that does not belong to the subnet of the network it is in, or "
    "addresses of two networks at once. It has a stale fixed address, got a lease from a second "
    "DHCP server, or sits in another VLAN than expected (for example through a port or access "
    'point that joins two networks). The result is often "connected but no internet", or '
    "guests reaching the main network.",
)
def client_subnet(net: Network) -> Iterator[Result]:
    own: dict[str, list[Subnet]] = defaultdict(list)
    for sub in net.subnets:
        own[sub.segment_id].append(sub)
    unknown: dict[str, list[str]] = defaultdict(list)
    for c in net.clients:
        addresses = [a for a in c.addresses if _usable(a)]
        if not addresses:
            continue
        homes: dict[IPAddress, str] = {}
        for a in addresses:
            segs = _segments_of(net, a)
            if len(segs) == 1:  # overlapping subnets are addr.subnet-overlap's business
                homes[a] = segs.pop()
        if len(set(homes.values())) > 1:
            detail = "; ".join(f"{a} in {segment_name(net, s)}" for a, s in homes.items())
            yield found(
                f"{_client_name(c)} has addresses in {len(set(homes.values()))} networks: {detail}",
                [c.id, *sorted(set(homes.values()))],
                fix="One device should be in one network. Check the port or access point it is "
                "connected to for a bridge or wrong VLAN between these networks.",
                key="networks",
            )
            continue
        if c.segment_id is None:
            continue
        subs = own.get(c.segment_id, [])
        if not subs:
            unknown[c.segment_id].append(c.id)
            continue
        versions = {s.interface.version for s in subs}
        label = segment_name(net, c.segment_id)
        for a in addresses:
            if a.version not in versions or any(_contains(s, a) for s in subs):
                continue
            nets = sorted(
                {str(s.interface.network) for s in subs if s.interface.version == a.version}
            )
            yield found(
                f"{_client_name(c)} uses {a}, which is not in the subnet of {label} "
                f"({_join(nets)})",
                [c.id, c.segment_id],
                fix="Check for a fixed address on the client, a second DHCP server, or a port "
                "in the wrong VLAN.",
                key=str(a),
            )
    for seg_id, ids in sorted(unknown.items()):
        yield incomplete(
            f"No subnet is known for {segment_name(net, seg_id)}, so the addresses of its "
            f"{_plural(len(ids), 'client')} cannot be checked",
            [seg_id],
        )


# --- dhcp.self-assigned (#54) --------------------------------------------------------------------


@rule(
    "dhcp.self-assigned",
    "Clients with a self-assigned address",
    Severity.WARNING,
    "A device that has only a 169.254.x.x address gave up waiting for a DHCP answer: the DHCP "
    "server is down, its pool is full, the VLAN does not reach the server, or a firewall blocks "
    'DHCP. The user only sees "no internet" on that device.',
)
def self_assigned(net: Network) -> Iterator[Result]:
    served = {s.segment_id for s in _enabled(net)}
    stuck: dict[str, list[Client]] = defaultdict(list)
    for c in net.clients:
        v4 = [a for a in c.addresses if a.version == 4]
        if v4 and all(a.is_link_local for a in v4) and c.segment_id in served:
            stuck[str(c.segment_id)].append(c)
    for seg_id, clients in sorted(stuck.items()):
        n = len(clients)
        yield found(
            f"{_plural(n, 'client')} on {segment_name(net, seg_id)} "
            f"{'has' if n == 1 else 'have'} only a self-assigned 169.254.x.x address: "
            f"{_join(_client_name(c) for c in clients)}",
            [seg_id, *(c.id for c in clients)],
            fix="Check that the DHCP server of the network is running, the pool is not full and "
            "the VLAN is carried to the port or access point.",
        )


# --- addr.prefix-consistent (#55) ----------------------------------------------------------------


@rule(
    "addr.prefix-consistent",
    "Device address does not match the router's subnet",
    Severity.ERROR,
    "A switch, access point or other device on a network has an address outside the router's "
    "subnet, or the right address with another mask. It cannot reach its gateway (or reaches "
    "only part of the network): it becomes unreachable from other networks, loses time and "
    "updates, and often keeps an old factory address.",
)
def prefix_consistent(net: Network) -> Iterator[Result]:
    routers = router_subnets(net)
    router_ids = {s.id for s in routers}
    by_seg: dict[tuple[str, int], list[Subnet]] = defaultdict(list)
    for s in routers:
        by_seg[(s.segment_id, s.interface.version)].append(s)
    missing: dict[tuple[str, int], set[str]] = defaultdict(set)
    for sub in sorted(net.subnets, key=lambda s: s.id):
        # IPv6 links often carry several prefixes (an access point's own ULA): IPv4 only.
        if sub.id in router_ids or sub.interface.version != 4 or sub.interface.ip.is_link_local:
            continue
        gws = by_seg.get((sub.segment_id, sub.interface.version))
        if not gws:
            missing[(sub.segment_id, sub.interface.version)].add(sub.device_id)
            continue
        name, label = device_name(net, sub.device_id), segment_name(net, sub.segment_id)
        inside = [g for g in gws if sub.interface.ip in g.interface.network]
        if not inside:
            ref = _join(sorted({str(g.interface) for g in gws}))
            yield found(
                f"{name} has {sub.interface} on {label}, outside the router's subnet ({ref})",
                [sub.id, *sorted(g.id for g in gws)],
                fix=f"Set the address and mask of {name} to the router's subnet.",
            )
        elif all(g.interface.network.prefixlen != sub.interface.network.prefixlen for g in inside):
            yield found(
                f"{name} has {sub.interface} on {label}, the router uses {inside[0].interface}",
                [sub.id, *sorted(g.id for g in inside)],
                fix=f"Set the mask of {name} to /{inside[0].interface.network.prefixlen} like the "
                "router's.",
                severity=Severity.WARNING,
            )
    for (seg_id, version), devices in sorted(missing.items()):
        names = _join(sorted(device_name(net, d) for d in devices))
        yield incomplete(
            f"No IPv{version} router address is known for {segment_name(net, seg_id)}, so the "
            f"address of {names} cannot be compared with it",
            [seg_id],
            key=str(version),
        )


# --- addr.gateway-position (#56) -----------------------------------------------------------------


@rule(
    "addr.gateway-position",
    "Router address at an unusual position",
    Severity.INFO,
    "Most people and devices with a fixed configuration expect the router at the first address "
    "of a subnet (.1 in a /24), some at the last. A router in the middle of the range, or "
    "networks of one site that mix both conventions, are a frequent cause of manually "
    "configured devices without internet.",
)
def gateway_position(net: Network) -> Iterator[Result]:
    entries: dict[str, dict[tuple[str, str], tuple[Subnet, str]]] = defaultdict(dict)
    for sub in sorted(router_subnets(net), key=lambda s: s.id):
        iface = sub.interface
        if not isinstance(iface, IPv4Interface) or iface.network.prefixlen > 30:
            continue
        first, last = iface.network.network_address + 1, iface.network.broadcast_address - 1
        pos = "first" if iface.ip == first else "last" if iface.ip == last else "middle"
        seg = net.segment(sub.segment_id)
        site = seg.site_id if seg else site_of_device(net, sub.device_id)
        entries[str(site)].setdefault((sub.segment_id, str(iface)), (sub, pos))
    for _site, subs in sorted(entries.items()):
        counts = Counter(pos for _, pos in subs.values() if pos != "middle")
        usual = "last" if counts["last"] > counts["first"] else "first"
        for sub, pos in subs.values():
            iface = sub.interface
            assert isinstance(iface, IPv4Interface)
            first = iface.network.network_address + 1
            target = first if usual == "first" else iface.network.broadcast_address - 1
            label = segment_name(net, sub.segment_id)
            fix = (
                f"Consider moving it to {target} (and update the DHCP router option and devices "
                "with a fixed address), or turn this rule off if the position is intended."
            )
            if pos == "middle":
                yield found(
                    f"The router address of {label} is {iface.ip}, neither the first nor the "
                    f"last usable address of {iface.network}",
                    [sub.id],
                    fix=fix,
                )
            elif pos != usual and counts["first"] and counts["last"]:
                yield found(
                    f"The router address of {label} is {iface.ip}, the {pos} usable address; "
                    f"the other networks of this site use the {usual} one",
                    [sub.id],
                    fix=fix,
                )


# --- dhcp.pool-usage (#57) and dhcp.lease-time (#65) ---------------------------------------------


@dataclass(frozen=True)
class _Usage:
    available: int
    used: int
    seen: int

    @property
    def high(self) -> bool:
        return self.used > 0.8 * self.available


def _usage(net: Network, srv: DhcpServer) -> _Usage | None:
    """Free pool addresses, clients holding one, clients seen on the network; None without pool."""
    if not srv.pools:
        return None
    spans: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for p in srv.pools:
        if p.start.version == p.end.version:
            lo, hi = sorted((int(p.start), int(p.end)))
            spans[p.start.version].append((lo, hi))
    size = 0
    for intervals in spans.values():
        end = -1
        for lo, hi in sorted(intervals):
            lo = max(lo, end + 1)
            if hi >= lo:
                size += hi - lo + 1
                end = hi
    in_pool = {
        r.address for r in srv.reservations if any(_in_pool(r.address, p) for p in srv.pools)
    }
    reserved = {r.mac for r in srv.reservations}
    used: set[str] = set()
    seen: set[str] = set()
    for c in net.clients:
        if c.mac in reserved or c.segment_id not in (srv.segment_id, None):
            continue
        if any(a not in in_pool and any(_in_pool(a, p) for p in srv.pools) for a in c.addresses):
            used.add(c.mac)
        if c.segment_id == srv.segment_id and any(
            a.version in spans and _usable(a) for a in c.addresses
        ):
            seen.add(c.mac)
    # The lease table says what is taken right now (#183); clients seen are the fallback and a
    # table an adapter capped may hold fewer leases than there are clients.
    leased = {
        x.address
        for x in srv.active_leases(srv.observed_at)
        if x.address not in in_pool and any(_in_pool(x.address, p) for p in srv.pools)
    }
    return _Usage(size - len(in_pool), max(len(used), len(leased)), len(seen))


@rule(
    "dhcp.pool-usage",
    "DHCP pool (nearly) full",
    Severity.WARNING,
    "When the address pool of a network is full, new phones, guests or a replaced device get no "
    "address and fall back to 169.254.x.x. Small pools with long lease times run out quickly, "
    "because every visitor keeps an address for days.",
)
def pool_usage(net: Network) -> Iterator[Result]:
    for srv in _enabled(net):
        label = segment_name(net, srv.segment_id)
        usage = _usage(net, srv)
        if usage is None:
            yield incomplete(
                f"{_server_name(net, srv, 'The')} for {label} did not report its pool, so "
                "its size cannot be checked",
                [srv.id],
            )
            continue
        fix = "Enlarge the pool (and the subnet if needed) or shorten the lease time."
        size = _plural(usage.available, "free address", "free addresses")
        if usage.used >= usage.available:
            yield found(
                f"The pool of {label} is full: it has {size} and {usage.used} are in use",
                [srv.id],
                fix=fix,
                severity=Severity.ERROR,
            )
        elif usage.high:
            yield found(
                f"The pool of {label} has {size} and {usage.used} are in use",
                [srv.id],
                fix=fix,
            )
        elif usage.seen > usage.available:
            yield found(
                f"{usage.seen} clients without a reservation have been seen on {label}, but its "
                f"pool has only {size}",
                [srv.id],
                fix=fix,
                key="seen",
            )


#: Lease times outside these bounds (seconds) are reported.
LEASE_MIN, LEASE_MAX, GUEST_LEASE_MAX = 5 * 60, 7 * 86400, 86400


def _duration(seconds: int) -> str:
    for unit, name in ((86400, "day"), (3600, "hour"), (60, "minute")):
        if seconds >= unit and seconds % unit == 0:
            return _plural(seconds // unit, name)
    return _plural(seconds, "second")


def _is_guest(net: Network, segment_id: str) -> bool:
    """A guest network: by purpose (declared, reported or guessed), or one of its SSIDs is."""
    seg = net.segment(segment_id)
    if seg is not None and seg.purpose is not None:
        return seg.purpose is SegmentPurpose.GUEST
    return any(
        w.purpose is SegmentPurpose.GUEST
        for w in net.wlans
        if w.segment_id == segment_id and w.enabled
    )


@rule(
    "dhcp.lease-time",
    "DHCP lease time very short or very long",
    Severity.INFO,
    "Very short leases cause constant DHCP traffic and short outages when the server is busy. "
    "Very long leases exhaust small pools (every visitor keeps an address) and keep moved "
    "devices on old addresses for days.",
)
def lease_time(net: Network) -> Iterator[Result]:
    for srv in _enabled(net):
        seconds = srv.lease_seconds
        if seconds is None:
            continue
        reserved = {r.mac for r in srv.reservations}
        clients = {
            c.mac
            for c in net.clients
            if c.segment_id == srv.segment_id and any(_usable(a) for a in c.addresses)
        }
        if clients and clients <= reserved:
            continue  # every client has a fixed lease
        label = segment_name(net, srv.segment_id)
        usage = _usage(net, srv)
        severity = Severity.WARNING if usage and usage.high else None
        lead = f"{_server_name(net, srv, 'The')} hands out leases of {_duration(seconds)}"
        fix = "Use 12-24 hours (a few hours on guest networks)."
        if seconds < LEASE_MIN:
            yield found(f"{lead} on {label}, which is very short", [srv.id], fix=fix)
        elif seconds > LEASE_MAX:
            yield found(
                f"{lead} on {label}, which is very long", [srv.id], fix=fix, severity=severity
            )
        elif seconds > GUEST_LEASE_MAX and _is_guest(net, srv.segment_id):
            yield found(
                f"{lead} on the guest network {label}; visitors keep their address that long",
                [srv.id],
                fix="Use a few hours on guest networks.",
                severity=severity,
            )


# --- dhcp.in-subnet (#58) ------------------------------------------------------------------------


def _special(sub: Subnet, address: IPAddress) -> str | None:
    """Why an address of the subnet cannot be handed out, if it cannot."""
    iface = sub.interface
    if address == iface.ip:
        return f"the router address of {sub.interface.network}"
    if isinstance(iface, IPv4Interface) and iface.network.prefixlen <= 30:
        if address == iface.network.network_address:
            return f"the network address of {iface.network}"
        if address == iface.network.broadcast_address:
            return f"the broadcast address of {iface.network}"
    return None


def _subnet_of(subnets: list[Subnet], address: IPAddress) -> Subnet | None:
    return next((s for s in subnets if _contains(s, address)), None)


def _nets(subnets: list[Subnet], version: int) -> str:
    return _join(
        sorted({str(s.interface.network) for s in subnets if s.interface.version == version})
    )


@rule(
    "dhcp.in-subnet",
    "DHCP pool or reservation outside the subnet",
    Severity.ERROR,
    "A DHCP pool or reservation hands out addresses that the clients of the network cannot use: "
    "outside the network's subnet (often after the subnet was resized), or the network, "
    "broadcast or router address. A reservation on the router address knocks out the gateway.",
)
def in_subnet(net: Network) -> Iterator[Result]:
    routers = router_subnets(net)
    for srv in _enabled(net):
        label = segment_name(net, srv.segment_id)
        for p in srv.pools:
            if p.start.version == p.end.version and int(p.start) > int(p.end):
                yield found(
                    f"The pool {_pool_text(p)} of {label} ends before it starts",
                    [srv.id],
                    fix="Swap the start and end address of the pool.",
                    key=f"order {_pool_text(p)}",
                )
        gws = [g for g in routers if g.segment_id == srv.segment_id]
        checked = [p.start for p in srv.pools] + [r.address for r in srv.reservations]
        versions = sorted({a.version for a in checked} - {g.interface.version for g in gws})
        for version in versions:
            yield incomplete(
                f"No IPv{version} router subnet is known for {label}; "
                f"{_server_name(net, srv)} may serve a relayed network, so its pools and "
                "reservations cannot be checked against the subnet",
                [srv.id],
                key=str(version),
            )

        for p in srv.pools:
            if p.start.version not in {g.interface.version for g in gws}:
                continue
            lo, hi = sorted((p.start, p.end), key=int)
            home = _subnet_of(gws, lo)
            if home is None or not _contains(home, hi):
                yield found(
                    f"The pool {_pool_text(p)} of {label} extends beyond {_nets(gws, lo.version)}",
                    [srv.id],
                    fix="Shrink the pool to the subnet.",
                    key=f"pool {_pool_text(p)}",
                )
                continue
            for end in (lo, hi):
                why = _special(home, end)
                if why and end != home.interface.ip:  # router address: dhcp.pool-fixed-address
                    yield found(
                        f"The pool {_pool_text(p)} of {label} includes {end}, {why}",
                        [srv.id],
                        fix="Start the pool after the network address and end it before the "
                        "broadcast address.",
                        key=f"pool {_pool_text(p)} {end}",
                    )
        for r in srv.reservations:
            if r.address.version not in {g.interface.version for g in gws}:
                continue
            home = _subnet_of(gws, r.address)
            who = r.hostname or r.mac
            if home is None:
                yield found(
                    f"The reservation {r.address} for {who} on {label} is outside "
                    f"{_nets(gws, r.address.version)}",
                    [srv.id],
                    fix="Reserve an address inside the subnet of the network.",
                    key=f"reservation {r.mac} {r.address}",
                )
            elif why := _special(home, r.address):
                yield found(
                    f"The reservation {r.address} for {who} on {label} is {why}",
                    [srv.id],
                    fix="Reserve a normal host address of the subnet for this device.",
                    key=f"reservation {r.mac} {r.address}",
                )


# --- addr.one-gateway (#59) ----------------------------------------------------------------------


@rule(
    "addr.one-gateway",
    "More than one router on a network",
    Severity.ERROR,
    "Two devices act as router on the same network, typically the internet provider's router "
    "and a firewall, or an access point still in router mode. Clients get a different default "
    "gateway depending on which one answered first: some bypass the firewall, and port "
    "forwards, VPN or parental controls work only for some devices.",
)
def one_gateway(net: Network) -> Iterator[Result]:
    dhcp_on = {(s.device_id, s.segment_id) for s in _enabled(net)}
    routers: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for sub in net.subnets:
        dev = net.device(sub.device_id)
        is_router = sub.gateway or (
            dev is not None
            and dev.role is DeviceRole.GATEWAY
            and (sub.device_id, sub.segment_id) in dhcp_on
        )
        if is_router and not sub.interface.ip.is_link_local:
            routers[sub.segment_id][sub.device_id].add(str(sub.interface.ip))
    for seg_id, devices in sorted(routers.items()):
        # devices that share an address (a virtual address of a redundant pair) count as one
        groups: list[tuple[set[str], set[str]]] = []
        for dev_id, addresses in sorted(devices.items()):
            merged = ({dev_id}, set(addresses))
            for g in [g for g in groups if g[1] & addresses]:
                groups.remove(g)
                merged = (merged[0] | g[0], merged[1] | g[1])
            groups.append(merged)
        if len(groups) < 2:
            continue
        detail = _join(
            f"{device_name(net, d)} ({_join(sorted(devices[d]))})" for d in sorted(devices)
        )
        yield found(
            f"{segment_name(net, seg_id)} has {len(groups)} routers: {detail}",
            [seg_id, *sorted(devices)],
            fix="Keep one router per network; put the others in access-point (bridge) mode or "
            "connect them through their own transit network.",
        )


# --- addr.double-nat (#60) -----------------------------------------------------------------------

_DOUBLE_NAT_FIX = (
    "Nothing to do if everything works. If port forwards, a VPN server, games or IPv6 behind "
    "{inner} matter, put {outer} into bridge (modem) mode, or make {inner} its exposed host "
    "(DMZ) and forward the ports there."
)


def _port_text(net: Network, port_id: str) -> str:
    port = net.port(port_id)
    name = port.label() if port else port_id.rsplit("/port/", 1)[-1]
    device = port.device_id if port else port_id.split("/port/", 1)[0]
    return f"{device_name(net, device)} port {name}"


def _cable_between(net: Network, port: str | None, device_id: str) -> str:
    """`` (cable A port x to B port y)`` when a link joins ``port`` to ``device_id``."""
    for link in net.links:
        for here, there in ((link.a, link.b), (link.b, link.a)):
            other = net.port(there)
            if here == port and other is not None and other.device_id == device_id:
                return f" (cable {_port_text(net, there)} to {_port_text(net, here)})"
    return ""


def _forwards_on_inner_only(net: Network, u: Uplink, upstream: Subnet) -> Iterator[Result]:
    """Port forwards of the inner router that the outer router does not pass on (#60, #135):
    from the internet they never arrive. Quiet unless both forward lists were read."""
    inner, outer = net.firewall_of(u.device_id), net.firewall_of(upstream.device_id)
    if inner is None or outer is None:
        return
    if not (inner.port_forwards_complete and outer.port_forwards_complete):
        return
    mine = {a.ip for a in u.addresses}
    passed = [f for f in outer.port_forwards if f.enabled and f.target_address in mine]
    dead = []
    for pf in inner.port_forwards:
        if not pf.enabled or not pf.external_ports:
            continue
        if pf.zones and not inner.zones_of(u.id) & set(pf.zones):
            continue  # listens on another interface
        if not any(
            (not o.protocols or not pf.protocols or set(o.protocols) & set(pf.protocols))
            and port_ranges_overlap(forward_target_ports(o), pf.external_ports)
            for o in passed
        ):
            dead.append(pf)
    if not dead:
        return
    inner_name, outer_name = device_name(net, u.device_id), device_name(net, upstream.device_id)
    ports = ", ".join(
        f"{'/'.join(p.value.upper() for p in pf.protocols) or 'all'} "
        f"{', '.join(str(r) for r in pf.external_ports)}"
        for pf in dead
    )
    yield found(
        f"{inner_name} forwards {ports} to devices behind it, but {outer_name} in front of it "
        f"does not forward them to {inner_name}: from the internet these ports never arrive.",
        [u.device_id, upstream.device_id, u.id],
        severity=Severity.WARNING,
        fix=f"Forward the same ports on {outer_name} to {inner_name}'s WAN address, make "
        f"{inner_name} the exposed host (DMZ) of {outer_name}, or put {outer_name} into "
        "bridge (modem) mode.",
        key=f"{u.id}/forwards",
    )


@rule(
    "addr.double-nat",
    "Router behind another router (double NAT)",
    Severity.INFO,
    "A router gets its internet (WAN) address from another router at the site, or a private or "
    "carrier-grade NAT address from the provider, so traffic is translated twice. Browsing "
    "works, but port forwards, VPN servers, many games and VoIP calls fail or need settings on "
    "both routers, IPv6 prefix delegation often stops at the first router, and it is unclear "
    "which device is the router. Reported as information: it is often intended (a firewall "
    "behind the provider's router). With the firewalls of both routers read (#135), port "
    "forwards on the inner router that the outer router does not pass on are reported "
    "separately as a warning: from the internet they cannot work.",
)
def double_nat(net: Network) -> Iterator[Result]:
    gateways = {d.id for d in net.devices if d.role is DeviceRole.GATEWAY}
    with_uplinks = {u.device_id for u in net.uplinks}
    for u in sorted(net.uplinks, key=lambda x: x.id):
        inner = device_name(net, u.device_id)
        v4 = ", ".join(str(a.ip) for a in u.ipv4())
        upstream = net.upstream_router(u)
        if upstream is not None:
            outer = device_name(net, upstream.device_id)
            yield found(
                f"{inner} gets its WAN address {v4} from {outer} "
                f"({segment_name(net, upstream.segment_id)}, {upstream.interface}): two routers "
                f"in a row{_cable_between(net, u.port_id, upstream.device_id)}.",
                [u.device_id, upstream.device_id, u.id],
                fix=_DOUBLE_NAT_FIX.format(inner=inner, outer=outer),
                key=f"{u.id}/router",
            )
            yield from _forwards_on_inner_only(net, u, upstream)
            continue
        nat = u.nat_class()
        if nat is NatClass.PRIVATE:
            yield found(
                f"{inner} has the private WAN address {v4}: another router that Signalbox does "
                "not read is in front of it.",
                [u.device_id, u.id],
                fix=_DOUBLE_NAT_FIX.format(inner=inner, outer="that router")
                + " Add that router to Signalbox to see both.",
                key=f"{u.id}/private",
            )
        elif nat is NatClass.CGNAT:
            yield found(
                f"{inner} has the WAN address {v4} from the provider's shared address space "
                "(carrier-grade NAT): nothing from the internet reaches it over IPv4.",
                [u.device_id, u.id],
                fix="Nothing to do if everything works. For port forwards or a VPN server over "
                "IPv4, ask the provider for a public IPv4 address, or use IPv6.",
                key=f"{u.id}/cgnat",
            )
    # without uplink data: a gateway port in no segment, cabled to another router's LAN port
    members = {m.port_id for s in net.segments for m in s.members}
    routed = {(x.device_id, x.segment_id) for x in router_subnets(net)}
    lan = {
        m.port_id: s.id for s in net.segments for m in s.members if m.mode is Membership.UNTAGGED
    }
    for link in sorted(net.links, key=lambda x: x.id):
        for wan, other in ((link.a, link.b), (link.b, link.a)):
            here, there = net.port(wan), net.port(other)
            if here is None or there is None or here.device_id == there.device_id:
                continue
            if here.device_id not in gateways or there.device_id not in gateways:
                continue
            if here.device_id in with_uplinks or wan in members or other not in lan:
                continue
            if (there.device_id, lan[other]) not in routed:
                continue  # the other end is not the router of the network it sends
            inner, outer = device_name(net, here.device_id), device_name(net, there.device_id)
            yield found(
                f"{_port_text(net, wan)} is in no network of {inner} and is cabled to "
                f"{_port_text(net, other)} ({segment_name(net, lan[other])}): {inner} probably "
                f"has its WAN there and sits behind {outer} (two routers in a row).",
                [here.device_id, there.device_id, link.id],
                fix=_DOUBLE_NAT_FIX.format(inner=inner, outer=outer),
                key=f"{link.id}/cable",
            )


# --- inventory.management-address (#62) ----------------------------------------------------------


def _management_ip(net: Network, text: str) -> IPAddress | None:
    host = text.strip().lower()
    if host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]
    elif host.count(":") == 1:
        host = host.split(":")[0]
    try:
        return ip_address(host)
    except ValueError:
        pass
    found_ = {
        r.address
        for d in net.dns_services
        for r in d.host_records
        if r.name.lower().rstrip(".") == host.rstrip(".")
    }
    return found_.pop() if len(found_) == 1 else None


@rule(
    "inventory.management-address",
    "Management address is a dynamic DHCP address",
    Severity.WARNING,
    "The address a device is managed at (by Signalbox, by you, by a controller) lies in a DHCP "
    "pool without a reservation. After a power cut or a long downtime it can get another address: "
    "the device seems to disappear. Two devices with the same management address cannot both be "
    "reached.",
)
def management_address(net: Network) -> Iterator[Result]:
    users: dict[str, list[str]] = defaultdict(list)
    for d in net.devices:
        if d.managed_by or not d.management_address:
            continue
        address = _management_ip(net, d.management_address)
        if address is None or address.is_loopback:
            continue  # a host name Signalbox cannot resolve, or a local simulator
        users[str(address)].append(d.id)
        macs = {p.mac for p in net.ports if p.device_id == d.id and p.mac}
        for srv in _enabled(net):
            if site_of_device(net, srv.device_id) != d.site_id:
                continue
            pool = next((p for p in srv.pools if _in_pool(address, p)), None)
            if pool is None:
                continue
            reserved = [r for r in srv.reservations if r.address == address]
            if any(r.mac in macs for r in reserved) if macs else reserved:
                continue
            yield found(
                f"{d.name} is managed at {address}, which is in the DHCP pool {_pool_text(pool)} "
                f"of {segment_name(net, srv.segment_id)} without a reservation",
                [d.id, srv.id],
                fix=f"Add a reservation for the MAC address of {d.name}, or give it a fixed "
                "address outside the pool.",
            )
    for text, ids in sorted(users.items()):
        if len(ids) > 1:
            yield found(
                f"{_join(sorted(device_name(net, i) for i in ids))} use the same management "
                f"address {text}",
                sorted(ids),
                fix="Give every device its own address and correct the address configured in "
                "Signalbox.",
                key=f"duplicate {text}",
            )


# --- dhcp.duplicate-reservation (#63) ------------------------------------------------------------


@rule(
    "dhcp.duplicate-reservation",
    "Device reserved twice on one network",
    Severity.WARNING,
    "One MAC address has several reservations with different addresses on the same network (on "
    "one server or on two), or one host name is reserved for two devices. Which address the "
    "device gets depends on the server and the order of entries, and DNS names and port "
    "forwards point at the other one. Common after moving DHCP from one router to another.",
)
def duplicate_reservation(net: Network) -> Iterator[Result]:
    by_mac: dict[tuple[str, str], list[tuple[DhcpServer, IPAddress]]] = defaultdict(list)
    by_name: dict[tuple[str, str], set[str]] = defaultdict(set)
    servers: dict[tuple[str, str], set[str]] = defaultdict(set)
    for srv in _enabled(net):
        for r in srv.reservations:
            by_mac[(srv.segment_id, r.mac)].append((srv, r.address))
            if r.hostname and r.hostname.strip():
                key = (srv.segment_id, r.hostname.strip().lower().split(".")[0])
                by_name[key].add(r.mac)
                servers[key].add(srv.id)
    for (seg_id, mac), entries in sorted(by_mac.items()):
        label = segment_name(net, seg_id)
        addresses = sorted({a for _, a in entries}, key=lambda a: (a.version, int(a)))
        if len(addresses) > 1:
            detail = _join(
                f"{a} ({device_name(net, s.device_id)})"
                for s, a in sorted(entries, key=lambda e: (e[1].version, int(e[1]), e[0].id))
            )
            yield found(
                f"{mac} has {len(entries)} reservations on {label}: {detail}",
                [seg_id, *sorted({s.id for s, _ in entries})],
                fix="Keep one reservation for this device and remove the others.",
                key=mac,
            )
            continue
        for srv_id, n in sorted(Counter(s.id for s, _ in entries).items()):
            if n > 1:
                srv = next(s for s, _ in entries if s.id == srv_id)
                yield found(
                    f"{mac} is reserved {n} times for {addresses[0]} by {_server_name(net, srv)} "
                    f"on {label}",
                    [srv_id],
                    fix="Remove the extra entries; they are harmless but confusing.",
                    severity=Severity.INFO,
                    key=f"{mac} twice",
                )
    for (seg_id, name), macs in sorted(by_name.items()):
        if len(macs) > 1:
            yield found(
                f"The host name {name} is reserved for {len(macs)} devices on "
                f"{segment_name(net, seg_id)}: {_join(sorted(macs))}",
                [seg_id, *sorted(servers[(seg_id, name)])],
                fix="Rename one of the reservations, or remove the one of a device that is gone.",
                key=f"name {name}",
            )


# --- dhcp.domain (#66) ---------------------------------------------------------------------------


def _domain(text: str | None) -> str | None:
    d = (text or "").strip().strip(".").lower()
    return d or None


@rule(
    "dhcp.domain",
    "DHCP domain names differ or are problematic",
    Severity.INFO,
    "Clients register and look up names with the domain their DHCP server gives them. With "
    "different domains per network, a name resolves on one VLAN and not on another; .local "
    "belongs to mDNS and breaks AirPrint and similar services. RFC 8375 recommends home.arpa "
    "for home networks.",
)
def dhcp_domain(net: Network) -> Iterator[Result]:
    per_site: dict[str, list[DhcpServer]] = defaultdict(list)
    for srv in _enabled(net):
        per_site[str(site_of_device(net, srv.device_id))].append(srv)
    for site, servers in sorted(per_site.items()):
        servers.sort(key=lambda s: s.id)
        with_domain = [(s, d) for s in servers if (d := _domain(s.domain))]
        if not with_domain:
            continue
        for srv, d in with_domain:
            if d == "local" or d.endswith(".local"):
                yield found(
                    f"{segment_name(net, srv.segment_id)} gets the domain {d} from DHCP; .local "
                    "is reserved for mDNS",
                    [srv.id],
                    fix="Use home.arpa (RFC 8375) or a domain you own.",
                    severity=Severity.WARNING,
                    key="local",
                )
        without = [s for s in servers if not _domain(s.domain)]
        if without:
            domains = _join(sorted({d for _, d in with_domain}))
            yield found(
                f"{_join(segment_name(net, s.segment_id) for s in without)} "
                f"{'gets' if len(without) == 1 else 'get'} no domain from DHCP, while the other "
                f"networks of site {site} get {domains}",
                [s.id for s in without],
                fix="Set the same local domain on every network.",
                key="missing",
            )
        if len({d for _, d in with_domain}) > 1:
            detail = "; ".join(f"{segment_name(net, s.segment_id)}: {d}" for s, d in with_domain)
            yield found(
                f"The networks of site {site} use different domains ({detail})",
                [s.id for s, _ in with_domain],
                fix="Use one local domain (home.arpa recommended), or ignore this finding if "
                "the domains differ on purpose.",
                key="different",
            )
    domain_of = {s.segment_id: d for s in _enabled(net) if (d := _domain(s.domain))}
    for dns in net.dns_services:
        if not dns.enabled:
            continue
        for rec in dns.host_records:
            name = rec.name.strip().strip(".").lower()
            segs = _segments_of(net, rec.address)
            if "." not in name or len(segs) != 1:
                continue
            seg_id = segs.pop()
            d = domain_of.get(seg_id)
            if d and name != d and not name.endswith("." + d):
                yield found(
                    f"The DNS name {name} ({rec.address}) does not end in {d}, the domain of "
                    f"{segment_name(net, seg_id)}",
                    [dns.id],
                    fix=f"Rename the record to {name.split('.')[0]}.{d}, or use the same domain "
                    "for DHCP and DNS.",
                    key=f"record {name} {rec.address}",
                )


# --- dhcp.reservation-hostname (#68) -------------------------------------------------------------

_GENERIC_NAMES = {"", "*", "localhost", "unknown", "none", "android", "iphone", "espressif"}


def _host_label(name: str | None, mac: str) -> str | None:
    """Comparable host name (first label, lower case), or None for a missing or generic one."""
    label = (name or "").strip().lower().split(".")[0]
    plain = "".join(c for c in label if c in "0123456789abcdef")
    if label in _GENERIC_NAMES or label.startswith("android-") or plain == mac.replace(":", ""):
        return None
    return label


@rule(
    "dhcp.reservation-hostname",
    "Reservation name differs from the device's name",
    Severity.INFO,
    "The host name of a DHCP reservation is not the name the device with that MAC address "
    "reports. Usually the reservation was made for another device (a replaced device or network "
    "card) or the device was renamed; DNS names derived from the reservation then point at the "
    "wrong machine.",
)
def reservation_hostname(net: Network) -> Iterator[Result]:
    clients = {c.mac: c for c in net.clients}
    for srv in _enabled(net):
        for r in srv.reservations:
            c = clients.get(r.mac)
            want = _host_label(r.hostname, r.mac)
            have = _host_label(c.hostname, r.mac) if c else None
            if c is None or want is None or have is None or want == have:
                continue
            yield found(
                f"The reservation for {r.mac} on {segment_name(net, srv.segment_id)} is named "
                f"{r.hostname}, the device calls itself {c.hostname}",
                [srv.id, c.id],
                fix="Rename the reservation, or check that it is for the right device.",
                key=r.mac,
            )


# --- dhcp.dns-cross-network (#69) ----------------------------------------------------------------


@rule(
    "dhcp.dns-cross-network",
    "DHCP hands out a DNS server in another network",
    Severity.INFO,
    "The DNS server a DHCP server hands out lies in another network than the one it serves "
    "(for example IoT clients told to use a resolver on the main LAN). That works only if the "
    "firewall allows DNS between the networks, and on guest and IoT networks that exception "
    "also opens the main network. Without it, the clients have no name resolution.",
)
def dns_cross_network(net: Network) -> Iterator[Result]:
    router_ips = {s.interface.ip for s in router_subnets(net)}
    for srv in _enabled(net):
        own = [s for s in net.subnets if s.segment_id == srv.segment_id]
        label = segment_name(net, srv.segment_id)
        for a in srv.dns_servers:
            if a in router_ips or any(_contains(s, a) for s in own):
                continue  # routers answer on all their interfaces
            other = sorted(_segments_of(net, a))
            if not other:
                continue
            yield found(
                f"Clients of {label} use {a} in {_join(segment_name(net, s) for s in other)} "
                "as DNS server",
                [srv.id, *other],
                fix="Make sure the firewall allows only DNS to that address, or hand out the "
                f"router's address in {label}.",
                key=str(a),
            )


RULES: list[Rule] = [
    client_subnet,
    self_assigned,
    prefix_consistent,
    gateway_position,
    pool_usage,
    in_subnet,
    one_gateway,
    double_nat,
    management_address,
    duplicate_reservation,
    lease_time,
    dhcp_domain,
    reservation_hostname,
    dns_cross_network,
]
