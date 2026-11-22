"""DNS rules: host records, forwarders and resolvers across devices (#74-#79, #81)."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from ipaddress import ip_address

from signalbox.adapters import Capability
from signalbox.model import DnsForwarder, DnsService, HostRecord, IPAddress, Network
from signalbox.rules import Result, Rule, Severity, found, incomplete, rule
from signalbox.rules._names import device_name, segment_name, site_of_device


def _services(net: Network) -> list[DnsService]:
    return [d for d in net.dns_services if d.enabled]


def _parse(text: str | None) -> IPAddress | None:
    try:
        return ip_address(text) if text else None
    except ValueError:
        return None


def _short(name: str) -> str:
    return name.lower().rstrip(".").split(".", 1)[0]


def _records(net: Network) -> Iterator[tuple[str, DnsService, HostRecord]]:
    """(site, service, record) for every host record of an enabled DNS service."""
    for dns in _services(net):
        site = site_of_device(net, dns.device_id)
        if site is not None:
            for rec in dns.host_records:
                yield site, dns, rec


def _addresses(values: set[IPAddress]) -> str:
    return ", ".join(str(a) for a in sorted(values, key=lambda a: (a.version, int(a))))


@dataclass
class _Index:
    """Who uses which address: devices (subnets, management), DNS services and clients."""

    device_of: dict[str, str] = field(default_factory=dict)
    #: (address, port) -> the enabled DNS services answering there.
    service_at: dict[tuple[str, int], list[DnsService]] = field(default_factory=dict)
    services: list[DnsService] = field(default_factory=list)
    clients: set[str] = field(default_factory=set)
    reserved: set[str] = field(default_factory=set)
    #: Sites and IP versions for which clients were reported, so an unused address means something.
    client_data: set[tuple[str, int]] = field(default_factory=set)

    @classmethod
    def of(cls, net: Network) -> _Index:
        idx = cls()
        for sub in net.subnets:
            idx.device_of.setdefault(str(sub.interface.ip), sub.device_id)
        for dev in net.devices:
            if (address := _parse(dev.management_address)) is not None:
                idx.device_of.setdefault(str(address), dev.id)
        service_at: dict[tuple[str, int], list[DnsService]] = defaultdict(list)
        idx.services = _services(net)
        for dns in idx.services:
            listen = [str(a) for a in dns.listen] or [
                a for a, d in idx.device_of.items() if d == dns.device_id
            ]
            for a in listen:
                service_at[(a, dns.port)].append(dns)
                idx.device_of.setdefault(a, dns.device_id)
        idx.service_at = dict(service_at)
        for client in net.clients:
            seg = net.segment(client.segment_id) if client.segment_id else None
            for address in client.addresses:
                idx.clients.add(str(address))
                if seg is not None and not address.is_link_local:
                    idx.client_data.add((seg.site_id, address.version))
        for srv in net.dhcp_servers:
            idx.reserved |= {str(r.address) for r in srv.reservations}
        failed = {e.device_id for e in net.errors if e.capability == Capability.CLIENTS}
        for dev in net.devices:
            if Capability.CLIENTS in dev.capabilities and dev.id not in failed:
                # A device that reads clients reports IPv4 neighbours; IPv6 only where seen.
                idx.client_data.add((dev.site_id, 4))
        return idx

    def used(self, address: IPAddress) -> bool:
        a = str(address)
        return a in self.device_of or a in self.clients

    def target(self, address: IPAddress) -> str:
        """The device behind an address, or the address itself if no device is known."""
        return self.device_of.get(str(address), str(address))

    def forward_target(self, dns: DnsService, fwd: DnsForwarder) -> str:
        """The device a forwarder of ``dns`` leads to (loopback: its own device), or the address
        itself if no device is known."""
        return dns.device_id if fwd.address.is_loopback else self.target(fwd.address)

    def reached(self, dns: DnsService, fwd: DnsForwarder) -> tuple[list[DnsService], bool]:
        """(the services a forwarder of ``dns`` leads to, whether it leads to a DNS service
        whose forwarders are unknown).

        A forwarder leads to a service only if address and port match; a loopback address is
        the forwarding device itself. A forward to a device that runs a known DNS service, on
        a port none of them listens on, goes to another DNS server Signalbox does not read
        (AdGuard Home next to Unbound): unknown, not a loop.
        """
        if fwd.address.is_loopback:
            hits = [s for s in self.services if s.device_id == dns.device_id and s.port == fwd.port]
        else:
            hits = self.service_at.get((str(fwd.address), fwd.port), [])
        device = self.forward_target(dns, fwd)
        unknown = any(not s.config_read for s in hits) or (
            not hits and any(s.device_id == device for s in self.services)
        )
        return hits, unknown


def _local_segment(net: Network, site: str | None, address: IPAddress) -> str | None:
    """The network of ``site`` (any site if None) whose subnet contains the address."""
    for sub in sorted(net.subnets, key=lambda s: s.id):
        if site is not None and site_of_device(net, sub.device_id) != site:
            continue
        if sub.interface.version == address.version and address in sub.interface.network:
            return sub.segment_id
    return None


@rule(
    "dns.host-record-reservation",
    "DNS record and DHCP reservation disagree",
    Severity.WARNING,
    "A DNS host record has the same name as a DHCP reservation but points to a different "
    "address. When a reservation is changed and the DNS record is not, the name points to the "
    "old address: backups, media players and bookmarks fail while the device itself works. "
    "The resolver and the DHCP server are often different devices.",
)
def host_record_reservation(net: Network) -> Iterator[Result]:
    reserved: dict[tuple[str, str], dict[str, set[IPAddress]]] = defaultdict(
        lambda: defaultdict(set)
    )
    reserved_ids: dict[tuple[str, str], set[str]] = defaultdict(set)
    by_address: dict[tuple[str, str], set[str]] = defaultdict(set)
    for srv in net.dhcp_servers:
        site = site_of_device(net, srv.device_id)
        if not srv.enabled or site is None:
            continue
        for res in srv.reservations:
            if res.hostname:
                name = _short(res.hostname)
                reserved[(site, name)][str(res.address.version)].add(res.address)
                reserved_ids[(site, name)].add(srv.id)
                by_address[(site, str(res.address))].add(name)
    records: dict[tuple[str, str], dict[str, set[IPAddress]]] = defaultdict(
        lambda: defaultdict(set)
    )
    record_ids: dict[tuple[str, str], set[str]] = defaultdict(set)
    for site, dns, rec in _records(net):
        records[(site, _short(rec.name))][str(rec.address.version)].add(rec.address)
        record_ids[(site, _short(rec.name))].add(dns.id)
        names = by_address.get((site, str(rec.address)), set())
        if names and _short(rec.name) not in names:
            yield found(
                f"The DNS record {rec.name} points to {rec.address}, which is reserved in DHCP "
                f"for {', '.join(sorted(names))}",
                [dns.id],
                fix="Use the same name for the record and the reservation, or ignore this if "
                "the record is an intended second name.",
                severity=Severity.INFO,
                key=f"name {rec.name} {rec.address}",
            )
    for key, by_version in sorted(records.items()):
        for version, addresses in sorted(by_version.items()):
            want = reserved.get(key, {}).get(version)
            if not want or want == addresses:
                continue
            name = key[1]
            yield found(
                f"The DNS record {name} points to {_addresses(addresses)}, the DHCP reservation "
                f"for {name} is {_addresses(want)}",
                sorted(record_ids[key] | reserved_ids[key]),
                fix="Update the DNS record (or the reservation) so that both use the same address.",
                key=f"{name} {version}",
            )


@rule(
    "dns.host-record-stale",
    "DNS record points to an address nothing uses",
    Severity.INFO,
    "A DNS host record points to an address that no known device, client or reservation uses. "
    "The name then resolves to nothing (time-outs instead of a clear error) or, worse, to "
    "whatever device gets that address next. Such records pile up after a server moved or a "
    "network was renumbered. The device may also just be off.",
)
def host_record_stale(net: Network) -> Iterator[Result]:
    idx = _Index.of(net)
    for site, dns, rec in sorted(_records(net), key=lambda r: (r[1].id, r[2].name, str(r[2]))):
        address = rec.address
        if address.is_loopback or address.is_unspecified or address.is_link_local:
            continue  # blocking entries and link-local names
        if idx.used(address) or str(address) in idx.reserved:
            continue
        seg = _local_segment(net, site, address)
        where = f"on {device_name(net, dns.device_id)}"
        if seg is not None:
            if (site, address.version) not in idx.client_data:
                continue  # no client data: cannot tell
            yield found(
                f"The DNS record {rec.name} {where} points to {address} on "
                f"{segment_name(net, seg)}, which no known device uses",
                [dns.id],
                fix="Remove the record, or check the device's address.",
                key=f"{rec.name} {address}",
            )
        elif address.is_private and _local_segment(net, None, address) is None:
            yield found(
                f"The DNS record {rec.name} {where} points to {address}, which is not in any "
                "network Signalbox knows",
                [dns.id],
                fix="Correct the address (typo or an old network), or remove the record.",
                severity=Severity.WARNING,
                key=f"{rec.name} {address}",
            )


@rule(
    "dns.host-record-dynamic",
    "DNS record points to a dynamic DHCP address",
    Severity.WARNING,
    "A DNS host record points to an address from a DHCP pool that is not reserved for a "
    "device. The record is right today and wrong after the next lease change, reboot or power "
    "cut.",
)
def host_record_dynamic(net: Network) -> Iterator[Result]:
    pools: dict[str, list[tuple[str, IPAddress, IPAddress, set[str]]]] = defaultdict(list)
    for srv in net.dhcp_servers:
        site = site_of_device(net, srv.device_id)
        if not srv.enabled or site is None:
            continue
        reserved = {str(r.address) for r in srv.reservations}
        for pool in srv.pools:
            lo, hi = sorted((pool.start, pool.end))
            pools[site].append((srv.id, lo, hi, reserved))
    for site, dns, rec in _records(net):
        for srv_id, lo, hi, reserved in pools.get(site, []):
            address = rec.address
            if address.version != lo.version or not lo <= address <= hi:  # type: ignore[operator]
                continue
            if str(address) in reserved:
                continue
            srv = next(s for s in net.dhcp_servers if s.id == srv_id)
            yield found(
                f"The DNS record {rec.name} points to {address}, a dynamic address of "
                f"{segment_name(net, srv.segment_id)} (pool {lo}-{hi})",
                [dns.id, srv_id],
                fix=f"Add a DHCP reservation for the device of {rec.name} at that address, or "
                "move the record to an address outside the pool.",
                key=f"{rec.name} {address}",
            )


def _edges(idx: _Index) -> dict[str, list[tuple[DnsForwarder, str]]]:
    """Service id -> (forwarder, service id) for each forwarder that is a known DNS service."""
    return {
        dns.id: [(fwd, t.id) for fwd in dns.forwarders for t in idx.reached(dns, fwd)[0]]
        for dns in idx.services
    }


def _label(net: Network, dns: DnsService) -> str:
    """The device's name, plus the service's name when the device runs several."""
    name = device_name(net, dns.device_id)
    several = sum(1 for d in _services(net) if d.device_id == dns.device_id) > 1
    if several:
        return f"{name} ({dns.name or f'port {dns.port}'})"
    return name


def _cycle(
    edges: dict[str, list[tuple[DnsForwarder, str]]], start: str
) -> list[tuple[str, DnsForwarder]]:
    """Shortest path from ``start`` back to itself as (service, forwarder) steps, or []."""
    queue: deque[tuple[str, list[tuple[str, DnsForwarder]]]] = deque([(start, [])])
    seen: set[str] = set()
    while queue:
        node, path = queue.popleft()
        for fwd, target in edges.get(node, []):
            step = [*path, (node, fwd)]
            if target == start:
                return step
            if target not in seen:
                seen.add(target)
                queue.append((target, step))
    return []


@rule(
    "dns.forwarder-loop",
    "DNS forwarders form a loop",
    Severity.ERROR,
    "DNS resolvers forward to each other in a circle (or one forwards to itself). Every lookup "
    "that is not cached goes round until it times out, often only after a reboot cleared the "
    "caches. Typical when a local filter (Pi-hole, AdGuard) forwards to the router and the "
    "router was set to forward to the filter. Two DNS servers on one device (AdGuard Home on "
    "port 53, Unbound on another port) are not a loop.",
)
def forwarder_loop(net: Network) -> Iterator[Result]:
    idx = _Index.of(net)
    edges = _edges(idx)
    names = {d.id: _label(net, d) for d in idx.services}
    reported: set[frozenset[str]] = set()
    for start in sorted(edges):
        steps = _cycle(edges, start)
        members = frozenset(s for s, _ in steps)
        if not steps or members in reported:
            continue
        reported.add(members)
        if len(steps) == 1:
            message = f"DNS lookups loop: {names[start]} forwards to {steps[0][1]}, itself"
        else:
            nxt = [s for s, _ in steps[1:]] + [start]
            parts = [
                f"{names[s]} forwards to {fwd} ({names[t]})"
                for (s, fwd), t in zip(steps, nxt, strict=True)
            ]
            message = "DNS lookups loop: " + ", ".join(parts)
        yield found(
            message,
            sorted(members),
            fix="Let one of them forward to an upstream resolver (or resolve recursively) "
            "instead of to the other.",
        )
    in_loop = set().union(*reported) if reported else set()
    for dns in sorted(idx.services, key=lambda d: d.id):
        if dns.id in in_loop or not dns.config_read:
            continue
        for fwd in dns.forwarders:
            hits, unknown = idx.reached(dns, fwd)
            if not unknown:
                continue
            device = device_name(net, idx.forward_target(dns, fwd))
            if hits:
                services = ", ".join(names[h.id] for h in hits)
                what = f"the DNS service {services} that Signalbox does not read"
            else:
                what = (
                    f"port {fwd.port} of {device}, where another DNS server that Signalbox "
                    "does not read listens"
                )
            yield incomplete(
                f"{names[dns.id]} forwards DNS to {fwd}, {what}: whether lookups come back "
                "in a loop cannot be checked",
                sorted({dns.id, *(h.id for h in hits)}),
                key=str(fwd),
            )


@rule(
    "dns.forwarder-missing",
    "DNS server on the local network does not exist",
    Severity.ERROR,
    "A resolver forwards to, or a DHCP server hands out, a DNS server with an address on a local "
    "network that no known device, DNS service or client uses. A Pi-hole or old server that was "
    "removed or moved leaves name resolution failing or slow while the router looks healthy.",
)
def forwarder_missing(net: Network) -> Iterator[Result]:
    idx = _Index.of(net)
    users: list[tuple[str, str, str, list[IPAddress]]] = []
    for dns in _services(net):
        users.append(
            (dns.id, dns.device_id, "forwards DNS to", [f.address for f in dns.forwarders])
        )
    for srv in net.dhcp_servers:
        if srv.enabled:
            users.append((srv.id, srv.device_id, "hands out the DNS server", srv.dns_servers))
    for obj, dev, verb, addresses in sorted(users):
        site = site_of_device(net, dev)
        for address in addresses:
            seg = _local_segment(net, None, address)
            if seg is None or idx.used(address):
                continue
            seg_obj = net.segment(seg)
            seg_site = seg_obj.site_id if seg_obj else site
            if (seg_site, address.version) not in idx.client_data:
                continue  # no client data for that network: the resolver may just be unknown
            others = len(addresses) > 1
            yield found(
                f"{device_name(net, dev)} {verb} {address}, but no device on "
                f"{segment_name(net, seg)} uses that address",
                [obj],
                fix="Update the DNS setting to an existing resolver, or bring the resolver back.",
                severity=Severity.WARNING if others else Severity.ERROR,
                key=str(address),
            )


def _redundant(net: Network, idx: _Index, dns: DnsService, seen: frozenset[str]) -> bool:
    """True if the resolver has more than one upstream, resolves itself or loops (reported
    elsewhere)."""
    if not dns.config_read or not dns.forwarders or dns.id in seen:
        return True
    targets = {idx.forward_target(dns, f) for f in dns.forwarders}
    if len(targets) > 1:
        return True
    nxt: list[DnsService] = []
    for f in dns.forwarders:
        hits, unknown = idx.reached(dns, f)
        if unknown:
            return True  # the next service's upstreams are not known
        nxt += hits
    return any(_redundant(net, idx, s, seen | {dns.id}) for s in nxt)


@rule(
    "dns.single-forwarder",
    "DNS resolver has only one upstream",
    Severity.INFO,
    "A DNS resolver forwards all lookups to a single upstream (one address, or several "
    "addresses of the same device). If that upstream is down (an ISP resolver outage, a "
    "Pi-hole update), the whole network has no name resolution although the internet "
    "connection works. A resolver without forwarders resolves itself and is not reported.",
)
def single_forwarder(net: Network) -> Iterator[Result]:
    idx = _Index.of(net)
    for dns in sorted(_services(net), key=lambda d: d.id):
        if _redundant(net, idx, dns, frozenset()):
            continue
        addresses = ", ".join(str(f) for f in dns.forwarders)
        target = idx.forward_target(dns, dns.forwarders[0])
        dev = target if target != str(dns.forwarders[0].address) else None
        upstream = f"{device_name(net, dev)} ({addresses})" if dev else addresses
        yield found(
            f"{device_name(net, dns.device_id)} forwards DNS only to {upstream}",
            [dns.id],
            fix="Add a second upstream resolver, or let the resolver resolve recursively.",
        )


def _local_domains(net: Network) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for srv in net.dhcp_servers:
        site = site_of_device(net, srv.device_id)
        if srv.domain and site is not None:
            out[site].add(srv.domain.lower().strip("."))
    return out


def _name_key(name: str, domains: set[str]) -> str:
    name = name.lower().rstrip(".")
    for domain in sorted(domains, key=len, reverse=True):
        if name.endswith("." + domain):
            return name[: -len(domain) - 1]
    return name


@rule(
    "dns.conflicting-records",
    "DNS name resolves differently on two resolvers",
    Severity.WARNING,
    "The same name has different addresses on different DNS resolvers of a site. Clients get "
    "different answers depending on which resolver they ask: it works on the phone but not on "
    "the laptop. IPv4 and IPv6 records of a name are compared "
    "separately; identical round-robin sets are fine.",
)
def conflicting_records(net: Network) -> Iterator[Result]:
    domains = _local_domains(net)
    groups: dict[tuple[str, str, int], dict[str, set[IPAddress]]] = defaultdict(
        lambda: defaultdict(set)
    )
    shown: dict[tuple[str, str, int], set[str]] = defaultdict(set)
    for site, dns, rec in _records(net):
        group = (site, _name_key(rec.name, domains.get(site, set())), int(rec.address.version))
        groups[group][dns.id].add(rec.address)
        shown[group].add(rec.name)
    for key, by_service in sorted(groups.items()):
        name = sorted(shown[key], key=len)[0]
        sets = {frozenset(v) for v in by_service.values()}
        if len(sets) > 1:
            names = {
                d.id: device_name(net, d.device_id) for d in _services(net) if d.id in by_service
            }
            parts = [f"{_addresses(a)} on {names[sid]}" for sid, a in sorted(by_service.items())]
            yield found(
                f"{name} resolves to {' and to '.join(parts)}",
                sorted(by_service),
                fix="Use the same record on every resolver, or use a single resolver.",
                key=f"{key[1]} {key[2]}",
            )


RULES: list[Rule] = [
    host_record_reservation,
    host_record_stale,
    host_record_dynamic,
    forwarder_loop,
    forwarder_missing,
    single_forwarder,
    conflicting_records,
]
