"""DHCP checks that need the lease table, options and relays (#183, #67).

Every rule stays quiet when the data it needs was not reported: a server whose lease table was
not read (``leases is None``) may have leased any address.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from datetime import datetime, timedelta
from ipaddress import IPv4Network

from signalbox.adapters import Capability
from signalbox.model import (
    LEASED_SOURCES,
    AddressSource,
    Client,
    DhcpServer,
    IPAddress,
    LeaseState,
    Network,
)
from signalbox.rules import Result, Rule, Severity, found, incomplete, rule
from signalbox.rules._names import device_name, segment_name

#: Lease time assumed for the grace period when the server did not report one.
DEFAULT_LEASE = timedelta(days=1)
DEFAULT_ROUTE = IPv4Network("0.0.0.0/0")


def _enabled_on(net: Network, segment_id: str) -> list[DhcpServer]:
    return [s for s in net.dhcp_servers_on(segment_id) if s.enabled]


def _reference_time(servers: list[DhcpServer]) -> datetime | None:
    """When the lease tables were read (the latest read); None when no server says."""
    times = [s.observed_at for s in servers if s.observed_at is not None]
    return max(times) if times else None


def _holds_address(servers: list[DhcpServer], client: Client, address: IPAddress) -> bool:
    """A server has a reservation, an offer or a reserved lease for this MAC and address."""
    for srv in servers:
        if any(r.mac == client.mac and r.address == address for r in srv.reservations):
            return True
        for lease in srv.leases_of(client.mac):
            if lease.address == address and lease.state in (
                LeaseState.OFFERED,
                LeaseState.RESERVED,
            ):
                return True
    return False


def _in_grace(
    servers: list[DhcpServer], client: Client, address: IPAddress, now: datetime | None
) -> bool:
    """The lease for this address ended less than one lease time ago (or when is not known)."""
    for srv in servers:
        for lease in srv.leases_of(client.mac):
            if lease.address != address or lease.state is not LeaseState.EXPIRED:
                continue
            if now is None or lease.expires is None:
                return True
            span = timedelta(seconds=srv.lease_seconds) if srv.lease_seconds else DEFAULT_LEASE
            if lease.expires + span >= now:
                return True
    return False


@rule(
    "dhcp.static-in-pool",
    "Fixed address inside the DHCP pool",
    Severity.WARNING,
    "A device uses an address from the range a DHCP server hands out, but the server did not "
    "give it to the device. Sooner or later the server leases the same address to another device "
    "and both lose their connection at random. Typical for printers, NAS and IoT devices that "
    "were configured by hand once.",
)
def static_in_pool(net: Network) -> Iterator[Result]:
    for client in sorted(net.clients, key=lambda c: c.id):
        seg = client.segment_id
        if seg is None or not net.leases_read(seg):
            continue
        if net.expected(client.id).static_address or net.expected(client.mac).static_address:
            continue
        servers = _enabled_on(net, seg)
        now = _reference_time(servers)
        bad: list[IPAddress] = []
        for address in client.addresses:
            if address.is_link_local or not any(s.in_pool(address) for s in servers):
                continue
            source = net.address_source(client, address, now)
            if source in LEASED_SOURCES:
                continue
            if source is not AddressSource.STATIC and (
                _holds_address(servers, client, address) or _in_grace(servers, client, address, now)
            ):
                continue
            bad.append(address)
        if not bad:
            continue
        name = client.hostname or client.mac
        text = ", ".join(str(a) for a in bad)
        yield found(
            f"{name} ({client.mac}) uses {text} inside the DHCP pool of "
            f"{segment_name(net, seg)} without a lease",
            [client.id, *sorted(s.id for s in servers)],
            fix=f"Give {name} a reservation, or a fixed address outside the pool. If the "
            "address is meant to be fixed, mark the device as using a static address.",
            mid="leases.staticInPool",
            fix_id="leases.staticInPool.fix",
            params={
                "name": name,
                "mac": client.mac,
                "addresses": text,
                "segment": segment_name(net, seg),
            },
        )


@rule(
    "dhcp.declined",
    "DHCP address declined (address conflict)",
    Severity.WARNING,
    "A device refused the address the DHCP server offered because another device already uses "
    "it (DHCPDECLINE). Two devices on the network have the same address: one of them has a "
    "fixed address inside the pool, or two DHCP servers hand out overlapping ranges.",
)
def declined(net: Network) -> Iterator[Result]:
    for srv in sorted(net.dhcp_servers, key=lambda s: s.id):
        if not srv.enabled:
            continue
        bad = sorted(
            {x.address for x in srv.leases or [] if x.state is LeaseState.DECLINED},
            key=lambda a: (a.version, int(a)),
        )
        if bad:
            yield found(
                f"The DHCP server on {device_name(net, srv.device_id)} marked "
                f"{', '.join(str(a) for a in bad)} on {segment_name(net, srv.segment_id)} as "
                "declined: another device already uses it",
                [srv.id],
                fix="Find the device that uses the address and move it outside the pool (or "
                "give it a reservation), then clear the declined lease.",
                mid="leases.declined",
                fix_id="leases.declined.fix",
                params={
                    "device": device_name(net, srv.device_id),
                    "addresses": ", ".join(str(a) for a in bad),
                    "segment": segment_name(net, srv.segment_id),
                },
            )


@rule(
    "dhcp.option-121-without-router",
    "Classless static routes without a default route",
    Severity.WARNING,
    "Clients that receive classless static routes (DHCP option 121) ignore the router option "
    "(RFC 3442). If the routes do not contain a default route (0.0.0.0/0), those clients lose "
    "their path to the internet.",
)
def option_121_without_router(net: Network) -> Iterator[Result]:
    for srv in sorted(net.dhcp_servers, key=lambda s: s.id):
        if not srv.enabled or not srv.static_routes:
            continue
        if any(r.destination == DEFAULT_ROUTE for r in srv.static_routes):
            continue
        via = f" via {srv.router}" if srv.router else ""
        yield found(
            f"The DHCP server on {device_name(net, srv.device_id)} hands out classless static "
            f"routes on {segment_name(net, srv.segment_id)} without a default route, so clients "
            "ignore the router option and have no way out",
            [srv.id],
            fix=f"Add a route 0.0.0.0/0{via} to the classless routes, or remove them.",
            mid="leases.option121",
            fix_id="leases.option121.via" if via else "leases.option121.fix",
            params={
                "device": device_name(net, srv.device_id),
                "segment": segment_name(net, srv.segment_id),
                "router": str(srv.router or ""),
            },
        )


def _dhcp_read_failed(net: Network, device_id: str) -> bool:
    return any(e.device_id == device_id and e.capability == Capability.DHCP for e in net.errors)


@rule(
    "dhcp.relay-target-missing",
    "DHCP relay forwards to no DHCP server",
    Severity.WARNING,
    "A DHCP relay passes requests of its network on to a DHCP server. If that address is not "
    "a device that runs an enabled DHCP server, or no address is set, the devices of the "
    "network get no address.",
)
def relay_target_missing(net: Network) -> Iterator[Result]:
    owners: dict[str, set[str]] = defaultdict(set)
    for sub in net.subnets:
        owners[str(sub.interface.ip)].add(sub.device_id)
    serving = {s.device_id for s in net.dhcp_servers if s.enabled}
    for relay in sorted(net.dhcp_relays, key=lambda r: r.id):
        if not relay.enabled:
            continue
        label = segment_name(net, relay.segment_id)
        where = device_name(net, relay.device_id)
        if not relay.servers:
            yield found(
                f"The DHCP relay on {where} for {label} has no server to forward to",
                [relay.id],
                fix="Enter the address of your DHCP server in the relay settings.",
                mid="leases.relayNoServer",
                fix_id="leases.relayNoServer.fix",
                params={"where": where, "segment": label},
            )
            continue
        for target in relay.servers:
            devices = owners.get(str(target), set())
            if devices & serving:
                continue
            if not devices:
                yield incomplete(
                    f"The DHCP relay on {where} for {label} forwards to {target}, which is not "
                    "a device Signalbox knows, so it cannot tell whether a DHCP server runs there",
                    [relay.id],
                    key=str(target),
                    mid="leases.relayTargetUnknown",
                    params={"where": where, "segment": label, "target": str(target)},
                )
            elif any(_dhcp_read_failed(net, d) for d in devices):
                yield incomplete(
                    f"The DHCP relay on {where} for {label} forwards to {target}, but the DHCP "
                    "servers of that device could not be read",
                    [relay.id],
                    key=str(target),
                    mid="leases.relayTargetUnread",
                    params={"where": where, "segment": label, "target": str(target)},
                )
            else:
                names = ", ".join(sorted(device_name(net, d) for d in devices))
                yield found(
                    f"The DHCP relay on {where} for {label} forwards to {target}, but no DHCP "
                    f"server is enabled on {names}",
                    [relay.id, *sorted(devices)],
                    fix="Enable the DHCP server there, or point the relay to the right address.",
                    key=str(target),
                    mid="leases.relayNoServerEnabled",
                    fix_id="leases.relayNoServerEnabled.fix",
                    params={
                        "where": where,
                        "segment": label,
                        "target": str(target),
                        "names": names,
                    },
                )


RULES: list[Rule] = [static_in_pool, declined, option_121_without_router, relay_target_missing]
