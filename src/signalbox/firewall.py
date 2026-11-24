"""Reachability through the firewalls of the network (#135, ADR 0013).

"Can traffic from segment, uplink or tunnel A reach address X on port P?" answered from the
:class:`~signalbox.model.Firewall` objects: ``allowed``, ``denied`` or ``unknown``. The answer
is conservative: ``allowed`` and ``denied`` only where every rule and policy on the way could be
evaluated exactly; a firewall that was not read, an inexact rule that may match, a path through
more than one router or a source that is not in a known zone give ``unknown``.

What is modelled (see docs/DESIGN.md, "Firewall"):

- traffic to a device itself (input chain) and through one router (forward chain), with the
  first-match rules, then zone pair policies, then the chain default of
  :meth:`Firewall.evaluate`;
- from the internet: port forwards of the router (destination NAT) first, private IPv4
  addresses only through a forward, and the router in front (double NAT) when the uplink has a
  private address and that router's firewall is read;
- a source in several subnets (IPv4 and IPv6, several prefixes) can reach the target when one
  of them can.

What is not: routing tables and policy routing, more than one router hop between two networks
of the site, client isolation on access points, rate limits and connection states other than
"new connection", the device's own service filters (``ManagementService.allowed_from`` is
applied by :meth:`Network.service_segments`).
"""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network

from signalbox.model import (
    DeviceRole,
    Firewall,
    FirewallChain,
    FirewallProtocol,
    FirewallVerdict,
    Flow,
    IPAddress,
    IPNetwork,
    ManagementService,
    Match,
    Network,
    PortForward,
    PortRange,
    ServiceTransport,
    Uplink,
    Verdict,
    internet_reachable_network,
)
from signalbox.routing import address_owner as address_owner
from signalbox.routing import address_segment as address_segment
from signalbox.routing import own_addresses as own_addresses

#: How many routers in front (double, triple NAT) are followed.
_MAX_UPSTREAM = 3


def _v(verdict: Verdict, reason: str, device_id: str | None = None) -> FirewallVerdict:
    return FirewallVerdict(verdict=verdict, reason=reason, device_id=device_id)


def any_of(verdicts: Iterable[FirewallVerdict]) -> FirewallVerdict:
    """Alternatives (several source subnets, several uplinks): allowed when one is allowed,
    denied when all are, unknown otherwise."""
    items = list(verdicts)
    for want in (Verdict.ALLOWED, Verdict.UNKNOWN):
        hit = next((v for v in items if v.verdict is want), None)
        if hit is not None:
            return hit
    if items:
        return items[0]
    return _v(Verdict.UNKNOWN, "no way to evaluate")


def in_series(verdicts: Iterable[FirewallVerdict]) -> FirewallVerdict:
    """Steps of one path (router, then the target's own filter): denied when one denies,
    allowed when all allow, unknown otherwise."""
    items = list(verdicts)
    for want in (Verdict.DENIED, Verdict.UNKNOWN):
        hit = next((v for v in items if v.verdict is want), None)
        if hit is not None:
            return hit
    if items:
        return items[-1]
    return _v(Verdict.UNKNOWN, "no way to evaluate")


def _protocol(service: ManagementService) -> FirewallProtocol | None:
    if service.transport is ServiceTransport.TCP:
        return FirewallProtocol.TCP
    if service.transport is ServiceTransport.UDP:
        return FirewallProtocol.UDP
    return None


def _host(address: IPAddress) -> IPNetwork:
    return ip_network(address)


def _family(address: IPAddress | None) -> int | None:
    return address.version if address is not None else None


def _source_networks(net: Network, source: str, family: int | None) -> list[IPNetwork | None]:
    """Source addresses of a flow from *source*: a segment's subnets of that family; ``None``
    (any address) for an uplink, a tunnel or a segment without a known subnet."""
    nets = sorted(
        {
            s.interface.network
            for s in net.subnets
            if s.segment_id == source and (family is None or s.interface.version == family)
        },
        key=str,
    )
    return list(nets) or [None]


def _zones(fw: Firewall, object_id: str) -> set[str] | None:
    zones = fw.zones_of(object_id)
    if not zones and any(not z.complete for z in fw.zones):
        return None  # it may be in the part of a zone the adapter could not map
    return zones


def _present(net: Network, device_id: str, where: str) -> str | None:
    """The object through which the device is attached to *where* (a segment, uplink or
    tunnel id): the segment itself, or the device's uplink whose address lies in it."""
    if any(u.id == where for u in net.uplinks_of(device_id)) or any(
        t.id == where for t in net.tunnels_of(device_id)
    ):
        return where
    if any(s.device_id == device_id and s.segment_id == where for s in net.subnets):
        return where
    nets = [s.interface.network for s in net.subnets if s.segment_id == where]
    for up in net.uplinks_of(device_id):
        if any(a.ip in n for a in up.addresses for n in nets if n.version == a.version):
            return up.id
    return None


def _filters(net: Network, device_id: str) -> bool:
    """Whether the device's own packet filter has to be asked: its firewall is read, or it is
    a gateway (whose firewall is then not read: unknown). A switch or access point without a
    read firewall is assumed to filter nothing (most cannot)."""
    if net.firewall_of(device_id) is not None:
        return True
    dev = net.device(device_id)
    return dev is not None and dev.role is DeviceRole.GATEWAY


def _is_uplink(net: Network, object_id: str) -> Uplink | None:
    return next((u for u in net.uplinks if u.id == object_id), None)


def _name(net: Network, device_id: str) -> str:
    dev = net.device(device_id)
    return dev.name if dev else device_id


def _forwards_elsewhere(
    fw: Firewall,
    zones: set[str] | None,
    protocol: FirewallProtocol | None,
    port: int | None,
    destination: IPAddress | None,
    own: set[IPAddress],
) -> FirewallVerdict | None:
    """A port forward that takes a connection to the device's own address on *port* away to
    another host: then the device's own service is not reached (``denied``), or may not be
    (``unknown``)."""
    uplink_zones = fw.uplink_zones()
    maybe = None
    for pf in fw.port_forwards:
        if not pf.zones and zones is not None and not (zones & uplink_zones):
            continue
        if pf.target_address in own:
            continue  # to the device itself (another port of its own)
        if pf.external_address is not None and destination not in (None, pf.external_address):
            continue
        m = pf.matches(zones, protocol, port)
        if m is Match.YES:
            return _v(
                Verdict.DENIED,
                f"port forward {pf.name or port} sends it to {pf.target_address}",
                fw.device_id,
            )
        if m is Match.MAYBE:
            maybe = _v(Verdict.UNKNOWN, f"port forward {pf.name or port} may take it", fw.device_id)
    return maybe


def device_input(
    net: Network,
    device_id: str,
    source: str,
    port: int | None = None,
    protocol: FirewallProtocol | None = None,
    destination: IPAddress | None = None,
    zones_from: str | None = None,
) -> FirewallVerdict:
    """Can traffic from *source* reach the device itself (its input chain) on *port*?

    *destination*: the device's address that is used (``None``: any of them). *zones_from*:
    the object whose zones the traffic arrives in, when it is not *source* (traffic routed by
    another router arrives from the device's own segment).
    """
    fw = net.firewall_of(device_id)
    if fw is None:
        return _v(
            Verdict.UNKNOWN, f"the firewall of {_name(net, device_id)} is not read", device_id
        )
    zones = _zones(fw, zones_from or source)
    results = []
    for src in _source_networks(net, source, _family(destination)):
        results.append(
            fw.evaluate(
                Flow(
                    chain=FirewallChain.INPUT,
                    source_zones=zones,
                    source=src,
                    destination=_host(destination) if destination else None,
                    family=_family(destination) or (src.version if src else None),
                    protocol=protocol,
                    port=port,
                )
            )
        )
    verdict = any_of(results)
    uplink = _is_uplink(net, zones_from or source)
    if uplink is not None and uplink.device_id == device_id:
        own = set(own_addresses(net, device_id))
        away = _forwards_elsewhere(fw, zones, protocol, port, destination, own)
        if away is not None:
            verdict = in_series([verdict, away]) if away.verdict is Verdict.UNKNOWN else away
        elif not fw.port_forwards_complete and verdict.verdict is Verdict.ALLOWED:
            verdict = _v(Verdict.UNKNOWN, "not every port forward could be read", device_id)
        if verdict.verdict is not Verdict.DENIED:
            verdict = in_series([verdict, _upstream(net, uplink, protocol, port, destination)])
    return verdict


def _upstream(
    net: Network,
    uplink: Uplink,
    protocol: FirewallProtocol | None,
    port: int | None,
    destination: IPAddress | None,
    depth: int = 0,
) -> FirewallVerdict:
    """Whether the internet gets to *uplink* at all: through the known router in front of it
    (double NAT, :meth:`Network.upstream_router`), whose port forwards and firewall decide;
    allowed when no router in front is known (the uplink faces the internet, as far as
    Signalbox knows), unknown when that router's firewall is not read."""
    front = net.upstream_router(uplink)
    if front is None or depth >= _MAX_UPSTREAM:
        return _v(Verdict.ALLOWED, "no known router in front", uplink.device_id)
    family = destination.version if destination is not None else 4
    own = [a.ip for a in uplink.addresses if a.version == family and not a.ip.is_link_local]
    targets = [a for a in own if a == destination] or own
    if not targets:
        return _v(Verdict.ALLOWED, "no address behind the router in front", uplink.device_id)
    outer = net.uplinks_of(front.device_id)
    if not outer:
        return _v(
            Verdict.UNKNOWN, f"{_name(net, front.device_id)} has no known uplink", front.device_id
        )
    verdict = any_of(
        reach(net, up.id, addr, port, protocol, _depth=depth + 1, _owner=False)
        for up in outer
        for addr in targets
    )
    if verdict.verdict is Verdict.DENIED:
        verdict = _v(
            Verdict.DENIED,
            f"{_name(net, front.device_id)} in front does not let it through: {verdict.reason}",
            verdict.device_id,
        )
    return verdict


def _forward_target(
    fw: Firewall,
    zones: set[str] | None,
    address: IPAddress,
    protocol: FirewallProtocol | None,
    port: int | None,
) -> tuple[Match, int | None, bool | None, str]:
    """The best port forward on *fw* to *address* on internal *port*: how it matches, the
    external port, whether it passes the filter by itself, its name."""
    uplink_zones = fw.uplink_zones()
    best: tuple[Match, int | None, bool | None, str] = (Match.NO, None, None, "")
    for pf in fw.port_forwards:
        if pf.target_address != address:
            continue
        if not pf.zones and zones is not None and not (zones & uplink_zones):
            continue
        external: int | None = port
        if port is not None and pf.external_ports and pf.target_port is not None:
            external = next(
                (
                    r.start + (port - pf.target_port)
                    for r in pf.external_ports
                    if pf.target_port <= port <= pf.target_port + (r.last - r.start)
                ),
                None,
            )
            if external is None:
                continue
        m = pf.matches(zones, protocol, external)
        if m is Match.YES:
            return m, external, pf.passes_filter, pf.name or str(external)
        if m is Match.MAYBE:
            best = (Match.MAYBE, external, pf.passes_filter, pf.name or str(external))
    return best


def _through(
    net: Network,
    router: str,
    source: str,
    entry: str,
    exit_: str,
    address: IPAddress,
    port: int | None,
    protocol: FirewallProtocol | None,
    depth: int,
) -> FirewallVerdict:
    """Traffic from *source* (arriving through *entry*) routed by *router* out through *exit_*
    to *address*."""
    fw = net.firewall_of(router)
    if fw is None:
        return _v(Verdict.UNKNOWN, f"the firewall of {_name(net, router)} is not read", router)
    zones_in, zones_out = _zones(fw, entry), _zones(fw, exit_)
    uplink = _is_uplink(net, entry)
    forwarded = False
    steps: list[FirewallVerdict] = []
    if uplink is not None and not internet_reachable_network(_host(address)):
        m, external, passes, name = _forward_target(fw, zones_in, address, protocol, port)
        if m is Match.NO:
            if not fw.port_forwards_complete:
                return _v(Verdict.UNKNOWN, "not every port forward could be read", router)
            return _v(
                Verdict.DENIED,
                f"{address} is a private address and {_name(net, router)} forwards no port to it",
                router,
            )
        forwarded = True
        if m is Match.MAYBE:
            steps.append(_v(Verdict.UNKNOWN, f"port forward {name} may apply", router))
        steps.append(_upstream(net, uplink, protocol, external, None, depth))
        if passes:
            steps.append(_v(Verdict.ALLOWED, f"port forward {name}", router))
            return in_series(steps)
    elif uplink is not None:
        steps.append(_upstream(net, uplink, protocol, port, None, depth))
    results = [
        fw.evaluate(
            Flow(
                chain=FirewallChain.FORWARD,
                source_zones=zones_in,
                destination_zones=zones_out,
                source=src,
                destination=_host(address),
                family=address.version,
                protocol=protocol,
                port=port,
                forwarded=forwarded,
            )
        )
        for src in _source_networks(net, source, address.version)
    ]
    return in_series([*steps, any_of(results)])


def reach(
    net: Network,
    source: str,
    address: IPAddress | str,
    port: int | None = None,
    protocol: FirewallProtocol | None = None,
    _depth: int = 0,
    _owner: bool = True,
) -> FirewallVerdict:
    """Can traffic from *source* (a segment, uplink or tunnel id) reach *address* on *port*?

    Same segment: allowed (no router in between), unless the target is a device whose own
    firewall decides. A device's own address it has in (or towards) the source: its input
    chain. Otherwise the one router that is in both the source and the target's segment
    decides (forward chain), followed by the target device's own firewall where read. No such
    router, or more than one hop: ``unknown``.
    """
    if isinstance(address, str):
        address = ip_address(address.strip("[]"))
    assert isinstance(address, IPv4Address | IPv6Address)
    owner = address_owner(net, address)
    owner_filters = owner is not None and _filters(net, owner)
    if owner is not None and _owner and owner_filters and _present(net, owner, source):
        return device_input(net, owner, source, port, protocol, address)
    on = own_addresses(net, owner).get(address) if owner else None
    target = address_segment(net, address) or on
    if target is None:
        return _v(Verdict.UNKNOWN, f"{address} is in no known network")
    own_check: list[FirewallVerdict] = []
    if owner is not None and _owner and owner_filters:
        own_check.append(device_input(net, owner, source, port, protocol, address, on or target))
    if target == source:
        return in_series([_v(Verdict.ALLOWED, "same network, no router in between"), *own_check])
    routers = []
    for dev in sorted(net.devices, key=lambda d: d.id):
        entry = _present(net, dev.id, source)
        exit_ = _present(net, dev.id, target)
        if entry is not None and exit_ is not None and entry != exit_:
            routers.append((dev.id, entry, exit_))
    if not routers:
        return _v(Verdict.UNKNOWN, "no single known router between the two networks")
    path = any_of(
        _through(net, r, source, entry, exit_, address, port, protocol, _depth)
        for r, entry, exit_ in routers
    )
    return in_series([path, *own_check])


def service_reach(net: Network, service: ManagementService, source: str) -> FirewallVerdict:
    """Can traffic from *source* (a segment, uplink or tunnel) reach the device's own
    *service*? Its input chain, at the device's address in (or towards) that source. Layer-2
    services are not filtered by an IP firewall: allowed."""
    if not service.enabled:
        return _v(Verdict.DENIED, "the service is off", service.device_id)
    if service.transport is ServiceTransport.LAYER2:
        return _v(Verdict.ALLOWED, "layer-2 service, no IP firewall applies", service.device_id)
    via = _present(net, service.device_id, source)
    own = own_addresses(net, service.device_id)
    addrs = sorted((a for a, where in own.items() if where == via), key=str) if via else []
    protocol = _protocol(service)
    if not addrs:
        return device_input(net, service.device_id, source, service.port, protocol)
    return any_of(
        device_input(net, service.device_id, source, service.port, protocol, a) for a in addrs
    )


def service_from_internet(net: Network, service: ManagementService) -> FirewallVerdict:
    """Whether the internet reaches *service* (#123): the device's own statement
    (:meth:`Network.service_from_wan`) first, then its firewall from each of its uplinks."""
    own = net.service_from_wan(service)
    if own is True:
        return _v(Verdict.ALLOWED, "the device says so", service.device_id)
    if own is False:
        return _v(Verdict.DENIED, "not offered on the internet side", service.device_id)
    if service.transport is ServiceTransport.LAYER2:
        return _v(Verdict.UNKNOWN, "layer-2 service on the uplink port", service.device_id)
    return any_of(service_reach(net, service, u.id) for u in net.uplinks_of(service.device_id))


def port_ranges_overlap(a: Iterable[PortRange], b: Iterable[PortRange]) -> list[tuple[int, int]]:
    """The inclusive port ranges that are in both *a* and *b*."""
    b = list(b)
    return [
        (max(x.start, y.start), min(x.last, y.last))
        for x in a
        for y in b
        if max(x.start, y.start) <= min(x.last, y.last)
    ]


def forward_target_ports(forward: PortForward) -> list[PortRange]:
    """The ports on the target that *forward* leads to (every port for an exposed host)."""
    if not forward.external_ports:
        return [PortRange(start=1, end=65535)]
    if forward.target_port is None:
        return list(forward.external_ports)
    return [
        PortRange(start=forward.target_port, end=min(65535, forward.target_port + r.last - r.start))
        for r in forward.external_ports
    ]
