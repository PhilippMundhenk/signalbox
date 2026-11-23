"""Foreign DHCP servers and routers (#184, #61): which answering servers Signalbox knows.

Pure functions over the model, like :mod:`signalbox.traces`. The runner puts every server seen
answering on the network with :func:`attach`: the devices' own sightings (their DHCP client's
server, rogue-server alerts; from the snapshots) and, while ``probes.enabled`` is on, the stored
answers to Signalbox's own probes (:mod:`signalbox.prober`). Each is matched against *that*
network (:func:`known_server`); the checks in :mod:`signalbox.rules.foreign` report the ones
that match nothing. Matching is core's job, never an integration's.
"""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import IPv6Address, ip_address

from signalbox.model import (
    ForeignServer,
    IPAddress,
    IPNetwork,
    Network,
    ServerKind,
    ServerOffer,
    ServerSighting,
    SightingSource,
    foreign_server_id,
)

#: Which source wins when several saw the same server.
_RANK = {SightingSource.PROBE: 0, SightingSource.DEVICE_ALERT: 1, SightingSource.CLIENT_LEASE: 2}


def _ip(text: str | None) -> IPAddress | None:
    try:
        return ip_address((text or "").strip().strip("[]"))
    except ValueError:
        return None


def eui64_mac(address: IPAddress | None) -> str | None:
    """The MAC address inside a modified EUI-64 interface id (``ff:fe`` in the middle)."""
    if not isinstance(address, IPv6Address):
        return None
    iid = address.packed[8:]
    if iid[3:5] != b"\xff\xfe":
        return None
    mac = bytes([iid[0] ^ 0x02, *iid[1:3], *iid[5:8]])
    return ":".join(f"{b:02x}" for b in mac)


def addresses(net: Network) -> dict[IPAddress, str]:
    """Every address a known device has: subnets, uplinks, tunnels, its management address."""
    out: dict[IPAddress, str] = {}
    for sub in sorted(net.subnets, key=lambda s: s.id):
        out.setdefault(sub.interface.ip, sub.device_id)
    for uplink in sorted(net.uplinks, key=lambda u: u.id):
        for a in uplink.addresses:
            out.setdefault(a.ip, uplink.device_id)
    for tunnel in sorted(net.tunnels, key=lambda t: t.id):
        for a in tunnel.addresses:
            out.setdefault(a.ip, tunnel.device_id)
    for dev in sorted(net.devices, key=lambda d: d.id):
        ip = _ip(dev.management_address)
        if ip is not None:
            out.setdefault(ip, dev.id)
    return out


def macs(net: Network) -> dict[str, str]:
    """Every MAC address of a known device's ports."""
    out: dict[str, str] = {}
    for port in sorted(net.ports, key=lambda p: p.id):
        if port.mac:
            out.setdefault(port.mac, port.device_id)
    return out


def known_server(
    net: Network,
    kind: ServerKind,
    segment_id: str | None,
    address: IPAddress | None,
    mac: str | None,
    offered: ServerOffer | None = None,
) -> tuple[str | None, str | None]:
    """The known device a server is, and how it matched; (None, None): a foreign server.

    A server is known when its address is one of a known device's addresses, its MAC one of a
    known device's ports (or, for a router advertisement, the MAC inside its EUI-64 link-local
    address), when it answered through a known relay or is the server a known relay forwards
    to, or when it is a router advertising only prefixes of the known gateway subnets of that
    network.
    """
    owned = addresses(net)
    if address is not None and address in owned:
        return owned[address], "address"
    ports = macs(net)
    for candidate in (mac, eui64_mac(address) if kind is ServerKind.RA else None):
        if candidate and candidate in ports:
            return ports[candidate], "mac"
    offer = offered or ServerOffer()
    if kind is not ServerKind.RA:
        relays = [r for r in net.dhcp_relays if r.enabled]
        for relay in sorted(relays, key=lambda r: r.id):
            if address is not None and address in relay.servers:
                return relay.device_id, "relay"
            if offer.relay is not None and owned.get(offer.relay) == relay.device_id:
                return relay.device_id, "relay"
        return None, None
    if segment_id is not None and offer.prefixes:
        gateways: dict[IPNetwork, str] = {
            s.interface.network: s.device_id
            for s in net.subnets
            if s.segment_id == segment_id and s.gateway and s.interface.version == 6
        }
        owners = {gateways.get(p) for p in offer.prefixes}
        if len(owners) == 1 and None not in owners:
            return owners.pop(), "prefix"
    return None, None


def _site(net: Network, segment_id: str | None, device_id: str | None) -> str | None:
    seg = net.segment(segment_id) if segment_id else None
    if seg is not None:
        return seg.site_id
    dev = net.device(device_id) if device_id else None
    return dev.site_id if dev is not None else None


def _key(address: IPAddress | None, mac: str | None) -> str:
    return mac or str(address)


def from_sighting(net: Network, sighting: ServerSighting) -> ForeignServer | None:
    """The answering server of one device sighting; None without a site."""
    site = _site(net, sighting.segment_id, sighting.device_id)
    if site is None:
        return None
    when = sighting.seen_at or sighting.observed_at
    return ForeignServer(
        id=foreign_server_id(
            site,
            sighting.kind,
            sighting.segment_id,
            _key(sighting.server_address, sighting.server_mac),
        ),
        site_id=site,
        segment_id=sighting.segment_id,
        kind=sighting.kind,
        server_address=sighting.server_address,
        server_mac=sighting.server_mac,
        offered=sighting.offered,
        first_seen=when,
        last_seen=when,
        source=sighting.origin,
        seen_by=[sighting.device_id],
    )


def combine(a: ForeignServer, b: ForeignServer) -> ForeignServer:
    """One server seen twice (or by several): earliest first, latest last, both seen by."""
    newer, older = (a, b) if a.last_seen >= b.last_seen else (b, a)
    source = min(a.source, b.source, key=lambda s: _RANK[s])
    return newer.model_copy(
        update={
            "first_seen": min(a.first_seen, b.first_seen),
            "server_address": newer.server_address or older.server_address,
            "server_mac": newer.server_mac or older.server_mac,
            "source": source,
            "seen_by": sorted({*a.seen_by, *b.seen_by}),
        }
    )


def attach(net: Network, probed: Iterable[ForeignServer] = ()) -> Network:
    """The network with every server seen answering, each matched (``known_as``)."""
    found: dict[str, ForeignServer] = {}
    candidates = [s for x in net.server_sightings if (s := from_sighting(net, x)) is not None]
    for server in [*candidates, *probed]:
        found[server.id] = combine(found[server.id], server) if server.id in found else server
    out = []
    for server in sorted(found.values(), key=lambda s: s.id):
        dev, how = known_server(
            net,
            server.kind,
            server.segment_id,
            server.server_address,
            server.server_mac,
            server.offered,
        )
        out.append(server.model_copy(update={"known_as": dev, "known_by": how}))
    return net.model_copy(update={"foreign_servers": out})


def foreign(net: Network, *kinds: ServerKind) -> list[ForeignServer]:
    """The servers that match no known device (of these kinds)."""
    return [s for s in net.foreign_servers if s.known_as is None and (not kinds or s.kind in kinds)]


def mac_of(net: Network, server: ForeignServer) -> str | None:
    """The server's MAC: as seen, else a client with its address (ARP tables of the routers)."""
    if server.server_mac:
        return server.server_mac
    if server.server_address is None:
        return None
    for client in sorted(net.clients, key=lambda c: c.id):
        if server.server_address in client.addresses:
            return client.mac
    return None


def where(net: Network, server: ForeignServer) -> list[str]:
    """Where the server's MAC was seen: ``port on device`` per read switch, AP or router (from
    MAC tables and client lists); empty when no device saw it."""
    mac = mac_of(net, server)
    out: list[str] = []
    for client in sorted(net.clients, key=lambda c: c.id):
        if mac is None or client.mac != mac or not client.seen_on:
            continue
        port = net.port(client.seen_on)
        if port is None:
            continue
        owner = net.device(port.device_id)
        text = f"port {port.name} of {owner.name if owner else port.device_id}"
        if text not in out:
            out.append(text)
    return out


def view(net: Network) -> list[dict[str, object]]:
    """Every answering server for the UI, with names, where its MAC is and whether it is
    known."""
    out: list[dict[str, object]] = []
    for server in net.foreign_servers:
        seg = net.segment(server.segment_id) if server.segment_id else None
        known = net.device(server.known_as) if server.known_as else None
        seen = []
        for who in server.seen_by:
            dev = net.device(who)
            seen.append(dev.name if dev else who.replace("signalbox/", "Signalbox on "))
        offer = server.offered
        out.append(
            {
                "id": server.id,
                "kind": server.kind.value,
                "site_id": server.site_id,
                "segment_id": server.segment_id,
                "segment_name": (seg.name or (f"VLAN {seg.vlan}" if seg.vlan else "untagged"))
                if seg
                else None,
                "server_address": str(server.server_address) if server.server_address else None,
                "server_mac": mac_of(net, server),
                "routers": [str(a) for a in offer.routers],
                "dns_servers": [str(a) for a in offer.dns_servers],
                "prefixes": [str(p) for p in offer.prefixes],
                "relay": str(offer.relay) if offer.relay else None,
                "router_lifetime": offer.router_lifetime,
                "first_seen": server.first_seen.isoformat(),
                "last_seen": server.last_seen.isoformat(),
                "source": server.source.value,
                "seen_by": seen,
                "known_as": server.known_as,
                "known_name": known.name if known else None,
                "known_by": server.known_by,
                "where": where(net, server),
            }
        )
    return out
