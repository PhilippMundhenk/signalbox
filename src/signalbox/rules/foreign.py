"""Checks on DHCP servers and routers that answer on a network but are not known (#61, #184).

Signalbox sees an answering server three ways: its own optional probe (``probes.enabled``), a
device's alert (MikroTik's rogue DHCP detector), and the server that gave a read device its own
address. Core matches each against the known devices (:mod:`signalbox.foreign`); these checks
report the ones that match nothing. Without a probe and without such a sighting they are
silent, as in the desired and predicted states.
"""

from __future__ import annotations

from collections.abc import Iterator

from signalbox.foreign import foreign, mac_of, where
from signalbox.model import ForeignServer, Network, ServerKind, SightingSource
from signalbox.rules import Result, Severity, found, rule
from signalbox.rules._names import device_name, segment_name

_CULPRITS = (
    "Typical culprits: the provider's router or a second router plugged in with its LAN "
    "side, an access point or mesh node left in router mode, a travel router, a NAS or a "
    "virtual machine host with its own DHCP server."
)


def _network(net: Network, server: ForeignServer) -> str:
    return segment_name(net, server.segment_id) if server.segment_id else f"site {server.site_id}"


def _who(net: Network, server: ForeignServer) -> str:
    parts = [str(server.server_address)] if server.server_address else []
    mac = mac_of(net, server)
    if mac:
        parts.append(f"MAC {mac}")
    return ", ".join(parts) or "address not known"


def _seen(net: Network, server: ForeignServer) -> str:
    names = [
        "Signalbox's probe" if s.startswith("signalbox/") else device_name(net, s)
        for s in server.seen_by
    ]
    how = {
        SightingSource.PROBE: "answered",
        SightingSource.DEVICE_ALERT: "reported as unknown by",
        SightingSource.CLIENT_LEASE: "gave an address to",
    }[server.source]
    return f"{how} {', '.join(dict.fromkeys(names))}"


def _find(net: Network, server: ForeignServer) -> str:
    ports = where(net, server)
    if ports:
        return f"Its MAC address is seen on {', '.join(ports)}: follow that cable."
    if mac_of(net, server):
        return (
            "Find the port with that MAC address in your switches' MAC address tables (or "
            "the router's client list)."
        )
    return "Look up its address in the router's ARP table to get the MAC, then the port."


@rule(
    "dhcp.foreign-server",
    "Unknown DHCP server answers on a network",
    Severity.ERROR,
    "A DHCP server that Signalbox does not know answered on this network: neither its address "
    "nor its MAC address belongs to a device Signalbox reads, and no known relay forwards to "
    "it. Clients that take its offer get its gateway and DNS servers: some lose the internet, "
    "others bypass the firewall or the filtering DNS. Seen by Signalbox's own probe (when "
    "probes are on), a device's rogue-server alert, or a device that got its own address "
    "from it.",
)
def foreign_dhcp(net: Network) -> Iterator[Result]:
    for server in foreign(net, ServerKind.DHCPV4, ServerKind.DHCPV6):
        offer = server.offered
        hands = []
        if offer.routers:
            hands.append(f"gateway {', '.join(str(a) for a in offer.routers)}")
        if offer.dns_servers:
            hands.append(f"DNS {', '.join(str(a) for a in offer.dns_servers)}")
        what = f", handing out {' and '.join(hands)}" if hands else ""
        yield found(
            f"Unknown DHCP server ({_who(net, server)}) on {_network(net, server)}{what}; "
            f"it {_seen(net, server)}",
            [server.id, *([server.segment_id] if server.segment_id else [])],
            fix=f"{_find(net, server)} Then turn off that device's DHCP server (or put it "
            f"into bridge / access point mode). {_CULPRITS} If it is meant to be there (a "
            "second server of a failover pair Signalbox does not read), acknowledge this.",
            key=server.id,
        )


@rule(
    "ra.foreign-router",
    "Unknown IPv6 router advertises on a network",
    Severity.ERROR,
    "A router that Signalbox does not know sent IPv6 router advertisements on this network, as "
    "a default router or with prefixes for clients to take addresses from. Clients then use "
    "it as a gateway for IPv6 and may bypass the firewall, or take addresses from a prefix "
    "that does not reach the internet. Routers that only announce routes (lifetime 0, no "
    "address prefix: Thread border routers such as smart speakers) are not reported.",
)
def foreign_ra(net: Network) -> Iterator[Result]:
    for server in foreign(net, ServerKind.RA):
        offer = server.offered
        if offer.router_lifetime == 0 and not offer.autonomous:
            continue  # announces routes only (Thread border router): not a default router
        bits = []
        if offer.router_lifetime:
            bits.append("as a default router")
        if offer.autonomous:
            bits.append(f"prefix {', '.join(str(p) for p in offer.autonomous)}")
        what = f" ({', '.join(bits)})" if bits else ""
        yield found(
            f"Unknown IPv6 router ({_who(net, server)}) advertises on "
            f"{_network(net, server)}{what}; it {_seen(net, server)}",
            [server.id, *([server.segment_id] if server.segment_id else [])],
            fix=f"{_find(net, server)} Then turn off IPv6 router advertisements on that device "
            "(or its router mode), or enable RA guard on the switch port. "
            f"{_CULPRITS} If it is a router you run on purpose, add it to Signalbox or "
            "acknowledge this.",
            key=server.id,
        )


RULES = [foreign_dhcp, foreign_ra]
