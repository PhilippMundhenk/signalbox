# 0015. Foreign DHCP servers and routers: device sightings, and an optional probe that never takes a lease

Date: 2026-11-23 · Status: accepted

## Context

A DHCP server or IPv6 router that nobody configured on purpose (an ISP box in router mode, a
travel router, an access point in router mode) is one of the most disruptive faults of a home
network, and no configuration Signalbox reads shows it: `dhcp.one-server` sees only the
servers of devices it reads. #184 asked for a place in the model for facts Signalbox observes
itself or devices report as alerts; #61 for the check. Path traces (#253, ADR 0014) introduced
the first active observation: optional, off by default, stored apart from the snapshots, a
*now* button with rate limits, a schedule. Foreign servers reuse that structure.

## Decision

- **Model.** `ForeignServer` (`<site>/foreign/<kind>/<segment key>/<MAC or address>`): site,
  segment, kind `dhcpv4 | dhcpv6 | ra`, server address and MAC, what it offers
  (`ServerOffer`: address, routers, DNS, prefixes, routes, domain, lease time, relay, RA
  router lifetime and autonomous prefixes), first and last seen, `source` probe | device-alert
  | client-lease, `seen_by` (a list: one server is often seen by the probe and a device), and
  `known_as`/`known_by`, set by core. The segment is part of the id: the same rogue on two
  VLANs is two problems. `Network.foreign_servers` holds every answering server, known or not;
  the checks take those with `known_as` empty.
- **Passive, always on (it is reading).** Integrations report `ServerSighting` objects with the
  `dhcp` capability (no API version, like relays): MikroTik's bound `/ip/dhcp-client` on a
  non-WAN interface (the server of the router's own lease) and `/ip/dhcp-server/alert`
  `unknown-server` (RouterOS's rogue DHCP detector). An integration reports what it saw, known
  or not; matching is core's job (`signalbox.foreign`). Other integrations have no such data
  Signalbox can read cheaply; OPNsense and OpenWrt logs were not used (parsing logs is fragile
  and needs more rights). Client lists carry no server identifier in any integration (Fritz!Box
  `NewAddressSource` says only "DHCP"), so leases of clients are not a source yet.
- **Known** means: an address of a read device (subnet, uplink, tunnel, management address),
  a MAC of a read device's port (for an RA also the MAC in an EUI-64 link-local address), the
  server a known relay forwards to or an answer through a known relay, or (RA only) a router
  advertising only prefixes of the known gateway subnets of that network.
- **The probe, fully optional** (`probes.enabled: false` by default; Philipp's rule for active
  observations). While it is off nothing is sent, `POST /api/probes` answers 403, stored answers
  are not used, and the segments page says what it would do. On *Probe now* or every
  `probes.interval_hours` (0: never on its own) Signalbox's host sends, on each interface that
  is up and on a network Signalbox knows (optionally only `probes.interfaces`):
  - one **DHCPDISCOVER**: random locally administered client MAC, broadcast flag, never a
    REQUEST, so no lease is taken; `wait_seconds` (3) of listening for OFFERs. A UDP socket
    bound to port 68 with `SO_REUSEADDR`, the interface chosen per packet with `IP_PKTINFO`:
    needs `CAP_NET_BIND_SERVICE` or `net.ipv4.ip_unprivileged_port_start` ≤ 68, no raw socket,
    no `CAP_NET_RAW`. The server's MAC comes from the host's ARP table (read only) or from a
    client of a read device with that address.
  - one **router solicitation** to ff02::2 (hop limit 255): a raw ICMPv6 socket, so
    `CAP_NET_RAW`; without it this leg reports so and the DHCP leg still runs
    (`probes.router_solicitation: false` skips it).

  It sees only the networks the host is attached to: host networking, a VLAN interface per
  network to probe more. One run at a time, one DISCOVER and one RS per interface, *Probe now*
  not again within `min_gap_seconds` (300). Every socket call goes through a small socket layer
  (`signalbox.probehost.Sockets`) that tests replace.
- **Stored apart from the snapshots** (store schema 6, table `foreign_servers`), the latest
  answer per id with `first_seen` kept; an answer the same interface did not hear in its next
  complete run is forgotten; pruned after `history.days`; *DELETE /api/probes* forgets all.
- **Checks** `dhcp.foreign-server` and `ra.foreign-router`, both errors, acknowledgeable per
  server (the finding key is the server's id), quiet without evidence and in the desired and
  predicted states. RAs with router lifetime 0 and no autonomous prefix (Thread border routers
  of smart speakers) are listed, not reported. The fix names the port where the MAC is seen
  (MAC tables, client lists) and the typical culprits.
- **UI**: a card on the segments page (*DHCP servers and routers answering*), like the routed
  paths card: the state per interface, *Probe now*, every server with known / foreign.

## Consequences

- One click (or a MikroTik alert) shows a second DHCP server and where it is plugged in.
- The capabilities are documented exactly (docs/PROBES.md); the container image is unchanged:
  the operator decides whether to give port 68 and `CAP_NET_RAW`.
- Verified in CI (Linux job) against a real second server: dnsmasq in a network namespace
  behind a veth pair answers the DISCOVER (no lease written) and, with the probe run as root,
  the router solicitation. MikroTik's alert list format and the probe on a real VLAN trunk are
  covered by simulators only (#21).
- Further sources plug into `ServerSighting` (Omada rogue DHCP events, OpenWrt logs) or the
  probe (DHCPv6 solicit, the `dhcpv6` kind is already in the model).
