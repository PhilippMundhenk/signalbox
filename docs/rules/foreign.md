<!-- rules of src/signalbox/rules/foreign.py; part of the rules documentation (docs/RULES.md lists all) -->

# Foreign DHCP servers and routers

These rules report DHCP servers and IPv6 routers that answer on a network but are not devices
Signalbox knows (#61, #184, [ADR 0015](../adr/0015-foreign-dhcp-servers-and-routers.md)).
Signalbox learns about an answering server three ways:

- **its own probe** (only while `probes.enabled` is on, [PROBES.md](../PROBES.md)): one
  DHCPDISCOVER and one router solicitation from Signalbox's host on each network it is
  attached to;
- **a device's alert**: MikroTik's rogue DHCP detector (`/ip/dhcp-server/alert`) lists the
  MAC addresses of servers it saw that are not in its `valid-server` list;
- **a device's own lease**: a device Signalbox reads (a MikroTik switch or access point with a
  DHCP client on its LAN) got its address from that server.

A server is *known* when its address is an address of a device Signalbox reads (subnet,
uplink, tunnel or management address), its MAC is the MAC of one of their ports (for a router
advertisement also the MAC inside its EUI-64 link-local address), it is the server a known
DHCP relay forwards to or it answered through a known relay, or (router advertisements only)
it advertises only the prefixes of the known gateway's subnets on that network. Without a probe
and without such a sighting both rules are silent; they are silent in the desired and
predicted states too. Both are acknowledgeable per server.

## `dhcp.foreign-server`

- **Severity:** error
- **Checks:** a DHCP server that matches no known device answered on a network (a DHCPOFFER to
  the probe, a device's rogue-server alert, or the server of a device's own lease). The
  finding names its address and MAC (the MAC from the probe host's ARP table, the alert, or a
  client of a read device with that address), what it hands out (gateway, DNS) and who saw it.
- **Stays quiet** for known servers and relays (an offer through a known relay, or from the
  server a known relay forwards to), and when nothing was seen.
- **Fix:** find the device: where a switch or access point Signalbox reads has the MAC in its
  MAC table, the finding names the port; else look the MAC up in your switches' MAC tables or
  the router's client list. Turn off its DHCP server (or put it into bridge / access point
  mode). Typical culprits: the provider's router or a second router plugged in with its LAN
  side, an access point or mesh node in router mode, a travel router, a NAS or a virtual
  machine host with its own DHCP server. Acknowledge it when it is meant to be there (the
  second server of a failover pair Signalbox does not read).

## `ra.foreign-router`

- **Severity:** error
- **Checks:** a router that matches no known device sent an IPv6 router advertisement on a
  network as a default router (router lifetime above 0) or with a prefix for clients to
  configure addresses from (prefix information with the A flag). Seen by the probe's router
  solicitation.
- **Stays quiet** for routers that only announce routes (router lifetime 0 and no address
  prefix: Thread border routers such as smart speakers and TV boxes), for known routers, and
  when nothing was seen.
- **Fix:** find the device by its MAC as above and turn off router advertisements (or its
  router mode), or enable RA guard on the switch port. Add it to Signalbox or acknowledge
  this when you run it on purpose.
