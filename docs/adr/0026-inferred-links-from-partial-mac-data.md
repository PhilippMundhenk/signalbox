# 0026. Inferred links from partial MAC data (#378)

Date: 2026-11-24 · Status: accepted

## Context

A real network without LLDP: gateway (OPNsense, ARP/NDP table only), a server switch (OpenWrt
with DSA), a VLAN trunk to a distribution switch (NETGEAR Plus) and two OpenWrt access points.
The topology drew one access point straight to the gateway and left both switches and the other
access point "not cabled". Cause: the OpenWrt integration read no bridge table, the plus
switches have none (and report their MAC on no port), so the only sightings were the gateway's
ARP entries (`Client.seen_on`). `fdb.adjacencies` then had no table that could put a switch in
between, and linked the gateway's port to the one access point whose MAC it saw there.

## Decision

- **OpenWrt reads its bridge table** (ADR 0016 had left it out): `file read` of
  `/sys/class/net/<bridge>/brforward` with `base64` and the members' `brport/port_no`. One ACL
  path more, no package, no `exec`; an older ACL is an optional gap that *Fix it* repairs.
- **More ways to know a device's MAC**: `Device.mac` for a switch whose MAC is on no port
  (NETGEAR Plus, Easy Smart; they still have no table: an optional gap), and the MAC that an
  ARP/NDP table gives for a device's management address.
- **The chain from every source**: a third device sits between a port and a device it learns
  when its own table learns the two on different ports (new), or as before when the far
  device's table puts both behind one port. With no table on either, a switch is taken to sit
  before a device that is none. ARP entries on a VLAN interface count for the jack below it.
- **Guessed ports, inferred links**: the far port of a device without a table and without the
  learned MAC on a jack is chosen among its free jacks by VLAN memberships, PVID and speed.
  Such a link, and one that no table of either device confirms, is `Link.inferred`: drawn
  dashed, listed with its evidence (`Link.evidence`: which port of which device saw what) on
  the device page, and left out of the checks.

## Consequences

- With the OpenWrt tables the chain of the issue is found; the plus switch's ports are a guess
  and say so. Without them (an older ACL) the gateway is linked to the switches only, dashed,
  and no access point is drawn cabled to the gateway.
- Checks never build on a guessed port: a dashed link causes no VLAN, speed or LAG finding.
- On DSA the software bridge only knows what reached the CPU (broadcasts, own traffic); enough
  for which port leads where, not for every client (a guess until a real device confirms it,
  #21).
