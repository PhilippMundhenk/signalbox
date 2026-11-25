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
- **A router's ARP table is no cable**: it only says a device is in the same layer-2 network
  as the router's port. When a known switch of that network may sit in between (its own table
  does not put it beside the path, the far device's table does not learn it on another port),
  no link is drawn from it to a device that is no switch, and a link to a switch is inferred.
  ARP entries of a VLAN interface count for the jack below it (they were dropped before, so
  only the devices in the untagged network were seen: the AP of the issue).
- **Sightings are held**: the MAC of a managed device seen on a port is recorded in the
  history (kind `mac-port`) and counts for the inference for 24 hours (`MAC_HOLD`) after it was
  last seen, so links do not come and go as ARP and table entries age out between reads.
- **Guessed ports, inferred links**: the far port of a device without a table and without the
  learned MAC on a jack is chosen among its free jacks by VLAN memberships, PVID and speed.
  Such a link, and one that no table of either device confirms, is `Link.inferred`: drawn
  dashed, listed with its evidence (`Link.evidence`: which port of which device saw what) on
  the device page, and left out of the checks.

## Consequences

- With the OpenWrt tables the chain of the issue is found; the plus switch's ports are a guess
  and say so. Without them (an older ACL) the gateway is linked to the switches only, dashed,
  and no access point is drawn cabled to the gateway.
- A cable moved within the hold time can show its old and new place for up to a day.
- Checks never build on a guessed port: a dashed link causes no VLAN, speed or LAG finding.
- On DSA the software bridge only knows what reached the CPU (broadcasts, own traffic); enough
  for which port leads where, not for every client (a guess until a real device confirms it,
  #21).

## Addendum: coarse host lists and wireless uplinks (#529)

Two real networks with a FRITZ!Box as gateway showed false links. (1) A router with an ARP
table only, cabled to the box, was also linked to an OpenWrt access point cabled to another box
port. (2) In a Wi-Fi mesh of OpenWrt access points, of which one is cabled to the box, every
mesh access point got a wired link to the box. Cause: the box's host list has no per-port
information and puts every wired host of its LAN on its one `lan` port, so "learned on the same
port" there was taken as evidence; and the ARP-only guard only looked at devices of role switch.

- **Coarse ports**: `Port.coarse` marks a port that aggregates all hosts behind it without
  per-port detail. The FRITZ!Box adapter sets it on `lan` (an explicit property, not a name
  match). Its sightings never count as a per-port table (`_between`, `_may_sit_between`), and a
  device without a table is not taken as an unmanaged switch beside it: the coarse device's own
  LAN switch joins them.
- **What a coarse port links to**: only devices that report no table, or whose own bridge table
  learns the coarse device on a wired port (the cabled access point), never everything behind
  it. A link to a device without a table is inferred (no table of either end confirms it).
- **Wireless uplinks**: a device whose bridge uplink is wireless gets no wired link from a
  coarse port: a bridge whose STP root port is a Wi-Fi/WDS/mesh interface, a mesh member with a
  wireless uplink or wireless hops to the controller, the station end of a wireless backhaul
  (mesh peer reported as uplink, or the WDS station of an access point's downlink).
- **The gateway first**: when several devices learned on one port are told apart by nothing and
  one of them reports no per-port table, the one holding the default next hop (default route,
  uplink gateway) of this device or of the others is the nearest; the others are taken as
  behind it (a LAN is a star around its gateway). The link is inferred, with evidence `gateway`.
  Not on a Wi-Fi port (there the access point is nearer), and not where all of them have real
  tables (then an unmanaged switch joins them all, as before).
- **ARP-only guard**: every switch and every other device that bridges and says where hosts are
  (a MAC address table, a coarse host list: access points, routers with LAN ports) may sit
  between an ARP-only router and what its ARP table sees. A device that says nothing about its
  ports is not taken to sit in between, or one table-less access point would hide every other.
  Before the gateway only a table that learns the two ends on different ports puts it in between.

Networks with real per-port tables (switches with FDBs, MikroTik and OpenWrt bridges) keep their
links; only data with ambiguous ports changes.

## Addendum: one cable per jack, VLANs through a switch (#545)

A router with one physical port and only an ARP table, cabled to an OpenWrt switch (DSA bridge
table), got three links to that switch: the real access port, the trunk to a switch without a
table, and the port of a WAN VLAN that runs from the router through the switch to the upstream
router. The switch learns the router's MAC per VLAN, so the WAN VLAN's traffic puts it behind
other ports too; nothing on the router's side says which port it is on.

- **A tagged-only sighting is no cable**: a table entry on a port that learns the address only
  in VLANs tagged on that port (by the segment's membership; the PVID counts as untagged), while
  the same table learns the address untagged on another port, is dropped from the sightings. It
  is a VLAN that runs through the switch, not where the address is plugged in. This also puts
  the switch between the router and the upstream router (learned on different ports).
- **One cable per jack and device**: a jack has at most one cable to a given other device. Of
  several links from one jack to ports of the same device (in either direction), the one kept
  is, in order: confirmed (not inferred); where the table learns the other device untagged in
  the VLAN of that device's own address (`Device.management_address` in its subnets, else its
  untagged network), then untagged in any VLAN, then without VLAN information, then tagged
  only; then the ports that learn the fewest addresses (an access port over a trunk). The far
  port chosen from a table uses the same order. Separate cables (LAG members) have separate
  jacks at both ends and all stay.
- Without VLAN information in the table the fewest learned addresses still pick the access
  port; a device also learned behind the trunk can then keep a link of its own to the router.
