<!-- rules of src/signalbox/rules/topology_checks.py; part of the rules documentation (docs/RULES.md lists all) -->

# Topology and inventory

## `lag.consistent`

- **Severity:** error for members with different VLANs and for a LAG whose far end is not one
  LAG on one device; warning for members with different speed or duplex; info when only one
  member of a LAG is up, or (#157) all are up but LACP aggregates only one of them
- **Checks:** the member ports of a link aggregation (LAG, bond) have the same speed, duplex and
  VLAN memberships (VLANs only where every member reports them; speed and duplex only for members
  that are not down). Where at least two members have known links, those links go to one device,
  and the ports there are members of one LAG too. Members are the ports that name the LAG
  (`Port.lag`) and the ports a LAG port runs on (`Port.lower`). Modes and LACP states are
  checked by the [link aggregation rules](lag_checks.md).
- **Incomplete:** the far-end device does not report its ports.
- **Fix:** configure a LAG on the other device as well (or remove all but one cable), connect
  all members to the same device, and configure VLANs on the LAG itself or the same on every
  member.

## `topology.hidden-device`

- **Severity:** info; warning when the port carries tagged VLANs
- **Checks:** a cable port of a router, switch or access point with no known link, behind which
  more than 3 client devices, or client devices of at least two networks, are seen. Usually an
  unmanaged switch or a travel router is connected there, which Signalbox cannot see through.
- **Stays quiet** when a device Signalbox knows (by MAC or address) is seen on that port: then
  the clients are behind that device. Signalbox keeps one place per client, so the count is a
  lower bound.
- **Fix:** add the switch or access point under *Devices*, or enter it on the *Topology* page.
  An unmanaged switch should not be on a port with tagged VLANs. For a server with virtual
  machines on that port, turn the rule off.

## `inventory.unknown-neighbour`

- **Severity:** info
- **Checks:** a device announced by LLDP (or a similar protocol) with a management address whose
  chassis MAC, system name and management address match no device in Signalbox. One finding per
  announced device, listing the ports that see it. Only for neighbours that announce no system
  capabilities and no description (then Signalbox cannot tell a switch from a phone, so such
  neighbours with an address are reported); a neighbour that does is judged by
  `inventory.unknown-network-device`. A device whose MAC address
  is annotated as a known neighbour (`known_neighbour`) is not reported, nor is one that a
  device reports as its own address in its MAC address table.
- **Fix:** add the device under *Devices* if it is a router, switch or access point; otherwise
  ignore the finding.

## `inventory.unknown-network-device`

- **Severity:** warning
- **Checks:** a neighbour seen by LLDP, MNDP or CDP that announces itself as a bridge (switch),
  router or WLAN access point (the enabled LLDP system capabilities, `Neighbour.capabilities`),
  or, when it announces no capabilities, whose system description names network equipment
  (switch, router, access point, RouterOS, OpenWrt, ...), and whose chassis MAC, management
  address and system name match no device, port MAC, own address of a device or subnet address
  in Signalbox. One finding per announced device, listing the ports that see it. **Stays
  quiet** for phones and stations (capability `telephone` or `station` without a network
  capability), neighbours with other or no capabilities and no gear description, and a MAC
  address annotated as `known_neighbour`.
- **Fix:** add the device under *Devices*; when its address is known, *Find devices* on that
  page can look for it there. Read from OpenWrt (lldpd), MikroTik (`/ip/neighbor`
  `system-caps-enabled`, `system-description`).

## `vlan.management-separate`

- **Severity:** info; **off unless enabled** (`rules: {vlan.management-separate: {enabled: true}}`)
- **Checks:** at a site that uses VLANs, the management addresses of routers, switches and
  access points lie in a network that also has client devices (other than the network devices
  themselves) or an SSID. One finding per network names the devices. Sites without VLANs stay
  quiet. A network with the purpose `management` is the management VLAN and is not reported;
  guest and IoT networks are left to `security.management-exposure`.
- **Fix:** consider a management VLAN that only admin devices can reach, and move the
  management addresses there; when the site has a network with the purpose `management`, the
  fix names it.

## `inventory.duplicate-device`

- **Severity:** warning
- **Checks:** no two devices in Signalbox (configured ones or ones reported by a controller, at
  any site) have the same management address or a port with the same MAC address. Loopback
  addresses and VRRP/CARP virtual MACs (`00:00:5e:00:01:xx`, `00:00:5e:00:02:xx`) are ignored.
- **Fix:** remove all but one of the devices from Signalbox; keep the one read through its
  controller if it has one.

## `redundancy.single-point`

- **Severity:** info
- **Checks:** at a site with a router and at least three network devices, the switches and
  access points whose failure, and the single links (not LAGs) whose failure, cut off at least
  two switches or access points from the router. One finding per site lists them all. Checked
  only when every switch and access point of the site has a known path to the router.
- **Fix:** add a second uplink (with LAG or spanning tree) for the devices named in the finding,
  or keep a spare switch.
