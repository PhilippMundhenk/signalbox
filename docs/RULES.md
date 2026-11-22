# Rules

The consistency rules that ship with Signalbox: what each one checks and how to fix a finding.

Each rule can be turned off or given another severity in the configuration
(`rules: {dhcp.dns-option: {enabled: false}}`). When a rule cannot check something because a
device did not report the data, it reports an *incomplete* finding (severity info) instead of
staying silent.

<!-- VLAN and link rules (src/signalbox/rules/vlan.py) -->

## VLANs and links

These rules use the known links (discovered by LLDP or entered by hand) and the VLAN memberships
of the ports at both ends. A device that reports no VLAN memberships at all (an unmanaged switch,
or one that could not be read) is treated as unknown: checks through it are reported as
incomplete, never as errors.

### `vlan.path-to-gateway`

- **Severity:** error
- **Checks:** every network (VLAN) that an access point offers on an enabled SSID, or that an
  access point or switch puts untagged on an access port, is carried (tagged, or untagged as the
  native VLAN) on both ends of every link along the shortest known path from that device to the
  router that has a subnet for the network. One finding per missing link, listing the devices
  whose clients need it.
- **Incomplete:** a device that is not connected to the router in the known topology (once per
  device), or a link end whose device does not report VLAN memberships.
- **Fix:** add the VLAN as tagged VLAN to the ports named in the finding. For an incomplete
  finding, add the missing link by hand or enable LLDP on the devices in between.

### `vlan.native-mismatch`

- **Severity:** error
- **Checks:** both ends of a link send the same network untagged (or both send nothing untagged).
- **Fix:** set the same untagged (native) VLAN on both ports, or none on both.

### `vlan.tagged-both-ends`

- **Severity:** warning (a VLAN the far end actually needs is an error of `vlan.path-to-gateway`)
- **Checks:** a VLAN tagged on one end of a link is configured on the other end as well.
- **Fix:** add the VLAN as tagged VLAN to the other port, or remove it from the first one.

### `vlan.unused`

- **Severity:** info
- **Checks:** a network that has a subnet on the router but no member port on any other device
  and no SSID that uses it. Often left over from an earlier setup.
- **Fix:** remove the VLAN and its subnet if it is no longer needed, or add it to the ports and
  SSIDs that should use it.

### `link.speed-duplex`

- **Severity:** warning
- **Checks:** the two ends of a cable link report a different speed or duplex mode (only where
  both ends report it and neither port is down; wireless links are skipped). Speed and duplex are
  separate findings.
- **Fix:** set both ports to auto-negotiation (or the same fixed speed and duplex); if the
  mismatch stays, replace the cable.

<!-- end of VLAN and link rules -->

<!-- DHCP and addressing rules (src/signalbox/rules/dhcp.py) -->

## DHCP and addressing

A *router address* below is the address of a subnet marked as the gateway, or of any subnet of
a device with the gateway role.

### `dhcp.one-server`

- **Severity:** error (more than one server), warning (none)
- **Checks:** every network (VLAN) with an IPv4 router address has exactly one enabled DHCP
  server. Networks with only IPv6 are skipped (they often use SLAAC). If no device at the site
  can report DHCP servers (or every one that can failed to), the rule reports the network as
  incomplete rather than as missing a server.
- **Fix:** keep the DHCP server on the router of the network and disable the others; enable one
  if there is none, unless every device on that network has a fixed address on purpose.

### `dhcp.pools-overlap`

- **Severity:** warning
- **Checks:** the address pools of one DHCP server do not cover the same addresses.
- **Fix:** shrink or merge the pools so that every address is in at most one.

### `dhcp.pool-fixed-address`

- **Severity:** warning
- **Checks:** no address that a router, switch or access point uses on the network (its subnet
  interface address) lies inside a DHCP pool of that network.
- **Fix:** move the pool above the fixed addresses, or give the device an address outside it.

### `dhcp.reservation-in-pool`

- **Severity:** warning
- **Checks:** static DHCP reservations use addresses outside the dynamic pool range.
- **Fix:** pick a reserved address outside the pool, or shrink the pool.

### `dhcp.router-option`

- **Severity:** warning
- **Checks:** the router (default gateway) option a DHCP server hands out is the interface
  address of the router on that network. A server without a router option is not checked (most
  servers then send their own address). If no router address is known for the network, the
  check is incomplete.
- **Fix:** set the router option to the router's address on that network.

### `dhcp.dns-option`

- **Severity:** warning
- **Checks:** every DNS server a DHCP server hands out is either a listen address of an enabled
  DNS service Signalbox knows (a service without listen addresses counts with all addresses of
  its device) or a router address of that network. Outside resolvers are reported; turn the rule
  off if you use one on purpose.
- **Fix:** hand out the address of your router or local resolver.

### `addr.subnet-overlap`

- **Severity:** error
- **Checks:** subnets of different networks, at the same or at different sites, do not overlap.
  The same subnet seen by several devices on one network is fine.
- **Fix:** give each network its own, non-overlapping address range.

### `addr.duplicate-ip`

- **Severity:** error
- **Checks:** no IP address belongs to more than one MAC address, among the addresses of known
  clients and the DHCP reservations of all servers. IPv6 link-local addresses are ignored.
- **Fix:** change the reservation or fixed address of one of the devices.

<!-- end of DHCP and addressing rules -->

<!-- Addressing and DHCP checks (src/signalbox/rules/addressing.py) -->

## Addressing and DHCP checks

More checks of addresses, DHCP pools, reservations and options. As above, a *router address* is
the address of a subnet marked as the gateway, or of any subnet of a device with the gateway
role. IPv6 link-local and IPv4 169.254.0.0/16 addresses are ignored unless a rule says otherwise.

### `addr.client-subnet`

- **Severity:** warning
- **Checks:** every address of a client lies in a subnet known for the network (VLAN) it is in
  (only IP versions for which the network has a subnet are compared). A client whose addresses
  lie in the subnets of two different networks is reported once, as a likely VLAN leak.
- **Incomplete:** once per network that has clients but no known subnet.
- **Fix:** check the client for a fixed address, look for a second DHCP server, or put the port
  or access point in the right VLAN.

### `dhcp.self-assigned`

- **Severity:** warning
- **Checks:** clients whose only IPv4 addresses are self-assigned (169.254.x.x) on a network that
  has an enabled DHCP server: their DHCP request was not answered. One finding per network.
  Networks without a DHCP server are left to `dhcp.one-server`.
- **Fix:** check that the DHCP server is running, its pool is not full and the VLAN reaches the
  port or access point of the client.

### `addr.prefix-consistent`

- **Severity:** error (address outside the router's subnet), warning (other mask)
- **Checks:** the IPv4 address of every device on a network that is not a router (switch and
  access point management interfaces) lies inside a router subnet of that network, with the same
  prefix length. Further subnets on the router itself are allowed. IPv6 is not compared, because
  IPv6 networks often carry several prefixes.
- **Incomplete:** a network with such device addresses but no IPv4 router address.
- **Fix:** set the device's address and mask to the router's subnet.

### `addr.gateway-position`

- **Severity:** info
- **Checks:** the router address of every IPv4 subnet (except /31 and /32) is the first or the
  last usable address, and all networks of a site use the same position. A site that mixes both
  reports the networks that differ from the majority (first wins a tie).
- **Fix:** move the router address (and update the DHCP router option and devices with a fixed
  address), or turn the rule off if your convention is different.

### `dhcp.pool-usage`

- **Severity:** warning (more than 80 % of the pool in use, or more clients seen on the network
  than the pool has addresses), error (pool full)
- **Checks:** the free addresses of each enabled DHCP server (all its pools together, overlaps
  counted once, minus reserved addresses inside the pools) against the clients without a
  reservation that hold an address in the pool. Clients without an address do not count.
- **Incomplete:** a server that did not report its pool.
- **Fix:** enlarge the pool (and the subnet if needed) or shorten the lease time.

### `dhcp.lease-time`

- **Severity:** info; warning for a long lease when the pool is more than 80 % in use
- **Checks:** the lease time of every enabled DHCP server is between 5 minutes and 7 days, and at
  most one day on a guest network (a network or SSID with "guest" in its name). Networks where
  every client has a reservation are skipped.
- **Fix:** use 12-24 hours, a few hours on guest networks.

### `dhcp.in-subnet`

- **Severity:** error
- **Checks:** every pool of an enabled DHCP server starts before it ends and lies inside a router
  subnet of its network, without the network or broadcast address; every reservation lies inside
  that subnet and is not its network, broadcast or router address. (A pool that contains the
  router address is reported by `dhcp.pool-fixed-address`.)
- **Incomplete:** no router subnet of that IP version is known for the network, for example
  because the server serves a relayed network.
- **Fix:** shrink the pool to the subnet; reserve a normal host address.

### `addr.one-gateway`

- **Severity:** error
- **Checks:** a network has at most one router: a device counts if its subnet on the network is
  marked as the gateway, or if it has the gateway role and runs a DHCP server there. Devices that
  share an address (the virtual address of a redundant pair) count as one. A DHCP server that
  hands out another router address is reported by `dhcp.router-option`.
- **Fix:** keep one router per network; put the others in access-point (bridge) mode or onto
  their own transit network.

### `inventory.management-address`

- **Severity:** warning
- **Checks:** the management address of a configured device (not one reported by a controller)
  is not in a DHCP pool at its site unless a reservation for one of the device's MAC addresses
  (or, if they are unknown, any reservation) holds it; and no two devices share a management
  address. Host names are resolved through the DNS host records Signalbox knows; names it cannot
  resolve and loopback addresses are skipped.
- **Fix:** add a reservation for the device's MAC address or give it a fixed address outside
  the pool; give every device its own address.

### `dhcp.duplicate-reservation`

- **Severity:** warning; info for the same reservation entered twice on one server
- **Checks:** a MAC address has reservations with only one address per network (across all
  enabled servers of that network), and a host name (first label, case-insensitive) is reserved
  for only one MAC address per network. A MAC reserved on different networks is fine.
- **Fix:** keep one reservation per device; rename or remove the duplicate.

### `dhcp.domain`

- **Severity:** info; warning for `.local`
- **Checks:** per site, the domains the enabled DHCP servers hand out: networks without a domain
  while others have one, networks with different domains, and domains ending in `.local`
  (reserved for mDNS). DNS host records with a dotted name whose address is in a network with a
  DHCP domain must end in that domain. Sites where no server hands out a domain are skipped.
- **Fix:** use one local domain (`home.arpa` is recommended by RFC 8375), or ignore the finding
  if the domains differ on purpose.

### `dhcp.reservation-hostname`

- **Severity:** info
- **Checks:** the host name of a reservation matches the host name the client with that MAC
  reports (first label, case-insensitive). Missing and generic names (the MAC itself,
  `android-...`, `localhost`, `*`) are skipped.
- **Fix:** rename the reservation, or check that it is for the right device.

### `dhcp.dns-cross-network`

- **Severity:** info
- **Checks:** a DNS server handed out by DHCP lies in a known subnet of the network it serves, or
  is a router address (routers answer on all their interfaces). A resolver in another network
  works only if the firewall lets DNS through.
- **Fix:** allow only DNS to that address in the firewall, or hand out the router's address in
  the network.

<!-- end of addressing and DHCP checks -->

<!-- Wi-Fi rules (src/signalbox/rules/wireless.py) -->

## Wi-Fi

### `wifi.ssid-consistent`

- **Severity:** error for security mode, passphrase and network (VLAN); warning for protected
  management frames (PMF), hidden setting and the roaming settings 802.11r, k and v
- **Checks:** a Wi-Fi network (SSID) broadcast by several access points of one site has the same
  settings on all of them. One finding per differing setting names the value per access point;
  passphrases are compared only by a fingerprint and the finding says just "passphrase differs"
  and which access points belong together. Settings a device did not report are not compared.
  The same SSID at different sites is checked per site (networks are per site).
- **Fix:** set the same value for that setting on every access point.

### `wifi.country`

- **Severity:** warning
- **Checks:** every enabled radio has a country code, and all radios of a site use the same one
  (compared case-insensitively).
- **Fix:** set the country code of the country the site is in on every radio.

### `wifi.channel-overlap`

- **Severity:** warning
- **Checks:** two enabled radios on different access points of the same site and band do not
  use overlapping channels. Signalbox does not know which access points hear each other, so
  every pair at a site counts as neighbours.
  - 2.4 GHz: channels overlap if they are less than 5 apart (1, 6 and 11 do not overlap); the
    channel width is ignored.
  - 5 and 6 GHz: a radio occupies the aligned block of 20 MHz channels of its width (20 MHz if
    not reported) in the standard channel plan (5 GHz blocks start at 36 and at 149, 6 GHz at
    1); radios overlap if their blocks share a 20 MHz channel. For example 36 at 80 MHz
    occupies 36-48 and overlaps 44 at 20 MHz but not 52 at 80 MHz.
- **Fix:** move one access point to a channel that does not overlap, or use a narrower width.

### `wifi.segment-at-gateway`

- **Severity:** error
- **Checks:** a Wi-Fi network bound to a VLAN uses a network for which a router has a subnet
  (a subnet marked as the gateway, or any subnet of a device with the gateway role).
  If no router at the site reported its subnets, the check is incomplete.
- **Fix:** create the VLAN with an address and DHCP on the router, or bind the SSID to a network
  that exists there.

<!-- end of Wi-Fi rules -->

<!-- Topology rules (src/signalbox/topology.py) -->

## Topology

Links come from LLDP (devices that announce their neighbours), from MAC tables (a device sees
another device's port address on one of its ports), and from cables entered by hand on the
*Topology* page. LLDP wins over MAC tables; entered cables are kept as they are.

### `topology.manual-conflict`

- **Severity:** warning
- **Checks:** a cable entered by hand agrees with what the devices report: if LLDP or a MAC table
  says one of its ports is connected to a different port, the entry and reality disagree.
- **Fix:** move the cable, or change the entered link to match.

### `topology.untagged-only-link`

- **Severity:** info
- **Checks:** when the site uses VLANs, a wired link between two devices that both report VLAN
  memberships carries at least one tagged VLAN. A link with only the untagged network is often a
  trunk that was configured as an access port.
- **Fix:** if VLANs should pass the link, tag them on both ports; otherwise ignore or turn off.

<!-- end of topology rules -->

<!-- Firmware rules (src/signalbox/rules/firmware.py) -->

## Firmware

### `firmware.drift`

- **Severity:** warning
- **Checks:** devices of the same vendor and model at one site run the same firmware version.
- **Fix:** update all of them to the same (newest) version.

### `firmware.update-available`

- **Severity:** info
- **Checks:** a device that reports an available update (OPNsense, MikroTik, ...) runs it.
- **Fix:** read the release notes and update in a maintenance window.

### `firmware.end-of-life`

- **Severity:** warning
- **Checks:** a device whose firmware the integration reports as end of life.
- **Fix:** update to a supported release, or plan to replace the device.

<!-- end of firmware rules -->
