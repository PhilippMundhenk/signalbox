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

### `vlan.trunk-scope`

- **Severity:** info
- **Checks:** a cable from a switch or router to an access point carries tagged only the networks
  the access point uses: those of its enabled SSIDs, of its own access ports, of its own
  addresses (subnets it reports) and of its management address. One finding per link lists the
  extra VLANs. Every extra VLAN can be reached by anyone who unplugs the access point.
- **Stays quiet** for links to switches, for access points with further links (they forward to
  other devices), for access points whose Wi-Fi could not be read or that have an SSID without a
  known network, for access points reported by a controller (it may move SSIDs between them), and
  when the network the access point is managed in is not known.
- **Fix:** remove the VLANs named in the finding from the switch port.

### `link.slow`

- **Severity:** warning; info for a single port at 10 Mbit/s
- **Checks:** a cable between two network devices (router, switch, access point) runs below
  1 Gbit/s or in half duplex. Unlike `link.speed-duplex` this checks the value itself, so it also
  works when only one end reports it. A port of a network device that is up in half duplex is
  reported even without a known link; one that is up at 10 Mbit/s is reported as info. Ports that
  are down, wireless, aggregates or virtual are skipped.
- **Fix:** replace the cable (a damaged cable often uses only two pairs, which limits it to
  100 Mbit/s) and check that both ports are set to auto-negotiation. If a device only has
  100 Mbit/s ports, turn the rule off or accept the finding.

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

<!-- IPv6 rules (src/signalbox/rules/ipv6.py) -->

## IPv6

A *client network* below is a network (VLAN) with an enabled SSID or at least one client seen on
it. *Router prefixes* are the IPv6 subnets of a router (a subnet marked as the gateway, or any
subnet of a device with the gateway role); link-local addresses are ignored.

### `ipv6.unknown-prefix`

- **Severity:** warning
- **Checks:** every global (2000::/3) or unique local (fc00::/7) IPv6 address of a client lies
  in a router prefix of the client's network. One finding per foreign /64, naming the clients
  that use it: another router or hotspot is sending router advertisements there. Clients
  without a known network, and networks without a known router, are skipped.
- **Incomplete:** clients have IPv6 addresses, but no router at the site reported any IPv6
  subnet (the integration may not read IPv6).
- **Fix:** look for another router, phone hotspot or virtual machine host on the network and
  turn off its router advertisements.

### `ipv6.prefix-64`

- **Severity:** warning
- **Checks:** every router prefix on a client network is a /64, the only length automatic
  addressing (SLAAC) works with. Networks without SSIDs or clients (point-to-point or transit
  links such as a /127) are not checked. Turn the rule off if a network uses only DHCPv6 on
  purpose.
- **Fix:** use a /64 per network; split a larger delegated prefix into /64s.

### `ipv6.partial`

- **Severity:** info
- **Checks:** per site, if the router has IPv6 on at least one client network, every other
  client network with a router subnet has IPv6 too; and if one has a global prefix, none has
  only a unique local (ULA) prefix.
- **Fix:** add a /64 from the delegated prefix to the network named in the finding, or turn the
  rule off if IPv6 is disabled there on purpose.

<!-- end of IPv6 rules -->

<!-- DNS rules (src/signalbox/rules/dns.py) -->

## DNS

Only enabled DNS services count. Host records are compared per site. An address is *used* if it
is an interface address or management address of a known device, a listen address of a DNS
service, or an address of a client seen in this run. Checks that rely on "no client uses this
address" only run for a site and IP version for which clients were reported (IPv4 when a device
reads clients; IPv6 only when IPv6 client addresses were seen), and stay silent otherwise.

### `dns.host-record-reservation`

- **Severity:** warning; info for a record with another name on a reserved address
- **Checks:** a host record whose name without the domain (`nas` for `nas.home.example`,
  case-insensitive) equals the hostname of a DHCP reservation at the same site points to the
  same addresses (several records of one name, round robin, are compared as a set; IPv4 and IPv6
  separately). A record whose address is reserved for a device with a different hostname is
  reported as info; it may be an intended second name. Reservations without a hostname are
  skipped.
- **Fix:** update the DNS record (or the reservation) so that both use the same address.

### `dns.host-record-stale`

- **Severity:** info for an unused address in a network of the site (the device may be off),
  warning for a private address outside every network Signalbox knows
- **Checks:** a host record does not point to an address in a network of the site that no
  device, client or DHCP reservation uses, nor to a non-public address that lies in no known
  network (a typo or an old network). Public addresses (intended overrides), `0.0.0.0` and
  loopback (blocking entries) and link-local addresses are not reported.
- **Fix:** remove the record, or correct the address.

### `dns.host-record-dynamic`

- **Severity:** warning
- **Checks:** a host record does not point to an address inside the pool of an enabled DHCP
  server at the same site unless that server has a reservation for the address. Records are
  treated as static: names the DNS service registers from DHCP leases are not reported as host
  records by the integrations.
- **Fix:** add a DHCP reservation for the device at that address, or move the record (and the
  device) to an address outside the pool.

### `dns.forwarder-loop`

- **Severity:** error
- **Checks:** DNS services do not forward in a circle. A forwarder that is an address of a
  device running a known DNS service (its listen addresses, or all its addresses if none are
  reported) leads to that service; a cycle, including a service that forwards to itself, is one
  finding that names each step. Domain-specific (conditional) forwards are not counted.
- **Fix:** let one of them forward to an upstream resolver, or resolve recursively.

### `dns.forwarder-missing`

- **Severity:** error when it is the only forwarder or DNS server, warning when others exist
- **Checks:** a forwarder of a DNS service, or a DNS server handed out by an enabled DHCP
  server, that lies in a known network is used by a known device, DNS service or client.
  Addresses outside every known network are not checked.
- **Fix:** point the setting to an existing resolver, or bring the resolver back.

### `dns.single-forwarder`

- **Severity:** info
- **Checks:** a DNS service with forwarders has more than one upstream: two forwarders that
  belong to the same known device count as one. If the single upstream is a known DNS service,
  the chain is followed: it is fine when that service has several upstreams or resolves itself.
  A service without forwarders is treated as resolving recursively and is not reported; loops
  are left to `dns.forwarder-loop`.
- **Fix:** add a second upstream resolver, or let the resolver resolve recursively.

### `dns.conflicting-records`

- **Severity:** warning
- **Checks:** a name has the same addresses on every DNS service of a site that has a record for
  it. Names are compared case-insensitively and without a local domain (the domain a DHCP server
  of the site hands out), so `nas` and `nas.home.example` are the same name when `home.example`
  is a DHCP domain. IPv4 and IPv6 records are compared separately; identical round-robin sets
  are fine, and several addresses of one name on a single service (round robin) are not
  reported.
- **Fix:** use the same record on every resolver, or use a single resolver.

<!-- end of DNS rules -->

<!-- Client rules (src/signalbox/rules/clients.py) -->

## Clients

A MAC address is *randomised* when it is locally administered (the second-lowest bit of the
first octet is set, for example `02:`, `x6:`, `xA:`, `xE:`). Phones, tablets and laptops use such
"private Wi-Fi addresses" by default and change them; virtual machines and containers use them
too, but keep them.

### `clients.duplicate-hostname`

- **Severity:** warning; info when one of the MAC addresses is randomised (often one phone or
  laptop seen with its private and its real address)
- **Checks:** clients with different MAC addresses on one network do not announce the same host
  name (compared case-insensitively, without the domain). Networks whose DHCP servers hand out
  the same domain are compared together. Empty and generic names (`android`, `iphone`, `ipad`,
  `espressif`, `localhost`, ...) and names that are just the MAC address are ignored, as are
  clients whose network is not known.
- **Fix:** rename one of the devices (in its own settings).

### `clients.random-mac`

- **Severity:** warning for a DHCP reservation or a DNS name; info for the share per network
- **Checks:**
  - no DHCP reservation is for a randomised MAC address (the same reservation on several servers
    is one finding);
  - no local DNS host record points to an address that a client with a randomised MAC address
    uses (IPv6 link-local addresses are ignored);
  - for information, per network: how many of the known clients use a randomised MAC address
    (only when at least one does). It explains why client lists grow and reservations, parental
    controls or firewall rules do not stick.
- **Fix:** turn off the private (random) address for this network on the device, then reserve
  its real MAC. Reservations for virtual machines or containers that keep their address are
  fine; turn the rule off if all of yours are.

<!-- end of client rules -->

<!-- Wi-Fi hygiene rules (src/signalbox/rules/wifi_hygiene.py) -->

## Wi-Fi hygiene

These rules look at single access points and radios; the rules under *Wi-Fi* compare access
points with each other. Disabled radios and SSIDs are skipped, and so are values a device did
not report (automatic channel, width or power).

### `wifi.6ghz-security`

- **Severity:** error
- **Checks:** every SSID on a 6 GHz radio uses WPA3 (personal or enterprise) or Enhanced Open
  (OWE). WPA2, WPA2/WPA3 transition mode and open networks are not allowed on 6 GHz and clients
  do not join them there. Protected management frames, which 6 GHz requires too, are checked by
  `wifi.pmf`.
- **Fix:** on 6 GHz use WPA3 only (or OWE) with PMF required; keep transition mode on 2.4 and
  5 GHz if old devices need it.

### `wifi.pmf`

- **Severity:** error for WPA3 (personal or enterprise) and OWE without PMF *required*; warning
  for WPA2/WPA3 transition mode with PMF *disabled*
- **Checks:** the protected management frames (PMF, 802.11w) setting matches the security mode.
  WPA2 and open networks are not checked. One finding per access point and SSID.
- **Incomplete:** the device did not report PMF for a WPA3, OWE or transition-mode SSID.
- **Fix:** set PMF to required (WPA3, OWE) or at least optional (transition mode).

### `wifi.hidden`

- **Severity:** info
- **Checks:** no enabled SSID is hidden. One finding per SSID and site. A hidden SSID that both
  ends of a wireless link broadcast (a mesh or bridge backhaul) is skipped.
- **Fix:** hiding adds no security; consider broadcasting the SSID and relying on WPA2/WPA3.

### `wifi.ssid-count`

- **Severity:** warning
- **Checks:** a radio broadcasts at most four SSIDs (three on 2.4 GHz). Hidden SSIDs count too,
  they send beacons as well.
- **Fix:** merge SSIDs or turn off the ones you do not need.

### `wifi.channel-width`

- **Severity:** warning for a 2.4 GHz radio wider than 20 MHz; info for 160 MHz on 5 GHz or
  320 MHz on 6 GHz at a site with more than one access point on that band
- **Checks:** channel widths fit the band and the number of access points. Radios with an
  unknown width are skipped.
- **Fix:** use 20 MHz on 2.4 GHz; 80 MHz on 5 GHz (160 MHz or less on 6 GHz) with several
  access points.

### `wifi.24-channel-plan`

- **Severity:** info
- **Checks:** a 2.4 GHz radio uses channel 1, 6 or 11. Where the country code allows channel 13
  (any reported code except US and CA), 5, 9 and 13 of the plan 1, 5, 9, 13 are accepted too.
  Radios on automatic channel selection are skipped. `wifi.channel-overlap` compares your own
  access points; this rule is about the neighbours.
- **Fix:** use channel 1, 6 or 11.

### `wifi.dfs`

- **Severity:** info
- **Checks:** a 5 GHz radio uses a radar (DFS) channel (52-144), or a width that reaches into
  them (for example 36 at 160 MHz occupies 36-64). The access point then waits up to ten minutes
  for radar after a start and leaves the channel when it detects one. Turn the rule off if you
  use DFS on purpose.
- **Fix:** if clients lose Wi-Fi now and then, try channels 36-48 or 149-165.

### `wifi.tx-power`

- **Severity:** info
- **Checks:**
  - on one access point, the 2.4 GHz radio does not send more than 3 dB louder than its 5 GHz
    radio, where both broadcast the same SSID;
  - at one site, the radios of one band on different access points are within 6 dB of each
    other.
  Radios with automatic or unreported power are skipped. The maximum power of a radio is not
  known, so "every radio at maximum power" is not checked.
- **Fix:** lower 2.4 GHz to about 3-6 dB below 5 GHz; bring the access points within about
  6 dB of each other, usually by lowering the loud one.

### `wifi.ssid-coverage`

- **Severity:** info
- **Checks:** at a site with several access points, an SSID is broadcast by every access point
  that has a radio for its bands, and on every band where another access point offers it (if
  the access point has a radio for that band). Sites with one access point are skipped. SSIDs in
  a desired state are compared by `drift.wlan` as well.
- **Fix:** add the SSID to the access points or bands named in the finding, or turn the rule
  off if a network is meant to cover only part of the site (for example a guest network).

### `wifi.segment-weakest-link`

- **Severity:** error when an open or OWE SSID puts clients into the same network (VLAN) as a
  password- or enterprise-protected SSID; info for password-protected SSIDs with different
  passwords on one network
- **Checks:** all SSIDs that share a network are equally protected. Two SSIDs with the same
  security and password (for example a 2.4 GHz-only SSID for IoT devices) are fine. An SSID that
  has different passwords on different access points is left to `wifi.ssid-consistent`.
- **Incomplete:** an open or OWE SSID whose network is not reported, at a site with a protected
  SSID.
- **Fix:** move the weaker SSID to its own network (VLAN), for example a guest network.

### `wifi.default-ssid`

- **Severity:** warning; error when the SSID is also open
- **Checks:** no enabled SSID has a vendor's factory name: `OpenWrt`, `LEDE`, `MikroTik-XXXXXX`,
  `FRITZ!Box ...`, `FRITZ!Repeater ...`, `TP-Link_XXXX`, `NETGEARxx`, `Omada_XXXXXX`, `dlink`,
  `ASUS`, `Linksys12345`, `ubnt`, `Xiaomi_XXXX`, `Tenda_XXXXXX` (whole name, case-insensitive).
- **Fix:** set up the access point (own SSID and password) or turn the radio off.

<!-- end of Wi-Fi hygiene rules -->

<!-- Topology and inventory rules (src/signalbox/rules/topology_checks.py) -->

## Topology and inventory

### `lag.consistent`

- **Severity:** error for members with different VLANs and for a LAG whose far end is not one
  LAG on one device; warning for members with different speed or duplex; info when only one
  member of a LAG is up
- **Checks:** the member ports of a link aggregation (LAG, bond) have the same speed, duplex and
  VLAN memberships (VLANs only where every member reports them; speed and duplex only for members
  that are not down). Where at least two members have known links, those links go to one device,
  and the ports there are members of one LAG too.
- **Incomplete:** the far-end device does not report its ports.
- **Fix:** configure a LAG on the other device as well (or remove all but one cable), connect
  all members to the same device, and configure VLANs on the LAG itself or the same on every
  member.

### `topology.hidden-device`

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

### `inventory.unknown-neighbour`

- **Severity:** info
- **Checks:** a device announced by LLDP (or a similar protocol) with a management address whose
  chassis MAC, system name and management address match no device in Signalbox. One finding per
  announced device, listing the ports that see it. LLDP capabilities are not read yet, so phones
  or computers that send LLDP with an address are reported as well.
- **Fix:** add the device under *Devices* if it is a router, switch or access point; otherwise
  ignore the finding.

### `vlan.management-separate`

- **Severity:** info; **off unless enabled** (`rules: {vlan.management-separate: {enabled: true}}`)
- **Checks:** at a site that uses VLANs, the management addresses of routers, switches and
  access points lie in a network that also has client devices (other than the network devices
  themselves) or an SSID. One finding per network names the devices. Sites without VLANs stay
  quiet.
- **Fix:** consider a management VLAN that only admin devices can reach, and move the
  management addresses there.

### `inventory.duplicate-device`

- **Severity:** warning
- **Checks:** no two devices in Signalbox (configured ones or ones reported by a controller, at
  any site) have the same management address or a port with the same MAC address. Loopback
  addresses and VRRP/CARP virtual MACs (`00:00:5e:00:01:xx`, `00:00:5e:00:02:xx`) are ignored.
- **Fix:** remove all but one of the devices from Signalbox; keep the one read through its
  controller if it has one.

### `redundancy.single-point`

- **Severity:** info
- **Checks:** at a site with a router and at least three network devices, the switches and
  access points whose failure, and the single links (not LAGs) whose failure, cut off at least
  two switches or access points from the router. One finding per site lists them all. Checked
  only when every switch and access point of the site has a known path to the router.
- **Fix:** add a second uplink (with LAG or spanning tree) for the devices named in the finding,
  or keep a spare switch.

<!-- end of topology and inventory rules -->
