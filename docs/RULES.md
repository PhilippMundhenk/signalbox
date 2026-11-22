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
