<!-- rules of src/signalbox/rules/addressing.py; part of the rules documentation (docs/RULES.md lists all) -->

# Addressing and DHCP checks

More checks of addresses, DHCP pools, reservations and options. As above, a *router address* is
the address of a subnet marked as the gateway, or of any subnet of a device with the gateway
role. IPv6 link-local and IPv4 169.254.0.0/16 addresses are ignored unless a rule says otherwise.

## `addr.client-subnet`

- **Severity:** warning
- **Checks:** every address of a client lies in a subnet known for the network (VLAN) it is in
  (only IP versions for which the network has a subnet are compared). A client whose addresses
  lie in the subnets of two different networks is reported once, as a likely VLAN leak.
- **Incomplete:** once per network that has clients but no known subnet.
- **Fix:** check the client for a fixed address, look for a second DHCP server, or put the port
  or access point in the right VLAN.

## `dhcp.self-assigned`

- **Severity:** warning
- **Checks:** clients whose only IPv4 addresses are self-assigned (169.254.x.x) on a network that
  has an enabled DHCP server: their DHCP request was not answered. One finding per network.
  Networks without a DHCP server are left to `dhcp.one-server`.
- **Fix:** check that the DHCP server is running, its pool is not full and the VLAN reaches the
  port or access point of the client.

## `addr.prefix-consistent`

- **Severity:** error (address outside the router's subnet), warning (other mask)
- **Checks:** the IPv4 address of every device on a network that is not a router (switch and
  access point management interfaces) lies inside a router subnet of that network, with the same
  prefix length. Further subnets on the router itself are allowed. IPv6 is not compared, because
  IPv6 networks often carry several prefixes.
- **Incomplete:** a network with such device addresses but no IPv4 router address.
- **Fix:** set the device's address and mask to the router's subnet.

## `addr.gateway-position`

- **Severity:** info
- **Checks:** the router address of every IPv4 subnet (except /31 and /32) is the first or the
  last usable address, and all networks of a site use the same position. A site that mixes both
  reports the networks that differ from the majority (first wins a tie).
- **Fix:** move the router address (and update the DHCP router option and devices with a fixed
  address), or turn the rule off if your convention is different.

## `dhcp.pool-usage`

- **Severity:** warning (more than 80 % of the pool in use, or more clients seen on the network
  than the pool has addresses), error (pool full)
- **Checks:** the free addresses of each enabled DHCP server (all its pools together, overlaps
  counted once, minus reserved addresses inside the pools) against the clients without a
  reservation that hold an address in the pool. Clients without an address do not count. When
  the server reported its lease table, its active leases in the pool count as well (the larger
  number wins), so a pool that is full right now is found even if not every client is known.
- **Incomplete:** a server that did not report its pool.
- **Fix:** enlarge the pool (and the subnet if needed) or shorten the lease time.

## `dhcp.lease-time`

- **Severity:** info; warning for a long lease when the pool is more than 80 % in use
- **Checks:** the lease time of every enabled DHCP server is between 5 minutes and 7 days, and at
  most one day on a guest network (a network or SSID with the purpose `guest`: declared,
  reported or guessed from the name, see [Network purposes](networks.md)). Networks where
  every client has a reservation are skipped.
- **Fix:** use 12-24 hours, a few hours on guest networks.

## `dhcp.in-subnet`

- **Severity:** error
- **Checks:** every pool of an enabled DHCP server starts before it ends and lies inside a router
  subnet of its network, without the network or broadcast address; every reservation lies inside
  that subnet and is not its network, broadcast or router address. (A pool that contains the
  router address is reported by `dhcp.pool-fixed-address`.)
- **Incomplete:** no router subnet of that IP version is known for the network, for example
  because the server serves a relayed network.
- **Fix:** shrink the pool to the subnet; reserve a normal host address.

## `addr.one-gateway`

- **Severity:** error
- **Checks:** a network has at most one router: a device counts if its subnet on the network is
  marked as the gateway, or if it has the gateway role and runs a DHCP server there. Devices that
  share an address (the virtual address of a redundant pair) count as one. A DHCP server that
  hands out another router address is reported by `dhcp.router-option`.
- **Fix:** keep one router per network; put the others in access-point (bridge) mode or onto
  their own transit network. A router behind another router (its WAN in the other one's LAN) is
  not a second router on that network: the two LANs are separate networks (see
  [DESIGN.md](../DESIGN.md#untagged-networks-of-several-routers)), and the double NAT is reported
  by `addr.double-nat`.

## `addr.double-nat`

- **Severity:** info
- **Checks:** a router whose uplink (WAN) address lies in the subnet of another known router at
  the site (names both routers and the cable between them where it is known), or whose WAN
  address is private (RFC 1918: a router Signalbox does not read is in front) or in the shared
  carrier-grade NAT space 100.64.0.0/10. Without uplink data: a router port that is in no network
  and is cabled to another router's LAN port.
- **Why info:** a firewall behind the provider's router is often intended and works for
  browsing; Signalbox cannot see whether the outer router has the inner one as exposed host.
- **Fix:** nothing if everything works. If port forwards, a VPN server, games or IPv6 behind the
  inner router matter: put the outer router into bridge (modem) mode, or make the inner router
  its exposed host (DMZ). For CGNAT: ask the provider for a public IPv4 address, or use IPv6.
- **Forwards on the inner router only (warning, #135):** when both routers' firewalls and
  forward lists were read, a port forward of the inner router that the outer router does not
  pass on to the inner router's WAN address (a forward of the same port, or an exposed host)
  can never work from the internet. Quiet when either list is unknown. Fix: forward the ports on
  the outer router too, make the inner router its exposed host, or use bridge mode.

## `inventory.management-address`

- **Severity:** warning
- **Checks:** the management address of a configured device (not one reported by a controller)
  is not in a DHCP pool at its site unless a reservation for one of the device's MAC addresses
  (or, if they are unknown, any reservation) holds it; and no two devices share a management
  address. Host names are resolved through the DNS host records Signalbox knows; names it cannot
  resolve and loopback addresses are skipped.
- **Fix:** add a reservation for the device's MAC address or give it a fixed address outside
  the pool; give every device its own address.

## `dhcp.duplicate-reservation`

- **Severity:** warning; info for the same reservation entered twice on one server
- **Checks:** a MAC address has reservations with only one address per network (across all
  enabled servers of that network), and a host name (first label, case-insensitive) is reserved
  for only one MAC address per network. A MAC reserved on different networks is fine.
- **Fix:** keep one reservation per device; rename or remove the duplicate.

## `dhcp.domain`

- **Severity:** info; warning for `.local`
- **Checks:** per site, the domains the enabled DHCP servers hand out: networks without a domain
  while others have one, networks with different domains, and domains ending in `.local`
  (reserved for mDNS). DNS host records with a dotted name whose address is in a network with a
  DHCP domain must end in that domain. Sites where no server hands out a domain are skipped.
- **Fix:** use one local domain (`home.arpa` is recommended by RFC 8375), or ignore the finding
  if the domains differ on purpose.

## `dhcp.reservation-hostname`

- **Severity:** info
- **Checks:** the host name of a reservation matches the host name the client with that MAC
  reports (first label, case-insensitive). Missing and generic names (the MAC itself,
  `android-...`, `localhost`, `*`) are skipped.
- **Fix:** rename the reservation, or check that it is for the right device.

## `dhcp.dns-cross-network`

- **Severity:** info
- **Checks:** a DNS server handed out by DHCP lies in a known subnet of the network it serves, or
  is a router address (routers answer on all their interfaces). A resolver in another network
  works only if the firewall lets DNS through.
- **Fix:** allow only DNS to that address in the firewall, or hand out the router's address in
  the network.
