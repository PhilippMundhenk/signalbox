<!-- rules of src/signalbox/rules/dhcp.py; part of the rules documentation (docs/RULES.md lists all) -->

# DHCP and addressing

A *router address* below is the address of a subnet marked as the gateway, or of any subnet of
a device with the gateway role.

## `dhcp.one-server`

- **Severity:** error (more than one server), warning (none)
- **Checks:** every network (VLAN) with an IPv4 router address has exactly one enabled DHCP
  server. Networks with only IPv6 are skipped (they often use SLAAC). If no device at the site
  can report DHCP servers (or every one that can failed to), the rule reports the network as
  incomplete rather than as missing a server.
- **Fix:** keep the DHCP server on the router of the network and disable the others; enable one
  if there is none, unless every device on that network has a fixed address on purpose.

## `dhcp.pools-overlap`

- **Severity:** warning
- **Checks:** the address pools of one DHCP server do not cover the same addresses.
- **Fix:** shrink or merge the pools so that every address is in at most one.

## `dhcp.pool-fixed-address`

- **Severity:** warning
- **Checks:** no address that a router, switch or access point uses on the network (its subnet
  interface address) lies inside a DHCP pool of that network.
- **Fix:** move the pool above the fixed addresses, or give the device an address outside it.

## `dhcp.reservation-in-pool`

- **Severity:** warning
- **Checks:** static DHCP reservations use addresses outside the dynamic pool range.
- **Fix:** pick a reserved address outside the pool, or shrink the pool.

## `dhcp.router-option`

- **Severity:** warning
- **Checks:** the router (default gateway) option a DHCP server hands out is the interface
  address of the router on that network. A server without a router option is not checked (most
  servers then send their own address). If no router address is known for the network, the
  check is incomplete.
- **Fix:** set the router option to the router's address on that network.

## `dhcp.dns-option`

- **Severity:** warning
- **Checks:** every DNS server a DHCP server hands out is either a listen address of an enabled
  DNS service Signalbox knows (a service without listen addresses counts with all addresses of
  its device) or a router address of that network. Outside resolvers are reported; turn the rule
  off if you use one on purpose.
- **Fix:** hand out the address of your router or local resolver.

## `addr.subnet-overlap`

- **Severity:** error
- **Checks:** subnets of different networks, at the same or at different sites, do not overlap.
  The same subnet seen by several devices on one network is fine.
- **Fix:** give each network its own, non-overlapping address range.

## `addr.duplicate-ip`

- **Severity:** error
- **Checks:** no IP address belongs to more than one MAC address, among the addresses of known
  clients and the DHCP reservations of all servers. IPv6 link-local addresses are ignored.
- **Fix:** change the reservation or fixed address of one of the devices.
