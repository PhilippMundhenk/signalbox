<!-- rules of src/signalbox/rules/ipv6.py; part of the rules documentation (docs/RULES.md lists all) -->

# IPv6

A *client network* below is a network (VLAN) with an enabled SSID or at least one client seen on
it. *Router prefixes* are the IPv6 subnets of a router (a subnet marked as the gateway, or any
subnet of a device with the gateway role); link-local addresses are ignored.

## `ipv6.unknown-prefix`

- **Severity:** warning
- **Checks:** every global (2000::/3) or unique local (fc00::/7) IPv6 address of a client lies
  in a router prefix of the client's network. One finding per foreign /64, naming the clients
  that use it: another router or hotspot is sending router advertisements there. Clients
  without a known network, and networks without a known router, are skipped.
- **Incomplete:** clients have IPv6 addresses, but no router at the site reported any IPv6
  subnet (the integration may not read IPv6).
- **Fix:** look for another router, phone hotspot or virtual machine host on the network and
  turn off its router advertisements.

## `ipv6.prefix-64`

- **Severity:** warning
- **Checks:** every router prefix on a client network is a /64, the only length automatic
  addressing (SLAAC) works with. Networks without SSIDs or clients (point-to-point or transit
  links such as a /127) are not checked. Turn the rule off if a network uses only DHCPv6 on
  purpose.
- **Fix:** use a /64 per network; split a larger delegated prefix into /64s.

## `ipv6.partial`

- **Severity:** info
- **Checks:** per site, if the router has IPv6 on at least one client network, every other
  client network with a router subnet has IPv6 too; and if one has a global prefix, none has
  only a unique local (ULA) prefix.
- **Fix:** add a /64 from the delegated prefix to the network named in the finding, or turn the
  rule off if IPv6 is disabled there on purpose.
