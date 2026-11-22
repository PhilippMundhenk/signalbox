<!-- rules of src/signalbox/rules/wan.py; part of the rules documentation (docs/RULES.md lists all) -->

# Internet connection (WAN)

These rules read the internet connections (uplinks) a gateway reports. They only look at
uplinks that were reported: a gateway whose integration does not read uplinks is not checked.
An uplink reported as down is ignored by the rules other than `wan.down` (its addresses may be
stale). Double NAT (a router behind another router) is `addr.double-nat`.

## `wan.cgnat`

- **Severity:** info
- **Checks:** an uplink whose IPv4 address is in the carrier-grade NAT range 100.64.0.0/10, or
  a DS-Lite uplink (IPv4 only through the provider's NAT). Port forwards, a VPN server at home
  and other connections from the internet over IPv4 cannot work.
- **Stays quiet** when another connected uplink of the site has a public IPv4 (a backup line on
  LTE behind CGNAT is normal), when a known router of the site uses the 100.64.0.0/10 address
  (double NAT), for MAP-E (part of the ports can be forwarded) and for an uplink with IPv6 only.
- **Fix:** with IPv6 on the line, reach the devices at home over IPv6; otherwise ask the
  provider for a public IPv4 address, or use a VPN or tunnel service that connects outwards.

## `wan.down`

- **Severity:** warning; info when another uplink of the same gateway is up (the finding names
  it)
- **Checks:** an uplink the gateway reports as not connected (no address, no PPP session).
- **Stays quiet** when the gateway does not say whether the uplink is connected.
- **Fix:** check the cable and the modem, the account details of a PPPoE login, and whether
  the provider reports an outage. Turn the rule off for a standby line that is down by design.

## `wan.dns-mismatch`

- **Severity:** info
- **Checks:** the DNS service of the gateway forwards to an address on the network of its own
  uplink (the provider's or the modem's side), which is not one of the DNS servers the provider
  hands out on that uplink, not the upstream gateway, and not used by any device, DNS service
  or client Signalbox knows. Typical after a modem or provider change: the old address was
  typed in and answers slowly or not at all.
- **Stays quiet** when the uplink reported no DNS servers, and for forwarders anywhere else:
  forwarding to a public resolver, a Pi-hole or a filter instead of the provider's DNS is a
  choice, not a mistake.
- **Fix:** forward to the DNS servers the provider hands out (named in the finding), or to a
  resolver you chose.

## `wan.no-ipv6`

- **Severity:** info
- **Checks:** a connected uplink has an IPv6 prefix delegated by the provider, but no network
  of the site with clients (an enabled SSID or a client seen on it) has a global IPv6 router
  subnet, nor any router subnet from the delegated prefix. `ipv6.partial` reports a site where
  only some networks have IPv6.
- **Stays quiet** when no network with clients is known at the site.
- **Incomplete:** the gateway reported no IPv6 subnet at all (not even a link-local or unique
  local one), so its integration may not read IPv6 on its networks.
- **Fix:** give each client network a /64 from the delegated prefix (with router
  advertisements), or turn the rule off if IPv6 stays off on purpose.
