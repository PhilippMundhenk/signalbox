<!-- rules of src/signalbox/rules/routing_checks.py; part of the rules documentation (docs/RULES.md lists all) -->

# Routing

These rules read the routing tables and policy rules that integrations report
([ADR 0024](../adr/0024-routing-tables-and-policy-routing.md)) and answer with
`signalbox.routing.next_hop`. Connected networks come from the subnets, so a device only has
routes here when its integration reads them (OpenWrt, OPNsense, MikroTik, Linux, FRITZ!Box).
A device whose routes were not read is never reported: that is "not known". Policy rules that
match on a source make the answer uncertain and the rules stay quiet.

## `route.default-missing`

- **Severity:** warning
- **Checks:** a router whose routes were read and that has no enabled IPv4 default route in the
  main table.
- **Stays quiet** for a device that is not a gateway, a gateway whose routes were not read,
  a device that was not read completely, and a router whose internet connections are all down.
- **Fix:** check the internet connection and the gateway setting; with several connections,
  make one the default.

## `route.multiple-default`

- **Severity:** info
- **Checks:** two or more enabled default routes of one family and table with the same metric
  and different next hops or interfaces.
- **Stays quiet** when a metric is not reported (OpenWrt does not always list it), when the
  metrics differ, and for routes that are disabled or not installed.
- **Fix:** give the connection that should win the lower metric.

## `route.unreachable-gateway`

- **Severity:** warning
- **Checks:** an enabled static route whose next hop is in none of the device's own networks
  (subnets, internet connection addresses, tunnel addresses).
- **Stays quiet** for link-local next hops, routes of other origins (DHCP, routing protocols)
  and devices whose own networks are not known.
- **Fix:** correct the next hop, or give the router an address in the next hop's network.

## `route.no-return`

- **Severity:** warning
- **Checks:** a static route sends a network to another router of the network (the next hop
  is its address), and that router has no route back to one of the networks behind the first
  router: no route at all, a blackhole, or only a default route towards a device Signalbox does
  not know (the provider).
- **Stays quiet** when the second router's routes were not read, when it masquerades traffic
  towards the destination (the answers then go to it itself), when a policy rule makes the
  answer uncertain, and for the network of the transit link.
- **Fix:** add a route on the second router for the network through the first, or make the
  first its default gateway.

## `route.asymmetric`

- **Severity:** info
- **Checks:** the same setup as `route.no-return`, but the second router answers through a
  third known router instead of the first: the path there and back differ.
- **Fix:** route the network on the second router through the first, or make the third the
  next hop of the first too.

## `route.vpn-return`

- **Severity:** warning
- **Checks:** a site-to-site WireGuard tunnel whose other end is also read, where the other
  end's peer entry for this tunnel accepts none of this site's networks (only the tunnel
  address). The other `vpn.*` rules ([VPN tunnels](vpn.md)) cover a missing peer, networks that
  do not exist at the other end and a missing route into the tunnel; this one covers the way
  back.
- **Stays quiet** when the other end is not read, when it does not list this tunnel (that is
  `vpn.ends-disagree`), for disabled peers and tunnels that are down.
- **Fix:** add the networks of this site to the allowed IPs of the peer on the other end, and
  a route for them through the tunnel.
