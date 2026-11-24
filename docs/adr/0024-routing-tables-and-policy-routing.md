# 0024. Routing tables: connected routes are derived, `next_hop` answers, policy routing is followed only as far as it is known

Date: 2026-11-24 · Status: accepted

## Context

#149 asks for the routing table of every router (static, default, VPN, dynamic) and policy
routing, so rules and the reachability helper (#135) stop guessing which router carries traffic
between two networks. Open questions in the issue: report connected routes at all, and how to
show OPNsense gateway-based policy routing before the firewall rules carry a gateway.

## Decision

- **Connected routes are always derived** from `Subnet`, the addresses of the device's uplinks
  and of its tunnels (`routing.connected_networks`). Adapters do not report them, even when the
  device lists them (`proto kernel`, MikroTik `connect`): two sources for one fact would
  disagree. `Route.origin` still has `connected` for plugins.
- **Two objects**, `Route` (`<device>/route/<hash of table, destination, gateway, interface,
  kind>`, no metric in the id so a changed metric is the same route) and `RoutingRule`, in
  `Snapshot` and `Network`. A rule's match fields are `src` and `dst` (`source` is taken by
  `Observed`). Read with `interfaces`, no capability and no API version. An integration that
  cannot read a table reports nothing, never an invented empty table: `has_routes(device)` is
  "was read".
- **`routing.next_hop(network, device, address)`** is pure and conservative: longest prefix
  wins, a connected network beats a route of the same length, then the lower metric; disabled
  routes and routes with `active=False` are ignored; rules that match on the destination only
  are followed in priority order, rules that match on a source or an incoming interface set
  `uncertain` (they depend on who sends). It returns `connected`, `gateway` (with the device
  that owns the gateway address), `interface`, `dropped`, `no-route` or `unknown` (nothing
  read).
- **Reachability** (`firewall.reach`) uses it where it used to guess: among several routers in
  both networks the one whose table keeps the address on its own networks is the path, a
  blackhole is `denied`, and with no common router a chain of two routers is followed.
- **Not read**: OPNsense policy routing (a firewall rule with a gateway; the filter model has
  no gateway yet), IPv6 on FRITZ!Box (TR-064 has none), full OPNsense kernel table
  (`getRoutes` is not used; the default route comes from the WAN uplink). These are documented
  per integration, not reported as gaps on every read.
- **Cap**: `ROUTE_LIMIT` (4096) routes per device are kept.

## Consequences

- Rules `route.*` answer with `next_hop` and stay quiet for a device whose routes were not
  read; `route.no-return` skips a router that masquerades towards the destination.
- A device with a policy rule on a source is answered `uncertain` and the checks skip it.
- Writes (desired state `routes`) are a later step, as the issue says.
