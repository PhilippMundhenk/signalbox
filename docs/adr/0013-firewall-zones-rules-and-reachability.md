# 0013. Firewall: zones, ordered rules, policies, NAT and a conservative reachability answer

Date: 2026-11-23 · Status: accepted

## Context

Several checks need to know whether traffic from one network reaches an address and port in
another: management reachable from guest or IoT networks (#120), from the internet (#123),
port forwards to dynamic addresses (#125), double NAT (#60). Without firewall data
`security.wan-management` and `security.service-exposure` could only say "not checked" for every
router. The real setups differ a lot: OpenWrt has zones with forwardings and policies; OPNsense
has per-interface pf rules (first match with `quick`), floating and group rules, aliases and an
implicit "block in"; MikroTik has ordered chains with interface lists and accepts by default;
a Linux gateway has whatever nftables (or iptables, firewalld, Docker) put there; a Fritz!Box
has no readable filter at all, only fixed behaviour and port sharing. A site often has two
routers in a row (an OPNsense behind a Fritz!Box) and site-to-site tunnels.

Emulating each vendor exactly is not possible and not needed: the checks need "allowed",
"denied" or "I cannot tell", and a wrong "allowed" or "denied" is worse than "I cannot tell".

## Decision

- **One `Firewall` per device** (`<device>/firewall`), read with a new capability `firewall`
  (**adapter API 1.4**). A device without one is "not read"; a device that filters nothing has
  one with `enabled = False`.
- **Zones are the vocabulary of the rules.** A `FirewallZone` is the vendor's group of
  interfaces (OpenWrt zone, OPNsense interface or group, MikroTik interface list or a single
  interface, nftables `iifname` set, Fritz!Box network) mapped by the adapter to segments,
  uplinks, tunnels and bare ports. A zone with interfaces the adapter could not map is
  `complete = False`.
- **Defaults per zone pair**: `ZonePolicy(source, destination | None, action)`, where `None` is
  the device itself (input), plus `input_policy` and `forward_policy` as fallbacks. OpenWrt
  forwardings and zone policies, OPNsense's "block in, pass out", RouterOS' chain default
  `accept` and the Fritz!Box's fixed guest isolation all fit.
- **Rules are ordered, first match wins** (`Firewall.rules` in evaluation order; `order` only
  for display). The adapter flattens what it can: OPNsense floating, group and interface rules,
  nftables jumps to plain chains, MikroTik jumps. A rule has a chain (input, forward, output or
  both), family, protocols, source and destination (zones, networks, ports, each optionally
  negated), action (accept, drop, reject), whether it applies to port-forwarded connections
  only (MikroTik `connection-nat-state=dstnat`) and `exact`: `False` when the device's rule
  has conditions the model does not express (schedules, GeoIP, marks, limits, an alias or chain
  the adapter could not resolve). Rules that only match established/related or invalid
  connections are left out: the model is stateful, only new connections are evaluated.
- **NAT**: `NatRule` for source NAT (masquerade or a fixed address, per outgoing zone;
  OpenWrt's zone `masq` is a zone attribute), `PortForward` for destination NAT (protocols,
  listening zones, external address and ports, allowed sources, target address and port,
  whether it passes the filter by itself, NAT reflection, `exact`). An exposed host is a
  forward without external ports.
- **Evaluation is three-valued and conservative** (`Firewall.evaluate`, `signalbox.firewall`):
  each rule matches `yes`, `no` or `maybe`; a `maybe` adds its action to the possible outcomes
  and evaluation goes on; the first `yes` ends it, else the zone pair policies (every pair of
  a source and a destination zone), else the fallback. One possible outcome is the answer;
  several, a missing policy, `rules_complete = False` or a source zone that is not known give
  `unknown`.
- **Paths are short.** `reach(net, source, address, port, protocol)` answers for a segment,
  uplink or tunnel as source: the target's own input chain when it has an address towards the
  source; otherwise the one router that is in both networks (forward chain), then the target's
  own firewall where read. From the internet, a private IPv4 address is only reached through a
  port forward; the router in front (double NAT, `Network.upstream_router`) is followed when
  it is known (unknown when its firewall is not read). A switch or access point without a read
  firewall is assumed not to filter; a gateway without one is `unknown`. No routing tables, no
  path through two routers inside the site.
- The management checks use the helper: `security.wan-management` and
  `security.service-exposure` are quiet where the firewall blocks, report an error where it
  lets traffic in, and say "not checked" only where it cannot decide.

## Consequences

- Every integration fills the same objects; ADAPTERS.md lists the sources and privileges per
  vendor. What a vendor can do beyond the model makes a rule inexact or the firewall
  incomplete, which shows up as "not checked", never as a false "allowed" or "denied".
- The checks that were blocked by #135 (#120 level 2, #125, #60, "guest reaches the LAN",
  "new segment without a zone", duplicate forwards) build on `reach`, `service_reach`,
  `Firewall.policy` and the port forwards; they are not part of this decision.
- Desired state and writes (declare per segment what it may reach, plan zone and rule changes,
  OpenWrt first so that its router writes can follow, #41) use the same objects later.
- A wrong guess in an adapter (a vendor default not modelled, an alias resolved wrongly) gives a
  wrong answer; integration tests against the real systems in CI and `exact = False` where in
  doubt are the safeguards.
