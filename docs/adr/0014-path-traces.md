# 0014. Path traces: traceroutes run on the devices, an optional active observation

Date: 2026-11-23 · Status: accepted

## Context

The model knows what each device says about itself: its subnets, its uplink addresses, its
tunnels. From that, Signalbox guesses the routed topology: an uplink address in another
gateway's network means "behind that one" (`Network.upstream_router`), two tunnels that name
each other's keys are a site link. What it cannot see is the path packets really take: a box of
the provider in router mode in front of the firewall, traffic to the other site that leaves
through the provider instead of the tunnel, an upstream that is not what the uplink suggests.
Philipp's idea (#253): let the routers Signalbox reads run traceroutes to each other and to the
internet. That is an *active* observation (#184): Signalbox makes the devices send packets,
which reading never does, and some devices need an extra permission for it.

## Decision

- **Fully optional.** `traces.enabled: false` by default. While it is off nothing is traced,
  `POST /api/traces` answers 403 `disabled`, stored traces are not put on the network, the
  automatic setup and *Fix it* add no permission for it, and the topology page only says what
  the feature would do. Traces run when the user presses *Trace now* on the topology page, or
  every `traces.interval_hours` (0, the default: never on its own).
- **A trace is an optional hook of an integration**, like the setup (no adapter API version):
  `Manifest.traces` (`TraceSupport`: the permission it needs, in plain words) and
  `Adapter.trace(target, max_hops, wait) -> TraceAnswer` (raw hops: TTL, address, RTT; whether
  the target answered). One probe per hop, numeric output, nothing but the trace. Built in:
  - OPNsense: `POST /api/diagnostics/traceroute/set` (configd `interface traceroute`, ICMP),
    privilege *Diagnostics: Traceroute* (`page-diagnostics-traceroute`).
  - MikroTik: `POST /rest/tool/traceroute` (`count=1`, `use-dns=no`), group policy `test`.
  - Linux gateway: `tracepath -n` (else `traceroute -n`) over the existing SSH read user; both
    use unprivileged UDP, so no sudo rule and no root.
  - Not supported: OpenWrt (rpcd has no traceroute method; LuCI's diagnostics run
    `/usr/bin/traceroute` through `file exec`, an exec right Signalbox does not ask for),
    Fritz!Box, Omada, the switches. They are still *targets*.
- **Signalbox's own host traces without root**: a few lines of Python do what `tracepath`
  does, a UDP socket per hop with the TTL set and `IP_RECVERR`, reading the ICMP error from the
  socket's error queue (`signalbox.tracehost`). No raw socket, no `CAP_NET_RAW`, no package in
  the image; Linux only. `traces.from_signalbox: false` leaves the host out.
- **Stored apart from the snapshots.** `PathTrace` (`trace/<source>/<target>`: source device
  or `signalbox`, target, purpose `gateway`/`internet`/`address`, hops, reached, error with fix
  and remedy) in a table of its own (store schema 5), the latest per pair, pruned after
  `history.days`. A device's traces go with the device. The runner puts them on
  `Network.traces` while the feature is on, hops matched against *that* network
  (`signalbox.traces.attach`: a hop is a known device by a subnet, uplink or tunnel address or
  its management address). Matching is core's job, never an integration's.
- **What a run traces.** By default every gateway that can trace and Signalbox's host, to
  every other gateway (its uplink address in the source's network when the source is in front
  of it, else its LAN address) and to `traces.internet_target` (1.1.1.1; empty: none); or only
  from one source, or only to one device or IP address (no host names). Rate limited: one run
  at a time, `traces.concurrency` traces at once, `traces.max_pairs` per run, *Trace now* not
  again within `traces.min_gap_seconds`, `traces.wait_seconds` per hop and
  `traces.timeout_seconds` per trace. Every failure becomes the trace's error, never the run's.
- **Derived routed view.** Per trace the hops with the known device, the tunnel a hop lies in
  and its kind (private, provider NAT, public); "B is in front of A" from consecutive known
  routers on traces to the internet, and an unknown router with a private address right after
  the last known one. The topology page shows them as *Routed paths*; links of the wiring
  view stay as they are (layer 2 is LLDP, MAC tables and cables).
- **Conservative checks**, info only, on complete traces only (target reached, every hop
  answered): `trace.not-via-tunnel` (a tunnel routes the target's network, but the first hop is
  elsewhere), `trace.extra-nat` (more routers with private addresses on the way out than the
  known uplinks predict).

## Consequences

- One click shows double NAT and the real path between sites, from what the routers see.
- The permissions are documented per integration (docs/TRACES.md); the automatic setup and
  *Fix it* (OPNsense `privileges`, MikroTik `policies`) grant them only while the feature is
  on. A refused trace names the permission and the remedy.
- Traceroutes reveal provider routers and the public path: like uplink addresses they are shown
  in the UI and never exported (no MQTT entity).
- Further integrations add a trace by implementing the hook; OpenWrt could if rpcd ever gets a
  traceroute method that needs no exec right.
- Verified in CI against the real software: OPNsense 26.7 (refused for the read user, then run
  with the privilege), RouterOS CHR (refused without `test`, then run), Debian with
  `iputils-tracepath`; output of hops beyond the CI network (provider routers) is covered by
  the simulators only (#21).
