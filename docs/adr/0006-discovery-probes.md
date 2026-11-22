# 0006. Device discovery: user-started, unauthenticated probes owned by the integrations

Date: 2026-11-22 · Status: accepted

## Context

Every device was added by hand: choose the integration, type the address, the port and the
login (#203). Most of that Signalbox could find itself: the routers already added report their
subnets, clients, DHCP leases and LLDP neighbours, and every supported device answers some
request without credentials (the Fritz!Box TR-064 description, OpenWrt's ubus, the OPNsense
login page, RouterOS's REST realm, the Omada controller's `/api/info`, the switches' discovery
broadcast). Until now Signalbox only ever talked to devices the user had added; finding devices
means sending requests to addresses nobody configured, which on someone's network is a
different kind of action: it can trip intrusion detection, wake devices, and it reveals that
Signalbox is there.

## Decision

- **Only when the user asks.** Discovery runs when the user presses *Find devices*
  (`POST /api/discovery`), never in the background or on a schedule; `discovery.enabled: false`
  turns it off completely. The page shows what will be and was searched.
- **Only known networks, or what the user typed.** Gateway subnets of added routers of /24 or
  smaller (`discovery.sweep_prefix`) completely; of larger ones and IPv6 only the gateway, plus
  the IPv4 addresses of clients, DHCP reservations and LLDP neighbours; plus addresses, networks
  and ranges the user enters. At most `discovery.max_hosts` addresses per run. The broadcast of
  the switch protocols stays in Signalbox's own layer-2 network.
- **Unauthenticated, read-only, bounded.** Probes send only requests that need no login, with
  short timeouts (`discovery.timeout_seconds`), at most `discovery.rate_per_second` requests and
  `discovery.concurrency` addresses at a time, read at most 256 KiB of an answer and follow no
  redirects. An address that does not answer on two ports is given up.
- **TLS on probes is not verified and nothing is pinned.** Pinning is trust the user gives a
  device (trust on first use, [https.py](../../src/signalbox/adapters/https.py)); a probe has not
  been given it and sends nothing that would need it. When the user adds a found device, the
  normal flow runs: certificate shown, confirmed, pinned, then the first credential sent.
- **A probe answer is only a suggestion.** Text from devices (model, name, firmware) is cleaned
  (no control or bidirectional characters, length bounded) and shown only as text. It prefills
  the device form (integration, role, address, name); nothing is stored but the user's
  *Ignore* list (integration and address). XML answers go through the same parser that
  refuses DTDs and entities as the Fritz!Box integration.
- **Integrations own their probes.** Two optional class methods on `Adapter`:
  `discover(probe: HostProbe) -> Candidate | None` per address and
  `discover_broadcast(probe: NetworkProbe) -> BroadcastResult | None` once per run. They must
  send through the given probe object, which enforces the rules above. The hooks are optional
  and have defaults, so the adapter API version stays 1.2 and every existing adapter, including
  out-of-process ones, keeps working (it simply finds nothing).
- **One run at a time, in memory.** Progress and candidates of the last run are kept in memory;
  candidates already added (same integration and host as a device's settings or management
  address) are marked.

## Consequences

- Adding a device is: *Find devices*, *Add*, enter the login, *Test connection*.
- Third-party integrations can join discovery by implementing a hook, without a new API version.
- What each probe sends is documented ([DISCOVERY.md](../DISCOVERY.md)); a probe that needs
  more than an unauthenticated request does not belong in discovery.
- No passive discovery (SSDP/UPnP, mDNS) for now: it would need a listener running in the
  background, which this decision rules out; it can be added later as another user-started
  source.
- The probes' signatures are taken from the vendors' documentation and the simulators; they
  still need confirming on real devices (#21).
