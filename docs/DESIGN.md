# Signalbox design

This is the starting design. Nothing here is final; decisions are recorded as they are made.

## Goal

A self-hosted controller for small office and home networks that:

1. **reads** every network device through an adapter into one vendor-neutral model,
2. **checks** the network for inconsistencies and explains each finding,
3. **shows** the topology: devices, ports, cables, VLANs and where clients are,
4. **configures** devices from one desired state, with a plan, review and rollback.

Reading and checking come first. "Tell me what is wrong with my network" is useful long before
"configure my network", and it is safe.

## Three layers

- **Observed state**: what the adapters read from the devices, normalised into the model.
  Read-only, always safe.
- **Desired state**: what the network should look like, stored as YAML files that can live in
  git (reviewable, diffable, revertible). The UI edits the same files.
- **Rules**: checks over the observed state, the desired state, or the difference between them.
  Each finding has a reason, the affected objects and a suggested fix.

## Data model

Typed models (Pydantic v2), with an exported JSON Schema as the published contract. Every object
carries its source (adapter and device), the time it was observed and a stable id.

| Object | Contents |
| --- | --- |
| Site | One network domain; a second location over a VPN is a second site |
| Device | Vendor, model, firmware, role (`gateway`, `switch`, `ap`, `other`), management address, adapter, capabilities |
| Port | Physical or logical port, link state, speed, PoE, LAG membership, neighbour (LLDP where available) |
| Link | A cable or wireless uplink between two ports; observed (LLDP, MAC tables) or entered by hand |
| Segment | Layer-2 network: VLAN id, name, purpose; membership per port `untagged` / `tagged` / `none` |
| Subnet | Prefix, gateway address, segment, IPv4/IPv6 |
| DhcpServer | Device, segment, enabled, pool, lease time, options, static reservations |
| DnsService | Resolver, host overrides, forwarders, split-DNS domains |
| Wlan | SSID, security (WPA2/WPA3, PMF), passphrase reference, segment, bands, hidden, roaming (802.11r/k/v) |
| Radio | Band, channel, width, transmit power, country code |
| Firewall | Zones, rules, NAT; read-only at first |
| Client | MAC, IP, hostname, segment, where it was seen (port or access point), last seen |
| Firmware | Current, available, end of life |

Rules for the model:

- No untyped dictionaries across the adapter boundary. Vendor fields the model does not cover go
  into an explicit `vendor_extra` that core logic never reads.
- A field is optional because a device cannot report it (declared as a capability), never by
  accident.

## Topology

The topology view is built from `Port` and `Link` objects:

- physical wiring: which port is connected to which, cable or wireless uplink,
- VLAN view: per link, which segments are tagged or untagged,
- clients placed on the port or access point where they were last seen.

Links that cannot be discovered (unmanaged switches, devices without LLDP) can be entered by hand
and are marked as such. A link seen by discovery but missing from the desired state, or the other
way round, is a finding.

## Consistency rules

Rules are small, pure functions over the model, each with an id, severity, explanation and an
optional fix. A first set:

- **DHCP**: exactly one enabled DHCP server per segment; pools do not overlap static reservations
  or gateway addresses; router and DNS options point at the actual gateway and resolver.
- **Addressing**: no overlapping subnets across segments and sites; no duplicate IP addresses.
- **Wireless**: an SSID has the same security, passphrase, segment and roaming settings on every
  access point; country code set; no overlapping channels between neighbouring access points.
- **VLANs**: every segment used on an access point or access port is tagged on every link on the
  path to the gateway; native VLAN the same on both ends of a link; no segment defined on the
  gateway that nothing can reach.
- **DNS**: host overrides match the DHCP reservations.
- **Hygiene**: firmware drift between identical devices, outdated firmware, management interfaces
  reachable from guest or IoT segments, TLS certificates close to expiry.
- **Drift**: observed state differs from desired state, field by field.

A check that cannot run (missing capability, device unreachable) is itself a visible finding,
never a silent skip.

## Adapters (plugins)

- One Python package per adapter, discovered through entry points, with a manifest: id, name,
  version, supported API version, vendor, device roles, capabilities, configuration schema.
  Adapters can live in separate repositories.
- Capabilities are typed protocols (`ReadsWlans`, `ReadsDhcp`, `WritesSegments`, …). Calling a
  capability an adapter does not implement is an error, never a silent fallback.
- A declarative configuration schema (host, credentials, TLS fingerprint) lets the UI render and
  validate the setup form.
- `observe() -> Snapshot` is the only required method. Writing is an optional capability.
- Writes are typed change sets (`SetWlan`, `AddSegmentToPort`, …). The adapter first returns the
  vendor calls it would make, so dry runs and review are possible.
- Optionally out of process (subprocess or container, small JSON-RPC protocol), so a third-party
  adapter only ever sees its own credentials.
- A shared contract test suite every adapter must pass, against a device simulator or recorded,
  sanitised fixtures committed to the adapter's repository.
- Rules and exporters (Home Assistant via MQTT, Prometheus metrics) use the same packaging.

Planned adapters: OPNsense (REST API), OpenWrt (ubus/rpcd or SSH and UCI), NETGEAR ProSAFE Plus
switches (NSDP, building on [Switchyard](https://github.com/PhilippMundhenk/switchyard)),
AVM Fritz!Box (TR-064). Later: UniFi, Omada, MikroTik, pfSense.

## Changing configuration

Plan → review → apply → verify → keep or roll back:

1. Edit the desired state (UI or YAML).
2. **Plan**: diff desired against observed per device, ordered by dependency (gateway VLAN and
   subnet before trunks before access point SSIDs), and run the rules on the resulting state
   before anything is touched.
3. **Review**: a person approves, seeing the exact vendor calls. Read-only by default; writing is
   enabled per site and per adapter.
4. **Apply**, with a per-device backup first (for example OPNsense `config.xml`, OpenWrt UCI
   export).
5. **Verify** by observing again and re-running the rules; roll back automatically if a device
   becomes unreachable (confirm-or-revert timer).
6. An audit log records who changed what and why.

## User interface

- **Findings first**: the start page lists the findings, each with its reason, the affected
  devices and a fix.
- **One view per concept, not per vendor**: Segments, Wireless, DHCP & DNS, Devices, Clients,
  Topology. Vendor details only on a device's advanced tab.
- Few concepts for a newcomer: site, device, segment, rule.
- Works on a phone.

## Quality and operations

- Small codebase; one container; SQLite by default; amd64 and arm64 images.
- Typed throughout (strict type checking), ruff, 95 % line coverage, end-to-end tests of working
  and refused paths against simulators.
- Fail loudly: no magic fallbacks, every skipped check visible.
- Credentials encrypted with a key kept outside the database; least-privilege API users per
  device; TLS verification on, with trust-on-first-use pinning for self-signed devices.
- Read-only by default; meant to run behind a reverse proxy with authentication.
- Maturity per adapter and capability is generated from contract test results, not maintained
  by hand.
- Semver releases, changelog, published container images.

## Phases

1. **Observe and check** (read-only): OPNsense and OpenWrt adapters, the model, the rule engine
   with DHCP, Wi-Fi and VLAN rules, findings UI, Home Assistant export.
2. ProSAFE Plus switches, topology view with wiring and VLANs, firmware hygiene, desired state
   with drift.
3. **Writes** for Wi-Fi and VLANs on OpenWrt and OPNsense, with plan, review, backup, verify and
   rollback. Fritz!Box adapter.
4. More adapters, out-of-process adapter runtime, rule plugins.

## Open questions

- Python (fits the existing libraries, such as `fritzconnection`, and Switchyard) or Go (single
  static binary)?
- How much of the desired state lives in git files and how much in the database?
- A separate app with a Home Assistant integration, or a Home Assistant add-on?
- Can an existing project (OpenWISP, NetBox) serve as a base or a data source?
