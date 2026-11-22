# Signalbox design

This is the design. Decisions are recorded in [adr/](adr/) as they are made; the status of each
component links to its issue.

## Goal

A self-hosted controller for small office and home networks that:

1. **reads** every network device through an adapter into one vendor-neutral model,
2. **checks** the network for inconsistencies and explains each finding,
3. **shows** the topology: devices, ports, cables, VLANs and where clients are,
4. **configures** devices from one desired state, with a plan, review and rollback.

Reading and checking come first. "Tell me what is wrong with my network" is useful long before
"configure my network", and it is safe.

## Components

Signalbox is built from separate components with narrow contracts. Data flows in one direction:
devices → integrations → model → checks / topology → people, and for changes
desired state → planner → deployment → devices, with every step tracked.

```
              read                                                    write (phase 3)
 devices ──────────────▶ integrations ──▶ network model ◀── desired state ──▶ planner
 (OPNsense, OpenWrt,     (adapters,       (observed)          (YAML intent)     │ change set,
  ProSAFE, Fritz!Box,     one per kind)        │                                │ predicted state
  MikroTik, TP-Link)                           ▼                                ▼
       ▲                              checks (rules), topology          review & approval
       │                                       │                                │
       │                                       ▼                                ▼
       └────────── transactional deployment ◀──────────────────────────────── plan
                   (lock, backup, apply, verify, commit or roll back)
                                │
                                ▼
                   change tracking (change log, audit) ──▶ rollback (revert, restore)
```

| Component | Code | Job | In | Out | Status |
| --- | --- | --- | --- | --- | --- |
| **Network model** | `signalbox.model`, `signalbox.merge` | the one vendor-neutral language every other component speaks | – | typed objects, JSON Schema ([schema.json](schema.json)) | done (#3) |
| **Integrations** (adapters) | `signalbox.adapters.<id>` | map one kind of device to the model and back; nothing vendor-specific leaves an adapter | device API | `Snapshot` (read); vendor calls for a change set (write) | read: OPNsense (#9), OpenWrt (#10), Fritz!Box (#24), Omada (#44), ProSAFE Plus and Easy Smart switches through Switchyard (#22, #44, [ADR 0003](adr/0003-switchyard-library.md)); MikroTik (#43); write: OpenWrt (#41), OPNsense (#42) |
| **Adapter API** | `signalbox.adapters` | the contract integrations implement: manifest, capabilities, errors, contract tests | – | – | done (#4) |
| **Inventory** | `signalbox.store`, `signalbox.config`, `signalbox.secrets` | sites, devices, cables, credentials (encrypted), certificate pins | UI/API | records | done (#11) |
| **Observation** | `signalbox.runner` | read every device on an interval, merge into one network | inventory, integrations | `Network`, findings history | done (#12) |
| **History** | `signalbox.sightings`, `signalbox.store` | after every round: first/last seen of devices, clients (per network) and ports, device status, link state, client network; changes as events; pruned after `history.days` | `Network` per round | read-only `History` for rules (`history_rule`), first/last seen in API and UI | done (#185) |
| **Checks** (rules) | `signalbox.rules.*` | find inconsistencies, explain them, suggest a fix; never change anything | `Network` (and `History`) | findings | done (#5–#8, #15) |
| **Topology** | `signalbox.topology` | links from LLDP, MAC tables and entered cables; the wiring and VLAN view | `Network` | links, topology view | done (#15) |
| **Desired state** | `signalbox.desired` | what the network should look like; drift against the observed state | YAML, UI | desired model, drift findings | done (#36), [DESIRED.md](DESIRED.md) |
| **Planner** | `signalbox.changes` | desired minus observed → typed change set per device, ordered; checks run on the predicted state | desired + observed state | plan | done (#37) |
| **Deployment** | `signalbox.deploy` | apply an approved plan as one transaction across devices | plan, approval | per-device result | done (#38), [CHANGES.md](CHANGES.md) |
| **Change tracking** | `signalbox.history` | immutable record of every change: who, why, plan, vendor calls, backups, results | deployments | change log, audit | done (#39) |
| **Rollback** | `signalbox.deploy`, `signalbox.history` | automatic inside a deployment; revert of a recorded change; restore of a backup | change log | new tracked deployment | done (#40) |
| **Interfaces** | `signalbox.web`, `signalbox.mqtt` | web UI and API, Home Assistant export | everything above | – | API #13, UI #14, MQTT #16 |

Rules for the boundaries:

- Only integrations know vendors. The model, checks, planner, deployment and UI never branch on
  a vendor; vendor details reach the UI only through `vendor_extra` on a device's advanced tab.
- Checks are pure functions of the model. They run the same way on the observed state, the
  desired state and the predicted state of a plan. A check that needs the past also gets the
  read-only history (`rule(net, history)`); the desired and predicted states have none, so such
  checks stay silent there.
- Nothing writes to a device except the deployment component, and only with an approved plan.
- Every write is a tracked change that can be rolled back.

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
| Segment | Layer-2 network: VLAN id, name, purpose and its source, isolated by the device; membership per port `untagged` / `tagged` / `none` |
| Subnet | Prefix, gateway address, segment, IPv4/IPv6 |
| DhcpServer | Device, segment, enabled, pool, lease time, options, static reservations |
| DnsService | Resolver, host overrides, forwarders, split-DNS domains |
| Wlan | SSID, security (WPA2/WPA3, PMF), passphrase reference, segment, bands, hidden, roaming (802.11r/k/v), purpose and its source, client isolation |
| Radio | Band, channel, width, transmit power, country code |
| Firewall | Zones, rules, NAT; read-only at first |
| Client | MAC, IP, hostname, segment, where it was seen (port or access point), last seen |
| Firmware | Current, available, end of life |

Rules for the model:

- No untyped dictionaries across the adapter boundary. Vendor fields the model does not cover go
  into an explicit `vendor_extra` that core logic never reads.
- A field is optional because a device cannot report it (declared as a capability), never by
  accident.

Network purpose (`main`, `guest`, `iot`, `management`, `servers`, `lab`, `voice`, `cameras`,
`transit`, `other`) on segments and SSIDs carries `purpose_source`: `reported` (set by the
adapter: Fritz!Box guest network, Omada guest SSID), `declared` (desired state) or `heuristic`
(guessed from the name by the merge: words starting with guest, gast or visitor; the word iot).
Declared beats reported beats heuristic. The merge sets reported purposes (the first device that
reports one for a segment wins) and fills the rest with guesses; the runner then applies the
declared purposes from the desired state to every network it builds (`Runner.network()`, so
checks, views and plans see the same), keeping a different reported value in
`reported_purpose` for the drift rules. `Segment.isolated` means the device keeps that network
apart by itself (the Fritz!Box guest network); `Wlan.client_isolation` that stations of an SSID
cannot reach each other (OpenWrt `isolate`). Both are None when not known.

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
- Optionally out of process (a separate program, one line of JSON each way), so a third-party
  adapter only ever sees its own credentials ([PLUGINS.md](PLUGINS.md)).
- A shared contract test suite every adapter must pass, against a device simulator or recorded,
  sanitised fixtures committed to the adapter's repository.
- Rules and exporters (Home Assistant via MQTT, Prometheus metrics) use the same packaging.

Planned adapters: OPNsense (REST API), OpenWrt (ubus/rpcd or SSH and UCI), NETGEAR ProSAFE Plus
switches (NSDP, building on [Switchyard](https://github.com/PhilippMundhenk/switchyard)),
AVM Fritz!Box (TR-064), MikroTik (RouterOS REST API, #43), TP-Link (Omada controller and Easy
Smart switches, #44). Later: UniFi, pfSense.

## Changing configuration

Phase 3. Components: planner (#37), deployment (#38), change tracking (#39), rollback (#40),
write capabilities of the integrations (#41, #42). Writes are off by default and enabled per site
and per adapter; every deployment is approved by a person.

### Plan

1. Edit the desired state (UI or YAML, #36).
2. The planner computes a **change set**: typed, vendor-neutral operations (`CreateSegment`,
   `SetPortMembership`, `SetWlan`, `SetDhcpPool`, ...), each with the old and the new value.
3. The change set is split per device and **ordered by dependency**: gateway VLAN and subnet
   before trunks before access ports and SSIDs; deletions in reverse order. No step may cut off
   the path to a later device or to Signalbox itself.
4. The checks run on the **predicted state** (observed state with the change set applied). A plan
   that would create an error finding is refused unless explicitly overridden.
5. Each integration translates its part into the exact vendor calls, shown in the review.

### Deploy (one transaction)

Per device, in plan order:

1. **Lock** the device and observe it again; if it changed since the plan was made, stop.
2. **Backup**: full configuration export, stored with the change record.
3. **Stage and apply** with the device's own transaction mechanism where it has one (OpenWrt: UCI
   staging and `apply` with a rollback timer; OPNsense: module apply, revert to the saved
   configuration revision on failure).
4. **Verify**: observe again, compare every changed field, check reachability, run the checks.
5. **Commit** (confirm the timer) or **roll back** this device.

Across devices: if a device fails, the devices already changed in this deployment are rolled
back in reverse order, so the network ends where it started. The result states per device what
happened; a partial success is never silent.

### Track

Every deployment is an immutable change record: who, when, why, the desired-state version, the
plan, the vendor calls, the backups, the per-device results, the observed state before and after.
Findings link to the change after which they first appeared.

### Roll back

- **Automatic**, inside a deployment (above).
- **Revert a change**: the inverse change set of a recorded change becomes a new plan, is
  checked on its predicted state and deployed as a new, tracked transaction.
- **Restore a backup**: last resort per device, with a warning that later changes are lost.

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

1. **Observe and check** (read-only): model, integrations for OPNsense and OpenWrt, inventory,
   observation, checks (DHCP, addressing, Wi-Fi, VLANs, topology), topology view, web UI, Home
   Assistant export. Issues #1–#20.
2. **Desired state**: ProSAFE Plus switches (#22), desired state and drift (#36), firmware
   hygiene.
3. **Changes**: planner (#37), transactional deployment (#38), change tracking (#39), rollback
   (#40), write capabilities for OpenWrt (#41) and OPNsense (#42), Fritz!Box (#24). Overview #23.
4. **More integrations**: MikroTik (#43), TP-Link Omada and Easy Smart (#44), UniFi, pfSense;
   out-of-process adapters, rule plugins. Overview #25.

## Open questions

Decided: Python ([ADR 0001](adr/0001-python-fastapi-pydantic.md)); components and the change
transaction ([ADR 0002](adr/0002-components-and-change-transactions.md)).

- How much of the desired state lives in git files and how much in the database?
- A separate app with a Home Assistant integration, or a Home Assistant add-on?
- Can an existing project (OpenWISP, NetBox) serve as a base or a data source?
