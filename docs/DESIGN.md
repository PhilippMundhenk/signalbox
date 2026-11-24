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
| **Automatic setup** | `signalbox.web.setup_api`, `signalbox.adapters.provision`, `signalbox.adapters.ssh`, `<adapter>.provision` | with the admin login given once: plan, then create the integration's own least-privilege login, save the device with it; the admin login is never kept | device form, admin login | steps, device record | done for OpenWrt, OPNsense, MikroTik (#231), [ADR 0009](adr/0009-automatic-setup-with-an-admin-login.md) |
| **Fix it** | `signalbox.web.fix_api`, `<adapter>.provision` (`REMEDIES`, `*Fix`) | a read gap or error names a remedy of its integration (`remedy=`); on request and after confirmation, with the admin login, only Signalbox's own packages and permissions are repaired, then the device is read again | read errors, admin login | steps, new reading | OpenWrt `access`, `lldp`; OPNsense `privileges` (#215), [ADR 0012](adr/0012-fix-it-for-read-problems.md) |
| **Path traces** | `signalbox.tracer`, `signalbox.traces`, `signalbox.tracehost`, `<adapter>.trace` | off by default; on *Trace now* or a schedule, the routers (OPNsense, MikroTik, Linux) and Signalbox's host trace to each other and to one internet address; hops matched to known devices: the routed path, who is in front of whom, paths through tunnels | inventory, `Network`, integrations' `trace` hook | `PathTrace` (stored apart), routed view, `trace.*` findings | done (#253), [TRACES.md](TRACES.md), [ADR 0014](adr/0014-path-traces.md) |
| **Foreign DHCP servers and routers** | `signalbox.prober`, `signalbox.probehost`, `signalbox.foreign` | servers the devices saw answer (their own DHCP lease, MikroTik's rogue DHCP alert) always; while `probes.enabled` is on (off by default) one DHCPDISCOVER (never a REQUEST) and one router solicitation from Signalbox's host on each of its networks, on *Probe now* or a schedule; each answering server matched to known devices | inventory, `Network`, the host's sockets | `ForeignServer` (probe answers stored apart), `dhcp.foreign-server`, `ra.foreign-router` | done (#184, #61), [PROBES.md](PROBES.md), [ADR 0015](adr/0015-foreign-dhcp-servers-and-routers.md) |
| **Discovery** | `signalbox.discovery` | find devices of the installed integrations when the user asks, without credentials; suggestions for the device form | known networks (`Network`), ranges the user enters, probes of the integrations | candidates | done (#203), [DISCOVERY.md](DISCOVERY.md), [ADR 0006](adr/0006-discovery-probes.md) |
| **Observation** | `signalbox.runner` | read every device on an interval, merge into one network | inventory, integrations | `Network`, findings history | done (#12) |
| **History** | `signalbox.sightings`, `signalbox.store` | after every round: first/last seen of devices, clients (per network) and ports, device status, link state, client network; changes as events; pruned after `history.days` | `Network` per round | read-only `History` for rules (`history_rule`), first/last seen in API and UI | done (#185) |
| **Checks** (rules) | `signalbox.rules.*` | find inconsistencies, explain them, suggest a fix; never change anything | `Network` (and `History`) | findings | done (#5–#8, #15) |
| **Topology** | `signalbox.topology` | links from LLDP, MAC tables (`signalbox.fdb`: uplinks, client placement, links through unread switches, #160) and entered cables; the wiring and VLAN view | `Network` | links, topology view | done (#15) |
| **Desired state** | `signalbox.desired` | what the network should look like; drift against the observed state | YAML, UI | desired model, drift findings | done (#36), [DESIRED.md](DESIRED.md) |
| **Annotations** | `signalbox.annotate`, `signalbox.store` | the user's own layer: labels, purpose, owner, notes, typed expectations, acknowledged findings; never written to devices | desired-state YAML, UI | `Network.annotations`, `Network.acknowledgements`, acknowledged findings | done (#186), [ADR 0007](adr/0007-annotations-and-acknowledgements.md) |
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
| Device | Vendor, model, firmware, role (`gateway`, `switch`, `ap`, `other`), management address, adapter, capabilities, health, time, whether Signalbox reads it encrypted |
| Port | Physical or logical port, link state, speed, PoE, LAG membership, neighbour (LLDP where available); configuration details: description, admin state, PVID, frame types, ingress filter, MTU / L2 MTU / jumbo flag, maximum and advertised speeds, auto-negotiation, medium, port profile, flow control, EEE; internal structure (#252, ADR 0008): role (jack, CPU port, switch port, bridge, VLAN / Wi-Fi interface, LAG, tunnel, virtual) and the ports it runs on, a cable can end there (`external`) derived |
| FdbEntry | One entry of a device's MAC address table (#160, ADR 0016): port, MAC, VLAN and segment, `dynamic` / `static` / `self`, age; at most 2048 per device, not in `GET /api/network` |
| Link | A cable or wireless uplink between two ports; observed (LLDP, MAC tables) or entered by hand; a `vpn` link between two tunnels whose peers name each other's public keys |
| Segment | Layer-2 network: VLAN id, name, purpose and its source, isolated by the device; membership per port `untagged` / `tagged` / `none` |
| Subnet | Prefix, gateway address, segment, IPv4/IPv6 |
| Uplink | A gateway's WAN connection: kind (`dhcp`, `static`, `pppoe`, `dslite`, `map-e`, `lte`, `bridge`, `other`), port, connected and since when, own addresses, delegated IPv6 prefixes, upstream gateway, provider DNS, public IPv4 where the device knows it, line rates; NAT class derived |
| ManagementService | A way to manage a device (SSH, telnet, HTTP/HTTPS, API, SNMP, FTP/TFTP, Winbox, MAC telnet/Winbox, RoMON, TR-064, UPnP, the vendor's own protocol): enabled, port, transport, encrypted, listen addresses / ports / segments, allowed source networks, reachable from the internet as the device says, SSH password and root login, HTTP-to-HTTPS redirect, SNMP versions and default community; reachable segments and internet exposure derived |
| DhcpServer | Device, segment, enabled, pool, lease time, options (router, DNS, NTP, search domains, classless routes, network boot, further options by code), static reservations, authoritative, failover peer, lease table (address, MAC, client id, host name, state, reserved, start and end, vendor class) |
| DhcpRelay | Device, segment, servers it forwards to, enabled |
| DnsService | Resolver with its port (several per device), host overrides, forwarders (address and port), split-DNS domains |
| Tunnel | A VPN interface of a device (`wireguard`): name, description, port, up, enabled, listen port, own public key, addresses, MTU; peers with public key, name, endpoint, allowed IPs, last handshake, transfer counters, keepalive, whether a pre-shared key is set. Never a private or pre-shared key ([ADR 0011](adr/0011-vpn-tunnels-and-site-links.md)) |
| Wlan | SSID, security (open, OWE, WEP, WPA/WPA2/WPA3 Personal and Enterprise incl. mixed and 192-bit modes; PMF), passphrase fingerprint and SSID-independent digest, segment, bands, hidden, roaming (802.11r/k/v), purpose and its source, client isolation; security details: pairwise and group ciphers, SAE (PWE, SAE-PK, anti-clogging), WPS (on, methods, AP PIN lock), group rekey interval, beacon protection |
| Radio | Band, channel, width, transmit power, country code, security modes the hardware and firmware can offer |
| Firewall | One per device (#135, [ADR 0013](adr/0013-firewall-zones-rules-and-reachability.md)): enabled, zones (segments, uplinks, tunnels, ports in them), default action per zone pair and per chain, ordered filter rules (chain, family, protocols, source and destination zones / networks / ports with negation, action, forwarded-only, exact), source NAT, port forwards (external ports → target address and port, passes the filter, reflection), whether rules and forwards were read completely; reachability derived |
| Client | MAC, IP, hostname, segment, where it was seen (port or access point), last seen, source per address (`dhcp`, `dhcp-reserved`, `static`, `slaac`, `slaac-privacy`, `dhcpv6`, `link-local`, `unknown`) |
| Firmware | Current, available, end of life |
| DeviceHealth | Uptime and boot time, last restart reason, CPU load and load average, memory, storage per mount (kind, wear), temperatures with limits, fans, power supplies, monitored UPS |
| DeviceTime | Device clock and Signalbox's time when it was read (offset, uncertainty), time zone, NTP client (servers, synchronised, stratum), NTP server (segments it serves) |
| Annotation | User data per object id (device, port, segment, subnet, `client/<mac>`): label, purpose, owner, notes, tags, typed expectations (`static_address`, `category`, `may_be_unreachable`, `known_neighbour`, ...); declared or stored |
| Acknowledgement | A finding accepted by the user: rule plus finding id or target object, reason, until, optional fingerprint of the message |
| PathTrace | An active observation (#253): a traceroute from a device or Signalbox's host to an address, purpose (gateway, internet, address), hops (TTL, address, RTT, matched device and interface), reached, error with fix and remedy; the latest per pair, stored apart from snapshots, on `Network.traces` only while `traces.enabled` ([ADR 0014](adr/0014-path-traces.md)) |
| ForeignServer | An active or passive observation (#184): a DHCP server or IPv6 router seen answering on a network (kind, address, MAC, what it hands out, first and last seen, source probe / device-alert / client-lease, seen by), `known_as` the known device it matches (none: foreign); probe answers stored apart from snapshots, device sightings (`ServerSighting`) from the snapshots ([ADR 0015](adr/0015-foreign-dhcp-servers-and-routers.md)) |

`Device.health` and `Device.time` (adapter API 1.2, capabilities `health` and `time`) are value
objects on the device rather than objects with their own ids: there is one per device, it has no
identity of its own and is read with the device, like `Firmware`. They are `None` when the
device's integration has no such capability, and every value inside is optional because devices
report very different subsets. Health values change on every observation: rules compare them
with thresholds and the observation history, never as drift from a desired state. A UPS is
reported by the device that monitors it (`DeviceHealth.ups`); a UPS with its own management
interface would be a device of its own. Clock offsets are computed in core
(`DeviceTime.offset_seconds()`) from the device's clock and Signalbox's time at the read, with
half the round trip as error bound. The time zone reveals the region: it is shown in the UI but
not exported to MQTT.

Wi-Fi security details (#167) are optional fields on `Wlan` and `Radio`, filled by the
`wireless` capability (no new capability, no adapter API change; `None` everywhere means "not
reported", so an adapter that fills none of them is unchanged). `Security` names the legacy
modes (`wep`, `wpa-psk`, `wpa-wpa2-psk`, `wpa-enterprise`) and `wpa3-enterprise-192` instead of
`other`; `Wlan.ciphers` (pairwise, `ccmp`/`ccmp-256`/`gcmp`/`gcmp-256`/`tkip`/`wep`) and
`group_cipher` say whether TKIP is still on in a mixed mode. `Wlan.sae` (`pwe`, `sae_pk`,
`anti_clogging_threshold`) matters on 6 GHz, which needs hash-to-element. `Wlan.wps` is `Wps`
(`enabled`, `methods` push-button/pin/nfc, `ap_pin_locked`), `key_rotation_seconds` the group
rekey interval (0: never), `beacon_protection` the BIGTK flag. `Radio.supported_security` is
what the radio could offer (an OpenWrt build with `wpad-basic` has no SAE), so a rule can say
"WPA3 is possible here" and a plan that asks for a mode the radio cannot do can be refused.
WLANs and radios belong to one snapshot each, so the merge passes the fields through.

Passphrases are never stored. `passphrase_fingerprint(ssid, passphrase)` (PBKDF2 salted with
the SSID, the WPA PMK, hashed again) compares one SSID across access points, but never two
SSIDs. `Wlan.passphrase_digest` (`passphrase_digest(passphrase)`) compares across SSIDs (#101):
PBKDF2-SHA256 with a per-installation key as salt, 64 bits shown as hex. The key is derived
from the vault key (`Vault.derive_key("passphrase-digest")`, HMAC-SHA256), installed by the
service at start (`set_passphrase_digest_key`), so it lives where the vault key lives and
changes with it; without a key (library use, tests, recordings, remote adapters in their own
process) the digest is `None`. Why keyed: an SSID-independent unkeyed hash would be one global
dictionary away from the passphrase (the same table works for every installation and every
SSID), and home passphrases are short. With the key as salt a guess can only be tested by
someone who also has the key, who could already decrypt the device credentials and read the
passphrase from the device. Both values stay in the observation database (snapshots), are
removed from `/api/network` (`public_network`), are not exported to MQTT and are redacted in
recordings; the JSON Schema documents the field. After a vault key change old snapshots carry
digests of the old key: comparisons across them miss a reuse (no false alarm) until the next
observation.

Desired state for these details (design, not built yet): `wlans[]` would get `wps: false` and
`ciphers: [ccmp]`, `None` meaning "leave as is", and `WlanValue` the same fields. They are not
added now because every writer would have to set or refuse them, and a desired value that the
writers silently ignore would be worse than none; turning WPS off is the first write worth
building (OpenWrt `wps_pushbutton`/`wps_label`, MikroTik `security.wps`, Fritz!Box
`X_AVM-DE_SetWPSConfig` *(guess: action name)*). A desired WPA3 mode on a radio whose
`supported_security` lacks it should be refused by the plan (`wifi.sae-unsupported-declared`).

Port configuration details (#156) are optional fields on `Port`, filled by the `interfaces`
capability where the device reports them (no new capability, no adapter API change: an adapter
that sets none of them is unchanged). `up` stays the link state and `admin_up` the configured
one. `pvid` is the ingress VLAN; the untagged `Segment.members` entry stays the egress truth
("sent untagged"), so the VLAN view keeps showing membership and the topology port panel adds
where untagged frames land when the two differ, which switches with separate PVID and
membership settings (ProSAFE, Easy Smart) allow. `vlan.single-untagged` (#110) reports that
mismatch; `Network.pvid_segment()` and `Network.untagged_segments()` give both sides.
`Port.jumbo_frames()` compares a jumbo flag with an MTU for `link.mtu` (#114), `max_speed_mbps`
lets `link.slow` (#108) flag a 1G link on 2.5G ports, and `Port.label()` puts the user's own
port description into findings ("port 5 (office desk)"). A description is user text that may
contain names: it is shown in the UI, never exported (MQTT, reports) by default. Ports are not
merged across devices (each port belongs to one snapshot), so the fields need no merge rule.

Desired state and plans (design, not built yet): `ports[]` would get optional `description`,
`admin_up` and `mtu`, `None` meaning "leave as is", and `PortValue` the same three fields. PVID
is not declared separately: it is implied by `untagged` (writers already set the PVID to the
untagged VLAN). Today a declared port always plans its VLANs, so a port entry that only names a
description would remove its memberships; the VLAN fields first have to become "not
specified" when left out. Disabling a port must be refused when it is on the path to Signalbox
or to a device later in the plan.

WAN uplinks (#148) are objects of their own (`Snapshot.uplinks`, `Network.uplinks`, id
`<device>/uplink/<name>`), not subnets with a flag: the WAN prefix is not a network of the site
(the OPNsense and MikroTik adapters already leave WAN addresses out of `Subnet`), and an uplink
has properties a subnet lacks (connection kind, session uptime, provider DNS, delegated
prefixes, line rate). They are read with the `interfaces` capability, the calls that already
list the WAN interface, so there is no new capability and no adapter API change: the field is
additive and empty for every adapter that does not fill it. The cost is that "no uplinks" does
not tell "the device has none" from "the integration does not read them"; checks therefore only
act on uplinks that are reported, never on their absence. A separate capability would only be
worth it if uplinks needed their own read (an extra slow call) and their own "incomplete"
finding; that can still be added later without breaking adapters that fill the list today.

The NAT class is derived in core, never reported: `Uplink.nat_class()` classifies the device's
own IPv4 addresses with `address_nat_class()` (RFC 1918 `private`, 100.64.0.0/10 `cgnat`, no
IPv4 of its own `none` (IPv6 only, DS-Lite, MAP-E), anything else `public`; documentation
prefixes count as public so simulators can stand in for real lines). `public_ipv4` is only the
address the internet sees where the device knows it apart from its own (a cloud lookup the
device does itself); Signalbox never looks it up, which would tell a third party where the
installation is. `Network.upstream_router()` finds a gateway subnet of another known device
that holds the uplink's address: this router sits behind that one (double NAT, "Internet via
192.0.2.1"). Uplinks belong to one device and are not merged. A modem in bridge mode that is a
device of its own reports a `bridge` uplink without addresses. The public address and the
delegated prefix identify the household: the device page shows them only behind a click, MQTT
publishes only connectivity and the NAT class, and recordings replace them with documentation
addresses like every address (which also hides whether a recorded line was private or CGNAT).

Desired state (design, not built yet): a site could declare `internet: {public_ipv4: true}`
(or `ipv6: true`), and `wan.expected` would report drift when the provider moves the line to
CGNAT or drops IPv6. Writing uplink settings stays out of scope: getting it wrong cuts off the
site and Signalbox with it.

Management services (#173) are objects of their own (`Snapshot.services`, `Network.services`,
id `<device>/service/<key>`, key the device's name of the service or its kind), one per service
the device has, enabled or not. Like uplinks they are read with the `interfaces` capability:
an additive list, no new capability and no adapter API change (still 1.2). An integration
that reads services reports every one it knows, so an empty list means "not read", never "no
services", and checks act only on reported services. If reading them ever needs its own slow
call or its own "incomplete" finding, a `services` capability can be added in a later minor
version without breaking adapters that fill the list today. `kind` is the vocabulary checks
use; `name` keeps the device's own word (`www-ssl`, `dropbear`, `remote-access`). `transport`
and `encrypted` are filled from the kind when the device does not say (SNMP counts as
encrypted only when it answers v3 with privacy alone; TR-064, RoMON and `other` stay unknown).
Community strings and passwords never enter the model, only whether a factory default is set.

Where a service listens is what the device itself applies: `listen` (addresses; empty or
`0.0.0.0`/`::` means all), `interfaces` (ports), `segments` (networks, OpenWrt `Interface`,
OPNsense listen interfaces, mapped by the adapter) and `allowed_from` (the service's own source
filter, MikroTik `address`). Reachability is derived in core, not reported, and without
firewall data (#135) it is an upper bound: `Network.service_segments()` lists the segments
that can reach one of the device's addresses (its own subnets and the network of its
management address; for layer-2 services the networks on its ports), narrowed by those four
restrictions. `Network.service_from_wan()` answers the device's own `from_wan` (Fritz!Box
internet access, FTP from the internet) where there is one; otherwise `false` for a device
without an uplink, a service bound away from the uplink or one restricted to private source
networks, and `null` ("the firewall decides") for a service that listens on the uplink. The
firewall itself is applied on top by `signalbox.firewall.service_reach()` and
`service_from_internet()` (#135, see "Firewall and forwarding"), which the checks call.
`Device.transport_encrypted` is separate: it is how Signalbox itself
reads the device (`false` for NSDP, Easy Smart UDP, plain HTTP), set by the adapter through
`SystemInfo`.

Desired state (design, not built yet): `devices[].services: {telnet: off, http: redirect, ssh:
{password: false}}`. Turning a service off must be refused when it is the one the integration
itself uses (MikroTik `www-ssl`/`api-ssl`, OpenWrt `uhttpd` for ubus).

DHCP leases (#183) are part of the server that handed them out: `DhcpServer.leases`, read with
the `dhcp` capability like pools and reservations, so a lease always names its server and
segment without a lookup and no top-level list keyed by server id is needed. `None` means the
table was not read, `[]` that it was read and is empty: only then may a check conclude that an
address has no lease (`Network.leases_read(segment)`). A lease keeps every state the server
reports (`active`, `expired`, `declined`, `offered`, `reserved`), its start and end, whether it
belongs to a reservation, the client id (option 61 or DUID: a DHCPv6 lease may have no MAC)
and the vendor class (option 60). Where an address came from is a second, independent fact on
the client, `Client.address_sources` (address → source), filled by the integration that knows
it from the client side (Fritz!Box `AddressSource`) or from the lease it merged into the client
(OPNsense, OpenWrt, MikroTik). `Network.address_source()` combines both: the client's own
answer, else an active lease of that MAC and address on any known server, else `link-local`
for such an address, else `None`; it never answers `static` by elimination, because whether a
missing lease means a fixed address needs a complete table and a grace period, which is the
check's decision (#67). DHCP relays are objects of their own (`<device>/dhcp-relay/<segment
key>`, `Snapshot.dhcp_relays`): a segment with an enabled relay needs no server of its own
(`Network.dhcp_relays_on()`). Options beyond router, DNS and domain are typed where checks
need them (NTP 42, search list 119, classless routes 121, network boot 66/67) and otherwise
kept by code in `options`, which never repeats a typed one. All of it is additive: no new
capability, no adapter API change (still 1.2). Lease host names, client ids and vendor classes
are client data like `Client.hostname`: stored, shown to signed-in users, neutralised in
recordings (`hostname`, `host-name`, `client_id` are name or secret fields there). Leases are
runtime state, never desired; options and relays could become declarable
(`segments[].dhcp.options`, design only).

### Untagged networks of several routers

Integrations report a device's plain LAN as `<site>/segment/native`. Two routers in a row (an
ISP router and a firewall whose WAN is in the ISP router's LAN, #205) have two separate untagged
networks, so the merge splits them ([ADR 0005](adr/0005-untagged-networks-of-several-routers.md)):
routers with overlapping subnets share a network, switches and access points join the one their
management address is in, clients the one their address is in, and a link between two ports that
both send the native network untagged joins the networks of its ends. With one network left
(every single-router site) nothing changes. Otherwise the main one keeps `<site>/segment/native`
(the one not in front of another router, then the one most switches and access points are
managed in, then the lowest router id) and every further one is
`<site>/segment/native-<router id>` (`native_segment_id()`, `is_native_segment()`), named after
its router (`lan (Fritz!Box)`). `Network.native_segment(device)` is a device's own untagged
network; `Port.pvid` 1 lands there. In the desired state `native` on a port or SSID means the
device's own untagged network, a `native` segment entry the main one; the LANs of further routers
are left out of an import and cannot be declared yet.

A router's uplink port (`Uplink.port_id`) is in no segment of its own router; link rules treat
it as an untagged member of the upstream router's network (`Network.upstream_router()`), and
where uplinks are not reported, a router port in no segment cabled to another router as an
uplink. `addr.double-nat` (#60) reports the two routers in a row as information.

### VPN tunnels and site links

A tunnel belongs to its device and is read with the `vpn` capability (adapter API 1.3, #239);
its peers are values on it. Two tunnels are the ends of one link when each has a peer with the
other's public key (`Network.tunnel_end`); `topology.tunnel_links` makes that a `Link` of kind
`vpn` between the two tunnel ids, within a site or across sites. A one-sided match (the other
tunnel does not name this one) gives no link: the ends disagree, which a check can report with
`Network.tunnel_with_key`.

A peer with allowed IPs that are more than one address and lie beyond the tunnel's own address
networks routes a network of
its own: a *site peer* (`Tunnel.site_peers`, `Tunnel.remote_networks`). A peer with only its
tunnel address is a client (phone, laptop). A site peer whose other end is not read is an
unmanaged remote site (`Network.remote_sites`): the topology shows it as a box with the networks
behind the tunnel, so one read end is enough to see that the site is connected. It is not a
`Site` of the inventory.

Private and pre-shared keys never enter the model: there is no field for them, the contract
checks refuse key-named fields and unknown WireGuard-shaped keys in `vendor_extra`, and
recordings replace every key by a placeholder. Integrations read the running state where the
device leaves the keys out (OPNsense `wireguard/service/show`). The peer endpoint is the other
site's public address: shown behind a click, never exported. Handshake times are absolute;
their age is taken against the time of the reading. See
[ADR 0011](adr/0011-vpn-tunnels-and-site-links.md).

### Firewall and forwarding

A device's packet filter and NAT are one `Firewall` object, read with the `firewall`
capability (adapter API 1.4, #135, [ADR 0013](adr/0013-firewall-zones-rules-and-reachability.md)).
It is a small common denominator of OpenWrt fw4, OPNsense pf, RouterOS, nftables and the
Fritz!Box, chosen so that core can answer one question exactly where the data allows it: *can
traffic from segment, uplink or tunnel A reach address X on port P?*

- **Zones** name groups of interfaces and map them to model objects (segments, uplinks,
  tunnels, ports). The merge moves native segment ids like for every other object.
- **Policies** give the default action per zone pair (`destination = None`: the device
  itself); `input_policy` and `forward_policy` are the fallbacks.
- **Rules** are in evaluation order, first match wins. Source and destination match zones,
  networks and ports, each optionally negated; `forwarded` restricts a rule to port-forwarded
  connections; `exact = False` marks a rule with conditions the model does not express.
- **Port forwards** and **source NAT** as reported; `passes_filter` says the forward needs no
  filter rule (OpenWrt redirects, Fritz!Box port sharing).
- `rules_complete` / `port_forwards_complete` are false where the device has rules the adapter
  cannot see (OPNsense rules outside the API, nftables includes it cannot follow).

`Firewall.evaluate(flow)` checks the rules with three-valued matching (`yes`, `no`, `maybe`: the
flow is broader than the rule, for example a whole segment against a host rule, or the rule
is inexact). A `maybe` adds its action to the possible outcomes, the first `yes` decides,
otherwise the zone pair policies and the fallback. One outcome (accept, or drop/reject) is the
answer; anything else is `unknown`.

`signalbox.firewall.reach()` builds the flows. To a device's own address it has towards the
source: that device's input chain. Otherwise the router present in both networks decides
(forward chain), followed by the target's own firewall where read; same segment means no
router. From the internet a private IPv4 address is reached only through a port forward, and a
router in front (double NAT) is followed when it is known. `service_reach()` and
`service_from_internet()` apply this to `ManagementService` objects.

Approximations, all documented as "not checked" rather than guessed: no routing tables or
policy routing, no path over two routers inside a site (a tunnel's far end is a separate
evaluation), connection state other than "new", rate limits, schedules, GeoIP and marks (the
rule becomes inexact), pf's last-match for non-`quick` rules (the adapter orders them or marks
them inexact), client isolation on access points, and several nftables base chains on one hook
(incomplete unless the others accept everything). A switch or access point without a read
firewall is taken as not filtering; a gateway without one is `unknown`.

The device page shows a firewall card: zones and what is in them, the default action per zone
pair as a matrix (`/api/network` adds it as `matrix`), the number of rules, the port forwards.
Desired state and writes (#295, [ADR 0017](adr/0017-firewall-desired-state-and-deployments.md)):
zone policies, rules and port forwards per device in the desired state, planned as the change
kinds `zone-policy`, `firewall-rule` and `port-forward`. Only objects Signalbox created (tagged
on the device) are changed or removed, unless the desired state adopts the device's own; a plan
that may cut Signalbox off from a device (reachability before and after) needs an explicit
override. OpenWrt writes them now; OPNsense and MikroTik follow.

### Annotations and acknowledged findings

Annotations (#186, [ADR 0007](adr/0007-annotations-and-acknowledgements.md)) are user data, not
observations: they live in the desired state (`sites.<site>.annotations` and
`acknowledgements`, reviewable in git, read-only in the UI) or in the database (set in the UI,
schema version 4), never in snapshots. Per target a declared annotation replaces a stored one.
The runner adds both to every network it builds (`signalbox.annotate.apply`, after
`apply_declared`), so checks, views, plans and MQTT see the same. They attach to model ids,
which are stable across runs: device ids, `<device>/port/<name>`, `<site>/segment/<key>`
(`native-<router>` included), `<device>/subnet/<name>` and `client/<mac>` for anything known by
its MAC address (clients, foreign access points, LLDP neighbours); `target_kind()` derives the
kind from the id and expectations that do not fit it are refused.

An acknowledgement names a rule and either one finding (its id: a hash of rule, key and
objects, so the same problem keeps its id) or a target object (every finding of that rule
naming it). `evaluate()` applies the active ones: the finding keeps its id and history and gets
`acknowledged`; `Finding.problem` is false for it. Acknowledged findings are listed apart on the
start page, counted apart in MQTT (the problem sensor ignores them) and never block a plan.
`until` ends an acknowledgement (the engine reports `ack.expired`), a fingerprint of the message
ends it when the details change. `annotations.stale` reports annotations and acknowledgements
whose object is gone, so changed ids never orphan user data silently. Checks read expectations
through `Network.expected(target)`, `Network.annotation()`, `Network.label()` and
`Network.knows()`.

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
- clients placed on the port or access point where they were last seen,
- VPN tunnels: a `vpn` link between two read tunnels whose peers name each other's public keys,
  drawn between the gateways (also of two sites), and an unmanaged remote site for a site peer
  whose other end is not read,
- routed paths (#253, optional): the layer-3 path of each path trace with the known routers on
  it and the hops inside a tunnel, and which router is in front of which
  (`signalbox.traces.routed_view`); it never adds links to the wiring view.

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

## Discovery

*Find devices* (#203) is the only place where Signalbox talks to addresses nobody configured,
so it is fenced in ([ADR 0006](adr/0006-discovery-probes.md)):

- **Started by the user only** (`POST /api/discovery`), never in the background;
  `discovery.enabled: false` turns it off.
- **Targets** (`signalbox.discovery.targets.plan`, a pure function of the network model and the
  input): gateway subnets of added routers up to /24 completely, larger ones and IPv6 only the
  gateway; IPv4 addresses of clients, DHCP reservations and LLDP neighbours; what the user
  types. Network devices (gateways, neighbours, vendor MAC prefixes, network-ish host names)
  first; at most `discovery.max_hosts`.
- **Probes belong to the integrations**: `Adapter.discover(probe)` per address and
  `Adapter.discover_broadcast(probe)` per run, optional class methods with defaults, so no
  adapter API version change. Core never imports vendor code: the engine
  (`signalbox.discovery.engine`) only calls the hooks of the installed adapters.
- **The probe object enforces the rules**: `HostProbe` sends unauthenticated HTTP(S) only
  (no credentials, no cookies kept, no proxy, TLS unverified and never pinned, no redirects,
  answers cut at 256 KiB), through one rate limiter per run and with bounded concurrency; an
  address silent on two ports is given up. Broadcast probes take the same limiter.
- **Answers are suggestions**: `Candidate` cleans device text; the engine keeps only
  non-secret settings of the integration and a role it supports (router for a known gateway
  address). Candidates live in memory until the next run; only the ignore list is stored.
  Adding a found device goes through the normal form, test and trust-on-first-use flow.

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
   that would create an error finding is refused unless explicitly overridden; one whose
   firewall changes may cut Signalbox off from a device needs its own override (#295).
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
