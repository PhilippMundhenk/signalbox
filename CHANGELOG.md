# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Project setup: Python package, checks, policies, stack decision (#1)
- CI: lint, mypy --strict, tests with the 95 % coverage gate on Python 3.11-3.13, secret scan, Dependabot (#2)
- Network model: typed, vendor-neutral objects, snapshot merging, JSON Schema export (`signalbox schema`, docs/schema.json) (#3)
- Adapter API: manifest, capability protocols, entry point discovery, contract checks (`signalbox.testing`), docs/ADAPTERS.md (#4)
- Rule engine: rules as plain functions, stable finding ids, "incomplete" findings, read errors as findings, per-rule settings, entry point discovery (#5)
- Configuration file with every key commented and `SIGNALBOX_*` overrides; SQLite store for sites, devices, links, snapshots and findings history; device credentials encrypted with a key outside the database; certificate trust on first use (#11)
- Observation runner: reads all devices concurrently on an interval or on demand, a broken device or adapter becomes a visible finding, findings history recorded (#12)
- Rules: VLAN paths to the gateway, native VLAN and tagging on both ends of a link, unused VLANs, link speed/duplex (#8)
- OPNsense adapter (read): interfaces, VLANs, subnets, DHCP (Kea and ISC), Unbound DNS, ARP/NDP and leases as clients; simulator; certificate pinning before any credential is sent (#9)
- OpenWrt adapter (read) over ubus JSON-RPC: ports, DSA bridge VLANs, wireless (radios, SSIDs, passphrase fingerprint), DHCP, clients, LLDP; simulator; rpcd ACL for a read-only user (#10)
- Rules: DHCP (one server per segment, pools, reservations, router and DNS options), addressing (overlapping subnets, duplicate IPs), Wi-Fi (same SSID settings on every access point, country code, channel overlap, SSID VLAN at the gateway) (#6, #7)
- Web API with password login (generated on first start, scrypt hash, lockout), session cookie, CSRF and content-type checks, strict CSP; `signalbox serve` and `signalbox reset-password`; docs/API.md generated from the code (#13)
- Topology: links discovered from LLDP and MAC tables next to the cables entered by hand, `/api/topology` with the VLANs at both ends of each link, rules for conflicting and untagged-only links (#15)
- Home Assistant export over MQTT: findings per site and status, firmware, clients per device, with discovery, availability and removal of stale entities (#16)
- Container image (non-root, `/data` volume, healthcheck), docker-compose.yml, release workflow for multi-arch images; `signalbox demo` with a simulated gateway and two access points; container smoke test in CI (#17)
- Icon (a railway signal), branding guide, favicon and app icons, social preview (#19)
- Documentation for users: README with getting started and demo, CONFIGURATION and MATURITY generated from the code, DEPLOYMENT, TROUBLESHOOTING, every rule in RULES.md (#18)
- Web interface: findings first, devices with a settings form generated from the adapter, certificate trust, topology with VLAN overlay and entered cables, segments, Wi-Fi, DHCP & DNS, clients, settings; light and dark; works on a phone; browser tests in CI (#14, #15)
- Desired state: YAML in the data folder (optionally a git repository), editor with import of the observed state, encrypted secrets for Wi-Fi passphrases, drift findings for segments, DHCP, Wi-Fi and port VLANs (#36)
- Planner: typed changes with the value before and after (router interface, DHCP, reservation, port VLANs, Wi-Fi), ordered by dependency and outwards from the gateway, risky changes flagged, checks on the predicted network, plan view; write interface for integrations (#37)
- Change tracking: every change recorded with reason, desired-state commit, plan, vendor calls, encrypted backups, per-device results and an append-only event log (#39)
- Transactional deployment: per device lock, re-read, backup, apply (with confirm timer where supported), verify, confirm or roll back; a failure rolls back the devices already changed, last first; off by default (`deploy.enabled` and per-device *Allow changes*) (#38)
- Rollback: revert an applied change as a new, checked change (refused when the devices changed since); restore a backup as a tracked change; Changes pages in the UI (#40)
- AVM Fritz!Box adapter (read) over TR-064: LAN, DHCP, Wi-Fi incl. guest network, clients; simulator (#24)
- TP-Link Omada adapter (read): one controller site through the Open API: networks, switch ports, SSIDs, clients; simulator (#44)
- Controllers report the devices they manage (adapter API 1.1): Omada's gateway, switches and access points are devices of their own in rules, topology and plans; changes to them go through the controller (#46)
- NETGEAR ProSAFE Plus and TP-Link Easy Smart switches (read) through Switchyard's protocol library (optional extra `switches`, included in the image): ports, 802.1Q VLANs, firmware (#22, #44)
- MikroTik adapter (read) over the RouterOS 7 REST API: interfaces, bridge VLAN filtering, addresses, DHCP, DNS, wifi (wifiwave2 and legacy), clients, neighbours (#43)
- Firmware checks: identical devices on different firmware, update available, end of life (#22)
- Out-of-process adapters: an integration can run as a separate program that only gets the settings of its device (JSON over stdin/stdout, `serve()` for Python adapters); exporter plugins (`signalbox.exporters`); docs/PLUGINS.md (#25)
- OPNsense writes: router interfaces (VLAN device and interface assignment, OPNsense 26.7+), Kea DHCP subnets and reservations, tagged VLANs on a port; backup and restore through the configuration history (#42)
- OpenWrt writes: port VLANs (DSA bridge-vlan), SSIDs (incl. a VLAN interface when needed), DHCP and reservations, staged in UCI and applied with the rpcd rollback timer (#41)
- TP-Link writes: Omada LAN networks with DHCP, switch port networks and SSIDs of managed devices through the controller; ProSAFE Plus and Easy Smart 802.1Q port VLANs and PVIDs through Switchyard (#44)
- MikroTik writes over the RouterOS REST API: VLAN router interfaces, DHCP, reservations, bridge port VLANs, wifi (RouterOS 7 wifi package); backup and diff-based restore (#43)
- 36 new checks from the check catalogue: addressing and DHCP (#53-#59, #62, #63, #65, #66, #68, #69), IPv6 and DNS (#70, #71, #73-#79, #81), clients and Wi-Fi hygiene (#82, #83, #87, #88, #91-#95, #97, #98, #100, #103); see docs/RULES.md
- Dependabot: newer versions of the GitHub Actions used in CI (#26-#29)
- VLAN, topology and inventory checks: trunk scope, link aggregation, slow links, hidden devices, unknown LLDP neighbours, management network (opt-in), duplicate devices, single points of failure (#105, #107-#109, #113, #117-#119); rules can be opt-in
- Fritz!Box writes over TR-064: LAN DHCP on/off and range; existing SSIDs (name, security, passphrase, on/off, hidden); backup and restore of the touched values (#24)
- Integration tests against the real OPNsense 26.7 in QEMU, in GitHub CI (nightly and on adapter changes): read contract, pinning, refusals, every write kind through the Deployer with revert, backup/restore via the configuration history (#138)
- Integration tests against the real OpenWrt 24.10 and 25.12 in QEMU (official image builder, hwsim radios, VLAN-filtering bridge) and a shared integration framework (`make integration`, docs/TESTING.md) (#136, #137)
- History for checks: when devices, clients and ports were first and last seen and how their status changed (`history.days`, default 30); checks for devices down for long, stale reservations, clients that changed network, flapping ports and devices; first/last seen in the UI (#185, #64, #85, #128)
- Network purpose and client isolation: networks and SSIDs have a purpose (main, guest, IoT, management, …) reported by Fritz!Box/Omada, declared in the desired state or guessed from the name, and client isolation (OpenWrt reads and writes it); checks for guest Wi-Fi without isolation, management reachable from guest/IoT networks, networks without a purpose; fixes the false error for the Fritz!Box guest WLAN (#164, #99, #120)
- Integration tests against the real MikroTik RouterOS 7.25 CHR in QEMU (#139)
- A Fritz!Box simulator rebuilt from AVM's TR-064 service descriptions (FRITZ!OS 7.57 and 8.02) with a conformance test of every action the Fritz!Box adapter uses; pinned switch captures; `tools/record_device.py` records a real device (private data neutralised) and replays it as a regression test (#141)
- Device health and time in the model (uptime, CPU, memory, storage, temperatures, fans, power supplies, UPS, clock, NTP, time zone), adapter API 1.2, shown on the device page and exported to Home Assistant (#178, #179, model stage)
- Wi-Fi passphrase changes can be reverted: the previous passphrase is kept as an encrypted secret version (#188)

### Changed
- VLAN 1 counts as the native (untagged) network, so devices that report their LAN as VLAN 1 and devices that report it untagged agree; a VLAN tagged on only one end of a link is a warning (#17)
- Both adapters use one HTTPS helper that pins the device certificate in the TLS connection itself; the plain-HTTP setting is `allow_insecure_http` for every adapter (#34)

### Fixed
- MikroTik, found against the real RouterOS: missing menus answer 400, missing permissions 500, export through /execute, a new DHCP server is briefly invalid, read-only properties not restored, names only into the comment the read side uses (#139)
- Fritz!Box, found against AVM's service descriptions: hidden-SSID actions without the X_AVM-DE_ prefix, open security spelled as the box lists it, SSID/passphrase limits from the box, faults 600/601 (#141)
- Simulator requests took about 40 ms (Nagle on the simulator socket); now about 3 ms (#189)
- OpenWrt, found by testing against the real software: LLDP through luci-app-lldpd, leftover staging after a rollback, confirm after the deadline, a second login taking over a pending change, restore while another change waits, wireless status on 25.12, wpad with 802.11v (#137)
- OPNsense, found by testing against the real software: snake_case API paths (camelCase was refused for least-privilege users), assigned VLAN names with a description suffix, Kea subnets and reservations from their search endpoints, firmware version with package revision, assignment API detection from 26.7.6, stale VLAN devices after a restore, corrected privilege list (#138)
- A failing confirm on a device with a rollback timer now restores the device instead of leaving the change in "deploying"; integration errors while planning are shown instead of an internal error (#41)
- Reads of the database could see a half-written device while the runner wrote it (#14)
- "Read all devices now" during a running round started the next round only after the interval (#12)
