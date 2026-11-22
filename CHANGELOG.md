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

### Changed
- VLAN 1 counts as the native (untagged) network, so devices that report their LAN as VLAN 1 and devices that report it untagged agree; a VLAN tagged on only one end of a link is a warning (#17)
- Both adapters use one HTTPS helper that pins the device certificate in the TLS connection itself; the plain-HTTP setting is `allow_insecure_http` for every adapter (#34)

### Fixed
- A failing confirm on a device with a rollback timer now restores the device instead of leaving the change in "deploying"; integration errors while planning are shown instead of an internal error (#41)
- Reads of the database could see a half-written device while the runner wrote it (#14)
- "Read all devices now" during a running round started the next round only after the interval (#12)
