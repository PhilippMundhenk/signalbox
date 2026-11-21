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
- Rules: DHCP (one server per segment, pools, reservations, router and DNS options), addressing (overlapping subnets, duplicate IPs), Wi-Fi (same SSID settings on every access point, country code, channel overlap, SSID VLAN at the gateway) (#6, #7)
- Web API with password login (generated on first start, scrypt hash, lockout), session cookie, CSRF and content-type checks, strict CSP; `signalbox serve` and `signalbox reset-password`; docs/API.md generated from the code (#13)
- Topology: links discovered from LLDP and MAC tables next to the cables entered by hand, `/api/topology` with the VLANs at both ends of each link, rules for conflicting and untagged-only links (#15)
