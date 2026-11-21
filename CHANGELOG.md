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
