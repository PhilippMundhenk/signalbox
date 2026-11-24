# 0018. Log and monitoring targets belong to their device; the SNMP agent stays a management service

Date: 2026-11-24 · Status: accepted

## Context

#180 asked for the places a device sends data to: remote syslog, NetFlow/IPFIX/sFlow, SNMP
traps, pushed metrics (collectd). Rules want to know whether a target answers (an old collector
address) and whether the devices of a site log to the same place, so "this device sends
nothing anywhere" must be distinguishable from "this device was not read". The issue sketched a
separate `LogTarget` object per target and a `Device.snmp` agent object. Since then the SNMP
agent became a `ManagementService` of kind `snmp` with `SnmpSettings` (#173, #221): versions,
whether a factory community is set, v3 privacy, write access, `allowed_from`; and
`security.insecure-services` reports v1/v2c with a default community.

## Decision

- **On the device.** `Device.log_targets: list[LogTarget] | None`: `None` is "not read", `[]`
  is "read, sends nothing", like `DhcpServer.leases`. A `LogTarget` is a plain value (no id):
  `kind` (`syslog`, `netflow`, `ipfix`, `sflow`, `snmp-trap`, `metrics`, `other`), `address`
  (address or host name), `port`, `transport` (`udp`, `tcp`, `tls`), `enabled` (configured but
  not used counts as disabled), the device's `name` and `topics` (facilities, levels, topics,
  flow version). Findings name the device; targets have no life of their own (they are not
  linked, merged or annotated), and a later desired state (`sites[].logging`) is per device too.
- **Read with `interfaces`**, no new capability and no adapter API version:
  `Observation.log_targets` is keyed by device id like `health` and `time`, so a controller can
  report its devices. `observe()` copies it to the devices. A device the integration could not
  read is left out (it stays `None`) and the read adds a gap, optional where the targets are an
  optional package or privilege: the device stays "ok".
- **SNMP is not duplicated.** The agent (versions, default community, write access, allowed
  sources) stays the `ManagementService` of kind `snmp`; only its trap destinations are log
  targets (`snmp-trap`). No new SNMP rule: `security.insecure-services` already reports the
  default community; the readers added here (OpenWrt `snmpd`) feed it. Community strings and
  trap communities never enter the model.
- **Rules** in `rules/logging_checks.py`: `log.target-unknown` (a target address in a known
  network nobody uses, or a private address outside every known network) and
  `log.inconsistent` (devices of a site send syslog to different collectors, or some nowhere).

## Consequences

- One field on `Device` instead of a new object list on `Observation`, `Snapshot` and
  `Network`; `merge` needs nothing new. A rule that needs a target id uses the device id plus
  the endpoint as its finding key.
- Vendor cloud management (MyFRITZ!, MikroTik Cloud, Omada Cloud) from #180 is not part of this:
  it is a management path, a `ManagementService` (Fritz!Box remote access is one already).
- Integrations without a read (Fritz!Box, Omada, ProSAFE/Easy Smart, Pi-hole, AdGuard Home)
  leave `log_targets` `None`; their devices are not counted by `log.inconsistent`.
