# 0021. Logging and SNMP desired state: syslog targets Signalbox created, an agent switch

Date: 2026-11-24 · Status: accepted

## Context

The read side of #180 ([ADR 0018](0018-log-and-monitoring-targets.md)) knows where a device
sends syslog and whether its SNMP agent answers. #327 asks for the desired state: where the
devices of a site should log to, and that the SNMP agent is off (or v3 only), written on
MikroTik and OpenWrt like the firewall of [ADR 0017](0017-firewall-desired-state-and-deployments.md).
Logging settings are the owner's: an existing collector must not be replaced because a partial
desired state says something else.

## Decision

- **Syntax**: `sites.<site>.logging` with `syslog` (targets: `address`, `port`, `transport`
  `udp` or `tcp`), `snmp` (`off` or `v3-only`), `devices` (default: every device whose log
  targets were read), `adopt` (addresses) and per-device `overrides` that replace a setting.
  YAML 1.1 reads an unquoted `off` as false; that is accepted as the word `off`.
- **Two change kinds**, with old and new values: `log-target` (key `syslog/<address>`: address,
  port, transport, sent at all) and `snmp-policy` (key `snmp`: `on`, `v3-only`, `off`). They are
  applied after the firewall kinds. Communities and trap communities are not part of any value.
- **Ownership**: a `LogTarget` has `managed`, set by the readers from a tag the writers put on
  the device (OpenWrt: option `signalbox_syslog` in the `system` section; MikroTik: an action named
  `signalbox-...`). The planner changes or removes only managed targets and targets whose address
  is under `adopt` (the change carries the address in `adopt`, like an adopted rule). A declared
  target at an address where the device has a different, unowned one is a planning error with
  the hint; unowned targets at other addresses are never touched. `snmp: off` needs no tag: the
  declaration is the switch, and the revert switches the agent on again.
- **Writers**: OpenWrt writes `log_ip`, `log_port`, `log_proto` of `system.@system[0]` (one slot;
  a second target, or replacing an unowned one without adopt, is refused) and `snmpd.general.enabled`,
  inside the existing `uci apply` transaction with its confirm timer; the write ACL gets `system`
  and `snmpd` (a login with the older ACL keeps working for the other kinds). MikroTik writes
  a `signalbox-<address>` action with four rules and `/snmp enabled`, armed by the scheduler
  revert of the firewall changes (#326). `v3-only` and TLS are drift-only: refused at the writer
  with the reason (SNMPv3 users need secrets; TLS needs certificates).
- **Drift** (`drift.logging`) is the planner's comparison, so drift and plan agree. A device
  named in the desired state but not read gives an incomplete finding; the site-wide default
  skips devices whose log targets are not read.
- **Import** writes the syslog targets of each device as an override with all of them under
  `adopt`, and `snmp: off` for an agent that is switched off.

## Consequences

- No surprise replacements: an existing collector is only replaced after the user lists it under
  `adopt`; an undone adoption leaves the target Signalbox's (tagged) with the old values.
- OpenWrt supports one remote target; several are a MikroTik feature.
- The tag option and the MikroTik four-topic rules are guesses until a real device confirms them
  (#21), as are the `snmpd` reload behaviour and `remote-protocol` on a configured router.
