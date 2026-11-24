<!-- rules of src/signalbox/rules/logging_checks.py; part of the rules documentation (docs/RULES.md lists all) -->

# Logging and monitoring targets

These rules read the remote targets a device sends syslog, flow records (NetFlow, IPFIX,
sFlow), SNMP traps or metrics to (issue #180, ADR 0018). A device whose targets were not read
is not checked; a device that was read and sends nothing counts as "no remote syslog". SNMP
v1/v2c with the default community `public` or `private` is reported by
`security.insecure-services` (management services); the community itself is never stored.

## `log.target-unknown`

- **Severity:** warning; "not checked" when the address is in no known network and not every
  device of the site was read
- **Checks:** the address of an enabled syslog, flow or trap target lies in a known network
  and some device or client uses it (checked only where clients are read for that network); a
  private address (RFC 1918, CGNAT, ULA) outside every known network must lie behind a VPN
  tunnel. Host names, public addresses outside the known networks and loopback are not
  checked.
- **Fix:** point the target to the address of the log collector, or remove it if there is none
  any more.

## `log.inconsistent`

- **Severity:** info
- **Checks:** the devices of one site whose targets were read send their syslog to the same
  set of collectors. Reported per site, listing which devices log where (or nowhere), when at
  least one device sends syslog to a remote target.
- **Fix:** send the syslog of every device of the site to the same collector.
