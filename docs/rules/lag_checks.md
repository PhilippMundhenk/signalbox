# Link aggregation

Rules on the LAG details that devices report (#157, ADR 0022): the mode of a LAG, and the LACP
state and partner of its members. Speeds, VLANs and whether the far end is a LAG at all are
checked by `lag.consistent` ([topology checks](topology_checks.md)). These rules stay quiet where a
device does not report the mode or the LACP state.

## `lag.mode-mismatch`

- **Severity:** error
- **Checks:** a LAG whose known cables all end in one LAG of one other device, where both
  devices report the mode and the modes do not work together: LACP on one end and a static
  mode (static, balance-xor, balance-rr, broadcast) on the other, LACP passive on both ends, or
  a Linux mode that needs no LAG on the far end (active-backup, balance-tlb, balance-alb)
  against a LAG. Reported once per pair of LAGs.
- **Fix:** set both ends to LACP (at least one of them active) or both to a static LAG.

## `lag.member-not-selected`

- **Severity:** warning
- **Checks:** a member of an LACP LAG (or of a LAG of unknown mode whose member reports its LACP
  state) that is up, but is not selected for the active aggregator or is not collecting and
  distributing frames. A backup member of an active-backup bond is not reported.
- **Fix:** check that the cable goes to the same device as the other members, and that the
  port there is in the same LACP LAG with the same speed and duplex.

## `lag.partner-mismatch`

- **Severity:** warning
- **Checks:** members of one LAG that report different LACP partners (system id, and key where
  reported). Members whose partner is not known are left out.
- **Fix:** connect all members to ports of one LAG on one device (or one switch stack).
