<!-- rules of src/signalbox/rules/stp_checks.py; part of the rules documentation (docs/RULES.md lists all) -->

# Spanning tree and loop protection

These rules use what the bridges report about their spanning tree (#155,
[ADR 0023](../adr/0023-spanning-tree.md)): per bridge (`Device.stp_bridges`) the protocol,
priority, bridge id and the root it sees; per bridge port (`Port.stp`) role, state, edge port,
path cost, BPDU guard, root guard and loop protection. Two bridges are in one layer-2 network
when a known cable (LLDP, MAC tables, entered by hand) joins a port of one to a port of the
other; a device that is not read, or does not report its spanning tree, splits the network
there. Everything stays quiet where a device does not report its spanning tree.

## `stp.several-roots`

- **Severity:** warning
- **Checks:** the bridges with spanning tree on in one layer-2 network name more than one root
  bridge. The spanning tree messages (BPDUs) do not get from one part to the other then: a
  switch or bridge in between has spanning tree off and drops them (a Linux bridge without STP
  does), or a port filters them; a loop through both parts is not blocked.
- **Fix:** the same protocol (RSTP) on every switch and bridge of the network; look for a
  device in between with spanning tree off or BPDU filtering.

## `stp.root-not-core`

- **Severity:** info
- **Checks:** in a network with one root, the root bridge is neither a gateway nor the core:
  the gateways that take part in the spanning tree, or, without one, the switches with the most
  cables to other bridges. A root that is not a device Signalbox reads (a cheap switch with the
  factory priority 32768 and a low MAC) counts as another device. Quiet when no gateway or
  switch of the network runs spanning tree.
- **Fix:** a lower bridge priority (for example 4096) on the core; the network reconverges
  for a few seconds when it changes.

## `stp.disabled-with-redundancy`

- **Severity:** warning
- **Checks:** a bridge with spanning tree off (protocol `none`) whose known cables lead to the
  same switch or gateway twice (not through one link aggregation), or to switches and gateways
  that are connected to each other another way: a loop. Quiet when a device on that loop blocks
  a port (spanning tree state blocking or discarding, role alternate or backup) or has the loop
  detection of simple switches on. A star (cables to switches that are not connected to each
  other) is no loop.
- **Fix:** RSTP on the bridge and the other switches, remove the second path, or combine
  parallel cables into a link aggregation.

## `stp.topology-changes`

- **Severity:** warning
- **Checks:** a bridge with spanning tree reports at least 20 topology changes, and more than
  6 per hour on average since the device started (its uptime). Needs a reader that reports
  the count (none of the built-in integrations does yet: neither the Linux kernel nor RouterOS
  count them).
- **Fix:** find the port that goes up and down; make ports to clients edge ports.

## `stp.client-port-not-edge`

- **Severity:** info
- **Checks:** a port of a bridge with spanning tree that says it is not an edge port
  (`edge` false), has clients behind it, no known cable to another device and is not the root,
  an alternate or a backup port. Bridges that have no edge ports at all (the Linux kernel's
  STP, OpenWrt) report `edge` unknown and are skipped.
- **Fix:** make the port an edge port (PortFast), with BPDU guard where only clients belong.
