# Port counters

Port counters are read where the device reports them (OpenWrt, Linux, MikroTik, OPNsense, SNMP,
Omada, UniFi; FRITZ!Box: the WAN totals only). Signalbox keeps the last value per port and the
change since the read before; a counter that goes down is a reset (a reboot), not a negative
number, and a wrapped 32-bit counter is counted through. The thresholds are parameters of
`port.errors` (`error_ratio`, `crc_ratio`, `min_packets`, `min_errors`), also per device with
`scopes`; the old `counters` section of the configuration is a deprecated alias (a value other
than the default is applied rule-wide and logged as a warning).

## `port.errors`

- **Severity:** warning when CRC/FCS errors are received; info for other errors
- **Checks:** between the last two reads of an Ethernet port or LAG, the CRC errors are at least
  `crc_ratio` of the packets received (default 0.01 %), or the errors (received and
  sent) are at least `error_ratio` of the packets (default 0.1 %). Ports that are down or
  disabled, reads with fewer than `min_packets` packets or `min_errors`
  errors, and the read after a counter reset are ignored. Lifetime totals are never judged.
- **Fix:** replace or re-terminate the cable, check the connectors and the SFP, keep
  auto-negotiation on both ends.

## `port.drops`

- **Severity:** info
- **Checks:** between the last two reads of an Ethernet port or LAG, the dropped packets (received
  and sent) are at least `drop_ratio` of the packets (default 1 %), with at least `min_drops`
  drops (default 20) and `min_packets` packets (default 1000). Ports that are down, and the read
  after a counter reset, are ignored.
- **Fix:** look for a link slower than the traffic, a loop or a flooding device; a faster link or
  traffic shaping helps.

## `port.utilisation`

- **Severity:** info
- **Checks:** the traffic between the last two reads divided by their distance, in the busier
  direction, is at least `utilisation_pct` (default 90 %) of the port's link speed. Needs the link
  speed and byte counters. It looks at one read interval, so a short burst counts as sustained;
  reads closer than `min_seconds` are skipped.
- **Fix:** move heavy devices to another port, aggregate links (LAG) or use a faster link.

## `port.idle-trunk`

- **Severity:** info
- **Checks:** a jack that is a trunk (tagged-only, or a tagged member of a VLAN) with a link that
  carried no more than `idle_kbps` (default 2 kbit/s, both directions together) between the last
  two reads. Spanning tree and LLDP frames alone stay below that. A quiet moment can trigger it,
  so it is a hint.
- **Fix:** check what is plugged in; disable the port or remove the tagged VLANs.

## `port.collisions`

- **Severity:** warning
- **Checks:** at least `min_collisions` (default 10) collisions between the last two reads on a
  port that is full duplex or runs at 1 Gbit/s or more. Collisions only happen on half duplex, so
  this is a duplex mismatch with the other end.
- **Fix:** leave both ends on auto-negotiation or force the same speed and duplex on both.

## `device.reboot-by-counters`

- **Severity:** info
- **Checks:** for devices whose boot time is not known (so `device.reboot` cannot see them): the
  counters of all their ports that report counters (at least `min_ports`, default 3) started from
  zero between the last two reads.
- **Fix:** if nobody restarted the device, check its power supply or PoE budget and temperature.

## Counters in the MQTT export

With MQTT on, a device that reports counters gets four diagnostic sensors in Home Assistant: the
bytes received and sent, the port errors and the port drops, each the total over the device's
jacks as the device counts it (`total_increasing`; it starts from zero when the device restarts).
No port names or other identifying data are published, so no export opt-in is involved.
