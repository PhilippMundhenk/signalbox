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
