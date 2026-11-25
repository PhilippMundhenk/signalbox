<!-- rules of src/signalbox/rules/neighbour_checks.py; part of the rules documentation (docs/RULES.md lists all) -->

# Neighbour details (LLDP)

These rules compare what a neighbour announces about its own port (`Neighbour.port_vlan`,
`max_frame_size`, `poe_requested_w`, #163) with the settings of the local port. Readers: OpenWrt
(lldpd through `luci.lldpd`), EdgeOS/VyOS (`show lldp neighbors detail`), MikroTik
(`/ip/neighbor`, VLAN id only) and SNMP (LLDP-MIB with the 802.1, 802.3 and LLDP-MED extension
tables). The VLAN and frame size rules only look at ports without a cable link, where the
other end is not read by Signalbox: `vlan.native-mismatch` and `link.mtu` compare both ends
otherwise. Nothing is checked where the neighbour or the local port does not report the value.

## `link.pvid-mismatch`

- **Severity:** warning
- **Checks:** the native (untagged) VLAN the neighbour announces against the port VLAN id (PVID)
  of the local port.
- **Fix:** set the same native VLAN on both ends of the cable.

## `link.mtu-mismatch`

- **Severity:** warning
- **Checks:** the maximum frame size the neighbour announces against the local MTU plus 22 bytes
  (Ethernet header, VLAN tag, checksum). Parameter `tolerance_bytes` (default 22) is the extra
  allowance.
- **Fix:** lower the MTU of the local port, or enable jumbo frames on the other end and in
  between.

## `poe.request-unmet`

- **Severity:** warning
- **Checks:** the power a neighbour requests (LLDP) against the local port: PoE switched off,
  or a port limit (`Port.poe.max_w`) below the request. Parameter `margin_w` (default 0.5 W).
- **Fix:** turn PoE on or raise the limit of the port, or move the device.
