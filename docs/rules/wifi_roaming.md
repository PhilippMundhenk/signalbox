<!-- rules of src/signalbox/rules/wifi_roaming.py; part of the rules documentation (docs/RULES.md lists all) -->

# Wi-Fi roaming and client association

Checks on the roaming settings of SSIDs across access points (#168) and on how well Wi-Fi
clients are connected (#170). Settings or readings a device did not report are never judged.
The thresholds are rule parameters (`max_dbm` of `wifi.min-rssi-too-high`, `min_dbm` and
`sustained_minutes` of `wifi.client-weak-signal`; #441, #447), so they can be set per site or
access point. Client readings are personal data (who is where) and stay on the server; clients
that are mesh peers or on backhaul SSIDs are skipped.

## `wifi.ft-mobility-domain-mismatch`

- **Severity:** warning
- **Checks:** per site and SSID, access points with 802.11r not reported off whose 802.11r
  mobility domain differs. Fast roaming only works inside one domain. OpenWrt without an explicit
  `mobility_domain` uses the first four hex digits of the MD5 sum of the SSID; Signalbox
  computes the same value. Domains read: OpenWrt, MikroTik (`ft-mobility-domain`).
- **Fix:** set the same mobility domain for the SSID on all access points.

## `wifi.min-rssi-too-high`

- **Severity:** warning
- **Checks:** an SSID whose minimum signal (`min_rssi_dbm`, MikroTik access list
  `signal-range`) or minimum association signal (`assoc_rssi_dbm`, OpenWrt
  `rssi_reject_assoc_rssi`) is above `max_dbm` (default -70 dBm). Such a limit kicks clients that still have a usable
  connection, and they reconnect in a loop.
- **Fix:** lower the limit to 5 dBm below `max_dbm` (-75 dBm) or weaker, or turn it off.

## `wifi.min-rssi-inconsistent`

- **Severity:** info
- **Checks:** per site and SSID, access points that report different `min_rssi_dbm` values.
  Access points without a limit are not compared (no limit and not reported look the same).
- **Fix:** use the same minimum signal on all access points.

## `wifi.client-weak-signal`

- **Severity:** info
- **Checks:** a wireless client whose reported signal is weaker than `min_dbm` (default -75 dBm)
  on the access point it is associated with (scopes match that access point). With the
  observation history it must have been weak on that access point for `sustained_minutes`
  (default 30) without a stronger reading in between (the history keeps the signal in steps of
  5 dB); a client the history does not know yet, or no history at all, is judged by the current
  reading.
- **Fix:** move the device or an access point closer together, or add an access point.

## `wifi.legacy-client`

- **Severity:** info
- **Checks:** a wireless client associated with 802.11b or g. Its frames take far more air
  time and slow down the whole radio. The standard is the one the access point reports for the
  station (OpenWrt: from the HT, VHT, HE flags and the band; MikroTik: the band of the
  registration row; Omada and UniFi: the controller's mode).
- **Fix:** replace the device, or give it an SSID of its own on a separate radio.
