<!-- rules of src/signalbox/rules/wifi_roaming.py; part of the rules documentation (docs/RULES.md lists all) -->

# Wi-Fi roaming and client association

Checks on the roaming settings of SSIDs across access points (#168) and on how well Wi-Fi
clients are connected (#170). Settings or readings a device did not report are never judged.
The thresholds are constants of the module for now (`MIN_RSSI_HIGH_DBM`,
`WEAK_CLIENT_SIGNAL_DBM`) and become rule parameters with #187. Client readings are one sample
of one moment, not a trend; they are personal data (who is where) and stay on the server.

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
  `rssi_reject_assoc_rssi`) is above -70 dBm. Such a limit kicks clients that still have a usable
  connection, and they reconnect in a loop.
- **Fix:** lower the limit to -75 dBm or weaker, or turn it off.

## `wifi.min-rssi-inconsistent`

- **Severity:** info
- **Checks:** per site and SSID, access points that report different `min_rssi_dbm` values.
  Access points without a limit are not compared (no limit and not reported look the same).
- **Fix:** use the same minimum signal on all access points.

## `wifi.client-weak-signal`

- **Severity:** info
- **Checks:** a wireless client whose reported signal is weaker than -75 dBm on the access
  point it is associated with. One reading only: sustained weakness needs the history (to do
  with #187).
- **Fix:** move the device or an access point closer together, or add an access point.

## `wifi.legacy-client`

- **Severity:** info
- **Checks:** a wireless client associated with 802.11b or g. Its frames take far more air
  time and slow down the whole radio. The standard is the one the access point reports for the
  station (OpenWrt: from the HT, VHT, HE flags and the band; MikroTik: the band of the
  registration row; Omada and UniFi: the controller's mode).
- **Fix:** replace the device, or give it an SSID of its own on a separate radio.
