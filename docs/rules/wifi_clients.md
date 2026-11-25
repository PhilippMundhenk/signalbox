<!-- rules of src/signalbox/rules/wifi_clients.py; part of the rules documentation (docs/RULES.md lists all) -->

# Wi-Fi settings and clients over time

Follow-ups of the roaming and client checks (#447; #168, #170). Settings or readings a device did
not report are never judged. Backhaul SSIDs (mesh, WDS, repeater uplinks) and mesh peers are
skipped. Client readings are personal data (who is where): they stay on the server, and the
history keeps a client's signal only in steps of 5 dB and for `history.days`.

## `wifi.ft-over-ds`

- **Severity:** info
- **Checks:** per access point and SSID with 802.11r not reported off, whether fast transition runs
  over the distribution system (`ft.over_ds`; OpenWrt `ft_over_ds`). Many clients handle it
  badly; fast transition over the air works wherever 802.11r does. An SSID that does not report
  the setting is not judged (OpenWrt: only an explicit option).
- **Fix:** turn off "FT over DS" for the SSID.

## `wifi.dtim-high`

- **Severity:** info
- **Parameter:** `max_period` (default 3 beacons; scopes match the WLAN).
- **Checks:** an enabled SSID whose DTIM period is above `max_period`. Broadcast and multicast
  frames wait that many beacons, which breaks discovery protocols and some power-saving clients.
  Read: OpenWrt `dtim_period`, UniFi, MikroTik.
- **Fix:** set the DTIM period to 1 or 2 (3 at most).

## `wifi.max-clients-low`

- **Severity:** warning
- **Checks:** an SSID whose client limit (`max_clients`; OpenWrt `maxassoc`, MikroTik
  `max-clients`) is not above the number of clients Signalbox sees on it at that access point.
  A limit of 0 means no limit. New clients are refused.
- **Fix:** raise or remove the limit, or add access points.

## `wifi.client-2-4-only`

- **Severity:** info
- **Checks:** a client on a 2.4 GHz radio that connects with 802.11ac or newer (so it can use
  5 GHz) while the same access point has an enabled 5 or 6 GHz radio with the same SSID. The
  band is the one the access point reports for the station, else the one of its radio. Clients
  without a reported standard are not judged.
- **Fix:** turn on band steering (OpenWrt usteer or dawn, the controller's setting), or move the
  device.

## `wifi.radio-overloaded`

- **Severity:** info
- **Parameters:** `max_clients` (default 30), `idle_clients` (default 10), scoped by the
  radio.
- **Checks:** a radio with more than `max_clients` clients (those whose access point reports
  the WLAN) while another radio of the same site with the same SSID has fewer than
  `idle_clients`.
- **Fix:** band steering or client load balancing, or less transmit power on the busy radio.

## `wifi.client-sticky`

- **Severity:** info
- **Needs:** the observation history. Signalbox records per wireless client the access point and
  the signal (rounded down to 5 dB) every round; without history nothing is reported.
- **Parameters:** `min_dbm` (default -75), `sustained_minutes` (default 30), `margin_db`
  (default 10), scoped by the WLAN.
- **Checks:** a client that has been below `min_dbm` on its current access point for at least
  `sustained_minutes` and was connected to another access point of the same SSID and site, with
  a signal at least `margin_db` stronger, earlier in the history. It is not known whether the
  other access point is in reach now (no 802.11k neighbour report or scan of the client is
  read), so this says "probably sticky". A client that left and came back with the same signal on
  the same access point counts as one stretch.
- **Fix:** turn on 802.11k and 802.11v (BSS transition), set a minimum signal or run usteer or
  dawn.
