# 0025. Neighbouring Wi-Fi networks: BSSIDs, passive lists always, scans only on request, kept on the server

Date: 2026-11-24 · Status: accepted

## Context

Channel planning without the neighbours is guesswork: in an apartment block the neighbours
decide which channel is usable. A foreign access point that broadcasts one of your SSIDs is an
evil twin or a forgotten old router (#102). #169 asked for the BSSIDs of our own WLANs and for
the access points the radios hear. Two things make this different from other observations:

- Getting the data can disturb the network. A scan (`iwinfo scan` on OpenWrt,
  `/interface/wifi/scan` on MikroTik) takes the radio off its channel; on some drivers the
  clients stall, on MikroTik they are disconnected. Philipp's rule: active probes are optional.
- The data is about other people. Neighbours' SSIDs and BSSIDs can locate a site (public BSSID
  databases), and they are not ours to publish.

## Decision

- **Model.** `Wlan.bssid` (optional). `WifiScanResult` (`<radio id>/scan/<bssid>`, or
  `<device id>/scan/<bssid>` when the device does not say which radio heard it):
  `device_id`, `radio_id`, `bssid`, `ssid` (None: hidden), `band`, `channel`, `width_mhz`,
  `signal_dbm`, `security`, `last_seen`, `kind` (`scan` or `rogue-detection`). A list
  `wifi_scan` on `Observation`, `Snapshot` and `Network`, read with `wireless` (no new
  capability, no adapter API version: an older adapter reports none). At most `SCAN_LIMIT`
  (256) per device, the strongest; one per id.
- **Derived, not stored**: whether a result is ours (its BSSID is one of our WLANs' BSSIDs or
  one of our ports' MACs, `signalbox.neighbours.own_macs`), and per radio the number of
  foreign access points on an overlapping channel and the strongest of them
  (`neighbour_count`, `strongest_foreign_dbm` in `GET /api/network`). The issue's
  `Radio.neighbour_count` field would have to be kept in step with the scan; deriving it in
  one core module keeps the snapshots raw.
- **Passive sources always, scans only on request.** A controller's rogue AP list (Omada) is
  read at every observation: the controller collects it anyway. A scan only runs where the
  user turned on the integration's advanced setting (OpenWrt `scan_neighbours`, off by
  default, documented as an active probe), at every read while it is on. MikroTik's scan
  disconnects clients and is not offered; FRITZ!Box has no TR-064 action for its neighbour
  list. No station of a foreign network is read or stored.
- **Kept on the server.** `GET /api/network` leaves `wifi_scan` out; `GET /api/wifi-scan`
  serves the device page's neighbours list (with `own` and `own_ssid` flags).
  `Network.without_neighbour_networks()` removes them from what exporters and MQTT get. The
  checks' findings, which reach MQTT and exporters, never name a foreign SSID or BSSID (the
  finding key is a hash of the BSSID). Scan results are not in the observation history; they
  live in the latest snapshot only and disappear with the next read that does not report them.
- **Checks.** `wifi.rogue-ssid` (warning): a foreign BSSID with one of our SSIDs at the same
  site; for scans only where every WLAN with that SSID reports its BSSID, and not for a BSSID
  next to one of our MACs (access points derive BSSIDs from their base MAC).
  `wifi.channel-crowded` (info): at least three audible foreign access points on the radio's
  channel, with the least crowded channel it heard. `wifi.ssid-consistent` also compares the
  security an own BSSID announces on the air with its settings.

## Consequences

- With the defaults, only Omada sites with rogue AP detection see neighbours; OpenWrt users
  opt in per device. The channel checks of #172 and these combine: utilisation says the
  channel is busy, the scan says who else is on it.
- An Omada EAP's own BSSIDs are not read (not in the documented API): an OpenWrt scan that
  hears an Omada EAP with our SSID cannot tell it from a twin, so `wifi.rogue-ssid` stays
  quiet for that SSID instead of guessing.
- Hashing foreign BSSIDs in the snapshot (an open question of #169) was not done: the device
  page needs the real BSSID to find the access point, and the snapshot never leaves the
  server.
- A "scan now" button (an on-demand, tracked action) remains open.
