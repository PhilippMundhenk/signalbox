<!-- rules of src/signalbox/rules/wifi_neighbours.py; part of the rules documentation (docs/RULES.md lists all) -->

# Neighbouring Wi-Fi networks

These rules use the access points your radios heard (#169, ADR 0025): a controller's rogue AP
list (Omada), or a scan you turned on in the device's settings (OpenWrt `scan_neighbours`, an
active probe, off by default). Without scan results they stay quiet.

Neighbours' SSIDs and BSSIDs are other people's data: the findings never name a foreign BSSID
or SSID, because findings reach MQTT and exporters. The device page's neighbours list shows
them, marked when they use one of your names.

## `wifi.rogue-ssid`

- **Severity:** warning
- **Checks:** an access point that is not yours broadcasts one of your SSIDs at the same site.
  It is yours when its BSSID is the BSSID of one of your WLANs or the MAC of one of your ports.
  For scan results it is only compared where every access point of yours with that SSID
  reports its BSSID, and a BSSID close to one of your MACs (same bytes 2 to 5, last byte within
  16, the locally administered bit ignored) counts as yours: access points derive their BSSIDs
  from their base MAC. A controller's rogue AP list already leaves out the access points it
  manages. The message says when the foreign one is an open network (or Enhanced Open).
- **Fix:** find it in the neighbours list of the device that heard it (signal and channel help
  to locate it). An old router or repeater of yours: switch it off or add it to Signalbox. Not
  yours: it may be an evil twin; rename your network or ask its owner to, and make sure your
  devices use WPA3, or WPA2 with protected management frames.

## `wifi.channel-crowded`

- **Severity:** info
- **Checks:** a radio heard at least 3 foreign access points stronger than -80 dBm (or
  without a signal value) on a channel overlapping its own: on 2.4 GHz less than 5 channels
  apart, on 5 and 6 GHz sharing a 20 MHz channel of the width's block. Where the radio also
  reports its channel utilisation (#172), the message names it; wifi.channel-busy reports the
  utilisation itself.
- **Fix:** where the radio heard a channel with fewer foreign access points (on 2.4 GHz 1, 6
  or 11; on 5 GHz a supported channel without radar detection, else 36-48 and 149-161), move
  there or turn on automatic channel selection. Otherwise use a narrower channel, or on 2.4 GHz
  move clients to 5 or 6 GHz.
