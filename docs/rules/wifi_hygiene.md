<!-- rules of src/signalbox/rules/wifi_hygiene.py; part of the rules documentation (docs/RULES.md lists all) -->

# Wi-Fi hygiene

These rules look at single access points and radios; the rules under *Wi-Fi* compare access
points with each other. Disabled radios and SSIDs are skipped, and so are values a device did
not report (automatic channel, width or power).

## `wifi.6ghz-security`

- **Severity:** error
- **Checks:** every SSID on a 6 GHz radio uses WPA3 (personal or enterprise) or Enhanced Open
  (OWE). WPA2, WPA2/WPA3 transition mode and open networks are not allowed on 6 GHz and clients
  do not join them there. Protected management frames, which 6 GHz requires too, are checked by
  `wifi.pmf`.
- **Fix:** on 6 GHz use WPA3 only (or OWE) with PMF required; keep transition mode on 2.4 and
  5 GHz if old devices need it.

## `wifi.pmf`

- **Severity:** error for WPA3 (personal or enterprise) and OWE without PMF *required*; warning
  for WPA2/WPA3 transition mode with PMF *disabled*
- **Checks:** the protected management frames (PMF, 802.11w) setting matches the security mode.
  WPA2 and open networks are not checked. One finding per access point and SSID.
- **Incomplete:** the device did not report PMF for a WPA3, OWE or transition-mode SSID.
- **Fix:** set PMF to required (WPA3, OWE) or at least optional (transition mode).

## `wifi.hidden`

- **Severity:** info
- **Checks:** no enabled SSID is hidden. One finding per SSID and site. A hidden SSID that both
  ends of a wireless link broadcast (a mesh or bridge backhaul) is skipped.
- **Fix:** hiding adds no security; consider broadcasting the SSID and relying on WPA2/WPA3.

## `wifi.ssid-count`

- **Severity:** warning
- **Checks:** a radio broadcasts at most four SSIDs (three on 2.4 GHz). Hidden SSIDs count too,
  they send beacons as well.
- **Fix:** merge SSIDs or turn off the ones you do not need.

## `wifi.channel-width`

- **Severity:** warning for a 2.4 GHz radio wider than 20 MHz; info for 160 MHz on 5 GHz or
  320 MHz on 6 GHz at a site with more than one access point on that band
- **Checks:** channel widths fit the band and the number of access points. Radios with an
  unknown width are skipped.
- **Fix:** use 20 MHz on 2.4 GHz; 80 MHz on 5 GHz (160 MHz or less on 6 GHz) with several
  access points.

## `wifi.24-channel-plan`

- **Severity:** info
- **Checks:** a 2.4 GHz radio uses channel 1, 6 or 11. Where the country code allows channel 13
  (any reported code except US and CA), 5, 9 and 13 of the plan 1, 5, 9, 13 are accepted too.
  Radios on automatic channel selection are skipped. `wifi.channel-overlap` compares your own
  access points; this rule is about the neighbours.
- **Fix:** use channel 1, 6 or 11.

## `wifi.dfs`

- **Severity:** info
- **Checks:** a 5 GHz radio uses a radar (DFS) channel (52-144), or a width that reaches into
  them (for example 36 at 160 MHz occupies 36-64). The access point then waits up to ten minutes
  for radar after a start and leaves the channel when it detects one. Turn the rule off if you
  use DFS on purpose.
- **Fix:** if clients lose Wi-Fi now and then, try channels 36-48 or 149-165.

## `wifi.tx-power`

- **Severity:** info
- **Checks:**
  - on one access point, the 2.4 GHz radio does not send more than 3 dB louder than its 5 GHz
    radio, where both broadcast the same SSID;
  - at one site, the radios of one band on different access points are within 6 dB of each
    other.
  Radios with automatic or unreported power are skipped. The maximum power of a radio is not
  known, so "every radio at maximum power" is not checked.
- **Fix:** lower 2.4 GHz to about 3-6 dB below 5 GHz; bring the access points within about
  6 dB of each other, usually by lowering the loud one.

## `wifi.ssid-coverage`

- **Severity:** info
- **Checks:** at a site with several access points, an SSID is broadcast by every access point
  that has a radio for its bands, and on every band where another access point offers it (if
  the access point has a radio for that band). Sites with one access point are skipped. SSIDs in
  a desired state are compared by `drift.wlan` as well.
- **Fix:** add the SSID to the access points or bands named in the finding, or turn the rule
  off if a network is meant to cover only part of the site (for example a guest network).

## `wifi.segment-weakest-link`

- **Severity:** error when an open or OWE SSID puts clients into the same network (VLAN) as a
  password- or enterprise-protected SSID; info for password-protected SSIDs with different
  passwords on one network
- **Checks:** all SSIDs that share a network are equally protected. Two SSIDs with the same
  security and password (for example a 2.4 GHz-only SSID for IoT devices) are fine. An SSID that
  has different passwords on different access points is left to `wifi.ssid-consistent`.
- **Incomplete:** an open or OWE SSID whose network is not reported, at a site with a protected
  SSID.
- **Fix:** move the weaker SSID to its own network (VLAN), for example a guest network.

## `wifi.default-ssid`

- **Severity:** warning; error when the SSID is also open
- **Checks:** no enabled SSID has a vendor's factory name: `OpenWrt`, `LEDE`, `MikroTik-XXXXXX`,
  `FRITZ!Box ...`, `FRITZ!Repeater ...`, `TP-Link_XXXX`, `NETGEARxx`, `Omada_XXXXXX`, `dlink`,
  `ASUS`, `Linksys12345`, `ubnt`, `Xiaomi_XXXX`, `Tenda_XXXXXX` (whole name, case-insensitive).
- **Fix:** set up the access point (own SSID and password) or turn the radio off.
