<!-- rules of src/signalbox/rules/wireless.py; part of the rules documentation (docs/RULES.md lists all) -->

# Wi-Fi

## `wifi.ssid-consistent`

- **Severity:** error for security mode, passphrase and network (VLAN); warning for protected
  management frames (PMF), hidden setting, the roaming settings 802.11r, k and v, and client
  isolation
- **Checks:** a Wi-Fi network (SSID) broadcast by several access points of one site has the same
  settings on all of them. One finding per differing setting names the value per access point;
  passphrases are compared only by a fingerprint and the finding says just "passphrase differs"
  and which access points belong together. Settings a device did not report are not compared.
  The same SSID at different sites is checked per site (networks are per site). Where a scan
  or a rogue AP list heard one of your own BSSIDs (#169), the security it announces on the air
  is compared with what its device reports (a warning per WLAN): a change not applied yet, or
  firmware that falls back to another mode.
- **Fix:** set the same value for that setting on every access point; for the security on the
  air, check the access point's settings.

## `wifi.country`

- **Severity:** warning
- **Checks:** every enabled radio has a country code, and all radios of a site use the same one
  (compared case-insensitively).
- **Fix:** set the country code of the country the site is in on every radio.

## `wifi.channel-overlap`

- **Severity:** warning
- **Checks:** two enabled radios on different access points of the same site and band do not
  use overlapping channels. Signalbox does not know which access points hear each other, so
  every pair at a site counts as neighbours.
  - 2.4 GHz: channels overlap if they are less than 5 apart (1, 6 and 11 do not overlap); the
    channel width is ignored.
  - 5 and 6 GHz: a radio occupies the aligned block of 20 MHz channels of its width (20 MHz if
    not reported) in the standard channel plan (5 GHz blocks start at 36 and at 149, 6 GHz at
    1); radios overlap if their blocks share a 20 MHz channel. Where a radio reports the centre
    of its channel (#172) and the span around it contains its channel, that span is used. For example 36 at 80 MHz
    occupies 36-48 and overlaps 44 at 20 MHz but not 52 at 80 MHz.
- **Fix:** move one access point to a channel that does not overlap, or use a narrower width.

## `wifi.segment-at-gateway`

- **Severity:** error
- **Checks:** a Wi-Fi network bound to a VLAN uses a network for which a router has a subnet
  (a subnet marked as the gateway, or any subnet of a device with the gateway role).
  If no router at the site reported its subnets, the check is incomplete. A network a router
  keeps to itself is served by that router and not reported: isolated by the device, no subnet
  in the model, and every SSID in it on a device with the gateway role (the Fritz!Box guest
  Wi-Fi, which has its own addresses that TR-064 does not expose).
- **Fix:** create the VLAN with an address and DHCP on the router, or bind the SSID to a network
  that exists there.
