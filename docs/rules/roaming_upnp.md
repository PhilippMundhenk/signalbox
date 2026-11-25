<!-- rules of src/signalbox/rules/roaming_upnp.py; part of the rules documentation (docs/RULES.md lists all) -->

# Fast roaming and UPnP

Two small checks: fast roaming (802.11r) settings of SSIDs (#90) and UPnP on gateways (#124).
Settings a device did not report are not judged.

## `wifi.roaming`

- **Severity:** info
- **Checks:** per site and SSID with 802.11r on: (1) only one access point broadcasts the SSID,
  so 802.11r has nothing to roam to and keeps some older clients out; (2) 802.11k or 802.11v is
  reported as off on the same SSID, so clients still find the next access point late. A setting
  that was not reported (`None`) is never judged. Access points that set 802.11r differently
  are reported by `wifi.ssid-consistent`. Mobility domains differing between access points:
  `wifi.ft-mobility-domain-mismatch` (#168).
- **Fix:** turn 802.11r off, or enable it on the other access points together with 802.11k
  and v; turn on the missing 802.11k/v.

## `security.upnp`

- **Severity:** warning when UPnP is enabled for a guest, IoT or camera network; info when it
  is enabled elsewhere
- **Checks:** a device reports an enabled UPnP management service (MikroTik `/ip/upnp`,
  Fritz!Box `X_AVM-DE_UPnP`). The networks are the ones the service listens in as the device says,
  otherwise those the gateway has addresses in. Not checked yet: the active port mappings
  (#176) and the OPNsense and OpenWrt adapters.
- **Fix:** turn UPnP off (at least for the guest or IoT network) and add the port forwards you
  need by hand.
