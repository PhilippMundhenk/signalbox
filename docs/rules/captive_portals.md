<!-- rules of src/signalbox/rules/captive_portals.py; part of the rules documentation (docs/RULES.md lists all) -->

# Captive portals

A captive portal is the login page guests see when they join a guest network. Signalbox reads
them (`CaptivePortal`, read-only) from Omada portals, MikroTik hotspots (`/ip/hotspot`),
OPNsense captive portal zones and openNDS or nodogsplash on OpenWrt. A portal says what it
covers (networks, SSIDs), how guests log in (`click-through`, `voucher`, `password`, `radius`,
`external`; unknown where the device does not say) and how long a session lasts. Passwords,
vouchers and RADIUS secrets are never read. The checks use the purpose of a network or SSID
(see [Network purposes](networks.md)) and its isolation; unknown settings are never judged.

## `portal.guest-unprotected`

- **Severity:** info
- **Checks:** an enabled guest SSID that reports client isolation as off, in a network the
  device does not isolate, has no enabled captive portal (named for the SSID or for its
  network). A guest network (VLAN) without any SSID of its own is reported when it is neither
  isolated by the device nor covered by a portal. Guest networks the device reports itself
  (Fritz!Box, Omada guest network) are left alone.
- **Fix:** turn on client isolation, or put a captive portal in front of the network.

## `portal.non-guest-network`

- **Severity:** warning
- **Checks:** an enabled portal covers a network or SSID whose purpose is known and is neither
  `guest` nor `other`. Everybody on it then has to log in first, which locks out printers,
  smart plugs and servers.
- **Fix:** move the portal to the guest network or SSID, or disable it.

## `portal.click-through-open`

- **Severity:** warning
- **Checks:** an enabled portal with click-through login (the guest only accepts the terms)
  covers an SSID that reports client isolation as off, or a network reported as not isolated.
  Not judged: SSIDs that do not report the setting, portals whose login is not known.
- **Fix:** turn on client isolation, or let the portal ask for a password or voucher.
