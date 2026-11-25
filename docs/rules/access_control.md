<!-- rules of src/signalbox/rules/access_control.py; part of the rules documentation (docs/RULES.md lists all) -->

# Access control

These rules use what devices report about who may use the network (#162, ADR 0030): the RADIUS
servers they know (`Device.radius_servers`) or use for an enterprise SSID (`Wlan.radius`), the
802.1X and port security of a port (`Port.access_control`) and the MAC filter of an SSID
(`Wlan.mac_filter`). Readers: OpenWrt, MikroTik, UniFi, SNMP (ports) and OPNsense (servers).
Shared secrets and MAC lists are never read. A device that reports nothing is not checked.

## `radius.unreachable`

- **Severity:** warning
- **Checks:** a RADIUS server used for Wi-Fi or 802.1X has a private address that no known
  network (router subnet) contains and no enabled route (other than the default) leads to.
  Quiet for public addresses, host names, and when no subnet is known.
- **Fix:** check the address in the device's settings; add a route when the server is behind
  another router.

## `port.dot1x-trunk`

- **Severity:** warning
- **Checks:** a port with 802.1X or MAC authentication is a tagged member of a network (it
  carries several VLANs, so an access point, switch or router hangs on it and cannot
  authenticate as a user).
- **Fix:** turn 802.1X off on the port, or move the device to a port without it.

## `wifi.mac-filter-as-security`

- **Severity:** info
- **Checks:** an enabled, open Wi-Fi network (not a mesh backhaul) has a MAC allow-list. MAC
  addresses are visible on air and easy to copy, and an open network is not encrypted anyway.
- **Fix:** use WPA2 or WPA3 (or WPA-Enterprise); keep the filter only as an extra.

## `wifi.enterprise-consistent`

- **Severity:** warning
- **Checks:** enabled WPA-Enterprise networks with the same SSID in one site name different sets
  of RADIUS authentication servers (address and port; port 1812 where the device does not say).
- **Fix:** give every access point of the network the same servers.
