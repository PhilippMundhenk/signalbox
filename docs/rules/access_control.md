<!-- rules of src/signalbox/rules/access_control.py; part of the rules documentation (docs/RULES.md lists all) -->

# Access control

These rules use what devices report about who may use the network (#162, ADR 0030): the RADIUS
servers they know (`Device.radius_servers`) or use for an enterprise SSID (`Wlan.radius`), the
802.1X and port security of a port (`Port.access_control`) and the MAC filter of an SSID
(`Wlan.mac_filter`). Readers: OpenWrt, MikroTik, UniFi, SNMP (ports) and OPNsense (servers: the
user manager and the FreeRADIUS plugin, see below).
Shared secrets and MAC lists are never read. A device that reports nothing is not checked.

## `radius.unreachable`

- **Severity:** warning
- **Checks:** a RADIUS server used for Wi-Fi or 802.1X has a private address that no known
  network (router subnet) contains and no enabled route (other than the default) leads to.
  Quiet for public addresses, host names, and when no subnet is known.
- **Fix:** check the address in the device's settings; add a route when the server is behind
  another router.

## `radius.single`

- **Severity:** info
- **Checks:** an enabled enterprise Wi-Fi network (all its access points together) knows fewer
  RADIUS authentication servers than `min_servers`, or a switch with 802.1X ports reports fewer
  802.1X servers than that. With one server there is no failover: while it is down nobody signs
  in. Quiet where a device does not report its servers.
- **Parameter:** `min_servers` (count, default 2, 1 turns the rule off), settable per scope.
- **Fix:** add a second RADIUS server, on another machine, to the network or the switch.

## `port.dot1x-trunk`

- **Severity:** warning
- **Checks:** a port with 802.1X or MAC authentication is a tagged member of a network (it
  carries several VLANs, so an access point, switch or router hangs on it and cannot
  authenticate as a user).
- **Fix:** turn 802.1X off on the port, or move the device to a port without it.

## `port.dot1x-no-fallback`

- **Severity:** warning
- **Checks:** a port in 802.1X-only mode (not MAC authentication, not "802.1X or MAC") with no
  guest VLAN and no authentication-failed VLAN where at least `min_clients` devices were seen
  that you declared (annotation, expected category) as printer, IoT, camera or media. Such
  devices rarely have an 802.1X supplicant, so they have no network there.
- **Parameter:** `min_clients` (count, default 1), settable per scope.
- **Fix:** allow MAC authentication (MAB) or a guest VLAN on the port, or plug the devices into a
  port without 802.1X.

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

## FreeRADIUS on OPNsense

The OPNsense adapter also reports the FreeRADIUS plugin (`os-freeradius`) as a RADIUS server of
the firewall (`local`, port 1812/1813, purposes Wi-Fi and 802.1X when NAS clients are enabled).
It reads `/api/freeradius/general/get`, `/api/freeradius/service/status` and the NAS clients
(`/api/freeradius/client/search_client`) with the privilege *Services: FreeRADIUS*
(`page-services-freeradius`; granted only where the firewall offers it, the setup is not
changed). The server is reported when it is enabled and not stopped. The shared secret of a NAS
client is only tested for presence (`secret_set`) and never kept; users and their passwords are
not read. No plugin (404): nothing is reported. 403: an optional gap naming the privilege.
Endpoints and field names are a guess until a real device confirms them (#21); the camelCase
spelling of 24.7 and 25.1 is tried as well.
