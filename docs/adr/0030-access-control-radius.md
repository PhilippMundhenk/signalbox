# 0030: Port access control, MAC filters and RADIUS servers (#162)

## Context

Small offices start to use WPA-Enterprise (often with the gateway as RADIUS server) and 802.1X
on desk ports. When the RADIUS server cannot be reached nothing connects, and a MAC filter on an
open SSID gives a false sense of security. RADIUS shared secrets and MAC address lists are
sensitive.

## Decision

- **`Port.access_control: PortAccessControl | None`**: mode (open, 802.1X, MAC authentication,
  both, static MACs), `max_macs`, `sticky`, `violation`, `guest_vlan`, `auth_fail_vlan`,
  `state` (authorised or not) and `dynamic_vlan`. `None` is "not reported".
- **`Wlan.mac_filter: MacFilter | None`** (mode and the *number* of entries, never the
  addresses), **`Wlan.radius: RadiusRef | None`** (authentication and accounting servers of an
  enterprise SSID, `secret_set`) and **`Wlan.dynamic_vlan`**.
- **`Device.radius_servers: list[RadiusServer] | None`**, filled like `multicast`
  (`Observation.radius_servers` per device id, read with `interfaces` or `wifi`): name, address,
  ports, purposes (Wi-Fi, 802.1X, VPN, login), `secret_set`, `local`. Nested in the device rather
  than a top-level object type: nothing refers to a server by id, and the entries never leave
  their device.
- **Secrets are never read into the model**: a reader turns the shared secret into a bool at
  once. No fingerprint is kept either: unlike a Wi-Fi passphrase (compared across access
  points) nothing needs to compare RADIUS secrets, and a fingerprint of a short secret helps
  an offline guess. `signalbox.testing` fails a contract test when a simulator's secret
  (marker `do-not-leak`) appears in a snapshot.
- Readers: OpenWrt (hostapd options of `wifi-iface`), MikroTik (`/radius`, `dot1x/server`,
  bridge port `learn`, wifi access list), UniFi (`radiusprofile`, port profile `dot1x_ctrl`,
  `wlanconf` MAC filter), SNMP (IEEE8021-PAE-MIB) and OPNsense (the authentication servers of
  type RADIUS). Writes are left for later.

## Consequences

- The checks (`radius.unreachable`, `port.dot1x-trunk`, `wifi.mac-filter-as-security`,
  `wifi.enterprise-consistent`) work on what is reported; a device that reports nothing is not
  checked.
- Field names of UniFi, the OPNsense endpoint and MikroTik's MAC filter semantics are guesses
  until checked on a real device (#21).
- Omada, ProSAFE and the Fritz!Box are not read (Omada is another helper's, #501).
