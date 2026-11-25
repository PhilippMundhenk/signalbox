<!-- rules of src/signalbox/rules/vpn_tunnels.py; part of the rules documentation (docs/RULES.md lists all) -->

# IPsec and OpenVPN tunnels

These rules read the IPsec connections and OpenVPN instances that integrations report
(OPNsense, MikroTik, OpenWrt for OpenVPN; #153). They stay quiet where a device did not report
what a rule needs: no proposals, no children, no running state. Pre-shared keys, static keys,
private keys and passwords are never read; the findings name the tunnel, never the partner's
gateway address (household data). Expiring certificates of VPN connections are reported by
`cert.vpn-expiring`, not here.

## `vpn.weak-crypto`

- **Severity:** warning
- **Checks:** an enabled IPsec connection whose proposals (phase 1 and child) offer DES or
  3DES, MD5 or SHA1, or a Diffie-Hellman group below `min_dh_group` (14 by default: groups 1, 2
  and 5 are too small); an IKEv1 connection in aggressive mode that does not use certificates
  (the hash of the pre-shared key can be captured and guessed offline); an OpenVPN instance
  whose ciphers include BF-CBC, DES, 3DES, RC2, RC4, CAST5 or IDEA. RouterOS lists algorithms
  per kind, so a weak entry counts whatever it is combined with.
- **Parameter:** `min_dh_group` (ADR 0027), per tunnel scope.
- **Stays quiet** for disabled tunnels, WireGuard, and where the device does not report
  algorithms.
- **Fix:** remove the weak algorithms on both ends (AES-256 or AES-128-GCM, SHA-256 or better,
  group 14 or higher, 19 for elliptic curves); use IKEv2.

## `vpn.tunnel-down`

- **Severity:** warning
- **Checks:** an enabled IPsec connection to a fixed partner gateway with no established IKE
  session (or, where only the children are known, with every child down), and an enabled
  OpenVPN client that is not connected.
- **Stays quiet** for roadwarrior connections (no fixed gateway: idle without clients),
  OpenVPN servers, disabled tunnels, and devices that do not report the running state
  (OpenWrt OpenVPN: configuration only).
- **Fix:** check that the other gateway runs and is reachable, identities, authentication and
  proposals, and the VPN log of the device.

## `vpn.child-down`

- **Severity:** warning
- **Checks:** an IPsec connection that is up (phase 1) with an enabled child (phase 2, policy)
  that is not established.
- **Stays quiet** when the device does not report child states, or the connection is down
  (that is `vpn.tunnel-down`).
- **Fix:** compare the networks (traffic selectors) and phase 2 proposals of both ends.

## `vpn.openvpn-no-tls-auth`

- **Severity:** warning for a server, info for a client
- **Checks:** an enabled OpenVPN instance that uses TLS but has neither `tls-auth` nor
  `tls-crypt` configured.
- **Stays quiet** for static-key tunnels, where the integration does not report it (MikroTik
  has no `tls-auth` option at all), and for disabled instances.
- **Fix:** generate a static key and set it as `tls-crypt` on the server and every client.

## `vpn.selector-overlap-local`

- **Severity:** warning
- **Checks:** a remote network of an IPsec child (traffic selector), or a route an OpenVPN
  client receives, that overlaps a network of the site the device belongs to.
- **Stays quiet** for `0.0.0.0/0` and `::/0`, for OpenVPN servers (their pushed routes are their
  own networks), WireGuard (see `vpn.allowed-ips-overlap`) and when the site's networks are
  not known.
- **Fix:** use different ranges at the two sites, or narrow the networks.

## `vpn.selector-mismatch`

- **Severity:** warning
- **Checks:** both ends of a site-to-site IPsec connection are read (each one's remote gateway
  is an address of the other device) and the local networks of one are not the remote networks
  of the other, or the other way round.
- **Stays quiet** when only one end is read, when either end reports no networks, and for
  disabled or down tunnels.
- **Fix:** make the local networks of each end the remote networks of the other.
