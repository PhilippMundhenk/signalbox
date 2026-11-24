<!-- rules of src/signalbox/rules/stored_certificates.py; part of the rules documentation (docs/RULES.md lists all) -->

# Certificates stored on devices

These rules read the certificates a device stores for other purposes than its own web interface:
VPN servers, RADIUS, authorities (issue #330). They need an integration that lists them
(MikroTik, OPNsense); a device that does not is not checked. The thresholds are those of
`security.certificate-expiry` (`certificates.warn_days` and `urgent_days`). Only public
certificate data is read; private keys never enter Signalbox.

## `cert.vpn-expiring`

- **Severity:** warning up to `certificates.warn_days` (default 30) before the expiry date,
  error up to `certificates.urgent_days` (default 7) before it and after it
- **Checks:** a certificate the device names in its VPN configuration (MikroTik IPsec identity,
  OpenVPN and SSTP server) is not expired and does not expire soon. Authorities are reported by
  `cert.ca-expiring`. Needs the observation history clock. OPNsense does not say what uses a
  certificate, so it is not reported there.
- **Fix:** renew the certificate on the device and select it again where the VPN uses it.

## `cert.ca-expiring`

- **Severity:** as above
- **Checks:** a certificate authority stored on the device is not expired and does not expire
  soon. The message names how many certificates of the device it issued: they all stop being
  trusted with it.
- **Fix:** create a new authority, sign the certificates again and distribute it before the old
  one expires.
