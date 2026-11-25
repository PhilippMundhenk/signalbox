<!-- rules of src/signalbox/rules/certificate_checks.py; part of the rules documentation (docs/RULES.md lists all) -->

# Device HTTPS certificates

These rules read the certificate a device presents for HTTPS (issues #121, #174): core reads it
during the pinning handshake, so every HTTPS integration provides it. Devices without HTTPS
(no certificate read) are not checked. Expiry and key checks apply to the certificate Signalbox
has pinned; a certificate that is not trusted yet is only reported by `cert.renewed`.

## `security.certificate-expiry`

- **Severity:** warning up to `warn_days` (default 30) before the expiry date, error up to
  `urgent_days` (default 7) before it and after it. Both are rule parameters (per device or
  site with `scopes`); the old `certificates.warn_days` / `urgent_days` settings are deprecated
  aliases that set the three expiry rules and log a warning.
- **Checks:** the pinned certificate has not expired and does not expire soon. Signalbox
  ignores the dates when it connects, but browsers, apps and controllers do not. Needs the
  observation history clock; silent without it.
- **Fix:** renew the certificate on the device, then confirm the new fingerprint in Signalbox.

## `cert.weak-key`

- **Severity:** info
- **Checks:** the RSA key has at least 2048 bits and the certificate is not signed with SHA-1
  or MD5. Elliptic-curve and Ed25519 keys are not checked.
- **Fix:** create a new certificate with a strong key and signature on the device, then
  confirm its fingerprint.

## `cert.renewed`

- **Severity:** info
- **Checks:** the device presents another certificate than the pinned one (it was renewed or
  regenerated). Names the expiry dates of the old and new certificate to explain the
  "untrusted certificate" status. Silent for a first certificate (nothing was pinned).
- **Fix:** compare the fingerprint with the device and trust it if the renewal was intended.
