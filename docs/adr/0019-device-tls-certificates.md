# 0019. The device certificate is read by core and belongs to the device

Date: 2026-11-24 · Status: accepted

## Context

#174 and #121 need the certificate a device presents: expiry, issuer, key strength, and a hint
that a device just regenerated it (which explains an "untrusted certificate" status). Every HTTPS
integration already probes it in `DeviceHttp` for pinning, but only kept the fingerprint. Adapters
should not each parse certificates.

## Decision

- **Core reads it.** `DeviceHttp` reports the DER bytes of every probe to a *certificate sink*
  (`signalbox.certificates`, a context variable) that `Adapter.observe` opens around the whole
  observation. The adapter base turns the first certificate into `Device.certificate`
  (`CertificateInfo`); integrations change nothing and cannot get it wrong. Also an untrusted
  certificate is described (`trusted: false`), so the UI can show what the user is asked to trust.
- **On the device.** One optional `CertificateInfo`, not a separate object: a device has one
  management certificate. Certificates stored on devices for other purposes (VPN, RADIUS, CA)
  are a follow-up (#330) with their own objects.
- **From the inventory.** `pinned_since` is a column of the device record (store schema 7), set
  when the fingerprint is trusted. The runner copies it into the snapshot.
- **Renewal memory.** While a device presents another certificate than the pinned one, the runner
  copies the previously pinned certificate's fingerprint and expiry from the stored snapshot into
  `previous_*` (and keeps them while the status stays untrusted). Trusting the new one clears them.
  No extra table: the snapshot of the failed read already exists.
- **Thresholds.** `warn_days` / `urgent_days` (30 / 7) are parameters of the expiry rules
  (ADR 0027, #441); they first reached the rules through `Network.certificate_*_days`
  (removed), and `certificates.*` in the configuration is a deprecated alias.
- **Recordings** do not contain the certificate: the replay generates its own.

## Consequences

A certificate is only known after a read that got as far as the TLS handshake; a device that is
unreachable keeps its last snapshot's certificate out of the new one (the card is empty).
Devices read over plain HTTP or non-HTTP protocols have none, and the rules stay quiet.
