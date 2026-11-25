# 0031. SSH host keys are pinned per device; a changed key stops the run and warns

Date: 2026-11-25 · Status: accepted

## Context

*Set up automatically* (ADR 0009) and *Fix it* (ADR 0012) send the admin password over SSH for
OpenWrt, OPNsense (its optional SSH step), Linux, EdgeOS/VyOS and MikroTik (the remedy that
uses SSH). `PinnedSsh` already compares the presented host key with the fingerprint the user
confirmed inside the key exchange, before any credential is sent. But the confirmation was not
kept: every run showed "The device presented this SSH host key" again, also for a device whose
key had been confirmed the day before. Asking every time trains users to click through the one
prompt that protects the admin password, and a key that really changed looked exactly like a
first contact (#526).

## Decision

- **A pin per device, apart from the certificate.** The store (schema 10) keeps the confirmed
  SSH host key per device in its own table `ssh_host_keys`: the `SHA256:` fingerprint as
  `ssh-keygen -l` shows it, the negotiated algorithm (reported by `PinnedSsh` through the context
  variable `presented_host_keys`), when it was confirmed and by what (`setup`, `fix:<remedy>`,
  `retrust`). Replaced and forgotten pins stay in the same table with `retired_at`, as the
  history. The HTTPS certificate pin (`devices.pinned_fingerprint`, ADR 0019) is unchanged; a
  read over SSH (Linux, EdgeOS) still pins its key there in hex, as before.
- **First contact is trust on first use, unchanged.** The plan without a password shows the
  presented key and nothing is sent until the user confirms it. A run with the confirmed key
  stores it as the pin of the stored device (after the save, for a new one) once the run saw
  that key in a handshake.
- **The pin replaces the prompt.** The plan answers how each presented SSH key compares with the
  pin (`host_key` / `ssh_host_key`: `new`, `known` or `changed`). With `known` the UI skips the
  confirmation and the step list says "SSH host key as confirmed on <date>". The server does not
  trust the UI for this: the run itself still connects with the pin, so a key that changed in
  between is refused in the handshake.
- **A changed key stops before the password.** The core checks before calling the adapter: a run
  whose confirmed key is not the device's pin is refused (409 `host_key_changed`) and the adapter
  never runs, so no password leaves Signalbox. A handshake that meets another key than the pin
  (plan, run or a read over SSH) records the change (`ssh_host_key_changes`) and answers with the
  old key, the new key and the date of the pin. The UI shows this as its own, prominent error,
  not as a first contact.
- **Re-trust is explicit and names the key.** `POST /api/devices/{id}/ssh-host-key/trust` takes
  the full new fingerprint and only accepts the key the device presented last; the old pin moves
  to the history. Trusting the changed read pin of a Linux or EdgeOS device in the device form is
  the same decision and updates the SSH pin too. `DELETE /api/devices/{id}/ssh-host-key` forgets
  the pin for a deliberate reset; the next contact is a first contact again. Removing a device
  removes its pins and their history.
- **A finding while it lasts.** `ssh.host-key-changed` (warning) reads
  `Device.ssh_host_key_change`, which core fills from the store, until the key is re-trusted or
  forgotten; acknowledging the finding hides it as for every finding.
- **Fix all** fetches every device's identity first: devices with a known key need no comparing,
  new ones are compared as before, a device whose key changed is shown with the warning and left
  out of the run (its key can be re-trusted there by name, which fetches the identities again).
  The job refuses an item whose confirmed key is not the pin before anything runs.
- **The admin login stays as in ADR 0009:** used once, never stored or logged. Fingerprints are
  public and may appear in answers, findings and logs.

## Consequences

The prompt only appears on the first contact, after *Forget*, and as a warning when the key
changed, so it means something when it appears. Integrations change nothing: the core compares
the fingerprints the plans already return, so every adapter that sets up or fixes over SSH is
covered, MikroTik included. Only the key the server negotiates first (Ed25519, then ECDSA, then
RSA, `HOST_KEY_ALGS`) is pinned; a device that drops that key type looks like a changed key (see the addendum).
The HTTPS certificate prompt of OPNsense and MikroTik is not part of this decision (see the addendum).

## Addendum (2026-11-25, #535): the certificate pin for setup and Fix it; every key type

- **One certificate pin, no second store.** Setup, *Fix it* and *Fix all* over HTTPS (OPNsense,
  MikroTik and every integration whose admin step uses HTTPS) compare the presented certificate
  with the pin the device's read connection already keeps (`devices.pinned_fingerprint`, ADR
  0019), not with a pin of their own: it is the same certificate on the same address, and two
  pins of one certificate could disagree. The plan answers `host_key` with `kind:
  "certificate"` and `new` (no stored device or nothing pinned: compare and confirm as before),
  `known` (no prompt; the steps say "Certificate as trusted on <date>", the date of
  `pinned_since`, without a date for a pin older than that column) or `changed`.
- **A changed certificate uses the existing change flow.** It is recorded as the certificate
  waiting to be trusted (`pending_fingerprint`), exactly as a reading records it, and the
  device is read again, so the findings are those a reading gives (`signalbox.read` with "not
  trusted", `cert.renewed` while the old one is known). A run whose confirmed certificate is not
  the pin is refused before the adapter is called (409 `certificate_changed`, old and new
  fingerprint and the date of the pin), as is a run whose handshake meets another certificate;
  no API key or password leaves Signalbox. The UI shows the same prominent warning as for an SSH
  host key.
- **Re-trust is the existing endpoint, by name.** `POST /api/devices/{id}/trust` takes the full
  new fingerprint and only accepts the one the device presented last; the warning's button
  names it. The pin it replaces goes to the history (store schema 11, `certificate_pins`:
  fingerprint, since when it was trusted, when and by what it was replaced), shown on the device
  page's certificate card and removed with the device. There is no *Forget* for certificates:
  a device without a certificate pin cannot be read over HTTPS at all.
- **Every SSH host key type is pinned at the first trust.** Signalbox still negotiates Ed25519
  first. When the presented key is `new`, the plan also fetches the device's other key types
  (ECDSA, RSA) in key exchanges of their own, without a login, from the address the presented
  key came from, and lists them under the key to confirm; after the run that saw the confirmed
  key they are stored with it (`ssh_host_keys.offered`, one key per type). A later handshake with
  any of these keys is `known`, so a device that drops Ed25519 is not taken as changed; any
  other key, also one of a pinned type, is a change as before. The other types are trusted on
  the same basis as the confirmed key (shown, first contact), not proven by the device; the
  OpenSSH `hostkeys-prove` extension would prove them but is offered only by OpenSSH and only
  after a login, so it is not used.
- **What is not covered.** Pins confirmed before this addendum, and a re-trust by name, hold
  only the one key: re-trust names one key, and the other types of the old pin go to the
  history; *Forget* and the next setup pin all types again. The other types live in memory
  between the plan and the run, so after a restart in between only the confirmed key is
  pinned. A read over SSH (Linux, EdgeOS) still pins one key in hex in `pinned_fingerprint`.
