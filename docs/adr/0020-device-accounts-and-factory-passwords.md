# 0020. Device accounts and factory passwords: booleans from the configured secret, names on the device page only

Date: 2026-11-24 · Status: accepted

## Context

#175 and #126 want the local accounts of a device (who may log in, with which rights, from
where, when last), whether the device still has its factory password, and what Signalbox's own
login may do, so that least privilege can be checked. Passwords are the most sensitive data
Signalbox touches: it holds the configured secret of every device, some APIs hand out more
(OpenWrt's rpcd configuration holds password hashes, the Omada site device account its
password), and the obvious way to find a default password, trying it, is an active probe that
can lock accounts or wake intrusion detection. Account names are often personal names.

## Decision

- **On the device.** `Device.accounts: list[DeviceAccount] | None` (`None`: not read).
  A `DeviceAccount` is a value without an id: `name`, `privilege` (`admin`, `write`, `read`,
  `other`; `None` where the device does not say), `enabled`, `password_set`, `key_auth`,
  `logins_tracked` with `last_login`, `is_signalbox`, `allowed_from`. Read with `interfaces`
  (`Observation.accounts`, keyed by device id like `log_targets`), no new capability and no
  adapter API version; a controller reports the accounts of its devices (Omada: the site
  device account on each adopted device).
- **No secret survives.** No field holds a password, key or hash, also not `vendor_extra`.
  `Device.default_credentials: bool | None` is computed by the integration in memory: the
  configured secret against `signalbox.factory_defaults` (one module with all factory
  literals, compared in constant time), or taken from the device when it reports its own
  default-password state (FRITZ!Box `X_AVM-DE_IsDefaultPasswordActive`). The OpenWrt reader
  drops rpcd's `password` options on arrival (only "set", "system password" or "none" stays);
  the Omada reader compares the device account's password and forgets it. A contract check
  (`signalbox.testing`) fails when a configured secret or a crypt hash appears anywhere in a
  snapshot.
- **No guessing by default.** Signalbox never tries a default login on its own. The one probe,
  "empty root password" on OpenWrt (#175's open question), is an opt-in device setting
  (`probe_empty_root_password`, advanced, off): one `session.login` as root with an empty
  password per read, the session destroyed at once, nothing changed. Read only: no account is
  ever changed.
- **Least privilege.** `Device.signalbox_account_privilege` is what the configured login may do
  (MikroTik group policies, rpcd ACLs, FRITZ!Box `BoxAdmin` right, OPNsense: a key that can
  read the user manager can change every account, so it is admin), and
  `Device.signalbox_account_needed` the least the integration needs (`Manifest.least_privilege`;
  the runner raises it to `write` for a device with "changes allowed"). The rule compares the
  two, so it stays quiet where no smaller login exists (FRITZ!Box, small switches).
- **Names stay on the device page.** Findings name the device and a count, never an account.
  The runner hands exporters and MQTT the network without accounts
  (`Network.without_account_names`); the booleans and privileges stay.
- **Rules** in `rules/account_checks.py`: `security.default-password` (#126, error),
  `account.signalbox-privileged`, `account.admin-default-name`, `account.no-password`,
  `account.stale` (a history rule).

## Consequences

The OpenWrt read ACL lists the `rpcd` config: Signalbox's login can read the rpcd password
hashes, which it drops at once (an older ACL gives an optional gap, *Fix it* updates it).
OPNsense has no read-only privilege for the user manager, so the documented API user cannot
list accounts and nothing is reported; a key that can, is reported as admin. RouterOS does not
tell whether a user has a password, so `account.no-password` stays quiet there. Several vendor
answers are guesses until a real device confirms them (#21): the FRITZ!Box rights and user
list layouts, the Omada `/users` and `device-account` endpoints, whether rpcd accepts an empty
root password.
