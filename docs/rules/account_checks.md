<!-- rules of src/signalbox/rules/account_checks.py; part of the rules documentation (docs/RULES.md lists all) -->

# Device accounts and factory passwords

These rules read the local accounts of a device, whether the login Signalbox uses is a factory
default, and what that login may do (issues #126, #175, [ADR 0020](../adr/0020-device-accounts-and-factory-passwords.md)).
Signalbox never stores, logs or exports a password, key or hash: the integration compares the
configured secret with a list of factory defaults in memory, and only the boolean is kept.
Signalbox never tries a login of its own to find a default password; the only probe (an empty
root password on OpenWrt) is off unless enabled per device. Account names are often personal
names: findings name the device and a count, the device page shows which accounts are meant.
Exporters and MQTT never get the accounts.

## `security.default-password`

- **Severity:** error
- **Checks:** the login Signalbox was given is the vendor's documented default (NETGEAR Plus
  `password`, TP-Link Easy Smart `admin`/`admin`, the Omada site device account
  `admin`/`admin`, MikroTik `admin` without a password, OpenWrt `root` without a password), or
  the device says itself that its default password is still active (FRITZ!Box,
  `X_AVM-DE_IsDefaultPasswordActive`). On OpenWrt the setting `probe_empty_root_password`
  (advanced, off by default) also tries one login as root with an empty password at every read.
- **Fix:** change the password on the device (its manual describes how), then update it in the
  device settings of Signalbox.

## `account.signalbox-privileged`

- **Severity:** info
- **Checks:** Signalbox's login may do more than the read-only login of the integration's setup
  guide (MikroTik: [a read-only user group](../adapters/mikrotik.md#a-read-only-user-group),
  OpenWrt: [read-only user](../adapters/openwrt.md#read-only-user-on-the-device), OPNsense:
  [a least-privilege API user](../adapters/opnsense.md#a-least-privilege-api-user)). A device
  with "changes allowed" is compared with a login that may write. Quiet where the integration
  has no smaller login (FRITZ!Box: "FRITZ!Box settings" is needed; NETGEAR and TP-Link switches
  have one login).
- **Fix:** set up the read-only login of the guide and give it to Signalbox instead.

## `account.admin-default-name`

- **Severity:** info
- **Checks:** an enabled administrator account named `admin` (or `administrator`) that logs in
  with a password, on a device whose management address is in a network with clients or Wi-Fi.
- **Fix:** create an administrator account with a name of your own and disable or delete the
  default one (or rename it, where the device allows).

## `account.no-password`

- **Severity:** warning
- **Checks:** an enabled account without a password that does not log in with a key only.
  Where the device says it: OpenWrt rpcd logins without a `password` option, the Omada site
  device account. (RouterOS does not say whether a user has a password.)
- **Fix:** set a password for the accounts marked on the device page, or delete them.

## `account.stale`

- **Severity:** info
- **Checks:** an enabled administrator account (not Signalbox's own) that did not log in for
  90 days, or never while Signalbox has known the device for 90 days. Only for devices that
  report login times (MikroTik `last-logged-in`). Needs the observation history clock.
- **Fix:** disable or delete the accounts nobody needs.
