<!-- rules of src/signalbox/rules/config_state.py; part of the rules documentation (docs/RULES.md lists all) -->

# Configuration state and backups

## `config.unsaved`

- **Severity:** warning
- **Checks:** a device that says its running configuration differs from the saved one (switches that need "save"). RouterOS saves every change at once and is never reported.
- **Fix:** save the running configuration on the device, or revert the change.

## `config.pending`

- **Severity:** warning
- **Checks:** a device with staged changes that are not applied (OpenWrt UCI changes in Signalbox's own ubus session, see the OpenWrt adapter page).
- **Fix:** apply the staged changes, or revert them.

## `backup.none`

- **Severity:** info
- **Checks:** a device that says what backups it keeps and has none (or none newer than 30 days although its configuration changed since), while Signalbox has no backup from the last 30 days either (Signalbox takes one before every change it deploys). Silent for devices that do not say, and while there is no history.
- **Fix:** download a backup from the device, or deploy a change through Signalbox.
