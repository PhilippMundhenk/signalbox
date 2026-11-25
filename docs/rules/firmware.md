<!-- rules of src/signalbox/rules/firmware.py; part of the rules documentation (docs/RULES.md lists all) -->

# Firmware

## `firmware.drift`

- **Severity:** warning
- **Checks:** devices of the same vendor, model and release channel at one site run the same firmware version (a beta device is not compared with stable ones).
- **Fix:** update all of them to the same (newest) version.

## `firmware.update-available`

- **Severity:** info
- **Checks:** a device that reports an available update (OPNsense, MikroTik, ...) runs it.
- **Fix:** read the release notes and update in a maintenance window.

## `firmware.end-of-life`

- **Severity:** warning
- **Checks:** a device whose firmware the integration reports as end of life.
- **Fix:** update to a supported release, or plan to replace the device.

## `firmware.security-update`

- **Severity:** warning
- **Checks:** a device whose vendor flags the available firmware as a security update (`Firmware.security_update`). Replaces `firmware.update-available` for that device.
- **Fix:** read the release notes and update in the next maintenance window.

## `firmware.beta-channel`

- **Severity:** info
- **Checks:** a device that follows or runs a beta, release candidate, testing or development channel (MikroTik, OPNsense development, FRITZ!OS Labs).
- **Fix:** switch to the stable or long-term channel unless testing on purpose.

## `firmware.auto-update-off`

- **Severity:** info
- **Checks:** a device that says it does not install updates by itself: Linux without unattended-upgrades (Debian, Ubuntu) or dnf-automatic (Fedora, RHEL), a FRITZ!Box on "off" or "notify", a UniFi site with automatic device upgrades off. Silent where the device does not say.
- **Fix:** switch on automatic updates (at least security updates), or update by hand regularly.

## `firmware.reboot-pending`

- **Severity:** info
- **Checks:** a device that installed an update and waits for a restart (`/var/run/reboot-required` on Linux, OPNsense's restart flag).
- **Fix:** restart in a maintenance window.
