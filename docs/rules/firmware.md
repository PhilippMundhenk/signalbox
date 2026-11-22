<!-- rules of src/signalbox/rules/firmware.py; part of the rules documentation (docs/RULES.md lists all) -->

# Firmware

## `firmware.drift`

- **Severity:** warning
- **Checks:** devices of the same vendor and model at one site run the same firmware version.
- **Fix:** update all of them to the same (newest) version.

## `firmware.update-available`

- **Severity:** info
- **Checks:** a device that reports an available update (OPNsense, MikroTik, ...) runs it.
- **Fix:** read the release notes and update in a maintenance window.

## `firmware.end-of-life`

- **Severity:** warning
- **Checks:** a device whose firmware the integration reports as end of life.
- **Fix:** update to a supported release, or plan to replace the device.
