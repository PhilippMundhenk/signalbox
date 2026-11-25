<!-- rules of src/signalbox/rules/health.py; part of the rules documentation (docs/RULES.md lists all) -->

# Device health

These checks read the health values a device reports (uptime, CPU, memory, storage, sensors,
fans, power supplies, UPS; capability `health`). Devices report very different subsets: a check
stays silent for a device that does not report its value. The default thresholds (most can be
changed per site, device or network, see [Parameters](../RULES.md#parameters)):

| Value | Threshold |
| --- | --- |
| Memory in use (programs, without page cache) | 90 % |
| CPU load | 90 % in two consecutive observations |
| Temperature | the sensor's own limit, else 85 °C |
| Storage (system and data) | 90 % (error from 98 %) |
| UPS runtime | 10 minutes |
| UPS self-test | older than 180 days |
| Uptime | 365 days |
| Restarts | in the last 24 hours; 3 or more is a warning |

## `device.resources`

- **Severity:** warning
- **Checks:** a device's memory in use (total minus available: page cache and buffers do not
  count) is below 90 %; its CPU load is not 90 % or more in this and the previous observation
  (a single spike is ignored; needs the history); every temperature sensor is below its own
  limit, or below 85 °C where the device reports no limit. One finding per value.
- **Fix:** memory: restart the device, remove unused packages or features, look for a firmware
  update; CPU: find what keeps it busy (inspection, VPN, logging) or use hardware offloading;
  temperature: give it air, clean its vents, check its fans.

## `health.storage-full`

- **Severity:** warning from 90 %, error from 98 %
- **Checks:** system storage (root, overlay, flash) and data disks are less than 90 % full.
  RAM-backed storage (tmpfs) and storage of unknown kind are not checked.
- **Fix:** remove unused packages, old logs or firmware images, or move logs to another disk.

## `health.fan-failed`

- **Severity:** warning
- **Checks:** no fan is reported as failed by the device. A fan at 0 rpm without the device's
  verdict is not reported: it may be off on purpose.
- **Fix:** clean or replace the fan; keep the device cool until then.

## `health.psu-failed`

- **Severity:** warning
- **Checks:** no power supply is reported as failed (no input or broken). Matters most for
  redundant power supplies, where the device keeps running on the other one.
- **Fix:** check the power cable and the outlet or UPS; replace the power supply if it has power.

## `health.ups-on-battery`

- **Severity:** warning
- **Checks:** a UPS monitored by a device (NUT on OPNsense, MikroTik `/system/ups`) does not run
  on battery.
- **Fix:** check the mains power and the UPS input; shut down devices that are not needed.

## `health.ups-runtime-low`

- **Severity:** warning
- **Checks:** the runtime a UPS reports at its present load is at least 10 minutes.
- **Fix:** replace the battery, or move devices that do not need the UPS to another outlet.

## `health.ups-not-tested`

- **Severity:** info
- **Checks:** the last self-test a UPS reports is not older than 180 days. Silent when it
  reports none, and without a history (no reference time).
- **Fix:** run a self-test and schedule one regularly.

## `health.uptime-very-long`

- **Severity:** info
- **Checks:** a device has restarted within the last 365 days. Firmware updates restart the
  device, so a longer uptime means it has not been updated either.
- **Fix:** check for a firmware update and install it in a quiet hour.

## `device.reboot`

- **Severity:** info for a restart in the last 24 hours, warning for 3 or more
- **Checks:** a device restarted when its boot time (reported, or derived from its uptime)
  moved between two observation rounds. The boot time is recorded rounded to the minute, and a
  move of less than 3 minutes is ignored, so the jitter of a derived boot time is not a restart.
  Restarts the device reports as a firmware update (`upgrade`) or as started by a user (`user`)
  are planned and not counted; power loss, watchdog, crash, other or unknown reasons are. A
  device seen for the first time, and the desired or predicted state of a plan, are not checked.
  Restarts by a Signalbox deployment are not matched yet: the integrations report them as
  `user` or `upgrade` where the device says so.
- **Fix:** if nobody restarted it, check its power supply or PoE budget, its temperature and
  memory use, and look for a firmware update if it crashes.

## `device.replaced`

- **Severity:** info
- **Checks:** a device reports another serial number or another base MAC address than at an
  earlier observation round (recorded in the history, per device and per value). A value the
  device did not report in a round is not a change, and neither is a value reported for the
  first time. Reported for 7 days after the change, with the end of the old and the new value
  (the last four characters): findings reach notifications, and serial numbers and base MACs
  are not shared unless `exports.identity` is set (#427).
- **Fix:** if you replaced the device, nothing to do; otherwise check who swapped it. Acknowledge
  the finding once you have seen it.
