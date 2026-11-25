<!-- rules of src/signalbox/rules/device_identity.py; part of the rules documentation (docs/RULES.md lists all) -->

# Device identity

These checks read the identity a device reports about itself (#177, #444): its hostname and its
boot loader. A check stays silent for a device that does not report the value. Serial numbers
and base MAC addresses are never part of a finding and stay out of exports and support bundles
unless `exports.identity` is on (#439).

Related: the duplicate-device check (#118) compares management addresses and MACs of configured
devices, and the unknown-neighbour check (#113) compares LLDP chassis ids with them. Both are
separate rules (see their own pages); this page covers the hostname and boot loader checks only.

## `device.name-mismatch`

- **Severity:** info
- **Checks:** the name in Signalbox differs from the hostname the device reports. Case and a
  domain suffix are ignored (`nas` equals `NAS.example.lan`); parameter `strip_domain` (0)
  compares the full names. Devices that run on another device (`hosted_on`) and names that are
  addresses are not compared.
- **Fix:** rename the device in Signalbox or on the device so both agree, or ignore the finding.

## `device.bootloader-outdated`

- **Severity:** info
- **Checks:** the boot loader version a device runs is older than the one its installed
  firmware carries. Read from RouterOS (RouterBOOT `current-firmware` against `upgrade-firmware`,
  both present on RouterOS 6.4x and 7). Other adapters report no available boot loader version
  yet, so they are not judged.
- **Fix:** upgrade the boot loader in a maintenance window (RouterOS: `/system routerboard
  upgrade`, then restart).
