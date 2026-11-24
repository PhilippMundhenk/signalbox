# MAC address tables

Rules on the forwarding databases (MAC address tables) that devices report (#160, ADR 0016).
They stay quiet for devices that report no table.

## `mac.flapping`

- **Severity:** warning
- **Checks:** a MAC address whose access port (by the device tables) changed 3 or more times in
  the last 24 hours. Counted per observation round. Ignored: wireless ports (roaming between
  access points), uplinks, addresses of network devices, and rounds in
  which a device did not answer or its table was cut off.
- **Fix:** look for a loop in the cabling and turn on spanning tree; check that no two devices
  use the same MAC address and that bonded or virtual NICs are set up consistently.

## `mac.static-stale`

- **Severity:** info
- **Checks:** a static entry in a MAC address table for an address that no device has reported
  for 14 days (or never, once Signalbox has observed for 14 days). Only at sites where a device
  reports clients. Ignored: addresses of network devices and clients that may be unreachable.
- **Fix:** remove the entry if the device is gone; keep it (and mark the client as may be
  unreachable) if the device is rarely on.

## `mac.table-full`

- **Severity:** info
- **Checks:** a device whose MAC address table has 1843 or more entries (90 % of the 2048 that
  Signalbox keeps per device). Beyond the limit entries are dropped, so client placement and
  links found through unmanaged switches may be incomplete.
- **Fix:** check for a loop or a device flooding random addresses.
