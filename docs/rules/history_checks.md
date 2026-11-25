<!-- rules of src/signalbox/rules/history_checks.py; part of the rules documentation (docs/RULES.md lists all) -->

# History

These checks use the observation history (issue #185): after every observation round Signalbox
records when each device, client and port was first and last seen, the device status and the
link state, the network of each client, and per device its boot time (rounded to the minute,
with the reboot reason) and whether its CPU load was high. Changes are kept as events. Everything is deleted
after `history.days` (default 30, see [CONFIGURATION.md](../CONFIGURATION.md)); client sightings
are a presence log and are never exported over MQTT. The checks stay silent while the history
is too short, and on the desired or the predicted state of a plan (which have no history).

## `device.down-long`

- **Severity:** warning after one hour, error after 24 hours
- **Checks:** a device that is unreachable or refuses the login, with how long it has not
  answered and when it was last read (or, if it never answered, when Signalbox first saw it).
  The per-round `signalbox.read` finding stays; this one adds the duration. Disabled devices
  are not checked, nor is an unreachable device annotated `may_be_unreachable` (a login that
  is refused is still reported).
- **Fix:** check power, cabling, address and password; remove or disable the device in
  Signalbox if it was replaced or retired.

## `device.flapping`

- **Severity:** warning
- **Checks:** a device that stopped answering (ok or partial to unreachable, login refused or
  untrusted certificate) at least 3 times in the last 24 hours.
- **Fix:** check its power supply or PoE budget, its temperature and its uplink cable.

## `port.flapping`

- **Severity:** warning for a port on a link between network devices; info for other ports
- **Checks:** an Ethernet port or LAG whose link went down at least 3 times in the last 24
  hours. The link state is taken from each observation round, so only losses that last until a
  round are seen. Wireless and virtual interfaces are ignored. Error counters are checked by
  `port.errors`.
- **Fix:** replace or re-terminate the cable, check the connectors, keep auto-negotiation on
  both ends. A computer that sleeps and wakes often also causes this (info).

## `dhcp.stale-reservation`

- **Severity:** info
- **Checks:** a DHCP reservation whose MAC address was not seen as a client during the whole
  history period (`history.days`). Checked only once Signalbox has observed the network for that
  long, and only at sites where a device that reports clients answered and reported them in this
  round. To look further back, raise `history.days`. A reservation for a MAC address annotated
  `may_be_unreachable` is not reported.
- **Fix:** remove the reservation if the device is gone. A device that is rarely on keeps it;
  turn the rule off if needed.

## `clients.network-changed`

- **Severity:** info
- **Checks:** a client that moved to another network (VLAN, or another site) in the last 7
  days, with the time of the move. Ignored: randomised MAC addresses, clients that moved 3 times
  or more in that week (they roam between networks by design), and moves seen while a device
  did not answer or did not report its clients (another device may know the client less well),
  and clients with an expected network (`clients.unexpected-network` covers those). A client
  without a merged network gets the one all devices that saw it agree on (`Client.sightings`),
  else the VLAN a switch learned it in (MAC address table);
  the finding names the port it is behind.
- **Fix:** if this was not intended, check the SSID it joined, or the switch port it is plugged
  into and that port's VLAN.
