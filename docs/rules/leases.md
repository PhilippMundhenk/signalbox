<!-- rules of src/signalbox/rules/leases.py; part of the rules documentation (docs/RULES.md lists all) -->

# DHCP leases, options and relays

These rules use the lease table, the classless routes and the relays that devices report. A
network whose DHCP server did not report its leases is skipped: without the table, "no lease"
means nothing.

## `dhcp.static-in-pool`

- **Severity:** warning
- **Checks:** a client whose address lies inside a DHCP pool of its network, and that either
  is known to use a fixed address (address source `static`) or has no active lease for it.
  Only networks where every enabled DHCP server reported its leases are checked. Silent for
  an expired lease that ended less than one lease time before the lease table was read, for a
  reservation, an offered or reserved lease, and for clients annotated with the expectation
  "uses a static address".
- **Fix:** give the device a reservation, or a fixed address outside the pool; or mark it as
  using a static address on purpose.

## `dhcp.declined`

- **Severity:** warning
- **Checks:** no enabled DHCP server has declined leases (a client found the offered address
  already in use: an address conflict on the network).
- **Fix:** find the device that uses the address, move it outside the pool or give it a
  reservation, then clear the declined lease.

## `dhcp.option-121-without-router`

- **Severity:** warning
- **Checks:** a DHCP server that hands out classless static routes (option 121) includes a
  default route 0.0.0.0/0. Clients that get option 121 ignore the router option (RFC 3442).
- **Fix:** add 0.0.0.0/0 via the router to the routes, or remove them.

## `dhcp.relay-target-missing`

- **Severity:** warning
- **Checks:** every enabled DHCP relay forwards to the address of a device with an enabled DHCP
  server, and has at least one target.
- **Incomplete:** the target is not a device Signalbox knows, or its DHCP servers could not be
  read.
- **Fix:** enable the DHCP server there, or point the relay to the right address.
