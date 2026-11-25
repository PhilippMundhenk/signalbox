<!-- rules of src/signalbox/rules/poe_checks.py; part of the rules documentation (docs/RULES.md lists all) -->

# Power over Ethernet

These rules use what a PoE switch reports about its power sourcing (#159): the budget of the
switch (`Device.poe`: total, used, reserved watts) and per port (`Port.poe`) the state, class,
power and limit. Readers: Omada, UniFi, MikroTik (`/interface/ethernet/poe`), OpenWrt with the
`realtek-poe` daemon and SNMP (POWER-ETHERNET-MIB). A switch that reports no budget or no PoE
data is not checked.

## `poe.budget`

- **Severity:** warning from 80 % of the budget, error from 100 %; info for ports without a
  powered device
- **Checks:** (1) the power the switch delivers (its own figure, else the sum of the ports)
  against its PoE budget; (2) a port whose powered device draws more than its 802.3 class
  allows (class 0 to 8, with a 5 % margin), which means a faulty device or a wrong class;
  (3) ports with PoE on where no powered device is detected (info, one finding per switch).
  When the budget is exceeded the switch cuts power to the lowest-priority ports and access
  points or cameras reboot at random.
- **Fix:** move a device to another PoE switch, use a PoE injector or lower the priority of
  ports that can wait; check or replace a device that draws more than its class; turn PoE off on
  unused ports.

## `poe.fault`

- **Severity:** error for a fault, warning for an overload
- **Checks:** a PoE port whose state is `fault` (short circuit, over-current, supply problem) or
  `overload`. The finding also names the managed device behind the port when the links show one
  (`signalbox.power.powered_by`, #437). Quiet where the switch reports no PoE state per port.
- **Fix:** check the cable and the powered device; unplug it and plug it in again.

## `poe.class-mismatch`

- **Severity:** warning
- **Checks:** the PoE class the switch detected on a port against the class the device announces
  in its LLDP power TLV (`Neighbour.poe_class`). Quiet when either side does not say.
- **Fix:** check the cable and the device's power supply; set the class or power limit of the
  port by hand if the device keeps announcing another class.

## `poe.unneeded`

- **Severity:** info (one finding per switch)
- **Checks:** ports with PoE on, a link, and no powered device detected: the device there has its
  own power supply. Ports without a link are covered by the idle note of `poe.budget`.
- **Fix:** turn PoE off on these ports (passive PoE can damage equipment).

## Which switch port powers which device

`signalbox.power.powered_by(net)` joins the PoE state of the ports with the cable links between
managed devices: the far end of a link whose port delivers power is powered by that port. Wireless,
VPN and inferred links are ignored. A PoE device on a port with PoE switched off is reported by
`poe.request-unmet` (from the device's LLDP power request).
