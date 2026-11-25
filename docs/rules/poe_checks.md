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
