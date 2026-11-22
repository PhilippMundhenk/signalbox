<!-- rules of src/signalbox/rules/expectations.py; part of the rules documentation (docs/RULES.md lists all) -->

# Expectations about clients

A client's annotation ([DESIRED.md](../DESIRED.md#annotations-and-acknowledgements)) can say
which network it belongs in (`segment`) and what kind of device it is (`category`). These rules
compare that with what is observed. Without an annotation they have nothing to say.

## `clients.unexpected-network`

- **Severity:** info
- **Checks:** a client that has an expected network is seen in a different one. Clients whose
  network is not known are skipped. While it applies, `clients.network-changed` stays quiet
  for that client.
- **Fix:** check the SSID it joined, or the switch port it is plugged into and that port's
  VLAN; if it belongs where it is now, change its expected network.

## `clients.category-network`

- **Severity:** info
- **Checks:** per site that has an IoT network (declared or reported by a device; a name-based
  guess is not enough): clients whose category is `iot` or `camera` that are on another network
  (guest and camera networks excepted), and clients whose category is `computer`, `phone`,
  `tablet` or `server` that are in the IoT network. One finding per network. Clients with an
  expected network are left to `clients.unexpected-network`. The category comes from the
  annotation only; guessing it from the vendor of the MAC address needs a vendor database that
  Signalbox does not ship yet (#84).
- **Fix:** move the device to the right Wi-Fi or port, or correct its category.
