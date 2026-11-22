<!-- rules of src/signalbox/rules/clients.py; part of the rules documentation (docs/RULES.md lists all) -->

# Clients

A MAC address is *randomised* when it is locally administered (the second-lowest bit of the
first octet is set, for example `02:`, `x6:`, `xA:`, `xE:`). Phones, tablets and laptops use such
"private Wi-Fi addresses" by default and change them; virtual machines and containers use them
too, but keep them.

## `clients.duplicate-hostname`

- **Severity:** warning; info when one of the MAC addresses is randomised (often one phone or
  laptop seen with its private and its real address)
- **Checks:** clients with different MAC addresses on one network do not announce the same host
  name (compared case-insensitively, without the domain). Networks whose DHCP servers hand out
  the same domain are compared together. Empty and generic names (`android`, `iphone`, `ipad`,
  `espressif`, `localhost`, ...) and names that are just the MAC address are ignored, as are
  clients whose network is not known.
- **Fix:** rename one of the devices (in its own settings).

## `clients.random-mac`

- **Severity:** warning for a DHCP reservation or a DNS name; info for the share per network
- **Checks:**
  - no DHCP reservation is for a randomised MAC address (the same reservation on several servers
    is one finding);
  - no local DNS host record points to an address that a client with a randomised MAC address
    uses (IPv6 link-local addresses are ignored);
  - for information, per network: how many of the known clients use a randomised MAC address
    (only when at least one does). It explains why client lists grow and reservations, parental
    controls or firewall rules do not stick.
- **Fix:** turn off the private (random) address for this network on the device, then reserve
  its real MAC. Reservations for virtual machines or containers that keep their address are
  fine; turn the rule off if all of yours are.
