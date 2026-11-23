<!-- rules of src/signalbox/rules/firewall_checks.py; part of the rules documentation (docs/RULES.md lists all) -->

# Firewall

These rules read the firewall model of a router (zones, rules, policies, port forwards; ADR 0013)
and the reachability answer of `signalbox.firewall`. A router whose firewall was not read, or
that does not decide exactly, is never reported: the rules stay quiet instead of guessing.
Related rules elsewhere: `security.management-exposure` (management reachable from guest and
IoT networks through the firewall), `addr.double-nat` (forwards on the inner router only),
`security.wan-management` and `security.service-exposure`.

## `security.port-forward-target`

- **Severity:** warning; error for a management service, info for an IoT/camera client or an
  unknown device
- **Checks:** an enabled port forward leads to a dynamic DHCP address (in a pool, no
  reservation or fixed address known), to an address in none of the known networks, to an
  address no known device uses (information, only where clients of that network are known), to
  a client in an IoT or camera network (information), or to a management service of a network
  device (error). Disabled forwards are skipped. Forwards into guest networks are
  `firewall.forward-into-guest`.
- **Fix:** reserve the address for the intended device's MAC, correct or remove the forward, or
  use a VPN instead of exposing management.

## `firewall.forward-into-guest`

- **Severity:** warning
- **Checks:** an enabled port forward targets an address in a guest network.
- **Fix:** move the service out of the guest network and forward there.

## `firewall.duplicate-port-forward`

- **Severity:** warning
- **Checks:** two enabled forwards of one router overlap in external port, protocol, uplink zone
  and external address. Forwards limited to different source networks are not compared.
- **Fix:** remove one forward or use different external ports.

## `firewall.segment-without-zone`

- **Severity:** warning
- **Checks:** a router has an address in a network that none of its firewall zones contains.
  Only when the firewall is enabled and was read completely (every rule, every zone interface
  mapped, no bare-interface zones).
- **Fix:** add the network's interface to a zone.

## `firewall.untrusted-reaches-lan`

- **Severity:** warning
- **Checks:** the router between a guest, IoT or camera network and a main or management
  network surely accepts new connections to an unused address of the target network on any
  port. Rules that allow only some ports, inexact rules, isolated networks and unread firewalls
  stay quiet.
- **Fix:** block the untrusted network from the main network; allow only what is needed.
