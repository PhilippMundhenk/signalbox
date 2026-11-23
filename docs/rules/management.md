<!-- rules of src/signalbox/rules/management.py; part of the rules documentation (docs/RULES.md lists all) -->

# Management services

These rules read the management services a device reported (telnet, SSH, web interface, SNMP,
...). A device that reported none is not checked: an empty list means "not read". Firewall
rules are not read yet (issue #135), so where they would decide a rule says "not checked".

## `security.insecure-services`

- **Severity:** warning; info when the service is limited to some networks or addresses
- **Checks:** an enabled service sends passwords in clear text or is a common target: telnet,
  FTP, TFTP, MAC telnet, plain HTTP that does not redirect to HTTPS, SNMP v1/v2c with the default
  community, SSH login of root with a password. One finding per device (and one more for the
  limited services).
- **Fix:** turn the service off and use SSH or HTTPS; change the SNMP community or use SNMPv3;
  allow SSH keys only for root.

## `security.wan-management`

- **Severity:** error; incomplete (info) when the firewall decides
- **Checks:** a gateway with a reported uplink offers a management service to the internet:
  the device says so (Fritz!Box remote access), or the service listens on the uplink without an
  address filter and its firewall (#135) lets the internet in: no port forward takes the port
  elsewhere, the input rules and the wan zone policy accept it, and a known router in front
  (double NAT) forwards it. Where the firewall is not read or does not decide exactly (inexact
  rules, rules it could not read), it is reported as not checked, with the reason. Services
  bound to other networks or limited to private addresses are fine.
- **Fix:** turn off remote access (or restrict it to a VPN) and use a VPN from outside.

## `security.service-exposure`

- **Severity:** error; incomplete (info) for routers whose firewall does not decide
- **Checks:** a management service is offered in a guest, IoT or camera network: the device
  says it offers it there, or a router has an address there and listens on it, and the
  router's firewall (#135) does not block that network from the service (error). Where the
  firewall is not read or does not decide exactly, the router case is reported as not
  checked. Switches and access points with an address there are covered by
  `security.management-exposure`. Networks the device isolates itself are skipped.
- **Fix:** offer the services only in the LAN or a management VLAN, or block that network.

## `security.plaintext-read`

- **Severity:** info; warning when the network is a guest, IoT or camera network
- **Checks:** Signalbox reads the device without encryption (NSDP, Easy Smart, plain HTTP) and
  the network of its management address also has clients or Wi-Fi networks.
- **Fix:** move the management of the device to a separate VLAN without clients or Wi-Fi.
