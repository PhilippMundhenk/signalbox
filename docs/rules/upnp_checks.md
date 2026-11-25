<!-- rules of src/signalbox/rules/upnp_checks.py; part of the rules documentation (docs/RULES.md lists all) -->

# UPnP, NAT-PMP and PCP mappings

These rules use what gateways report about the ports devices opened themselves (#176, ADR 0029):
`Device.upnp` with the protocols, secure mode and the dynamic mappings (protocol, external
port, the device's address and port). Readers: OpenWrt (miniupnpd), OPNsense (`os-upnp`, state
only), MikroTik (`/ip/upnp`) and Fritz!Box (port sharing with a lease). Whether UPnP is on at
all is `security.upnp`. A gateway that does not report its mappings is not checked; mappings of
a gateway whose UPnP service says off are ignored. The device behind a mapping is found by its
address among the clients. Descriptions of mappings are never part of a finding.

## `upnp.mapping-untrusted`

- **Severity:** warning
- **Checks:** a mapping leads to an address in a guest, IoT or camera network (purpose
  declared, reported or guessed). A camera or a compromised guest device can expose itself this
  way. The network is the one a client with that address is in, otherwise the smallest network
  that contains it.
- **Fix:** turn UPnP off on the gateway for that network or remove the mapping, and add the port
  forward by hand if the device really has to be reachable.

## `upnp.management-port`

- **Severity:** warning
- **Checks:** the port on the internet side or the target port of a mapping is one of SSH (22),
  Telnet (23), SMB (139, 445), remote desktop (3389), VNC (5900), Winbox (8291) or the RouterOS
  API (8728, 8729). Programs that open these unasked point to malware or to a service that
  should not be reachable from outside.
- **Fix:** remove the mapping and find the program that asked for it; use a VPN when the service
  has to be reachable from outside.

## `upnp.insecure-mode`

- **Severity:** warning
- **Checks:** a gateway with UPnP on says secure mode is off, so a device can map ports to
  another device (miniupnpd `secure_mode`, OPNsense). Quiet where the gateway does not report
  secure mode (MikroTik, Fritz!Box).
- **Fix:** turn secure mode on, or UPnP off.

## `upnp.many-mappings`

- **Severity:** info
- **Parameter:** `max_mappings` (count, default 20): report a gateway with more enabled
  mappings than this. Set per gateway, site or network through the rule scopes (ADR 0027).
- **Checks:** a gateway that reports its mappings has more than `max_mappings`. The message
  also counts the mappings without an end (lease 0), which programs forgot to remove.
- **Fix:** review the list on the device page, remove what you do not know, and turn UPnP off if
  no device needs it.

## `upnp.mapping-to-unknown`

- **Severity:** info
- **Checks:** a mapping leads to an address that no client and no device (their networks,
  internet connections, management addresses) has. Quiet where no clients are read. A device that
  is switched off may be missing from the client list, so this is information only.
- **Fix:** remove the mapping if you do not know the device it was for.

## `upnp.cgnat-useless`

- **Severity:** info
- **Checks:** UPnP is on at a gateway whose connected internet connections all have a
  carrier-grade NAT address (100.64.0.0/10) or a private one (another router in front), so
  opened ports cannot be reached from the internet. Quiet when one connection has a public
  address, or none is known.
- **Fix:** turn UPnP off; use a public IPv4 address, IPv6 or a VPN.

## `upnp.stale-mapping`

- **Severity:** info
- **Parameter:** `stale_days` (d, default 14): report a mapping whose device was not seen for
  longer than this (ADR 0027 scopes apply).
- **Checks:** the client behind a mapping was last seen (client list or history, whichever is
  newer) more than `stale_days` ago. Gateways report the time left of a lease, not when it
  ended, so an expired lease cannot be told apart. Quiet without history or for unknown devices.
- **Fix:** remove the mapping, or turn UPnP off if no device needs it.
