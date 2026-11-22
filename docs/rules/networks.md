<!-- rules of src/signalbox/rules/networks.py; part of the rules documentation (docs/RULES.md lists all) -->

# Network purposes

What a network is for (`main`, `guest`, `iot`, `management`, `servers`, `lab`, `voice`,
`cameras`, `transit`, `other`) is known from three sources, strongest first:

1. **declared** in the desired state (`segments: [{vlan: 30, purpose: guest}]`, or `purpose` on
   an SSID), see [DESIRED.md](../DESIRED.md);
2. **reported** by the device: the Fritz!Box guest network (segment and SSID), the Omada guest
   network flag of an SSID;
3. **guessed** from the name of the segment or SSID: a word starting with `guest`, `gast` or
   `visitor` means guest, the word `iot` means IoT. A guess is marked as such in findings and
   in the UI, and makes the guest Wi-Fi finding a warning instead of an error.

`guest`, `iot` and `cameras` count as untrusted networks.

## `wifi.guest-isolation`

- **Severity:** error; warning when the SSID is a guest network only by its name
- **Checks:** an enabled SSID with the purpose `guest` is not in the same network (VLAN) as
  other, non-guest SSIDs, in a network with another purpose, or in the untagged main network.
  Silent when the SSID's network has the purpose `guest` or is isolated by the device, when the
  SSID's own VLAN has no known purpose (then `segment.purpose-missing` asks), and for guest
  networks the device reports itself (Fritz!Box, Omada guest network): the device keeps those
  apart. Declare `purpose: main` on an SSID that only looks like a guest network.
- **Fix:** bind the SSID to a separate guest VLAN, or use the router's guest network.

## `segment.guest-no-isolation`

- **Severity:** warning
- **Checks:** an enabled SSID whose purpose (or its network's) is `guest` has client isolation
  switched off, so guests reach each other's devices. Checked where the access point reports
  the setting (OpenWrt `option isolate`); unknown values and networks isolated by the device
  are not reported.
- **Fix:** turn on client isolation (`client_isolation: true` on the SSID in the desired state;
  OpenWrt: `option isolate '1'`).

## `security.management-exposure`

- **Severity:** error; incomplete (info) for routers
- **Checks (level 1, without firewall data):** the management address of a switch or access
  point lies in a guest, IoT or camera network, or such a device has an address there (a
  subnet interface that is not the gateway). A router has an address in every network it
  serves; whether its management interface is reachable from there depends on its firewall,
  which Signalbox does not read yet, so each such router address is reported as not checked.
  Level 2 (firewall rules, issue #135) is not implemented.
- **Fix:** move the management address to the LAN or a management VLAN, or block access from
  that network to the device.

## `segment.purpose-missing`

- **Severity:** info
- **Checks:** at a site with at least two networks, every network has a declared or reported
  purpose. One finding per site lists the networks without one, and those with only a guess.
- **Fix:** declare the purposes in the desired state, for example
  `segments: [{vlan: 20, purpose: iot}]`.

## `segment.iot-on-5ghz-only`

- **Severity:** info
- **Checks:** an enabled SSID whose purpose (or its network's) is `iot` is broadcast on at least
  one radio of a known band at the site, and on 2.4 GHz. Many IoT devices only have 2.4 GHz.
- **Fix:** also broadcast the SSID on 2.4 GHz, unless all its devices support 5 GHz.
