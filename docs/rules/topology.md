<!-- rules of src/signalbox/topology.py; part of the rules documentation (docs/RULES.md lists all) -->

# Topology

Links come from LLDP (devices that announce their neighbours), from MAC tables (a device sees
another device's port address on one of its ports), and from cables entered by hand on the
*Topology* page. LLDP wins over MAC tables; entered cables are kept as they are.

## `topology.manual-conflict`

- **Severity:** warning
- **Checks:** a cable entered by hand agrees with what the devices report: if LLDP or a MAC table
  says one of its ports is connected to a different port, the entry and reality disagree.
- **Fix:** move the cable, or change the entered link to match.

## `topology.untagged-only-link`

- **Severity:** info
- **Checks:** when the site uses VLANs, a wired link between two devices that both report VLAN
  memberships carries at least one tagged VLAN. A link with only the untagged network is often a
  trunk that was configured as an access port.
- **Fix:** if VLANs should pass the link, tag them on both ports; otherwise ignore or turn off.
