<!-- rules of src/signalbox/rules/multicast_checks.py; part of the rules documentation (docs/RULES.md lists all) -->

# Multicast

These rules use what devices report about multicast (#161, ADR 0028): the IGMP and MLD snooping
and querier settings per bridge (`Device.multicast.settings`) and the services that reflect
discovery or streams between networks (`Device.multicast.reflectors`: mDNS repeater, SSDP and
UDP broadcast relay, IGMP proxy). Readers: MikroTik, OpenWrt, OPNsense (reflectors only) and UniFi.
Only settings are read, never the names of the services a reflector carries. A device that
reports nothing is not checked.

## `multicast.snooping-no-querier`

- **Severity:** warning
- **Checks:** a network has a bridge with IGMP snooping on, every bridge of the network that
  says whether it is the querier says it is not, and none has seen a querier. Streams (IPTV,
  Sonos, Chromecast) then stop a few minutes after they started, when the memberships time out.
  Quiet when a bridge does not say, and when a bridge reports the querier it sees.
- **Fix:** turn on the multicast querier on the router's bridge (or one switch), or turn
  snooping off if nothing needs it.

## `multicast.reflector-guest`

- **Severity:** warning
- **Checks:** an enabled mDNS repeater, SSDP or UDP broadcast relay joins at least two networks,
  one of them a guest network (purpose declared, reported or guessed). Guests then see the names
  of your devices and can address them.
- **Fix:** take the guest network out of the reflector's interfaces.

## `multicast.reflector-missing`

- **Severity:** info
- **Parameter:** `min_clients` (count, default 1): the clients an IoT network and the network
  of your own devices need before it is reported.
- **Checks:** an IoT network (purpose declared or reported, not guessed) has clients, a main
  network of the same site has clients, and no enabled mDNS, SSDP or relay reflector joins the
  two. Casting, AirPlay and printing from the main network do not find the devices. Quiet when no
  device reports multicast, and when a reflector does not say which networks it joins.
- **Fix:** turn on an mDNS reflector for the two networks, and nothing else; ignore it when the
  devices should stay out of sight.

## `multicast.iptv-proxy`

- **Severity:** info
- **Checks:** a gateway with a known uplink has an enabled IGMP proxy whose upstream is another
  interface than the uplink. The provider's streams then do not arrive, unless the provider
  delivers its TV in a VLAN of its own, which is the upstream on purpose.
- **Fix:** set the uplink as the upstream of the IGMP proxy.
