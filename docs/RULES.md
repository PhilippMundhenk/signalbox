# Rules

The consistency rules that ship with Signalbox: what each one checks and how to fix a finding.

Each rule can be turned off or given another severity in the configuration
(`rules: {dhcp.dns-option: {enabled: false}}`). When a rule cannot check something because a
device did not report the data, it reports an *incomplete* finding (severity info) instead of
staying silent.

Each group is documented next to the others in [rules/](rules/), one file per rule module
(`docs/rules/<module>.md` for `src/signalbox/rules/<module>.py`), so that new rules do not
touch a shared file. This index is generated (`python tools/gen_docs.py`).

## [Addressing and DHCP checks](rules/addressing.md)

- [`addr.client-subnet`](rules/addressing.md#addrclient-subnet)
- [`dhcp.self-assigned`](rules/addressing.md#dhcpself-assigned)
- [`addr.prefix-consistent`](rules/addressing.md#addrprefix-consistent)
- [`addr.gateway-position`](rules/addressing.md#addrgateway-position)
- [`dhcp.pool-usage`](rules/addressing.md#dhcppool-usage)
- [`dhcp.lease-time`](rules/addressing.md#dhcplease-time)
- [`dhcp.in-subnet`](rules/addressing.md#dhcpin-subnet)
- [`addr.one-gateway`](rules/addressing.md#addrone-gateway)
- [`addr.double-nat`](rules/addressing.md#addrdouble-nat)
- [`inventory.management-address`](rules/addressing.md#inventorymanagement-address)
- [`dhcp.duplicate-reservation`](rules/addressing.md#dhcpduplicate-reservation)
- [`dhcp.domain`](rules/addressing.md#dhcpdomain)
- [`dhcp.reservation-hostname`](rules/addressing.md#dhcpreservation-hostname)
- [`dhcp.dns-cross-network`](rules/addressing.md#dhcpdns-cross-network)

## [Clients](rules/clients.md)

- [`clients.duplicate-hostname`](rules/clients.md#clientsduplicate-hostname)
- [`clients.random-mac`](rules/clients.md#clientsrandom-mac)

## [DHCP and addressing](rules/dhcp.md)

- [`dhcp.one-server`](rules/dhcp.md#dhcpone-server)
- [`dhcp.pools-overlap`](rules/dhcp.md#dhcppools-overlap)
- [`dhcp.pool-fixed-address`](rules/dhcp.md#dhcppool-fixed-address)
- [`dhcp.reservation-in-pool`](rules/dhcp.md#dhcpreservation-in-pool)
- [`dhcp.router-option`](rules/dhcp.md#dhcprouter-option)
- [`dhcp.dns-option`](rules/dhcp.md#dhcpdns-option)
- [`addr.subnet-overlap`](rules/dhcp.md#addrsubnet-overlap)
- [`addr.duplicate-ip`](rules/dhcp.md#addrduplicate-ip)

## [DNS](rules/dns.md)

- [`dns.host-record-reservation`](rules/dns.md#dnshost-record-reservation)
- [`dns.host-record-stale`](rules/dns.md#dnshost-record-stale)
- [`dns.host-record-dynamic`](rules/dns.md#dnshost-record-dynamic)
- [`dns.forwarder-loop`](rules/dns.md#dnsforwarder-loop)
- [`dns.forwarder-missing`](rules/dns.md#dnsforwarder-missing)
- [`dns.single-forwarder`](rules/dns.md#dnssingle-forwarder)
- [`dns.conflicting-records`](rules/dns.md#dnsconflicting-records)

## [Firmware](rules/firmware.md)

- [`firmware.drift`](rules/firmware.md#firmwaredrift)
- [`firmware.update-available`](rules/firmware.md#firmwareupdate-available)
- [`firmware.end-of-life`](rules/firmware.md#firmwareend-of-life)

## [Device health](rules/health.md)

- [`device.resources`](rules/health.md#deviceresources)
- [`health.storage-full`](rules/health.md#healthstorage-full)
- [`health.fan-failed`](rules/health.md#healthfan-failed)
- [`health.psu-failed`](rules/health.md#healthpsu-failed)
- [`health.ups-on-battery`](rules/health.md#healthups-on-battery)
- [`health.ups-runtime-low`](rules/health.md#healthups-runtime-low)
- [`health.ups-not-tested`](rules/health.md#healthups-not-tested)
- [`health.uptime-very-long`](rules/health.md#healthuptime-very-long)
- [`device.reboot`](rules/health.md#devicereboot)

## [History](rules/history_checks.md)

- [`device.down-long`](rules/history_checks.md#devicedown-long)
- [`device.flapping`](rules/history_checks.md#deviceflapping)
- [`port.flapping`](rules/history_checks.md#portflapping)
- [`dhcp.stale-reservation`](rules/history_checks.md#dhcpstale-reservation)
- [`clients.network-changed`](rules/history_checks.md#clientsnetwork-changed)

## [IPv6](rules/ipv6.md)

- [`ipv6.unknown-prefix`](rules/ipv6.md#ipv6unknown-prefix)
- [`ipv6.prefix-64`](rules/ipv6.md#ipv6prefix-64)
- [`ipv6.partial`](rules/ipv6.md#ipv6partial)

## [Network purposes](rules/networks.md)

- [`wifi.guest-isolation`](rules/networks.md#wifiguest-isolation)
- [`segment.guest-no-isolation`](rules/networks.md#segmentguest-no-isolation)
- [`security.management-exposure`](rules/networks.md#securitymanagement-exposure)
- [`segment.purpose-missing`](rules/networks.md#segmentpurpose-missing)
- [`segment.iot-on-5ghz-only`](rules/networks.md#segmentiot-on-5ghz-only)

## [Ports](rules/ports.md)

- [`vlan.single-untagged`](rules/ports.md#vlansingle-untagged)
- [`vlan.client-port-mismatch`](rules/ports.md#vlanclient-port-mismatch)
- [`link.mtu`](rules/ports.md#linkmtu)
- [`port.admin-down-with-neighbour`](rules/ports.md#portadmin-down-with-neighbour)
- [`port.eee-on-uplink`](rules/ports.md#porteee-on-uplink)
- [`port.autoneg-mismatch`](rules/ports.md#portautoneg-mismatch)
- [`port.description-mismatch`](rules/ports.md#portdescription-mismatch)

## [Time and NTP](rules/time_checks.md)

- [`time.offset`](rules/time_checks.md#timeoffset)
- [`time.not-synchronised`](rules/time_checks.md#timenot-synchronised)
- [`time.ntp-unreachable`](rules/time_checks.md#timentp-unreachable)
- [`time.dhcp-ntp-mismatch`](rules/time_checks.md#timedhcp-ntp-mismatch)
- [`time.no-local-ntp`](rules/time_checks.md#timeno-local-ntp)
- [`time.timezone`](rules/time_checks.md#timetimezone)

## [Topology](rules/topology.md)

- [`topology.manual-conflict`](rules/topology.md#topologymanual-conflict)
- [`topology.untagged-only-link`](rules/topology.md#topologyuntagged-only-link)

## [Topology and inventory](rules/topology_checks.md)

- [`lag.consistent`](rules/topology_checks.md#lagconsistent)
- [`topology.hidden-device`](rules/topology_checks.md#topologyhidden-device)
- [`inventory.unknown-neighbour`](rules/topology_checks.md#inventoryunknown-neighbour)
- [`vlan.management-separate`](rules/topology_checks.md#vlanmanagement-separate)
- [`inventory.duplicate-device`](rules/topology_checks.md#inventoryduplicate-device)
- [`redundancy.single-point`](rules/topology_checks.md#redundancysingle-point)

## [VLANs and links](rules/vlan.md)

- [`vlan.path-to-gateway`](rules/vlan.md#vlanpath-to-gateway)
- [`vlan.native-mismatch`](rules/vlan.md#vlannative-mismatch)
- [`vlan.tagged-both-ends`](rules/vlan.md#vlantagged-both-ends)
- [`vlan.unused`](rules/vlan.md#vlanunused)
- [`link.speed-duplex`](rules/vlan.md#linkspeed-duplex)
- [`vlan.trunk-scope`](rules/vlan.md#vlantrunk-scope)
- [`link.slow`](rules/vlan.md#linkslow)

## [Internet connection (WAN)](rules/wan.md)

- [`wan.cgnat`](rules/wan.md#wancgnat)
- [`wan.down`](rules/wan.md#wandown)
- [`wan.dns-mismatch`](rules/wan.md#wandns-mismatch)
- [`wan.no-ipv6`](rules/wan.md#wanno-ipv6)

## [Wi-Fi hygiene](rules/wifi_hygiene.md)

- [`wifi.6ghz-security`](rules/wifi_hygiene.md#wifi6ghz-security)
- [`wifi.pmf`](rules/wifi_hygiene.md#wifipmf)
- [`wifi.hidden`](rules/wifi_hygiene.md#wifihidden)
- [`wifi.ssid-count`](rules/wifi_hygiene.md#wifissid-count)
- [`wifi.channel-width`](rules/wifi_hygiene.md#wifichannel-width)
- [`wifi.24-channel-plan`](rules/wifi_hygiene.md#wifi24-channel-plan)
- [`wifi.dfs`](rules/wifi_hygiene.md#wifidfs)
- [`wifi.tx-power`](rules/wifi_hygiene.md#wifitx-power)
- [`wifi.ssid-coverage`](rules/wifi_hygiene.md#wifissid-coverage)
- [`wifi.segment-weakest-link`](rules/wifi_hygiene.md#wifisegment-weakest-link)
- [`wifi.default-ssid`](rules/wifi_hygiene.md#wifidefault-ssid)

## [Wi-Fi](rules/wireless.md)

- [`wifi.ssid-consistent`](rules/wireless.md#wifissid-consistent)
- [`wifi.country`](rules/wireless.md#wificountry)
- [`wifi.channel-overlap`](rules/wireless.md#wifichannel-overlap)
- [`wifi.segment-at-gateway`](rules/wireless.md#wifisegment-at-gateway)
