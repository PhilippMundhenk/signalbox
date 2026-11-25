# Rules

The consistency rules that ship with Signalbox: what each one checks and how to fix a finding.

Each rule can be turned off or given another severity in the configuration
(`rules: {dhcp.dns-option: {enabled: false}}`). When a rule cannot check something because a
device did not report the data, it reports an *incomplete* finding (severity info) instead of
staying silent.

Each group is documented next to the others in [rules/](rules/), one file per rule module
(`docs/rules/<module>.md` for `src/signalbox/rules/<module>.py`), so that new rules do not
touch a shared file. This index is generated (`python tools/gen_docs.py`).

## [Device accounts and factory passwords](rules/account_checks.md)

- [`security.default-password`](rules/account_checks.md#securitydefault-password)
- [`account.signalbox-privileged`](rules/account_checks.md#accountsignalbox-privileged)
- [`account.admin-default-name`](rules/account_checks.md#accountadmin-default-name)
- [`account.no-password`](rules/account_checks.md#accountno-password)
- [`account.stale`](rules/account_checks.md#accountstale)

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

## [Annotations and acknowledgements](rules/annotation_checks.md)

- [`annotations.stale`](rules/annotation_checks.md#annotationsstale)
- [`ack.expired`](rules/annotation_checks.md#ackexpired)

## [Device HTTPS certificates](rules/certificate_checks.md)

- [`security.certificate-expiry`](rules/certificate_checks.md#securitycertificate-expiry)
- [`cert.weak-key`](rules/certificate_checks.md#certweak-key)
- [`cert.renewed`](rules/certificate_checks.md#certrenewed)

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
- [`dns.forwarder-encrypted`](rules/dns.md#dnsforwarder-encrypted)
- [`dns.conflicting-records`](rules/dns.md#dnsconflicting-records)

## [Expectations about clients](rules/expectations.md)

- [`clients.unexpected-network`](rules/expectations.md#clientsunexpected-network)
- [`clients.category-network`](rules/expectations.md#clientscategory-network)
- [`clients.vendor-network`](rules/expectations.md#clientsvendor-network)

## [MAC address tables](rules/fdb_checks.md)

- [`mac.flapping`](rules/fdb_checks.md#macflapping)
- [`mac.static-stale`](rules/fdb_checks.md#macstatic-stale)
- [`mac.table-full`](rules/fdb_checks.md#mactable-full)

## [Firewall](rules/firewall_checks.md)

- [`security.port-forward-target`](rules/firewall_checks.md#securityport-forward-target)
- [`firewall.forward-into-guest`](rules/firewall_checks.md#firewallforward-into-guest)
- [`firewall.duplicate-port-forward`](rules/firewall_checks.md#firewallduplicate-port-forward)
- [`firewall.segment-without-zone`](rules/firewall_checks.md#firewallsegment-without-zone)
- [`firewall.untrusted-reaches-lan`](rules/firewall_checks.md#firewalluntrusted-reaches-lan)

## [Firmware](rules/firmware.md)

- [`firmware.drift`](rules/firmware.md#firmwaredrift)
- [`firmware.update-available`](rules/firmware.md#firmwareupdate-available)
- [`firmware.end-of-life`](rules/firmware.md#firmwareend-of-life)

## [Foreign DHCP servers and routers](rules/foreign.md)

- [`dhcp.foreign-server`](rules/foreign.md#dhcpforeign-server)
- [`ra.foreign-router`](rules/foreign.md#raforeign-router)

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

## [Link aggregation](rules/lag_checks.md)

- [`lag.mode-mismatch`](rules/lag_checks.md#lagmode-mismatch)
- [`lag.member-not-selected`](rules/lag_checks.md#lagmember-not-selected)
- [`lag.partner-mismatch`](rules/lag_checks.md#lagpartner-mismatch)

## [DHCP leases, options and relays](rules/leases.md)

- [`dhcp.static-in-pool`](rules/leases.md#dhcpstatic-in-pool)
- [`dhcp.declined`](rules/leases.md#dhcpdeclined)
- [`dhcp.option-121-without-router`](rules/leases.md#dhcpoption-121-without-router)
- [`dhcp.relay-target-missing`](rules/leases.md#dhcprelay-target-missing)

## [Logging and monitoring targets](rules/logging_checks.md)

- [`log.target-unknown`](rules/logging_checks.md#logtarget-unknown)
- [`log.plain-transport`](rules/logging_checks.md#logplain-transport)
- [`log.inconsistent`](rules/logging_checks.md#loginconsistent)

## [Management services](rules/management.md)

- [`security.insecure-services`](rules/management.md#securityinsecure-services)
- [`cloud.enabled`](rules/management.md#cloudenabled)
- [`security.wan-management`](rules/management.md#securitywan-management)
- [`security.service-exposure`](rules/management.md#securityservice-exposure)
- [`security.plaintext-read`](rules/management.md#securityplaintext-read)

## [Network purposes](rules/networks.md)

- [`wifi.guest-isolation`](rules/networks.md#wifiguest-isolation)
- [`segment.guest-no-isolation`](rules/networks.md#segmentguest-no-isolation)
- [`security.management-exposure`](rules/networks.md#securitymanagement-exposure)
- [`segment.purpose-missing`](rules/networks.md#segmentpurpose-missing)
- [`segment.iot-on-5ghz-only`](rules/networks.md#segmentiot-on-5ghz-only)

## [Port counters](rules/port_counters.md)

- [`port.errors`](rules/port_counters.md#porterrors)

## [Ports](rules/ports.md)

- [`vlan.single-untagged`](rules/ports.md#vlansingle-untagged)
- [`vlan.client-port-mismatch`](rules/ports.md#vlanclient-port-mismatch)
- [`link.mtu`](rules/ports.md#linkmtu)
- [`port.admin-down-with-neighbour`](rules/ports.md#portadmin-down-with-neighbour)
- [`port.eee-on-uplink`](rules/ports.md#porteee-on-uplink)
- [`port.autoneg-mismatch`](rules/ports.md#portautoneg-mismatch)
- [`port.description-mismatch`](rules/ports.md#portdescription-mismatch)

## [Fast roaming and UPnP](rules/roaming_upnp.md)

- [`wifi.roaming`](rules/roaming_upnp.md#wifiroaming)
- [`security.upnp`](rules/roaming_upnp.md#securityupnp)

## [Routing](rules/routing_checks.md)

- [`route.default-missing`](rules/routing_checks.md#routedefault-missing)
- [`route.multiple-default`](rules/routing_checks.md#routemultiple-default)
- [`route.unreachable-gateway`](rules/routing_checks.md#routeunreachable-gateway)
- [`route.no-return`](rules/routing_checks.md#routeno-return)
- [`route.asymmetric`](rules/routing_checks.md#routeasymmetric)
- [`route.vpn-return`](rules/routing_checks.md#routevpn-return)

## [Certificates stored on devices](rules/stored_certificates.md)

- [`cert.vpn-expiring`](rules/stored_certificates.md#certvpn-expiring)
- [`cert.ca-expiring`](rules/stored_certificates.md#certca-expiring)

## [Spanning tree and loop protection](rules/stp_checks.md)

- [`stp.several-roots`](rules/stp_checks.md#stpseveral-roots)
- [`stp.root-not-core`](rules/stp_checks.md#stproot-not-core)
- [`stp.disabled-with-redundancy`](rules/stp_checks.md#stpdisabled-with-redundancy)
- [`stp.topology-changes`](rules/stp_checks.md#stptopology-changes)
- [`stp.client-port-not-edge`](rules/stp_checks.md#stpclient-port-not-edge)

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
- [`inventory.unknown-network-device`](rules/topology_checks.md#inventoryunknown-network-device)
- [`vlan.management-separate`](rules/topology_checks.md#vlanmanagement-separate)
- [`inventory.duplicate-device`](rules/topology_checks.md#inventoryduplicate-device)
- [`redundancy.single-point`](rules/topology_checks.md#redundancysingle-point)

## [Path traces](rules/traces.md)

- [`trace.not-via-tunnel`](rules/traces.md#tracenot-via-tunnel)
- [`trace.extra-nat`](rules/traces.md#traceextra-nat)

## [VLANs and links](rules/vlan.md)

- [`vlan.path-to-gateway`](rules/vlan.md#vlanpath-to-gateway)
- [`vlan.native-mismatch`](rules/vlan.md#vlannative-mismatch)
- [`vlan.tagged-both-ends`](rules/vlan.md#vlantagged-both-ends)
- [`vlan.unused`](rules/vlan.md#vlanunused)
- [`link.speed-duplex`](rules/vlan.md#linkspeed-duplex)
- [`vlan.trunk-scope`](rules/vlan.md#vlantrunk-scope)
- [`link.slow`](rules/vlan.md#linkslow)

## [VPN tunnels](rules/vpn.md)

- [`vpn.handshake-stale`](rules/vpn.md#vpnhandshake-stale)
- [`vpn.allowed-ips-overlap`](rules/vpn.md#vpnallowed-ips-overlap)
- [`vpn.allowed-ips-unrouted`](rules/vpn.md#vpnallowed-ips-unrouted)
- [`vpn.keepalive-behind-nat`](rules/vpn.md#vpnkeepalive-behind-nat)
- [`vpn.ends-disagree`](rules/vpn.md#vpnends-disagree)

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

## [Neighbouring Wi-Fi networks](rules/wifi_neighbours.md)

- [`wifi.rogue-ssid`](rules/wifi_neighbours.md#wifirogue-ssid)
- [`wifi.channel-crowded`](rules/wifi_neighbours.md#wifichannel-crowded)

## [Wi-Fi radio state](rules/wifi_radio.md)

- [`wifi.channel-busy`](rules/wifi_radio.md#wifichannel-busy)
- [`wifi.radar-hit`](rules/wifi_radio.md#wifiradar-hit)
- [`wifi.legacy-standard`](rules/wifi_radio.md#wifilegacy-standard)

## [Wi-Fi regulatory limits](rules/wifi_regulatory.md)

- [`wifi.regulatory`](rules/wifi_regulatory.md#wifiregulatory)

## [Wi-Fi security](rules/wifi_security.md)

- [`wifi.weak-security`](rules/wifi_security.md#wifiweak-security)
- [`wifi.wpa3-available`](rules/wifi_security.md#wifiwpa3-available)
- [`wifi.passphrase-reuse`](rules/wifi_security.md#wifipassphrase-reuse)
- [`wifi.wps`](rules/wifi_security.md#wifiwps)
- [`wifi.6ghz-h2e`](rules/wifi_security.md#wifi6ghz-h2e)

## [Wi-Fi](rules/wireless.md)

- [`wifi.ssid-consistent`](rules/wireless.md#wifissid-consistent)
- [`wifi.country`](rules/wireless.md#wificountry)
- [`wifi.channel-overlap`](rules/wireless.md#wifichannel-overlap)
- [`wifi.segment-at-gateway`](rules/wireless.md#wifisegment-at-gateway)
