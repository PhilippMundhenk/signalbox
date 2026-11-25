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

## [Captive portals](rules/captive_portals.md)

- [`portal.guest-unprotected`](rules/captive_portals.md#portalguest-unprotected)
- [`portal.non-guest-network`](rules/captive_portals.md#portalnon-guest-network)
- [`portal.click-through-open`](rules/captive_portals.md#portalclick-through-open)

## [Device HTTPS certificates](rules/certificate_checks.md)

- [`security.certificate-expiry`](rules/certificate_checks.md#securitycertificate-expiry)
- [`cert.weak-key`](rules/certificate_checks.md#certweak-key)
- [`cert.renewed`](rules/certificate_checks.md#certrenewed)

## [Clients](rules/clients.md)

- [`clients.duplicate-hostname`](rules/clients.md#clientsduplicate-hostname)
- [`clients.random-mac`](rules/clients.md#clientsrandom-mac)

## [Configuration state and backups](rules/config_state.md)

- [`config.unsaved`](rules/config_state.md#configunsaved)
- [`config.pending`](rules/config_state.md#configpending)
- [`backup.none`](rules/config_state.md#backupnone)

## [Device identity](rules/device_identity.md)

- [`device.name-mismatch`](rules/device_identity.md#devicename-mismatch)
- [`device.bootloader-outdated`](rules/device_identity.md#devicebootloader-outdated)

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
- [`dns.dnssec-off`](rules/dns.md#dnsdnssec-off)
- [`dns.rebind-protection-off`](rules/dns.md#dnsrebind-protection-off)
- [`dns.blocklist-stale`](rules/dns.md#dnsblocklist-stale)

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
- [`firmware.security-update`](rules/firmware.md#firmwaresecurity-update)
- [`firmware.beta-channel`](rules/firmware.md#firmwarebeta-channel)

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
- [`device.replaced`](rules/health.md#devicereplaced)

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

## [Wi-Fi mesh and wireless backhaul](rules/mesh_checks.md)

- [`mesh.weak-backhaul`](rules/mesh_checks.md#meshweak-backhaul)
- [`mesh.backhaul-2-4`](rules/mesh_checks.md#meshbackhaul-2-4)
- [`mesh.chain-too-long`](rules/mesh_checks.md#meshchain-too-long)
- [`mesh.wired-possible`](rules/mesh_checks.md#meshwired-possible)
- [`mesh.channel-locked`](rules/mesh_checks.md#meshchannel-locked)

## [Multi-WAN and dynamic DNS](rules/multiwan.md)

- [`wan.group-member-down`](rules/multiwan.md#wangroup-member-down)
- [`wan.group-last-member`](rules/multiwan.md#wangroup-last-member)
- [`wan.monitor-local`](rules/multiwan.md#wanmonitor-local)
- [`wan.on-backup`](rules/multiwan.md#wanon-backup)
- [`wan.failover-same-path`](rules/multiwan.md#wanfailover-same-path)
- [`wan.monitor-missing`](rules/multiwan.md#wanmonitor-missing)
- [`wan.degraded`](rules/multiwan.md#wandegraded)
- [`ddns.mismatch`](rules/multiwan.md#ddnsmismatch)
- [`ddns.update-failed`](rules/multiwan.md#ddnsupdate-failed)
- [`ddns.private-address`](rules/multiwan.md#ddnsprivate-address)
- [`ddns.plain-http`](rules/multiwan.md#ddnsplain-http)
- [`ddns.vpn-endpoint`](rules/multiwan.md#ddnsvpn-endpoint)
- [`ddns.stale`](rules/multiwan.md#ddnsstale)

## [Neighbour details (LLDP)](rules/neighbour_checks.md)

- [`link.pvid-mismatch`](rules/neighbour_checks.md#linkpvid-mismatch)
- [`link.mtu-mismatch`](rules/neighbour_checks.md#linkmtu-mismatch)
- [`poe.request-unmet`](rules/neighbour_checks.md#poerequest-unmet)

## [Network purposes](rules/networks.md)

- [`wifi.guest-isolation`](rules/networks.md#wifiguest-isolation)
- [`segment.guest-no-isolation`](rules/networks.md#segmentguest-no-isolation)
- [`security.management-exposure`](rules/networks.md#securitymanagement-exposure)
- [`segment.purpose-missing`](rules/networks.md#segmentpurpose-missing)
- [`segment.iot-on-5ghz-only`](rules/networks.md#segmentiot-on-5ghz-only)

## [Power over Ethernet](rules/poe_checks.md)

- [`poe.budget`](rules/poe_checks.md#poebudget)
- [`poe.fault`](rules/poe_checks.md#poefault)
- [`poe.class-mismatch`](rules/poe_checks.md#poeclass-mismatch)
- [`poe.unneeded`](rules/poe_checks.md#poeunneeded)

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

## [IPv6 router advertisements and DHCPv6](rules/ra_consistency.md)

- [`ipv6.ra-consistent`](rules/ra_consistency.md#ipv6ra-consistent)

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
- [`vlan.name-consistent`](rules/vlan.md#vlanname-consistent)

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

## [Wi-Fi settings and clients over time](rules/wifi_clients.md)

- [`wifi.ft-over-ds`](rules/wifi_clients.md#wifift-over-ds)
- [`wifi.dtim-high`](rules/wifi_clients.md#wifidtim-high)
- [`wifi.max-clients-low`](rules/wifi_clients.md#wifimax-clients-low)
- [`wifi.client-2-4-only`](rules/wifi_clients.md#wificlient-2-4-only)
- [`wifi.radio-overloaded`](rules/wifi_clients.md#wifiradio-overloaded)
- [`wifi.client-sticky`](rules/wifi_clients.md#wificlient-sticky)

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

## [Wi-Fi roaming and client association](rules/wifi_roaming.md)

- [`wifi.ft-mobility-domain-mismatch`](rules/wifi_roaming.md#wifift-mobility-domain-mismatch)
- [`wifi.min-rssi-too-high`](rules/wifi_roaming.md#wifimin-rssi-too-high)
- [`wifi.min-rssi-inconsistent`](rules/wifi_roaming.md#wifimin-rssi-inconsistent)
- [`wifi.client-weak-signal`](rules/wifi_roaming.md#wificlient-weak-signal)
- [`wifi.legacy-client`](rules/wifi_roaming.md#wifilegacy-client)

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

## Parameters

The thresholds of these rules can be changed in the configuration, for all objects
(`rules.<id>.params`) or for some sites, devices or networks (`rules.<id>.scopes`, see
[CONFIGURATION.md](CONFIGURATION.md#rules)). A finding lists the values it was judged with and
where each came from. The defaults are the values the rules used before they had parameters.

### `account.stale`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `days` | `90` | d | Days without a login. |

### `cert.ca-expiring`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `warn_days` | `30` | d | Days before the expiry date from which a warning is reported. |
| `urgent_days` | `7` | d | Days before the expiry date from which the warning is an error (an expired certificate is always an error). |

### `cert.vpn-expiring`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `warn_days` | `30` | d | Days before the expiry date from which a warning is reported. |
| `urgent_days` | `7` | d | Days before the expiry date from which the warning is an error (an expired certificate is always an error). |

### `ddns.stale`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `days` | `30` | d | Days without an update of the name. |

### `device.name-mismatch`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `strip_domain` | `1` | count | 1: compare only the part before the first dot (nas and nas.example.lan are the same name); 0: compare the full names. |

### `device.resources`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `memory_pct` | `90` | % | Memory in use from which it is reported. |
| `temperature_c` | `85` | °C | Temperature limit for sensors that report no limit of their own. |

### `dhcp.lease-time`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `min_seconds` | `300` | s | Leases shorter than this are reported. |
| `max_seconds` | `604800` | s | Leases longer than this are reported. |
| `guest_max_seconds` | `86400` | s | Leases longer than this are reported on guest networks. |

### `dhcp.pool-usage`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `high_pct` | `80` | % | Share of the pool in use above which it is reported as nearly full. |

### `dns.blocklist-stale`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `days` | `14` | d | Days since the block list was last downloaded. |

### `health.storage-full`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `warn_pct` | `90` | % | Fill level from which it is a warning. |
| `error_pct` | `98` | % | Fill level from which it is an error. |

### `health.ups-not-tested`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `days` | `180` | d | Age of the last self-test. |

### `health.ups-runtime-low`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `minutes` | `10` | min | Remaining runtime below which it is reported. |

### `health.uptime-very-long`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `days` | `365` | d | Uptime from which it is reported. |

### `link.mtu-mismatch`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `tolerance_bytes` | `22` | bytes | Frame size the neighbour may be smaller than the local MTU needs before it is reported (devices count header, tag and FCS differently). |

### `mesh.chain-too-long`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `max_hops` | `2` | count | Most wireless hops between a node and the wired network. |

### `mesh.weak-backhaul`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `signal_dbm` | `-75` | dBm | Backhaul signal below which a link is weak. |
| `rate_mbps` | `100` | Mbit/s | Backhaul link rate below which a link is slow. |

### `poe.budget`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `warn_pct` | `80` | % | Share of the budget in use from which it is a warning (100 % is an error). |

### `poe.request-unmet`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `margin_w` | `0.5` | W | Watts the request may exceed the port's limit by before it is reported. |

### `port.errors`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `error_ratio` | `0.001` | ratio | Report a port (information) when the errors between two reads are at least this share of its packets (0.001: one in a thousand). |
| `crc_ratio` | `0.0001` | ratio | Warn when the CRC/FCS errors received between two reads are at least this share of the packets received (0.0001: one in ten thousand). |
| `min_packets` | `1000` | count | Reads with fewer packets than this on a port are too small to judge. |
| `min_errors` | `5` | count | Fewer errors than this between two reads are never reported (a single bad frame). |

### `security.certificate-expiry`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `warn_days` | `30` | d | Days before the expiry date from which a warning is reported. |
| `urgent_days` | `7` | d | Days before the expiry date from which the warning is an error (an expired certificate is always an error). |

### `time.offset`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `max_seconds` | `60` | s | Clock offset allowed beyond the uncertainty of the read. |

### `vpn.handshake-stale`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `minutes` | `5` | min | Time without a handshake after which a peer is reported. |

### `wan.degraded`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `loss_pct` | `5` | % | Packet loss from which a line is degraded. |
| `latency_ms` | `300` | ms | Latency from which a line is degraded. |

### `wifi.channel-busy`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `info_pct` | `60` | % | Utilisation reported as information. |
| `warning_pct` | `80` | % | Utilisation reported as a warning. |

### `wifi.channel-crowded`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `dbm` | `-80` | dBm | Neighbours weaker than this are not counted. |
| `count` | `3` | count | Neighbours from which it is reported. |

### `wifi.client-sticky`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `min_dbm` | `-75` | dBm | A client below this signal is weak (#447). The history keeps the signal in steps of 5 dB. |
| `sustained_minutes` | `30` | min | How long the client has been weak on the same access point (#447). |
| `margin_db` | `10` | dBm | How much stronger the client's signal was on another access point of the SSID before (#447). |

### `wifi.client-weak-signal`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `min_dbm` | `-75` | dBm | A client below this signal is slow and drops packets (#170). The history keeps the signal in steps of 5 dB. |
| `sustained_minutes` | `30` | min | How long a client must have been weak on the same access point before it is reported (#447). Without any history the current reading counts. |

### `wifi.dtim-high`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `max_period` | `3` | count | A DTIM period above this makes sleeping clients wait that many beacons for broadcast and multicast traffic (#447). |

### `wifi.min-rssi-too-high`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `max_dbm` | `-70` | dBm | A minimum signal above this kicks clients that are still usable (#168). The fix suggests 5 dBm below it. |

### `wifi.radio-overloaded`

| Parameter | Default | Unit | Meaning |
| --- | --- | --- | --- |
| `max_clients` | `30` | count | A radio with more clients than this is crowded (#447). |
| `idle_clients` | `10` | count | Another radio with the same SSID and fewer clients than this counts as free (#447). |
