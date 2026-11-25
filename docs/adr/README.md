# Architecture decision records

| # | Decision |
| --- | --- |
| [0001](0001-python-fastapi-pydantic.md) | Python, FastAPI, Pydantic v2, SQLite and a UI without build step |
| [0002](0002-components-and-change-transactions.md) | Explicit components, and changes as tracked transactions |
| [0003](0003-switchyard-library.md) | Switchyard as an optional, pinned library for the switch protocols |
| [0004](0004-controllers-report-several-devices.md) | Controllers report the devices they manage (adapter API 1.1) |
| [0005](0005-untagged-networks-of-several-routers.md) | Untagged networks of several routers are separate segments (#205) |
| [0006](0006-discovery-probes.md) | Device discovery: user-started, unauthenticated probes owned by the integrations |
| [0007](0007-annotations-and-acknowledgements.md) | Annotations and acknowledged findings are user data on the network (#186) |
| [0008](0008-internal-port-structure.md) | The internal port structure of a device: `Port.role` and `Port.lower` (#252) |
| [0009](0009-automatic-setup-with-an-admin-login.md) | Automatic setup with an admin login, used once and never kept (#231) |
| [0010](0010-isc-dhcp-settings-through-a-helper-script.md) | ISC DHCP settings of OPNsense through an optional, forced-command script (#242) |
| [0011](0011-vpn-tunnels-and-site-links.md) | VPN tunnels belong to their device, site links come from matching public keys, keys never enter the model (#239) |
| [0012](0012-fix-it-for-read-problems.md) | Fix it: known remedies for read problems, run like the automatic setup (#215) |
| [0013](0013-firewall-zones-rules-and-reachability.md) | Firewall: zones, ordered rules, zone pair policies, NAT and a conservative allowed / denied / unknown answer (#135) |
| [0014](0014-path-traces.md) | Path traces: traceroutes run on the devices, an optional active observation stored apart from snapshots (#253) |
| [0015](0015-foreign-dhcp-servers-and-routers.md) | Foreign DHCP servers and routers: device sightings always, an optional probe from Signalbox's host that never takes a lease (#184, #61) |
| [0016](0016-mac-address-tables.md) | MAC address tables: raw entries per device, bounded, one core module derives client placement and links (#160) |
| [0017](0017-firewall-desired-state-and-deployments.md) | Firewall desired state and deployments: tagged objects only, zone references, a lockout check with an explicit override (#295) |
| [0018](0018-log-and-monitoring-targets.md) | Log and monitoring targets belong to their device; the SNMP agent stays a management service (#180) |
| [0019](0019-device-tls-certificates.md) | The device certificate is read by core and belongs to the device (#174) |
| [0020](0020-device-accounts-and-factory-passwords.md) | Device accounts and factory passwords: only booleans leave the integration, names stay on the device page (#175) |
| [0021](0021-logging-and-snmp-desired-state.md) | Logging and SNMP desired state: syslog targets Signalbox created or adopted, an agent switch, drift and writes on MikroTik and OpenWrt (#327) |
| [0022](0022-link-aggregation-details.md) | Link aggregation details live on the LAG port and its members; members stay `Port.lower` and `Port.lag` (#157) |
| [0023](0023-spanning-tree.md) | Spanning tree per bridge on the device, per port on the port, bridge ids in one canonical form (#155) |
| [0024](0024-routing-tables-and-policy-routing.md) | Routing tables: connected routes are derived from subnets, `next_hop` answers conservatively, policy routing only as far as it is known (#149) |
| [0025](0025-neighbouring-wifi-networks.md) | Neighbouring Wi-Fi networks: BSSIDs, passive lists always, scans only on request, kept on the server (#169) |
| [0026](0026-inferred-links-from-partial-mac-data.md) | Inferred links from partial MAC data: OpenWrt bridge tables, MACs from ARP entries, guessed ports drawn dashed and left out of the checks (#378) |
| [0027](0027-rule-parameters-and-scopes.md) | Typed rule parameters next to each rule, read through `ctx.params`; per-scope settings by site, device, role, network, purpose or tag, most specific wins (#187) |
| [0028](0028-multicast.md) | Multicast: snooping and querier per bridge, reflectors (mDNS, SSDP, IGMP proxy, UDP relay) per device; only settings are read (#161) |
| [0029](0029-upnp-port-mappings.md) | UPnP, NAT-PMP and PCP: protocols, secure mode, permission rules and the dynamic mappings per gateway; `mappings_complete` where a device cannot list them (#176) |
| [0030](0030-access-control-radius.md) | Port access control (802.1X, MAC authentication, port security), MAC filters and RADIUS servers; shared secrets and MAC lists are never read (#162) |
| [0031](0031-ssh-host-key-pins.md) | SSH host keys are pinned per device; a changed key stops the run before the password and warns, re-trust names the new key (#526); addendum: setup and Fix it reuse the certificate pin, every SSH key type is pinned (#535) |

New records copy the structure of the existing ones: Context, Decision, Consequences.
