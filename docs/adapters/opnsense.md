# OPNsense adapter

Adapter id `opnsense`, role `gateway`. Reads an OPNsense firewall through its REST API (every
read is a `GET`) and, when changes are allowed, writes router interfaces, VLANs on ports, Kea
DHCP subnets and reservations ([Writing](#writing-changes)).

| Capability | What is read |
| --- | --- |
| system | product name, firmware version and the newest available version |
| interfaces | ports, VLANs, assigned IPv4/IPv6 addresses: segments and subnets (the firewall is the gateway of each) |
| dhcp | Kea DHCPv4 (pools, router, DNS, domain, lease time, reservations); ISC DHCPv4 (enabled, static mappings) |
| dns | Unbound: enabled, listen addresses and port, forwarders with ports, host overrides; dnsmasq's DNS when on; an unread DNS server on port 53 when neither listens there (AdGuard Home) |
| clients | ARP and NDP tables plus DHCP leases (Kea and ISC), with segment and port |

> **Verified against OPNsense 26.7.9 in CI.** The endpoints, privileges, answers and write
> calls below are checked every night against the official OPNsense nano image (26.7, updated
> to the newest 26.7.x) running in QEMU: tests/integration/test_opnsense_real.py, set up by
> tools/integration/opnsense/ ([Integration tests](#integration-tests)). Versions before 26.7
> are not tested. Parsing stays tolerant: a missing field is left empty, unknown fields are
> ignored, and an answer of the wrong shape becomes a readable "could not read" finding
> (`unexpected answer from <endpoint>: ...`), never a crash.

## Setup

```yaml
adapter: opnsense
url: https://192.0.2.1          # web interface address, optional :port
api_key: "..."                  # stored encrypted
api_secret: "..."               # stored encrypted
```

On the first connection Signalbox shows the SHA-256 fingerprint of the firewall's certificate
(the device is "untrusted certificate"). Compare it with *System > Trust > Certificates* on the
firewall and confirm it; from then on the certificate is pinned. A changed certificate stops
reading until it is confirmed again. The key and secret are only sent after the pinned
certificate was presented (see `signalbox/adapters/https.py`).

`allow_insecure_http: true` allows an `http://` URL. It sends the key in clear text and is only
meant for the simulator.

## Automatic setup

*Set up automatically* in the device form (#231, [ADR 0008](../adr/0008-automatic-setup-with-an-admin-login.md))
creates the user of the next section through the API, with an API key of root.
It is optional: the manual setup below is the same result and always works. Nothing is
changed on the device unless you start it for that device and confirm the plan (never from
*Find devices*, a read or in the background), and `setup.enabled: false` in the
configuration turns it off completely (the API refuses it, the form does not show it).


1. *System > Access > Users*, root, *API keys*, `+`: the browser downloads key and secret.
2. In the device form: the address, then that key and secret under *Set up automatically*.
   *Show what it does* shows the web interface's certificate fingerprint first; nothing is sent
   before you trust it.
3. The plan: the user `signalbox` (scrambled password, so no web interface login; no groups;
   exactly the privileges below, or with those of the write user when *Allow changes* is on),
   then a new API key for it; older keys of `signalbox` are deleted once the new one exists.
4. *Set up the device* runs it and saves the device with the new key, stored encrypted and
   never shown. Root's key is not stored or logged: **delete it on the firewall afterwards**.

The calls are those of the web interface's user manager (OPNsense 24.7 and later):
`POST /api/auth/user/search`, `GET /api/auth/user/get/<uuid>`, `POST /api/auth/user/add` or
`set/<uuid>` with `{"user": {"name", "descr", "scrambled_password": "1", "priv": "<ids>",
"group_memberships": ""}}`, `POST /api/auth/user/add_api_key/signalbox` (answers `key` and
`secret`), `POST /api/auth/user/search_api_key` and `del_api_key/<id>`; the removal is
`POST /api/auth/user/del/<uuid>`. A user `signalbox` with scope `system` is left alone.
Running it again puts the privileges back as documented and replaces the key.

Verified in CI on 26.7 (`tests/integration/test_opnsense_setup_real.py`): pinning and a refused
root secret; the user created, the firewall read with its key (contract, every capability);
a second run with nothing to change but the key; with writes the privileges updated and the
old key refused afterwards; the new key refused by the user manager (403); the removal.

## A least-privilege API user

1. *System > Access > Users*: add a user `signalbox`, no shell, a scrambled password, no group
   memberships.
2. Give it only these privileges (*Effective Privileges*, edit):

   | Privilege (as named in the web interface) | Needed for |
   | --- | --- |
   | System: Firmware | `/api/core/firmware/status` (system) |
   | Status: Interfaces | `/api/interfaces/overview/*` |
   | Interfaces: VLAN | `/api/interfaces/vlan_settings/*` |
   | Services: DHCP: Kea(v4) (if Kea is used) | `/api/kea/dhcpv4/*`, `/api/kea/leases4/*` |
   | Services: DHCRelay | `/api/dhcrelay/*` (DHCP relays; confirmed against the core ACL, `page-services-dhcprelay`) |
   | Services: Unbound | `/api/unbound/*` (the general settings are only readable with this one; *Services: Unbound DNS: General* and *Edit Host and Domain Override* do not cover `/api/unbound/settings/get`) |
   | Diagnostics: ARP Table, Diagnostics: NDP Table | `/api/diagnostics/interface/get_arp`, `get_ndp` |
   | Lobby: Dashboard | `/api/diagnostics/system/system_*`, `/api/diagnostics/cpu_usage/*` (health, and the clock for time) |
   | Status: NTP | `/api/ntpd/service/status` (time: the NTP peers) |

   ISC DHCP is a plugin since OPNsense 26.1 (`os-isc-dhcp`); without it its endpoints answer 404
   and are skipped. With the plugin, add its DHCP server and lease pages.

3. Create an API key for the user (*API keys*, `+`); the browser downloads a file with key and
   secret.

OPNsense privileges are per page and do not distinguish reading from writing: the user can call
the write endpoints of these pages too (for example start a firmware update). Signalbox only
sends `GET` requests with this user, but treat the key like an admin password, and restrict who can reach the
web interface. The privileges above are what the integration tests give their read user
(verified on 26.7.9: everything is read, the configuration history is refused with 403).
Their patterns only match the snake_case paths (`get_arp`, not `getArp`), which is why
Signalbox uses those. A missing privilege shows up as `access denied (HTTP 403); check the user's
privileges` for the capability that needs it, the rest is still read.

## Writing (changes)

With `deploy.enabled` and *Allow changes* on the device, Signalbox can change:

| Kind | What it does on the firewall | Endpoints (all `POST`) |
| --- | --- | --- |
| `router` | **update**: sets the static IPv4 address (and the description, if the name changes) of the interface assigned to the network; IPv6 is left alone. **create** (VLAN networks only): creates the VLAN device on the LAN's port if it does not exist (device name `vlan0.<tag>`), assigns it as a new interface (`optN`, not locked) with a static IPv4 address. **remove** (VLAN networks only): unassigns the interface and deletes its VLAN device when nothing else uses it | `/api/interfaces/vlan_settings/add_item`, `del_item/<uuid>`, `reconfigure`; `/api/interfaces/assignment/add_item`, `set_item/<identifier>`, `del_item/<identifier>`, `reconfigure` |
| `dhcp` | Kea DHCPv4: creates, updates or deletes the subnet of the network's interface (pool, DNS servers, lease time; on a new subnet the router option is the interface address and option autocollect is off), and adds or removes the interface from the interfaces Kea listens on (turning a network on also turns the Kea service on) | `/api/kea/dhcpv4/add_subnet`, `set_subnet/<uuid>`, `del_subnet/<uuid>`, `/api/kea/dhcpv4/set`, then `/api/kea/service/reconfigure` |
| `reservation` | adds, changes or deletes a Kea reservation in the network's subnet | `/api/kea/dhcpv4/add_reservation`, `set_reservation/<uuid>`, `del_reservation/<uuid>`, then `/api/kea/service/reconfigure` |
| `port` | the **tagged** VLANs of a port are the VLAN devices with that port as parent: adds and deletes them. The **untagged** network of a port is its interface assignment, which is never changed (refused) | `/api/interfaces/vlan_settings/add_item`, `del_item/<uuid>`, `reconfigure` |

Not writable: `wlan` (OPNsense is no access point). Unbound host overrides are not a change
kind of Signalbox yet.

Refused, with a message naming the reason, before anything is sent:

- **ISC DHCP**: the OPNsense API cannot change ISC DHCP (its ranges and options live on legacy
  pages). A DHCP or reservation change on a network served by ISC is refused; move the network
  to Kea DHCP to manage it with Signalbox.
- **Router interfaces on OPNsense before 26.7.6**: *Interfaces > Assignments* got an API in
  26.7 (`/api/interfaces/assignment/*`), but only with device, description and lock; the
  address fields (`type4`, `ipaddr`, ...) came with 26.7.6. Without them (no `ipaddr` in the
  assignment rows, or no API at all) every `router` change is refused (`no interface assignment
  API with addresses`); `dhcp`, `reservation` and `port` do not need it.
- removing or creating the LAN or a network on its own port (only VLAN networks are created and
  removed); a new network without a name; names other than letters, digits and `_` (OPNsense's
  rule for interface descriptions); IPv6 router addresses; a new DHCP network without
  `lease_seconds` while Kea has a default lease time (Kea always hands one out, so the read could
  never show "none"); deleting a VLAN that still carries an assigned interface; a locked
  interface (unlock it in the web interface).

A validation error of the firewall becomes an error naming the field, for example
`/api/interfaces/vlan_settings/add_item: the firewall refused the change (vlan.tag: Tag for this
device must be unique.)`.

`plan_changes` lists every call with its payload for the review. A call that refers to
something an earlier change of the same deployment creates shows a placeholder, for example
`{new subnet 203.0.113.0/24}`; during the deployment each change is planned again on a fresh
read, so the calls sent use the real identifiers. No secret is ever part of a payload.

### No confirm timer: backup and restore

The OPNsense API applies a change at once and has no confirm-or-revert timer, so `apply` never
returns a deadline. Safety comes from the backup:

- **backup**: `GET /api/core/backup/backups/this` lists the configuration history; Signalbox
  downloads the newest revision (the configuration in use) with
  `GET /api/core/backup/download/this/<id>` and stores the `config.xml` encrypted with the
  change (format `opnsense-config-xml`). An empty history (history switched off) refuses the
  deployment before anything is changed.
- **restore** (when applying or verifying fails, or when you restore a backup): finds the stored
  revision in the history again (same revision time and content), reverts to it with
  `POST /api/core/backup/revert_backup/<id>` and applies it with the `reconfigure` calls of VLANs,
  interface assignments and Kea (a component that is not installed is skipped). Restoring twice
  is harmless. If the revision was pruned from the history in the meantime, the restore fails
  with a message: upload the `config.xml` stored with the change in *System > Configuration >
  Backups* by hand (the upload is not part of the API).

Verified on 26.7.9: the newest history revision is the configuration in use (every API save
adds one), and `revert_backup` with the `reconfigure` calls puts VLANs, interface assignments
and addresses and Kea back without a reboot. One leftover: a VLAN device created after the
backup stays in the kernel (unassigned, no longer in the configuration) until the next reboot;
the read side ignores unassigned VLAN devices, so the network reads as before.

Because there is no timer, a change that cuts Signalbox off from the firewall (a new LAN address,
for example) cannot be undone automatically: the verification fails, and the restore cannot
reach the firewall either. Signalbox marks such changes as risky in the review.

### A separate API user for writing

Keep the read-only user for observing and create a second user for deployments; store its key
in the device settings only while changes are allowed. It needs the read privileges above plus:

| Privilege (as named in the web interface) | Needed for |
| --- | --- |
| Interfaces: VLAN | `/api/interfaces/vlan_settings/*` (create and delete VLAN devices) |
| Interfaces: Assign network ports | `/api/interfaces/assignment/*` (router interfaces, 26.7.6 and newer) |
| Services: DHCP: Kea(v4) | `/api/kea/dhcpv4/*`, `/api/kea/service/reconfigure` |
| Diagnostics: Configuration History | `/api/core/backup/*` (backup and restore) |

These are the privileges of the integration tests' write user (verified on 26.7.9). As with reading, OPNsense privileges are per page: this user can change everything on
these pages, so treat its key like an admin password.

## Mapping to the model

- **Ports**: every interface row except loopback, `enc`, `pflog`, `pfsync` and VLAN devices.
  Kind from the name (`bridge*`, `lagg*`, tunnels as virtual), speed and duplex from `media`.
- **Segments**: an assigned VLAN interface is `<site>/segment/<tag>` with its parent port tagged;
  VLANs that are defined but not assigned also appear. The untagged LAN (`lan`) is the native
  segment. Any other untagged assigned interface (for example a DMZ on its own port) is
  `<site>/segment/<identifier>`. The WAN (`wan`) is the uplink and only appears as a port.
- **Uplink** (#148): the `wan` row is `<device>/uplink/wan` on its port. Kind from `link_type`
  (`dhcp`, `static`, `pppoe`; anything else, such as `l2tp` or `ppp`, is `other`), up when
  `status` is `up` and the interface has an address (`no carrier`: down), addresses from
  `ipv4`/`ipv6` (link-local left out), the upstream gateway from `gateways` (else
  `ifctl.router`), the provider's resolvers from `ifctl.nameserver` and the delegated prefix from
  `ifctl.prefix`. The API reports no connection uptime, line rate or public address; the
  gateway monitor (`/api/routes/gateway/status`) is not read, so no privilege is added.
- **Subnets**: each global address of an assigned, non-WAN interface, with `gateway: true`.
  Link-local and loopback addresses are skipped.
- **DHCP (Kea)**: one server per Kea subnet, attached to the interface whose network contains it;
  enabled when Kea is enabled and listens on that interface. The lease time is the subnet's own
  `valid_lifetime`, else the general one. Pools from `pools` (ranges or CIDR,
  one per line). With `option_data_autocollect`, empty router, DNS and NTP options become the
  interface address: OPNsense writes that address into all three on every Kea save
  (`KeaDhcpv4::setNodes`; in CI an empty `ntp_servers` of the LAN subnet was filled in by the
  first deployment). Reservations by subnet.
- **DHCP (ISC)**: researched against opnsense/plugins `net/isc-dhcp` (#242): its API has exactly
  two controllers, `DHCPv4/Api/Leases` (`search_lease`) and `DHCPv4/Api/Service` (`status`, start,
  stop, restart). There is no settings or static-map API; ranges, router, DNS, NTP, domain, lease
  time, options and failover live in `config.xml` (`dhcpd`), edited on legacy pages. The only
  reader is the configuration backup, whose privilege exposes every secret; Signalbox does not
  use it for reading, so these stay unknown (no pools, router, DNS) until OPNsense adds an API.
  Kea is read first; ISC only for interfaces that no enabled Kea server serves (Kea off or not
  configured: ISC alone; both: each on its own interfaces). Signalbox reports one server per interface that has leases, enabled when the service runs,
  with the static mappings from the lease list as reservations, and no pools.
- **DNS** (#241): Unbound is `<device>/dns/unbound`. Listen addresses are the addresses of the
  selected interfaces (all when none is selected), the port is `general.port`. Global forwarders
  (`dots` entries without a domain) become `forwarders` with their port (empty: 853 for DNS over
  TLS, 53 for a plain forward, Unbound's defaults); per-domain forwards go to
  `vendor_extra.domain_forwards`. Enabled `A`/`AAAA` host overrides become host records.
  Dnsmasq (`/api/dnsmasq/settings/get`, OPNsense 25.1+) is `<device>/dns/dnsmasq` when enabled
  with a DNS port (`port` 0 is DHCP only, empty is 53): its selected interfaces, port and
  `hosts`; its upstreams are the system's DNS servers, which this API does not show. When
  neither listens on port 53 although one is on, something else does (AdGuard Home, a plugin
  whose API needs its own login): it is reported as `<device>/dns/port-53` with
  `config_read: false`, its settings are not read.
- **Clients**: merged by MAC from ARP, NDP, ISC and Kea leases; the firewall's own MACs, permanent
  and incomplete entries are skipped. Segment and port from the interface the entry was seen on,
  otherwise from the address.
- **Health** (#178): the dashboard widgets: uptime and load averages (`system_time`), memory
  (`system_resources`; the ZFS ARC, where there is one, is cache and not counted as used), the
  file systems (`system_disk`: `/` is `system`, tmpfs `temporary`, other UFS/ZFS mounts `data`),
  the temperature sensors (`system_temperature`) and the CPU threads (`cpu_usage/get_cpu_type`).
  The CPU load is only an event stream (`cpu_usage/stream`) and is not read.
- **Time** (#179): the clock is the `Date` header of the `system_time` answer (the firewall's
  clock, whole seconds), the UTC offset its local `datetime` against that header; the NTP client
  is ntpd's peer list (`*` marks the peer in use, with its stratum). The time zone setting and the
  NTP configuration (servers, interfaces) are legacy pages without an API: no zone name, no NTP
  server. Kea's `option_data.ntp_servers` (option 42) is `DhcpServer.ntp_servers`.

### DHCP leases, options and relays (#183)

- **Leases** of every server, all states. Kea: `/api/kea/leases4/search` rows go to the server
  whose subnet holds the address (`hwaddr`, `client_id`, `hostname`, `expire` as epoch,
  `valid_lifetime`: `starts` = `expire` - lifetime; `state` 0 active, 1 declined, 2 expired);
  `reserved` when a reservation of the subnet has that MAC and address. ISC (plugin
  `os-isc-dhcp`, used where Kea does not serve the interface): `/api/dhcpv4/leases/search_lease`
  rows (`starts`, `ends` as `YYYY/MM/DD HH:MM:SS` UTC, `state`, `type` `static` is `reserved`; a
  static row without state is `reserved`). An ISC interface without rows has no server entry
  (the API lists leases only, see the note under DHCP).
- **Kea options**: `option_data.domain_search` (search list), `static_routes` (pairs
  `a.b.c.d/n - gateway`), `tftp_server_name`, `boot_file_name`, `time_servers` (option 4),
  subnet `next_server`. *(guess: key names and the route format; CI dumps `search_subnet`.)*
- **Failover**: with `ha.enabled`, the first `/api/kea/dhcpv4/search_peer` row that is not
  `ha.this_server_name` is `failover_peer` *(guess)*. `authoritative` is not exposed: unknown.
- **Relays**: `/api/dhcrelay/settings/search_relay` (`enabled`, `interface`, `destination` as
  uuids of `search_dest`, whose rows have `server`), one `DhcpRelay` per interface *(guess:
  field names; the privilege `page-services-dhcprelay`, "Services: DHCRelay", is the one in the
  core ACL)*. A firewall without the DHCRelay privilege makes the DHCP read fail with an access
  error: add the privilege (the CI user has it).

## Endpoints and answers

As OPNsense 26.7.9 answers them (shortened; recorded by tools/integration/opnsense/dump.py in
every integration run). All `GET`, HTTP basic auth (key as user, secret as password). Grid endpoints get
`?current=1&rowCount=-1` (all rows). A 404 on the optional DHCP endpoints means "component not
installed" and is not an error.

### `/api/core/firmware/status` (system)

```json
{"status": "none", "product": {"product_name": "OPNsense", "product_version": "26.7.9_3",
  "product_latest": "26.7.9", "product_series": "26.7"}}
```

`product_version` is required; the fields may also be at the top level. It carries the package
revision (`_3`), `product_latest` does not: the same release is no update.

### `/api/interfaces/overview/interfaces_info` (interfaces)

```json
{"rows": [{"device": "vtnet0", "identifier": "lan", "description": "LAN", "status": "up",
  "is_physical": true, "macaddr": "02:00:00:00:01:00", "media": "10Gbase-T <full-duplex>",
  "vlan_tag": null, "ipv4": [{"ipaddr": "192.0.2.1/24"}],
  "ipv6": [{"ipaddr": "2001:db8:1::1/64"}, {"ipaddr": "fe80::ff:fe00:100/64"}]},
 {"device": "vlan0.20", "identifier": "opt1", "description": "IoT", "is_physical": false,
  "vlan_tag": "20", "ipv4": [{"ipaddr": "198.51.100.1/24"}]},
 {"device": "vtnet2", "identifier": "", "description": "Unassigned Interface", "ipv4": []}]}
```

Each row also has flags, capabilities, routes and the interface's `config`. `identifier` is
empty for unassigned devices; `pfsync0` is never listed. The `wan` row also carries what the
interface received, as OPNsense's interface overview builds it (`OverviewController.php`, the
`/tmp/<device>_<key>[v6]` files of `Autoconf`): one string per address family, the file's
content with one value per line. OPNsense 26.7.9 in CI (DHCP on QEMU's user network, no IPv6)
answers `"link_type": "dhcp"`, `"link_typev6": "none"`, `"gateways": ["10.0.2.2"]`,
`"ifctl.nameserver": ["10.0.2.3"]`, `"ifctl.router": ["10.0.2.2"]` *(`ifctl.prefix` of a WAN
with DHCPv6-PD not seen yet, #21)*:

```json
{"device": "vtnet1", "identifier": "wan", "status": "up", "link_type": "dhcp",
 "link_typev6": "dhcp6", "ipv4": [{"ipaddr": "100.64.23.45/22"}],
 "gateways": ["100.64.20.1"], "ifctl.nameserver": ["100.64.0.53"],
 "ifctl.router": ["100.64.20.1"], "ifctl.prefix": ["2001:db8:1::/56"]}
```

Port details (#156) from the same rows: `description` and `enabled` of an assigned interface
(an unassigned device, such as a VLAN trunk, has neither; a disabled interface whose device is
still up, because VLANs run on it, is reported as unknown), `mtu`, the fastest entry of
`supported_media` as the maximum speed, `media_raw` with `autoselect` as auto-negotiation, and
the medium of a physical port from its media words (`baseT`/`baseTX` copper; `SX`, `LX`, `SR`,
`LR`, `Twinax`, ... a cage, `sfp+` from 10 Gbit/s). *Guess*: `enabled`, `mtu`,
`supported_media` and `media_raw` from the OPNsense source (the integration test checks
`description`, `enabled` and `mtu` on 26.7):

```json
{"device": "igb0", "identifier": "lan", "description": "LAN", "enabled": true, "mtu": "1500",
 "media": "1000baseT <full-duplex>", "media_raw": "Ethernet autoselect (1000baseT <full-duplex>)",
 "supported_media": ["autoselect", "1000baseT <full-duplex>", "100baseTX <full-duplex>"]}
```

### `/api/interfaces/vlan_settings/search_item` (interfaces)

```json
{"rows": [{"uuid": "...", "if": "vtnet2", "tag": "20", "pcp": "0", "proto": "",
  "descr": "IoT", "vlanif": "vlan0.20 [IoT]"}]}
```

An assigned VLAN's `vlanif` has the interface description appended in brackets; Signalbox
strips it. New VLAN devices are named `vlan0.<tag>` by Signalbox (OPNsense would number them
`vlan01`, `vlan02`, ... when no name is given).

### `/api/interfaces/assignment/search_item` (writing, 26.7.6 and newer)

```json
{"rows": [{"uuid": "opt1", "identifier": "opt1", "if": "vlan0.20", "descr": "IoT", "lock": "0",
  "enable": "1", "type4": "staticv4", "ipaddr": "198.51.100.1/24", "type6": "",
  "ipaddrv6": ""}]}
```

### `/api/kea/dhcpv4/get`, `search_subnet`, `search_reservation` (dhcp)

`get` has the general settings only (`general`, `lexpire`, `ha`):

```json
{"dhcpv4": {"general": {"enabled": "1", "valid_lifetime": "4000",
  "interfaces": {"lan": {"value": "LAN", "selected": 1}, "opt1": {"value": "IoT", "selected": 0}}}}}
```

Subnets and reservations are grids (`?current=1&rowCount=-1`); nested fields are named with
dots:

```json
{"rows": [{"uuid": "<uuid>", "subnet": "192.0.2.0/24", "pools": "192.0.2.100-192.0.2.199",
  "valid_lifetime": "", "option_data_autocollect": "1", "option_data.routers": "",
  "option_data.domain_name_servers": "", "option_data.domain_name": "", "description": "LAN"}]}
```

```json
{"rows": [{"uuid": "<uuid>", "subnet": "<subnet uuid>", "%subnet": "192.0.2.0/24",
  "ip_address": "192.0.2.10", "hw_address": "02:00:00:00:00:10", "hostname": "printer"}]}
```

An answer of `get` that still contains `subnets` and `reservations` (the model form) is read
as well.

### `/api/kea/leases4/search` (clients)

```json
{"rows": [{"address": "192.0.2.100", "hwaddr": "00:00:5e:00:53:21", "hostname": "laptop",
  "if_name": "lan"}], "stats": {"active": 1}, "interfaces": []}
```

### `/api/dhcpv4/service/status`, `/api/dhcpv4/leases/search_lease` (dhcp, clients)

Only with the ISC DHCP plugin (404 on 26.7 without it; not tested in CI). Assumed answers, from
the plugin's source:

```json
{"status": "running"}
```

`running`, `stopped` or `disabled` (then the leases are not read for DHCP).

```json
{"rows": [{"address": "203.0.113.10", "mac": "00:00:5e:00:53:30", "hostname": "kiosk",
  "if": "opt2", "type": "static", "status": "offline"}]}
```

### `/api/unbound/settings/get` (dns)

```json
{"unbound": {
  "general": {"enabled": "1", "port": "53",
              "active_interface": {"lan": {"value": "LAN", "selected": 0}}},
  "dots": {"dot": []}}}
```

No selected interface means Unbound listens on all of them. `dots.dot` is a list when empty,
an object by uuid otherwise; an entry is `{"enabled": "1", "type": "dot" | "forward", "domain":
"", "server": "192.0.2.53", "port": ""}` (field names from the opnsense/core Unbound model).

### `/api/dnsmasq/settings/get` (dns, optional)

```json
{"dnsmasq": {"enable": "1", "port": "0", "interface": {"lan": {"value": "LAN", "selected": 1}},
  "hosts": {"<uuid>": {"host": "nas", "domain": "home.example", "ip": "192.0.2.10"}}}}
```

Not installed (404) or not allowed (403): not read. *Guess*: the shape follows the opnsense/core
Dnsmasq model; not yet seen on a real device.

### `/api/unbound/settings/search_host_override` (dns)

```json
{"rows": [{"uuid": "<uuid>", "enabled": "1", "hostname": "nas", "domain": "home.example",
  "rr": "A", "server": "192.0.2.10", "description": "", "isAlias": false}]}
```

### `/api/diagnostics/system/system_time`, `system_resources`, `system_disk`, `system_temperature`, `/api/diagnostics/cpu_usage/get_cpu_type` (health, time)

As 26.7.9 answers them to the read user with *Lobby: Dashboard* (QEMU, nano image):

```json
{"uptime": "00:00:16", "datetime": "Sun Nov 22 16:23:43 UTC 2026",
 "boottime": "Sun Nov 22 16:23:27 UTC 2026", "config": "Sun Nov 22 16:22:55 UTC 2026",
 "loadavg": "0.29, 0.06, 0.02"}
{"memory": {"total": "3176632320", "total_frmt": "3029", "used": 626695725, "used_frmt": "597"}}
{"devices": [{"device": "/dev/ufs/OPNsense_Nano", "type": "ufs", "total_bytes": 8023601152,
  "used_bytes": 2369683456, "available_bytes": 5012033536, "used_pct": 32, "mountpoint": "/"},
 {"device": "tmpfs", "type": "tmpfs", "total_bytes": 1588318208, "used_bytes": 1454080,
  "mountpoint": "/tmp"}, ...]}
[]
["AMD EPYC 7763 64-Core Processor (2 cores, 2 threads)"]
```

`uptime` is `HH:MM:SS`, after a day `N day(s), HH:MM:SS`. `memory.used` counts everything but
inactive, cached, laundry and free pages; with ZFS the answer also has `arc` (bytes), which is
subtracted. QEMU has no temperature sensors (`[]`); on hardware each row is `{"device":
"dev.cpu.0.temperature", "temperature": "47.0", "type": "cpu", ...}` (*Guess* from the
controller's source, the sensor name is `device`). `datetime` is PHP's `D M j G:i:s T Y` in the
firewall's zone; the zone abbreviation (`UTC`, `CET`) is not a usable name, so only the offset
against the `Date` header (rounded to 15 minutes) is kept.

### `/api/ntpd/service/status` (time)

ntpd's `ntpq` peers as a grid. Requested **without** `?current=1&rowCount=-1`: the pattern of
*Status: NTP* is the bare path, and 26.7.9 refuses the request with a query string (HTTP 403).
In CI, right after boot, only the pools are there:

```json
{"rows": [{"status": "__pool", "server": "0.opnsense.pool.ntp.org", "refid": ".POOL.",
  "stratum": "16", "type": "p", "when": "-", "poll": "64", "reach": "0", "delay": "0.000",
  "offset": "+0.000", "jitter": "0.000"}, ...]}
```

`status` `*` is the peer ntpd synchronises with (then in sync, `stratum` its stratum), `+`
candidates, `__pool` a configured pool. Seconds later the servers ntpd took from the pools
appear as rows of type `u` (status ` `, not yet selected), indistinguishable from configured
servers; the servers listed are every peer and pool in the answer. A 404 (ntpd not there) leaves the NTP client empty.

### `/api/diagnostics/interface/get_arp`, `/api/diagnostics/interface/get_ndp` (clients)

```json
[{"mac": "02:00:00:00:01:00", "ip": "192.0.2.1", "intf": "vtnet0", "expired": false,
  "expires": -1, "permanent": true, "type": "ethernet", "hostname": "",
  "intf_description": "LAN"}]
```

A plain list; `{"rows": [...]}` is accepted as well. NDP entries have no `permanent` field and
their addresses may carry a `%scope`. The camelCase paths (`getArp`) answer 403 to a user with
only the *Diagnostics: ARP Table* privilege.

### Write answers

`add_*` answer `{"result": "saved", "uuid": "..."}` (the assignment API answers the new
identifier, `opt2`), `set_*` `{"result": "saved"}`, `del_*` `{"result": "deleted"}`,
`reconfigure` `{"status": "ok"}`, `revert_backup/<id>` `{"status": "reverted"}`. A refused value
is `{"result": "failed", "validations": {"<model>.<field>": "<message>"}}`, for example
`reservation.ip_address: Address not in specified subnet`.

## Integration tests

`.github/workflows/integration.yml` (job `opnsense`, nightly, on demand and on pull requests
that touch adapters or simulators) downloads `OPNsense-26.7-nano-amd64.img.bz2` from the
official mirror, checks its SHA-256 against the published checksum file and a pinned hash, and
boots it in QEMU with KVM (tools/integration/opnsense/vm.py):

- first boot over the serial console: log in, update to the newest 26.7.x packages
  (`pkg upgrade`), preseed `/conf/config.xml` (tools/integration/opnsense/preseed.py: LAN
  vtnet0 192.0.2.1/24 and 2001:db8:1::1/64, WAN vtnet1 by DHCP, VLAN 20 "IoT" on the trunk
  vtnet2 as opt1 198.51.100.1/24, the read and write API users of
  tools/integration/opnsense/privileges.json with fresh keys), reboot, then through the API:
  Kea on LAN with a pool and a reservation, an Unbound host override. The prepared disk is
  cached (weekly, to pick up new 26.7.x releases).
- every run boots a throw-away overlay of that disk; the runner reaches the web interface at
  `https://127.0.0.1:8443` (a port forward to the LAN).
- tests/integration/test_opnsense_real.py: the read contract with the read user, the mapping of
  the preseeded firewall, certificate pinning with the real web interface certificate, a wrong
  secret (auth failed), the read user refused on the configuration history, deployments through
  the Deployer (a new VLAN network with Kea subnet and reservation; changed router address,
  DHCP pool, DNS and lease time, reservation and tagged VLANs on the trunk), each reverted to
  the original, the restore of a backup through the configuration history, a validation
  error of the firewall, and health and time with the read user's privileges.

The test VM is never run locally: without `IT_OPNSENSE_URL` the tests skip.

## Simulator

`signalbox.sim.opnsense.OpnsenseSimulator` answers all of these endpoints with neutral sample
data (documentation prefixes, `02:` MACs): LAN untagged with IPv4 and IPv6, VLAN 20 "IoT" and
VLAN 30 "Guest", an unassigned VLAN 40, a DHCP WAN behind the provider's carrier-grade NAT
(100.64.23.45/22, a delegated 2001:db8:1::/56), Kea on LAN and IoT, ISC on Guest, Unbound
overrides, ARP and NDP entries. Switches: wrong key or secret (401), `api_enabled=False` (404 everywhere),
`delay`, `malformed` (broken JSON per endpoint) and `fail` (a status code per endpoint or
endpoint prefix).

It also implements the write endpoints above. Writes change the answers of the read endpoints:
configuration endpoints (VLANs, Kea) at once, the interface overview after the assignment
`reconfigure`, as on a firewall. Every write stores a revision in a simulated configuration
history; a revision downloads as a `config.xml` that serialises the simulator's configuration,
and `revert_backup` puts it back. The simulated firewall checks fields like OPNsense does
(description characters, unique tags and device names, networks, pools inside the subnet, MACs,
locked interfaces) and answers `{"result": "failed", "validations": {"<field>": "..."}}`;
`invalid` forces such an answer for any write endpoint.
Where the integration tests found the real OPNsense answering differently, the simulator was
changed to answer the same way: snake_case paths (camelCase is accepted too, as by OPNsense's
router), `[<interface>]` after assigned VLAN names, Kea subnets and reservations as grids,
the package revision in `product_version`, assignment rows with address fields
(`assignment_api="26.7"` drops them, as before 26.7.6) and VLAN devices left behind by a
revert (`leftovers`).
`signalbox.sim.server.serve()` runs it on a free local port, over TLS with a certificate from
`self_signed_certificate()`.


## Management services (#173)

Signalbox reads only two things, because OPNsense has no narrow API for the rest:

- The **web interface** Signalbox itself uses (*verified on 26.7.9 in CI*): `https` (or `http` with `allow_insecure_http`)
  on the port of the configured address, always enabled (it answers). `transport_encrypted`
  follows the scheme.
- **SNMP**, when the `os-net-snmp` plugin is installed: `GET /api/netsnmp/general/get`
  (`general.enabled`, `listen`, and whether `general.community` is `public` or `private`; the
  string itself is never stored; the plugin's general settings are SNMP v2c only). Without the
  plugin the endpoint does not exist and no SNMP service is reported. The user needs the
  *Services: Net-SNMP* privilege for it (*guess: privilege name from the plugin's ACL, not tried
  in CI, where the plugin is not installed*); without it SNMP is left out.

**Not readable, and why.** The SSH daemon (enabled, port, listen interfaces, password and
root login), the web interface's own settings (listen interfaces, protocol, redirect from HTTP,
other ports) and the plugin's SNMPv3 users are only in the system configuration. The
administration page is a legacy PHP page with no API (`core/Api` has no controller for it),
and the only way to the values is the configuration backup (`/api/core/backup/download/this`),
which needs a privilege that exposes every secret of the firewall: certificates' private keys,
VPN and RADIUS secrets, password hashes. Signalbox does not download it for reading; the
backup privilege stays with the write user that needs it for changes. A rule that needs to know
whether SSH is on therefore has no answer for OPNsense.
