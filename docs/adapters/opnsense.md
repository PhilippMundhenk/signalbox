# OPNsense adapter

Adapter id `opnsense`, role `gateway`. Reads an OPNsense firewall through its REST API (every
read is a `GET`) and, when changes are allowed, writes router interfaces, VLANs on ports, Kea
DHCP subnets and reservations ([Writing](#writing-changes)).

| Capability | What is read |
| --- | --- |
| system | product name, firmware version and the newest available version |
| interfaces | ports, VLANs, assigned IPv4/IPv6 addresses: segments and subnets (the firewall is the gateway of each) |
| dhcp | Kea DHCPv4 (pools, router, DNS, domain, lease time, reservations); ISC DHCPv4 (enabled, static mappings) |
| dns | Unbound: enabled, listen addresses, forwarders, host overrides |
| clients | ARP and NDP tables plus DHCP leases (Kea and ISC), with segment and port |

> **Not yet confirmed on a real device.** The endpoint paths and JSON shapes below come from the
> public OPNsense API documentation and the source of the web interface, not from a recorded
> answer. Real-device validation is [issue #21](https://github.com/PhilippMundhenk/signalbox/issues/21).
> Parsing is deliberately tolerant: a missing field is left empty, unknown fields are ignored, and
> an answer of the wrong shape becomes a readable "could not read" finding
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

## A least-privilege API user

1. *System > Access > Users*: add a user `signalbox`, no shell, a scrambled password, no group
   memberships.
2. Give it only these privileges (*Effective Privileges*, edit):

   | Privilege (as named in the web interface) | Needed for |
   | --- | --- |
   | System: Firmware | `/api/core/firmware/status` (system) |
   | Status: Interfaces | `/api/interfaces/overview/*` |
   | Interfaces: Other Types: VLAN | `/api/interfaces/vlan_settings/*` |
   | Services: Kea DHCP: v4 (if Kea is used) | `/api/kea/dhcpv4/*`, `/api/kea/leases4/*` |
   | Services: DHCP: Server, Status: DHCP leases (if ISC DHCP is used) | `/api/dhcpv4/service/status`, `/api/dhcpv4/leases/*` |
   | Services: Unbound DNS: General, Host Overrides | `/api/unbound/settings/*` |
   | Diagnostics: ARP Table, Diagnostics: NDP Table | `/api/diagnostics/interface/getArp`, `getNdp` |

3. Create an API key for the user (*API keys*, `+`); the browser downloads a file with key and
   secret.

OPNsense privileges are per page and do not distinguish reading from writing: the user can call
the write endpoints of these pages too (for example start a firmware update). Signalbox only
sends `GET` requests with this user, but treat the key like an admin password, and restrict who can reach the
web interface. The privilege names above are from the documentation; check them against your
version. A missing privilege shows up as `access denied (HTTP 403); check the user's
privileges` for the capability that needs it, the rest is still read.

## Writing (changes)

With `deploy.enabled` and *Allow changes* on the device, Signalbox can change:

| Kind | What it does on the firewall | Endpoints (all `POST`) |
| --- | --- | --- |
| `router` | **update**: sets the static IPv4 address (and the description, if the name changes) of the interface assigned to the network; IPv6 is left alone. **create** (VLAN networks only): creates the VLAN device on the LAN's port if it does not exist (device name `vlan0.<tag>`), assigns it as a new interface (`optN`, not locked) with a static IPv4 address. **remove** (VLAN networks only): unassigns the interface and deletes its VLAN device when nothing else uses it | `/api/interfaces/vlan_settings/addItem`, `delItem/<uuid>`, `reconfigure`; `/api/interfaces/assignment/addItem`, `setItem/<identifier>`, `delItem/<identifier>`, `reconfigure` |
| `dhcp` | Kea DHCPv4: creates, updates or deletes the subnet of the network's interface (pool, DNS servers, lease time; on a new subnet the router option is the interface address and option autocollect is off), and adds or removes the interface from the interfaces Kea listens on (turning a network on also turns the Kea service on) | `/api/kea/dhcpv4/addSubnet`, `setSubnet/<uuid>`, `delSubnet/<uuid>`, `/api/kea/dhcpv4/set`, then `/api/kea/service/reconfigure` |
| `reservation` | adds, changes or deletes a Kea reservation in the network's subnet | `/api/kea/dhcpv4/addReservation`, `setReservation/<uuid>`, `delReservation/<uuid>`, then `/api/kea/service/reconfigure` |
| `port` | the **tagged** VLANs of a port are the VLAN devices with that port as parent: adds and deletes them. The **untagged** network of a port is its interface assignment, which is never changed (refused) | `/api/interfaces/vlan_settings/addItem`, `delItem/<uuid>`, `reconfigure` |

Not writable: `wlan` (OPNsense is no access point). Unbound host overrides are not a change
kind of Signalbox yet.

Refused, with a message naming the reason, before anything is sent:

- **ISC DHCP**: the OPNsense API cannot change ISC DHCP (its ranges and options live on legacy
  pages). A DHCP or reservation change on a network served by ISC is refused; move the network
  to Kea DHCP to manage it with Signalbox.
- **Router interfaces on OPNsense before 26.7**: interface assignments and addresses got an API
  with the MVC rewrite of *Interfaces > Assignments* in 26.7 (`/api/interfaces/assignment/*`).
  On older versions every `router` change is refused (`no interface assignment API`); `dhcp`,
  `reservation` and `port` work on 24.7 and newer.
- removing or creating the LAN or a network on its own port (only VLAN networks are created and
  removed); a new network without a name; names other than letters, digits and `_` (OPNsense's
  rule for interface descriptions); IPv6 router addresses; a new DHCP network without
  `lease_seconds` while Kea has a default lease time (Kea always hands one out, so the read could
  never show "none"); deleting a VLAN that still carries an assigned interface; a locked
  interface (unlock it in the web interface).

A validation error of the firewall becomes an error naming the field, for example
`/api/interfaces/vlan_settings/addItem: the firewall refused the change (vlan.tag: Tag for this
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
  `POST /api/core/backup/revertBackup/<id>` and applies it with the `reconfigure` calls of VLANs,
  interface assignments and Kea (a component that is not installed is skipped). Restoring twice
  is harmless. If the revision was pruned from the history in the meantime, the restore fails
  with a message: upload the `config.xml` stored with the change in *System > Configuration >
  Backups* by hand (the upload is not part of the API).

> **Needs confirmation on a real device** ([#21](https://github.com/PhilippMundhenk/signalbox/issues/21)):
> that the newest history revision always equals the running configuration, and whether
> `revertBackup` followed by the `reconfigure` calls puts interface addresses back without a
> reboot (the assignment `reconfigure` applies pending assignment changes; after a revert there
> may be none).

Because there is no timer, a change that cuts Signalbox off from the firewall (a new LAN address,
for example) cannot be undone automatically: the verification fails, and the restore cannot
reach the firewall either. Signalbox marks such changes as risky in the review.

### A separate API user for writing

Keep the read-only user for observing and create a second user for deployments; store its key
in the device settings only while changes are allowed. It needs the read privileges above plus:

| Privilege (as named in the web interface) | Needed for |
| --- | --- |
| Interfaces: Other Types: VLAN | `/api/interfaces/vlan_settings/*` (create and delete VLAN devices) |
| Interfaces: Assignments | `/api/interfaces/assignment/*` (router interfaces, 26.7 and newer) |
| Services: Kea DHCP: v4 | `/api/kea/dhcpv4/*`, `/api/kea/service/reconfigure` |
| Diagnostics: Configuration History | `/api/core/backup/*` (backup and restore) |

The privilege names are taken from the documentation and the source; check them against your
version. As with reading, OPNsense privileges are per page: this user can change everything on
these pages, so treat its key like an admin password.

## Mapping to the model

- **Ports**: every interface row except loopback, `enc`, `pflog`, `pfsync` and VLAN devices.
  Kind from the name (`bridge*`, `lagg*`, tunnels as virtual), speed and duplex from `media`.
- **Segments**: an assigned VLAN interface is `<site>/segment/<tag>` with its parent port tagged;
  VLANs that are defined but not assigned also appear. The untagged LAN (`lan`) is the native
  segment. Any other untagged assigned interface (for example a DMZ on its own port) is
  `<site>/segment/<identifier>`. The WAN (`wan`) is the uplink and only appears as a port.
- **Subnets**: each global address of an assigned, non-WAN interface, with `gateway: true`.
  Link-local and loopback addresses are skipped.
- **DHCP (Kea)**: one server per Kea subnet, attached to the interface whose network contains it;
  enabled when Kea is enabled and listens on that interface. The lease time is the subnet's own
  `valid_lifetime`, else the general one. Pools from `pools` (ranges or CIDR,
  one per line). With `option_data_autocollect`, empty router/DNS options become the interface
  address, as Kea does. Reservations by subnet.
- **DHCP (ISC)**: the API does not expose ISC ranges and options (they live on legacy pages).
  Signalbox reports one server per interface that has leases, enabled when the service runs,
  with the static mappings from the lease list as reservations, and no pools.
- **DNS**: one Unbound service. Listen addresses are the addresses of the selected interfaces
  (all when none is selected). Global forwarders (`dots` entries without a domain) become
  `forwarders`; per-domain forwards go to `vendor_extra.domain_forwards`. Enabled `A`/`AAAA`
  host overrides become host records.
- **Clients**: merged by MAC from ARP, NDP, ISC and Kea leases; the firewall's own MACs, permanent
  and incomplete entries are skipped. Segment and port from the interface the entry was seen on,
  otherwise from the address.

## Endpoints and assumed answers

All `GET`, HTTP basic auth (key as user, secret as password). Grid endpoints get
`?current=1&rowCount=-1` (all rows). A 404 on the optional DHCP endpoints means "component not
installed" and is not an error.

### `/api/core/firmware/status` (system)

```json
{"status": "update", "product": {"product_name": "OPNsense", "product_version": "24.7.1",
  "product_latest": "24.7.2"}}
```

`product_version` is required; the fields may also be at the top level.

### `/api/interfaces/overview/interfacesInfo` (interfaces)

```json
{"rows": [{"device": "igb0", "identifier": "lan", "description": "LAN", "status": "up",
  "macaddr": "02:00:00:00:01:00", "media": "1000baseT <full-duplex>", "vlan_tag": null,
  "ipv4": [{"ipaddr": "192.0.2.1/24"}],
  "ipv6": [{"ipaddr": "2001:db8:1::1/64", "link-local": false}]}]}
```

`identifier` is empty for unassigned devices.

### `/api/interfaces/vlan_settings/searchItem` (interfaces)

```json
{"rows": [{"uuid": "...", "vlanif": "vlan01", "if": "igb0", "tag": "20", "descr": "IoT"}]}
```

### `/api/kea/dhcpv4/get` (dhcp)

```json
{"dhcpv4": {
  "general": {"enabled": "1", "valid_lifetime": "4000",
              "interfaces": {"lan": {"value": "LAN", "selected": 1}}},
  "subnets": {"subnet4": {"<uuid>": {"subnet": "192.0.2.0/24",
      "pools": "192.0.2.100-192.0.2.199", "option_data_autocollect": "1",
      "option_data": {"routers": "", "domain_name_servers": "", "domain_name": ""}}}},
  "reservations": {"reservation": {"<uuid>": {
      "subnet": {"<subnet uuid>": {"value": "192.0.2.0/24", "selected": 1}},
      "ip_address": "192.0.2.10", "hw_address": "02:00:00:00:00:10", "hostname": "printer"}}}}}
```

### `/api/kea/leases4/search` (clients)

```json
{"rows": [{"address": "192.0.2.100", "hwaddr": "02:00:00:00:00:21", "hostname": "laptop",
  "if_name": "lan"}]}
```

### `/api/dhcpv4/service/status` (dhcp)

```json
{"status": "running"}
```

`running`, `stopped` or `disabled` (then the leases are not read for DHCP).

### `/api/dhcpv4/leases/searchLease` (dhcp, clients)

```json
{"rows": [{"address": "203.0.113.10", "mac": "02:00:00:00:00:30", "hostname": "kiosk",
  "if": "opt2", "type": "static", "status": "offline"}]}
```

### `/api/unbound/settings/get` (dns)

```json
{"unbound": {
  "general": {"enabled": "1", "port": "53",
              "active_interface": {"lan": {"value": "LAN", "selected": 1}}},
  "dots": {"dot": {"<uuid>": {"enabled": "1", "type": "forward", "domain": "",
                              "server": "192.0.2.53", "port": "53"}}}}}
```

### `/api/unbound/settings/searchHostOverride` (dns)

```json
{"rows": [{"enabled": "1", "hostname": "nas", "domain": "home.example", "rr": "A",
  "server": "192.0.2.10"}]}
```

Newer versions may call the address field `address`; both are accepted.

### `/api/diagnostics/interface/getArp`, `/api/diagnostics/interface/getNdp` (clients)

```json
[{"mac": "02:00:00:00:00:10", "ip": "192.0.2.10", "intf": "igb0", "permanent": false,
  "hostname": "printer.home.example"}]
```

A plain list; `{"rows": [...]}` is accepted as well. NDP addresses may carry a `%scope`.

## Simulator

`signalbox.sim.opnsense.OpnsenseSimulator` answers all of these endpoints with neutral sample
data (documentation prefixes, `02:` MACs): LAN untagged with IPv4 and IPv6, VLAN 20 "IoT" and
VLAN 30 "Guest", an unassigned VLAN 40, Kea on LAN and IoT, ISC on Guest, Unbound overrides,
ARP and NDP entries. Switches: wrong key or secret (401), `api_enabled=False` (404 everywhere),
`delay`, `malformed` (broken JSON per endpoint) and `fail` (a status code per endpoint or
endpoint prefix).

It also implements the write endpoints above. Writes change the answers of the read endpoints:
configuration endpoints (VLANs, Kea) at once, the interface overview after the assignment
`reconfigure`, as on a firewall. Every write stores a revision in a simulated configuration
history; a revision downloads as a `config.xml` that serialises the simulator's configuration,
and `revertBackup` puts it back. The simulated firewall checks fields like OPNsense does
(description characters, unique tags and device names, networks, pools inside the subnet, MACs,
locked interfaces) and answers `{"result": "failed", "validations": {"<field>": "..."}}`;
`invalid` forces such an answer for any write endpoint.
`signalbox.sim.server.serve()` runs it on a free local port, over TLS with a certificate from
`self_signed_certificate()`.
