# OPNsense adapter

Adapter id `opnsense`, role `gateway`. Reads an OPNsense firewall through its REST API (every
read is a `GET`) and, when changes are allowed, writes router interfaces, VLANs on ports, Kea
DHCP subnets and reservations, and firewall rules, port forwards and zone policies
([Writing](#writing-changes), [Firewall changes](#firewall-changes-295)).

| Capability | What is read |
| --- | --- |
| system | product name, firmware version and the newest available version |
| interfaces | ports, VLANs, assigned IPv4/IPv6 addresses: segments and subnets (the firewall is the gateway of each) |
| dhcp | Kea DHCPv4 (pools, router, DNS, domain, lease time, reservations); ISC DHCPv4 (enabled, static mappings) |
| dns | Unbound: enabled, listen addresses and port, forwarders with ports, host overrides; dnsmasq's DNS when on; an unread DNS server on port 53 when neither listens there (AdGuard Home) |
| clients | ARP and NDP tables plus DHCP leases (Kea and ISC), with segment and port |
| vpn | WireGuard instances as running (`wg show`): interface, state, listen port, public key, addresses and MTU from the interface overview; peers with public key, name, endpoint, allowed IPs, last handshake, transfer, keepalive ([WireGuard](#wireguard)) |

> **Verified against OPNsense 26.7.9 in CI.** The endpoints, privileges, answers and write
> calls below are checked every night against the official OPNsense nano image (26.7, updated
> to the newest 26.7.x) running in QEMU: tests/integration/test_opnsense_real.py, set up by
> tools/integration/opnsense/ ([Integration tests](#integration-tests)). 25.1 is read in CI as
> well, 24.7 only by a simulator variant ([Versions](#versions-390)). Parsing stays tolerant: a missing field is left empty, unknown fields are
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

*Set up automatically* in the device form (#231, [ADR 0009](../adr/0009-automatic-setup-with-an-admin-login.md))
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

The calls are those of the web interface's user manager (OPNsense 25.1 and later; [Versions](#versions-390)):
`POST /api/auth/user/search`, `GET /api/auth/user/get/<uuid>`, `POST /api/auth/user/add` or
`set/<uuid>` with `{"user": {"name", "descr", "scrambled_password": "1", "priv": "<ids>",
"group_memberships": ""}}`, `POST /api/auth/user/add_api_key/signalbox` (answers `key` and
`secret`), `POST /api/auth/user/search_api_key` and `del_api_key/<id>`; the removal is
`POST /api/auth/user/del/<uuid>`. A user `signalbox` with scope `system` is left alone.
Running it again puts the privileges back as documented and replaces the key.

The plan also offers *Also read the ISC DHCP settings* (off by default): the script and SSH key
of [ISC DHCP settings](#isc-dhcp-settings-optional-242), over SSH as root with a second pinned
host key.

The plan also offers *Also let Signalbox list the accounts* (off by default, #349): it adds the
privilege *System: Access: Users* (`page-system-usermanager`) to the user, see
[Accounts](#accounts-175). Without it the device page says the accounts are not readable.

Verified in CI on 26.7 (`tests/integration/test_opnsense_setup_real.py`): pinning and a refused
root secret; the user created, the firewall read with its key (contract, every capability);
a second run with nothing to change but the key; with writes the privileges updated and the
old key refused afterwards; the new key refused by the user manager (403); the removal.

## ISC DHCP settings (optional, #242)

The ISC DHCP plugin (`os-isc-dhcp`) has an API for leases and the service state only. Ranges,
gateway, DNS and NTP servers, domain, lease times, static maps and the failover peer are in the
`<dhcpd>` and `<dhcpdv6>` sections of `/conf/config.xml`, and the only API that returns that
file is the backup, which also returns every password hash, API secret and VPN key of the
firewall. Signalbox does not read it. Instead it can read those settings through **one small
script that you install on the firewall** and that prints nothing else.

**Fully optional and off by default.** Without it Signalbox reads the ISC leases as before
(the server shows lease table and static leases, no pool or options, with a note saying why).
Nothing is installed unless you tick *Also read the ISC DHCP settings* in the plan of *Set up
automatically* and confirm it; `setup.enabled: false` turns the installation off completely
(the form does not offer it, the API refuses it). *Remove* in the same form deletes the script
and the key again. Kea comes first: ISC settings are read only for interfaces no enabled Kea
server serves.

### What is installed

- `/usr/local/sbin/signalbox-isc-dhcp`, owner root, mode 0755: the file
  [`isc_script.py`](../../src/signalbox/adapters/opnsense/isc_script.py) of this repository,
  verbatim (about 150 lines of Python 3 standard library, OPNsense ships `python3`). It takes no
  argument and no input, reads `/conf/config.xml` and prints JSON. Per interface of `<dhcpd>`
  and `<dhcpdv6>` it prints only: `enable`, `range` (from, to), `gateway`, `dnsserver`,
  `ntpserver`, `domain`, `defaultleasetime`, `maxleasetime`, `failover_peerip` and per static map
  the MAC (DUID), address and host name. Each value is checked against its format (an address, a
  MAC, a host name, a number) and dropped if it is not one; nothing else is ever printed (no
  other section, no `ddnsdomainkey`, no descriptions), whatever the file contains. A test feeds it
  a `config.xml` full of secrets and compares.
- One line in root's `/root/.ssh/authorized_keys`: a new ed25519 key made by Signalbox, whose
  private half is stored encrypted in Signalbox (`isc_ssh_key`):

  ```
  command="/usr/local/sbin/signalbox-isc-dhcp",restrict ssh-ed25519 AAAA... signalbox-isc-dhcp
  ```

  `command=` makes sshd run the script whatever the client asks for, `restrict` turns off
  forwarding, a terminal and everything else. The key can do exactly one thing: print that JSON.

### Why root with a forced command

The script has to read `/conf/config.xml`, which is readable by root only (0640 root:wheel).
The options OPNsense offers, and why this one was chosen:

- A non-root user with `sudo` or `doas` limited to the script: neither is part of the base
  system (`os-sudo` is an extra plugin), and the user would need a shell login, which the
  user manager only gives to members of the administrators group, a much wider access than one
  script.
- A non-root user in the group that may read the file: the file is root:wheel and OPNsense
  accounts cannot be put into `wheel`.
- A root key with a forced command and `restrict`: no extra package, nothing but one script
  can run, and the key is useless for a shell, a file copy or a tunnel even if it leaks. The
  price is that root login over SSH must be allowed (*System > Settings > Administration >
  Secure Shell*: *Permit root user login*). Leave *Permit password authentication* off if you
  can: a key is enough for this.

The SSH host key is pinned like the certificate: the setup shows its fingerprint, nothing
(not even the SSH password of root) is sent before you confirm it, and the confirmed
fingerprint is stored as `isc_ssh_host_key`; Signalbox only uses the key for a firewall that
presents it. The root SSH password given to the setup is used for that one request only and is
never stored or logged. To install, the setup needs root's SSH password (or key login is not
supported: use the manual way).

### Install it yourself

1. Copy `src/signalbox/adapters/opnsense/isc_script.py` to
   `/usr/local/sbin/signalbox-isc-dhcp`; `chown root:wheel` it and `chmod 0755` it.
   Read it first: it is short.
2. Make a key pair on the machine that runs Signalbox: `ssh-keygen -t ed25519 -N "" -C
   signalbox-isc-dhcp -f signalbox-isc`.
3. Add the line shown above (with the content of `signalbox-isc.pub`) to
   `/root/.ssh/authorized_keys` on the firewall. (Check after a reboot that it is still there; if
   the web interface rewrites the file, add the key under *System > Access > Users > root >
   Authorized keys* instead and prefix it with the same `command=...,restrict` options.)
4. Find the host key fingerprint on the firewall: `ssh-keygen -lf
   /etc/ssh/ssh_host_ed25519_key.pub` (`SHA256:...`).
5. In the device's settings (*Advanced*): `isc_ssh_key` = the private key file's content,
   `isc_ssh_host_key` = the fingerprint, optionally `isc_ssh_port` (default 22). Or in YAML:
   `isc_ssh_key: "-----BEGIN OPENSSH PRIVATE KEY-----..."`.
6. Check on the firewall: `/usr/local/sbin/signalbox-isc-dhcp | python3 -m json.tool`.

Removing it: delete the script, the `authorized_keys` line and the two settings.

### What Signalbox does with the output

For every interface the script reports as `enable`d (the ISC server runs and the plugin's status
is not `disabled`): the DHCP server gets the pool (`range`), router (`gateway`), DNS and NTP
servers, domain, lease time (`defaultleasetime`, ISC's default 7200 s when empty), the static
maps as reservations and the failover peer. An empty `gateway` or `dnsserver` means ISC hands out
the interface address or the firewall's own resolver; Signalbox shows what is configured, so
the field stays empty. IPv6 (`dhcpdv6`) is printed by the script for completeness and not read
yet. If the script cannot be run (key refused, host key changed, python missing, bad output) the
leases are read as before and the server's `vendor_extra.note` says why; the device does not
fail.

Not verified on a real firewall (#21): the `authorized_keys` handling by the web interface
(whether root's key file is kept), that root key login with a forced command is accepted with
the default sshd settings of OPNsense 26.7, and the layout of `<dhcpd>` of every plugin version.
The integration test image has no `os-isc-dhcp`, so CI covers the script, the adapter and the
setup against the simulator only (`signalbox.sim.opnsense_ssh`: an SSH server that runs the
installed script against a `config.xml` with planted secrets).
### Fix it

A read refused with HTTP 403 names the remedy *Add the missing privileges* (#215,
[ADR 0012](../adr/0012-fix-it-for-read-problems.md)): the
device page offers *Fix it* next to the error ("What to do" stays the manual way). With an API
key of root, after the certificate is trusted and the plan confirmed, Signalbox finds the user
the stored API key belongs to (`POST /api/auth/user/search_api_key`) and adds the privileges of
this guide it lacks (`POST /api/auth/user/set/<uuid>` with its current privileges plus the
missing ones, with those of the write user since changes are allowed). Its other privileges,
groups, password and keys stay; root and system users are refused. Then the firewall is read
again. Off with `setup.fixes: false` or `setup.enabled: false`.

Verified in CI on 26.7: the user `signalbox` without `page-status-ntp` gives a 403 with the
remedy, the fix adds exactly that privilege and the same key reads the firewall completely.

## A least-privilege API user

1. *System > Access > Users*: add a user `signalbox`, no shell, a scrambled password, no group
   memberships.
2. Give it only these privileges (*Effective Privileges*, edit; the user manager is not among
   them on purpose, see [Accounts](#accounts-175)):

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
   | VPN: WireGuard: Status | `/api/wireguard/service/show` (vpn: tunnels and peers; never *VPN: WireGuard: Configuration*, whose grids return the private keys) |
   | Firewall: Rules [new] | `/api/firewall/filter/search_rule` (firewall: the rules of all three kinds, see "Firewall and NAT") |
   | Firewall: Aliases | `/api/firewall/alias/search_item` (read-only patterns: search, list, get) |
   | Firewall: Groups | `/api/firewall/group/search_item` (interface groups as zones) |
   | Firewall: NAT: Destination NAT | `/api/firewall/d_nat/search_rule` (port forwards) |
   | Firewall: NAT: Source NAT | `/api/firewall/source_nat/search_rule` (outbound NAT) |
   | Firewall: NAT: 1:1 | `/api/firewall/one_to_one/search_rule` (one-to-one NAT) |
   | System: Settings: Logging | `/api/syslog/settings/search_destinations` (remote syslog targets, #180; `page-diagnostics-logs-settings-targets` in the core ACL) |
   | Diagnostics: Netflow configuration | `/api/diagnostics/netflow/getconfig` (NetFlow export, #180; `page-diagnostics-netflow`) |
   | System: Certificate Manager, System: Authority Manager | `/api/trust/cert/search`, `/api/trust/ca/search` (stored certificates and authorities, #330; `page-system-certmanager`, `page-system-camanager`; never `get/<uuid>` or the exports, which answer private keys) |
   | System: Static Routes, System: Gateways | `/api/routes/routes/searchroute`, `/api/routes/gateway/status` (static routes and gateway status, #149; `page-system-staticroutes`, `page-system-gateways`, *guess* until a 26.7 image says otherwise) |
   | System: Gateway Groups | `/api/routing/group_settings/search` (gateway groups, #150; `page-system-gatewaygroups`, **26.7 and newer only**: an older firewall does not know the privilege, the automatic setup leaves it out there, and the groups stay unread; the 26.7 integration image refused the read with 403 until the privilege was granted) |
   | Services: Dynamic DNS | `/api/dyndns/accounts/search_item` (dynamic DNS accounts of `os-ddclient`, #154; `page-services-dyndns`, *guess*) |

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

## WireGuard

Read with the `vpn` capability (adapter API 1.3, #239) from one endpoint,
`GET /api/wireguard/service/show` (privilege *VPN: WireGuard: Status*, pattern
`api/wireguard/service/*`). It is `wg show all dump` as grid rows, parsed by OPNsense's
`wg_show.py`, which leaves out the private key of every interface and the pre-shared key of
every peer before the answer leaves the firewall:

- `type: interface` rows: `if` (`wg0`), `public-key`, `listen-port`, `status` (`up`/`down`
  from ifconfig), `name`/`ifname` (the instance name) → a `Tunnel` `<device>/tunnel/wg0`;
  addresses and MTU come from the interface overview row of the same device, which is also
  its port (`<device>/port/wg0`). FreeBSD shows a tunnel address with a host prefix
  (`2001:db8:ff::1/128` for an instance configured with `/64`, verified on 26.7.9).
- `type: peer` rows: `public-key`, `name` (the peer name), `endpoint` (`host:port`,
  `[v6]:port` or `(none)`), `allowed-ips` (comma list), `latest-handshake` (epoch seconds, 0:
  none), `transfer-rx`/`-tx`, `persistent-keepalive` (seconds or `off`) → `TunnelPeer`.

The configuration endpoints (`/api/wireguard/server/search_server`,
`/api/wireguard/client/search_client`) are not used: they need *VPN: WireGuard: Configuration*
and return every field of the model, the private keys (`privkey`, `psk`) included. The
consequence: a disabled instance or peer, which is not running, is not seen. The status
privilege also allows `api/wireguard/service/reconfigure` and `start`/`stop` (one pattern for
the whole service controller); Signalbox only sends the `GET`. Without the privilege the `vpn`
capability fails with `access denied (HTTP 403)`; everything else is still read.

Verified in CI (tests/integration/test_opnsense_real.py): the VM has an instance `s2s`
(2001:db8:ff::1/64, port 51820) with a peer `site-b` (allowed IPs 2001:db8:ff::2/128 and
2001:db8:20::/64, an endpoint that never answers, keepalive 25), and the read user gets 403 on
both configuration grids.

## Path traces (optional, #253)

Only while `traces.enabled` is on ([TRACES.md](../TRACES.md)): *Trace now* calls
`POST /api/diagnostics/traceroute/set` with
`{"traceroute": {"settings": {"hostname": "<address>", "ipproto": "inet", "protocol": "icmp",
"source_address": ""}}}`; the firewall runs configd's `interface traceroute`
(`traceroute -a -w 2 -q 1 -I`, at most 20 s) and answers `{"result": "ok", "response": {"rows":
[{"ttl", "AS", "host", "address", "probes"}]}}` (hops that did not answer are left out; Signalbox
fills in their TTL as unanswered). The API user needs the privilege **Diagnostics: Traceroute**
(`page-diagnostics-traceroute`); without it the call is HTTP 403 and the trace says so, with
*Fix it* (`privileges`) on the device page. The automatic setup and *Fix it* add the privilege
only while path traces are on.

## Firewall and NAT (#135)

Read with the `firewall` capability (adapter API 1.4, [ADR 0013](../adr/0013-firewall-zones-rules-and-reachability.md))
from six grids, each with the privilege in the table above (the privilege ids are
`page-filter-api`, `page-firewall-aliases`, `page-interfaces-groups-edit`,
`page-firewall-nat-portforward-edit`, `page-filter-snat-api`, `page-firewall-nat-1-1-edit`; they
are in `READ_PRIVILEGES` of the automatic setup and in `tools/integration/opnsense/privileges.json`,
a test compares them). Like all OPNsense privileges they also allow the write endpoints of their
pages; Signalbox only sends `GET`. Without one of them the `firewall` capability fails with
`access denied (HTTP 403)` and the *Fix it* "privileges" action adds it; the rest is still read.

- **Rules**: `filter/search_rule` lists, in evaluation order (`sort_order`), the rules of the new
  model, those of the legacy *Firewall: Rules* pages (`legacy`) and the automatic ones
  (`is_automatic`: anti-lockout, DHCP, ...), read from the controller source of 26.7. A release
  whose rows have no `sort_order` lists only the new model: `rules_complete = False`.
  An empty list counts the same. Seen on a real 25.1 (#379): the device page said "0 filter rules"
  and "Not every rule could be read". *Guess* (to confirm with a real 25.x, #21): there the API
  lists only the rules of *Firewall: Automation: Filter*, not those of the classic *Firewall:
  Rules* pages; no privilege is missing (the read privilege `page-filter-api` is the right one).
  Signalbox reports an optional gap (no change of the device status), and the zone matrix, the
  checks and the reachability treat every pair as unknown, never as `drop`. CI (26.7) lists the
  legacy rows. API reference: <https://docs.opnsense.org/development/api/core/firewall.html>.
  pf takes the first matching `quick` rule, else the last matching rule: the adapter lists the
  quick rules in order and then the others in reverse. `direction out` rules are `output` rules
  (forwarded traffic rides on the state of the `in` rule), the others have no chain (the
  destination tells). Legacy rows name interfaces by description: mapped back to identifiers.
  Not expressed (rule `exact = False`): schedules, TCP flags, tags, state limits, an alias of a
  URL table, GeoIP or external type, host names, a negated interface list. Zero rows or an action
  other than pass, block, reject (`match`) are not rules.
- **Zones** are the assigned interfaces (identifier `lan`, `wan`, `opt1`; description in
  `description`) and the interface groups (`group/search_item`), mapped to the segments, the
  `wan` uplink and, for WireGuard, to the tunnels (the `wireguard` group zone holds all instances).
  Policies: pf's default block, as `input_policy` and `forward_policy` `drop`.
- **Aliases**: `alias/search_item` (`name`, `type`, `content`, `enabled`): host, network,
  network group and port aliases are resolved (nested ones too); `lan`, `lanip`, `(self)` and
  interface groups in a network field become the interface's networks or addresses.
- **NAT**: `d_nat/search_rule` (flattened `destination.network`, `destination.port`, `target`,
  `local-port`, `pass`) to `PortForward` (`pass` = `pass` is `passes_filter`; automatic rows are
  skipped; a no-redirect exception row or a target that is no single address makes
  `port_forwards_complete` false); `source_nat/search_rule` to `NatRule` (no `target` is
  masquerade; a `nonat` row makes the others inexact); `one_to_one/search_rule` to a forward
  without ports and a `NatRule` (whole networks are not expressed: incomplete). A release without
  the MVC pages (404) leaves the forwards unread.
- **CI**: vm.py adds an alias, a rule (LAN, TCP 8443 to the alias) and a port forward (WAN 8443 to
  it, local port 443); `test_firewall_rules_and_port_forward` asserts them, the evaluation of the
  web interface from LAN and WAN, and the outbound NAT.
  Confirmed in CI (26.7.9): the privilege ids, the rows (legacy and automatic ones included),
  alias `content`, `filter/apply`. The firewall's own `sshlockout` and `virusprot` table rules
  and "block all targeting port 0" are left out (they only hit abusive hosts). *Guess*: floating
  legacy rules without `quick`, other releases.

## Writing (changes)

With `deploy.enabled` and *Allow changes* on the device, Signalbox can change:

| Kind | What it does on the firewall | Endpoints (all `POST`) |
| --- | --- | --- |
| `router` | **update**: sets the static IPv4 address (and the description, if the name changes) of the interface assigned to the network; IPv6 is left alone. **create** (VLAN networks only): creates the VLAN device on the LAN's port if it does not exist (device name `vlan0.<tag>`), assigns it as a new interface (`optN`, not locked) with a static IPv4 address. **remove** (VLAN networks only): unassigns the interface and deletes its VLAN device when nothing else uses it | `/api/interfaces/vlan_settings/add_item`, `del_item/<uuid>`, `reconfigure`; `/api/interfaces/assignment/add_item`, `set_item/<identifier>`, `del_item/<identifier>`, `reconfigure` |
| `dhcp` | Kea DHCPv4: creates, updates or deletes the subnet of the network's interface (pool, DNS servers, lease time; on a new subnet the router option is the interface address and option autocollect is off), and adds or removes the interface from the interfaces Kea listens on (turning a network on also turns the Kea service on) | `/api/kea/dhcpv4/add_subnet`, `set_subnet/<uuid>`, `del_subnet/<uuid>`, `/api/kea/dhcpv4/set`, then `/api/kea/service/reconfigure` |
| `reservation` | adds, changes or deletes a Kea reservation in the network's subnet | `/api/kea/dhcpv4/add_reservation`, `set_reservation/<uuid>`, `del_reservation/<uuid>`, then `/api/kea/service/reconfigure` |
| `port` | the **tagged** VLANs of a port are the VLAN devices with that port as parent: adds and deletes them. The **untagged** network of a port is its interface assignment, which is never changed (refused) | `/api/interfaces/vlan_settings/add_item`, `del_item/<uuid>`, `reconfigure` |
| `firewall-rule`, `port-forward`, `zone-policy` | tagged rules of the new rules page and tagged port forwards, and the zone policies as tagged rules ([Firewall changes](#firewall-changes-295)) | `/api/firewall/filter/add_rule`, `set_rule/<uuid>`, `del_rule/<uuid>`, `apply`; `/api/firewall/d_nat/add_rule`, `set_rule/<uuid>`, `del_rule/<uuid>`, `apply` |

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

### Firewall changes (#295)

Declared in `sites.<site>.firewalls` ([DESIRED.md](../DESIRED.md), [ADR 0017](../adr/0017-firewall-desired-state-and-deployments.md)).
What Signalbox owns is tagged by the **description** of the row, and nothing else is touched:

| Declared | Written as | Tag (description) |
| --- | --- | --- |
| rule | a rule of the new rules page (`quick`, direction `in`, sequence 1, 2, ... so that they come before the device's own, which the web interface numbers from 100) on the source zone's interface (no source zone: a floating rule); a rule to the device has the destination `(self)`, a routed one with no destination `(self)` negated, one with a destination zone that zone's network (`lan`), else the addresses | `signalbox:<key>` and ` <name>` when the name has a `-` (the key is the name with `_`) |
| forward | a rule of the destination NAT page on the zone's interface, destination `<interface>ip` and the external port, target and local port, `pass` (an associated filter rule) | `signalbox:<key>[ <name>]` |
| zone policy | pass, block or reject from the interface to the network of the destination zone, to `(self)` for the device, sequence 900000 and up (a fallback behind every other rule); `drop` is no rule, because pf blocks what no rule passes | `signalbox:policy/<from>/<to or device>` |

- Rules, forwards and policies that carry the tag and are no longer declared are removed
  (policies stay until declared away, like on OpenWrt). The device's own rules and forwards are
  never touched, except `adopt: <name>`: the one row of the **new** pages with that description is
  changed in place (`set_rule`, which only sets the fields it is sent): it keeps its place and
  every field the declaration does not set (`log`, `statetype`, `category`, ...); the plan lists
  them. Rows of the legacy pages and the automatic
  ones cannot be deleted through the API, so adopting one is refused. `adopt: true` on a policy
  changes nothing here (a policy never removes the device's own rules).
  Undoing an adoption by *revert* is refused by the firewall (the old rule read back has the
  addresses of `(self)` expanded); restore the backup of the deployment instead.
- A rule with addresses needs `family: 4` or `family: 6` (OPNsense refuses addresses with
  "IPv4+IPv6"; confirmed on 26.7.9 in CI).
- Refused with the reason, before anything is sent: an unknown zone; a destination zone **and**
  destination addresses in one rule; more than one port or range per rule; ICMP without family
  4 or 6; protocols that no one rule matches (`tcp` and `icmp`); a forward on an interface group,
  to an IPv6 address, or with a protocol other than tcp, udp or both; a release without the
  destination NAT API (HTTP 404; forwards only).
- **No rollback timer on 26.7.** Up to 26.1 the filter API had `savepoint`, `apply/<revision>`
  and `cancel_rollback` (an automatic revert after 60 s). The controllers of 26.7.9 have none of
  them (`apply` only reloads the rules), so Signalbox does not offer a timer it cannot have: the
  changes are saved with the add, set and delete calls and applied with `filter/apply` (and
  `d_nat/apply`); when the verification fails the backup is restored (see below), which also
  reloads the rules. The lockout check of the plan is the protection against cutting Signalbox
  off: a plan that may do it needs the explicit override, and one that slips through cannot be
  undone from Signalbox (use the console).
- Privileges: no new ones. The privileges the firewall is *read* with already cover the write
  endpoints of the same pages (OPNsense privileges do not tell reading from writing): *Firewall:
  Rules [new]* (`page-filter-api`, `/api/firewall/filter/*`) and *Firewall: NAT: Destination NAT*
  (`page-firewall-nat-portforward-edit`, `/api/firewall/d_nat/*`), together with *Diagnostics:
  Configuration History* for the backup, as in "A separate API user for writing". So the write
  user of a deployment is the user that reads the firewall plus the privileges of that section;
  the read-only user has the same pages, which is why Signalbox only ever sends `GET` with it.
  Keep the key of a user that may write rules like an admin password: it can add a rule that
  opens the firewall. Never put it in a log; Signalbox logs the calls without secrets.
- *Guesses until a real device confirms them (#21)*: that `page-filter-api` also covers
  `filter/apply` and `d_nat/apply`; that sequences below 100 sort before the device's own rules;
  that a floating rule (no interface) with direction `in` is accepted; `ipv6-icmp` as the
  protocol of an IPv6 ICMP rule; a port range written `8000-8100`. The integration test
  (`test_firewall_rule_and_port_forward_then_revert`) writes one rule and one forward and
  reads them back on 26.7.9 (nightly and on pull requests).

### No confirm timer: backup and restore

The OPNsense API applies a change at once and has no confirm-or-revert timer (not for the
firewall changes either, see above), so `apply` never returns a deadline. Safety comes from the
backup:

- **backup**: `GET /api/core/backup/backups/this` lists the configuration history; Signalbox
  downloads the newest revision (the configuration in use) with
  `GET /api/core/backup/download/this/<id>` and stores the `config.xml` encrypted with the
  change (format `opnsense-config-xml`). An empty history (history switched off) refuses the
  deployment before anything is changed.
- **restore** (when applying or verifying fails, or when you restore a backup): finds the stored
  revision in the history again (same revision time and content), reverts to it with
  `POST /api/core/backup/revert_backup/<id>` and applies it with the `reconfigure` calls of VLANs,
  interface assignments and Kea and `filter/apply` (a component that is not installed is skipped). Restoring twice
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
| Firewall: Rules [new], Firewall: NAT: Destination NAT | `/api/firewall/filter/*`, `/api/firewall/d_nat/*` (firewall changes; already among the read privileges) |
| Diagnostics: Configuration History | `/api/core/backup/*` (backup and restore) |

These are the privileges of the integration tests' write user (verified on 26.7.9). As with reading, OPNsense privileges are per page: this user can change everything on
these pages, so treat its key like an admin password.

## Mapping to the model

- **Port structure** (#252, ADR 0008), only from the interface list and the VLAN list the API
  user can already read (no new privilege): rows with `is_physical` are `jack`; a VLAN device
  of `vlan_settings` is a port of role `vlan` (kind virtual) on its `if`; `lagg*` is `lag`,
  `bridge*` is `bridge`; `wg*`, `ovpn*`, `tun*`, `tap*`, `gif*`, `gre*`, `pppoe*` and `ipsec*` are
  `tunnel`. The members of a lagg or bridge are taken from `members`, `laggport` or
  `bridge_members` of the interface row where it has one; the LAGG and bridge pages
  (`/api/interfaces/lagg_settings/*`, `bridge_settings/*`) are not read, they would need more
  privileges. *Confirmed on the firewall in CI*: NICs as jacks, the VLAN device on its NIC;
  *guess* (needs a firewall with a lagg or bridge, #21): lagg and bridge members.

- **Ports**: every interface row except loopback, `enc`, `pflog`, `pfsync`. Kind from the name (`bridge*`, `lagg*`, tunnels as virtual), speed and duplex from `media`.
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
  TLS, 53 for a plain forward, Unbound's defaults); per-domain forwards (`dots` entries
  with a domain, also those of the domain override grid, when the release has one) are forwarders with
  `domain` set (#182; they were `vendor_extra.domain_forwards`). Further settings (#182, guesses for the
  setting names until checked on a real firewall, #21): `recursive` (no general forwarder and no
  `general.forwarding`), `rebind_protection` (true when "Private Addresses" `advanced.privateaddress`
  is set; Unbound's own default is not shown, so otherwise unknown) with `privatedomain` as
  `rebind_allowed_domains`, `cache_size` (`advanced.msgcachesize`, MB), `register_dhcp` (`regdhcp`),
  `dynamic_records` (`regdhcp` or `regdhcpstatic`), `local_domain` (`regdhcpdomain`) and
  `listen_segments` (the segments of the selected interfaces). The host overrides (#386, #393) are
  read as before and do not depend on the forwarders.
  Host records (#386), each with its `source`: enabled `A`/`AAAA` host overrides (`host-override`),
  their aliases (`alias`, with the addresses of the override they point to), and, when
  "Register DHCP static mappings" / "Register DHCP leases" is on, the names of the DHCP
  reservations (`dhcp-static`) and active leases (`dhcp-lease`) of the enabled servers, with the
  registration domain (`regdhcpdomain`, else the server's domain). DHCP-derived records follow the
  DHCP data, so the DNS checks that compare records with DHCP leave them out. The grids are read
  completely (`rowCount=-1`, then page by page up to `total`). Both spellings are tried
  (`search_host_override`, then `searchHostOverride`: 25.1 and older). A grid that cannot be read
  (refused, missing) is an optional gap naming the privilege *Services: Unbound DNS*
  (`page-services-unbound`) and the service shows "host records not read" (`host_records_read`
  false), not "none configured".
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
Ranges, options and static maps are not in this API: see
[ISC DHCP settings](#isc-dhcp-settings-optional-242).

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

*Guesses* for 25.1 and older (#21, #386): the camelCase spelling `searchHostOverride`; the target
in `server` (`address` or `ip` are accepted too); `rr` as a key (`A`) or a label (`A (IPv4 address)`).

### `/api/unbound/settings/search_host_alias` (dns)

```json
{"rows": [{"uuid": "<uuid>", "enabled": "1", "host": "<uuid of the override>",
  "hostname": "storage", "domain": "home.example", "description": ""}]}
```

*Guess* from the Unbound model: `host` is the uuid of the override (its name is tried, too). Not
found (404): no aliases. Same for `search_domain_override` (`domain`, `server`, `port`).
"Register DHCP leases" and "static mappings" are read from `general.regdhcp`,
`general.regdhcpstatic` and `general.regdhcpdomain` (also a `dhcp` node with `enable`, `static`,
`domain`): a *guess* for the names, not yet seen on 25.1 or 26.7.

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

## Versions (#390)

Signalbox supports the current OPNsense and the two major releases before it (rule of #389):
26.x, 25.x and 24.x. OPNsense 26.7 is the reference (every endpoint below is recorded from it);
the older releases were compared with the public sources of `opnsense/core` at the tags 24.7.12,
25.1.12, 25.7.11 and 26.1.11 (controllers, models, ACLs and the router), and are read with the
fallbacks below. The firmware version is read once per observation from
`core/firmware/status`; most behaviour does not depend on it (a missing endpoint is a 404 and
becomes an optional gap), the version only picks what a 404 cannot say.

| | 26.7 | 25.7 | 25.1 | 24.7 |
| --- | --- | --- | --- | --- |
| Reads (interfaces, VLANs, Kea, Unbound, ARP/NDP, WireGuard, certificates, routes, log targets) | CI | sources | CI | simulator, sources |
| Firewall rules (`filter/search_rule`) | all rules | one request per interface with `show_all=1` | one request per interface with `show_all=1` | four columns only: not read, gap |
| Port forwards (`firewall/d_nat`) | yes | optional gap | optional gap | optional gap |
| Source NAT, one-to-one (`source_nat`, `one_to_one`) | yes | yes | yes | yes |
| dnsmasq DNS (`dnsmasq/settings`) | yes | yes | yes | not there, ignored |
| NTP state (`ntpd/service/status`) | yes | yes | not there, no NTP state | not there, no NTP state |
| Disk table (`system_disk`) | `total_bytes`, `used_bytes` | `df -h` sizes | `df -h` sizes | `df -h` sizes |
| Interface assignment API (router writes) | 26.7.6 and newer | no | no | no |
| Interface negation in a rule (`interfacenot`, writes) | yes | yes | yes | no, refused with a message |
| User manager API (automatic setup, Fix it, accounts) | yes | yes | yes | no, manual setup only |
| WireGuard status privilege | *VPN: WireGuard: Status* | *Status* | *VPN: WireGuard* (full page) | *VPN: WireGuard* (full page) |
| Automatic setup, writes (VLAN, Kea, firewall rules) | CI | simulator | simulator | simulator |

What the sources showed, and what the adapter does about it:

- **Action spelling.** The router of 24.7 and newer turns `search_item` and `searchItem` into
  the same action (`Mvc/Router.php`), but the privileges (ACL patterns) name the action as the
  release spells it: camelCase up to 25.1 (`api/diagnostics/system/systemTime`, `getArp*`),
  snake_case from 25.7. A key that is not root's gets **403** for the other spelling (seen on a
  real 25.1: `system_time`, `get_arp`). So every request uses the spelling of the firmware
  version read first (`compat.SNAKE_ACL`, `_ApiHttp`) and, on a 404, the other one. Releases
  before 24.7 are a guess (not checked).
- **ISC DHCP (core).** `dhcpv4/service/status` has no privilege before 26 (root only) and the
  leases need *Status: DHCP leases* (`page-status-dhcpleases`), which the read set of the guide
  does not include: a 403 there leaves ISC unread instead of failing DHCP and clients (found by
  the 25.1 CI run).
- **Port forwards.** `firewall/d_nat` is new in 26.1; on 25.x and 24.x the forwards stay unread
  (`port_forwards_complete` false) with the optional gap `opnsense.forwardsUnread`, naming the
  release. Changing a forward is refused with a message.
- **Rules (#379).** From 25.1 until 26.7 `search_rule` lists only the *floating* rules (no or
  several interfaces) of the new model by default (read on a real 25.1: `rows: []` for the
  rule of the LAN). `show_all=1` adds the legacy and the automatic rules (with `sort_order`),
  and a rule of one interface appears only when `interface=<identifier>` names its interface
  (`FilterController::searchRuleAction`). So the adapter asks once without and once per
  interface and interface group with `show_all=1`, and unites the rows by uuid in `sort_order`
  (a rule of the new model without one: after its `sequence`; *guess* until the 25.1 CI run
  checks the rule "Signalbox CI: NAS"). 24.7 lists four columns (`enabled`, `sequence`,
  `action`, `description`) and no `show_all`: the rules stay unread, the rules gap says so,
  the zone matrix is "unknown" (`get_rule` per uuid is not used).
- **Disk table.** `system_disk` answers `blocks`/`used`/`available` as `df -h` prints them
  (`28G`, `1.8G`) before 26.7: parsed by 1024 (`vitals.size_bytes`), rounded, so the usage is
  approximate there (*guess*: only 26.7's answer was recorded).
- **Uptime.** `system_time` words are translated with the interface language (`3 Tage,
  04:05:06`); the parser takes any word.
- **Accounts and automatic setup** need the user manager API of 25.1. On 24.7 the setup and
  *Fix it* stop with `opnsense.noUserApi` and the setup guide's manual steps; the accounts are
  not listed (no gap).
- **Privileges.** The read privileges of the guide exist on 24.7, 25.1 and 25.7 under the same
  ids, except *VPN: WireGuard: Status* (`page-wireguard-diagnostics`, 25.7): before that
  `api/wireguard/service/show` belongs to the full *VPN: WireGuard* page
  (`page-wireguard-config`), which also lets a key read the private keys through the other
  endpoints. Without it the WireGuard capability reports its privilege error; the other
  reads are not affected. The CI user of the 25.1 job has `page-wireguard-config`.
- **Not checked.** Plugins (os-net-snmp, os-dhcp) and Unbound's host overrides (#386, its own
  change). 24.7 stores API keys as `<apikeys><item>` in `config.xml`, 25.1 and newer as
  `key|hash`: the CI preseed (`preseed.py`) writes the second form, so a 24.7 image needs its
  own preseed.

CI: job `opnsense` of `.github/workflows/integration.yml` runs 26.7 with all tests and 25.1 with
tests/integration/test_opnsense_versions_real.py (read only), both from the official nano
images (`OPNSENSE_VERSION` in tools/integration/opnsense/vm.py). The 24.7 and 25.7 images are on
the same mirrors (hashes in `vm.py` for 24.7); 24.7 is not run because of the preseed format
above; 25.7 is not run to keep the job count down (25.1 is the release in use).

The simulator takes `OpnsenseSimulator(release="25.1")` or `"24.7"` (`sim.opnsense.RELEASES`,
`older_release`): the data of the release as listed above, `snake_case=False` for a release that
only knows camelCase actions. tests/test_opnsense_versions.py runs the adapter contract against
every variant and checks the fallbacks.

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
  DHCP pool, DNS and lease time, reservation and tagged VLANs on the trunk; one rule and one port
  forward, read back as declared), each reverted to the original, the restore of a backup through the configuration history, a validation
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
The rules of the new filter page and the destination NAT page can be added, changed and deleted
(`add_rule`, `set_rule/<uuid>`, `del_rule/<uuid>`; the legacy and automatic rows cannot), with
the field checks of the models (action, interface, protocol, networks, ports, sequence), kept in
the configuration history and reverted with it; `filter/apply` and `d_nat/apply` answer `OK` and
are listed in `applied`. There is no savepoint, as on 26.7.
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

## Log and flow targets (#180)

- **Remote syslog**: `GET /api/syslog/settings/search_destinations` (grid, privilege *System:
  Settings: Logging*, `page-diagnostics-logs-settings-targets`): `hostname`, `port`,
  `transport` (`udp4`, `tcp4`, `tls4`, ... or their display text `UDP(4)`), `enabled`, `level`,
  `facility`, `description`.
- **NetFlow**: `GET /api/diagnostics/netflow/getconfig` (privilege *Diagnostics: Netflow
  configuration*, `page-diagnostics-netflow`): `capture.targets` (`host:port` list), exported
  while `capture.interfaces` is not empty, `capture.version` (`v5`, `v9`). The local Insight
  collector (127.0.0.1:2056) is left out.

Both privileges are in the read user's list (automatic setup, *Fix it*). Without the syslog
privilege the targets are not read (an optional gap names the privilege); without the NetFlow
one only the flows are missing. *Verified in CI* with the destination and export the VM setup
adds (see tests/integration/test_opnsense_real.py).

## MAC address table (#160)

Not read: the API has no call for the bridge address cache (`ifconfig bridge0 addr`). The ARP
table's interface stays the clients' `seen_on`, which core counts for devices without a table.

## Accounts (#175)

The user manager (`POST /api/auth/user/search`, `/api/auth/user/search_api_key`,
`GET /api/auth/user/get/<uuid>`) has no read-only privilege: whoever may read it may change
every account. The API user of the setup guide therefore cannot read it, and Signalbox says so
(#349): the accounts stay unread (`accounts` is unset, which is not the same as an empty list
for "no accounts") and an *optional* gap on the device page, with the fix naming the privilege,
*System: Access: Users* (`page-system-usermanager`, confirmed against the core ACL on 26.7 in
CI, `tests/integration/test_opnsense_setup_real.py`). The device stays "ok". An OPNsense
without the user manager API (404) reports nothing.

It is **optional and your decision**: add that privilege to the user (*System > Access > Users*,
*Effective Privileges*), or tick *Also let Signalbox list the accounts* in the plan of *Set up
automatically* (off by default; running the setup again without it takes the privilege away
again). Mind that the user, and anyone holding its API key, can then also change every account
and privilege. *Fix it* never adds this privilege on its own.

A key that can read it is an administrator's: Signalbox then lists the users (privilege admin
for the `admins` group or `page-all`, write for other privileges, other for none;
`authorizedkeys` only as "has a key") and reports its own privilege as admin, so
`account.signalbox-privileged` suggests the least-privilege user of the guide (`write`: OPNsense
privileges are per page, not read-only). Which fields the search rows carry (`disabled`,
`is_admin`) is a *guess* (#21). API keys cannot be factory defaults: `default_credentials` stays
unknown.

## Stored certificates (#330)

- `GET /api/trust/cert/search` and `/api/trust/ca/search` (grids; privileges *System: Certificate
  Manager* and *System: Authority Manager*, both in the read user's list: automatic
  setup and *Fix it* add them; users made by hand before #330 need the two pages added).
  Per row: description, `commonname`, `valid_from`, `valid_to`, `caref` (the issuing authority),
  `in_use`, and the PEM of the public certificate (`crt_payload`) where the grid has it: key
  type and size, signature and fingerprint come from that.
- **Never read**: `get/<uuid>`, the export calls, `prv_payload`, `prv`, `csr_payload`. A test
  feeds a row full of key material and shows none of it is kept.
- Without a privilege an optional gap names it; what was readable is still reported.
- *Guess until the 26.7 integration image confirms it (#21)*: which fields the search rows
  carry (fields that are missing stay empty) and the date format. OPNsense does not say which
  VPN or service uses a certificate, so `cert.vpn-expiring` stays quiet for it.

## Routes (#149)

- `GET /api/routes/routes/searchroute` (grid; privilege *System: Static Routes*,
  `page-system-staticroutes`): `network`, `gateway` (the gateway's name), `disabled`, `descr`.
- `GET /api/routes/gateway/status` (privilege *System: Gateways*, `page-system-gateways`):
  `items` with `name`, `address`, `status`; it turns a route's gateway name into an address and
  marks a route through a gateway that is `down` (or has `loss` or `delay`) as not installed.
- The default route is the one through the WAN interface's gateway (the uplink), not a read of
  the kernel table (`/api/diagnostics/interface/getRoutes` is not used).

Both privileges are in the read user's list (automatic setup, *Fix it*); a refused grid is an
optional gap naming the privilege. Policy routing on OPNsense is a firewall rule with a gateway;
the filter model has no gateway yet, so it is not read. *Guess:* the privilege names and the
row fields until a 26.7 image says otherwise (#21).

### DNS transport, DNSSEC and block lists (#182, #80)

`unbound/settings/get`: a `dots` entry of type `dot` is a forwarder with transport `tls` and
`tls_name` from `verify`; type `forward` is plain DNS. `general.dnssec` becomes `dnssec`. The
DNSBL (`dnsbl`, 22.1 and later; older releases have none: no block lists) lists the selected
predefined lists by name and own lists by the host of their URL (never the path, which can carry
a token). Number of entries: not in the settings. Guesses for #21: the `verify` and `dnsbl`
spelling on 24.7 and 25.x (compared with the sources, not recorded).

## IPv6 router advertisements and DHCPv6 (#151)

- **Router advertisements and ISC DHCPv6** have no API (Services: Router Advertisements,
  Services: DHCPv6). They are read through the optional helper script of
  [ISC DHCP settings](#isc-dhcp-settings-optional-242), which now also prints, per interface of
  `<dhcpdv6>`: `ramode` (`disabled`, `router`, `unmanaged`, `managed`, `assist`, `stateless_dhcp`),
  `radnsserver`, `radomainsearchlist`, `ranodefault` (checked values only, nothing else of the
  section). `ramode`: `router` and `unmanaged` are SLAAC, `managed` and `assist` set M and O
  (`managed` without the A flag), `stateless_dhcp` sets O. `enable` plus `range`, `dnsserver`,
  `domain` and `defaultleasetime` give the DHCPv6 server. Without the script nothing of this is read.
- **Kea DHCPv6** *(guess: OPNsense 24.7 and later; `/api/kea/dhcpv6/get`, `search_subnet`,
  `search_pd_pool` and their field names)* is read like Kea DHCPv4: subnet, pools, DNS servers,
  prefix delegation pools. A 404 means no Kea DHCPv6 and is not an error.
- **The delegated prefix on the WAN** is `Uplink.delegated_prefixes` (already read).

## Gateway health and dynamic DNS (#150, #154)

- `GET /api/routes/gateway/status` (already read for routes): the row whose `address` is the WAN
  uplink's next hop gives the uplink's health (`status` `none` is online, a status with `down`
  is down, `loss` and `delay` are degraded; `delay` and `loss` as `4.2 ms` and `0.0 %`) and its
  monitor (`monitor`, the address pinged). Fields as of 24.7 to 26.1 *(guess, #21)*.
- **Gateway groups** (#150): `GET /api/routing/group_settings/search` (privilege *System: Gateway Groups*, `page-system-gatewaygroups`) lists them, with the tiers
  and the status row of every gateway in a tier (`gateways`: tier index to rows with `name`,
  `address`, `status`, `delay`, `loss`, `monitor`). The API exists since **26.7**, when Deciso
  moved the groups into the MVC model `GatewayGroups` (`System: Gateways: Group`); **24.7, 25.1,
  25.7 and 26.1 keep the groups in config.xml only and have no such API** (checked in the
  sources of those tags): there the groups stay unread and, where the firewall has two or more
  gateways, an optional gap says so; the gateway health above is still read. Several gateways
  in the first tier are load balancing, otherwise the lowest tier with a gateway that is not
  down is the active member; a gateway the API lists without a status is disabled or inactive
  and counts as down. The tier keys are ranked in order; the row layout is a *guess* (#21).
- `GET /api/dyndns/accounts/search_item` (plugin `os-ddclient`): one client per hostname of an
  enabled or disabled account (`service`, `protocol`, `hostnames`, `interface`, `enabled`). The
  rows hold `username` and `password`; they are never read. Not installed (404): nothing is
  reported, without a gap on every read. No privilege (403, *Services: Dynamic DNS*,
  `page-services-dyndns`, *guess*): an optional gap naming the privilege, never "no dynamic DNS";
  automatic setup and "Repair Signalbox's access" grant it where the firewall offers it (the privilege exists only with the plugin; without it the user manager refuses it, so it is left out) (#440). The plugin has no API for the last update or the address announced.

### Configuration state, backups and channel (#181)

The configuration history (`/api/core/backup/backups/this`, the same call the backup uses) gives
`local_backups` (number of revisions, newest, automatic) and `config_state` (newest revision,
time and user). The channel comes from `product_id` of `core/firmware/status`: `opnsense` is
community (stable), `opnsense-business` business (long-term), `opnsense-devel` development;
`needs_reboot` is `reboot_pending`. *(Guess: on releases without `product_id` the channel falls
back to `product_name`; whether "apply needed" can be read is open, so `pending` stays unknown,
#21.)*
