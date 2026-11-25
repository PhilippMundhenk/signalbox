# Ubiquiti EdgeRouter (EdgeOS) and VyOS adapter, and EdgeSwitch via SNMP

Reads an **EdgeRouter** (EdgeOS) or a **VyOS** router over SSH, read only (#403). Signalbox logs
in with a user of its own at the level **operator** (it may run `show` commands and nothing
else), with a key and a pinned host key, sends one read script per observation on standard input
of `sh -s` and maps the answer to the model. Nothing on the router is changed, nothing needs
root, no configuration mode is entered. The configuration is read with
`show configuration commands`, so the same reader serves every EdgeRouter model.

An **EdgeSwitch** is not read by this adapter: read it with the generic
[SNMP adapter](snmp.md), see [EdgeSwitch](#edgeswitch-through-snmp) below.

| | |
| --- | --- |
| Adapter id | `edgeos` |
| Roles | `gateway` (recommended), `other` |
| Capabilities | interfaces (ports, VLANs, bridges, bonds, subnets, uplink, routes, SSH/GUI/Telnet services), DHCP (server, relay, leases), DNS (forwarding), neighbours (LLDP), health, time, vpn (WireGuard), firewall (rule-sets, NAT, port forwards) |
| Writes | none |
| Simulator | `signalbox.sim.edgeos` (an asyncssh server answering with recorded command output) |
| Automatic setup | no: create the user by hand (below); nothing is installed or changed on the router by Signalbox |

> **Not yet confirmed on a real router** ([#21](https://github.com/PhilippMundhenk/signalbox/issues/21)).
> The command output in the simulator follows what Ubiquiti's EdgeRouter documentation and the
> VyOS documentation show, with invented values and documentation addresses only; parts that
> are guesses are marked *(guess)* below. Please report your model and version in #21.

## Versions (#389)

The current EdgeOS line and the two before it, so that a router that has not been updated still
works, plus VyOS:

| Software | Versions | Status |
| --- | --- | --- |
| EdgeOS | **2.0.x** (EdgeRouter X, 4, 6P, 12, Infinity, Lite and Pro on 2.0.9), **1.10.x** (the last release for EdgeRouter models that never got 2.0), **1.9.x** | 2.0 and 1.10 with a recorded simulator profile each (EdgeRouter X and Lite); 1.9 reads with the 1.10 code and is a *(guess)* |
| VyOS | **1.3** (equuleus), **1.4** (sagitta), **1.5** (rolling, the image of the CI job) | 1.3 and 1.4 with a simulator profile each; 1.5 on the real VyOS in CI. VyOS 1.4 and newer renamed the firewall (`firewall ipv4 ...`, `firewall ipv6 ...`), which is read since #495 (see [Firewall mapping](#firewall-mapping)), and removed the user levels (see [Setup](#setup)) |

Where the spelling changed between releases, both are read:

| What | EdgeOS 1.9, 1.10, 2.0 and VyOS 1.3 | VyOS 1.4 and newer |
| --- | --- | --- |
| DHCP default router, DNS | `default-router`, `dns-server` | `option default-router`, `option name-server` |
| DHCP address range | `start A stop B` (EdgeOS), `range N start A` and `range N stop B` (VyOS) | `range N start/stop` |
| Static lease | `static-mapping X ip-address`, `mac-address` | `mac` *(guess)* |
| NAT interface | `outbound-interface eth0` | `outbound-interface name eth0` |
| NAT | `service nat rule` (EdgeOS), `nat source/destination rule` (VyOS) | `nat source/destination rule` |
| WireGuard peer | the peer key is the name (EdgeOS); `peer NAME pubkey KEY` (VyOS 1.3) | `peer NAME public-key KEY` |
| WireGuard port | `listen-port` | `port` |
| DHCP leases | `show dhcp leases` (EdgeOS), `show dhcp server leases` (VyOS) | `show dhcp server leases` |

EdgeOS 2.0 and VyOS 1.3 use the same `firewall name` model, so the same reader serves them.

## Setup

1. Create the read user on the router, in configuration mode (SSH or the web UI's *CLI*).
   **EdgeOS and VyOS up to 1.3**: the level **operator** may run `show` commands and cannot
   change anything; do not give it `admin`:

   ```
   configure
   set system login user signalbox level operator
   set system login user signalbox authentication public-keys signalbox type ssh-ed25519
   set system login user signalbox authentication public-keys signalbox key <the key>
   commit
   save
   exit
   ```

   `<the key>` is the middle part of the public key line, without `ssh-ed25519` and without the
   comment. Create the key pair on the machine that runs Signalbox:
   `ssh-keygen -t ed25519 -N '' -f signalbox_edgeos` (a key without a passphrase; a password
   works too: `set system login user signalbox authentication plaintext-password '...'`, which
   the router stores hashed).

   **VyOS 1.4 and newer** have no user levels (the rolling release refuses the line with
   `[level] is not valid`): leave the line `set system login user signalbox level operator` out.
   VyOS then has no read-only login at all, every local user is a full administrator, and the
   user `signalbox` has the full rights of one. Prefer the key to a password (a key-only user
   cannot be guessed over the network) and read [Restricting the login on VyOS 1.4 and
   newer](#restricting-the-login-on-vyos-14-and-newer).
2. In Signalbox add a device with adapter `edgeos`, role `gateway`: the router's address, the
   user `signalbox` and the private key (OpenSSH format). Then *Test connection* and trust the
   SSH host key it shows. Compare it with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on
   the router first.

```yaml
adapter: edgeos
host: 192.0.2.1
port: 22
username: signalbox
private_key: "-----BEGIN OPENSSH PRIVATE KEY----- ..."   # or: password
```

Signalbox reads only: it does not install or change anything on the router unless you start
the optional [automatic setup](#automatic-setup). The operator level prints the whole
configuration (`show configuration commands`), which the read needs; secrets are filtered out on
the router before they are sent ([Secrets](#secrets)).

### Automatic setup

Optional, off unless you start it for one device and confirm the plan (and the config switch for
automatic setups is on); the manual setup above stays first-class. In the device form, *Set up
automatically* logs in over SSH with an administrator of the router (password, used for this
one request and never stored), shows the SSH host key to compare, and then creates the user
`signalbox` with a key generated by Signalbox (only the public half is sent) and **no
password**. The version is read **before** the plan is built:

| Router | The user gets | The plan |
| --- | --- | --- |
| EdgeOS 1.x/2.x, VyOS up to 1.3 | `level operator` (read only) | user, key, host key |
| VyOS 1.4 and newer | **no level, full rights** (key-only login) | the same, plus a step that says in plain words that the user has the rights of an administrator because the version has no read-only level |

On VyOS 1.4 and newer the router is asked whether the option `level` still exists (its
configuration template): a build that still has it gets `level operator`, one that does not
(the rolling release) gets the user without a level and the plan says so. A user of that name
with a level other than operator is never touched. *Remove* deletes the user again.

### Restricting the login on VyOS 1.4 and newer

VyOS has no read-only user, so narrow the user `signalbox` down where you can:

- allow SSH to the router only from the address of Signalbox (an `input` rule of your firewall,
  or `set service ssh listen-address` on the management interface only);
- keep it key-only: do not set a password for it (the automatic setup sets none);
- on a router that others can reach, run Signalbox's reads from a management VLAN only.

Signalbox itself only ever runs `show` commands and read-only `ip` and `/proc` reads
([What is read](#what-is-read)); the restriction above is about what the key could do if it were
stolen.

## What is read

The operational commands run through `/opt/vyatta/bin/vyatta-op-cmd-wrapper` (present on
EdgeOS 1.x and 2.0 and on VyOS 1.3, 1.4 and 1.5) as the operator user (VyOS 1.4 and newer: as
the user created in the setup).

| Capability | Source | What |
| --- | --- | --- |
| system | `show version` | vendor (Ubiquiti or VyOS), model (`HW model`, `Hardware model`), version, serial, `system host-name` |
| interfaces | `show configuration commands` (`interfaces ...`), `ip -o link`, `ip -o addr`, `/sys/class/net` | ports of every type: ethernet jacks (link, speed, duplex, MAC, MTU), `vif` VLANs (`eth0.20`), bridges (`bridge-group`, `member interface`), `switch0` of the EdgeRouter X (`switch-port interface`), bonds (`bond-group`, `member interface`), WireGuard and other tunnels, PPPoE sessions; the segments (VLANs with tagged and untagged members) and subnets of every L3 interface; the uplink (the interface with the default route: DHCP, static or PPPoE, gateway, address); SSH, web GUI (HTTP and HTTPS) and Telnet services |
| routes | `protocols static route`, `ip route`, `ip -6 route` | default and static routes (also those configured but not installed, marked inactive), blackhole routes, DHCP and dynamic routes; connected routes come from the subnets |
| dhcp | `service dhcp-server`, `service dhcp-relay`, `show dhcp leases` | per subnet: pool, lease time, router, DNS, NTP, domain, static leases, the lease table, authoritative; relays |
| dns | `service dns forwarding`, `system static-host-mapping` | listen addresses (of `listen-on` interfaces), forwarders (`name-server`), host records, `cache-size`, `recursive=false` (dnsmasq), and `dhcp <interface>` as `register_dhcp`/`dynamic_records` (the names of that DHCP server's leases are answered, #456) |
| neighbours | `show lldp neighbors detail` | LLDP neighbours per port: chassis, remote port, name, description, management address, capabilities; an optional finding where `service lldp` is off |
| vpn | `interfaces wireguard`, `show interfaces wireguard <if> public-key` | tunnels with their own public key, listen port, addresses and peers (public key, endpoint, allowed IPs, keepalive). Never a private or pre-shared key |
| firewall | `firewall name`, `firewall ipv6-name` (EdgeOS, VyOS 1.3), `firewall ipv4`, `firewall ipv6` (VyOS 1.4 and newer), `service nat`, `nat`, `port-forward` | see below |
| health | `/proc`, `df`, `/sys/class/thermal` | uptime, load, CPU count, memory, storage, temperature |
| time | `date`, `system time-zone`, `system ntp` / `service ntp` | clock, time zone, NTP servers |

### Firewall mapping

A rule-set is *applied* to an interface in one direction. Every interface is a zone:

| Applied as | Chain | Zone of the rule |
| --- | --- | --- |
| `firewall in name X` | forward | source zone is the interface |
| `firewall out name X` | forward | destination zone is the interface |
| `firewall local name X` | input (to the router) | source zone is the interface |

**VyOS 1.4 and newer** (`firewall ipv4` and `firewall ipv6`) have base chains instead:

| Chain | Model chain | Zones of a rule |
| --- | --- | --- |
| `firewall ipv4 forward filter` | forward | `inbound-interface name X` is the source zone, `outbound-interface name X` the destination zone |
| `firewall ipv4 input filter` | input | `inbound-interface name X` is the source zone |
| `firewall ipv4 output filter` | output | `outbound-interface name X` is the destination zone |
| `firewall ipv4 name X` | the chain that jumps to it | rules are unrolled where a rule with `action jump` and `jump-target X` enters the chain, under the interfaces of the jump rule; the chain's default action (`drop` if none, as VyOS does) closes it |

The same for `ipv6`. The `default-action` of a base chain (`accept` if none) is its last rule.
`state` is read as `state new enable` (EdgeOS, VyOS 1.3) and as the values of `state` (VyOS 1.4
and newer). An interface that is a group, a wildcard (`eth2*`) or negated names no zone and
makes the rule inexact; a jump to a chain that does not exist, `return` and a chain whose
default action is not accept/drop/reject give `rules_complete = false` and a finding.

`local` sets are evaluated first, then `in`, then `out`. The default action of a set is a last
rule of that interface, so the order across interfaces stays right. The model evaluates new
connections only, so rules that only accept `established`/`related` connections or drop
`invalid` ones are not rules for new connections and are left out. Conditions the model has no
field for (address groups, TCP flags, a rate `limit`, `recent`, time of day, `!protocol`) make a
rule *inexact*: it can only ever "maybe" match. `exclude`d and load-balanced NAT rules, zone-based
policies (`zone-policy` on EdgeOS 2.0 and VyOS 1.3, `firewall zone` on 1.4 and newer) are not read, and a
finding says so (`rules_complete = false`).

NAT: `masquerade` and source NAT with an outside address; port forwards from destination NAT
rules (`service nat rule N type destination`, `nat destination rule`) and from the EdgeOS
`port-forward` wizard (with `auto-firewall` as "passes the filter" and `hairpin-nat` as NAT
reflection).

### Secrets

The read script filters the configuration on the router before it is sent: lines with a
`private-key`, `preshared-key`, `plaintext-password`, `encrypted-password`, a `password`,
`secret`, `key` or a `community` are never transmitted, and the reader drops them again. WireGuard
pre-shared keys therefore show as "not known". Nothing is read from `/config/auth`.

## Findings you may see

| Finding | Meaning |
| --- | --- |
| the device refused the login | wrong user or key, or the user does not exist at the level operator |
| did not answer the read commands completely | the login shell is not the default (`vbash`), or the user lacks the level |
| show configuration commands printed nothing | no operator level, or the wrapper is missing |
| zone-policy is not read | zone-based firewalls are not mapped yet |
| LLDP is off (optional) | enable it with `set service lldp interface all` for the neighbours |
| the DHCP subnet is on no network of the router | a `subnet` without an interface address in it |

## Guesses that need a real router (#21)

- The exact column layout of `show dhcp leases` (EdgeOS) and `show dhcp server leases` (VyOS),
  and that the times are UTC.
- `show lldp neighbors detail` on EdgeOS 1.10 (it may not exist before 2.0; then the optional
  finding says LLDP is off) and its field names.
- `show interfaces wireguard <if> public-key` as the way to read an interface's own public key
  on EdgeOS 2.0 and VyOS 1.3 and 1.4.
- The `mac` spelling of a static lease and the `public-key` spelling of a WireGuard peer on
  VyOS 1.4, and which VyOS 1.4 rolling build moved them.
- EdgeOS 1.9 reading like 1.10; EdgeOS 2.0 `switch0` with `vlan-aware` (the members of its VLANs
  are taken as the switch's ports).
- `proto zebra` and `proto static` as the origin of static routes (the configured routes decide).
- The CLI of the EdgeSwitch for SNMPv3 below.

## EdgeSwitch through SNMP

An EdgeSwitch (the managed switches of the EdgeSwitch line) speaks the standard SNMP MIBs, so
the generic [SNMP adapter](snmp.md) reads its ports, VLANs, MAC table, spanning tree, LLDP
neighbours and link aggregation. There is no separate adapter. Enable SNMPv3 with a read-only
user and add the switch as an *SNMP switch*:

1. On the switch, in the web UI under *System > SNMP* (menu names vary with the firmware) or in
   the CLI, enable SNMP, **switch SNMP v1 and v2c off** and create an SNMPv3 user with the
   access level **read only** and the security level **authentication and privacy**
   (`authPriv`) *(guess: the menu path)*. The CLI of the EdgeSwitch (FASTPATH based) looks like
   this *(guess: check `snmp-server ?` on your firmware)*:

   ```
   (EdgeSwitch) #configure
   (EdgeSwitch) (Config)#snmp-server view all 1.3.6.1 included
   (EdgeSwitch) (Config)#snmp-server group signalbox-ro v3 priv read all
   (EdgeSwitch) (Config)#snmp-server user signalbox signalbox-ro auth-sha <auth password> priv-aes128 <priv password>
   (EdgeSwitch) (Config)#exit
   (EdgeSwitch) #write memory
   ```

   Use two different passwords of 8 or more characters. The EdgeSwitch offers SHA and AES-128:
   in Signalbox choose the algorithm **sha** (not sha256). Give the group no write view.
2. If the switch has an SNMP access list or management ACL, allow the host Signalbox runs on
   (UDP 161). Enable LLDP (`lldp` on the ports) and spanning tree if you use them: the switch's
   neighbours and the topology need LLDP.
3. In Signalbox add a device with adapter `snmp`, role `switch`: the switch's address, version
   `v3`, the user `signalbox`, algorithm `sha`, both passwords. *Test connection*.

The switch is then a device of its own; the router's LLDP neighbour (`eth1` above, the switch's
`0/1`) and the switch's MAC table connect the two in the topology. Fall back to SNMP v2c with a
read-only community only where the firmware has no v3 (the SNMP page explains why that is
weaker). Not tested on a real EdgeSwitch *(guess)*: the standard MIBs are read as for every
switch; report your model in #21.

## Integration tests

Two layers. The recorded command output of an EdgeRouter X (EdgeOS 2.0), an EdgeRouter Lite
(EdgeOS 1.10) and VyOS 1.3 and 1.4 is served by `signalbox.sim.edgeos` and read by the contract
tests (`tests/test_edgeos.py`). There is no emulator image of EdgeOS itself.

The real VyOS runs in CI (job `Integration / VyOS`, `tools/integration/edgeos/vm.py`; the test
is tests/integration/test_edgeos_real.py, it skips without `IT_EDGEOS_URL` and fails in CI,
`REQUIRE_INTEGRATION`), never locally:

- **The image**: the official rolling ISO from github.com/vyos/vyos-nightly-build (VyOS 1.5
  development), pinned by version and SHA-256 (`TAG` and `PINNED_SHA256` in
  `tools/integration/edgeos/vm.py`). VyOS publishes the stable and LTS images only to
  subscribers, so the 1.3 and 1.4 branches are covered by the simulator only.
- **When the pin is gone**: the release page keeps about 30 builds (about a month). Then the job
  takes the newest build, still passes, and shows a **warning in the job summary** ("VyOS pinned
  build gone", with the new tag, its SHA-256 and the lines to change). To re-pin: copy the tag
  into `TAG` and the SHA-256 from the summary into `PINNED_SHA256` in
  `tools/integration/edgeos/vm.py` (the hash is the one the job computed on its own download;
  VyOS publishes a minisign signature but no checksum file) and update the date comment. A
  re-pin only makes the job reproducible again; until then it tests the newest build.
- **Boot**: the live system on the serial console (nothing is installed), login with the
  documented live password, then a throw-away read user `signalbox` with a generated key
  (level operator where the version has levels, none on the rolling release), eth1 192.0.2.1/24
  with a DHCP server, DNS forwarding, VLAN 20 on eth2, LLDP, source NAT and a small firewall
  (forward and input chains, a named chain entered by a jump, IPv6), all on documentation
  prefixes.
- **Tests** read it over SSH as that user, with the pinned host key: contract, system and
  version, ports and subnets, DHCP and DNS, NAT and routes, the lab firewall, time, untrusted and
  wrong pin. The **automatic setup** runs against the same VM as the live user (`vyos`) for a
  second login: the plan before the first trust shows only the fingerprint, the plan names the
  full rights, the setup creates the user, Signalbox reads as that user, a second run changes
  nothing, the removal deletes it.
- **What the real VyOS rolling showed**: `set system login user <name> level operator` is
  refused (`[level] is not valid`): the rolling release (1.5) has no user levels. The setup
  (manual and automatic) therefore creates the user without that line there, and says that the
  user has full rights. The firewall of 1.4 and newer (`firewall ipv4`/`ipv6`) is read since
  #495; everything else of the lab (ports, VLAN, subnets, DHCP, DNS forwarding, NAT, routes,
  uptime, time) is read as the simulator expects.
