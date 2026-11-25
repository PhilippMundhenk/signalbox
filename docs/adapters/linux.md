# Linux gateway adapter (Debian, Raspberry Pi OS, Ubuntu, Arch Linux ARM)

Reads a Linux box (see [Supported distributions](#supported-distributions)) that does gateway work (a Raspberry Pi as the router of a second
site, a mini PC with dnsmasq) over SSH, read-only (#240). Signalbox logs in with a user of its
own, sends one read script per observation on standard input of `sh -s` and maps the answer to
the model. Nothing on the device is changed; nothing needs root except the WireGuard status, the nftables
ruleset and the legacy iptables rules, which a sudoers rule allows for exactly the read commands.

| | |
| --- | --- |
| Adapter id | `linux` |
| Roles | `gateway`, `other` |
| Capabilities | interfaces (ports, segments, subnets, uplink, SSH service), DHCP, DNS, health, time, vpn (WireGuard), firewall (nftables, or legacy iptables when nft has no rules) |
| Writes | none |
| Simulator | `signalbox.sim.linux` (an asyncssh server answering the read and setup scripts) |
| Automatic setup | yes: root or a sudo user over SSH ([below](#automatic-setup)) |
| Discovery | the SSH identification line of OpenSSH on Debian, Raspberry Pi OS or Ubuntu (other distributions do not name themselves there: add the device by hand) |

## Supported distributions

The distribution is read from `/etc/os-release` (`ID`, then the words of `ID_LIKE`; without it the marker files `/etc/debian_version` (apt), `/etc/arch-release` (pacman), `/etc/alpine-release` (apk), `/etc/fedora-release` or `/etc/redhat-release` (dnf), else unknown, never guessed) by the reader
(`vendor_extra.os_id`, `os_family`, `package_manager`) and by the automatic setup, never assumed.
What the reader needs is `ip -j` and `bridge` (iproute2 with JSON, 4.13 or newer; busybox `ip`
prints no JSON, and then nothing is read and a gap says so), `ss`, `/proc` and `/sys`, and
optionally `nft`, `wg` and `tracepath`.

Versions (#389): the current release and the two major versions before it, so that an old box
that has not been updated still works. The reader uses only what is old and stable (`ip -j` from
iproute2 4.13, `/proc`, `iptables-save`, `nft -j` from nftables 0.9), never a feature of the
newest release.

| Distribution | Versions | Status | Package manager |
| --- | --- | --- | --- |
| Debian | 13 (trixie), 12 (bookworm), 11 (bullseye) | all three tested in CI (one container each, the same integration tests, #417); 12 also on real devices | `apt` |
| Raspberry Pi OS | 12 (bookworm), 11 (bullseye) | Debian-based (`ID=raspbian` on 11, `ID=debian` on 12, both read as Debian): the Debian 11 and 12 rows apply; not tested on hardware (#21) | `apt` |
| Ubuntu | 26.04, 24.04, 22.04 (LTS) | as Debian, not run (#21) | `apt` |
| Arch Linux ARM, Arch Linux | rolling: images of any age (an old image has a stale package database, see below) | simulator (single-NIC Raspberry Pi 2, systemd-networkd, legacy iptables) and one real Raspberry Pi 2 (#302) | `pacman` |
| Fedora and relatives | the current release and the two before | simulator only, not tried on a device (#21) | `dnf` |
| Alpine | the current stable series and the two before | simulator only, not tried on a device (#21); busybox has no `useradd`: create the user by hand (`adduser -D -s /bin/sh signalbox`, then unlock it with `passwd -u signalbox`) | `apk` |

The sudoers rule names `/usr/bin/wg` and `/usr/sbin/nft`; on Arch and Fedora `/usr/sbin` is a link
to `/usr/bin`, so the same rule works. systemd-networkd, dhcpcd, NetworkManager and netctl
configure the interfaces; Signalbox reads the result with `ip`, so it does not matter which one
is used (only systemd-networkd `.network` files with `DHCPServer=yes` are read for DHCP). The SSH
unit is `ssh` on Debian and `sshd` elsewhere; both are recognised. An interface without carrier
(Wi-Fi dongle, unplugged jack) is a port that is down, and its addresses are still read.

A host that does not forward IP packets (`net.ipv4.ip_forward=0`, the default on Arch) has no WAN
side: the interface with its default route is also its network, so its segment and subnet
(not a gateway subnet) are read. On a router (forwarding on) the uplink stays out of the
subnets, unless nothing else has an address.

Install what the reader can use, as root (the plan of the automatic setup shows the same
commands, unticked, and *Fix it* does the first):

| Tool | `apt` (Debian, Ubuntu, Raspberry Pi OS) | `pacman` (Arch Linux ARM) | `dnf` (Fedora) | `apk` (Alpine) |
| --- | --- | --- | --- | --- |
| `nft` (firewall) | `apt-get install nftables` | `pacman -S --needed nftables` | `dnf install nftables` | `apk update && apk add nftables` |
| `ip -j`, `bridge` | `apt-get install iproute2` | `pacman -S --needed iproute2` | `dnf install iproute` | `apk update && apk add iproute2` |
| `wg` (VPN) | `apt-get install wireguard-tools` | `pacman -S --needed wireguard-tools` | `dnf install wireguard-tools` | `apk update && apk add wireguard-tools` |
| `tracepath` (traces) | `apt-get install iputils-tracepath` | `pacman -S --needed iputils` | `dnf install iputils` | `apk update && apk add iputils-tracepath` |

Stale package database (#394): on an old box `pacman -S` fails with `failed retrieving file ...
404` because the mirror no longer has the version the old database names. Arch does not support
partial upgrades, so the setup never runs `pacman -Sy <package>`; it recognises the 404 and says
that the package lists are out of date and that a full `sudo pacman -Syu` is needed first
(large and risky on an old device), and that Signalbox reads legacy iptables without nftables.
Installing `nftables` is therefore not needed for the firewall. `apt` installs run
`apt-get update` first (no partial-upgrade problem there), Alpine `apk update`, and `dnf`
refreshes its metadata itself.

### Legacy iptables (#394)

Without nftables, or when `nft` shows no rules, the firewall is read from `iptables-save` and
`ip6tables-save` (Debian 9 and older, Arch Linux ARM images before the nf_tables switch, boxes
switched with `update-alternatives --set iptables /usr/sbin/iptables-legacy`):

- *Source.* `nft -j list ruleset` when it has rules (iptables-nft systems, the Debian default
  since 10, show up there), else `iptables-save`/`ip6tables-save`. The firewall's advanced tab
  (`vendor_extra.source`) says `nft` or `iptables-save`. Rules in both (legacy rules next to an
  nft ruleset) keep the nft ones and make the rules incomplete with a gap.
- *Mapping* (the same model as nft, ADR 0013): `filter` `INPUT` and `FORWARD` chains with their
  policy and rules in order, `-j <chain>` as a jump, `-g` as a goto, `nat` `PREROUTING` `DNAT`
  as port forwards, `POSTROUTING` `MASQUERADE`/`SNAT` as NAT. Read: `-i/-o`, `-s/-d` (also `!`),
  `-p`, `--dport/--sport` and `multiport` (ranges), `-m conntrack --ctstate`/`state`, `-m comment`.
  Every other module or option (`limit`, `recent`, `mark`, ICMP types, `-f`, ...) keeps the rule
  with `exact = false`; `LOG`, `MARK` and similar targets decide nothing and are skipped; ranges in
  `--to-destination`/`--to-source` and `REDIRECT` make the forwards or NAT incomplete. A
  dropping `raw` `PREROUTING` chain makes the rules incomplete. Not read: `OUTPUT`, `security`.
- *Permission.* `iptables-save` needs `CAP_NET_ADMIN`: the sudoers rule above allows exactly
  `/usr/sbin/iptables-save ""` and `/usr/sbin/ip6tables-save ""` (the empty argument list: `-f FILE`
  or `-c` are not allowed), nothing that changes a rule. Without the rule nothing is reported
  and a gap names the file to add; without only the `ip6tables-save` line the IPv4 rules are
  read and marked incomplete. Existing devices: run *Set up automatically* again (or add the two
  commands) to get the new rule.

## Manual setup

On the device, as a user that may use sudo (paste the commands; replace the key line):

```sh
# 1. a user of its own for Signalbox: no password, no sudo, no groups
sudo useradd --system --create-home --shell /bin/sh signalbox
# 2. its login key: on your computer run  ssh-keygen -t ed25519 -N '' -f signalbox-key
#    paste the file signalbox-key into "Private key" below, and signalbox-key.pub here:
sudo install -d -m 700 -o signalbox -g "$(id -gn signalbox)" ~signalbox/.ssh
echo 'PASTE-THE-LINE-OF-signalbox-key.pub' | sudo tee ~signalbox/.ssh/authorized_keys
sudo chown signalbox: ~signalbox/.ssh/authorized_keys && sudo chmod 600 ~signalbox/.ssh/authorized_keys
#    (or instead a password:  sudo passwd signalbox)
# 3. optional, only with WireGuard, nftables or iptables: the read-only commands without a password
sudo tee /etc/sudoers.d/signalbox >/dev/null <<'END'
# Signalbox: read the WireGuard status (public keys only), the nftables ruleset and the
# legacy iptables rules (iptables-save without arguments).
signalbox ALL=(root) NOPASSWD: /usr/bin/wg show all public-key, /usr/bin/wg show all listen-port, /usr/bin/wg show all peers, /usr/bin/wg show all endpoints, /usr/bin/wg show all allowed-ips, /usr/bin/wg show all latest-handshakes, /usr/bin/wg show all transfer, /usr/bin/wg show all persistent-keepalive, /usr/sbin/nft -j list ruleset, /usr/sbin/iptables-save "", /usr/sbin/ip6tables-save ""
END
sudo chmod 440 /etc/sudoers.d/signalbox && sudo visudo -cf /etc/sudoers.d/signalbox
```

1. The user `signalbox` has no password, no sudo and no groups: it can read what every user can
   read (`ip`, `/proc`, `/sys`, `/etc/ssh/sshd_config`, `/etc/dnsmasq.conf`, lease files that
   are world-readable).
2. Log in with a key (recommended). Paste the private key into *Private key* in the device form;
   a field without line breaks is fine, Signalbox puts them back. Or give the user a password
   (`sudo passwd signalbox`) and enter that; the SSH server must then allow password logins.
3. Only with WireGuard or nftables: `wg` and `nft` need `CAP_NET_ADMIN`. The sudoers rule
   allows exactly these commands: the `wg show all <field>` ones print public keys only (never
   `wg show all dump`, `private-key` or `preshared-keys`, which are not allowed and never
   sent), and `nft -j list ruleset` only prints the packet filter rules (no secrets):

   ```text
# Signalbox: read the WireGuard status (public keys only), the nftables ruleset and the
# legacy iptables rules (iptables-save without arguments).
signalbox ALL=(root) NOPASSWD: /usr/bin/wg show all public-key, /usr/bin/wg show all listen-port, /usr/bin/wg show all peers, /usr/bin/wg show all endpoints, /usr/bin/wg show all allowed-ips, /usr/bin/wg show all latest-handshakes, /usr/bin/wg show all transfer, /usr/bin/wg show all persistent-keepalive, /usr/sbin/nft -j list ruleset, /usr/sbin/iptables-save "", /usr/sbin/ip6tables-save ""
   ```

4. In the device form: the address, user `signalbox` and the key. *Test connection* shows the
   SSH host key's SHA-256 fingerprint; compare it on the device with
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` (the form shows hex, ssh-keygen base64:
   the message also names the `SHA256:...` form) and trust it.

## Settings

| Key | Default | Meaning |
| --- | --- | --- |
| `host` | | address or host name (a `ssh://` prefix and a path are removed) |
| `port` | `22` | SSH port |
| `username` | `signalbox` | the read user |
| `private_key` | | OpenSSH private key without passphrase; stored encrypted, never sent back |
| `password` | | or the user's password; one of the two is required |

## Host key pinning

Like certificates: the host key the device presents is compared with the pinned fingerprint
inside the SSH key exchange (`signalbox.adapters.ssh.PinnedSsh`), before the key or password is
used. Not pinned yet, or different: the device is reported untrusted with the fingerprint, and
nothing is sent. The pin is the hex SHA-256 of the host key (the same value `ssh-keygen -l`
prints in base64). Nothing of the Signalbox machine is used: no `~/.ssh/config`, `known_hosts`,
agent or other keys.

## What is read

One script (`signalbox.adapters.linux.collect.READ`) per observation, one more for the clock:

| Model | Source |
| --- | --- |
| System | `/etc/os-release` (`PRETTY_NAME` as firmware), `/proc/device-tree/model` (Raspberry Pi and other boards) or DMI `sys_vendor`/`product_name`; kernel (`uname -srm`) and IP forwarding in `vendor_extra` |
| Ports | `ip -j -d link show` and `/sys/class/net/*` (`device`, `wireless`, `speed`, `duplex`): roles (ADR 0008) from `linkinfo.info_kind`: `bridge` (members: `master`), `vlan` (parent: `link`), `bond`/`team` (lag; its members get `lag`, and `/proc/net/bonding/<bond>` gives mode, hash, LACP rate, minimum links and per member the aggregator, LACP state and partner, #157), `dsa` (jack on its `conduit`, the CPU port), `wireguard`/`tun`/`gre`/`ipip`/`sit`/`ppp` (tunnel), `veth`/`dummy`/`macvlan` (virtual); without a kind a Wi-Fi interface or, with a `device`, a jack. `mtu`, `admin_up` (`UP` flag), link (`operstate`) |
| Segments, subnets | interfaces with global addresses (`ip -j addr show`), except tunnels and, on a router, the uplink (a host that does not forward, or whose only address is on the uplink, keeps it, #302): a VLAN interface is its VLAN (tagged on its parent), anything else the untagged network (a bridge's members untagged); a VLAN-filtering bridge from `bridge -j vlan show`. Subnets are gateway subnets on a `gateway` with IP forwarding on |
| Uplink | role `gateway` only: the interfaces of the default routes (`ip -j route`, IPv4 and IPv6), not WireGuard or other tunnels (a full tunnel is not an uplink); `dhcp` when the route's `protocol` is `dhcp` or the address is dynamic, `pppoe` for PPP, else `static`; addresses and the next hop |
| SSH service | `sshd_config` with `Include` (first value wins, everything after the first `Match` ignored): `Port`, `ListenAddress`, `PasswordAuthentication` (default yes), `PermitRootLogin` (default `prohibit-password`: root with a key only); enabled: `ssh.service` active or the port listening (`ss -Hltun`) |
| DHCP | dnsmasq (`/etc/dnsmasq.conf`, `/etc/dnsmasq.d/*.conf`: `dhcp-range` with `set:`/`tag:`, `dhcp-host`, `dhcp-option`, `domain`, `dhcp-authoritative`; lease file `/var/lib/misc/dnsmasq.leases`), Kea (`/etc/kea/kea-dhcp4.conf` with comments, `subnet4` and `shared-networks`, pools, `option-data`, reservations, HA peer; `/var/lib/kea/kea-leases4.csv`), ISC dhcpd (`/etc/dhcp/dhcpd.conf`, `/var/lib/dhcp/dhcpd.leases`), systemd-networkd (`.network` files with `DHCPServer=yes`; no lease table). A range is mapped to the segment of its interface or of the device address in its network. A file that exists but is not readable is reported as a gap with the fix |
| DNS | dnsmasq (`port`, `listen-address`, `server=`, `/etc/resolv.conf` without `no-resolv`, `host-record`, `address=/name/ip`); `server=/corp.example/192.0.2.53` as a forwarder with `domain`, `stop-dns-rebind` and `rebind-domain-ok`, `cache-size`, `domain`; `register_dhcp`/`dynamic_records` when a `dhcp-range` exists (dnsmasq registers the names of its leases); `listen_segments` from `interface=` and `listen-address=` (#182, #456)); systemd-resolved (#182, when the unit runs): `[Resolve]` of `/etc/systemd/resolved.conf` and its drop-ins in `resolved.conf.d` (`DNS=` with `address#server-name` and `address:port#name`, `DNSOverTLS=yes` as TLS upstreams on port 853 (v239 and later; `opportunistic` stays plain and is noted in `vendor_extra`), `DNSSEC=yes` or `allow-downgrade`, `Domains=`); upstreams that only come from the links (DHCP, networkd) are not read, so without `DNS=` the service counts as not read; AdGuard Home, Pi-hole and Unbound are recognised (unit, process or installation) with `config_read=false`: their configuration and APIs need their own login |
| Spanning tree (#155) | from the same `ip -j -d link show`: a bridge's `info_data` (`stp_state` 0 off, 1 the kernel's STP, 2 a user-space daemon such as mstpd, read as RSTP; `priority`, `bridge_id`, `root_id`, `root_port`, `root_path_cost`) and each member's `info_slave_data` (`state`, `cost`, `guard` = BPDU guard, `root_block` = root guard, `no`). The kernel has no edge ports or roles: root port from `root_port`, designated when the member's `designated_bridge` is the bridge itself, a blocking port alternate |
| Health | `/proc/uptime`, `/proc/loadavg`, `/proc/meminfo` (total minus available), CPU count, `df -P -T -B1` (`/` system, tmpfs temporary, `/boot*` other, others data), thermal zones |
| Time | `date +%s.%N`, `timedatectl show` (time zone, NTP, synchronised), chrony (`chronyc -n -c tracking`/`sources`: synchronised, stratum, current server; `server`/`pool` lines; `allow` means it serves time), else systemd-timesyncd (`timedatectl show-timesync`, `timesyncd.conf`) |
| Tunnels (`vpn`) | every `wireguard` interface of `ip -d link` (port, up, addresses, MTU) with `wg show all public-key`, `listen-port`, `peers`, `endpoints`, `allowed-ips`, `latest-handshakes`, `transfer`, `persistent-keepalive`, run directly (root) or with `sudo -n` (the rule above). No peer names (wg-quick has none outside its configuration file, which holds the private key and is never read) and no `preshared_key` (only `preshared-keys` would tell, which prints the keys). Without the rule: the interfaces without keys and peers, and a gap that says what to add |
| Firewall (`firewall`, #135) | `nft -j list ruleset`, run directly (root) or with `sudo -n /usr/sbin/nft -j list ruleset` (the rule above). Every interface named by `iifname`/`oifname` (single names, literal sets and named sets, resolved) is a zone of its own named after it, mapped like the networks: a network interface to its segment, the uplink to the uplink, `wireguard` to its tunnel, anything else to its port; `lo` maps to nothing by design, a wildcard (`eth*`) or vanished interface makes the zone `complete=False`. Base chains of type `filter` on the hooks `input` and `forward` give the rules in evaluation order (`ip saddr/daddr`, `ip6`, `tcp/udp sport/dport`, `meta l4proto`, `nfproto`, `ct status dnat` as `forwarded`, verdicts `accept`/`drop`/`reject`) and their `policy` as `input_policy`/`forward_policy` (no base chain: accept, and `enabled=False` when no chain filters). Rules that only match `ct state established,related` or `invalid` are left out. `jump` and `goto` to regular chains are flattened with the jump's conditions merged in. Conditions the model lacks (marks, limits, ICMP types, the `xt` matches iptables-nft uses for modules, a set that is empty or filled at run time) keep the rule with `exact=False`. `nat` chains: `dnat to` in `prerouting` is a port forward (`passes_filter=False`: the filter rules decide), `masquerade`/`snat` in `postrouting` a NAT rule; `redirect`, `dnat` without a plain address and `snat` ranges make the forwards (or rules) incomplete. iptables-nft systems (the Debian default) show up in nft too. Not read: `output` chains, `netdev`, `bridge` and `arp` tables. `rules_complete=False` with a gap: `iptables` runs the legacy backend with rules of its own next to nft rules (its rules are invisible to nft; with an empty nft ruleset they are read, see [Legacy iptables](#legacy-iptables-394)), several base chains on one hook that cannot be merged (a later chain exists and an earlier one accepts or has a `drop` policy), a verdict map, a jump to an unknown chain, a dropping `prerouting` filter chain. Without the sudoers rule nothing is reported (not read) and a gap says what to add |

Not read: Pi-hole's own DHCP server, dnsmasq IPv6 ranges (`constructor:`), firewalld and ufw
as such (only what they put into nftables).

### Update state (#181)

Read without root and without network access, for the Debian family (Debian 11 to 13, Ubuntu,
Raspberry Pi OS) and the Fedora family (Fedora, RHEL 8 to 10 and clones); other systems report
none of it:

| What | Debian family | Fedora family |
|---|---|---|
| Installs by itself (`auto_update`) | `apt-config shell` of `APT::Periodic::Unattended-Upgrade` non-zero, `/usr/bin/unattended-upgrade` installed and `apt-daily-upgrade.timer` not disabled | `dnf-automatic-install.timer` enabled, or `dnf-automatic.timer` (`dnf5-automatic.timer`) enabled with `apply_updates = yes` |
| Waiting updates | `apt-get -s upgrade` (the lists of the last `apt update`), security: origin `*-security` | `dnf -C check-update` (cache only), security: `dnf -C updateinfo list --security` |
| Last check | mtime of `/var/lib/apt/periodic/update-success-stamp` | not read |
| Restart pending | `/var/run/reboot-required` | not read |

The restart flag is only ever "yes": not every system writes the file, so its absence says
nothing. The Fedora family reads and the dnf5 names are unconfirmed on real systems (#21). No
sudoers rule is needed.

### Remote syslog (#180)

The read script prints `/etc/rsyslog.conf`, `/etc/rsyslog.d/*.conf`,
`/etc/syslog-ng/syslog-ng.conf` and `/etc/syslog-ng/conf.d/*.conf`. rsyslog: `*.* @host:port`
(UDP), `@@host` (TCP) and `action(type="omfwd" target=... port=... protocol=...)`, TLS with
`StreamDriverMode="1"`; the selector of a legacy line is the topic. syslog-ng: each
`destination` with `network()`, `syslog()`, `udp()` or `tcp()` (`transport()`, `port()`), enabled
when a `log` statement names it. No file: nothing is forwarded (journald alone). A file the
user may not read leaves the targets unread with an optional gap. *Guess:* targets in templates,
includes outside those directories (#21).

## Automatic setup

With *Set up automatically* in the device form ([ADR 0009](../adr/0009-automatic-setup-with-an-admin-login.md)),
optional like everywhere: root's password, or a user that may use sudo with its password
(Raspberry Pi OS: the user created at installation). Signalbox shows the SSH host key to confirm
first and sends nothing before. Then, over that pinned connection (a sudo user's password goes to
`sudo -S` on standard input, not on a command line; with `NOPASSWD` it is not sent at all):

1. creates the user `signalbox` (`useradd --system --create-home --shell /bin/sh`), unless it
   exists; a user of that name in `sudo`, `adm`, `docker` or a similar group is refused;
2. generates an ed25519 key in Signalbox and writes only the public key (comment
   `signalbox-read`) to the user's `authorized_keys`, replacing what was there; the private key
   is stored encrypted in Signalbox;
3. with `wg` or `nft` installed, writes the sudoers rule above to `/etc/sudoers.d/<login>` after
   `visudo -c` accepted it;
4. pins the confirmed host key for reading, so one fingerprint is confirmed, not two.

Optional extras, unticked in the plan, each only when the tool is missing: *nftables*, *iproute2*
(`ip -j` and `bridge`), *wireguard-tools* and *tracepath*. Ticked, each is one step that runs the
package manager of the detected distribution (`apt-get`, `pacman`, `dnf` or `apk`, the command
verbatim in the plan, table above) before the sudoers rule, which then also covers a freshly
installed `nft` or `wg`. On a distribution Signalbox does not know the extras are refused (install
the tools by hand). *Remove* does not uninstall packages.

*Fix it* (read-side, no *Allow changes* needed) on the gap "only legacy iptables is installed" (now only when `iptables-save` is missing too):
*Install nftables* does the same two steps (package and sudoers rule) for the stored login. No
firewall rule or network setting is changed.

A re-run repairs and sets a new key. *Remove* deletes `/etc/sudoers.d/<login>` and the user with
its home directory. Root, `pi`, `admin` and other system accounts are never set up.

## Path traces (optional, #253)

Only while `traces.enabled` is on ([TRACES.md](../TRACES.md)): one script over the same SSH
login runs `tracepath -n -m <hops> <address>` (Debian package `iputils-tracepath`), or
`traceroute -n -q 1 -w 1 -m <hops> <address>` where `tracepath` is missing. Both send
unprivileged UDP: no sudo rule, no root, nothing to set up. With neither installed the trace
says so.

## Integration tests

CI starts a container per Debian release (11 bullseye, 12 bookworm, 13 trixie; a job matrix, one job summary each, #417) with OpenSSH, iproute2, dnsmasq, chrony, nftables, iptables and wireguard-tools
(`tools/integration/linux/`): a dummy LAN with a VLAN, a bridge, dnsmasq with a lease, chrony,
a WireGuard interface with a peer, and nftables rules with a port forward and masquerade (the runner's kernel has the modules; the container gets
`NET_ADMIN`). The manual setup above is run as written to create the read user; the tests read
the container as that user (with and without the sudoers rule) and run the automatic setup as
root and as a sudo user ([TESTING.md](../TESTING.md)).

*Legacy iptables* (#394): one test switches the container to the `iptables-legacy` alternatives, removes the nft rules, loads the legacy twin of the ruleset with `iptables` (runner kernel permitting, else skipped) and reads it through the sudoers rule with `iptables-save`; then it restores the nft rules.

Simulator only: Kea, ISC dhcpd and systemd-networkd's DHCP server, timesyncd, AdGuard Home,
Pi-hole, DSA, bonds and VLAN-filtering bridges, a real Raspberry Pi's device tree and thermal
zone (#21).

## MAC address table (#160)

`bridge -j -s fdb show` runs as the read user (a netlink dump, no root, no sudoers line):
entries with a `master` are the bridge's table (`permanent` → `self`, `static` → `static`,
else `dynamic`, `updated` → age); entries without one (a port's own unicast/multicast list) and
multicast addresses are left out. Confirmed in CI: a static entry added on the Debian 11, 12 and 13
target's bridge port is read.

## Routes and policy rules (#149)

The read script adds `ip -j route show table all`, `ip -j -6 route show table all`,
`ip -j rule show` and `ip -j -6 rule show` (sections `routes4`, `routes6`, `rules4`,
`rules6`; as the read user, no root). The `local` table, the empty `default` table and the
kernel's own routes for connected networks are left out. `protocol` gives the origin (`dhcp`,
`ra`, `static` or `boot`, a routing daemon such as `bird` or `zebra` is dynamic); a route out of
a WireGuard interface is a `vpn` route; `type` `blackhole`, `unreachable` and `prohibit` are
dropping routes. A rule with a key Signalbox cannot evaluate (`fwmark`, `uidrange`, ...) is left
out. *CI*: a static route, a table with its own default route and a rule in the container.
*Guess:* the JSON key of a blackhole rule's action (#21).

## IPv6 router advertisements and DHCPv6 (#151)

Read from files, with `dhcp`: `/etc/radvd.conf` (`interface` blocks: `AdvSendAdvert`,
`AdvManagedFlag`, `AdvOtherConfigFlag`, `AdvDefaultLifetime`, `prefix` with `AdvOnLink` and
`AdvAutonomous`, `RDNSS`, `DNSSL`; reported while the `radvd` unit or process runs) and, in
dnsmasq's configuration with `enable-ra`, the IPv6 `dhcp-range` lines (`constructor:<if>` or
`interface:<if>` or the range's prefix finds the network; `ra-only` SLAAC, `ra-stateless`
stateless, a range of addresses stateful) with `dhcp-option=option6:dns-server` and
`option6:domain-search`. systemd-networkd's `IPv6SendRA`, Kea DHCPv6 and the kernel's own
advertisements are not read. Debian 11, 12 and 13 use the same files.
