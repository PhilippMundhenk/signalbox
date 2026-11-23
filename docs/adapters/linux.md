# Linux gateway adapter (Debian, Raspberry Pi OS, Ubuntu)

Reads a Debian-based Linux box that does gateway work (a Raspberry Pi as the router of a second
site, a mini PC with dnsmasq) over SSH, read-only (#240). Signalbox logs in with a user of its
own, sends one read script per observation on standard input of `sh -s` and maps the answer to
the model. Nothing on the device is changed; nothing needs root except the WireGuard status,
which a sudoers rule allows for exactly the read commands.

| | |
| --- | --- |
| Adapter id | `linux` |
| Roles | `gateway`, `other` |
| Capabilities | interfaces (ports, segments, subnets, uplink, SSH service), DHCP, DNS, health, time, vpn (WireGuard) |
| Writes | none |
| Simulator | `signalbox.sim.linux` (an asyncssh server answering the read and setup scripts) |
| Automatic setup | yes: root or a sudo user over SSH ([below](#automatic-setup)) |
| Discovery | the SSH identification line of OpenSSH on Debian, Raspberry Pi OS or Ubuntu |

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
# 3. optional, only with WireGuard: the read-only wg commands without a password
sudo tee /etc/sudoers.d/signalbox >/dev/null <<'END'
# Signalbox: read the WireGuard status. These commands print public keys only.
signalbox ALL=(root) NOPASSWD: /usr/bin/wg show all public-key, /usr/bin/wg show all listen-port, /usr/bin/wg show all peers, /usr/bin/wg show all endpoints, /usr/bin/wg show all allowed-ips, /usr/bin/wg show all latest-handshakes, /usr/bin/wg show all transfer, /usr/bin/wg show all persistent-keepalive
END
sudo chmod 440 /etc/sudoers.d/signalbox && sudo visudo -cf /etc/sudoers.d/signalbox
```

1. The user `signalbox` has no password, no sudo and no groups: it can read what every user can
   read (`ip`, `/proc`, `/sys`, `/etc/ssh/sshd_config`, `/etc/dnsmasq.conf`, lease files that
   are world-readable).
2. Log in with a key (recommended). Paste the private key into *Private key* in the device form;
   a field without line breaks is fine, Signalbox puts them back. Or give the user a password
   (`sudo passwd signalbox`) and enter that; the SSH server must then allow password logins.
3. Only with WireGuard: `wg` needs `CAP_NET_ADMIN`. The sudoers rule allows exactly these
   commands, all of which print public keys only (never `wg show all dump`, `private-key` or
   `preshared-keys`, which are not allowed and never sent):

   ```text
# Signalbox: read the WireGuard status. These commands print public keys only.
signalbox ALL=(root) NOPASSWD: /usr/bin/wg show all public-key, /usr/bin/wg show all listen-port, /usr/bin/wg show all peers, /usr/bin/wg show all endpoints, /usr/bin/wg show all allowed-ips, /usr/bin/wg show all latest-handshakes, /usr/bin/wg show all transfer, /usr/bin/wg show all persistent-keepalive
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
| Ports | `ip -j -d link show` and `/sys/class/net/*` (`device`, `wireless`, `speed`, `duplex`): roles (ADR 0008) from `linkinfo.info_kind`: `bridge` (members: `master`), `vlan` (parent: `link`), `bond`/`team` (lag), `dsa` (jack on its `conduit`, the CPU port), `wireguard`/`tun`/`gre`/`ipip`/`sit`/`ppp` (tunnel), `veth`/`dummy`/`macvlan` (virtual); without a kind a Wi-Fi interface or, with a `device`, a jack. `mtu`, `admin_up` (`UP` flag), link (`operstate`) |
| Segments, subnets | interfaces with global addresses (`ip -j addr show`), except the uplink and tunnels: a VLAN interface is its VLAN (tagged on its parent), anything else the untagged network (a bridge's members untagged); a VLAN-filtering bridge from `bridge -j vlan show`. Subnets are gateway subnets on a `gateway` with IP forwarding on |
| Uplink | role `gateway` only: the interfaces of the default routes (`ip -j route`, IPv4 and IPv6), not WireGuard or other tunnels (a full tunnel is not an uplink); `dhcp` when the route's `protocol` is `dhcp` or the address is dynamic, `pppoe` for PPP, else `static`; addresses and the next hop |
| SSH service | `sshd_config` with `Include` (first value wins, everything after the first `Match` ignored): `Port`, `ListenAddress`, `PasswordAuthentication` (default yes), `PermitRootLogin` (default `prohibit-password`: root with a key only); enabled: `ssh.service` active or the port listening (`ss -Hltun`) |
| DHCP | dnsmasq (`/etc/dnsmasq.conf`, `/etc/dnsmasq.d/*.conf`: `dhcp-range` with `set:`/`tag:`, `dhcp-host`, `dhcp-option`, `domain`, `dhcp-authoritative`; lease file `/var/lib/misc/dnsmasq.leases`), Kea (`/etc/kea/kea-dhcp4.conf` with comments, `subnet4` and `shared-networks`, pools, `option-data`, reservations, HA peer; `/var/lib/kea/kea-leases4.csv`), ISC dhcpd (`/etc/dhcp/dhcpd.conf`, `/var/lib/dhcp/dhcpd.leases`), systemd-networkd (`.network` files with `DHCPServer=yes`; no lease table). A range is mapped to the segment of its interface or of the device address in its network. A file that exists but is not readable is reported as a gap with the fix |
| DNS | dnsmasq (`port`, `listen-address`, `server=`, `/etc/resolv.conf` without `no-resolv`, `host-record`, `address=/name/ip`); AdGuard Home, Pi-hole and Unbound are recognised (unit, process or installation) with `config_read=false`: their configuration and APIs need their own login |
| Health | `/proc/uptime`, `/proc/loadavg`, `/proc/meminfo` (total minus available), CPU count, `df -P -T -B1` (`/` system, tmpfs temporary, `/boot*` other, others data), thermal zones |
| Time | `date +%s.%N`, `timedatectl show` (time zone, NTP, synchronised), chrony (`chronyc -n -c tracking`/`sources`: synchronised, stratum, current server; `server`/`pool` lines; `allow` means it serves time), else systemd-timesyncd (`timedatectl show-timesync`, `timesyncd.conf`) |
| Tunnels (`vpn`) | every `wireguard` interface of `ip -d link` (port, up, addresses, MTU) with `wg show all public-key`, `listen-port`, `peers`, `endpoints`, `allowed-ips`, `latest-handshakes`, `transfer`, `persistent-keepalive`, run directly (root) or with `sudo -n` (the rule above). No peer names (wg-quick has none outside its configuration file, which holds the private key and is never read) and no `preshared_key` (only `preshared-keys` would tell, which prints the keys). Without the rule: the interfaces without keys and peers, and a gap that says what to add |

Not read: Pi-hole's own DHCP server, dnsmasq IPv6 ranges (`constructor:`), firewall rules
(nftables/iptables, #135).

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
3. with `wg` installed, writes the sudoers rule above to `/etc/sudoers.d/<login>` after
   `visudo -c` accepted it;
4. pins the confirmed host key for reading, so one fingerprint is confirmed, not two.

A re-run repairs and sets a new key. *Remove* deletes `/etc/sudoers.d/<login>` and the user with
its home directory. Root, `pi`, `admin` and other system accounts are never set up.

## Path traces (optional, #253)

Only while `traces.enabled` is on ([TRACES.md](../TRACES.md)): one script over the same SSH
login runs `tracepath -n -m <hops> <address>` (Debian package `iputils-tracepath`), or
`traceroute -n -q 1 -w 1 -m <hops> <address>` where `tracepath` is missing. Both send
unprivileged UDP: no sudo rule, no root, nothing to set up. With neither installed the trace
says so.

## Integration tests

CI starts a Debian 12 container with OpenSSH, iproute2, dnsmasq, chrony and wireguard-tools
(`tools/integration/linux/`): a dummy LAN with a VLAN, a bridge, dnsmasq with a lease, chrony,
and a WireGuard interface with a peer (the runner's kernel has the module; the container gets
`NET_ADMIN`). The manual setup above is run as written to create the read user; the tests read
the container as that user (with and without the sudoers rule) and run the automatic setup as
root and as a sudo user ([TESTING.md](../TESTING.md)).

Simulator only: Kea, ISC dhcpd and systemd-networkd's DHCP server, timesyncd, AdGuard Home,
Pi-hole, DSA, bonds and VLAN-filtering bridges, a real Raspberry Pi's device tree and thermal
zone (#21).
