"""A simulated Linux gateway (a Raspberry Pi with Raspberry Pi OS) behind an SSH server (#240).

The device answers the read scripts of :mod:`signalbox.adapters.linux.collect` section by
section from :class:`LinuxSim` (what ``ip -j``, ``ss``, ``df`` ... print, and the files), and
the setup scripts of :mod:`signalbox.adapters.linux.provision` against a small model of the
users, their ``authorized_keys`` and ``/etc/sudoers.d``. Anything else fails with status 127.
Every script received is kept in ``scripts`` (the tests check that nothing that prints a
private key is ever sent). The WireGuard and nft sections are answered only for root or a user
with exactly the sudoers rule of the setup guide.

Sample data uses documentation addresses and locally administered MACs only.

    async with serve_ssh(LinuxSim()) as (port, fingerprint):
        ...
"""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import json
import re
import threading
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import Any

import asyncssh

from signalbox.adapters.linux import distro
from signalbox.adapters.linux.setup import sudoers, sudoers_path
from signalbox.adapters.ssh import host_key_fingerprint

ROOT_PASSWORD = "example-root-password"
ADMIN_USER = "pi"
ADMIN_PASSWORD = "example-admin-password"
NOW = 1795400000  # the simulated clock (2026-11-22)


def wg_key(seed: int) -> str:
    """A well-formed WireGuard public key (32 bytes, base64)."""
    raw = bytes((seed * 7 + i * 13) % 256 for i in range(31)) + b"\x00"
    return base64.b64encode(raw).decode()


GW_KEY = wg_key(1)
PEER_KEY = wg_key(2)  # the other site (OPNsense)
PHONE_KEY = wg_key(3)


def _link(
    index: int, name: str, mac: str | None = None, *, up: bool = True, **extra: Any
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "ifindex": index,
        "ifname": name,
        "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"] if up else ["BROADCAST", "MULTICAST"],
        "mtu": 1500,
        "operstate": "UP" if up else "DOWN",
        "link_type": "ether",
        "address": mac,
    }
    row.update(extra)
    return row


def _brport(number: int, state: str = "forwarding") -> dict[str, Any]:
    """``info_slave_data`` of a bridge member in ``ip -j -d link show`` (iproute2 6.x)."""
    return {
        "state": state,
        "priority": 32,
        "cost": 100,
        "hairpin": False,
        "guard": False,
        "root_block": False,
        "fastleave": False,
        "learning": True,
        "flood": True,
        "id": f"0x{0x8000 + number:x}",
        "no": f"0x{number:x}",
        "designated_port": 0x8000 + number,
        "designated_cost": 0,
        "designated_bridge": "8000.2:5b:0:0:0:2",
        "designated_root": "8000.2:5b:0:0:0:2",
    }


def default_links() -> list[dict[str, Any]]:
    return [
        {
            "ifindex": 1,
            "ifname": "lo",
            "flags": ["LOOPBACK", "UP", "LOWER_UP"],
            "mtu": 65536,
            "operstate": "UNKNOWN",
            "link_type": "loopback",
            "address": "00:00:00:00:00:00",
        },
        _link(2, "eth0", "02:5b:00:00:00:01", parentbus="platform", parentdev="fd580000.ethernet"),
        _link(
            3,
            "eth1",
            "02:5b:00:00:00:02",
            master="br0",
            parentbus="usb",
            linkinfo={"info_slave_kind": "bridge", "info_slave_data": _brport(1)},
        ),
        _link(
            4,
            "wlan0",
            "02:5b:00:00:00:03",
            master="br0",
            parentbus="mmc",
            linkinfo={"info_slave_kind": "bridge", "info_slave_data": _brport(2)},
        ),
        _link(
            5,
            "br0",
            "02:5b:00:00:00:02",
            linkinfo={
                "info_kind": "bridge",
                "info_data": {
                    "vlan_filtering": 0,
                    "stp_state": 0,
                    "priority": 32768,
                    "bridge_id": "8000.2:5b:0:0:0:2",
                    "root_id": "8000.2:5b:0:0:0:2",
                    "root_port": 0,
                    "root_path_cost": 0,
                    "topology_change": 0,
                },
            },
        ),
        _link(
            6,
            "eth1.30",
            "02:5b:00:00:00:02",
            link="eth1",
            linkinfo={"info_kind": "vlan", "info_data": {"protocol": "802.1Q", "id": 30}},
        ),
        {
            "ifindex": 7,
            "ifname": "wg0",
            "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"],
            "mtu": 1420,
            "operstate": "UNKNOWN",
            "link_type": "none",
            "linkinfo": {"info_kind": "wireguard"},
        },
    ]


def _addr(name: str, *entries: tuple[str, str, int, bool]) -> dict[str, Any]:
    return {
        "ifname": name,
        "addr_info": [
            {
                "family": fam,
                "local": local,
                "prefixlen": plen,
                "scope": "global" if not local.startswith("fe80") else "link",
                **({"dynamic": True} if dyn else {}),
            }
            for fam, local, plen, dyn in entries
        ],
    }


def default_addresses() -> list[dict[str, Any]]:
    return [
        _addr("lo", ("inet", "127.0.0.1", 8, False)),
        _addr(
            "eth0", ("inet", "198.51.100.2", 24, True), ("inet6", "fe80::5b:ff:fe00:1", 64, False)
        ),
        _addr("br0", ("inet", "192.0.2.1", 25, False), ("inet6", "2001:db8:1::1", 64, False)),
        _addr("eth1.30", ("inet", "192.0.2.129", 26, False)),
        _addr("wg0", ("inet", "203.0.113.250", 30, False)),
    ]


DNSMASQ_CONF = """# Signalbox simulator: LAN and IoT VLAN
interface=br0
interface=eth1.30
listen-address=192.0.2.1
no-resolv
server=203.0.113.53
server=/corp.example/192.0.2.250
domain=home.example
dhcp-authoritative
dhcp-range=set:lan,192.0.2.50,192.0.2.100,255.255.255.128,12h
dhcp-range=set:iot,192.0.2.140,192.0.2.180,255.255.255.192,1h
dhcp-option=tag:lan,option:ntp-server,192.0.2.1
dhcp-option=tag:iot,option:router,192.0.2.129
dhcp-option=tag:lan,option:domain-search,home.example,lab.example
dhcp-option=tag:lan,252,"http://192.0.2.1/wpad.dat"
dhcp-host=02:00:00:00:00:10,192.0.2.10,printer
host-record=nas.home.example,192.0.2.20
address=/router.home.example/192.0.2.1
"""

DNSMASQ_LEASES = f"""{NOW + 3600} 02:00:00:00:00:10 192.0.2.10 printer 01:02:00:00:00:00:10
{NOW + 7200} 02:00:00:00:00:21 192.0.2.61 laptop *
{NOW + 600} 02:00:00:00:00:31 192.0.2.141 sensor *
"""

SSHD_CONFIG = """Include /etc/ssh/sshd_config.d/*.conf
#Port 22
KbdInteractiveAuthentication no
UsePAM yes
PermitRootLogin prohibit-password
"""


def _files(files: dict[str, str], unreadable: tuple[str, ...] = ()) -> str:
    out = [f"@@@ {p}\n{t.rstrip(chr(10))}" for p, t in files.items()]
    out += [f"@@! {p}" for p in unreadable]
    return "\n".join(out) + ("\n" if out else "")


def default_fdb() -> list[dict[str, Any]]:
    """``bridge -j -s fdb show`` (#160): br0's own addresses, two learned clients, one static
    entry, and entries the reader leaves out (the port's own multicast list, no master)."""
    return [
        {"mac": "02:5b:00:00:00:02", "ifname": "eth1", "master": "br0", "state": "permanent"},
        {"mac": "02:5b:00:00:00:02", "ifname": "br0", "master": "br0", "state": "permanent"},
        {"mac": "02:00:00:00:00:10", "ifname": "eth1", "master": "br0", "state": "", "updated": 4},
        {"mac": "02:00:00:00:00:21", "ifname": "wlan0", "master": "br0", "updated": 31},
        {"mac": "02:00:00:00:00:44", "ifname": "eth1", "master": "br0", "state": "static"},
        {"mac": "33:33:00:00:00:01", "ifname": "eth1", "flags": ["self"], "state": "permanent"},
        {"mac": "02:00:00:00:00:55", "ifname": "eth1", "flags": ["self"], "state": "permanent"},
        {"mac": "02:00:00:00:00:66", "ifname": "gone0", "master": "br0", "state": ""},
    ]


def default_sections() -> dict[str, str]:
    return {
        "os": _files(
            {
                "/etc/os-release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian '
                'GNU/Linux"\nVERSION_ID="12"\nID=debian\n',
                "/etc/debian_version": "12.12\n",
            }
        ),
        "hostname": "gateway2\n",
        "kernel": "Linux 6.12.47+rpt-rpi-2712 aarch64\n",
        "model": _files({"/proc/device-tree/model": "Raspberry Pi 5 Model B Rev 1.0\x00"}),
        "link": json.dumps(default_links()) + "\n",
        "addr": json.dumps(default_addresses()) + "\n",
        "route": json.dumps(
            [
                {
                    "dst": "default",
                    "gateway": "198.51.100.1",
                    "dev": "eth0",
                    "protocol": "dhcp",
                    "metric": 100,
                    "flags": [],
                },
                {"dst": "192.0.2.0/25", "dev": "br0", "protocol": "kernel", "scope": "link"},
                {"dst": "198.51.100.128/25", "dev": "wg0", "protocol": "static", "scope": "link"},
            ]
        )
        + "\n",
        "route6": json.dumps(
            [
                {
                    "dst": "default",
                    "gateway": "fe80::1",
                    "dev": "eth0",
                    "protocol": "ra",
                    "metric": 1024,
                }
            ]
        )
        + "\n",
        # ip -j route show table all / ip -j rule show (#149): the kernel's own routes, the
        # local table, a static route through the WireGuard tunnel, a route of table 100 and
        # the rules of a policy routing setup (one subnet through table 100). *guess* (#21)
        "routes4": json.dumps(
            [
                {
                    "dst": "default",
                    "gateway": "198.51.100.1",
                    "dev": "eth0",
                    "protocol": "dhcp",
                    "metric": 100,
                    "flags": [],
                },
                {"dst": "192.0.2.0/25", "dev": "br0", "protocol": "kernel", "scope": "link"},
                {"dst": "198.51.100.128/25", "dev": "wg0", "protocol": "static", "scope": "link"},
                {
                    "dst": "203.0.113.0/24",
                    "gateway": "192.0.2.5",
                    "dev": "br0",
                    "protocol": "static",
                },
                {"dst": "default", "gateway": "198.51.100.1", "dev": "eth0", "table": "100"},
                {"dst": "198.18.66.0/24", "type": "blackhole", "protocol": "static"},
                {"type": "local", "dst": "192.0.2.1", "table": "local", "dev": "br0"},
            ]
        )
        + "\n",
        "routes6": json.dumps(
            [
                {
                    "dst": "default",
                    "gateway": "fe80::1",
                    "dev": "eth0",
                    "protocol": "ra",
                    "metric": 1024,
                }
            ]
        )
        + "\n",
        "rules4": json.dumps(
            [
                {"priority": 0, "src": "all", "table": "local"},
                {"priority": 100, "src": "192.0.2.128", "srclen": 25, "table": "100"},
                {"priority": 32766, "src": "all", "table": "main"},
                {"priority": 32767, "src": "all", "table": "default"},
            ]
        )
        + "\n",
        "rules6": json.dumps(
            [
                {"priority": 0, "src": "all", "table": "local"},
                {"priority": 32766, "src": "all", "table": "main"},
            ]
        )
        + "\n",
        "sysnet": "eth0 1 0 1000 full\neth1 1 0 1000 full\nwlan0 1 1 - -\nbr0 0 0 - -\n"
        "eth1.30 0 0 1000 full\nwg0 0 0 - -\nlo 0 0 - -\n",
        "bridge-vlan": "",
        "fdb": json.dumps(default_fdb()),
        "forward": "1\n1\n",
        "uptime": "273906.51 1043262.11\n",
        "loadavg": "0.08 0.12 0.10 1/312 4321\n",
        "meminfo": "MemTotal:        8245136 kB\nMemFree:         6123456 kB\n"
        "MemAvailable:    7012345 kB\n",
        "cpus": "4\n",
        "df": "Filesystem     Type     1-blocks        Used   Available Capacity Mounted on\n"
        "/dev/mmcblk0p2 ext4  62763040768  5242880000 54830080000      9% /\n"
        "tmpfs          tmpfs  4221509632     1052672  4220456960      1% /dev/shm\n"
        "tmpfs          tmpfs   844304384     6291456   838012928      1% /run\n"
        "/dev/mmcblk0p1 vfat    535805952    66060288   469745664     13% /boot/firmware\n",
        "thermal": "cpu-thermal 48250\n",
        "units": "ssh active enabled\nsshd  \ndnsmasq active enabled\nkea-dhcp4-server inactive "
        "not-found\nisc-dhcp-server inactive not-found\nsystemd-networkd inactive disabled\n"
        "AdGuardHome inactive not-found\npihole-FTL inactive not-found\nunbound inactive "
        "not-found\nchrony active enabled\nchronyd active alias\nsystemd-timesyncd inactive "
        "not-found\n",
        "procs": "chronyd\ndnsmasq\nsshd\nsystemd\n",
        "present": "",
        "listen": "udp   UNCONN 0      0        192.0.2.1:53         0.0.0.0:*\n"
        "udp   UNCONN 0      0          0.0.0.0:67         0.0.0.0:*\n"
        "udp   UNCONN 0      0          0.0.0.0:51820      0.0.0.0:*\n"
        "tcp   LISTEN 0      128        0.0.0.0:22         0.0.0.0:*\n"
        "tcp   LISTEN 0      128           [::]:22            [::]:*\n",
        "sshd": _files(
            {
                "/etc/ssh/sshd_config": SSHD_CONFIG,
                "/etc/ssh/sshd_config.d/10-signalbox-sim.conf": "PasswordAuthentication no\n",
            }
        ),
        "resolv": _files({"/etc/resolv.conf": "nameserver 127.0.0.1\nsearch home.example\n"}),
        # rsyslog as Debian ships it, plus a forward to the collector in the LAN (#180)
        "syslog": _files(
            {
                "/etc/rsyslog.conf": 'module(load="imuxsock")\n*.*;auth,authpriv.none '
                "-/var/log/syslog\nauth,authpriv.* /var/log/auth.log\n"
                "$IncludeConfig /etc/rsyslog.d/*.conf\n",
                "/etc/rsyslog.d/50-forward.conf": "*.info @192.0.2.5:514\n",
            }
        ),
        "dnsmasq": _files({"/etc/dnsmasq.conf": DNSMASQ_CONF}),
        "dnsmasq-leases": _files({"/var/lib/misc/dnsmasq.leases": DNSMASQ_LEASES}),
        "kea": "",
        "kea-leases": "",
        "isc": "",
        "isc-leases": "",
        "networkd": "",
        "iptables": "iptables v1.8.9 (nf_tables)\n",
    }


def arch_sections() -> dict[str, str]:
    """Arch Linux ARM on a Raspberry Pi 2 as a single-NIC host (#302): systemd-networkd, one
    wired interface that carries the default route, a Wi-Fi dongle without carrier, IP
    forwarding off, no WireGuard, no nft (legacy iptables), ``sshd`` as the unit name."""
    links = [
        default_links()[0],
        _link(2, "eth0", "02:5b:00:00:00:21", parentbus="platform", parentdev="3f980000.usb"),
        _link(3, "wlan0", "02:5b:00:00:00:22", up=False, parentbus="usb"),
    ]
    addresses = [
        _addr("lo", ("inet", "127.0.0.1", 8, False)),
        _addr(
            "eth0",
            ("inet", "192.0.2.20", 24, True),
            ("inet6", "fe80::5b:ff:fe00:21", 64, False),
        ),
    ]
    routes = [
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "protocol": "dhcp"},
        {"dst": "192.0.2.0/24", "dev": "eth0", "protocol": "kernel", "scope": "link"},
    ]
    return default_sections() | {
        "syslog": "",  # journald only: nothing forwarded (#180)
        "os": _files(
            {
                "/etc/os-release": 'NAME="Arch Linux ARM"\nPRETTY_NAME="Arch Linux ARM"\n'
                "ID=archarm\nID_LIKE=arch\nBUILD_ID=rolling\n",
            }
        ),
        "hostname": "alarm\n",
        "kernel": "Linux 6.6.51-1-rpi armv7l\n",
        "model": _files({"/proc/device-tree/model": "Raspberry Pi 2 Model B Rev 1.1\x00"}),
        "link": json.dumps(links) + "\n",
        "addr": json.dumps(addresses) + "\n",
        "route": json.dumps(routes) + "\n",
        "route6": "[]\n",
        "sysnet": "eth0 1 0 100 full\nwlan0 1 1 - -\nlo 0 0 - -\n",
        "fdb": "",
        "forward": "0\n0\n",
        "cpus": "4\n",
        "units": "ssh not-found \nsshd active enabled\ndnsmasq inactive not-found\n"
        "kea-dhcp4-server inactive not-found\nisc-dhcp-server inactive not-found\n"
        "systemd-networkd active enabled\nAdGuardHome inactive not-found\n"
        "pihole-FTL inactive not-found\nunbound inactive not-found\nchrony inactive not-found\n"
        "chronyd inactive not-found\nsystemd-timesyncd active enabled\n",
        "procs": "sshd\nsystemd\nsystemd-network\nsystemd-timesyn\n",
        "listen": "tcp   LISTEN 0      128        0.0.0.0:22         0.0.0.0:*\n",
        "dnsmasq": "",
        "dnsmasq-leases": "",
        "networkd": _files(
            {
                "/etc/systemd/network/20-wired.network": "[Match]\nName=eth0\n\n[Network]\n"
                "DHCP=yes\n",
            }
        ),
        "iptables": "iptables v1.8.10 (legacy)\n",
    }


def arch_sim(**changes: Any) -> LinuxSim:
    """The Arch Linux ARM host as a device: no nft, no wg, no tracepath."""
    return LinuxSim(
        sections=arch_sections(),
        nft_installed=False,
        iptables_save=ARCH_IPTABLES_SAVE,
        wg_installed=False,
        trace_tool="none",
        **changes,
    )


def default_wireguard() -> dict[str, str]:
    return {
        "public-key": f"wg0\t{GW_KEY}\n",
        "listen-port": "wg0\t51820\n",
        "peers": f"wg0\t{PEER_KEY}\nwg0\t{PHONE_KEY}\n",
        "endpoints": f"wg0\t{PEER_KEY}\t203.0.113.1:51820\nwg0\t{PHONE_KEY}\t(none)\n",
        "allowed-ips": f"wg0\t{PEER_KEY}\t203.0.113.249/32 198.51.100.128/25\n"
        f"wg0\t{PHONE_KEY}\t203.0.113.251/32\n",
        "latest-handshakes": f"wg0\t{PEER_KEY}\t{NOW - 42}\nwg0\t{PHONE_KEY}\t0\n",
        "transfer": f"wg0\t{PEER_KEY}\t123456\t654321\nwg0\t{PHONE_KEY}\t0\t0\n",
        "persistent-keepalive": f"wg0\t{PEER_KEY}\t25\nwg0\t{PHONE_KEY}\toff\n",
    }


def _meta(key: str) -> dict[str, Any]:
    return {"meta": {"key": key}}


def _pay(protocol: str, field_name: str) -> dict[str, Any]:
    return {"payload": {"protocol": protocol, "field": field_name}}


def _eq(left: dict[str, Any], right: Any, op: str = "==") -> dict[str, Any]:
    return {"match": {"op": op, "left": left, "right": right}}


def _rule(
    chain: str, *expr: dict[str, Any], family: str = "inet", table: str = "filter", **extra: Any
) -> dict[str, Any]:
    return {"rule": {"family": family, "table": table, "chain": chain, "expr": list(expr), **extra}}


def _state(*names: str) -> dict[str, Any]:
    return _eq({"ct": {"key": "state"}}, {"set": list(names)}, "in")


#: ``iptables-save`` of the legacy backend (#394): the same small router as ``default_nft`` (input
#: and forward drop by default, a chain for the VPN, one port forward, masquerade).
LEGACY_IPTABLES_SAVE = """# Generated by iptables-save v1.8.9 (legacy) on Tue Nov 24 12:00:00 2026
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING -i eth0 -p tcp -m tcp --dport 8443 -m comment --comment nas -j DNAT --to-destination 192.0.2.20:443
-A POSTROUTING -o eth0 -j MASQUERADE
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:from_vpn - [0:0]
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -i br0 -j ACCEPT
-A INPUT -s 203.0.113.0/24 -i eth0 -p tcp -m tcp --dport 22 -m comment --comment "ssh from the office" -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i br0 -o eth0 -j ACCEPT
-A FORWARD -i eth0 -m conntrack --ctstate DNAT -j ACCEPT
-A FORWARD -i wg0 -j from_vpn
-A from_vpn -d 192.0.2.20/32 -p tcp -m multiport --dports 80,443 -j ACCEPT
COMMIT
"""  # noqa: E501
#: ``ip6tables-save`` of the same device
LEGACY_IP6TABLES_SAVE = """# Generated by ip6tables-save v1.8.9 (legacy) on Tue Nov 24 12:00:00 2026
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -s 2001:db8:1::/64 -i br0 -j ACCEPT
COMMIT
"""
#: ``iptables-save`` of an iptables-nft system (Debian 11 and 12 default, Docker's chains): the
#: legacy tables are empty, the rules live in nf_tables and show up in ``nft`` too.
NFT_BACKED_IPTABLES_SAVE = """# Warning: iptables-legacy tables present, use iptables-legacy-save to see them
# Generated by iptables-nft-save v1.8.9 (nf_tables) on Tue Nov 24 12:00:00 2026
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]
-A FORWARD -j DOCKER-USER
-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i docker0 ! -o docker0 -j ACCEPT
-A DOCKER-USER -j RETURN
COMMIT
# Completed on Tue Nov 24 12:00:00 2026
"""  # noqa: E501
#: A single-NIC Arch Linux ARM host with legacy iptables: SSH from the LAN only.
ARCH_IPTABLES_SAVE = """# Generated by iptables-save v1.8.10 (legacy) on Tue Nov 24 12:00:00 2026
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -s 192.0.2.0/24 -i eth0 -p tcp -m tcp --dport 22 -j ACCEPT
COMMIT
"""


def default_nft() -> str:
    """``nft -j list ruleset`` of a small router: input and forward drop by default, a jump to
    a chain for the VPN, a named set, one port forward and masquerade (documentation addresses)."""
    accept, drop = {"accept": None}, {"drop": None}

    def chain(name: str, **kw: Any) -> dict[str, Any]:
        return {"chain": {"family": "inet", "table": "filter", "name": name, **kw}}

    base = {"type": "filter", "prio": 0}
    objects: list[dict[str, Any]] = [
        {"metainfo": {"version": "1.0.6", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": "filter", "handle": 1}},
        {
            "set": {
                "family": "inet",
                "table": "filter",
                "name": "office",
                "type": "ipv4_addr",
                "flags": ["interval"],
                "elem": [{"prefix": {"addr": "203.0.113.0", "len": 24}}],
            }
        },
        chain("input", **base, hook="input", policy="drop"),
        _rule("input", _state("established", "related"), accept),
        _rule("input", _state("invalid"), drop),
        _rule("input", _eq(_meta("iifname"), "lo"), accept),
        _rule("input", _eq(_meta("iifname"), "br0"), accept),
        _rule(
            "input",
            _eq(_meta("iifname"), "eth1.30"),
            _eq(_pay("udp", "dport"), {"set": [53, 67]}),
            accept,
        ),
        _rule(
            "input",
            _eq(_meta("iifname"), "eth0"),
            _eq(_pay("ip", "saddr"), "@office"),
            _eq(_pay("tcp", "dport"), 22),
            accept,
            comment="ssh from the office",
        ),
        _rule("input", _eq(_pay("icmp", "type"), "echo-request"), accept),
        chain("forward", **base, hook="forward", policy="drop"),
        _rule("forward", _state("established", "related"), accept),
        _rule("forward", _eq(_meta("iifname"), "br0"), _eq(_meta("oifname"), "eth0"), accept),
        _rule("forward", _eq(_meta("iifname"), "eth1.30"), _eq(_meta("oifname"), "eth0"), accept),
        _rule(
            "forward",
            _eq(_meta("iifname"), "eth0"),
            _eq({"ct": {"key": "status"}}, "dnat", "in"),
            accept,
            comment="port forwards",
        ),
        _rule("forward", _eq(_meta("iifname"), "wg0"), {"jump": {"target": "from_vpn"}}),
        chain("from_vpn"),
        _rule(
            "from_vpn",
            _eq(_pay("ip", "daddr"), "192.0.2.20"),
            _eq(_pay("tcp", "dport"), {"set": [80, 443]}),
            accept,
        ),
        {"table": {"family": "ip", "name": "nat", "handle": 2}},
        {
            "chain": {
                "family": "ip",
                "table": "nat",
                "name": "prerouting",
                "type": "nat",
                "hook": "prerouting",
                "prio": -100,
                "policy": "accept",
            }
        },
        _rule(
            "prerouting",
            _eq(_meta("iifname"), "eth0"),
            _eq(_pay("tcp", "dport"), 8443),
            {"dnat": {"addr": "192.0.2.20", "port": 443, "family": "ip"}},
            family="ip",
            table="nat",
            comment="nas",
        ),
        {
            "chain": {
                "family": "ip",
                "table": "nat",
                "name": "postrouting",
                "type": "nat",
                "hook": "postrouting",
                "prio": 100,
                "policy": "accept",
            }
        },
        _rule(
            "postrouting",
            _eq(_meta("oifname"), "eth0"),
            {"masquerade": None},
            family="ip",
            table="nat",
        ),
    ]
    return json.dumps({"nftables": objects})


def default_time() -> dict[str, str]:
    return {
        "clock": f"{NOW}.250000000\n",
        "timedatectl": "Timezone=Europe/Berlin\nLocalRTC=no\nCanNTP=yes\nNTP=yes\n"
        "NTPSynchronized=yes\n",
        "timesync": "",
        "tracking": "CB007101,203.0.113.123,2,1795399990.123,0.000012,-0.000004,0.000020,"
        "-1.234,0.001,0.010,0.012,0.001,64.2,Normal\n",
        "sources": "^,*,203.0.113.123,1,6,377,12,-0.000012,-0.000013,0.000011\n"
        "^,+,203.0.113.124,2,6,377,13,0.000101,0.000099,0.000210\n",
        "timezone": _files({"/etc/timezone": "Europe/Berlin\n"})
        + "/usr/share/zoneinfo/Europe/Berlin\n",
        "chrony": _files(
            {
                "/etc/chrony/chrony.conf": "pool 2.debian.pool.ntp.org iburst\n"
                "server 203.0.113.123 iburst\nallow 192.0.2.0/24\n"
            }
        ),
        "timesyncd": "",
    }


#: ``/proc/net/bonding/bond0`` of an 802.3ad bond over eth2 and eth3 (Linux 6.12); eth3 is
#: not aggregated (it waits for its partner), as when its cable goes to another switch.
BOND_PROC = """Ethernet Channel Bonding Driver: v6.12.47+rpt-rpi-2712

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
Transmit Hash Policy: layer2+3 (2)
MII Status: up
MII Polling Interval (ms): 100
Up Delay (ms): 0
Down Delay (ms): 0
Peer Notification Delay (ms): 0

802.3ad info
LACP active: on
LACP rate: fast
Min links: 1
Aggregator selection policy (ad_select): stable
System priority: 65535
System MAC address: 02:5b:00:00:00:10
Active Aggregator Info:
\tAggregator ID: 1
\tNumber of ports: 1
\tActor Key: 9
\tPartner Key: 7
\tPartner Mac Address: 02:00:00:00:10:01

Slave Interface: eth2
MII Status: up
Speed: 1000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: 02:5b:00:00:00:04
Slave queue ID: 0
Aggregator ID: 1
Actor Churn State: none
Partner Churn State: none
Actor Churned Count: 0
Partner Churned Count: 0
details actor lacp pdu:
    system priority: 65535
    system mac address: 02:5b:00:00:00:10
    port key: 9
    port priority: 255
    port number: 1
    port state: 63
details partner lacp pdu:
    system priority: 32768
    system mac address: 02:00:00:00:10:01
    oper key: 7
    port priority: 32768
    port number: 5
    port state: 61

Slave Interface: eth3
MII Status: up
Speed: 1000 Mbps
Duplex: full
Link Failure Count: 1
Permanent HW addr: 02:5b:00:00:00:05
Slave queue ID: 0
Aggregator ID: 2
Actor Churn State: churned
Partner Churn State: churned
Actor Churned Count: 1
Partner Churned Count: 1
details actor lacp pdu:
    system priority: 65535
    system mac address: 02:5b:00:00:00:10
    port key: 9
    port priority: 255
    port number: 2
    port state: 71
details partner lacp pdu:
    system priority: 65535
    system mac address: 00:00:00:00:00:00
    oper key: 1
    port priority: 255
    port number: 1
    port state: 1
"""


def add_bond(sim: LinuxSim) -> LinuxSim:
    """The gateway with a second NIC pair bonded (#157): ``bond0`` (802.3ad) over eth2 and
    eth3, ``/proc/net/bonding/bond0`` of :data:`BOND_PROC`."""
    links = json.loads(sim.sections["link"])
    links += [
        _link(8, "eth2", "02:5b:00:00:00:10", master="bond0", parentbus="pci"),
        _link(9, "eth3", "02:5b:00:00:00:10", master="bond0", parentbus="pci"),
        _link(
            10,
            "bond0",
            "02:5b:00:00:00:10",
            linkinfo={"info_kind": "bond", "info_data": {"mode": "802.3ad"}},
        ),
    ]
    sim.sections["link"] = json.dumps(links) + "\n"
    sim.sections["sysnet"] = (
        sim.sections["sysnet"].rstrip("\n")
        + "\neth2 1 0 1000 full\neth3 1 0 1000 full\nbond0 0 0 2000 full\n"
    )
    sim.sections["bonding"] = _files({"/proc/net/bonding/bond0": BOND_PROC})
    return sim


@dataclass
class User:
    password: str | None = None
    keys: list[str] = field(default_factory=list)  # authorized_keys lines
    groups: set[str] = field(default_factory=set)
    #: may use sudo: "nopasswd", "password" or None
    sudo: str | None = None
    system: bool = False


def default_users() -> dict[str, User]:
    return {
        "root": User(password=ROOT_PASSWORD),
        ADMIN_USER: User(password=ADMIN_PASSWORD, groups={"sudo"}, sudo="password"),
    }


@dataclass
class LinuxSim:
    """The device; change its fields between connections."""

    sections: dict[str, str] = field(default_factory=default_sections)
    wireguard: dict[str, str] = field(default_factory=default_wireguard)
    #: ``nft -j list ruleset``
    nft: str = field(default_factory=default_nft)
    nft_installed: bool = True
    #: ``iptables-save`` / ``ip6tables-save`` (legacy iptables, #394): the text each prints, and
    #: whether the commands exist. The default is a system without iptables rules.
    iptables_save: str = ""
    ip6tables_save: str = ""
    iptables_installed: bool = True
    #: ``ip6tables-save`` is not covered by the sudoers rule (an older rule of the setup)
    ip6tables_denied: bool = False
    time: dict[str, str] = field(default_factory=default_time)
    users: dict[str, User] = field(default_factory=default_users)
    sudoers_files: dict[str, str] = field(default_factory=dict)
    wg_installed: bool = True
    #: ``ip -j`` works (iproute2); ``False``: busybox ``ip``, the JSON sections stay empty
    ip_json: bool = True
    visudo: bool = True
    scripts: list[str] = field(default_factory=list)
    #: Every install fails (no network, the package database is stale)
    install_fails: bool = False
    #: The package manager commands that ran (#302)
    installed: list[str] = field(default_factory=list)
    commands: list[tuple[str, str]] = field(default_factory=list)
    #: Traceroutes (#253): ``tracepath``, ``traceroute`` or ``none`` installed; target -> hops
    #: (address or None, RTT in ms); a target not listed answers through one router
    #: (198.51.100.1, the uplink's) and then itself.
    trace_tool: str = "tracepath"
    routes: dict[str, list[tuple[str | None, float | None]]] = field(default_factory=dict)

    def trace(self, script: str) -> str:
        """``tracepath -n`` / ``traceroute -n`` output for the target of a trace script."""
        found = re.search(r"-m (\d+) (\S+) 2>&1", script)
        if self.trace_tool == "none" or found is None:
            return "@@none\n@@end\n"
        limit, target = int(found.group(1)), found.group(2)
        hops = self.routes.get(target, [("198.51.100.1", 0.6), (target, 1.4)])[:limit]
        out = [f"@@{self.trace_tool}"]
        if self.trace_tool == "tracepath":
            out.append(" 1?: [LOCALHOST]                      pmtu 1500")
        else:
            out.append(f"traceroute to {target} ({target}), {limit} hops max, 60 byte packets")
        for ttl, (addr, rtt) in enumerate(hops, start=1):
            last = addr == target
            if self.trace_tool == "tracepath":
                text = f"{addr:<40} {rtt:.3f}ms{' reached' if last else ''}" if addr else "no reply"
                out.append(f"{ttl:2d}:  {text}")
            else:
                out.append(f"{ttl:2d}  {addr}  {rtt:.3f} ms" if addr else f"{ttl:2d}  *")
        if self.trace_tool == "tracepath":
            out.append(f"     Resume: pmtu 1500 hops {len(hops)} back {len(hops)}")
        return "\n".join([*out, "@@end"]) + "\n"

    # reading -------------------------------------------------------------------------------

    def wg_allowed(self, user: str) -> bool:
        if user == "root":
            return True
        return self.sudoers_files.get(sudoers_path(user)) == sudoers(user)

    def read(self, user: str, script: str) -> str:
        source = self.sections if script.startswith("# signalbox-read") else self.time
        out: list[str] = []
        for name in re.findall(r"echo @@([a-z0-9-]+)", script):
            if name == "wg-denied":
                continue
            if name == "wg-tool":
                if self.wg_installed and not self.wg_allowed(user):
                    out.append("@@wg-denied")
                out.append(f"@@wg-tool\n{'/usr/bin/wg' if self.wg_installed else 'none'}")
                continue
            if name in ("nft-denied", "ipt4-denied", "ipt6-denied"):
                continue
            if name in ("ipt4-tool", "ipt6-tool", "ipt4-save", "ipt6-save"):
                v4 = name.startswith("ipt4")
                path = f"/usr/sbin/{'ip' if v4 else 'ip6'}tables-save"
                allowed = self.wg_allowed(user) and (v4 or not self.ip6tables_denied)
                if name.endswith("tool"):
                    if self.iptables_installed and not allowed:
                        out.append(f"@@{name[:4]}-denied")
                    out.append(f"@@{name}\n{path if self.iptables_installed else 'none'}")
                else:
                    text = self.iptables_save if v4 else self.ip6tables_save
                    text = text if self.iptables_installed and allowed else ""
                    out.append(f"@@{name}\n{text}" if text else f"@@{name}")
                continue
            if name == "nft-tool":
                if self.nft_installed and not self.wg_allowed(user):
                    out.append("@@nft-denied")
                out.append(f"@@nft-tool\n{'/usr/sbin/nft' if self.nft_installed else 'none'}")
                continue
            if name == "nft":
                text = self.nft if self.nft_installed and self.wg_allowed(user) else ""
                out.append(f"@@nft\n{text}" if text else "@@nft")
                continue
            if name.startswith("wg-"):
                text = ""
                if self.wg_installed and self.wg_allowed(user):
                    text = self.wireguard.get(name[3:], "")
                out.append(f"@@{name}\n{text.rstrip(chr(10))}" if text else f"@@{name}")
                continue
            text = source.get(name, "")
            if not self.ip_json and name in (
                "link",
                "addr",
                "route",
                "route6",
                "routes4",
                "routes6",
                "rules4",
                "rules6",
                "bridge-vlan",
                "fdb",
            ):
                text = ""
            out.append(f"@@{name}\n{text.rstrip(chr(10))}" if text else f"@@{name}")
        return "\n".join(out) + "\n"

    # setup -----------------------------------------------------------------------------------

    def run(self, user: str, command: str, stdin: bytes) -> tuple[int, bytes, str]:
        self.commands.append((user, command))
        if command == "sudo -n true":
            return (
                (0, b"", "")
                if self.users[user].sudo == "nopasswd"
                else (
                    1,
                    b"",
                    "sudo: a password is required",
                )
            )
        as_root = user == "root"
        data = stdin
        if command in ("sudo -n sh -s", "sudo -S -p '' sh -s"):
            account = self.users.get(user)
            if account is None or account.sudo is None:
                return 1, b"", f"{user} is not in the sudoers file."
            if command.startswith("sudo -S"):
                line, _, data = stdin.partition(b"\n")
                if account.sudo == "password" and line.decode() != account.password:
                    return 1, b"", "sudo: 1 incorrect password attempt"
            elif account.sudo != "nopasswd":
                return 1, b"", "sudo: a password is required"
            as_root = True
        elif command != "sh -s":
            return 127, b"", f"sh: {command}: not found"
        script = data.decode()
        self.scripts.append(script)
        if script.startswith(("# signalbox-read", "# signalbox-time")):
            return 0, self.read(user, script).encode(), ""
        if script.startswith("# signalbox-trace"):
            return 0, self.trace(script).encode(), ""
        if not script.startswith("# signalbox-setup:"):
            return 127, b"", "sh: unknown script"
        if not as_root:
            return 1, b"", "Permission denied"
        return self.setup(script)

    def install(self, tool: str, script: str) -> tuple[int, bytes, str]:
        """``apt-get``/``pacman``/``dnf``/``apk``: only the device's own manager exists."""
        os_text = self.sections.get("os", "")
        release = dict(re.findall(r"^(\w+)=\"?([^\"\n]*)\"?$", os_text, re.M))
        found = distro.detect(release)
        command = found.install(tool)
        if self.install_fails:
            return (
                1,
                b"",
                "error: failed retrieving file 'nftables-1.0.9-1-armv7h.pkg.tar.xz' from "
                "mirror.example : The requested URL returned error: 404\n"
                "warning: failed to retrieve some files\n"
                "error: failed to commit transaction (failed to retrieve some files)",
            )
        if command is None or command not in script:
            word = re.search(r"\b(apt-get|pacman|dnf|apk)\b", script)
            return 127, b"", f"sh: {word.group(1) if word else 'install'}: not found"
        self.installed.append(command)
        if tool == "nftables":
            self.nft_installed = True
        elif tool == "wireguard":
            self.wg_installed = True
        elif tool == "tracepath":
            self.trace_tool = "tracepath"
        elif tool == "iproute2":
            self.ip_json = True
        return 0, b"", ""

    def setup(self, script: str) -> tuple[int, bytes, str]:
        step = script.split("\n", 1)[0].split(":", 1)[1].strip()
        values = dict(re.findall(r"^(\w+)='([^']*)'$", script, re.M))
        name = values.get("U", "")
        if step == "inspect":
            account = self.users.get(name)
            out = ["@@user"]
            if account is not None:
                out.append(f"{name}:x:999:999::/home/{name}:/bin/sh")
            out.append("@@groups")
            if account is not None:
                out.append(" ".join(sorted({name, *account.groups})))
            out.append("@@keys")
            if account is not None:
                out += account.keys
            out.append("@@sudoers")
            if sudoers_path(name) in self.sudoers_files:
                out.append(self.sudoers_files[sudoers_path(name)].rstrip("\n"))
            out.append("@@wg")
            if self.wg_installed:
                out.append("/usr/bin/wg")
            out.append("@@nft")
            if self.nft_installed:
                out.append("/usr/sbin/nft")
            out.append("@@ipt")
            if self.iptables_installed:
                out.append("/usr/sbin/iptables-save")
            out.append("@@os")
            out.append(self.sections.get("os", "").split("\n", 1)[-1].rstrip("\n"))
            out.append("@@have")
            if self.nft_installed:
                out.append("nft")
            if self.wg_installed:
                out.append("wg")
            if self.trace_tool == "tracepath":
                out.append("tracepath")
            if self.ip_json:
                out += ["bridge", "ip-json"]
            out.append("@@end")
            return 0, ("\n".join(out) + "\n").encode(), ""
        if step.startswith("install-"):
            return self.install(step.removeprefix("install-"), script)
        if step == "user":
            if name in self.users:
                return 9, b"", f"useradd: user '{name}' already exists"
            self.users[name] = User(system=True)
            return 0, b"", ""
        if step == "key":
            if name not in self.users:
                return 1, b"", f"getent: no user {name}"
            self.users[name].keys = [values["K"]]
            return 0, b"", ""
        if step == "sudoers":
            if not self.visudo:
                return 1, b"", "sh: visudo: not found"
            body = re.search(r"<<'SIGNALBOX'\n(.*?)\nSIGNALBOX\n", script, re.S)
            if body is None:
                return 1, b"", "no rule"
            target = re.search(r"^mv \"\$T\" '([^']+)'$", script, re.M)
            if target is None:
                return 1, b"", "no target"
            self.sudoers_files[target.group(1)] = body.group(1) + "\n"
            return 0, b"", ""
        if step == "remove-sudoers":
            self.sudoers_files.pop(values.get("P", ""), None)
            return 0, b"", ""
        if step == "remove-user":
            self.users.pop(name, None)
            return 0, b"", ""
        return 127, b"", f"unknown step {step}"


class _Server(asyncssh.SSHServer):
    def __init__(self, device: LinuxSim) -> None:
        self.device = device

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        account = self.device.users.get(username)
        return account is not None and account.password is not None and account.password == password

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        account = self.device.users.get(username)
        if account is None:
            return False
        mine = key.export_public_key("openssh").decode().split()[:2]
        return any(line.split()[:2] == mine for line in account.keys)


@asynccontextmanager
async def serve_ssh(device: LinuxSim) -> AsyncIterator[tuple[int, str]]:
    """Serve ``device`` on 127.0.0.1; yields the port and the host key fingerprint."""
    key = asyncssh.generate_private_key("ssh-ed25519")

    async def handle(process: asyncssh.SSHServerProcess[bytes]) -> None:
        user = process.get_extra_info("username")
        command = process.command or ""
        data = await process.stdin.read() if command.endswith("sh -s") else b""
        code, out, err = device.run(user, command, data)
        process.stdout.write(out)
        if err:
            process.stderr.write(err.encode() + b"\n")
        process.exit(code)

    server = await asyncssh.create_server(
        lambda: _Server(device),
        "127.0.0.1",
        0,
        server_host_keys=[key],
        process_factory=handle,
        encoding=None,
    )
    port = server.sockets[0].getsockname()[1]
    try:
        yield port, host_key_fingerprint(key)
    finally:
        server.close()
        await server.wait_closed()


@contextmanager
def serve_ssh_in_thread(device: LinuxSim) -> Iterator[tuple[int, str]]:
    """:func:`serve_ssh` on an event loop of its own (for synchronous tests and the demo)."""
    loop = asyncio.new_event_loop()
    ready: concurrent.futures.Future[tuple[int, str]] = concurrent.futures.Future()
    stop = asyncio.Event()

    async def main() -> None:
        async with serve_ssh(device) as served:
            ready.set_result(served)
            await stop.wait()

    thread = threading.Thread(target=loop.run_until_complete, args=(main(),), daemon=True)
    thread.start()
    try:
        yield ready.result(timeout=10)
    finally:
        loop.call_soon_threadsafe(stop.set)
        thread.join(timeout=10)
        loop.close()
