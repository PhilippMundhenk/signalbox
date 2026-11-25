"""A simulated EdgeRouter (EdgeOS) or VyOS router behind an SSH server (#403).

The device answers the read script of :mod:`signalbox.adapters.edgeos.collect` section by section
with *recorded* command output: ``show version``, ``show configuration commands``, ``ip -o``,
``show dhcp leases``, ``show lldp neighbors detail`` and the files under ``/proc``. The outputs
follow the formats the public documentation of EdgeOS (Ubiquiti's EdgeRouter user guide and
help articles) and VyOS (docs.vyos.io) shows, with invented values only: documentation
addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), locally administered MACs (02:...),
no device data of anyone. Four profiles:

``edgeos-2.0``
    an EdgeRouter X: DHCP WAN, ``switch0`` with VLAN 20, WireGuard, LLDP, firewall rule-sets,
    NAT, a port forward, DHCP server and DNS forwarding.
``edgeos-1.10``
    an EdgeRouter Lite: PPPoE WAN, a bridge, a VLAN, no WireGuard, no LLDP.
``vyos-1.3`` and ``vyos-1.4``
    a VyOS router: its own spellings (``member interface``, ``range 0 start``, ``translation
    address``, ``show dhcp server leases``); 1.4 names its firewall ``firewall ipv4``.

The raw configuration contains lines with secrets (a private key path, an encrypted password, an
SNMP community, a pre-shared key): the real read script filters them on the device (this
simulator does not run a shell), so the reader's own filter is tested against them.

    async with serve_ssh(EdgeosSim()) as (port, fingerprint):
        ...
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import re
import shlex
import threading
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field

import asyncssh

from signalbox.adapters.ssh import host_key_fingerprint
from signalbox.sim.linux import wg_key

NOW = 1795400000  # the simulated clock (2026-11-22)
USER = "signalbox"
PROFILES = ("edgeos-2.0", "edgeos-1.10", "vyos-1.3", "vyos-1.4")

GW_KEY = wg_key(11)
SITE_KEY = wg_key(12)
PHONE_KEY = wg_key(13)

#: Lines of secrets a device prints and the read script filters (never reach the model).
SECRET_LINES = f"""set interfaces wireguard wg0 private-key /config/auth/wg.key
set interfaces wireguard wg0 peer {SITE_KEY} preshared-key 'SIMULATOR-NOT-A-REAL-PSK'
set service snmp community private authorization rw
set system login user admin authentication encrypted-password '$6$EXAMPLE$notarealhash'
set system login user admin authentication plaintext-password ''
set system login user signalbox authentication public-keys laptop key 'SIMULATOR-PUBLIC-KEY'
set vpn l2tp remote-access authentication local-users username u1 password 'simulator-not-real'
"""


def _link(n: int, name: str, mac: str | None, flags: str, state: str, mtu: int = 1500) -> str:
    kind = f"link/ether {mac} brd ff:ff:ff:ff:ff:ff" if mac else "link/none "
    parent = ""
    if "." in name:
        parent = f"@{name.split('.')[0]}"
    return (
        f"{n}: {name}{parent}: <{flags}> mtu {mtu} qdisc noqueue state {state} mode DEFAULT "
        f"group default qlen 1000\\    {kind}"
    )


_UP = "BROADCAST,MULTICAST,UP,LOWER_UP"
_DOWN = "NO-CARRIER,BROADCAST,MULTICAST,UP"
_LOOPBACK = (
    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group "
    "default qlen 1\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00"
)


def _addr(n: int, name: str, text: str, scope: str = "global", brd: str = "") -> str:
    family = "inet6" if ":" in text else "inet"
    extra = f" brd {brd}" if brd else ""
    return (
        f"{n}: {name}    {family} {text}{extra} scope {scope} {name}\\       "
        "valid_lft forever preferred_lft forever"
    )


# --- EdgeRouter X, EdgeOS 2.0.9 -----------------------------------------------------------------

EDGEOS_20_VERSION = """Version:      v2.0.9-hotfix.7
Build ID:     5574651
Build on:     03/10/23 06:52
Copyright:    2012-2023 Ubiquiti Inc.
HW model:     EdgeRouter X 5-Port
HW S/N:       SIM0A1B2C3D4
Uptime:       10:15:03 up 3 days,  4:20,  1 user,  load average: 0.08, 0.05, 0.01
"""

EDGEOS_20_CONFIG = f"""set firewall all-ping enable
set firewall broadcast-ping disable
set firewall ipv6-name WANv6_IN default-action drop
set firewall ipv6-name WANv6_IN rule 10 action accept
set firewall ipv6-name WANv6_IN rule 10 state established enable
set firewall ipv6-name WANv6_IN rule 10 state related enable
set firewall ipv6-name WANv6_IN rule 20 action accept
set firewall ipv6-name WANv6_IN rule 20 protocol ipv6-icmp
set firewall name IOT_IN default-action accept
set firewall name IOT_IN rule 10 action drop
set firewall name IOT_IN rule 10 description 'IoT must not reach the LAN'
set firewall name IOT_IN rule 10 destination address 192.0.2.0/25
set firewall name IOT_IN rule 10 state new enable
set firewall name WAN_IN default-action drop
set firewall name WAN_IN description 'WAN to internal'
set firewall name WAN_IN rule 10 action accept
set firewall name WAN_IN rule 10 description 'Allow established/related'
set firewall name WAN_IN rule 10 state established enable
set firewall name WAN_IN rule 10 state related enable
set firewall name WAN_IN rule 20 action drop
set firewall name WAN_IN rule 20 description 'Drop invalid state'
set firewall name WAN_IN rule 20 state invalid enable
set firewall name WAN_IN rule 30 action accept
set firewall name WAN_IN rule 30 description 'Web server'
set firewall name WAN_IN rule 30 destination address 192.0.2.50
set firewall name WAN_IN rule 30 destination port 80,443
set firewall name WAN_IN rule 30 protocol tcp
set firewall name WAN_IN rule 30 state new enable
set firewall name WAN_LOCAL default-action drop
set firewall name WAN_LOCAL rule 10 action accept
set firewall name WAN_LOCAL rule 10 state established enable
set firewall name WAN_LOCAL rule 10 state related enable
set firewall name WAN_LOCAL rule 20 action accept
set firewall name WAN_LOCAL rule 20 description 'SSH from the admin network'
set firewall name WAN_LOCAL rule 20 destination port ssh
set firewall name WAN_LOCAL rule 20 protocol tcp
set firewall name WAN_LOCAL rule 20 source address 198.51.100.0/25
set firewall name WAN_LOCAL rule 30 action accept
set firewall name WAN_LOCAL rule 30 description 'Rate limited ping'
set firewall name WAN_LOCAL rule 30 limit burst 5
set firewall name WAN_LOCAL rule 30 protocol icmp
set firewall receive-redirects disable
set firewall send-redirects enable
set firewall source-validation disable
set firewall syn-cookies enable
set interfaces ethernet eth0 address dhcp
set interfaces ethernet eth0 description Internet
set interfaces ethernet eth0 duplex auto
set interfaces ethernet eth0 firewall in name WAN_IN
set interfaces ethernet eth0 firewall local name WAN_LOCAL
set interfaces ethernet eth0 speed auto
set interfaces ethernet eth1 description 'Desk switch'
set interfaces ethernet eth2 description 'Access point'
set interfaces ethernet eth3 disable
set interfaces ethernet eth4 description Spare
set interfaces loopback lo
set interfaces switch switch0 address 192.0.2.1/25
set interfaces switch switch0 description Local
set interfaces switch switch0 mtu 1500
set interfaces switch switch0 switch-port interface eth1
set interfaces switch switch0 switch-port interface eth2
set interfaces switch switch0 switch-port interface eth3
set interfaces switch switch0 switch-port interface eth4
set interfaces switch switch0 switch-port vlan-aware enable
set interfaces switch switch0 vif 20 address 192.0.2.129/26
set interfaces switch switch0 vif 20 description IoT
set interfaces switch switch0 vif 20 firewall in name IOT_IN
set interfaces wireguard wg0 address 198.51.100.254/30
set interfaces wireguard wg0 listen-port 51820
set interfaces wireguard wg0 mtu 1420
set interfaces wireguard wg0 peer {SITE_KEY} allowed-ips 198.51.100.253/32
set interfaces wireguard wg0 peer {SITE_KEY} allowed-ips 198.51.100.0/25
set interfaces wireguard wg0 peer {SITE_KEY} description 'Second site'
set interfaces wireguard wg0 peer {SITE_KEY} endpoint 203.0.113.77:51820
set interfaces wireguard wg0 peer {SITE_KEY} persistent-keepalive 25
set interfaces wireguard wg0 peer {PHONE_KEY} allowed-ips 198.51.100.255/32
set port-forward auto-firewall enable
set port-forward hairpin-nat enable
set port-forward lan-interface switch0
set port-forward rule 1 description 'Web server'
set port-forward rule 1 forward-to address 192.0.2.50
set port-forward rule 1 forward-to port 80
set port-forward rule 1 original-port 8080
set port-forward rule 1 protocol tcp
set port-forward wan-interface eth0
set protocols static route 192.0.2.192/26 next-hop 192.0.2.10
set protocols static route 192.0.2.224/27 blackhole
set protocols static route 192.0.2.240/28 next-hop 192.0.2.11
set service dhcp-server disabled false
set service dhcp-server shared-network-name IOT authoritative disable
set service dhcp-server shared-network-name IOT subnet 192.0.2.128/26 default-router 192.0.2.129
set service dhcp-server shared-network-name IOT subnet 192.0.2.128/26 dns-server 192.0.2.129
set service dhcp-server shared-network-name IOT subnet 192.0.2.128/26 lease 43200
set service dhcp-server shared-network-name IOT subnet 192.0.2.128/26 start 192.0.2.150 stop 192.0.2.190
set service dhcp-server shared-network-name LAN authoritative enable
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/25 default-router 192.0.2.1
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/25 dns-server 192.0.2.1
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/25 domain-name lan.example
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/25 lease 86400
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/25 ntp-server 192.0.2.1
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/25 start 192.0.2.20 stop 192.0.2.99
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/25 static-mapping printer ip-address 192.0.2.50
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/25 static-mapping printer mac-address 02:00:00:00:00:50
set service dns forwarding cache-size 150
set service dns forwarding listen-on switch0
set service dns forwarding dhcp switch0
set service dns forwarding listen-on switch0.20
set service dns forwarding name-server 203.0.113.53
set service dns forwarding name-server 203.0.113.54
set service gui http-port 80
set service gui https-port 443
set service gui older-ciphers disable
set service lldp interface all
set service nat rule 5010 description masquerade
set service nat rule 5010 log disable
set service nat rule 5010 outbound-interface eth0
set service nat rule 5010 protocol all
set service nat rule 5010 type masquerade
set service nat rule 5020 description 'Mail relay'
set service nat rule 5020 outbound-interface eth0
set service nat rule 5020 source address 192.0.2.40
set service nat rule 5020 type source
set service nat rule 5020 outside-address address 203.0.113.12
set service ssh port 22
set service ssh protocol-version v2
set system host-name er-sim
set system login user signalbox level operator
set system ntp server ntp.example.org
set system static-host-mapping host-name nas.lan.example inet 192.0.2.60
set system time-zone UTC
{SECRET_LINES}"""

EDGEOS_20_LINK = "\n".join(
    [
        _LOOPBACK,
        _link(2, "eth0", "02:5e:00:00:00:00", _UP, "UP"),
        _link(3, "eth1", "02:5e:00:00:00:01", _UP, "UP"),
        _link(4, "eth2", "02:5e:00:00:00:02", _UP, "UP"),
        _link(5, "eth3", "02:5e:00:00:00:03", "BROADCAST,MULTICAST", "DOWN"),
        _link(6, "eth4", "02:5e:00:00:00:04", _DOWN, "DOWN"),
        _link(7, "switch0", "02:5e:00:00:00:01", _UP, "UP"),
        _link(8, "switch0.20", "02:5e:00:00:00:01", _UP, "UP"),
        _link(9, "wg0", None, "POINTOPOINT,NOARP,UP,LOWER_UP", "UNKNOWN", 1420),
    ]
)
EDGEOS_20_ADDR = "\n".join(
    [
        _addr(1, "lo", "127.0.0.1/8", "host"),
        _addr(2, "eth0", "203.0.113.10/24", brd="203.0.113.255"),
        _addr(2, "eth0", "fe80::5e:ff:fe00:0/64", "link"),
        _addr(7, "switch0", "192.0.2.1/25", brd="192.0.2.127"),
        _addr(8, "switch0.20", "192.0.2.129/26", brd="192.0.2.191"),
        _addr(9, "wg0", "198.51.100.254/30"),
    ]
)
EDGEOS_20_ROUTE = """default via 203.0.113.1 dev eth0  proto dhcp
192.0.2.0/25 dev switch0  proto kernel  scope link  src 192.0.2.1
192.0.2.128/26 dev switch0.20  proto kernel  scope link  src 192.0.2.129
192.0.2.192/26 via 192.0.2.10 dev switch0  proto zebra  metric 1
blackhole 192.0.2.224/27  proto zebra  metric 1
198.51.100.252/30 dev wg0  proto kernel  scope link  src 198.51.100.254
203.0.113.0/24 dev eth0  proto kernel  scope link  src 203.0.113.10
"""
EDGEOS_20_SYSNET = """lo 0 0 - -
eth0 1 0 1000 full
eth1 1 0 1000 full
eth2 1 0 100 full
eth3 1 0 - -
eth4 1 0 - -
switch0 0 0 - -
switch0.20 0 0 - -
wg0 0 0 - -
"""

EDGEOS_LEASES = """IP address      Hardware address    Lease expiration     Pool       Client Name
----------      ----------------    ----------------     ----       -----------
192.0.2.21      02:00:00:00:00:21   2026/11/23 08:15:00  LAN        laptop
192.0.2.50      02:00:00:00:00:50   2026/11/23 02:00:00  LAN        printer
192.0.2.151     02:00:00:00:00:61   2026/11/22 18:30:00  IOT        sensor1
"""

EDGEOS_LLDP = """-------------------------------------------------------------------------------
LLDP neighbors:
-------------------------------------------------------------------------------
Interface:    eth1, via: LLDP, RID: 1, Time: 0 day, 03:12:44
  Chassis:
    ChassisID:    mac 02:5e:11:00:00:01
    SysName:      es-sim
    SysDescr:     EdgeSwitch 8-Port 150W, 1.9.2, Linux 3.6.5-b2a2d4af, 1.0.0.5004
    MgmtIP:       192.0.2.2
    Capability:   Bridge, on
    Capability:   Router, off
  Port:
    PortID:       ifname 0/1
    PortDescr:    0/1
    TTL:          120
    MFS:          1522
    VLAN:         1, pvid: yes
    VLAN:         20, pvid: no
  LLDP-MED:
    Device Type:  Network Connectivity Device
-------------------------------------------------------------------------------
Interface:    eth2, via: LLDP, RID: 2, Time: 0 day, 03:12:50
  Chassis:
    ChassisID:    mac 02:5e:22:00:00:01
    SysName:      ap-sim
    SysDescr:     Access point
                  firmware 6.6.1
    MgmtIP:       192.0.2.3
    Capability:   Bridge, on
    Capability:   Wlan, on
  Port:
    PortID:       mac 02:5e:22:00:00:02
-------------------------------------------------------------------------------
"""

PROC = {
    "uptime": "263700.55 1017000.10\n",
    "loadavg": "0.08 0.05 0.01 1/102 4711\n",
    "meminfo": "MemTotal:         504852 kB\nMemFree:          210000 kB\n"
    "MemAvailable:     330000 kB\nBuffers:           30000 kB\n",
    "cpus": "2\n",
    "df": "Filesystem     Type   1-blocks      Used Available Capacity Mounted on\n"
    "overlay        overlay 3779035136 912261120 2866774016 25% /\n"
    "tmpfs          tmpfs    259641344   1048576  258592768   1% /run\n",
    "thermal": "cpu_thermal 48000\n",
    "kernel": "Linux 4.14.54-UBNT mips64\n",
}

# --- EdgeRouter Lite, EdgeOS 1.10 --------------------------------------------------------------

EDGEOS_110_VERSION = """Version:      v1.10.11
Build ID:     5370113
Build on:     02/03/20 11:40
Copyright:    2012-2020 Ubiquiti Networks, Inc.
HW model:     EdgeRouter Lite 3-Port
HW S/N:       SIM9Z8Y7X6W5
Uptime:       10:15:03 up 12 days,  1:02,  1 user,  load average: 0.02, 0.03, 0.00
"""
EDGEOS_110_CONFIG = f"""set firewall name WAN_IN default-action drop
set firewall name WAN_IN rule 10 action accept
set firewall name WAN_IN rule 10 state established enable
set firewall name WAN_IN rule 10 state related enable
set firewall name WAN_LOCAL default-action drop
set firewall name WAN_LOCAL rule 10 action accept
set firewall name WAN_LOCAL rule 10 state established enable
set firewall name WAN_LOCAL rule 10 state related enable
set interfaces bridge br0
set interfaces bridge br0 description Wired
set interfaces ethernet eth0 description Internet
set interfaces ethernet eth0 pppoe 0 default-route auto
set interfaces ethernet eth0 pppoe 0 firewall in name WAN_IN
set interfaces ethernet eth0 pppoe 0 firewall local name WAN_LOCAL
set interfaces ethernet eth0 pppoe 0 mtu 1492
set interfaces ethernet eth1 address 192.0.2.1/26
set interfaces ethernet eth1 description Local
set interfaces ethernet eth1 vif 30 address 198.51.100.1/26
set interfaces ethernet eth1 vif 30 description Guests
set interfaces ethernet eth2 bridge-group bridge br0
set interfaces ethernet eth2 description Wired
set interfaces loopback lo
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/26 default-router 192.0.2.1
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/26 dns-server 192.0.2.1
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/26 lease 86400
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/26 start 192.0.2.10 stop 192.0.2.60
set service dns forwarding cache-size 150
set service dns forwarding listen-on eth1
set service dns forwarding name-server 203.0.113.53
set service nat rule 5010 outbound-interface pppoe0
set service nat rule 5010 type masquerade
set service ssh port 22
set service ssh disable-password-authentication
set service telnet
set system host-name erl-sim
set system login user signalbox level operator
set system ntp server ntp.example.org
set system time-zone Europe/Berlin
{SECRET_LINES}"""
EDGEOS_110_LINK = "\n".join(
    [
        _LOOPBACK,
        _link(2, "eth0", "02:5e:01:00:00:00", _UP, "UP"),
        _link(3, "eth1", "02:5e:01:00:00:01", _UP, "UP"),
        _link(4, "eth2", "02:5e:01:00:00:02", _UP, "UP"),
        _link(5, "eth1.30", "02:5e:01:00:00:01", _UP, "UP"),
        _link(6, "br0", "02:5e:01:00:00:02", _UP, "UP"),
        _link(7, "pppoe0", None, "POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP", "UNKNOWN", 1492),
    ]
).replace("link/none ", "link/ppp ")
EDGEOS_110_ADDR = "\n".join(
    [
        _addr(1, "lo", "127.0.0.1/8", "host"),
        _addr(3, "eth1", "192.0.2.1/26", brd="192.0.2.63"),
        _addr(5, "eth1.30", "198.51.100.1/26", brd="198.51.100.63"),
        "7: pppoe0    inet 203.0.113.77 peer 203.0.113.1/32 scope global pppoe0\\       "
        "valid_lft forever preferred_lft forever",
    ]
)
EDGEOS_110_ROUTE = """default via 203.0.113.1 dev pppoe0  proto zebra  metric 1
192.0.2.0/26 dev eth1  proto kernel  scope link  src 192.0.2.1
198.51.100.0/26 dev eth1.30  proto kernel  scope link  src 198.51.100.1
203.0.113.1 dev pppoe0  proto kernel  scope link  src 203.0.113.77
"""
EDGEOS_110_SYSNET = """lo 0 0 - -
eth0 1 0 1000 full
eth1 1 0 1000 full
eth2 1 0 100 half
eth1.30 0 0 - -
br0 0 0 - -
pppoe0 0 0 - -
"""

# --- VyOS 1.3 and 1.4 ----------------------------------------------------------------------------

VYOS_13_VERSION = """Version:          VyOS 1.3.3
Release train:    equuleus

Built by:         autobuild@vyos.net
Built on:         Sun 18 Dec 2022 22:49 UTC
Build UUID:       00000000-0000-0000-0000-000000000000
Build commit ID:  0000000000000

Architecture:     x86_64
Boot via:         installed image
System type:      KVM guest

Hardware vendor:  QEMU
Hardware model:   Standard PC (Q35 + ICH9, 2009)
Hardware S/N:
Hardware UUID:    00000000-0000-0000-0000-000000000000

Copyright:        VyOS maintainers and contributors
"""
VYOS_14_VERSION = VYOS_13_VERSION.replace("VyOS 1.3.3", "VyOS 1.4.0").replace("equuleus", "sagitta")

_VYOS_COMMON = f"""set interfaces bridge br0 address '192.0.2.1/24'
set interfaces bridge br0 member interface 'eth1'
set interfaces bonding bond0 member interface 'eth2'
set interfaces bonding bond0 member interface 'eth3'
set interfaces bonding bond0 mode '802.3ad'
set interfaces ethernet eth0 address 'dhcp'
set interfaces ethernet eth0 description 'Internet'
set interfaces ethernet eth0 vif 100 address '198.51.100.65/26'
set interfaces ethernet eth1 description 'LAN'
set interfaces ethernet eth2 description 'Uplink A'
set interfaces ethernet eth3 description 'Uplink B'
set interfaces loopback lo
set interfaces wireguard wg0 address '198.51.100.254/30'
set interfaces wireguard wg0 peer site2 allowed-ips '198.51.100.0/25'
set interfaces wireguard wg0 peer site2 endpoint '203.0.113.77:51820'
set interfaces wireguard wg0 peer site2 PEERKEYWORD '{SITE_KEY}'
set interfaces wireguard wg0 port '51820'
set protocols static route 192.0.2.192/26 next-hop 192.0.2.10
set service lldp interface eth1
set service ntp server ntp.example.org
set service ssh port '22'
set system host-name 'vyos-sim'
set system time-zone 'UTC'
{SECRET_LINES}"""

VYOS_13_CONFIG = (
    _VYOS_COMMON.replace("PEERKEYWORD", "pubkey")
    + """set firewall name WAN_IN default-action 'drop'
set firewall name WAN_IN rule 10 action 'accept'
set firewall name WAN_IN rule 10 state established 'enable'
set firewall name WAN_IN rule 10 state related 'enable'
set firewall name WAN_IN rule 20 action 'accept'
set firewall name WAN_IN rule 20 destination port '443'
set firewall name WAN_IN rule 20 protocol 'tcp'
set firewall name WAN_IN rule 20 state new 'enable'
set interfaces ethernet eth0 firewall in name 'WAN_IN'
set nat destination rule 10 description 'Web'
set nat destination rule 10 destination port '8443'
set nat destination rule 10 inbound-interface 'eth0'
set nat destination rule 10 protocol 'tcp'
set nat destination rule 10 translation address '192.0.2.50'
set nat destination rule 10 translation port '443'
set nat source rule 100 outbound-interface 'eth0'
set nat source rule 100 source address '192.0.2.0/24'
set nat source rule 100 translation address 'masquerade'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 default-router '192.0.2.1'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 dns-server '192.0.2.1'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 domain-name 'lan.example'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 lease '86400'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 range 0 start '192.0.2.100'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 range 0 stop '192.0.2.199'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 static-mapping nas ip-address '192.0.2.60'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 static-mapping nas mac-address '02:00:00:00:00:60'
set service dns forwarding listen-address '192.0.2.1'
set service dns forwarding name-server '203.0.113.53'
"""
)
VYOS_14_CONFIG = (
    _VYOS_COMMON.replace("PEERKEYWORD", "public-key")
    + """set firewall ipv4 forward filter default-action 'drop'
set firewall ipv4 forward filter rule 10 action 'accept'
set firewall ipv4 forward filter rule 10 state 'established'
set firewall ipv4 forward filter rule 10 state 'related'
set firewall ipv4 forward filter rule 20 action 'jump'
set firewall ipv4 forward filter rule 20 inbound-interface name 'eth0'
set firewall ipv4 forward filter rule 20 jump-target 'WAN_IN'
set firewall ipv4 forward filter rule 30 action 'accept'
set firewall ipv4 forward filter rule 30 description 'LAN out'
set firewall ipv4 forward filter rule 30 inbound-interface name 'br0'
set firewall ipv4 forward filter rule 30 outbound-interface name 'eth0'
set firewall ipv4 input filter default-action 'drop'
set firewall ipv4 input filter rule 10 action 'accept'
set firewall ipv4 input filter rule 10 destination port '22'
set firewall ipv4 input filter rule 10 inbound-interface name 'br0'
set firewall ipv4 input filter rule 10 protocol 'tcp'
set firewall ipv4 name WAN_IN default-action 'drop'
set firewall ipv4 name WAN_IN rule 10 action 'accept'
set firewall ipv4 name WAN_IN rule 10 description 'Web server'
set firewall ipv4 name WAN_IN rule 10 destination address '192.0.2.50'
set firewall ipv4 name WAN_IN rule 10 destination port '443'
set firewall ipv4 name WAN_IN rule 10 protocol 'tcp'
set firewall ipv6 forward filter default-action 'drop'
set firewall ipv6 forward filter rule 10 action 'accept'
set firewall ipv6 forward filter rule 10 state 'established'
set firewall ipv6 forward filter rule 10 state 'related'
set nat destination rule 10 description 'Web'
set nat destination rule 10 destination port '8443'
set nat destination rule 10 inbound-interface name 'eth0'
set nat destination rule 10 protocol 'tcp'
set nat destination rule 10 translation address '192.0.2.50'
set nat destination rule 10 translation port '443'
set nat source rule 100 outbound-interface name 'eth0'
set nat source rule 100 source address '192.0.2.0/24'
set nat source rule 100 translation address 'masquerade'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 option default-router '192.0.2.1'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 option domain-name 'lan.example'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 option name-server '192.0.2.1'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 lease '86400'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 range 0 start '192.0.2.100'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 range 0 stop '192.0.2.199'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 static-mapping nas ip-address '192.0.2.60'
set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 static-mapping nas mac '02:00:00:00:00:60'
set service dns forwarding listen-address '192.0.2.1'
set service dns forwarding name-server '203.0.113.53'
"""
)
VYOS_LINK = "\n".join(
    [
        _LOOPBACK,
        _link(2, "eth0", "02:5e:02:00:00:00", _UP, "UP"),
        _link(3, "eth1", "02:5e:02:00:00:01", _UP, "UP"),
        _link(4, "eth2", "02:5e:02:00:00:02", _UP, "UP"),
        _link(5, "eth3", "02:5e:02:00:00:02", _UP, "UP"),
        _link(6, "eth0.100", "02:5e:02:00:00:00", _UP, "UP"),
        _link(7, "br0", "02:5e:02:00:00:01", _UP, "UP"),
        _link(8, "bond0", "02:5e:02:00:00:02", _UP, "UP"),
        _link(9, "wg0", None, "POINTOPOINT,NOARP,UP,LOWER_UP", "UNKNOWN", 1420),
    ]
)
VYOS_ADDR = "\n".join(
    [
        _addr(1, "lo", "127.0.0.1/8", "host"),
        _addr(2, "eth0", "203.0.113.20/24", brd="203.0.113.255"),
        _addr(6, "eth0.100", "198.51.100.65/26", brd="198.51.100.127"),
        _addr(7, "br0", "192.0.2.1/24", brd="192.0.2.255"),
        _addr(9, "wg0", "198.51.100.254/30"),
    ]
)
VYOS_ROUTE = """default via 203.0.113.1 dev eth0 proto dhcp src 203.0.113.20 metric 210
192.0.2.0/24 dev br0 proto kernel scope link src 192.0.2.1
192.0.2.192/26 via 192.0.2.10 dev br0 proto static metric 1
198.51.100.252/30 dev wg0 proto kernel scope link src 198.51.100.254
203.0.113.0/24 dev eth0 proto kernel scope link src 203.0.113.20
198.51.100.64/26 dev eth0.100 proto kernel scope link src 198.51.100.65
"""
VYOS_SYSNET = """lo 0 0 - -
eth0 1 0 1000 full
eth1 1 0 1000 full
eth2 1 0 1000 full
eth3 1 0 1000 full
eth0.100 0 0 - -
br0 0 0 - -
bond0 0 0 - -
wg0 0 0 - -
"""
VYOS_LEASES = """IP Address    MAC address        State    Lease start          Lease expiration     Remaining    Pool    Hostname
------------  -----------------  -------  -------------------  -------------------  -----------  ------  ----------
192.0.2.100   02:00:00:00:00:70  active   2026/11/22 08:00:00  2026/11/23 08:00:00  23:55:00     LAN     laptop
192.0.2.60    02:00:00:00:00:60  active   2026/11/22 07:00:00  2026/11/23 07:00:00  22:55:00     LAN     nas
192.0.2.101   02:00:00:00:00:71  free     2026/11/20 08:00:00  2026/11/21 08:00:00  -            LAN
"""
VYOS_LLDP = """-------------------------------------------------------------------------------
LLDP neighbors:
-------------------------------------------------------------------------------
Interface:    eth1, via: LLDP, RID: 1, Time: 0 day, 03:12:44
  Chassis:
    ChassisID:    mac 02:5e:11:00:00:09
    SysName:      sw-sim
    SysDescr:     Managed switch
    MgmtIP:       192.0.2.4
    Capability:   Bridge, on
  Port:
    PortID:       ifname Gi1/0/3
"""


@dataclass
class EdgeosSim:
    """A router with recorded command output; ``sections`` overrides single sections."""

    profile: str = "edgeos-2.0"
    #: The login of the operator user: its authorized public keys (OpenSSH lines) and password.
    keys: list[str] = field(default_factory=list)
    password: str | None = None
    #: Replaces sections of the answer (name -> text), for the variants the tests need.
    sections: dict[str, str] = field(default_factory=dict)
    #: Lines added to the configuration.
    extra_config: str = ""
    #: The answer stops before ``@@end`` (a login shell that does not run the script).
    truncate: bool = False
    #: Every script received.
    scripts: list[str] = field(default_factory=list)
    commands: list[tuple[str, str]] = field(default_factory=list)
    #: The administrator of the automatic setup (login, password); None: no admin login.
    admin: tuple[str, str] | None = None
    #: Local users made by the setup: login -> level (None: no level set).
    users: dict[str, str | None] = field(default_factory=dict)
    #: The option ``level`` exists: EdgeOS and VyOS up to 1.3 yes; None: by profile (the
    #: VyOS 1.4 profile has none, like the rolling release).
    levels: bool | None = None
    #: The configuration commands received by the setup, in order.
    applied: list[str] = field(default_factory=list)

    @property
    def has_levels(self) -> bool:
        return self.levels if self.levels is not None else self.profile != "vyos-1.4"

    def setup(self, script: str) -> tuple[int, bytes, str]:
        """The two scripts of the automatic setup (``edgeos.provision``)."""
        if script.startswith("# signalbox-setup: inspect"):
            login = re.search(r"^U='([^']*)'", script, re.M)
            who = login.group(1) if login else ""
            level = self.users.get(who)
            parts = [
                f"@@version\n{self.data()['version']}",
                "@@level\n" + ("yes\n" if self.has_levels else ""),
                "@@user\n" + (f"set system login user {who} level '{level}'\n" if level else ""),
                f"@@exists\n{1 if who in self.users else 0}\n",
                "@@end\n",
            ]
            return 0, "".join(parts).encode(), ""
        body = re.search(r"<<'SIGNALBOX'\n(.*?)\nSIGNALBOX\n", script, re.S)
        if body is None:
            return 127, b"", "sh: unknown script"
        out = ""
        for line in body.group(1).splitlines():
            words = shlex.split(line)
            if words[:4] == ["set", "system", "login", "user"]:
                self.applied.append(line)
                who = words[4]
                if words[5:] == ["level", "operator"]:
                    if not self.has_levels:
                        out += f"Set failed\n  [ system login user {who} level ] is not valid\n"
                        continue
                    self.users[who] = "operator"
                else:
                    self.users.setdefault(who, None)
                if words[5:8] == ["authentication", "public-keys", "signalbox"] and (
                    words[8] == "key"
                ):
                    self.keys = [f"ssh-ed25519 {words[9]}"]
            elif words[:4] == ["delete", "system", "login", "user"]:
                self.applied.append(line)
                self.users.pop(words[4], None)
                self.keys = []
        return 0, out.encode(), ""

    def data(self) -> dict[str, str]:
        p = self.profile
        edge = p.startswith("edgeos")
        version, config, link, addr, route, sysnet, leases, lldp = {
            "edgeos-2.0": (
                EDGEOS_20_VERSION,
                EDGEOS_20_CONFIG,
                EDGEOS_20_LINK,
                EDGEOS_20_ADDR,
                EDGEOS_20_ROUTE,
                EDGEOS_20_SYSNET,
                EDGEOS_LEASES,
                EDGEOS_LLDP,
            ),
            "edgeos-1.10": (
                EDGEOS_110_VERSION,
                EDGEOS_110_CONFIG,
                EDGEOS_110_LINK,
                EDGEOS_110_ADDR,
                EDGEOS_110_ROUTE,
                EDGEOS_110_SYSNET,
                EDGEOS_LEASES,
                "",
            ),
            "vyos-1.3": (
                VYOS_13_VERSION,
                VYOS_13_CONFIG,
                VYOS_LINK,
                VYOS_ADDR,
                VYOS_ROUTE,
                VYOS_SYSNET,
                "",
                VYOS_LLDP,
            ),
            "vyos-1.4": (
                VYOS_14_VERSION,
                VYOS_14_CONFIG,
                VYOS_LINK,
                VYOS_ADDR,
                VYOS_ROUTE,
                VYOS_SYSNET,
                "",
                VYOS_LLDP,
            ),
        }[p]
        out = {
            "version": version,
            "config": config + self.extra_config,
            "link": link + "\n",
            "addr": addr + "\n",
            "route": route,
            "route6": "",
            "sysnet": sysnet,
            "dhcp-leases": leases if edge else "",
            "dhcp-leases-server": VYOS_LEASES if not edge else "",
            "lldp": lldp,
            "wg-keys": f"wg0 {GW_KEY}\n" if p in ("edgeos-2.0", "vyos-1.3", "vyos-1.4") else "",
            "uptime": PROC["uptime"],
            "loadavg": PROC["loadavg"],
            "meminfo": PROC["meminfo"],
            "cpus": PROC["cpus"],
            "df": PROC["df"],
            "thermal": PROC["thermal"] if p == "edgeos-2.0" else "",
            "kernel": PROC["kernel"] if edge else "Linux 5.4.220-amd64-vyos x86_64\n",
            "clock": f"{NOW}.123456789\n",
        }
        return out | self.sections

    def run(self, command: str, stdin: bytes) -> tuple[int, bytes, str]:
        if command != "sh -s":
            self.commands.append(("", command))
            return 127, b"", f"sh: {command}: not found"
        script = stdin.decode()
        self.scripts.append(script)
        if script.startswith("# signalbox-setup"):
            return self.setup(script)
        if not script.startswith(("# signalbox-read", "# signalbox-time")):
            return 127, b"", "sh: unknown script"
        data = self.data()
        out: list[str] = []
        for name in re.findall(r"^echo @@([\w-]+)", script, re.M):
            if name == "end":
                if self.truncate:
                    break
                out.append("@@end\n")
                continue
            out.append(f"@@{name}\n{data.get(name, '')}")
            if not out[-1].endswith("\n"):
                out[-1] += "\n"
        return 0, "".join(out).encode(), ""


class _Server(asyncssh.SSHServer):
    def __init__(self, device: EdgeosSim) -> None:
        self.device = device

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return self.device.password is not None or self.device.admin is not None

    def validate_password(self, username: str, password: str) -> bool:
        if self.device.admin is not None and (username, password) == self.device.admin:
            return True
        return username == USER and password == self.device.password

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        mine = key.export_public_key("openssh").decode().split()[:2]
        return username == USER and any(line.split()[:2] == mine for line in self.device.keys)


@asynccontextmanager
async def serve_ssh(device: EdgeosSim) -> AsyncIterator[tuple[int, str]]:
    """Serve ``device`` on 127.0.0.1; yields the port and the host key fingerprint."""
    key = asyncssh.generate_private_key("ssh-ed25519")

    async def handle(process: asyncssh.SSHServerProcess[bytes]) -> None:
        command = process.command or ""
        data = await process.stdin.read() if command.endswith("sh -s") else b""
        code, out, err = device.run(command, data)
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
def serve_ssh_in_thread(device: EdgeosSim) -> Iterator[tuple[int, str]]:
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
