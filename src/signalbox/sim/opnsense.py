"""Simulator of the OPNsense REST API endpoints the ``opnsense`` adapter reads and writes.

The answers follow the JSON shapes in ``docs/adapters/opnsense.md`` (from the public API docs,
not yet confirmed on a real device, issue #21). Sample network, documentation addresses only:

- LAN ``igb0`` untagged, 192.0.2.1/24 and 2001:db8:1::1/64, Kea DHCP
- VLAN 20 "IoT" on ``igb0``, 198.51.100.1/24, Kea DHCP with its own options
- VLAN 30 "Guest" on ``igb0``, 203.0.113.1/24, ISC DHCP
- VLAN 40 "Lab" defined but not assigned; WAN ``igb1`` (uplink, DHCP behind the provider's
  carrier-grade NAT: 100.64.23.45/22, 2001:db8:ffff::2/64, delegated prefix 2001:db8:1::/56)
- Unbound with forwarders and host overrides, dnsmasq for DHCP only; ARP and NDP entries;
  DHCP leases
- the dashboard's health widgets (uptime, load, memory, ZFS disks, two CPU sensors), the
  clock in Europe/Berlin and ntpd in sync with a local GPS-backed server
- WireGuard instance ``wg0`` (2001:db8:ff::1, shown as /128 like on 26.7.9; port 51820; not
  assigned) with a site-to-site peer ``site-b`` (routes 2001:db8:20::/64, handshake 42 s before
  the start) and a phone that never connected (#239)

Failure switches on :class:`OpnsenseSimulator`: ``api_enabled=False`` (404 on everything),
``delay`` (seconds before every answer), ``malformed`` (endpoints answering broken JSON),
``fail`` (a status code per endpoint);
a wrong key or secret is answered with 401. ``data`` can be edited by tests.

Writes (VLAN devices, interface assignments, Kea subnets and reservations, rules of the new
filter page and destination NAT (#295), configuration history) change ``data``, so the read
endpoints show the result: configuration endpoints at once, the interface overview after
``/api/interfaces/assignment/reconfigure`` (it shows the running interfaces). Every write stores
a revision of the configuration history; a revision downloads as a ``config.xml`` serialising
the configuration part of ``data``, and ``revert_backup`` puts it back.
Write failure switches: ``invalid`` (path or path prefix -> validation messages, answered as
``{"result": "failed", "validations": {...}}``) and ``fail`` (also by prefix); the simulated
firewall validates fields itself, too (descriptions, tags, networks, pools, MACs).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import copy
import hashlib
import ipaddress
import re
import secrets
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from signalbox.sim.opnsense_users import Users

KEY = "sim-key"
#: Unbound grids that answer paged (#386).
UNBOUND_GRIDS = (
    "/api/unbound/settings/search_host_override",
    "/api/unbound/settings/search_host_alias",
    "/api/unbound/settings/search_domain_override",
)
SECRET = "sim-secret"
#: shared secret of the simulated RADIUS server: tests assert that it is never read (#162)
RADIUS_SECRET = "sim-radius-secret-do-not-leak"
#: shared secrets of the simulated FreeRADIUS NAS clients (os-freeradius, #519): never read either
FREERADIUS_SECRET = "sim-freeradius-client-secret-do-not-leak"
USERS = "/api/auth/user/"
TRACEROUTE = "/api/diagnostics/traceroute/set"
TRACE_PRIVILEGE = "page-diagnostics-traceroute"
#: *System: Access: Users*: the user manager's API (#349).
ACCOUNTS_PRIVILEGE = "page-system-usermanager"


#: ``lldpcli show neighbors`` of lldpd 1.0.x as os-lldpd passes it on (documentation addresses,
#: locally administered MACs); the last block is on an interface the adapter does not know.
LLDPD_NEIGHBORS = """\
-------------------------------------------------------------------------------
LLDP neighbors:
-------------------------------------------------------------------------------
Interface:    igb0, via: LLDP, RID: 1, Time: 0 day, 03:12:44
  Chassis:
    ChassisID:    mac 02:00:00:00:10:01
    SysName:      switch1
    SysDescr:     Simulated managed switch
    MgmtIP:       192.0.2.2
    Capability:   Bridge, on
    Capability:   Router, off
  Port:
    PortID:       ifname gi1
    PortDescr:    uplink to firewall
    TTL:          120
    VLAN:         1, pvid: yes
    VLAN:         20
    MFS:          1522
-------------------------------------------------------------------------------
Interface:    igb2, via: CDPv2, RID: 2, Time: 1 day, 00:00:05
  Chassis:
    ChassisID:    local sim-ap-1
    SysName:      ap1
  Port:
    PortID:       ifname eth0
    VLAN:         30, pvid: yes
-------------------------------------------------------------------------------
Interface:    tun9, via: LLDP, RID: 3, Time: 0 day, 00:00:01
  Chassis:
    ChassisID:    mac 02:00:00:00:10:09
-------------------------------------------------------------------------------
"""


def _wg_key(name: str) -> str:
    """A WireGuard public key of the sample: base64 of SHA-256 of a name (valid, nobody's real
    key; computed so that no key-shaped literal is in the source)."""
    return base64.b64encode(hashlib.sha256(name.encode()).digest()).decode()


WG_KEY = _wg_key("sim-opnsense-wg0")
WG_SITE_B = _wg_key("sim-site-b")
WG_PHONE = _wg_key("sim-phone")
WG_SHOW = "/api/wireguard/service/show"
#: IPsec and OpenVPN (#153); the pre-shared key is in the simulator's answers so that tests can
#: assert it never reaches the model.
IPSEC_PSK = "sim-ipsec-psk-do-not-leak"
IPSEC_PSKS = "/api/ipsec/pre_shared_keys/search_item"
IPSEC_CONNECTION = "7f1c2a10-0000-4000-8000-0000000000a1"
IPSEC_CHILD = "7f1c2a10-0000-4000-8000-0000000000b1"
OVPN_SERVER = "9d3e5b20-0000-4000-8000-0000000000c1"
OVPN_CLIENT = "5a1b7c40-0000-4000-8000-0000000000c2"


def _opt(selected: dict[str, tuple[str, bool]]) -> dict[str, dict[str, Any]]:
    """An OPNsense option field: ``{key: {"value": label, "selected": 0|1}}``."""
    return {k: {"value": v, "selected": int(on)} for k, (v, on) in selected.items()}


#: ``supported_media`` of a gigabit copper port (FreeBSD ifmedia words).
GIGABIT = [
    "autoselect",
    "1000baseT",
    "1000baseT <full-duplex>",
    "100baseTX <full-duplex>",
    "100baseTX",
    "10baseT/UTP <full-duplex>",
    "10baseT/UTP",
]


def _iface(device: str, ident: str, descr: str, **kw: Any) -> dict[str, Any]:
    return {
        "device": device,
        "identifier": ident,
        "description": descr,
        "enabled": True,
        "status": "up",
        "macaddr": kw.pop("mac", "02:00:00:00:01:00"),
        "mtu": kw.pop("mtu", "1500"),
        "media": kw.pop("media", ""),
        "is_physical": kw.pop("physical", False),
        "vlan_tag": kw.pop("vlan", None),
        "ipv4": [{"ipaddr": a} for a in kw.pop("v4", [])],
        "ipv6": [{"ipaddr": a, "link-local": a.startswith("fe80")} for a in kw.pop("v6", [])],
        **kw,
    }


def _rows_of(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {"total": len(rows), "rowCount": len(rows), "current": 1, "rows": rows}


def _fw_rule(
    uuid: str, description: str, interface: str, action: str = "pass", **kw: Any
) -> dict[str, Any]:
    """A row of ``filter/search_rule``: a rule of the MVC model (interface identifiers,
    ``quick``) or, with ``legacy``, one of the legacy pages or an automatic one (the interface
    is the description, as the controller translates it)."""
    return {
        "uuid": uuid,
        "enabled": "1",
        "action": action,
        "quick": "1",
        "interface": interface,
        "interfacenot": "0",
        "direction": "in",
        "ipprotocol": "inet",
        "protocol": "any",
        "source_net": "any",
        "source_not": "0",
        "source_port": "",
        "destination_net": "any",
        "destination_not": "0",
        "destination_port": "",
        "description": description,
        **kw,
    }


def firewall_data() -> dict[str, Any]:
    """The packet filter of the sample firewall (#135), as OPNsense 26.7 answers: rules of all
    three kinds in evaluation order, aliases, an interface group, a port forward, outbound NAT
    and a one-to-one mapping (documentation addresses)."""
    legacy: dict[str, Any] = {"legacy": True, "%protocol": "ANY"}
    rules = [
        _fw_rule(
            "deny-all",
            "Default deny / state violation rule",
            "",
            "block",
            quick="0",
            ipprotocol="",
            sort_order="000000.0000001",
            is_automatic=True,
            **legacy,
        ),
        _fw_rule(
            "automatic_anti_lockout",
            "Anti-Lockout Rule",
            "LAN",
            destination_net="(self)",
            destination_port="22 80 443",
            protocol="tcp",
            is_automatic=True,
            sort_order="000000.1000001",
            **legacy,
        ),
        _fw_rule(
            "sshlockout",
            "sshlockout",
            "",
            "block",
            source_net="sshlockout",
            destination_net="(self)",
            destination_port="22",
            sort_order="000000.1000002",
            is_automatic=True,
            **legacy,
        ),
        _fw_rule(
            "virusprot",
            "virusprot overload table",
            "",
            "block",
            source_net="virusprot",
            sort_order="000000.1000003",
            is_automatic=True,
            **legacy,
        ),
        _fw_rule(
            "port0",
            "block all targeting port 0",
            "",
            "block",
            protocol="tcp/udp",
            destination_port="0",
            sort_order="000000.1000004",
            is_automatic=True,
            **legacy,
        ),
        _fw_rule(
            "iot-dns",
            "IoT: DNS to the firewall",
            "opt1",
            protocol="tcp/udp",
            destination_net="(self)",
            destination_port="53",
            sort_order="300000.0000001",
            sequence="1",
        ),
        _fw_rule(
            "iot-block",
            "IoT: nothing to the LAN",
            "opt1",
            "block",
            destination_net="lan",
            sort_order="300000.0000002",
            sequence="2",
        ),
        _fw_rule(
            "iot-any",
            "IoT: the internet",
            "opt1",
            source_net="opt1",
            destination_net="(self)",
            destination_not="1",
            sort_order="300000.0000003",
            sequence="3",
        ),
        _fw_rule(
            "guest-blocklist",
            "Guest: block list",
            "opt2",
            "reject",
            destination_net="blocklist",
            sort_order="300000.0000004",
            sequence="4",
        ),
        _fw_rule(
            "float-ssh",
            "Floating: SSH from the NAS",
            "",
            protocol="tcp",
            quick="0",
            source_net="nas",
            destination_port="22",
            sort_order="300000.0000005",
            sequence="5",
        ),
        _fw_rule(
            "lan-any",
            "Default allow LAN to any rule",
            "LAN",
            source_net="lan",
            sort_order="000001.1000002",
            **legacy,
        ),
        _fw_rule(
            "lan-any-v6",
            "Default allow LAN IPv6 to any rule",
            "LAN",
            ipprotocol="inet6",
            source_net="lan",
            sort_order="000001.1000003",
            **legacy,
        ),
    ]
    return {
        "/api/firewall/filter/search_rule": _rows_of(rules),
        # os-lldpd (#470): configd passes `lldpcli show neighbors` through as text
        "/api/lldpd/service/neighbor": {"response": LLDPD_NEIGHBORS},
        # os-ddclient (#154): the rows also hold the account, which the adapter never reads
        "/api/dyndns/accounts/search_item": _rows_of(
            [
                {
                    "uuid": "d1",
                    "enabled": "1",
                    "service": "dyndns2",
                    "protocol": "dyndns2",
                    "hostnames": "fw.example.dyndns.invalid",
                    "interface": "wan",
                    "username": "sim-user",
                    "password": "sim-secret-token",
                    "description": "home",
                }
            ]
        ),
        # captive portal (#460): one zone on the guest network, accepting the terms only
        "/api/captiveportal/settings/search_zones": _rows_of(
            [
                {
                    "uuid": "c1",
                    "zoneid": "0",
                    "enabled": "1",
                    "description": "Guest portal",
                    "interfaces": "opt2",
                    "authservers": "",
                    "hardtimeout": "480",
                    "idletimeout": "0",
                }
            ]
        ),
        "/api/captiveportal/voucher/list_providers": ["Guest vouchers"],
        # mDNS repeater plugin (#161, guess: shape): LAN and IoT
        "/api/mdnsrepeater/settings/get": {
            "mdnsrepeater": {
                "enabled": "1",
                "interfaces": _opt({"lan": ("LAN", True), "opt1": ("IoT", True)}),
            }
        },
        # UDP broadcast relay plugin: SSDP between LAN and IoT (guess: fields)
        "/api/udpbroadcastrelay/settings/search_relay": _rows_of(
            [
                {
                    "uuid": "r1",
                    "enabled": "1",
                    "listenport": "1900",
                    "interfaces": "lan,opt1",
                    "description": "SSDP",
                }
            ]
        ),
        # os-upnp plugin (#176, guess: shape): UPnP and NAT-PMP on LAN, secure mode on
        "/api/miniupnpd/settings/get": {
            "miniupnpd": {
                "general": {
                    "enabled": "1",
                    "enable_upnp": "1",
                    "enable_natpmp": "1",
                    "iface_array": _opt({"lan": ("LAN", True), "opt1": ("IoT", False)}),
                    "secure_mode": "1",
                    "permuser1": "allow 1024-65535 192.0.2.0/24 1024-65535",
                    "permuser2": "deny 0-65535 0.0.0.0/0 0-65535",
                    "permuser3": "",
                    "permuser4": "",
                }
            }
        },
        "/api/miniupnpd/service/status": {"status": "running"},
        # RADIUS server of the user manager (guess: endpoint and fields); the secret is never read
        "/api/auth/server/search": _rows_of(
            [
                {
                    "uuid": "s1",
                    "name": "Office RADIUS",
                    "type": "radius",
                    "host": "192.0.2.53",
                    "radius_auth_port": "1812",
                    "radius_acct_port": "1813",
                    "radius_secret": RADIUS_SECRET,
                },
                {"uuid": "s2", "name": "Directory", "type": "ldap", "host": "192.0.2.54"},
            ]
        ),
        # os-freeradius (#519; guess: endpoints and fields): settings, status, NAS clients
        "/api/freeradius/general/get": {"freeradius": {"general": {"enabled": "1", "vlan": "0"}}},
        "/api/freeradius/service/status": {"status": "running"},
        "/api/freeradius/client/search_client": _rows_of(
            [
                {
                    "uuid": "c1",
                    "enabled": "1",
                    "name": "Office access point",
                    "ip": "192.0.2.20",
                    "secret": FREERADIUS_SECRET,
                    "description": "do-not-leak",
                },
                {
                    "uuid": "c2",
                    "enabled": "1",
                    "name": "Desk switch",
                    "ip": "192.0.2.21",
                    "secret": FREERADIUS_SECRET,
                },
            ]
        ),
        "/api/firewall/alias/search_item": _rows_of(
            [
                {
                    "uuid": "a1",
                    "enabled": "1",
                    "name": "nas",
                    "type": "host",
                    "content": "192.0.2.10",
                },
                {
                    "uuid": "a2",
                    "enabled": "1",
                    "name": "blocklist",
                    "type": "urltable",
                    "content": "",
                },
                {
                    "uuid": "a3",
                    "enabled": "1",
                    "name": "mgmt_ports",
                    "type": "port",
                    "content": "22,8443",
                },
            ]
        ),
        "/api/firewall/group/search_item": _rows_of(
            [{"uuid": "g1", "ifname": "internal", "members": "lan,opt1", "descr": "Internal"}]
        ),
        "/api/firewall/d_nat/search_rule": _rows_of(
            [
                {
                    "uuid": "d1",
                    "disabled": "0",
                    "nordr": "0",
                    "interface": "wan",
                    "ipprotocol": "inet",
                    "protocol": "tcp",
                    "source.network": "any",
                    "source.port": "",
                    "source.not": "0",
                    "destination.network": "wanip",
                    "destination.port": "8443",
                    "destination.not": "0",
                    "target": "nas",
                    "local-port": "443",
                    "pass": "pass",
                    "natreflection": "",
                    "descr": "NAS web interface",
                    "sort_order": "400000.0000001",
                },
                {
                    "uuid": "automatic_ftp_1",
                    "interface": "lan",
                    "protocol": "tcp",
                    "destination.port": "21",
                    "target": "127.0.0.1",
                    "is_automatic": True,
                },
            ]
        ),
        "/api/firewall/source_nat/search_rule": _rows_of(
            [
                {
                    "uuid": "automatic_lan",
                    "enabled": "1",
                    "interface": "wan",
                    "ipprotocol": "inet",
                    "protocol": "any",
                    "source_net": "192.0.2.0/24,198.51.100.0/24",
                    "target": "",
                    "description": "Auto created rule",
                    "is_automatic": True,
                }
            ]
        ),
        "/api/firewall/one_to_one/search_rule": _rows_of(
            [
                {
                    "uuid": "o1",
                    "enabled": "1",
                    "interface": "wan",
                    "type": "binat",
                    "source_net": "198.51.100.50",
                    "destination_net": "any",
                    "external": "100.64.23.46",
                    "description": "Lab host",
                }
            ]
        ),
    }


def sample_data() -> dict[str, Any]:
    """Answers by endpoint path (a fresh copy every call)."""
    lan_ifaces = {"lan": ("LAN", True), "opt1": ("IoT", True), "opt2": ("Guest", False)}
    data: dict[str, Any] = {
        "/api/core/firmware/status": {
            "status": "update",
            "status_msg": "There are 3 updates available.",
            "needs_reboot": "0",
            "product": {
                "product_name": "OPNsense",
                "product_id": "opnsense",
                "product_version": "26.7.8_1",
                "product_latest": "26.7.9",
                "product_arch": "amd64",
            },
        },
        "/api/interfaces/overview/interfaces_info": {
            "total": 6,
            "rowCount": 6,
            "current": 1,
            "rows": [
                _iface(
                    "igb0",
                    "lan",
                    "LAN",
                    media="1000baseT <full-duplex>",
                    media_raw="Ethernet autoselect (1000baseT <full-duplex>)",
                    supported_media=GIGABIT,
                    physical=True,
                    v4=["192.0.2.1/24"],
                    v6=["2001:db8:1::1/64", "fe80::1/64"],
                ),
                _iface(
                    "igb1",
                    "wan",
                    "WAN",
                    mac="02:00:00:00:02:00",
                    media="2500Base-T <full-duplex>",
                    media_raw="Ethernet autoselect (2500Base-T <full-duplex>)",
                    supported_media=[*GIGABIT, "2500Base-T", "2500Base-T <full-duplex>"],
                    physical=True,
                    v4=["100.64.23.45/22"],
                    v6=["2001:db8:ffff::2/64", "fe80::2/64"],
                    link_type="dhcp",
                    link_typev6="dhcp6",
                    gateways=["100.64.20.1", "fe80::1"],
                    **{
                        "ifctl.nameserver": ["100.64.0.53", "2001:db8:ffff::53\n2001:db8:ffff::54"],
                        "ifctl.router": ["100.64.20.1", "fe80::1"],
                        "ifctl.prefix": ["2001:db8:1::/56"],
                    },
                ),
                _iface("vlan01", "opt1", "IoT", vlan=20, v4=["198.51.100.1/24"]),
                _iface("vlan02", "opt2", "Guest", vlan=30, v4=["203.0.113.1/24"]),
                _iface(
                    "igb2",
                    "",
                    "",
                    mac="02:00:00:00:03:00",
                    status="no carrier",
                    media="autoselect",
                    media_raw="Ethernet autoselect",
                    supported_media=["autoselect", "10Gbase-SR", "10Gbase-Twinax", "1000baseSX"],
                    mtu="9000",
                    physical=True,
                ),
                _iface("lo0", "lo0", "Loopback", mac="", v4=["127.0.0.1/8"], v6=["::1/128"]),
                _iface(
                    "wg0", "", "", mac="", mtu="1420", v6=["2001:db8:ff::1/128"]
                ),  # as ifconfig shows it
            ],
        },
        "/api/interfaces/vlan_settings/search_item": {
            "total": 3,
            "rowCount": 3,
            "current": 1,
            "rows": [
                {"uuid": "v-20", "vlanif": "vlan01", "if": "igb0", "tag": "20", "descr": "IoT"},
                {"uuid": "v-30", "vlanif": "vlan02", "if": "igb0", "tag": "30", "descr": "Guest"},
                {"uuid": "v-40", "vlanif": "vlan03", "if": "igb0", "tag": "40", "descr": "Lab"},
            ],
        },
        "/api/kea/dhcpv4/get": {
            "dhcpv4": {
                "general": {
                    "enabled": "1",
                    "interfaces": _opt(lan_ifaces),
                    "valid_lifetime": "4000",
                },
                "subnets": {
                    "subnet4": {
                        "s-lan": {
                            "subnet": "192.0.2.0/24",
                            "pools": "192.0.2.100-192.0.2.199",
                            "option_data_autocollect": "1",
                            "option_data": {"routers": "", "domain_name_servers": ""},
                            "description": "LAN",
                        },
                        "s-iot": {
                            "subnet": "198.51.100.0/24",
                            "pools": "198.51.100.128/26\n198.51.100.200-198.51.100.210",
                            "option_data_autocollect": "0",
                            "option_data": {
                                "routers": "198.51.100.1",
                                "domain_name_servers": "198.51.100.1,192.0.2.1",
                                "domain_name": "iot.example",
                                "ntp_servers": "198.51.100.1",
                                "domain_search": "iot.example,example.net",
                                "static_routes": "203.0.113.0/24 - 198.51.100.254",
                                "tftp_server_name": "tftp.iot.example",
                                "boot_file_name": "pxelinux.0",
                            },
                            "next_server": "198.51.100.5",
                            "description": "IoT",
                        },
                    }
                },
                "reservations": {
                    "reservation": {
                        "r-1": {
                            "subnet": _opt({"s-lan": ("192.0.2.0/24", True)}),
                            "ip_address": "192.0.2.10",
                            "hw_address": "00:00:5e:00:53:10",
                            "hostname": "printer",
                        },
                        "r-2": {
                            "subnet": _opt({"s-iot": ("198.51.100.0/24", True)}),
                            "ip_address": "198.51.100.20",
                            "hw_address": "00:00:5e:00:53:20",
                            "hostname": "sensor",
                        },
                    }
                },
            }
        },
        "/api/kea/leases4/search": {
            "total": 3,
            "rows": [
                {
                    "address": "192.0.2.100",
                    "hwaddr": "02:00:00:00:00:21",
                    "client_id": "01:02:00:00:00:00:21",
                    "hostname": "laptop",
                    "expire": 1795000000,
                    "valid_lifetime": 4000,
                    "state": 0,
                    "if_name": "lan",
                    "if_descr": "LAN",
                },
                {
                    "address": "192.0.2.101",
                    "hwaddr": "02:00:00:00:00:22",
                    "hostname": "phone",
                    "expire": 1794990000,
                    "valid_lifetime": 4000,
                    "state": 2,
                    "if_name": "lan",
                },
                {
                    "address": "198.51.100.20",
                    "hwaddr": "00:00:5e:00:53:20",
                    "hostname": "sensor",
                    "expire": 1795000000,
                    "valid_lifetime": 4000,
                    "state": 0,
                    "if_name": "opt1",
                },
            ],
        },
        "/api/dhcrelay/settings/search_relay": {
            "total": 1,
            "rows": [{"uuid": "rl-1", "enabled": "1", "interface": "opt2", "destination": "d-1"}],
        },
        "/api/dhcrelay/settings/search_dest": {
            "total": 1,
            "rows": [{"uuid": "d-1", "name": "core", "server": "192.0.2.53"}],
        },
        "/api/dhcpv4/service/status": {"status": "running"},
        "/api/dhcpv4/leases/search_lease": {
            "total": 2,
            "interfaces": {"opt2": "Guest"},
            "rows": [
                {
                    "address": "203.0.113.150",
                    "mac": "02:00:00:00:00:31",
                    "hostname": "guest-phone",
                    "if": "opt2",
                    "if_descr": "Guest",
                    "type": "dynamic",
                    "status": "online",
                    "starts": "2026/11/22 10:00:00",
                    "ends": "2026/11/22 22:00:00",
                    "state": "active",
                },
                {
                    "address": "203.0.113.10",
                    "mac": "00:00:5e:00:53:30",
                    "hostname": "kiosk",
                    "if": "opt2",
                    "if_descr": "Guest",
                    "type": "static",
                    "status": "offline",
                    "state": "",
                },
            ],
        },
        "/api/unbound/settings/get": {
            "unbound": {
                "general": {
                    "enabled": "1",
                    "port": "53",
                    "dnssec": "1",
                    "regdhcpdomain": "lan.example",
                    "active_interface": _opt(
                        {"lan": ("LAN", True), "opt1": ("IoT", True), "opt2": ("Guest", False)}
                    ),
                },
                "advanced": {
                    "msgcachesize": "8",
                    "privateaddress": "10.0.0.0/8,172.16.0.0/12",
                    "privatedomain": "corp.example",
                },
                "dnsbl": {
                    "enabled": "1",
                    "type": _opt({"ag": ("AdGuard List", True), "yy": ("Yoyo List", False)}),
                    "lists": "https://lists.example.net/hosts?token=redacted",
                },
                "dots": {
                    "dot": {
                        "d-1": {
                            "enabled": "1",
                            "type": "forward",
                            "domain": "",
                            "server": "192.0.2.53",
                            "port": "53",
                        },
                        "d-2": {
                            "enabled": "1",
                            "type": "dot",
                            "domain": "",
                            "server": "2001:db8:53::53",
                            "port": "853",
                            "verify": "dns.example.net",
                        },
                        "d-3": {
                            "enabled": "1",
                            "type": "forward",
                            "domain": "corp.example",
                            "server": "198.51.100.53",
                        },
                        "d-4": {"enabled": "0", "type": "forward", "server": "192.0.2.54"},
                    }
                },
            }
        },
        # dnsmasq does DHCP only (port 0), as on a fresh OPNsense 25.7
        "/api/dnsmasq/settings/get": {"dnsmasq": {"enable": "1", "port": "0", "hosts": {}}},
        "/api/unbound/settings/search_host_override": {
            "total": 4,
            "rows": [
                {
                    "uuid": "h-1",
                    "enabled": "1",
                    "hostname": "nas",
                    "domain": "home.example",
                    "rr": "A",
                    "server": "192.0.2.10",
                },
                {
                    "uuid": "h-2",
                    "enabled": "1",
                    "hostname": "nas",
                    "domain": "home.example",
                    "rr": "AAAA",
                    "server": "2001:db8:1::10",
                },
                {
                    "uuid": "h-3",
                    "enabled": "0",
                    "hostname": "old",
                    "domain": "home.example",
                    "rr": "A",
                    "server": "192.0.2.11",
                },
                {
                    "uuid": "h-4",
                    "enabled": "1",
                    "hostname": "",
                    "domain": "home.example",
                    "rr": "MX",
                    "mx": "mail.home.example",
                    "server": "",
                },
            ],
        },
        # an alias of the first host override (``host`` is that override's uuid); the shape
        # is a guess from the Unbound model (#386, #21)
        "/api/unbound/settings/search_host_alias": {
            "total": 1,
            "rows": [
                {
                    "uuid": "a-1",
                    "enabled": "1",
                    "host": "h-1",
                    "hostname": "storage",
                    "domain": "home.example",
                    "description": "",
                }
            ],
        },
        # netstat -i style rows, keyed "<name> / <MAC>" or "<name> / <network>" (fixed values)
        "/api/diagnostics/interface/get_interface_statistics": {
            "statistics": {
                "igb0 / 02:00:00:00:01:00": {
                    "name": "igb0",
                    "flags": "0x8843",
                    "mtu": "1500",
                    "network": "<Link#1>",
                    "address": "02:00:00:00:01:00",
                    "received-packets": "5120344",
                    "received-errors": "2",
                    "dropped-packets": "0",
                    "received-bytes": "3841230112",
                    "sent-packets": "4311870",
                    "send-errors": "0",
                    "sent-bytes": "1893340871",
                    "collisions": "0",
                },
                "igb0 / 192.0.2.0/24": {
                    "name": "igb0",
                    "network": "192.0.2.0/24",
                    "address": "192.0.2.1",
                    "received-packets": "1",
                },
            }
        },
        "/api/diagnostics/interface/get_arp": [
            {
                "mac": "00:00:5e:00:53:10",
                "ip": "192.0.2.10",
                "intf": "igb0",
                "expired": False,
                "expires": 1100,
                "permanent": False,
                "type": "ethernet",
                "manufacturer": "",
                "hostname": "printer.home.example",
                "intf_description": "LAN",
            },
            {
                "mac": "02:00:00:00:00:21",
                "ip": "192.0.2.100",
                "intf": "igb0",
                "permanent": False,
                "hostname": "",
            },
            {"mac": "00:00:5e:00:53:20", "ip": "198.51.100.20", "intf": "vlan01", "hostname": ""},
            {"mac": "02:00:00:00:01:00", "ip": "192.0.2.1", "intf": "igb0", "permanent": True},
            {"mac": "(incomplete)", "ip": "192.0.2.99", "intf": "igb0"},
        ],
        "/api/diagnostics/interface/get_ndp": [
            {"mac": "00:00:5e:00:53:10", "ip": "2001:db8:1::10", "intf": "igb0"},
            {"mac": "00:00:5e:00:53:10", "ip": "fe80::10%igb0", "intf": "igb0"},
        ],
        # the dashboard widgets (Lobby: Dashboard); "datetime" is set on every answer
        SYSTEM_TIME: {
            "uptime": "3 days, 04:05:06",
            "datetime": "",
            "boottime": "Thu Nov 19 13:06:54 CET 2026",
            "config": "Thu Nov 19 13:10:02 CET 2026",
            "loadavg": "0.13, 0.07, 0.04",
        },
        "/api/diagnostics/system/system_information": {
            "name": "fw.example.net",
            "versions": ["OPNsense 26.7.8_1-amd64", "FreeBSD 14.3-RELEASE-p4"],
        },
        "/api/diagnostics/system/system_resources": {
            "memory": {
                "total": "4277690368",
                "total_frmt": "4079",
                "used": 1015021568.0,
                "used_frmt": "968",
                "arc": "209715200",
                "arc_frmt": "200",
                "arc_txt": "ARC size 200 MB",
            }
        },
        "/api/diagnostics/system/system_disk": {
            "devices": [
                {
                    "device": "zroot/ROOT/default",
                    "type": "zfs",
                    "blocks": "26G",
                    "total": "26G",
                    "total_bytes": 27917287424,
                    "used": "1.8G",
                    "used_bytes": 1932735283,
                    "available": "24G",
                    "available_bytes": 25984552141,
                    "used_pct": 7,
                    "mountpoint": "/",
                },
                {
                    "device": "zroot/var/log",
                    "type": "zfs",
                    "blocks": "24G",
                    "total": "24G",
                    "total_bytes": 26038288384,
                    "used": "51M",
                    "used_bytes": 53736243,
                    "available": "24G",
                    "available_bytes": 25984552141,
                    "used_pct": 0,
                    "mountpoint": "/var/log",
                },
                {
                    "device": "tmpfs",
                    "type": "tmpfs",
                    "blocks": "2.0G",
                    "total": "2.0G",
                    "total_bytes": 2138845184,
                    "used": "260K",
                    "used_bytes": 266240,
                    "available": "2.0G",
                    "available_bytes": 2138578944,
                    "used_pct": 0,
                    "mountpoint": "/tmp",
                },
                {
                    "device": "/dev/gpt/efiboot0",
                    "type": "msdosfs",
                    "blocks": "260M",
                    "total": "260M",
                    "total_bytes": 272629760,
                    "used": "1.3M",
                    "used_bytes": 1363148,
                    "available": "259M",
                    "available_bytes": 271266612,
                    "used_pct": 1,
                    "mountpoint": "/boot/efi",
                },
            ]
        },
        "/api/diagnostics/system/system_temperature": [
            {
                "device": "dev.cpu.0.temperature",
                "device_seq": 0,
                "temperature": "47.0",
                "type_translated": "CPU",
                "type": "cpu",
            },
            {
                "device": "dev.cpu.1.temperature",
                "device_seq": 1,
                "temperature": "45.0",
                "type_translated": "CPU",
                "type": "cpu",
            },
        ],
        "/api/diagnostics/cpu_usage/get_cpu_type": ["AMD GX-412TC SOC (4 cores, 4 threads)"],
        # wg_show.py: ``wg show all dump`` without private and pre-shared keys, plus the names;
        # latest-handshake is set when answered (OpnsenseSimulator.wg_handshake_ago)
        WG_SHOW: {
            "total": 3,
            "rowCount": 3,
            "current": 1,
            "rows": [
                {
                    "if": "wg0",
                    "type": "interface",
                    "public-key": WG_KEY,
                    "listen-port": "51820",
                    "fwmark": "off",
                    "endpoint": "51820",
                    "status": "up",
                    "name": "s2s",
                    "latest-handshake-age": None,
                    "latest-handshake-epoch": None,
                    "peer-status": "offline",
                    "ifname": "s2s",
                },
                {
                    "if": "wg0",
                    "type": "peer",
                    "public-key": WG_SITE_B,
                    "endpoint": "[2001:db8:ffff:20::1]:51820",
                    "allowed-ips": "2001:db8:ff::2/128,2001:db8:20::/64",
                    "latest-handshake": 0,
                    "transfer-rx": 1834567,
                    "transfer-tx": 2934871,
                    "persistent-keepalive": "25",
                    "name": "site-b",
                    "peer-status": "online",
                    "ifname": "s2s",
                },
                {
                    "if": "wg0",
                    "type": "peer",
                    "public-key": WG_PHONE,
                    "endpoint": "(none)",
                    "allowed-ips": "2001:db8:ff::3/128",
                    "latest-handshake": 0,
                    "transfer-rx": 0,
                    "transfer-tx": 0,
                    "persistent-keepalive": "off",
                    "name": "phone",
                    "peer-status": "offline",
                    "ifname": "s2s",
                },
            ],
        },
        # Remote syslog (#180): one destination for the collector in the LAN (grid rows; option
        # fields as their keys, as the integration image answers them: *guess* until CI says)
        "/api/syslog/settings/search_destinations": {
            "total": 1,
            "rowCount": 1,
            "current": 1,
            "rows": [
                {
                    "uuid": "5a3c2a84-0000-4000-8000-000000000180",
                    "enabled": "1",
                    "transport": "udp4",
                    "program": "",
                    "level": "info,notice,warn,err,crit,alert,emerg",
                    "facility": "",
                    "hostname": "192.0.2.5",
                    "certificate": "",
                    "port": "514",
                    "rfc5424": "0",
                    "description": "collector",
                }
            ],
        },
        # NetFlow export (#180): configured to the collector but on no interface (off)
        "/api/diagnostics/netflow/getconfig": {
            "netflow": {
                "capture": {
                    "interfaces": {"lan": {"value": "LAN", "selected": 0}},
                    "egress_only": {"lan": {"value": "LAN", "selected": 0}},
                    "version": {
                        "v5": {"value": "v5", "selected": 0},
                        "v9": {"value": "v9", "selected": 1},
                    },
                    "targets": {"192.0.2.5:2055": {"value": "192.0.2.5:2055", "selected": 1}},
                },
                "collect": {"enable": "0"},
                "activeTimeout": "1800",
                "inactiveTimeout": "15",
            }
        },
        # Certificates and authorities (#330): the search grids, public data only (the
        # answer of ``get/<uuid>``, with the private key, is not simulated: nothing calls it).
        # Fields as the adapter expects them: *guess* until the 26.7 image says otherwise.
        "/api/trust/ca/search": {
            "total": 1,
            "rowCount": 1,
            "current": 1,
            "rows": [
                {
                    "uuid": "7c1d0e22-0000-4000-8000-000000000330",
                    "refid": "6a0b0000330ca",
                    "descr": "Lab CA",
                    "commonname": "lab-ca",
                    "valid_from": "1767225600",
                    "valid_to": "2082758400",
                    "in_use": "1",
                }
            ],
        },
        "/api/trust/cert/search": {
            "total": 2,
            "rowCount": 2,
            "current": 1,
            "rows": [
                {
                    "uuid": "7c1d0e22-0000-4000-8000-000000000331",
                    "refid": "6a0b0000331ce",
                    "descr": "Web GUI",
                    "caref": "6a0b0000330ca",
                    "commonname": "opnsense.lab.example",
                    "valid_from": "1767225600",
                    "valid_to": "1924992000",
                    "san_dns": "opnsense.lab.example",
                    "in_use": "1",
                },
                {
                    "uuid": "7c1d0e22-0000-4000-8000-000000000332",
                    "refid": "6a0b0000332ce",
                    "descr": "VPN server",
                    "caref": "6a0b0000330ca",
                    "commonname": "vpn.lab.example",
                    "valid_from": "1767225600",
                    "valid_to": "1924992000",
                    "in_use": "0",
                },
            ],
        },
        # Static routes and gateways (#149): a lab network 198.18.20.0/24 (benchmarking range)
        # behind a second router on the LAN, and the WAN gateway. Fields as the adapter
        # expects them: *guess* until the 26.7 image says otherwise.
        "/api/routes/routes/searchroute": {
            "total": 2,
            "rowCount": 2,
            "current": 1,
            "rows": [
                {
                    "uuid": "7c1d0e22-0000-4000-8000-000000000149",
                    "disabled": "0",
                    "network": "198.18.20.0/24",
                    "gateway": "LAB_GW",
                    "descr": "Lab behind the second router",
                },
                {
                    "uuid": "7c1d0e22-0000-4000-8000-000000000150",
                    "disabled": "1",
                    "network": "198.18.30.0/24",
                    "gateway": "LAB_GW",
                    "descr": "Old lab",
                },
            ],
        },
        "/api/routes/gateway/status": {
            "items": [
                {
                    "name": "WAN_DHCP",
                    "address": "100.64.20.1",
                    "status": "none",
                    "monitor": "100.64.20.1",
                    "delay": "4.2 ms",
                    "stddev": "0.3 ms",
                    "loss": "0.0 %",
                },
                {"name": "LAB_GW", "address": "192.0.2.254", "status": "online"},
                {
                    "name": "WAN2_LTE",
                    "address": "198.51.100.1",
                    "status": "none",
                    "monitor": "203.0.113.53",
                    "delay": "38.0 ms",
                    "stddev": "4.1 ms",
                    "loss": "0.0 %",
                },
            ],
            "status": "ok",
        },
        # Gateway groups (#150), 26.7 only: the group API lists the tiers with the status row of
        # each gateway in them. Fields as the adapter expects them: *guess* until a 26.7 image
        # says otherwise.
        "/api/routing/group_settings/search": {
            "total": 1,
            "rowCount": 1,
            "current": 1,
            "rows": [
                {
                    "uuid": "7c1d0e22-0000-4000-8000-000000000151",
                    "name": "WAN_FAILOVER",
                    "trigger": "down",
                    "descr": "Cable with a mobile backup",
                    "gateways": {
                        "0": [
                            {
                                "name": "WAN_DHCP",
                                "address": "100.64.20.1",
                                "status": "none",
                                "monitor": "100.64.20.1",
                                "delay": "4.2 ms",
                                "loss": "0.0 %",
                            }
                        ],
                        "1": [
                            {
                                "name": "WAN2_LTE",
                                "address": "198.51.100.1",
                                "status": "none",
                                "monitor": "203.0.113.53",
                                "delay": "38.0 ms",
                                "loss": "0.0 %",
                            }
                        ],
                    },
                }
            ],
        },
        # os-net-snmp (not part of the base system): general settings, v2c community "public"
        "/api/netsnmp/general/get": {
            "general": {
                "enabled": "1",
                "community": "public",
                "syslocation": "",
                "syscontact": "",
                "l3visibility": "0",
                "versionoid": "0",
                "enableagentx": "0",
                "enableobservium": "0",
                "listen": {
                    "192.0.2.1": {"value": "192.0.2.1", "selected": 1},
                    "198.51.100.1": {"value": "198.51.100.1", "selected": 0},
                },
            }
        },
        "/api/ntpd/service/status": {
            "total": 3,
            "rowCount": 3,
            "current": 1,
            "rows": [
                {
                    "status": "*",
                    "server": "203.0.113.123",
                    "refid": ".GPS.",
                    "stratum": "1",
                    "type": "u",
                    "when": "34",
                    "poll": "64",
                    "reach": "377",
                    "delay": "0.512",
                    "offset": "-0.103",
                    "jitter": "0.043",
                },
                {
                    "status": "+",
                    "server": "198.51.100.123",
                    "refid": "203.0.113.123",
                    "stratum": "2",
                    "type": "u",
                    "when": "12",
                    "poll": "64",
                    "reach": "377",
                    "delay": "1.204",
                    "offset": "0.381",
                    "jitter": "0.112",
                },
                {
                    "status": "__pool",
                    "server": "0.opnsense.pool.ntp.org",
                    "refid": ".POOL.",
                    "stratum": "16",
                    "type": "p",
                    "when": "-",
                    "poll": "64",
                    "reach": "0",
                    "delay": "0.000",
                    "offset": "+0.000",
                    "jitter": "0.000",
                },
            ],
        },
        **firewall_data(),
    }
    return copy.deepcopy(data)


#: The simulated releases (#390) and the firmware version each reports.
RELEASES = {"26.7": "26.7.8_1", "25.1": "25.1.12_4", "24.7": "24.7.12_1"}


def older_release(data: dict[str, Any], release: str) -> None:
    """Make ``data`` what OPNsense ``release`` answers, from the public sources of the tags
    24.7.12, 25.1.12 and 25.7.11 (docs/adapters/opnsense.md, "Versions"):

    - all older than 26.7: no destination NAT API (26.1), no gateway group API (26.7), no ntpd
      API (25.7), the disk table of
      ``df -h`` without byte counts, no interface assignment API, ``search_rule`` as
      :meth:`OpnsenseSimulator.old_filter_rows` answers it;
    - 25.1 and 24.7 refuse a snake_case action with 403 (camelCase ACL patterns);
    - 24.7: also no dnsmasq (25.1), no user manager (25.1), no ``interfacenot`` on rules.
    """
    if release not in RELEASES:
        raise ValueError(f"unknown OPNsense release {release!r}: {', '.join(RELEASES)}")
    if release == "26.7":
        return
    product = data["/api/core/firmware/status"]["product"]
    product["product_version"] = RELEASES[release]
    product["product_latest"] = RELEASES[release].split("_")[0]
    for path in (
        "/api/firewall/d_nat/search_rule",
        "/api/ntpd/service/status",
        "/api/routing/group_settings/search",
    ):
        data.pop(path, None)
    for row in data["/api/diagnostics/system/system_disk"]["devices"]:
        for key in ("total", "total_bytes", "used_bytes", "available_bytes"):
            row.pop(key, None)
    if release == "24.7":
        data.pop("/api/dnsmasq/settings/get", None)


# --- writing ---------------------------------------------------------------------------------

SYSTEM_TIME = "/api/diagnostics/system/system_time"
BACKUPS = "/api/core/backup/backups/this"
DOWNLOAD = "/api/core/backup/download/this"
ASSIGN = "/api/interfaces/assignment/"
INTERFACES = "/api/interfaces/overview/interfaces_info"
VLANS = "/api/interfaces/vlan_settings/search_item"
KEA = "/api/kea/dhcpv4/get"
KEA_SUBNETS = "/api/kea/dhcpv4/search_subnet"
KEA_RESERVATIONS = "/api/kea/dhcpv4/search_reservation"
#: The parts of ``data`` that are configuration (saved in config.xml, restored by a revert).
FILTER = "/api/firewall/filter/search_rule"
DNAT = "/api/firewall/d_nat/search_rule"
CONFIG = (INTERFACES, VLANS, KEA, FILTER, DNAT)
_WRITE = re.compile(
    r"^/api/(interfaces/vlan_settings|interfaces/assignment|kea/dhcpv4|kea/service|core/backup"
    r"|firewall/filter|firewall/d_nat)"
    r"/(\w+)(?:/([^/]+))?(?:/([^/]+))?$"
)
_DESCR = re.compile(r"^[a-z_0-9]{0,255}$", re.IGNORECASE)


class Refused(Exception):
    """A write the simulated firewall refuses: becomes ``{"result": "failed", ...}``."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.validations = {field: message}


def to_xml(state: dict[str, Any], time: str, description: str) -> str:
    """config.xml of the simulated firewall: a revision header and the state, typed."""
    root = ET.Element("opnsense")
    rev = ET.SubElement(root, "revision")
    ET.SubElement(rev, "time").text = time
    ET.SubElement(rev, "description").text = description
    ET.SubElement(rev, "username").text = "signalbox-sim"
    _put(ET.SubElement(root, "signalbox_sim"), state)
    return '<?xml version="1.0"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


def _put(el: ET.Element, value: Any) -> None:
    if isinstance(value, dict):
        el.set("t", "dict")
        for k, v in value.items():
            child = ET.SubElement(el, "v", k=str(k))
            _put(child, v)
    elif isinstance(value, list):
        el.set("t", "list")
        for v in value:
            _put(ET.SubElement(el, "v"), v)
    elif value is None:
        el.set("t", "null")
    else:
        el.set("t", type(value).__name__)
        el.text = str(value)


def _get(el: ET.Element) -> Any:
    kind = el.get("t")
    if kind == "dict":
        return {c.get("k", ""): _get(c) for c in el}
    if kind == "list":
        return [_get(c) for c in el]
    text = el.text or ""
    return {
        "null": lambda: None,
        "bool": lambda: text == "True",
        "int": lambda: int(text),
        "float": lambda: float(text),
    }.get(kind or "", lambda: text)()


def from_xml(text: str) -> dict[str, Any]:
    root = ET.fromstring(text)
    body = root.find("signalbox_sim")
    if root.tag != "opnsense" or body is None:
        raise ValueError("not a config.xml of this simulator")
    state: dict[str, Any] = _get(body)
    return state


class _Writes:
    """Write endpoints of :class:`OpnsenseSimulator` (mixed in; works on its ``data``)."""

    data: dict[str, Any]
    history: list[tuple[str, str, str]]
    pending: list[tuple[str, str, dict[str, Any]]]
    leftovers: list[dict[str, Any]]
    assignment_api: str
    locked: set[str]
    posts: list[tuple[str, Any]]
    applied: list[str]

    # configuration history ----------------------------------------------------------------

    def state(self) -> dict[str, Any]:
        return copy.deepcopy({p: self.data[p] for p in CONFIG if p in self.data})

    def save(self, description: str) -> None:
        """Store a revision of the current configuration (as every OPNsense save does)."""
        n = len(self.history)
        time = f"{1700000000 + n}.{n:04d}"
        self.history.append((f"config-{time}.xml", time, to_xml(self.state(), time, description)))

    def _current(self) -> None:
        """Make sure the newest revision is the configuration in use (tests edit ``data``)."""
        if not self.history or from_xml(self.history[-1][2]) != self.state():
            self.save("configuration as found")

    def backups(self) -> dict[str, Any]:
        self._current()
        return {
            "items": [
                {
                    "time": time,
                    "time_iso": "",
                    "description": "",
                    "username": "signalbox-sim",
                    "filesize": len(xml),
                    "id": rid,
                }
                for rid, time, xml in reversed(self.history)
            ]
        }

    def download(self, rid: str | None) -> str | None:
        self._current()
        return next((x for r, _, x in reversed(self.history) if rid in (None, r)), None)

    def revert(self, rid: str) -> dict[str, Any]:
        found = next((x for r, _, x in self.history if r == rid), None)
        if found is None:
            return {"status": "not_found"}
        before = {r["vlanif"]: r for r in self._rows(VLANS)} if VLANS in self.data else {}
        self.data.update(copy.deepcopy(from_xml(found)))
        self.pending.clear()
        if VLANS in self.data and INTERFACES in self.data:
            # as on OPNsense: the revert changes config.xml, the VLAN reconfigure only creates
            # devices; one that is gone from the configuration stays until a reboot
            kept = {r["vlanif"] for r in self._rows(VLANS)}
            rows = self._rows(INTERFACES)
            present = {r.get("device") for r in [*rows, *self.leftovers]}
            for name, vlan in before.items():
                if name not in kept and name not in present:
                    parent = next((r for r in rows if r.get("device") == vlan["if"]), {})
                    self.leftovers.append(
                        {
                            "device": name,
                            "identifier": "",
                            "description": "Unassigned Interface",
                            "is_physical": False,
                            "status": "up",
                            "macaddr": parent.get("macaddr", ""),
                            "ipv4": [],
                            "ipv6": [],
                        }
                    )
        self.save(f"reverted to {rid}")
        return {"status": "reverted"}

    # helpers ------------------------------------------------------------------------------

    def _rows(self, path: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = self.data[path]["rows"]
        return rows

    def _kea(self) -> dict[str, Any]:
        if KEA not in self.data:
            raise KeyError(KEA)
        root: dict[str, Any] = self.data[KEA]["dhcpv4"]
        return root

    def _assigned(self) -> dict[str, dict[str, Any]]:
        return {r["identifier"]: r for r in self._rows(INTERFACES) if r.get("identifier")}

    def _uuid(self, prefix: str) -> str:
        return f"{prefix}-{len(self.history)}-{len(self.posts)}"

    def _sync_listen(self, selected: list[str] | None = None) -> None:
        """Kea's interface option field lists every assigned interface (not the WAN)."""
        general = self._kea()["general"]
        old = general.get("interfaces", {})
        if selected is None:
            selected = [k for k, v in old.items() if v.get("selected")]
        assigned = {
            k: r for k, r in self._assigned().items() if k != "wan" and not k.startswith("lo")
        }
        general["interfaces"] = {
            k: {"value": r.get("description") or k.upper(), "selected": int(k in selected)}
            for k, r in assigned.items()
        }

    # dispatch -----------------------------------------------------------------------------

    def write(self, path: str, body: Any) -> Any:
        match = _WRITE.match(path)
        if match is None or (path.startswith("/api/kea/") and KEA not in self.data):
            return None
        if path.startswith("/api/firewall/d_nat/") and DNAT not in self.data:
            return None
        area, action, arg, arg2 = match.groups()
        body = body if isinstance(body, dict) else {}
        handler = getattr(self, f"_{area.replace('/', '_')}_{action}", None)
        if handler is None:
            return None
        if not action.startswith("search"):
            self.posts.append((path, body))
        try:
            answer: Any = handler(body, arg, arg2)
        except Refused as exc:
            return {"result": "failed", "validations": exc.validations}
        return answer

    # VLAN devices -------------------------------------------------------------------------

    def _vlan_fields(self, item: dict[str, Any], uuid: str | None) -> dict[str, Any]:
        tag = str(item.get("tag", "")).strip()
        if not tag.isdigit() or not 1 <= int(tag) <= 4094:
            raise Refused("vlan.tag", "Value should be between 1 and 4094.")
        parent = str(item.get("if", ""))
        ports = {r["device"] for r in self._rows(INTERFACES) if r.get("is_physical")}
        if parent not in ports:
            raise Refused("vlan.if", "Please select a valid parent interface.")
        others = [r for r in self._rows(VLANS) if r.get("uuid") != uuid]
        if any(r["if"] == parent and str(r["tag"]) == tag for r in others):
            raise Refused("vlan.tag", "Tag for this device must be unique.")
        vlanif = str(item.get("vlanif", "")).strip()
        if not vlanif or any(r["vlanif"] == vlanif for r in others):
            raise Refused("vlan.vlanif", "The device name must be unique.")
        return {"vlanif": vlanif, "if": parent, "tag": tag, "descr": str(item.get("descr", ""))}

    def _vlan_list(self) -> Any:
        """The VLAN grid as OPNsense shows it: an assigned device gets ``[<interface>]``."""
        answer = copy.deepcopy(self.data[VLANS])
        overview = self.data.get(INTERFACES)
        rows = answer.get("rows") if isinstance(answer, dict) else None
        if not isinstance(rows, list) or not isinstance(overview, dict):
            return answer  # test data of the wrong shape: as it is
        names = {
            r.get("device"): r.get("description") or str(r["identifier"]).upper()
            for r in overview.get("rows", [])
            if isinstance(r, dict) and r.get("identifier")
        }
        for row in rows:
            if isinstance(row, dict) and row.get("vlanif") in names:
                row["vlanif"] = f"{row['vlanif']} [{names[row['vlanif']]}]"
        return answer

    def _kea_answer(self, path: str) -> Any:
        """Kea as OPNsense 26.7 answers it: ``get`` has the general settings only, subnets
        and reservations are grids with dotted names for nested fields."""
        data = self.data[KEA]
        root = data.get("dhcpv4") if isinstance(data, dict) else None
        if not isinstance(root, dict):
            return data if path == KEA else {"rows": []}
        if path == KEA:
            hidden = ("subnets", "reservations")
            return {"dhcpv4": {k: v for k, v in root.items() if k not in hidden}}
        part, name = (
            ("subnets", "subnet4") if path == KEA_SUBNETS else ("reservations", "reservation")
        )
        items = root.get(part, {}).get(name, {})
        rows = [{"uuid": k, **_grid_row(v)} for k, v in items.items() if isinstance(v, dict)]
        return {"rows": rows, "rowCount": len(rows), "total": len(rows), "current": 1}

    def _interfaces_vlan_settings_add_item(self, body: dict[str, Any], *_: Any) -> Any:
        uuid = self._uuid("v")
        row = {"uuid": uuid, **self._vlan_fields(body.get("vlan", {}), None)}
        self._rows(VLANS).append(row)
        self.save("VLAN added")
        return {"result": "saved", "uuid": uuid}

    def _interfaces_vlan_settings_del_item(self, _: Any, uuid: str, *__: Any) -> Any:
        row = next((r for r in self._rows(VLANS) if r["uuid"] == uuid), None)
        if row is None:
            return {"result": "not found"}
        if any(r["device"] == row["vlanif"] for r in self._assigned().values()):
            raise Refused("vlan.vlanif", "This VLAN cannot be deleted because it is assigned.")
        self._rows(VLANS).remove(row)
        self.save("VLAN deleted")
        return {"result": "deleted"}

    def _interfaces_vlan_settings_reconfigure(self, *_: Any) -> Any:
        return {"status": "ok"}

    # interface assignments ----------------------------------------------------------------

    def _devices(self) -> dict[str, dict[str, Any]]:
        physical = {r["device"]: r for r in self._rows(INTERFACES) if r.get("is_physical")}
        vlans = {r["vlanif"]: r for r in self._rows(VLANS)}
        return {**physical, **vlans}

    def _iface_fields(self, item: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if "descr" in item:
            if not _DESCR.match(str(item["descr"])):
                raise Refused(
                    "interface.descr",
                    "Only letters, numbers and underscores are allowed in the description.",
                )
            out["description"] = str(item["descr"])
        if "ipaddr" in item:
            try:
                addr = ipaddress.ip_interface(str(item["ipaddr"]))
            except ValueError:
                raise Refused("interface.ipaddr", "Please specify a valid address.") from None
            if addr.version != 4 or "/" not in str(item["ipaddr"]):
                raise Refused("interface.ipaddr", "A valid IPv4 network must be provided.")
            out["ipv4"] = [{"ipaddr": str(addr)}]
        return out

    def _interfaces_assignment_search_item(self, *_: Any) -> Any:
        rows = []
        for k, r in self._assigned().items():
            v4 = next((a["ipaddr"] for a in r.get("ipv4", []) if isinstance(a, dict)), "")
            v6 = [a["ipaddr"] for a in r.get("ipv6", []) if isinstance(a, dict)]
            v6 = [a for a in v6 if not a.lower().startswith("fe80")]
            rows.append(
                {
                    "uuid": k,
                    "identifier": k,
                    "if": r["device"],
                    "descr": r.get("description", ""),
                    "lock": "1" if k in self.locked else "0",
                    "enable": "1",
                    "type4": "staticv4" if v4 else "",
                    "ipaddr": v4,
                    "type6": "staticv6" if v6 else "",
                    "ipaddrv6": v6[0] if v6 else "",
                }
            )
        if self.assignment_api == "26.7":  # before 26.7.6: no address fields
            rows = [{k: r[k] for k in ("uuid", "identifier", "if", "descr", "lock")} for r in rows]
        return {"rows": rows, "total": len(rows), "current": 1, "rowCount": len(rows)}

    def _interfaces_assignment_add_item(self, body: dict[str, Any], *_: Any) -> Any:
        item = body.get("interface", {})
        device = str(item.get("if", ""))
        if device not in self._devices():
            raise Refused("interface.if", "Please select a valid device.")
        taken = {r["device"] for r in self._assigned().values()}
        taken |= {i["if"] for op, _, i in self.pending if op == "add"}
        if device in taken:
            raise Refused("interface.if", "This device is already assigned.")
        fields = self._iface_fields(item)
        used = set(self._assigned()) | {k for _, k, _ in self.pending}
        n = 1
        while f"opt{n}" in used:
            n += 1
        ident = f"opt{n}"
        if str(item.get("lock", "1")) == "1":
            self.locked.add(ident)
        self.pending.append(("add", ident, {"if": device, **fields}))
        return {"result": "saved", "uuid": ident}

    def _interfaces_assignment_set_item(self, body: dict[str, Any], ident: str, *_: Any) -> Any:
        if ident not in self._assigned():
            return {"result": "failed"}
        self.pending.append(("set", ident, self._iface_fields(body.get("interface", {}))))
        return {"result": "saved"}

    def _interfaces_assignment_del_item(self, _: Any, ident: str, *__: Any) -> Any:
        if ident not in self._assigned():
            return {"result": "not found"}
        if ident in self.locked:
            return {
                "errorMessage": "Interface locked, unset lock first before removal",
                "errorTitle": "locked",
            }
        self.pending.append(("delete", ident, {}))
        return {"result": "deleted"}

    def _interfaces_assignment_reconfigure(self, *_: Any) -> Any:
        rows = self._rows(INTERFACES)
        devices = self._devices()
        for op, ident, fields in self.pending:
            row = self._assigned().get(ident)
            if op == "delete" and row is not None:
                rows.remove(row)
            elif op == "set" and row is not None:
                row.update(fields)
            elif op == "add":
                dev = devices[fields["if"]]
                parent = next((r for r in rows if r["device"] == dev.get("if")), dev)
                new = _iface(
                    fields["if"],
                    ident,
                    fields.get("description", ""),
                    mac=parent.get("macaddr", "02:00:00:00:01:00"),
                    vlan=int(dev["tag"]) if "tag" in dev else None,
                )
                new["ipv4"] = fields.get("ipv4", [])
                rows.append(new)
        self.pending.clear()
        if KEA in self.data:
            self._sync_listen()
        self.save("interfaces applied")
        return {"status": "ok"}

    # Kea DHCPv4 ---------------------------------------------------------------------------

    def _kea_dhcpv4_set(self, body: dict[str, Any], *_: Any) -> Any:
        general = body.get("dhcpv4", {}).get("general", {})
        if "interfaces" in general:
            names = [x for x in str(general["interfaces"]).split(",") if x]
            unknown = [x for x in names if x not in self._assigned() or x == "wan"]
            if unknown:
                raise Refused("dhcpv4.general.interfaces", "Option not in list.")
            self._sync_listen(names)
        if "enabled" in general:
            self._kea()["general"]["enabled"] = str(general["enabled"])
        self.save("Kea settings")
        return {"result": "saved"}

    def _subnet_fields(self, item: dict[str, Any], old: dict[str, Any]) -> dict[str, Any]:
        merged = {**old, **{k: v for k, v in item.items() if k != "option_data"}}
        merged["option_data"] = {**old.get("option_data", {}), **item.get("option_data", {})}
        try:
            net = ipaddress.ip_network(str(merged.get("subnet", "")), strict=False)
        except ValueError:
            raise Refused("subnet4.subnet", "Entry is not a valid network.") from None
        for line in str(merged.get("pools", "")).split("\n"):
            if not line.strip():
                continue
            try:
                ends = [ipaddress.ip_address(x.strip()) for x in line.split("-")]
            except ValueError:
                raise Refused("subnet4.pools", "Invalid pool.") from None
            if any(a not in net for a in ends):
                raise Refused("subnet4.pools", "Pool is not inside the subnet.")
        lifetime = str(merged.get("valid_lifetime", ""))
        if lifetime and not lifetime.isdigit():
            raise Refused("subnet4.valid_lifetime", "Please specify a valid number.")
        merged.setdefault("option_data_autocollect", "1")
        merged.setdefault("description", "")
        return merged

    def _kea_dhcpv4_add_subnet(self, body: dict[str, Any], *_: Any) -> Any:
        subnets = self._kea()["subnets"]["subnet4"]
        item = self._subnet_fields(body.get("subnet4", {}), {})
        if any(s["subnet"] == item["subnet"] for s in subnets.values()):
            raise Refused("subnet4.subnet", "Subnets must be unique.")
        uuid = self._uuid("s")
        subnets[uuid] = item
        self.save("Kea subnet added")
        return {"result": "saved", "uuid": uuid}

    def _kea_dhcpv4_set_subnet(self, body: dict[str, Any], uuid: str, *_: Any) -> Any:
        subnets = self._kea()["subnets"]["subnet4"]
        if uuid not in subnets:
            return {"result": "failed"}
        subnets[uuid] = self._subnet_fields(body.get("subnet4", {}), subnets[uuid])
        self.save("Kea subnet changed")
        return {"result": "saved"}

    def _kea_dhcpv4_del_subnet(self, _: Any, uuid: str, *__: Any) -> Any:
        subnets = self._kea()["subnets"]["subnet4"]
        if subnets.pop(uuid, None) is None:
            return {"result": "not found"}
        self.save("Kea subnet deleted")
        return {"result": "deleted"}

    def _reservation_fields(self, item: dict[str, Any], uuid: str | None) -> dict[str, Any]:
        subnets = self._kea()["subnets"]["subnet4"]
        ref = str(item.get("subnet", ""))
        if ref not in subnets:
            raise Refused("reservation.subnet", "Related item not found.")
        net = ipaddress.ip_network(subnets[ref]["subnet"], strict=False)
        try:
            address = ipaddress.ip_address(str(item.get("ip_address", "")))
        except ValueError:
            raise Refused("reservation.ip_address", "Please specify a valid address.") from None
        if address not in net:
            raise Refused("reservation.ip_address", "Address not in subnet.")
        mac = str(item.get("hw_address", "")).lower()
        if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            raise Refused("reservation.hw_address", "Please specify a valid MAC address.")
        others = {k: r for k, r in self._kea()["reservations"]["reservation"].items() if k != uuid}
        if any(r["hw_address"] == mac and ref in r["subnet"] for r in others.values()):
            raise Refused("reservation.hw_address", "Duplicate entry exists.")
        return {
            "subnet": _opt({ref: (subnets[ref]["subnet"], True)}),
            "ip_address": str(address),
            "hw_address": mac,
            "hostname": str(item.get("hostname", "")),
            "description": str(item.get("description", "")),
        }

    def _kea_dhcpv4_add_reservation(self, body: dict[str, Any], *_: Any) -> Any:
        item = self._reservation_fields(body.get("reservation", {}), None)
        uuid = self._uuid("r")
        self._kea()["reservations"]["reservation"][uuid] = item
        self.save("Kea reservation added")
        return {"result": "saved", "uuid": uuid}

    def _kea_dhcpv4_set_reservation(self, body: dict[str, Any], uuid: str, *_: Any) -> Any:
        reservations = self._kea()["reservations"]["reservation"]
        if uuid not in reservations:
            return {"result": "failed"}
        reservations[uuid] = self._reservation_fields(body.get("reservation", {}), uuid)
        self.save("Kea reservation changed")
        return {"result": "saved"}

    def _kea_dhcpv4_del_reservation(self, _: Any, uuid: str, *__: Any) -> Any:
        if self._kea()["reservations"]["reservation"].pop(uuid, None) is None:
            return {"result": "not found"}
        self.save("Kea reservation deleted")
        return {"result": "deleted"}

    def _kea_service_reconfigure(self, *_: Any) -> Any:
        return {"status": "ok"}

    # packet filter and destination NAT (#295) ----------------------------------------------
    #
    # Rows are stored as the search grids answer them (flat; the NAT pages' nested ``source`` and
    # ``destination`` as ``destination.network``). The new rules page and the NAT page have no
    # savepoint or rollback timer on 26.7 (checked against the controllers of 26.7.9), nor has
    # the simulator: ``filter/apply`` answers ``{"status": "OK"}`` and counts in ``applied``.

    def _zone_names(self) -> set[str]:
        groups = self.data.get("/api/firewall/group/search_item", {}).get("rows", [])
        return set(self._assigned()) | {g["ifname"] for g in groups}

    def _net_token(self, field: str, value: str, extra: set[str]) -> None:
        """A network field: ``any``, an address, a network, an interface token or an alias."""
        names = self._zone_names()
        aliases = {
            a["name"] for a in self.data.get("/api/firewall/alias/search_item", {}).get("rows", [])
        }
        for token in [t for t in value.split(",") if t]:
            base = token.removesuffix("ip").removesuffix(":network")
            try:
                ipaddress.ip_network(token, strict=False)
            except ValueError:
                if token not in {"any", "(self)", *aliases, *extra} and base not in names:
                    raise Refused(field, "Please specify a valid network or alias.") from None

    def _ports(self, field: str, value: str, protocol: str) -> None:
        if not value:
            return
        if protocol.lower() not in ("tcp", "udp", "tcp/udp"):
            raise Refused(field, "A port needs the protocol TCP, UDP or TCP/UDP.")
        first, _, last = value.partition("-")
        if not (first.isdigit() and (not last or last.isdigit())):
            raise Refused(
                field, "Please specify a valid port number, well-known name, alias or range."
            )
        if not 1 <= int(first) <= int(last or first) <= 65535:
            raise Refused(
                field, "Please specify a valid port number, well-known name, alias or range."
            )

    def _sequence(self, field: str, value: Any) -> str:
        text = str(value or "").strip()
        if not text.isdigit() or not 1 <= int(text) <= 999999:
            raise Refused(field, "Sequence shall be between 1 and 999999.")
        return text

    def _filter_row(self, body: dict[str, Any], uuid: str, old: dict[str, Any]) -> dict[str, Any]:
        item = {**{k: v for k, v in old.items() if k not in ("uuid", "sort_order")}, **body}
        if item.get("action") not in ("pass", "block", "reject"):
            raise Refused("rule.action", "Please select a valid action.")
        zones = [z for z in str(item.get("interface", "")).split(",") if z]
        for zone in zones:
            if zone not in self._zone_names():
                raise Refused("rule.interface", "Please select a valid interface.")
        if item.get("direction") not in ("in", "out", "any"):
            raise Refused("rule.direction", "Please select a valid direction.")
        if item.get("ipprotocol") not in ("inet", "inet6", "inet46"):
            raise Refused("rule.ipprotocol", "Please select a valid IP protocol.")
        protocol = str(item.get("protocol", ""))
        if protocol not in ("any", "TCP", "UDP", "TCP/UDP", "ICMP", "ipv6-icmp", "ESP", "GRE"):
            raise Refused("rule.protocol", "Please select a valid protocol.")
        for name in ("source_net", "destination_net"):
            self._net_token(f"rule.{name}", str(item.get(name, "")), set())
            for token in str(item.get(name, "")).split(","):
                try:
                    version = ipaddress.ip_network(token, strict=False).version
                except ValueError:
                    continue
                if item["ipprotocol"] != f"inet{'6' if version == 6 else ''}":
                    raise Refused(
                        f"rule.{name}",
                        "Destination address type should match selected TCP/IP protocol version.",
                    )
        self._ports("rule.destination_port", str(item.get("destination_port", "")), protocol)
        item["sequence"] = self._sequence("rule.sequence", item.get("sequence", 1))
        item["uuid"] = uuid
        item["sort_order"] = f"300000.{int(item['sequence']):07d}"
        item.setdefault("%interface", ",".join(zones))
        return item

    def _place(self, rows: list[dict[str, Any]], item: dict[str, Any], prefix: str) -> None:
        """Insert a row among the rows of its own page, in the order of ``sort_order``."""
        mine = [i for i, r in enumerate(rows) if str(r.get("sort_order", "")).startswith(prefix)]
        for i in mine:
            if str(rows[i]["sort_order"]) >= str(item["sort_order"]):
                rows.insert(i, item)
                return
        rows.insert(mine[-1] + 1 if mine else len(rows), item)

    def _firewall_filter_add_rule(self, body: dict[str, Any], *_: Any) -> Any:
        uuid = self._uuid("fr")
        defaults = {"enabled": "1", "quick": "1", "direction": "in", "interfacenot": "0"}
        item = self._filter_row({**defaults, **body.get("rule", {})}, uuid, {})
        self._place(self._rows(FILTER), item, "300000.")
        self.save("filter rule added")
        return {"result": "saved", "uuid": uuid}

    def _own_row(self, path: str, uuid: str) -> dict[str, Any] | None:
        row = next((r for r in self._rows(path) if r.get("uuid") == uuid), None)
        return None if row is None or row.get("legacy") or row.get("is_automatic") else row

    def _firewall_filter_set_rule(self, body: dict[str, Any], uuid: str, *_: Any) -> Any:
        row = self._own_row(FILTER, uuid)
        if row is None:
            return {"result": "failed"}
        new = self._filter_row(body.get("rule", {}), uuid, row)
        self._rows(FILTER).remove(row)
        self._place(self._rows(FILTER), new, "300000.")
        self.save("filter rule changed")
        return {"result": "saved"}

    def _firewall_filter_del_rule(self, _: Any, uuid: str, *__: Any) -> Any:
        row = self._own_row(FILTER, uuid)
        if row is None:
            return {"result": "not found"}
        self._rows(FILTER).remove(row)
        self.save("filter rule deleted")
        return {"result": "deleted"}

    def _firewall_filter_apply(self, *_: Any) -> Any:
        self.applied.append("filter")
        return {"status": "OK\n\n"}

    def _dnat_row(self, body: dict[str, Any], uuid: str, old: dict[str, Any]) -> dict[str, Any]:
        flat: dict[str, Any] = {}
        for key, value in body.items():
            if isinstance(value, dict):
                flat |= {f"{key}.{k}": v for k, v in value.items()}
            else:
                flat[key] = value
        item = {**{k: v for k, v in old.items() if k not in ("uuid", "sort_order")}, **flat}
        zone = str(item.get("interface", ""))
        if zone not in self._assigned():
            raise Refused("rule.interface", "Please select a valid interface.")
        if str(item.get("protocol", "")).lower() not in ("tcp", "udp", "tcp/udp"):
            raise Refused("rule.protocol", "Please select a valid protocol.")
        item["protocol"] = str(item["protocol"]).lower()
        self._net_token("rule.destination.network", str(item.get("destination.network", "")), set())
        self._ports("rule.destination.port", str(item.get("destination.port", "")), "tcp")
        try:
            ipaddress.ip_address(str(item.get("target", "")))
        except ValueError:
            raise Refused("rule.target", "Please specify a valid address.") from None
        local = str(item.get("local-port", ""))
        if local and not (local.isdigit() and 1 <= int(local) <= 65535):
            raise Refused("rule.local-port", "Please specify a valid port number or alias.")
        item["sequence"] = self._sequence("rule.sequence", item.get("sequence", 1))
        item["uuid"] = uuid
        item["sort_order"] = f"400000.{int(item['sequence']):07d}"
        return item

    def _firewall_d_nat_add_rule(self, body: dict[str, Any], *_: Any) -> Any:
        uuid = self._uuid("dn")
        item = self._dnat_row({"disabled": "0", **body.get("rule", {})}, uuid, {})
        self._place(self._rows(DNAT), item, "400000.")
        self.save("port forward added")
        return {"result": "saved", "uuid": uuid}

    def _firewall_d_nat_set_rule(self, body: dict[str, Any], uuid: str, *_: Any) -> Any:
        row = self._own_row(DNAT, uuid)
        if row is None:
            return {"result": "failed"}
        new = self._dnat_row(body.get("rule", {}), uuid, row)
        self._rows(DNAT).remove(row)
        self._place(self._rows(DNAT), new, "400000.")
        self.save("port forward changed")
        return {"result": "saved"}

    def _firewall_d_nat_del_rule(self, _: Any, uuid: str, *__: Any) -> Any:
        row = self._own_row(DNAT, uuid)
        if row is None:
            return {"result": "not found"}
        self._rows(DNAT).remove(row)
        self.save("port forward deleted")
        return {"result": "deleted"}

    def _firewall_d_nat_apply(self, *_: Any) -> Any:
        self.applied.append("d_nat")
        return {"status": "OK\n\n"}

    # backups ------------------------------------------------------------------------------

    def _core_backup_revert_backup(self, _: Any, rid: str, *__: Any) -> Any:
        return self.revert(rid)


def _grid_row(item: dict[str, Any]) -> dict[str, Any]:
    """A model item as a search grid row: option fields as the selected keys plus ``%name``
    with their labels, nested containers as ``parent.child``."""
    row: dict[str, Any] = {}
    for key, value in item.items():
        if not isinstance(value, dict):
            row[key] = value
        elif value and all(isinstance(v, dict) and "selected" in v for v in value.values()):
            chosen = [k for k, v in value.items() if v.get("selected")]
            row[key] = ",".join(chosen)
            row[f"%{key}"] = ",".join(str(value[k].get("value", k)) for k in chosen)
        else:
            row |= {f"{key}.{k}": v for k, v in value.items()}
    return row


def _snake(part: str) -> str:
    """``searchItem`` -> ``search_item`` (only plain camelCase words, never ids or MACs)."""
    if not re.fullmatch(r"[a-z]+(?:[A-Z][a-z0-9]*)+", part):
        return part
    return re.sub(r"(?<!^)(?=[A-Z])", "_", part).lower()


def _prefixed(table: dict[str, Any], path: str) -> Any:
    return next((v for p, v in table.items() if path == p or path.startswith(p + "/")), None)


#: What ``GET /`` answers without a session: the login form (trimmed; names as in OPNsense 24).
LOGIN_PAGE = """<!doctype html>
<html lang="en-US" class="no-js"><head><title>Login | OPNsense</title></head>
<body class="page-login"><form method="post" id="iform">
<input type="text" id="usernamefld" name="usernamefld" autocomplete="username">
<input type="password" id="passwordfld" name="passwordfld" autocomplete="current-password">
<button type="submit" name="login" value="1">Login</button></form>
<p>OPNsense (c) 2014-2026 Deciso B.V.</p></body></html>
"""


def vpn_data() -> dict[str, Any]:
    """IPsec connections, sessions and OpenVPN instances (#153): opt-in (``vpn=True``), so that
    the sample of the other tests keeps one WireGuard tunnel."""
    return {
        # IPsec connections (swanctl) to a site, and its sessions; documentation addresses
        "/api/ipsec/connections/search_connection": {
            "total": 1,
            "rowCount": 1,
            "current": 1,
            "rows": [
                {
                    "uuid": IPSEC_CONNECTION,
                    "enabled": "1",
                    "description": "site-c",
                    "version": "IKEv2",
                    "aggressive": "0",
                    "remote_addrs": "203.0.113.50",
                    "proposals": "aes256-sha256-modp2048",
                    "dpd_delay": "10",
                }
            ],
        },
        "/api/ipsec/connections/search_child": {
            "total": 1,
            "rowCount": 1,
            "current": 1,
            "rows": [
                {
                    "uuid": IPSEC_CHILD,
                    "enabled": "1",
                    "connection": IPSEC_CONNECTION,
                    "description": "lan-to-site-c",
                    "local_ts": "192.0.2.0/24",
                    "remote_ts": "198.18.99.0/24",
                    "esp_proposals": "aes256-sha256-modp2048",
                    "rekey_time": "3600",
                }
            ],
        },
        "/api/ipsec/connections/search_local": {
            "total": 1,
            "rowCount": 1,
            "current": 1,
            "rows": [
                {"uuid": "1", "connection": IPSEC_CONNECTION, "auth": "psk", "id": "fw.example"}
            ],
        },
        IPSEC_PSKS: {
            "total": 1,
            "rowCount": 1,
            "current": 1,
            "rows": [{"uuid": "2", "ident": "fw.example", "Key": IPSEC_PSK}],
        },
        "/api/ipsec/sessions/search_phase1": {
            "total": 1,
            "rowCount": 1,
            "current": 1,
            "rows": [
                {
                    "ikeid": "1",
                    "name": IPSEC_CONNECTION,
                    "phase1desc": "site-c",
                    "status": "ESTABLISHED",
                }
            ],
        },
        "/api/ipsec/sessions/search_phase2": {
            "total": 1,
            "rowCount": 1,
            "current": 1,
            "rows": [
                {
                    "ikeid": "1",
                    "name": IPSEC_CHILD,
                    "state": "INSTALLED",
                    "install-time": "1800",
                }
            ],
        },
        # OpenVPN instances (23.7 and later) and who is connected (#153)
        "/api/openvpn/instances/search": {
            "total": 2,
            "rowCount": 2,
            "current": 1,
            "rows": [
                {
                    "uuid": OVPN_SERVER,
                    "enabled": "1",
                    "description": "road-warrior",
                    "role": "server",
                    "proto": "udp4",
                    "port": "1194",
                    "server": "198.18.77.0/24",
                    "route": "192.0.2.0/24",
                    "tls_key": "static-key-uuid",
                    "data-ciphers": "AES-256-GCM,AES-128-GCM",
                },
                {
                    "uuid": OVPN_CLIENT,
                    "enabled": "1",
                    "description": "to-provider",
                    "role": "client",
                    "proto": "tcp4",
                    "port": "443",
                    "remote": "203.0.113.60",
                    "tls_key": "static-key-uuid",
                    "data-ciphers": "AES-256-GCM",
                },
            ],
        },
        "/api/openvpn/service/search_sessions": {
            "total": 2,
            "rowCount": 2,
            "current": 1,
            "rows": [
                {
                    "type": "server",
                    "description": "road-warrior",
                    "common_name": "laptop",
                    "virtual_address": "198.18.77.2",
                    "connected_since": "2026-11-22 08:00:00",
                    "status": "connected",
                },
                {"type": "client", "description": "to-provider", "status": "connected"},
            ],
        },
    }


@dataclass
class OpnsenseSimulator(_Writes):
    api_key: str = KEY
    api_secret: str = SECRET
    api_enabled: bool = True
    delay: float = 0.0
    malformed: set[str] = field(default_factory=set)
    #: Status code to answer per path instead of the data (403, 500, ...).
    fail: dict[str, int] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=sample_data)
    #: Paths requested so far (to check that nothing is sent before the pin check).
    requests: list[str] = field(default_factory=list)
    #: Validation messages to answer per path (or path prefix) of a write endpoint.
    invalid: dict[str, dict[str, str]] = field(default_factory=dict)
    #: Configuration history: (id, time, config.xml), oldest first.
    history: list[tuple[str, str, str]] = field(default_factory=list)
    #: Interface assignment changes waiting for ``reconfigure``.
    pending: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)
    #: Devices left in the "kernel" by a revert (overview rows that are not configuration).
    leftovers: list[dict[str, Any]] = field(default_factory=list)
    #: Paths that answer only under their camelCase spelling (OPNsense 25.1 and older know
    #: ``searchHostOverride``, not ``search_host_override``): the snake_case request is a 404.
    camel_only: set[str] = field(default_factory=set)
    #: Rows per answer of the Unbound grids (0: as asked): a long list is paged (#386).
    page_limit: int = 0
    #: "26.7.6": assignment rows with addresses; "26.7": only device, description, lock;
    #: "none": no assignment API (404, before 26.7).
    assignment_api: str = "26.7.6"
    #: The simulated release (``RELEASES``); older ones answer as :func:`older_release` says.
    release: str = "26.7"
    #: IPsec connection and OpenVPN instances in the answers (#153).
    vpn: bool = False
    #: False: only camelCase actions exist (``searchItem``), snake_case answers 404 (a guess for
    #: releases before 24.7, whose router is not known to translate it).
    snake_case: bool = True
    #: Assigned interfaces that are locked against removal.
    locked: set[str] = field(default_factory=set)
    #: Write requests received: (path, body).
    posts: list[tuple[str, Any]] = field(default_factory=list)
    #: Packet filter reloads (``filter/apply``, ``d_nat/apply``) received.
    applied: list[str] = field(default_factory=list)
    #: Time zone of the firewall (System: Settings: General), for ``system_time``'s datetime.
    timezone: str = "Europe/Berlin"
    #: The user manager (``/api/auth/user/*``); ``api_key`` is root's key.
    accounts: Users = field(default_factory=Users)
    #: Last WireGuard handshake per peer key (epoch seconds): 42 s before the simulator started.
    wg_handshakes: dict[str, int] = field(
        default_factory=lambda: {WG_SITE_B: int(datetime.now(UTC).timestamp()) - 42}
    )

    #: Traceroutes (#253): target -> hops (address or None for ``*``, RTT in ms). A target not
    #: listed answers through one router (192.0.2.254) and then itself.
    routes: dict[str, list[tuple[str | None, float | None]]] = field(default_factory=dict)
    #: Traces received (the request bodies).
    traces: list[Any] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.vpn:
            self.data.update(vpn_data())
        older_release(self.data, self.release)
        if self.release != "26.7":
            self.assignment_api = "none"

    @property
    def acl_camel(self) -> bool:
        """Releases before 25.7: the ACL patterns are camelCase (``systemTime``, ``getArp``)."""
        return self.release in ("25.1", "24.7")

    @property
    def user_api(self) -> bool:
        """The user manager API (``/api/auth/user``) exists from 25.1."""
        return self.release != "24.7"

    def paged(self, grid: dict[str, Any], query: Any) -> dict[str, Any]:
        """A grid answer the way OPNsense pages it: ``rowCount`` rows of page ``current``
        (-1: all, but at most ``page_limit`` when that is set), ``total`` and ``rowCount``."""
        rows = grid.get("rows", [])
        count = int(query.get("rowCount", -1))
        page = max(int(query.get("current", 1)), 1)
        if self.page_limit and (count < 0 or count > self.page_limit):
            count = self.page_limit
        shown = rows if count < 0 else rows[(page - 1) * count : page * count]
        return {**grid, "rows": shown, "total": len(rows), "rowCount": len(shown), "current": page}

    def old_filter_rows(self, show_all: bool, interface: str = "") -> dict[str, Any]:
        """``filter/search_rule`` of 25.1 (all fields; the rules of the new model only the
        floating ones, or those of ``interface``, and the legacy and automatic ones only with
        ``show_all``, as read on a real 25.1) and 24.7 (four columns of the rules of the new
        model)."""
        rows = copy.deepcopy(self.data[FILTER]["rows"])
        other = [r for r in rows if r.get("legacy") or r.get("is_automatic")]
        mvc = [r for r in rows if r not in other]
        if self.release == "24.7":
            keep = ("uuid", "enabled", "sequence", "action", "description")
            rows = [{k: r[k] for k in keep if k in r} for r in mvc]
        else:
            names = str(interface).split(",") if interface else []
            mvc = [
                {k: v for k, v in r.items() if k != "sort_order"}
                for r in mvc
                if not r.get("interface")
                or (
                    "," in str(r["interface"])
                    if not names
                    else bool(set(names) & set(str(r["interface"]).split(",")))
                )
            ]
            rows = [*other, *mvc] if show_all else mvc
        return {"total": len(rows), "rowCount": len(rows), "current": 1, "rows": rows}

    def traceroute(self, caller: str, body: Any) -> Response:
        """``diagnostics/traceroute/set``: as configd's traceroute.py answers (unanswered hops
        are left out); 403 for a user without *Diagnostics: Traceroute*."""
        if caller != "root":
            user = next((u for u in self.accounts.users if u["name"] == caller), None)
            if user is not None and TRACE_PRIVILEGE not in user["priv"]:
                return JSONResponse({"status": 403, "message": "Forbidden"}, status_code=403)
        self.traces.append(body)
        settings = (body.get("traceroute") or {}).get("settings") or {}
        host = str(settings.get("hostname", ""))
        if not host:
            return JSONResponse(
                {"result": "failed", "validations": {"traceroute.settings.hostname": "Required"}}
            )
        hops = self.routes.get(host, [("192.0.2.254", 0.4), (host, 1.2)])
        rows = [
            {
                "address": addr,
                "ttl": str(ttl),
                "AS": "AS0",
                "host": addr,
                "probes": f"{rtt:.3f} ms" if rtt is not None else "",
            }
            for ttl, (addr, rtt) in enumerate(hops, start=1)
            if addr is not None
        ]
        return JSONResponse({"result": "ok", "response": {"rows": rows}})

    def wireguard_show(self) -> Any:
        answer = copy.deepcopy(self.data[WG_SHOW])
        now = int(datetime.now(UTC).timestamp())
        for row in answer.get("rows", []) if isinstance(answer, dict) else []:
            at = self.wg_handshakes.get(row.get("public-key", ""))
            if isinstance(row, dict) and row.get("type") == "peer" and at is not None:
                row["latest-handshake"] = at
                row["latest-handshake-age"] = now - at
        return answer

    def local_time(self) -> str:
        """``Sun Nov 22 17:12:00 CET 2026``, PHP's ``date("D M j G:i:s T Y")``."""
        try:
            now = datetime.now(ZoneInfo(self.timezone))
        except (ZoneInfoNotFoundError, ValueError):
            now = datetime.now(UTC)
        return f"{now:%a %b} {now.day} {now.hour}:{now:%M:%S} {now.tzname()} {now.year}"

    def may_manage_users(self, caller: str) -> bool:
        """Root, and users with *System: Access: Users* (or everything), may call the user
        manager; no other privilege reaches it."""
        if caller == "root":
            return True
        user = next((u for u in self.accounts.users if u["name"] == caller), None)
        return user is not None and bool({ACCOUNTS_PRIVILEGE, "page-all"} & set(user["priv"]))

    def authorised(self, header: str | None) -> bool:
        return self.caller(header) is not None

    def caller(self, header: str | None) -> str | None:
        """The user a request's key belongs to (``root`` for ``api_key``), None: refused."""
        if not header or not header.startswith("Basic "):
            return None
        try:
            user, _, password = base64.b64decode(header[6:]).decode().partition(":")
        except (binascii.Error, UnicodeDecodeError):
            return None
        if secrets.compare_digest(user, self.api_key) and secrets.compare_digest(
            password, self.api_secret
        ):
            return "root"
        return self.accounts.user_of(user, password)

    def app(self) -> FastAPI:
        app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

        @app.api_route("/{path:path}", methods=["GET", "POST"])
        async def answer(path: str, request: Request) -> Response:
            # OPNsense routes camelCase and snake_case actions alike (snake_case is canonical)
            if not self.snake_case and any("_" in part for part in path.split("/")[3:4]):
                self.requests.append("/" + path)
                return JSONResponse({"errorMessage": "Endpoint not found"}, status_code=404)
            if self.acl_camel and any("_" in part for part in path.split("/")[3:4]):
                # the privileges of 24.7 and 25.1 name camelCase actions: another spelling is
                # refused (403) although the router would run it (seen on a real 25.1)
                self.requests.append("/" + path)
                if not path.startswith("api/auth/user/"):
                    return JSONResponse({"status": 403, "message": "Forbidden"}, status_code=403)
            spelled = "/" + path
            path = "/" + "/".join(_snake(part) for part in path.split("/"))
            snake_request = spelled == path
            self.requests.append(path)
            if path == "/" and request.method == "GET":
                # the web interface's login page, served to anyone (found by discovery, #203)
                return Response(LOGIN_PAGE, media_type="text/html")
            if not self.api_enabled or (snake_request and path in self.camel_only):
                return JSONResponse({"errorMessage": "Endpoint not found"}, status_code=404)
            caller = self.caller(request.headers.get("authorization"))
            if caller is None:
                return JSONResponse(
                    {"status": 401, "message": "Authentication Failed"},
                    status_code=401,
                    headers={"WWW-Authenticate": 'Basic realm="api"'},
                )
            if path.startswith(USERS) and not self.user_api:
                return JSONResponse({"errorMessage": "Endpoint not found"}, status_code=404)
            if path.startswith(ASSIGN) and self.assignment_api == "none":
                return JSONResponse({"errorMessage": "Endpoint not found"}, status_code=404)
            if path.startswith(USERS) and not self.may_manage_users(caller):
                return JSONResponse({"status": 403, "message": "Forbidden"}, status_code=403)
            if self.delay:
                await asyncio.sleep(self.delay)
            status = _prefixed(self.fail, path)
            if status is not None:
                return JSONResponse({"message": "simulated failure"}, status_code=status)
            invalid = _prefixed(self.invalid, path)
            if invalid is not None:
                return JSONResponse({"result": "failed", "validations": invalid})
            if path == TRACEROUTE and request.method == "POST":
                return self.traceroute(caller, await request.json())
            if path.startswith(USERS):
                body = await request.json() if await request.body() else {}
                users = self.accounts.answer(path, body)
                if users is None:
                    return JSONResponse({"errorMessage": "Endpoint not found"}, status_code=404)
                return JSONResponse(users)
            if path == BACKUPS:
                return JSONResponse(self.backups())
            if path == DOWNLOAD or path.startswith(DOWNLOAD + "/"):
                xml = self.download(path[len(DOWNLOAD) + 1 :] or None)
                if xml is None:
                    return Response(status_code=200)  # OPNsense sends nothing for unknown ids
                return Response(xml, media_type="application/octet-stream")
            if request.method == "POST" or path.startswith(ASSIGN):
                body = await request.json() if await request.body() else {}
                answer = self.write(path, body)
                if answer is not None:
                    return JSONResponse(answer)
            grids = (KEA_SUBNETS, KEA_RESERVATIONS)
            if path not in self.data and not (path in grids and KEA in self.data):
                return JSONResponse({"errorMessage": "Endpoint not found"}, status_code=404)
            if path in self.malformed:
                return Response('{"rows": [', media_type="application/json")
            if path == VLANS:
                return JSONResponse(self._vlan_list())
            if path == INTERFACES and self.leftovers and isinstance(self.data[path], dict):
                overview = copy.deepcopy(self.data[path])
                overview["rows"] = [*overview.get("rows", []), *copy.deepcopy(self.leftovers)]
                return JSONResponse(overview)
            if path == FILTER and self.release in ("25.1", "24.7"):
                query = request.query_params
                return JSONResponse(
                    self.old_filter_rows(bool(query.get("show_all")), query.get("interface", ""))
                )
            if path in (KEA, *grids):
                return JSONResponse(self._kea_answer(path))
            if path in UNBOUND_GRIDS and isinstance(self.data[path], dict):
                return JSONResponse(self.paged(self.data[path], request.query_params))
            if path == WG_SHOW:
                return JSONResponse(self.wireguard_show())
            if path == SYSTEM_TIME and isinstance(self.data[path], dict):
                return JSONResponse({**self.data[path], "datetime": self.local_time()})
            return JSONResponse(self.data[path])

        return app
