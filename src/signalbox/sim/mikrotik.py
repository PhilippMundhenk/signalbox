"""Simulator of the RouterOS 7 REST API (``GET /rest/<menu>``) the ``mikrotik`` adapter reads.

The answers follow the JSON shapes in ``docs/adapters/mikrotik.md`` (from the RouterOS
documentation, not yet confirmed on a real device, issue #21): lists of objects with ``.id``,
every value a string. Sample network, documentation addresses only:

- a hEX-like router with Wi-Fi: ``ether1`` is the uplink (interface list ``WAN``, DHCP client
  bound to 203.0.113.2/24, DHCPv6 prefix 2001:db8:1::/56, ``/ip/cloud`` public address),
  ``ether2``-``ether5``, ``wifi1`` (2.4 GHz), ``wifi2`` (5 GHz) and the virtual ``wifi3`` in
  ``bridge`` with VLAN filtering; ``pppoe_session`` answers the PPPoE monitor of a client
  added to ``/interface/pppoe-client``
- VLAN 1 (native LAN, 192.0.2.1/24, 2001:db8:1::1/64) untagged on ether2, ether3, wifi1/2;
  VLAN 20 "iot" (198.51.100.1/24) tagged on ether2, untagged on ether4 and wifi3; ether5 disabled
- health (uptime, CPU, memory, flash, one CPU temperature), the clock (Europe/Berlin), an NTP
  client in sync and the NTP server enabled, handed out by DHCP on the LAN
- DHCP on both, with static leases; DNS with static entries; ARP, IPv6 neighbours, bridge hosts,
  Wi-Fi registrations; one LLDP/MNDP neighbour (a switch on ether2)

Failure switches on :class:`MikrotikSimulator`: ``rest_enabled=False`` (404 on everything),
``delay`` (seconds before every answer), ``malformed`` (paths answering broken JSON), ``fail``
(a status code per path), ``wireless`` (``"wifi"``, ``"legacy"`` or ``"none"``: which wireless
package is installed); a wrong user or password is answered with 401. ``data`` can be edited.

Writes change ``data``: ``PUT /rest/<menu>`` creates, ``PATCH``/``DELETE /rest/<menu>/<.id>``
change and remove, ``POST /rest/<menu>/unset`` clears a property, ``POST /rest/execute`` with
``{"script": "/export", "as-string": ""}`` answers an export text (``POST /rest/export`` answers
``[]``, as the real one does). A menu the device does not have is HTTP 400 ``no such command or
directory (<name>)``, as RouterOS 7.25.1 CHR answers in CI (#139). The simulator refuses what
RouterOS would (missing properties, unknown interfaces, pools or servers, duplicate names, bad
addresses, dynamic entries) with HTTP 400 and a ``detail``, and afterwards settles what RouterOS
computes itself: VLAN and Wi-Fi interfaces in ``/interface``, the dynamic bridge port of a Wi-Fi
interface with ``datapath.bridge``, and the ``current-*`` lists and dynamic entries of the
bridge VLAN table ("added by pvid"). Write switches: ``read_only`` (HTTP 500 ``not enough
permissions (9)``, a group without ``write``), ``fail_write`` (a status per menu),
``ignore_writes`` (answer success, change nothing).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import copy
import json
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from ipaddress import ip_address, ip_interface
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

USER = "signalbox"
PASSWORD = "sim-password"
#: Wi-Fi passphrase of the sample SSID "Example" (to test the fingerprint).
PASSPHRASE = "correct horse battery staple"

MAC = "02:00:00:00:{:02x}:{:02x}"


def _mac(a: int, b: int) -> str:
    return MAC.format(a, b).upper()  # RouterOS writes MACs in upper case


def _ids(*rows: dict[str, Any]) -> list[dict[str, Any]]:
    """A menu answer: every row gets a ``.id`` (``*1``, ``*2``, ...)."""
    return [{".id": f"*{i:X}", **row} for i, row in enumerate(rows, start=1)]


def _iface(name: str, kind: str, mac: str, running: bool = True, **kw: Any) -> dict[str, Any]:
    return {
        "name": name,
        "default-name": name if kind == "ether" else "",
        "type": kind,
        "mtu": "1500",
        "actual-mtu": "1500",
        **({"l2mtu": "1568"} if kind in ("ether", "wifi") else {}),
        "mac-address": mac,
        "running": "true" if running else "false",
        "disabled": "false",
        "dynamic": "false",
        "slave": "false",
        **kw,
    }


#: What a gigabit port of RouterOS 7.12+ offers in auto-negotiation.
GIGABIT = ",".join(f"{s}-baseT-{d}" for s in ("10M", "100M", "1G") for d in ("half", "full"))


def _ether(name: str, speed: str, **kw: Any) -> dict[str, Any]:
    return {
        "name": name,
        "default-name": name,
        "speed": speed,
        "auto-negotiation": "true",
        "advertise": GIGABIT,
        "rx-flow-control": "off",
        "tx-flow-control": "off",
        "l2mtu": "1568",
        **kw,
    }


def _port(interface: str, pvid: str = "1", frame_types: str = "admit-all") -> dict[str, Any]:
    return {
        "interface": interface,
        "bridge": "bridge",
        "pvid": pvid,
        "frame-types": frame_types,
        "ingress-filtering": "true",
        "disabled": "false",
        "dynamic": "false",
        "inactive": "false",
    }


def sample_data() -> dict[str, Any]:
    """Answers by path (a fresh copy every call)."""
    bridge_mac = _mac(1, 0)
    data: dict[str, Any] = {
        "/rest/system/resource": {
            "uptime": "3d04:05:06",
            "version": "7.15.3 (stable)",
            "build-time": "2024-07-24 10:39:00",
            "factory-software": "7.0.4",
            "free-memory": "190000000",
            "total-memory": "268435456",
            "cpu": "ARMv7",
            "cpu-count": "4",
            "cpu-frequency": "864",
            "cpu-load": "3",
            "free-hdd-space": "103260160",
            "total-hdd-space": "134217728",
            "write-sect-since-reboot": "1524",
            "write-sect-total": "85210",
            "architecture-name": "arm64",
            "board-name": "hAP ax^2",
            "platform": "MikroTik",
        },
        # RouterOS 7: one row per sensor (CHR: only {"state": "disabled", ...}). A hAP ax^2
        # has a CPU sensor only; a CRS3xx adds fans, PSU states and the input voltage.
        "/rest/system/health": _ids(
            {"name": "cpu-temperature", "value": "52", "type": "C"},
        ),
        # date/time are replaced by the current time in gmt-offset on every answer.
        "/rest/system/clock": {
            "date": "2026-11-22",
            "time": "12:00:00",
            "time-zone-autodetect": "false",
            "time-zone-name": "Europe/Berlin",
            "gmt-offset": "+01:00",
            "dst-active": "false",
        },
        "/rest/system/ntp/client": {
            "enabled": "true",
            "mode": "unicast",
            "servers": "0.pool.ntp.org,1.pool.ntp.org",
            "vrf": "main",
            "status": "synchronized",
            "synced-server": "203.0.113.123",
            "synced-stratum": "2",
            "system-offset": "-0.215",
            "freq-drift": "1.124",
        },
        "/rest/system/ntp/server": {
            "enabled": "true",
            "broadcast": "false",
            "multicast": "false",
            "manycast": "false",
            "broadcast-addresses": "",
            "vrf": "main",
            "use-local-clock": "false",
            "local-clock-stratum": "5",
            "auth-key": "none",
        },
        "/rest/system/routerboard": {
            "routerboard": "true",
            "board-name": "hAP ax^2",
            "model": "C52iG-5HaxD2HaxD",
            "firmware-type": "ipq6000",
            "current-firmware": "7.15.3",
            "upgrade-firmware": "7.15.3",
        },
        "/rest/system/package/update": {
            "channel": "stable",
            "installed-version": "7.15.3",
            "latest-version": "7.16",
            "status": "New version is available",
        },
        "/rest/interface": _ids(
            _iface("ether1", "ether", _mac(0, 1), comment="uplink"),
            _iface("ether2", "ether", _mac(0, 2)),
            _iface("ether3", "ether", _mac(0, 3)),
            _iface("ether4", "ether", _mac(0, 4)),
            _iface("ether5", "ether", _mac(0, 5), running=False, disabled="true"),
            _iface("wifi1", "wifi", _mac(0, 6)),
            _iface("wifi2", "wifi", _mac(0, 7)),
            _iface("wifi3", "wifi", _mac(0, 8)),
            _iface("bridge", "bridge", bridge_mac),
            _iface("iot", "vlan", bridge_mac),
            _iface("lo", "loopback", "00:00:00:00:00:00"),
        ),
        "/rest/interface/ethernet": _ids(
            _ether("ether1", "1G-baseT-full"),
            _ether("ether2", "1Gbps"),
            _ether(
                "ether3",
                "100M-baseT-half",
                **{"auto-negotiation": "false", "advertise": "", "rx-flow-control": "on"},
            ),
            _ether("ether4", "1G-baseT-full"),
            _ether("ether5", "1G-baseT-full"),
        ),
        "/rest/interface/bridge": _ids(
            {
                "name": "bridge",
                "comment": "LAN",
                "vlan-filtering": "true",
                "pvid": "1",
                "frame-types": "admit-all",
                "protocol-mode": "rstp",
                "mac-address": bridge_mac,
                "disabled": "false",
            }
        ),
        "/rest/interface/bridge/port": _ids(
            _port("ether2"),
            _port("ether3", frame_types="admit-only-untagged-and-priority-tagged"),
            _port("ether4", pvid="20", frame_types="admit-only-untagged-and-priority-tagged"),
            {**_port("ether5"), "ingress-filtering": "false"},
            _port("wifi1"),
            _port("wifi2"),
            _port("wifi3", pvid="20"),
        ),
        "/rest/interface/bridge/vlan": _ids(
            {
                "bridge": "bridge",
                "vlan-ids": "1",
                "tagged": "",
                "untagged": "bridge,ether2,ether3,wifi1,wifi2",
                "current-tagged": "",
                "current-untagged": "bridge,ether2,ether3,wifi1,wifi2",
                "comment": "added by pvid",
                "dynamic": "true",
                "disabled": "false",
            },
            {
                "bridge": "bridge",
                "vlan-ids": "20",
                "tagged": "bridge,ether2",
                "untagged": "ether4",
                "current-tagged": "bridge,ether2",
                "current-untagged": "ether4,wifi3",
                "comment": "IoT devices",
                "dynamic": "false",
                "disabled": "false",
            },
        ),
        "/rest/interface/vlan": _ids(
            {
                "name": "iot",
                "vlan-id": "20",
                "interface": "bridge",
                "mtu": "1500",
                "mac-address": bridge_mac,
                "running": "true",
                "disabled": "false",
            }
        ),
        "/rest/interface/list/member": _ids(
            {"list": "WAN", "interface": "ether1", "disabled": "false", "dynamic": "false"},
            {"list": "LAN", "interface": "bridge", "disabled": "false", "dynamic": "false"},
        ),
        "/rest/ip/address": _ids(
            {
                "address": "192.0.2.1/24",
                "network": "192.0.2.0",
                "interface": "bridge",
                "actual-interface": "bridge",
                "disabled": "false",
                "dynamic": "false",
                "invalid": "false",
            },
            {
                "address": "198.51.100.1/24",
                "network": "198.51.100.0",
                "interface": "iot",
                "actual-interface": "iot",
                "disabled": "false",
                "dynamic": "false",
                "invalid": "false",
            },
            {
                "address": "203.0.113.2/24",
                "network": "203.0.113.0",
                "interface": "ether1",
                "actual-interface": "ether1",
                "disabled": "false",
                "dynamic": "true",
                "invalid": "false",
            },
        ),
        "/rest/ipv6/address": _ids(
            {
                "address": "2001:db8:1::1/64",
                "interface": "bridge",
                "actual-interface": "bridge",
                "advertise": "true",
                "disabled": "false",
                "dynamic": "false",
                "invalid": "false",
                "link-local": "false",
            },
            {
                "address": "fe80::1/64",
                "interface": "bridge",
                "actual-interface": "bridge",
                "disabled": "false",
                "dynamic": "true",
                "invalid": "false",
                "link-local": "true",
            },
            {
                "address": "2001:db8:ffff::2/64",
                "interface": "ether1",
                "actual-interface": "ether1",
                "disabled": "false",
                "dynamic": "true",
                "invalid": "false",
            },
        ),
        "/rest/ip/dhcp-client": _ids(
            {
                "interface": "ether1",
                "status": "bound",
                "address": "203.0.113.2/24",
                "gateway": "203.0.113.1",
                "dhcp-server": "203.0.113.1",
                "primary-dns": "203.0.113.53",
                "secondary-dns": "203.0.113.54",
                "expires-after": "23h12m5s",
                "add-default-route": "yes",
                "use-peer-dns": "yes",
                "disabled": "false",
                "dynamic": "false",
                "invalid": "false",
            }
        ),
        "/rest/ipv6/dhcp-client": _ids(
            {
                "interface": "ether1",
                "status": "bound",
                "request": "address,prefix",
                "pool-name": "isp",
                "prefix": "2001:db8:1::/56, 2d23h50m10s",
                "dhcp-server": "fe80::1%ether1",
                "disabled": "false",
                "dynamic": "false",
                "invalid": "false",
            }
        ),
        "/rest/interface/pppoe-client": [],
        # as RouterOS 7.25.1 (CHR) answers: ``available-from``, dynamic rows for the resolver and
        # open connections, a ``reverse-proxy`` row that is no service of the adapter's list
        "/rest/ip/service": _ids(
            *(
                {
                    "name": n,
                    "port": port,
                    "available-from": addr,
                    **({"certificate": cert} if cert is not None else {}),
                    "disabled": off,
                    "dynamic": "false",
                    "invalid": "false",
                    "max-sessions": "20",
                    "proto": "tcp",
                    "vrf": "main",
                }
                for n, port, addr, cert, off in (
                    ("ftp", "21", "", None, "true"),
                    ("ssh", "22", "192.0.2.0/24,198.51.100.0/24", None, "false"),
                    ("telnet", "23", "", None, "true"),
                    ("www", "80", "", None, "false"),
                    ("www-ssl", "443", "", "signalbox-www", "false"),
                    ("reverse-proxy", "443", "", "none", "false"),
                    ("winbox", "8291", "192.0.2.0/24", None, "false"),
                    ("api", "8728", "", None, "false"),
                    ("api-ssl", "8729", "", "none", "true"),
                )
            ),
            {
                "name": "resolver",
                "port": "53",
                "proto": "tcp",
                "disabled": "false",
                "dynamic": "true",
                "invalid": "false",
            },
            {
                "name": "www-ssl",
                "port": "443",
                "proto": "tcp",
                "local": "192.0.2.1",
                "remote": "192.0.2.2:56578",
                "connection": "true",
                "disabled": "false",
                "dynamic": "true",
                "invalid": "false",
            },
        ),
        "/rest/tool/mac-server": {"allowed-interface-list": "LAN"},
        "/rest/tool/mac-server/mac-winbox": {"allowed-interface-list": "none"},
        "/rest/tool/romon": {"enabled": "false", "id": "00:00:00:00:00:00", "secrets": "*****"},
        "/rest/ip/ssh": {
            "ciphers": "auto",
            "forwarding-enabled": "no",
            "host-key-type": "ed25519",
            "password-authentication": "yes-if-no-key",
            "strong-crypto": "false",
        },
        "/rest/ip/upnp": {
            "allow-disable-external-interface": "false",
            "enabled": "false",
            "show-dummy-rule": "true",
        },
        "/rest/snmp": {
            "contact": "",
            "enabled": "true",
            "location": "",
            "trap-version": "1",
            "vrf": "main",
        },
        "/rest/snmp/community": _ids(
            {
                "name": "public",
                "addresses": "::/0",
                "security": "none",
                "read-access": "true",
                "write-access": "false",
                "authentication-protocol": "MD5",
                "authentication-password": "*****",
                "encryption-protocol": "DES",
                "encryption-password": "*****",
                "disabled": "false",
                "default": "true",
            }
        ),
        "/rest/ip/cloud": {  # after a cloud update (CHR in CI without one: no public-address)
            "ddns-enabled": "auto",
            "ddns-update-interval": "none",
            "update-time": "false",
            "public-address": "203.0.113.2",
            "status": "updated",
        },
        "/rest/ip/dhcp-server": _ids(
            {
                "name": "defconf",
                "interface": "bridge",
                "address-pool": "default-dhcp",
                "authoritative": "yes",
                "lease-time": "30m",
                "disabled": "false",
                "invalid": "false",
                "dynamic": "false",
            },
            {
                "name": "iot-dhcp",
                "interface": "iot",
                "address-pool": "iot-pool",
                "lease-time": "1d00:00:00",
                "disabled": "false",
                "invalid": "false",
                "dynamic": "false",
            },
        ),
        "/rest/ip/dhcp-server/network": _ids(
            {
                "address": "192.0.2.0/24",
                "gateway": "192.0.2.1",
                "dns-server": "192.0.2.1",
                "domain": "home.example",
                "ntp-server": "192.0.2.1",
                "next-server": "192.0.2.5",
                "boot-file-name": "pxelinux.0",
                "dhcp-option": "search,routes,wpad",
                "comment": "defconf",
            },
            {
                "address": "198.51.100.0/24",
                "gateway": "198.51.100.1",
                "dns-server": "198.51.100.1,192.0.2.1",
                "domain": "iot.example",
                "ntp-server": "",
            },
        ),
        "/rest/ip/dhcp-server/option": _ids(
            {"name": "search", "code": "119", "value": "0x04686f6d65076578616d706c6500"},
            {"name": "routes", "code": "121", "value": "0x18cb0071c00002fe"},
            {"name": "wpad", "code": "252", "value": "'http://192.0.2.1/wpad.dat'"},
        ),
        "/rest/ip/dhcp-relay": _ids(
            {
                "name": "iot-relay",
                "interface": "iot",
                "dhcp-server": "192.0.2.53",
                "local-address": "198.51.100.1",
                "disabled": "false",
                "invalid": "false",
            }
        ),
        "/rest/ip/pool": _ids(
            {"name": "default-dhcp", "ranges": "192.0.2.100-192.0.2.199"},
            {
                "name": "iot-pool",
                "ranges": "198.51.100.100-198.51.100.149,198.51.100.200-198.51.100.210",
            },
        ),
        "/rest/ip/dhcp-server/lease": _ids(
            {
                "address": "192.0.2.10",
                "mac-address": _mac(0, 0x10),
                "server": "defconf",
                "comment": "printer",
                "host-name": "PRN-0010",
                "status": "bound",
                "dynamic": "false",
                "disabled": "false",
                "active-address": "192.0.2.10",
                "active-mac-address": _mac(0, 0x10),
            },
            {
                "address": "198.51.100.20",
                "mac-address": _mac(0, 0x20),
                "server": "iot-dhcp",
                "host-name": "sensor",
                "status": "waiting",
                "dynamic": "false",
                "disabled": "false",
            },
            {
                "address": "192.0.2.100",
                "mac-address": _mac(0, 0x21),
                "server": "defconf",
                "host-name": "laptop",
                "status": "bound",
                "dynamic": "true",
                "disabled": "false",
                "active-address": "192.0.2.100",
                "active-mac-address": _mac(0, 0x21),
                "client-id": "1:" + _mac(0, 0x21),
                "class-id": "android-dhcp-14",
                "expires-after": "25m10s",
            },
            {
                "address": "198.51.100.101",
                "mac-address": _mac(0, 0x22),
                "server": "iot-dhcp",
                "host-name": "phone",
                "status": "bound",
                "dynamic": "true",
                "disabled": "false",
                "expires-after": "23h59m",
            },
            {
                "address": "198.51.100.102",
                "mac-address": _mac(0, 0x23),
                "server": "iot-dhcp",
                "status": "offered",
                "dynamic": "true",
                "disabled": "false",
            },
        ),
        "/rest/ip/dns": {
            "servers": "192.0.2.53,2001:db8:53::53",
            "dynamic-servers": "203.0.113.1",
            "allow-remote-requests": "true",
            "cache-size": "2048",
            "cache-max-ttl": "1w",
        },
        "/rest/ip/dns/static": _ids(
            {
                "name": "nas.home.example",
                "type": "A",
                "address": "192.0.2.10",
                "ttl": "1d",
                "disabled": "false",
            },
            {
                "name": "nas.home.example",
                "type": "AAAA",
                "address": "2001:db8:1::10",
                "ttl": "1d",
                "disabled": "false",
            },
            {"name": "old.home.example", "address": "192.0.2.11", "disabled": "true"},
            {
                "name": "files.home.example",
                "type": "CNAME",
                "cname": "nas.home.example",
                "disabled": "false",
            },
            {"regexp": ".*\\.ads\\.example", "address": "0.0.0.0", "disabled": "false"},
        ),
        "/rest/ip/arp": _ids(
            {
                "address": "192.0.2.10",
                "mac-address": _mac(0, 0x10),
                "interface": "bridge",
                "status": "reachable",
                "dynamic": "true",
                "complete": "true",
                "DHCP": "true",
            },
            {
                "address": "192.0.2.100",
                "mac-address": _mac(0, 0x21),
                "interface": "bridge",
                "status": "stale",
                "dynamic": "true",
                "complete": "true",
            },
            {
                "address": "198.51.100.20",
                "mac-address": _mac(0, 0x20),
                "interface": "iot",
                "status": "reachable",
                "dynamic": "true",
            },
            {
                "address": "203.0.113.1",
                "mac-address": _mac(9, 1),
                "interface": "ether1",
                "status": "reachable",
                "dynamic": "true",
            },
            {"address": "192.0.2.99", "interface": "bridge", "status": "failed"},
        ),
        "/rest/ipv6/neighbor": _ids(
            {
                "address": "2001:db8:1::10",
                "mac-address": _mac(0, 0x10),
                "interface": "bridge",
                "status": "reachable",
            },
            {
                "address": "fe80::10",
                "mac-address": _mac(0, 0x10),
                "interface": "bridge",
                "status": "stale",
            },
        ),
        "/rest/interface/bridge/host": _ids(
            {
                "mac-address": bridge_mac,
                "on-interface": "bridge",
                "bridge": "bridge",
                "vid": "1",
                "local": "true",
                "dynamic": "false",
            },
            {
                "mac-address": _mac(0, 0x10),
                "on-interface": "ether3",
                "bridge": "bridge",
                "vid": "1",
                "local": "false",
                "dynamic": "true",
            },
            {
                "mac-address": _mac(0, 0x21),
                "on-interface": "ether2",
                "bridge": "bridge",
                "vid": "1",
                "local": "false",
                "dynamic": "true",
            },
            {
                "mac-address": _mac(0, 0x20),
                "on-interface": "ether4",
                "bridge": "bridge",
                "vid": "20",
                "local": "false",
                "dynamic": "true",
            },
            {
                "mac-address": _mac(0, 0x22),
                "on-interface": "wifi3",
                "bridge": "bridge",
                "vid": "20",
                "local": "false",
                "dynamic": "true",
            },
            {
                "mac-address": _mac(0, 0x50),
                "on-interface": "ether2",
                "bridge": "bridge",
                "vid": "1",
                "local": "false",
                "dynamic": "true",
            },
        ),
        "/rest/ip/neighbor": _ids(
            {
                "interface": "ether2,bridge",
                "address": "192.0.2.2",
                "address4": "192.0.2.2",
                "mac-address": _mac(0, 0x50),
                "identity": "switch",
                "platform": "MikroTik",
                "version": "7.15.3 (stable)",
                "board": "CRS326-24G-2S+",
                "interface-name": "ether24",
                "discovered-by": "lldp,mndp",
                "system-caps": "bridge,router",
            },
            {"interface": "ether1", "identity": "isp-modem", "discovered-by": "cdp"},
        ),
        "/rest/interface/wifi": _ids(
            {
                "name": "wifi1",
                "default-name": "wifi1",
                "mac-address": _mac(0, 6),
                "configuration.mode": "ap",
                "configuration.ssid": "Example",
                "configuration.country": "Germany",
                "configuration.tx-power": "17",
                "channel.band": "2ghz-ax",
                "channel.frequency": "2437",
                "channel.width": "20/40mhz",
                "security": "home",
                "steering.rrm": "yes",
                "steering.wnm": "yes",
                "datapath.bridge": "bridge",
                "disabled": "false",
                "running": "true",
            },
            {
                "name": "wifi2",
                "default-name": "wifi2",
                "mac-address": _mac(0, 7),
                "configuration": "home-5g",
                "channel.band": "5ghz-ax",
                "channel.width": "20/40/80mhz",
                "security": "home",
                "datapath.bridge": "bridge",
                "disabled": "false",
                "running": "true",
            },
            {
                "name": "wifi3",
                "master-interface": "wifi1",
                "mac-address": _mac(0, 8),
                "configuration.mode": "ap",
                "configuration.ssid": "Example-IoT",
                "configuration.hide-ssid": "true",
                "security.authentication-types": "wpa2-psk",
                "security.passphrase": "iot-passphrase",
                "security.encryption": "ccmp,tkip",
                "security.wps": "push-button",
                "datapath.bridge": "bridge",
                "datapath.vlan-id": "20",
                "disabled": "false",
                "running": "true",
            },
        ),
        "/rest/interface/wifi/configuration": _ids(
            {
                "name": "home-5g",
                "mode": "ap",
                "ssid": "Example",
                "country": "Germany",
                "tx-power": "23",
            }
        ),
        "/rest/interface/wifi/security": _ids(
            {
                "name": "home",
                "authentication-types": "wpa2-psk,wpa3-psk",
                "passphrase": PASSPHRASE,
                "management-protection": "allowed",
                "encryption": "ccmp",
                "group-encryption": "ccmp",
                "sae-pwe": "both",
                "sae-anti-clogging-threshold": "5",
                "wps": "disable",
                "group-key-update": "1h",
                "ft": "yes",
                "ft-over-ds": "yes",
            }
        ),
        "/rest/interface/wifi/channel": [],
        # users and groups (#231: the automatic setup creates its own); no passwords shown
        "/rest/user": _ids({"name": "admin", "group": "full", "disabled": "false"}),
        "/rest/user/group": _ids(
            {"name": "read", "policy": "local,telnet,ssh,reboot,read,test,winbox,web,sniff,api"},
            {"name": "full", "policy": "local,telnet,ssh,read,write,policy,api,rest-api"},
        ),
        "/rest/interface/wifi/registration-table": _ids(
            {
                "interface": "wifi3",
                "ssid": "Example-IoT",
                "mac-address": _mac(0, 0x22),
                "uptime": "1h2m3s",
                "signal": "-61",
                "band": "2ghz-ax",
            }
        ),
    }
    return copy.deepcopy(data | legacy_wireless())


def legacy_wireless() -> dict[str, Any]:
    """Answers of the older ``wireless`` package (served with ``wireless="legacy"``)."""
    return {
        "/rest/interface/wireless": _ids(
            {
                "name": "wlan1",
                "mode": "ap-bridge",
                "ssid": "Example",
                "band": "2ghz-b/g/n",
                "frequency": "2412",
                "channel-width": "20/40mhz-XX",
                "country": "germany",
                "security-profile": "home",
                "wps-mode": "push-button",
                "hide-ssid": "false",
                "vlan-mode": "no-tag",
                "vlan-id": "1",
                "disabled": "false",
                "running": "true",
                "mac-address": _mac(0, 6),
            },
            {
                "name": "wlan2",
                "mode": "ap-bridge",
                "ssid": "Example",
                "band": "5ghz-a/n/ac",
                "frequency": "auto",
                "channel-width": "20/40/80mhz-XXXX",
                "security-profile": "home",
                "disabled": "true",
                "running": "false",
                "mac-address": _mac(0, 7),
            },
            {
                "name": "wlan3",
                "master-interface": "wlan1",
                "mode": "ap-bridge",
                "ssid": "Example-Guest",
                "security-profile": "default",
                "vlan-mode": "use-tag",
                "vlan-id": "30",
                "disabled": "false",
            },
            {"name": "wlan4", "master-interface": "wlan1", "mode": "station", "ssid": "Upstream"},
        ),
        "/rest/interface/wireless/security-profiles": _ids(
            {
                "name": "default",
                "mode": "none",
                "authentication-types": "",
                "management-protection": "disabled",
            },
            {
                "name": "home",
                "mode": "dynamic-keys",
                "authentication-types": "wpa2-psk",
                "wpa2-pre-shared-key": PASSPHRASE,
                "unicast-ciphers": "aes-ccm",
                "group-ciphers": "aes-ccm",
                "group-key-update": "5m",
                "management-protection": "allowed",
            },
        ),
        "/rest/interface/wireless/registration-table": _ids(
            {"interface": "wlan1", "mac-address": _mac(0, 0x23), "signal-strength": "-55dBm"}
        ),
    }


WIFI_PATHS = (
    "/rest/interface/wifi",
    "/rest/interface/wifi/configuration",
    "/rest/interface/wifi/security",
    "/rest/interface/wifi/channel",
    "/rest/interface/wifi/registration-table",
)
LEGACY_PATHS = (
    "/rest/interface/wireless",
    "/rest/interface/wireless/security-profiles",
    "/rest/interface/wireless/registration-table",
)


@dataclass
class MikrotikSimulator:
    username: str = USER
    password: str = PASSWORD
    rest_enabled: bool = True
    delay: float = 0.0
    malformed: set[str] = field(default_factory=set)
    #: Status code to answer per path instead of the data (403, 500, ...).
    fail: dict[str, int] = field(default_factory=dict)
    #: Paths the user's group may not read: HTTP 500 "not enough permissions (9)".
    no_policy: set[str] = field(default_factory=set)
    #: New DHCP servers answering ``invalid`` once ("No IP address on interface"), as the
    #: real RouterOS does for a moment after the change.
    settling: set[str] = field(default_factory=set)
    #: Installed wireless package: "wifi" (RouterOS 7 wifi), "legacy" (wireless) or "none".
    wireless: str = "wifi"
    #: ``/system/clock`` answers the current time (False: ``date`` and ``time`` as in ``data``).
    clock_ticks: bool = True
    data: dict[str, Any] = field(default_factory=sample_data)
    #: Paths requested so far (to check that nothing is sent before the pin check).
    requests: list[str] = field(default_factory=list)
    #: The user's group lacks ``write``: every write is answered with 403.
    read_only: bool = False
    #: Status code to answer per menu for writes (``/rest/ip/address``, ``/rest/export``, ...).
    fail_write: dict[str, int] = field(default_factory=dict)
    #: Answer writes with success but change nothing (to test the verification).
    ignore_writes: bool = False
    #: Writes received: (method, path, body).
    writes: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)
    #: what ``/interface/pppoe-client/monitor`` reports for a running client
    pppoe_session: dict[str, str] = field(
        default_factory=lambda: {
            "status": "connected",
            "uptime": "1d2h3m4s",
            "active-links": "1",
            "encoding": "",
            "service-name": "",
            "ac-name": "isp-bras",
            "ac-mac": _mac(9, 2),
            "mtu": "1492",
            "mru": "1492",
            "local-address": "203.0.113.77",
            "remote-address": "203.0.113.1",
        }
    )
    #: monitor refused (HTTP 500 ``not enough permissions``), as for a group without the policy
    read_only_monitor: bool = False
    next_id: int = 0x100
    #: passwords of the users in ``/rest/user`` other than ``username`` (set through REST)
    logins: dict[str, str] = field(default_factory=dict)

    def authorised(self, header: str | None) -> bool:
        if not header or not header.startswith("Basic "):
            return False
        try:
            user, _, password = base64.b64decode(header[6:]).decode().partition(":")
        except (binascii.Error, UnicodeDecodeError):
            return False
        if user in self.logins and secrets.compare_digest(password, self.logins[user]):
            return True
        return secrets.compare_digest(user, self.username) and secrets.compare_digest(
            password, self.password
        )

    def answers(self) -> dict[str, Any]:
        """``data`` without the menus of the wireless packages that are not installed."""
        absent = {
            "wifi": LEGACY_PATHS,
            "legacy": WIFI_PATHS,
        }.get(self.wireless, WIFI_PATHS + LEGACY_PATHS)
        return {k: v for k, v in self.data.items() if k not in absent}

    def app(self) -> FastAPI:
        app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
        not_found = {"error": 404, "message": "Not Found"}

        def no_such(path: str) -> JSONResponse:
            """A menu this device does not have: HTTP 400, as RouterOS 7.25 answers it."""
            name = path.rstrip("/").rsplit("/", 1)[-1]
            return _bad(f"no such command or directory ({name})")

        @app.api_route("/{path:path}", methods=["GET"])
        async def answer(path: str, request: Request) -> Response:
            path = "/" + path
            self.requests.append(path)
            if not self.rest_enabled:
                return JSONResponse(not_found, status_code=404)
            if not self.authorised(request.headers.get("authorization")):
                return JSONResponse(
                    {"error": 401, "message": "Unauthorized"},
                    status_code=401,
                    headers={"WWW-Authenticate": 'Basic realm="RouterOS"'},
                )
            if self.delay:
                await asyncio.sleep(self.delay)
            if path in self.fail:
                return JSONResponse(
                    {"error": self.fail[path], "message": "simulated failure"},
                    status_code=self.fail[path],
                )
            if path in self.no_policy:
                return JSONResponse(NO_POLICY, status_code=500)
            if path == DHCP_SERVER and self.settling:
                answer = copy.deepcopy(self.data[DHCP_SERVER])
                for row in self.data[DHCP_SERVER]:  # valid from the next read on
                    if row.get(".id") in self.settling:
                        row["invalid"] = "false"
                        row.pop(".about", None)
                self.settling.clear()
                return JSONResponse(answer)
            data = self.answers()
            if path not in data:
                return no_such(path)
            if path in self.malformed:
                return Response('[{".id": "*1", ', media_type="application/json")
            if path == CLOCK and self.clock_ticks and isinstance(data[path], dict):
                return JSONResponse(_ticking(data[path]))
            return JSONResponse(data[path])

        @app.api_route("/{path:path}", methods=["PUT", "PATCH", "DELETE", "POST"])
        async def write(path: str, request: Request) -> Response:
            path = "/" + path
            self.requests.append(path)
            if not self.rest_enabled:
                return JSONResponse(not_found, status_code=404)
            if not self.authorised(request.headers.get("authorization")):
                return JSONResponse({"error": 401, "message": "Unauthorized"}, status_code=401)
            raw = await request.body()
            try:
                body = json.loads(raw) if raw else {}
            except ValueError:
                return _bad("invalid JSON")
            if not isinstance(body, dict):
                return _bad("expected an object")
            if request.method == "POST" and path == PPPOE_MONITOR:
                return self.monitor(body)
            self.writes.append((request.method, path, body))
            return self.write(request.method, path, body)

        return app

    def monitor(self, body: dict[str, Any]) -> Response:
        """``/interface/pppoe-client/monitor <numbers> once``: the session of one client."""
        if self.read_only_monitor:
            return JSONResponse(NO_POLICY, status_code=500)
        name = str(body.get("numbers", ""))
        rows = self.answers().get(PPPOE_CLIENT, [])
        row = next((r for r in rows if name in (r.get("name"), r.get(".id"))), None)
        if row is None:  # as RouterOS 7.25.1 CHR answers an unknown client
            return JSONResponse({"error": 404, "message": "Not Found"}, status_code=404)
        if row.get("running") != "true":
            return JSONResponse([{"status": "disconnected"}])
        return JSONResponse([dict(self.pppoe_session)])

    # --- writes -------------------------------------------------------------------------------

    def write(self, method: str, path: str, body: dict[str, Any]) -> Response:
        """One write request (the HTTP layer already checked the credentials)."""
        if method == "POST" and path in (EXPORT, EXECUTE):
            menu, ref = path, ""
        elif method == "POST" and path.endswith("/unset"):
            menu, ref = path.removesuffix("/unset"), str(body.get("numbers", ""))
        elif method == "PUT":
            menu, ref = path, ""
        else:
            menu, _, ref = path.rpartition("/")
        if menu not in (EXPORT, EXECUTE) and (
            menu not in WRITABLE or not isinstance(self.answers().get(menu), list)
        ):
            return _bad(f"no such command or directory ({menu.rsplit('/', 1)[-1]})")
        if self.read_only and menu != EXPORT:
            return JSONResponse(NO_POLICY, status_code=500)
        if menu in self.fail_write:
            code = self.fail_write[menu]
            return JSONResponse({"error": code, "message": "simulated failure"}, status_code=code)
        if menu == EXPORT:  # the text goes to a terminal, which REST does not have
            return JSONResponse([])
        if menu == EXECUTE:
            if body.get("script") != "/export" or "as-string" not in body:
                return _bad("only /export with as-string is simulated")
            return JSONResponse({"ret": self.export()})
        if self.ignore_writes:
            return JSONResponse({".id": "*FFFF"} if method == "PUT" else [])
        rows: list[dict[str, Any]] = self.data[menu]
        values = {k: str(v) for k, v in body.items() if k not in (".id", "numbers")}
        password = values.pop("password", None) if menu == USER_MENU else None
        if method == "PUT":
            row = {".id": self._id(), **DEFAULTS.get(menu, {}), **values}
            problem = self._check(menu, row, rows)
            if problem:
                return _bad(problem)
            if menu == WIFI:
                row.setdefault("mac-address", _mac(0x0A, len(rows)))
            if menu == DHCP_SERVER:  # RouterOS checks the interface's address a moment later
                row.update({"invalid": "true", ".about": "No IP address on interface"})
                self.settling.add(row[".id"])
            rows.append(row)
            if password is not None:
                self.logins[row["name"]] = password
            self._settle(menu, row)
            return JSONResponse(row, status_code=201)
        found: dict[str, Any] | None = next((r for r in rows if r.get(".id") == ref), None)
        if found is None:
            return JSONResponse(
                {"error": 404, "message": "Not Found", "detail": "no such item"}, status_code=404
            )
        row = found
        if row.get("dynamic") == "true":
            return _bad("cannot change dynamic entry")
        if method == "DELETE":
            rows.remove(row)
            self.logins.pop(str(row.get("name")), None)
            self._settle(menu, None)
            return Response(status_code=204)
        if method == "POST":
            changed = {k: v for k, v in row.items() if k != values.get("value-name")}
        else:
            changed = {**row, **values}
        problem = self._check(menu, changed, [r for r in rows if r is not row])
        if problem:
            return _bad(problem)
        row.clear()
        row.update(changed)
        if password is not None:
            self.logins[row["name"]] = password
        self._settle(menu, row)
        return JSONResponse(row if method == "PATCH" else [])

    def _id(self) -> str:
        self.next_id += 1
        return f"*{self.next_id:X}"

    def _names(self, menu: str) -> set[str]:
        return {r.get("name", "") for r in self.data.get(menu, [])}

    def _check(self, menu: str, row: dict[str, Any], others: list[dict[str, Any]]) -> str | None:
        """What RouterOS would refuse about one entry (None: nothing)."""
        for key in REQUIRED.get(menu, ()):
            if not row.get(key):
                return f"missing value for {key}"
        if "name" in row and any(o.get("name") == row["name"] for o in others):
            return f"entry with name {row['name']} already exists"
        interfaces = self._names(INTERFACE)
        if menu in (VLAN, WIFI) and row["name"] in interfaces:
            before: dict[str, Any] = next(
                (o for o in self.data[menu] if o.get(".id") == row[".id"]), {}
            )
            if before.get("name") != row["name"]:
                return f"interface with name {row['name']} already exists"
        for key in REFERENCES.get(menu, ()):
            names = row.get(key, "").split(",") if key in ("tagged", "untagged") else [row[key]]
            if any(n and n not in interfaces for n in names):
                return f"input does not match any value of {key}"
        try:
            if menu in (IP_ADDRESS, DHCP_NETWORK):
                ip_interface(row["address"])
            if menu == DHCP_LEASE:
                ip_address(row["address"])
            if menu == POOL:
                for part in row["ranges"].split(","):
                    for a in part.split("-"):
                        ip_address(a)
        except ValueError:
            return "invalid value for argument address"
        if menu == VLAN and not (row["vlan-id"].isdigit() and 1 <= int(row["vlan-id"]) <= 4094):
            return "invalid value for argument vlan-id"
        if menu == DHCP_SERVER and row["address-pool"] not in self._names(POOL) | {"static-only"}:
            return "input does not match any value of address-pool"
        if menu == DHCP_LEASE and row["server"] not in self._names(DHCP_SERVER) | {"all"}:
            return "input does not match any value of server"
        master = row.get("master-interface") if menu == WIFI else None
        if master and master not in self._names(WIFI):
            return "input does not match any value of master-interface"
        return None

    def _settle(self, menu: str, row: dict[str, Any] | None) -> None:
        """What RouterOS computes itself after a change."""
        if row is not None and menu == IP_ADDRESS:
            row["network"] = str(ip_interface(row["address"]).network.network_address)
            row["actual-interface"] = row["interface"]
        data = self.data
        # /interface follows the VLAN and Wi-Fi menus
        derived = {"vlan": self._names(VLAN), "wifi": self._names(WIFI)}
        interfaces = [
            r
            for r in data[INTERFACE]
            if r.get("type") not in derived or r.get("name") in derived[r["type"]]
        ]
        known = {r.get("name") for r in interfaces}
        for kind, menu_path in (("vlan", VLAN), ("wifi", WIFI)):
            for r in data.get(menu_path, []):
                if r.get("name") not in known:
                    mac = r.get("mac-address") or _mac(1, 0)
                    interfaces.append({".id": self._id(), **_iface(r["name"], kind, mac)})
        for r in interfaces:
            if r.get("type") == "wifi":
                w: dict[str, Any] = next(
                    (x for x in data.get(WIFI, []) if x.get("name") == r.get("name")), {}
                )
                r["disabled"] = w.get("disabled", r.get("disabled", "false"))
        data[INTERFACE] = interfaces
        # dynamic bridge ports of Wi-Fi interfaces with datapath.bridge
        ports = [p for p in data[BRIDGE_PORT] if p.get("dynamic") != "true"]
        static = {p.get("interface") for p in ports}
        for w in data.get(WIFI, []):
            if w.get("datapath.bridge") and w.get("name") not in static:
                port = _port(w["name"], pvid=w.get("datapath.vlan-id") or "1")
                port.update(bridge=w["datapath.bridge"], dynamic="true")
                ports.append({".id": self._id(), **port})
        data[BRIDGE_PORT] = ports
        # the bridge VLAN table: current lists, and dynamic entries for the pvids
        off = {r.get("name") for r in interfaces if r.get("disabled") == "true"}
        bridges = {b.get("name", ""): b for b in data[BRIDGE]}

        def by_pvid(bridge: str, vid: str, tagged: list[str]) -> list[str]:
            out = [bridge] if bridges[bridge].get("pvid", "1") == vid else []
            out = [b for b in out if b not in tagged]
            for p in ports:
                if (
                    p.get("bridge") == bridge
                    and p.get("pvid", "1") == vid
                    and p.get("frame-types") != "admit-only-vlan-tagged"
                    and p.get("disabled") != "true"
                    and p.get("interface") not in off
                ):
                    out.append(p["interface"])
            return out

        entries = [e for e in data[BRIDGE_VLAN] if e.get("dynamic") != "true"]
        covered: set[tuple[str, str]] = set()
        for e in entries:
            tagged = [x for x in e.get("tagged", "").split(",") if x]
            untagged = [x for x in e.get("untagged", "").split(",") if x]
            vids = e.get("vlan-ids", "").split(",")
            bridge = e.get("bridge", "")
            covered |= {(bridge, v) for v in vids}
            pvid = by_pvid(bridge, vids[0], tagged) if len(vids) == 1 and bridge in bridges else []
            e["current-tagged"] = ",".join(tagged)
            e["current-untagged"] = ",".join(dict.fromkeys(untagged + pvid))
        dynamic = []
        for b, row_b in bridges.items():
            pvids = [row_b.get("pvid", "1")] + [
                p.get("pvid", "1") for p in ports if p.get("bridge") == b
            ]
            for vid in dict.fromkeys(pvids):
                members = by_pvid(b, vid, [])
                if (b, vid) not in covered and members:
                    dynamic.append(
                        {
                            ".id": self._id(),
                            "bridge": b,
                            "vlan-ids": vid,
                            "tagged": "",
                            "untagged": ",".join(members),
                            "current-tagged": "",
                            "current-untagged": ",".join(members),
                            "comment": "added by pvid",
                            "dynamic": "true",
                            "disabled": "false",
                        }
                    )
        data[BRIDGE_VLAN] = dynamic + entries

    def export(self) -> str:
        """A crude ``/export`` of the writable menus, secrets hidden as RouterOS does."""
        lines = ["# simulated RouterOS export"]
        for menu in WRITABLE:
            rows = [r for r in self.data.get(menu, []) if r.get("dynamic") != "true"]
            if rows:
                lines.append(menu.removeprefix("/rest"))
            for r in rows:
                props = " ".join(
                    f"{k}={v}"
                    for k, v in r.items()
                    if k not in COMPUTED and "passphrase" not in k and v != ""
                )
                lines.append(f"add {props}")
        return "\n".join(lines) + "\n"


def _ticking(clock: dict[str, Any]) -> dict[str, Any]:
    """``/system/clock`` with the current time in its ``gmt-offset`` (``+01:00``)."""
    text = str(clock.get("gmt-offset", "+00:00"))
    try:
        sign = -1 if text.startswith("-") else 1
        hours, _, minutes = text.lstrip("+-").partition(":")
        offset = timedelta(minutes=sign * (int(hours) * 60 + int(minutes or 0)))
    except ValueError:
        return clock
    now = datetime.now(UTC).astimezone(timezone(offset))
    return {**clock, "date": now.date().isoformat(), "time": now.strftime("%H:%M:%S")}


def _bad(detail: str) -> JSONResponse:
    return JSONResponse({"error": 400, "message": "Bad Request", "detail": detail}, status_code=400)


EXPORT = "/rest/export"
PPPOE_CLIENT = "/rest/interface/pppoe-client"
PPPOE_MONITOR = "/rest/interface/pppoe-client/monitor"
DHCP_CLIENT = "/rest/ip/dhcp-client"
LIST_MEMBER = "/rest/interface/list/member"
EXECUTE = "/rest/execute"
#: The answer of RouterOS 7.25.1 to a request the user's group has no policy for.
NO_POLICY = {
    "error": 500,
    "message": "Internal Server Error",
    "detail": "not enough permissions (9)",
}
INTERFACE = "/rest/interface"
BRIDGE = "/rest/interface/bridge"
VLAN = "/rest/interface/vlan"
BRIDGE_PORT = "/rest/interface/bridge/port"
BRIDGE_VLAN = "/rest/interface/bridge/vlan"
IP_ADDRESS = "/rest/ip/address"
POOL = "/rest/ip/pool"
DHCP_SERVER = "/rest/ip/dhcp-server"
DHCP_NETWORK = "/rest/ip/dhcp-server/network"
CLOCK = "/rest/system/clock"
DHCP_LEASE = "/rest/ip/dhcp-server/lease"
WIFI = "/rest/interface/wifi"
USER_MENU = "/rest/user"
USER_GROUP = "/rest/user/group"
#: Menus the simulator accepts writes for.
WRITABLE = (
    VLAN,
    BRIDGE,
    BRIDGE_VLAN,
    BRIDGE_PORT,
    IP_ADDRESS,
    POOL,
    DHCP_NETWORK,
    DHCP_SERVER,
    DHCP_LEASE,
    WIFI,
    USER_MENU,
    USER_GROUP,
)
REQUIRED = {
    VLAN: ("name", "vlan-id", "interface"),
    IP_ADDRESS: ("address", "interface"),
    BRIDGE_VLAN: ("bridge", "vlan-ids"),
    BRIDGE_PORT: ("bridge", "interface"),
    POOL: ("name", "ranges"),
    DHCP_NETWORK: ("address",),
    DHCP_SERVER: ("name", "interface"),
    DHCP_LEASE: ("address", "mac-address"),
    WIFI: ("name",),
    USER_MENU: ("name", "group"),
    USER_GROUP: ("name", "policy"),
}
#: Properties that name interfaces (checked against ``/interface``).
REFERENCES = {
    VLAN: ("interface",),
    IP_ADDRESS: ("interface",),
    BRIDGE_PORT: ("interface", "bridge"),
    BRIDGE_VLAN: ("bridge", "tagged", "untagged"),
    DHCP_SERVER: ("interface",),
}
_STATIC = {"disabled": "false", "dynamic": "false"}
DEFAULTS: dict[str, dict[str, str]] = {
    VLAN: {"mtu": "1500", "running": "true", **_STATIC},
    IP_ADDRESS: {"invalid": "false", **_STATIC},
    BRIDGE_VLAN: {"tagged": "", "untagged": "", **_STATIC},
    BRIDGE_PORT: {
        "pvid": "1",
        "frame-types": "admit-all",
        "ingress-filtering": "true",
        "inactive": "false",
        **_STATIC,
    },
    DHCP_SERVER: {
        "address-pool": "static-only",
        "lease-time": "30m",
        "invalid": "false",
        **_STATIC,
    },
    DHCP_LEASE: {"server": "all", "status": "waiting", **_STATIC},
    WIFI: {"running": "true", **_STATIC},
}
COMPUTED = {
    ".id",
    "dynamic",
    "running",
    "invalid",
    "inactive",
    "current-tagged",
    "current-untagged",
}
