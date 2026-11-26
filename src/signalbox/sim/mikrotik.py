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
``routeros6`` (a RouterOS 6 device: ``/rest`` answers its HTML page, HTTP 404),
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
import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

USER = "signalbox"
PASSWORD = "sim-password"
#: Wi-Fi passphrase of the sample SSID "Example" (to test the fingerprint).
PASSPHRASE = "correct horse battery staple"

MAC = "02:00:00:00:{:02x}:{:02x}"


def _wg_key(name: str) -> str:
    """A WireGuard key of the sample: base64 of SHA-256 of a name (valid, nobody's real key;
    computed so that no key-shaped literal is in the source)."""
    return base64.b64encode(hashlib.sha256(name.encode()).digest()).decode()


def wg_private_key(interface: str) -> str:
    """The private key the simulated router generates for an interface added through a write
    (#152): it must never leave the integration (``do-not-leak`` in the seed)."""
    return _wg_key(f"sim-wg-private-do-not-leak-{interface}")


def wg_public_key(interface: str) -> str:
    return _wg_key(f"sim-wg-public-{interface}")


#: ``wg0`` of the sample and its peers: a site and a phone (#152)
WG_KEY = _wg_key("sim-mikrotik-wg0")
WG_SITE = _wg_key("sim-mikrotik-site")
WG_PHONE = _wg_key("sim-mikrotik-phone")


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
        **({"link-downs": "1"} if kind == "ether" else {}),
        **(_traffic(running) if kind in ("ether", "bridge", "wifi") else {}),
        **kw,
    }


def _traffic(running: bool) -> dict[str, str]:
    """The counters of a ``/rest/interface`` row (fixed values, RouterOS writes numbers as text)."""
    if not running:
        return dict.fromkeys(("rx-byte", "tx-byte", "rx-packet", "tx-packet"), "0")
    return {
        "rx-byte": "73920411",
        "tx-byte": "402331874",
        "rx-packet": "611203",
        "tx-packet": "702114",
        "rx-error": "0",
        "tx-error": "0",
        "rx-drop": "4",
        "tx-drop": "0",
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
        "loop-protect": "default",
        **kw,
    }


def _port(interface: str, pvid: str = "1", frame_types: str = "admit-all") -> dict[str, Any]:
    return {
        "interface": interface,
        "bridge": "bridge",
        "pvid": pvid,
        "frame-types": frame_types,
        "ingress-filtering": "true",
        "fast-leave": "false",
        "unknown-multicast-flood": "true",
        "disabled": "false",
        "dynamic": "false",
        "inactive": "false",
    }


def _fw(chain: str, action: str, comment: str, **kw: str) -> dict[str, str]:
    """A row of ``/ip/firewall/filter`` or ``nat``."""
    return {
        "chain": chain,
        "action": action,
        "comment": comment,
        "disabled": "false",
        "dynamic": "false",
        "invalid": "false",
        "bytes": "0",
        "packets": "0",
        **kw,
    }


def firewall_data() -> dict[str, Any]:
    """The packet filter of the sample router (#135): the default configuration of RouterOS 7
    (``defconf``) plus a user chain, rules of the owner's, a destination NAT and address lists
    (documentation addresses)."""
    est = "established,related,untracked"
    lst = {"builtin": "false", "dynamic": "false", "include": "", "exclude": ""}
    entry = {"disabled": "false", "dynamic": "false"}
    return {
        "/rest/interface/list": _ids(
            {"name": "all", **lst, "builtin": "true"},
            {"name": "none", **lst, "builtin": "true"},
            {"name": "LAN", **lst},
            {"name": "WAN", **lst},
            {"name": "IOT", **lst},
            {"name": "INSIDE", **lst, "include": "LAN,IOT"},
        ),
        "/rest/ip/firewall/address-list": _ids(
            {"list": "trusted", "address": "192.0.2.10", **entry},
            {"list": "trusted", "address": "198.51.100.0/28", **entry},
            {"list": "trusted", "address": "198.51.100.64-198.51.100.79", **entry},
            {"list": "scanners", "address": "203.0.113.66", **entry, "dynamic": "true"},
        ),
        "/rest/ip/firewall/filter": _ids(
            _fw("input", "accept", "defconf: accept established", **{"connection-state": est}),
            _fw("input", "drop", "defconf: drop invalid", **{"connection-state": "invalid"}),
            _fw("input", "accept", "defconf: accept ICMP", protocol="icmp"),
            _fw("input", "accept", "defconf: accept loopback", **{"dst-address": "127.0.0.1"}),
            _fw(
                "input",
                "accept",
                "IoT: DNS",
                protocol="udp",
                **{"dst-port": "53", "in-interface": "iot"},
            ),
            _fw("input", "drop", "defconf: drop all not from LAN", **{"in-interface-list": "!LAN"}),
            _fw("forward", "accept", "defconf: accept in ipsec", **{"ipsec-policy": "in,ipsec"}),
            _fw("forward", "accept", "defconf: accept out ipsec", **{"ipsec-policy": "out,ipsec"}),
            _fw(
                "forward",
                "fasttrack-connection",
                "defconf: fasttrack",
                **{"connection-state": "established,related", "hw-offload": "true"},
            ),
            _fw("forward", "accept", "defconf: accept established", **{"connection-state": est}),
            _fw("forward", "drop", "defconf: drop invalid", **{"connection-state": "invalid"}),
            _fw(
                "forward", "jump", "IoT rules", **{"in-interface-list": "IOT", "jump-target": "iot"}
            ),
            _fw(
                "forward",
                "accept",
                "NAS from trusted hosts",
                protocol="tcp",
                **{"dst-address": "192.0.2.10", "dst-port": "443", "src-address-list": "trusted"},
            ),
            _fw("forward", "drop", "block scanners", **{"src-address-list": "scanners"}),
            _fw(
                "forward",
                "drop",
                "defconf: drop all from WAN not DSTNATed",
                **{
                    "connection-nat-state": "!dstnat",
                    "connection-state": "new",
                    "in-interface-list": "WAN",
                },
            ),
            _fw(
                "iot",
                "accept",
                "IoT: web",
                protocol="tcp",
                **{"dst-port": "80,443", "out-interface-list": "WAN"},
            ),
            _fw(
                "iot", "return", "IoT: SSH is somebody else's", protocol="tcp", **{"dst-port": "22"}
            ),
            _fw("iot", "drop", "IoT: nothing else to the LAN", **{"out-interface-list": "LAN"}),
        ),
        "/rest/ipv6/firewall/filter": _ids(
            _fw("input", "accept", "defconf: accept established", **{"connection-state": est}),
            _fw("input", "accept", "defconf: accept ICMPv6", protocol="icmpv6"),
            _fw("input", "drop", "defconf: drop all not from LAN", **{"in-interface-list": "!LAN"}),
            _fw("forward", "drop", "defconf: drop all from WAN", **{"in-interface-list": "WAN"}),
        ),
        "/rest/ip/firewall/nat": _ids(
            _fw(
                "srcnat",
                "masquerade",
                "defconf: masquerade",
                **{"ipsec-policy": "out,none", "out-interface-list": "WAN"},
            ),
            _fw(
                "dstnat",
                "dst-nat",
                "NAS web interface",
                protocol="tcp",
                **{
                    "dst-port": "8443",
                    "in-interface-list": "WAN",
                    "dst-address-type": "local",
                    "to-addresses": "192.0.2.10",
                    "to-ports": "443",
                },
            ),
        ),
        "/rest/ip/firewall/raw": [],
        "/rest/system/scheduler": [],
    }


#: shared secret and password of the simulated VPN (#153): tests assert they never leak
IPSEC_SECRET = "sim-vpn-secret-do-not-leak"


def vpn_data() -> dict[str, Any]:
    """IPsec and OpenVPN of a router (#153): opt-in (``sim.data.update(vpn_data())``). The
    menus show the secrets, as a group with the sensitive policy would see them."""
    return {
        "/rest/ip/ipsec/identity": _ids(
            {
                "peer": "site-b",
                "auth-method": "digital-signature",
                "certificate": "vpn-gateway",
                "disabled": "false",
            },
            {
                "peer": "site-c",
                "auth-method": "pre-shared-key",
                "secret": IPSEC_SECRET,
                "disabled": "false",
            },
        ),
        "/rest/ip/ipsec/peer": _ids(
            {
                "name": "site-c",
                "address": "203.0.113.50/32",
                "profile": "site-profile",
                "exchange-mode": "ike2",
                "passive": "false",
                "disabled": "false",
                "comment": "site C",
            }
        ),
        "/rest/ip/ipsec/profile": _ids(
            {
                "name": "site-profile",
                "hash-algorithm": "sha256",
                "enc-algorithm": "aes-256",
                "dh-group": "modp2048",
                "dpd-interval": "8s",
            }
        ),
        "/rest/ip/ipsec/proposal": _ids(
            {
                "name": "site-proposal",
                "auth-algorithms": "sha256",
                "enc-algorithms": "aes-256-cbc",
                "pfs-group": "modp2048",
                "lifetime": "30m",
            }
        ),
        "/rest/ip/ipsec/policy": _ids(
            {
                "peer": "site-c",
                "src-address": "192.0.2.0/24",
                "dst-address": "198.18.88.0/24",
                "proposal": "site-proposal",
                "tunnel": "true",
                "ph2-state": "established",
                "disabled": "false",
                "dynamic": "false",
            }
        ),
        "/rest/ip/ipsec/active-peers": _ids(
            {
                "remote-address": "203.0.113.50",
                "local-address": "203.0.113.1",
                "state": "established",
                "uptime": "1h2m3s",
            }
        ),
        "/rest/interface/ovpn-server/server": _ids(
            {
                "enabled": "true",
                "port": "1194",
                "protocol": "tcp",
                "cipher": "aes256-cbc,aes256-gcm",
                "certificate": "vpn-gateway",
            }
        ),
        "/rest/interface/ovpn-server": _ids(
            {
                "name": "<ovpn-laptop>",
                "user": "laptop",
                "client-address": "198.18.77.2",
                "uptime": "5m",
            }
        ),
        "/rest/interface/ovpn-client": _ids(
            {
                "name": "ovpn-out1",
                "connect-to": "203.0.113.60",
                "port": "1194",
                "protocol": "tcp",
                "cipher": "aes256-gcm",
                "user": "sim-user",
                "password": IPSEC_SECRET,
                "running": "true",
                "disabled": "false",
            }
        ),
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
            "serial-number": "SIM0000001A",  # invented
            "firmware-type": "ipq6000",
            "current-firmware": "7.15.3",
            "upgrade-firmware": "7.15.3",
        },
        "/rest/system/identity": {"name": "hap-ax2"},
        "/rest/system/history": [
            {
                ".id": "*1",
                "action": "set bridge vlan-filtering",
                "by": "admin",
                "time": "2026-11-20 10:11:12",
                "undoable": "true",
                "policy": "write",
            },
        ],
        "/rest/file": [
            {
                ".id": "*1",
                "name": "pre-change.backup",
                "type": "backup",
                "size": "180000",
                "creation-time": "2026-11-18 09:00:00",
            },
            {".id": "*2", "name": "skins", "type": "directory"},
        ],
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
            _iface("wg0", "wg", "00:00:00:00:00:00"),
            _iface("lo", "loopback", "00:00:00:00:00:00"),
        ),
        # the switch chip behind ether2-ether5: its CPU port is not an interface (#252)
        "/rest/interface/ethernet/switch/port": _ids(
            {"name": "ether2", "switch": "switch1"},
            {"name": "ether3", "switch": "switch1"},
            {"name": "ether4", "switch": "switch1"},
            {"name": "ether5", "switch": "switch1"},
            {"name": "switch1-cpu", "switch": "switch1"},
        ),
        "/rest/interface/bonding": [],
        "/rest/interface/ethernet": _ids(
            _ether("ether1", "1G-baseT-full"),
            _ether("ether2", "1Gbps"),
            _ether(
                "ether3",
                "100M-baseT-half",
                **{"auto-negotiation": "false", "advertise": "", "rx-flow-control": "on"},
            ),
            _ether("ether4", "1G-baseT-full", **{"loop-protect": "on"}),
            _ether("ether5", "1G-baseT-full"),
        ),
        # PoE-out of two ports (RouterOS boards with PoE out); ether5 is switched off
        "/rest/interface/ethernet/poe": _ids(
            {"name": "ether4", "poe-out": "auto-on", "poe-priority": "10", "poe-voltage": "auto"},
            {"name": "ether5", "poe-out": "off", "poe-priority": "10", "poe-voltage": "auto"},
        ),
        "/rest/interface/bridge": _ids(
            {
                "name": "bridge",
                "comment": "LAN",
                "vlan-filtering": "true",
                "pvid": "1",
                "frame-types": "admit-all",
                "protocol-mode": "rstp",
                "priority": "0x8000",
                "igmp-snooping": "true",
                "multicast-querier": "true",
                "igmp-version": "2",
                "mld-version": "1",
                "mac-address": bridge_mac,
                "disabled": "false",
            }
        ),
        # groups the bridge learned (IPTV in the office network, a speaker group in the IoT one)
        "/rest/interface/bridge/mdb": _ids(
            {"bridge": "bridge", "vid": "1", "group": "239.255.0.1", "ports": "ether2"},
            {"bridge": "bridge", "vid": "20", "group": "239.255.0.2", "ports": "ether4"},
        ),
        "/rest/interface/bridge/port": _ids(
            _port("ether2"),
            _port("ether3", frame_types="admit-only-untagged-and-priority-tagged"),
            {
                **_port("ether4", pvid="20", frame_types="admit-only-untagged-and-priority-tagged"),
                "edge": "yes",
                "bpdu-guard": "true",
            },
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
        **firewall_data(),
        "/rest/interface/list/member": _ids(
            {"list": "WAN", "interface": "ether1", "disabled": "false", "dynamic": "false"},
            {"list": "LAN", "interface": "bridge", "disabled": "false", "dynamic": "false"},
            {"list": "IOT", "interface": "iot", "disabled": "false", "dynamic": "false"},
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
                "address": "2001:db8:ff::4/64",
                "interface": "wg0",
                "actual-interface": "wg0",
                "disabled": "false",
                "dynamic": "false",
                "invalid": "false",
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
        # the menus return private-key and preshared-key: the adapter must drop them
        "/rest/interface/wireguard": _ids(
            {
                "name": "wg0",
                "mtu": "1420",
                "listen-port": "51820",
                "private-key": _wg_key("sim-secret-private"),
                "public-key": WG_KEY,
                "running": "true",
                "disabled": "false",
                "comment": "site link",
            }
        ),
        "/rest/interface/wireguard/peers": _ids(
            {
                "interface": "wg0",
                "name": "peer1",
                "comment": "site-b",
                "public-key": WG_SITE,
                "private-key": "",
                "preshared-key": _wg_key("sim-secret-psk"),
                "allowed-address": "2001:db8:ff::1/128,203.0.113.0/24",
                "endpoint-address": "198.51.100.77",
                "endpoint-port": "51820",
                "current-endpoint-address": "198.51.100.77",
                "current-endpoint-port": "51820",
                "persistent-keepalive": "25s",
                "last-handshake": "42s",
                "rx": "1834567",
                "tx": "2934871",
                "disabled": "false",
            },
            {
                "interface": "wg0",
                "name": "peer2",
                "public-key": WG_PHONE,
                "allowed-address": "2001:db8:ff::3/128",
                "endpoint-address": "",
                "endpoint-port": "0",
                "persistent-keepalive": "",
                "rx": "0",
                "tx": "0",
                "comment": "phone",
                "disabled": "false",
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
        "/rest/ipv6/nd": _ids(
            {
                "interface": "all",
                "managed-address-configuration": "false",
                "other-configuration": "true",
                "advertise-dns": "true",
                "dns": "2001:db8:1::1",
                "ra-lifetime": "30m",
                "ra-interval": "3m20s-10m",
                "disabled": "false",
                "dynamic": "false",
                "invalid": "false",
            }
        ),
        "/rest/ipv6/nd/prefix": _ids(
            {
                "interface": "bridge",
                "prefix": "2001:db8:1::/64",
                "autonomous": "true",
                "on-link": "true",
                "disabled": "false",
                "dynamic": "true",
                "invalid": "false",
            }
        ),
        "/rest/ipv6/dhcp-server": _ids(
            {
                "name": "dhcp6-lan",
                "interface": "bridge",
                "address-pool": "pd-pool",
                "lease-time": "3d",
                "disabled": "false",
                "dynamic": "false",
                "invalid": "false",
            }
        ),
        "/rest/ipv6/pool": _ids(
            {
                "name": "pd-pool",
                "prefix": "2001:db8:2::/48",
                "prefix-length": "56",
                "dynamic": "false",
            }
        ),
        "/rest/interface/pppoe-client": [],
        # as RouterOS 7.25.1 (CHR) answers: ``available-from``, dynamic rows for the resolver and
        # open connections, a ``reverse-proxy`` row that is no service of the adapter's list
        # Certificates (#330), as RouterOS 7 lists them: public data and the ``private-key`` flag.
        # *Guess* until a CHR run says otherwise: the date and ``key-size`` formats.
        "/rest/certificate": _ids(
            {
                "name": "signalbox-ca",
                "common-name": "signalbox-ca",
                "issuer": "CN=signalbox-ca",
                "key-type": "rsa",
                "key-size": "2048",
                "digest-algorithm": "sha256",
                "fingerprint": "a1" * 32,
                "invalid-before": "2026-01-01T00:00:00",
                "invalid-after": "2036-01-01T00:00:00",
                "key-usage": "key-cert-sign,crl-sign",
                "akid": "0a0b",
                "skid": "0a0b",
                "authority": "true",
                "trusted": "true",
                "private-key": "true",
            },
            {
                "name": "signalbox-www",
                "common-name": "router",
                "issuer": "CN=signalbox-ca",
                "subject-alt-name": "DNS:router.lab.example,IP:192.0.2.1",
                "key-type": "rsa",
                "key-size": "2048",
                "digest-algorithm": "sha256",
                "fingerprint": "b2" * 32,
                "invalid-before": "2026-01-01T00:00:00",
                "invalid-after": "2031-01-01T00:00:00",
                "akid": "0a0b",
                "skid": "0c0d",
                "authority": "false",
                "trusted": "false",
                "private-key": "true",
            },
            {
                "name": "vpn-gateway",
                "common-name": "vpn.lab.example",
                "issuer": "CN=signalbox-ca",
                "key-type": "rsa",
                "key-size": "3072",
                "digest-algorithm": "sha256",
                "fingerprint": "c3" * 32,
                "invalid-before": "2026-01-01T00:00:00",
                "invalid-after": "2031-01-01T00:00:00",
                "akid": "0a0b",
                "skid": "0e0f",
                "authority": "false",
                "trusted": "false",
                "private-key": "true",
            },
        ),
        "/rest/ip/ipsec/identity": _ids(
            {
                "peer": "site-b",
                "auth-method": "digital-signature",
                "certificate": "vpn-gateway",
                "disabled": "false",
            }
        ),
        # Routes (#149), as RouterOS 7 lists the table: the default route learned from DHCP on
        # ether1, a static lab route (2nd router on the bridge) with a disabled twin, a
        # blackhole, and the connected networks (left out by the adapter). *guess* (#21).
        "/rest/ip/route": _ids(
            {
                "dst-address": "0.0.0.0/0",
                "gateway": "203.0.113.1",
                "distance": "1",
                "routing-table": "main",
                "dhcp": "true",
                "dynamic": "true",
                "active": "true",
                "disabled": "false",
            },
            {
                "dst-address": "198.18.20.0/24",
                "gateway": "192.0.2.254",
                "distance": "1",
                "routing-table": "main",
                "static": "true",
                "dynamic": "false",
                "active": "true",
                "disabled": "false",
            },
            {
                "dst-address": "198.18.30.0/24",
                "gateway": "192.0.2.254",
                "distance": "1",
                "routing-table": "main",
                "static": "true",
                "dynamic": "false",
                "active": "false",
                "disabled": "true",
            },
            {
                "dst-address": "198.18.99.0/24",
                "distance": "1",
                "routing-table": "main",
                "static": "true",
                "blackhole": "true",
                "active": "true",
                "disabled": "false",
            },
            {
                "dst-address": "192.0.2.0/24",
                "gateway": "bridge",
                "distance": "0",
                "routing-table": "main",
                "connect": "true",
                "dynamic": "true",
                "active": "true",
                "disabled": "false",
            },
        ),
        "/rest/ipv6/route": _ids(
            {
                "dst-address": "::/0",
                "gateway": "fe80::1%ether1",
                "distance": "1",
                "routing-table": "main",
                "dynamic": "true",
                "active": "true",
                "disabled": "false",
            },
        ),
        "/rest/routing/rule": _ids(
            {
                "src-address": "198.51.100.0/24",
                "action": "lookup",
                "table": "iot-out",
                "disabled": "false",
            },
        ),
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
        UPNP: {
            "allow-disable-external-interface": "false",
            "enabled": "false",
            "show-dummy-rule": "true",
        },
        UPNP_INTERFACES: _ids(
            {
                "interface": "bridge",
                "type": "internal",
                "forced-ip": "0.0.0.0",
                "disabled": "false",
            },
            {
                "interface": "ether1",
                "type": "external",
                "forced-ip": "0.0.0.0",
                "disabled": "false",
            },
        ),
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
        # RouterOS' four default actions plus a remote action "syslog" the user added (#180)
        "/rest/system/logging/action": _ids(
            {"name": "memory", "target": "memory", "memory-lines": "1000", "default": "true"},
            {"name": "disk", "target": "disk", "disk-file-name": "log", "default": "true"},
            {"name": "echo", "target": "echo", "remember": "true", "default": "true"},
            {
                "name": "remote",
                "target": "remote",
                "remote": "0.0.0.0",
                "remote-port": "514",
                "src-address": "0.0.0.0",
                "bsd-syslog": "false",
                "syslog-facility": "daemon",
                "syslog-severity": "auto",
                "default": "true",
            },
            {
                "name": "syslog",
                "target": "remote",
                "remote": "192.0.2.5",
                "remote-port": "514",
                "src-address": "0.0.0.0",
                "bsd-syslog": "false",
                "syslog-facility": "daemon",
                "syslog-severity": "auto",
                "default": "false",
            },
        ),
        "/rest/system/logging": _ids(
            {"topics": "info", "action": "memory", "disabled": "false", "invalid": "false"},
            {"topics": "error", "action": "memory", "disabled": "false", "invalid": "false"},
            {"topics": "warning", "action": "memory", "disabled": "false", "invalid": "false"},
            {"topics": "critical", "action": "echo", "disabled": "false", "invalid": "false"},
            {"topics": "info", "action": "syslog", "disabled": "false", "invalid": "false"},
            {"topics": "warning", "action": "syslog", "disabled": "false", "invalid": "false"},
        ),
        "/rest/ip/traffic-flow": {
            "enabled": "false",
            "interfaces": "all",
            "cache-entries": "32k",
            "active-flow-timeout": "30m",
            "inactive-flow-timeout": "15s",
            "packet-sampling": "false",
        },
        "/rest/ip/traffic-flow/target": [],
        "/rest/ip/cloud": {  # after a cloud update (CHR in CI without one: no public-address)
            "ddns-enabled": "auto",
            "dns-name": "abc123def456.sn.mynetname.invalid",
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
        # the rogue DHCP detector (#184): RouterOS lists the MACs of servers that answered on
        # the interface and are not in valid-server; none here
        "/rest/ip/dhcp-server/alert": _ids(
            {
                "interface": "bridge",
                "valid-server": _mac(0, 1),
                "unknown-server": "",
                "alert-timeout": "1h",
                "disabled": "false",
                "invalid": "false",
            }
        ),
        # queues (#166, guess: field names): cake on the WAN through a queue tree, one simple
        # queue limiting a network, and the types
        "/rest/queue/type": _ids(
            {"name": "cake-default", "kind": "cake"},
            {"name": "default-small", "kind": "pfifo"},
        ),
        "/rest/queue/simple": _ids(
            {
                "name": "guests",
                "target": "198.51.100.0/24",
                "max-limit": "5M/20M",
                "queue": "default-small/default-small",
                "disabled": "false",
                "dynamic": "false",
            }
        ),
        "/rest/queue/tree": _ids(
            {
                "name": "wan-up",
                "parent": "ether1",
                "max-limit": "18M",
                "queue": "cake-default",
                "disabled": "false",
            }
        ),
        # hotspot (#460): click-through (trial login) on the main network
        "/rest/ip/hotspot": _ids(
            {
                "name": "hotspot1",
                "interface": "bridge",
                "profile": "hsprof1",
                "idle-timeout": "5m",
                "disabled": "false",
                "invalid": "false",
            }
        ),
        "/rest/ip/hotspot/profile": _ids(
            {"name": "hsprof1", "login-by": "trial,cookie", "use-radius": "no"}
        ),
        "/rest/ip/hotspot/user/profile": _ids({"name": "default", "session-timeout": "8h"}),
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
            "mdns-repeat-ifaces": "bridge,iot",
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
                "age": "1m5s",
                "vlan-id": "1",
                "system-caps": "bridge,router,wlan-ap",
                "system-caps-enabled": "bridge,router",
                "system-description": "MikroTik RouterOS 7.15.3 CRS326-24G-2S+",
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
                "ft-mobility-domain": "44481",
                "ft-reassociation-deadline": "20s",
                "ft-nas-identifier": "02aabbcc0001",
            }
        ),
        "/rest/interface/wifi/channel": [],
        # what the radios support (#172); field names from RouterOS 7.13 ``/interface/wifi/radio
        # print`` *(guess: REST spelling, the ``interface`` column)*
        "/rest/interface/wifi/radio": _ids(
            {
                "interface": "wifi1",
                "radio-mac": _mac(0, 6),
                "phy-id": "wifi1",
                "tx-chains": "0,1",
                "rx-chains": "0,1",
                "bands": "2ghz-g,2ghz-n,2ghz-ax",
                "countries": "all",
                "2g-channels": ",".join(str(2407 + 5 * c) for c in range(1, 14)),
                "ciphers": "tkip,ccmp,gcmp,ccmp-256,gcmp-256,cmac,gmac,cmac-256,gmac-256",
                "max-interfaces": "16",
            },
            {
                "interface": "wifi2",
                "radio-mac": _mac(0, 7),
                "phy-id": "wifi2",
                "tx-chains": "0,1,2,3",
                "rx-chains": "0,1,2,3",
                "bands": "5ghz-a,5ghz-n,5ghz-ac,5ghz-ax",
                "countries": "all",
                "5g-channels": ",".join(
                    str(5000 + 5 * c) for c in [*range(36, 65, 4), *range(100, 141, 4)]
                ),
                "ciphers": "tkip,ccmp,gcmp,ccmp-256,gcmp-256,cmac,gmac,cmac-256,gmac-256",
                "max-interfaces": "16",
            },
        ),
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
                "tx-rate": "286.7Mbps-20MHz-2S",
                "rx-rate": "172.0Mbps-20MHz-2S",
                "auth-type": "wpa2-psk ft",
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
            {
                "interface": "wlan1",
                "mac-address": _mac(0, 0x23),
                "signal-strength": "-55dBm",
                "tx-rate": "144.4Mbps-20MHz/2S/SGI",
                "rx-rate": "130Mbps-20MHz/2S",
                "uptime": "3d2h",
            }
        ),
    }


WIFI_PATHS = (
    "/rest/interface/wifi",
    "/rest/interface/wifi/configuration",
    "/rest/interface/wifi/security",
    "/rest/interface/wifi/channel",
    "/rest/interface/wifi/registration-table",
    "/rest/interface/wifi/radio",
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
    #: A RouterOS 6 device: no REST API, every path answers its HTML web page (HTTP 404)
    routeros6: bool = False
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
    #: what ``/interface/bonding/monitor-slaves bond=<name> once`` reports per bond (#157)
    bond_members: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    #: what ``/interface/bridge/monitor`` reports (#155): the bridge is the root bridge
    bridge_monitor: dict[str, str] = field(
        default_factory=lambda: {
            "state": "enabled",
            "current-mac-address": _mac(1, 0).upper(),
            "root-bridge": "true",
            "root-bridge-id": f"0x8000.{_mac(1, 0).upper()}",
            "root-path-cost": "0",
            # the querier the bridge sees (this router: the field name is a guess, #21)
            "multicast-querier-address": "192.0.2.1",
            "port-count": "6",
            "designated-port-count": "5",
        }
    )
    #: ``/interface/bridge/port/monitor`` per interface; the rest are designated and forwarding
    port_monitor: dict[str, dict[str, str]] = field(
        default_factory=lambda: {
            "ether3": {"role": "alternate-port", "forwarding": "false", "learning": "false"},
            "ether4": {"edge-port": "true"},
            "ether5": {"status": "inactive", "role": "disabled-port", "forwarding": "false"},
        }
    )
    #: ``/interface/ethernet/poe/monitor once`` per port (a camera on ether4)
    poe_monitor: dict[str, dict[str, str]] = field(
        default_factory=lambda: {
            "ether4": {
                "name": "ether4",
                "poe-out-status": "powered-on",
                "poe-out-voltage": "48.1V",
                "poe-out-current": "120mA",
                "poe-out-power": "5.8W",
            },
        }
    )
    next_id: int = 0x100
    #: Traceroutes (#253): target -> hops (address or None, RTT in ms); a target not listed
    #: answers through one router (192.0.2.254) and then itself.
    routes: dict[str, list[tuple[str | None, float | None]]] = field(default_factory=dict)
    #: Traceroute requests received (bodies).
    traces: list[dict[str, Any]] = field(default_factory=list)
    #: passwords of the users in ``/rest/user`` other than ``username`` (set through REST)
    logins: dict[str, str] = field(default_factory=dict)
    #: A login set through REST is refused with 401 this many times first (RouterOS applies a new
    #: user or password a moment later, #520); ``refusals`` counts what is left per user.
    login_lag: int = 0
    refusals: dict[str, int] = field(default_factory=dict)
    #: Errors of the scripts the scheduler ran (a line RouterOS would have refused).
    script_errors: list[str] = field(default_factory=list)

    def authorised(self, header: str | None) -> bool:
        if not header or not header.startswith("Basic "):
            return False
        try:
            user, _, password = base64.b64decode(header[6:]).decode().partition(":")
        except (binascii.Error, UnicodeDecodeError):
            return False
        if user in self.logins and secrets.compare_digest(password, self.logins[user]):
            if self.refusals.get(user, 0) > 0:
                self.refusals[user] -= 1
                return False
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
            if self.routeros6:
                return Response(
                    "<html><body>RouterOS router configuration page</body></html>",
                    status_code=404,
                    media_type="text/html",
                )
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
            if request.method == "POST" and path == BONDING_MONITOR:
                if self.read_only_monitor:
                    return JSONResponse(NO_POLICY, status_code=500)
                return JSONResponse(self.bond_members.get(str(body.get("bond", "")), []))
            if request.method == "POST" and path in (BRIDGE_MONITOR, BRIDGE_PORT_MONITOR):
                return self.stp_monitor(path, body)
            if request.method == "POST" and path == POE_MONITOR:
                if self.read_only_monitor:
                    return JSONResponse(NO_POLICY, status_code=500)
                return JSONResponse(
                    [
                        self.poe_monitor.get(name, {"name": name, "poe-out-status": "off"})
                        for name in str(body.get("numbers", "")).split(",")
                    ]
                )
            if request.method == "POST" and path == TRACEROUTE:
                return self.traceroute(path, body)
            self.writes.append((request.method, path, body))
            return self.write(request.method, path, body)

        return app

    def traceroute(self, path: str, body: dict[str, Any]) -> Response:
        """``/tool/traceroute`` once (#253): one row per hop, ``.section`` 0; refused like
        RouterOS 7.25 without the policy test when ``path`` is in ``no_policy``."""
        if path in self.no_policy:
            return JSONResponse(NO_POLICY, status_code=500)
        self.traces.append(dict(body))
        host = str(body.get("address", ""))
        if not host:
            return _bad("missing address")
        hops = self.routes.get(host, [("192.0.2.254", 0.4), (host, 1.2)])
        hops = hops[: int(str(body.get("max-hops", "30")) or 30)]
        rows = [
            {
                ".section": "0",
                "address": addr or "",
                "loss": "0%" if addr else "100%",
                "sent": "1",
                "last": f"{rtt}ms" if rtt is not None else "timeout",
                "avg": f"{rtt}" if rtt is not None else "",
                "status": "" if addr else "timeout",
            }
            for addr, rtt in hops
        ]
        return JSONResponse(rows)

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

    def stp_monitor(self, path: str, body: dict[str, Any]) -> Response:
        """``/interface/bridge/monitor`` and ``/interface/bridge/port/monitor`` with ``once``
        (#155): one row per entry of ``numbers`` (``.id`` or name)."""
        if self.read_only_monitor:
            return JSONResponse(NO_POLICY, status_code=500)
        menu = "/rest/interface/bridge" if path == BRIDGE_MONITOR else "/rest/interface/bridge/port"
        rows = self.answers().get(menu, [])
        out: list[dict[str, str]] = []
        for number in str(body.get("numbers", "")).split(","):
            row = next(
                (r for r in rows if number in (r.get(".id"), r.get("name"), r.get("interface"))),
                None,
            )
            if row is None:
                return _bad("no such item")
            if path == BRIDGE_MONITOR:
                out.append(dict(self.bridge_monitor))
                continue
            name = str(row.get("interface"))
            out.append(
                {
                    "interface": name,
                    "status": "in-bridge",
                    "port-number": str(len(out) + 1),
                    "role": "designated-port",
                    "edge-port": "false",
                    "point-to-point-port": "true",
                    "sending-rstp": "true",
                    "learning": "true",
                    "forwarding": "true",
                    "actual-path-cost": "20000",
                    **self.port_monitor.get(name, {}),
                }
            )
        return JSONResponse(out)

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
        if method == "POST" and path == UPNP + "/set":
            if self.read_only:
                return JSONResponse(NO_POLICY, status_code=500)
            if UPNP in self.fail_write:
                code = self.fail_write[UPNP]
                return JSONResponse(
                    {"error": code, "message": "simulated failure"}, status_code=code
                )
            if not self.ignore_writes and "enabled" in body:
                self.data[UPNP]["enabled"] = _truth(str(body["enabled"]))
            return JSONResponse(self.data[UPNP])
        if method == "POST" and path == SNMP + "/set":
            if self.read_only:
                return JSONResponse(NO_POLICY, status_code=500)
            if SNMP in self.fail_write:
                code = self.fail_write[SNMP]
                return JSONResponse(
                    {"error": code, "message": "simulated failure"}, status_code=code
                )
            if not self.ignore_writes and "enabled" in body:
                self.data[SNMP]["enabled"] = _truth(str(body["enabled"]))
            return JSONResponse(self.data[SNMP])
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
        before = values.pop("place-before", None)
        if method == "PUT":
            row = {".id": self._id(), **DEFAULTS.get(menu, {}), **values}
            problem = self._check(menu, row, rows)
            if problem:
                return _bad(problem)
            if menu == WIFI:
                row.setdefault("mac-address", _mac(0x0A, len(rows)))
            self._generate_keys(menu, row)
            if menu == DHCP_SERVER:  # RouterOS checks the interface's address a moment later
                row.update({"invalid": "true", ".about": "No IP address on interface"})
                self.settling.add(row[".id"])
            if before is not None:
                spot = next((i for i, r in enumerate(rows) if r.get(".id") == before), None)
                if spot is None:
                    return _bad("input does not match any value of place-before")
                rows.insert(spot, row)
            else:
                rows.append(row)
            if password is not None:
                self.logins[row["name"]] = password
                self.refusals[row["name"]] = self.login_lag
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
            if values.get("value-name") == "disabled" and menu in (FW_FILTER, FW_FILTER6, FW_NAT):
                return _bad("input does not match any value of value-name")  # as the CHR (#331)
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
            self.refusals[row["name"]] = self.login_lag
        self._settle(menu, row)
        return JSONResponse(row if method == "PATCH" else [])

    # --- the revert timer of firewall changes (#295) -------------------------------------------

    def fire_scheduler(self) -> int:
        """Run every ``/system/scheduler`` entry now, as the router does when its time comes
        (the script of ``on-event``); an entry with ``interval=0s`` stays after it ran."""
        fired = 0
        for row in list(self.data[SCHEDULER]):
            fired += 1
            try:
                for line in str(row.get("on-event", "")).splitlines():
                    self._script_line(line)
            except ValueError as exc:
                self.script_errors.append(str(exc))
        return fired

    def _script_line(self, line: str) -> None:
        words = _script_words(line)
        if not words:
            return
        if words[:3] == ["/ip", "upnp", "set"]:
            values = dict(a.split("=", 1) for a in words[3:])
            self.data[UPNP]["enabled"] = _truth(values.get("enabled", "yes"))
            return
        if words[:2] == ["/snmp", "set"]:
            values = dict(a.split("=", 1) for a in words[2:])
            self.data[SNMP]["enabled"] = _truth(values.get("enabled", "yes"))
            return
        at = next((i for i, w in enumerate(words) if w in SCRIPT_VERBS), None)
        if at is None:
            raise ValueError(f"unsupported script line: {line}")
        menu = SCRIPT_MENUS.get(" ".join(words[:at]))
        if menu is None:
            raise ValueError(f"unsupported menu in the script: {line}")
        rows: list[dict[str, Any]] = self.data[menu]
        verb, args = words[at], words[at + 1 :]
        if verb == "add":
            props = dict(a.split("=", 1) for a in args)
            before = props.pop("place-before", None)
            if before and before.startswith("*"):
                found = [r for r in rows if r.get(".id") == before]
            else:
                found = self._found(rows, before) if before else []
            row = {".id": self._id(), **DEFAULTS.get(menu, {}), **props}
            problem = self._check(menu, row, rows)
            if problem:
                raise ValueError(f"{problem}: {line}")
            self._generate_keys(menu, row)
            spot = next((i for i, r in enumerate(rows) if found and r is found[0]), len(rows))
            rows.insert(spot, row)
            return
        matched = self._found(rows, args[0])
        if verb == "remove":
            for row in matched:
                rows.remove(row)
        elif verb == "set":
            for row in matched:
                row.update(dict(a.split("=", 1) for a in args[1:]))
        else:
            for row in matched:
                row.pop(args[1], None)

    @staticmethod
    def _found(rows: list[dict[str, Any]], expr: str) -> list[dict[str, Any]]:
        """``[find where name="x"]`` (also ``a=x and b=y``): the rows with those values;
        ``*1F``: the row with that id."""
        if re.fullmatch(r"\*[0-9A-F]+", expr):
            return [r for r in rows if r.get(".id") == expr]
        m = re.fullmatch(r"\[find where (.*)\]", expr)
        if m is None:
            raise ValueError(f"unsupported find expression: {expr}")
        tests = []
        for part in m.group(1).split(" and "):
            key, eq, value = part.partition("=")
            if not eq or not re.fullmatch(r"[\w-]+", key):
                raise ValueError(f"unsupported find expression: {expr}")
            tests.append((key, _script_words(value)[0]))
        return [r for r in rows if all(r.get(k) == v for k, v in tests)]

    def _check_firewall(self, menu: str, row: dict[str, Any]) -> str | None:
        """What RouterOS refuses about a filter or NAT row (the cases the writer must avoid)."""
        chain, action = row.get("chain", ""), row.get("action", "")
        nat = menu == FW_NAT
        if nat != (chain in ("srcnat", "dstnat")) or not chain:
            return "input does not match any value of chain"
        if action not in (NAT_ACTIONS if nat else FILTER_ACTIONS):
            return "input does not match any value of action"
        lists = {r.get("name") for r in self.data[INTERFACE_LIST]}
        for key in ("in-interface-list", "out-interface-list"):
            if row.get(key) and row[key].removeprefix("!") not in lists:
                return f"input does not match any value of {key}"
        if chain in ("input", "dstnat") and row.get("out-interface-list"):
            return "out-interface-list is not valid in this chain"
        if chain in ("output", "srcnat") and row.get("in-interface-list"):
            return "in-interface-list is not valid in this chain"
        if (row.get("dst-port") or row.get("src-port")) and row.get("protocol") not in (
            "tcp",
            "udp",
        ):
            return "ports are valid only with protocol tcp or udp"
        for key in ("src-address", "dst-address", "to-addresses"):
            for part in row.get(key, "").removeprefix("!").split(","):
                if not part:
                    continue
                try:
                    nets = [ip_network(a, strict=False) for a in part.split("-")]
                except ValueError:
                    return f"invalid value for argument {key}"
                if any((n.version == 6) != (menu == FW_FILTER6) for n in nets):
                    return f"invalid value for argument {key}"
        for key in ("dst-port", "src-port", "to-ports"):
            for part in row.get(key, "").removeprefix("!").split(","):
                if part and not all(p.isdigit() and 0 < int(p) < 65536 for p in part.split("-")):
                    return f"invalid value for argument {key}"
        if action == "dst-nat" and not row.get("to-addresses"):
            return "missing value for to-addresses"
        if row.get("disabled", "false") not in ("true", "false", "yes", "no"):
            return "invalid value for argument disabled"
        return None

    def _check_scheduler(self, row: dict[str, Any]) -> str | None:
        try:
            datetime.strptime(row.get("start-time", ""), "%H:%M:%S")
        except ValueError:
            return "invalid value for argument start-time"
        date = row.get("start-date", "")
        try:
            if "/" in date:
                datetime.strptime(date.title(), "%b/%d/%Y")
            else:
                datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            return "invalid value for argument start-date"
        if not row.get("on-event"):
            return "missing value for on-event"
        unknown = set(filter(None, row.get("policy", "").split(","))) - POLICIES
        return (
            f"invalid value for argument policy ({','.join(sorted(unknown))})" if unknown else None
        )

    def _generate_keys(self, menu: str, row: dict[str, Any]) -> None:
        """RouterOS generates the key pair of a WireGuard interface added without a
        ``private-key`` (#152); the simulated private key is marked ``do-not-leak``."""
        if menu == WG_MENU and not row.get("private-key"):
            name = str(row.get("name"))
            row["private-key"] = wg_private_key(name)
            row["public-key"] = wg_public_key(name)
            row.setdefault("running", "true")
            row.setdefault("disabled", "false")
        if menu == WG_PEERS:
            row.setdefault("private-key", "")
            row.setdefault("disabled", "false")

    def _id(self) -> str:
        self.next_id += 1
        return f"*{self.next_id:X}"

    def _names(self, menu: str) -> set[str]:
        return {r.get("name", "") for r in self.data.get(menu, [])}

    def _check(self, menu: str, row: dict[str, Any], others: list[dict[str, Any]]) -> str | None:
        """What RouterOS would refuse about one entry (None: nothing)."""
        if menu in (FW_FILTER, FW_FILTER6, FW_NAT):
            return self._check_firewall(menu, row)
        if menu == SCHEDULER:
            return self._check_scheduler(row)
        if menu == IP_ROUTE:
            distance = row.get("distance", "1")
            if not distance.isdigit() or not 1 <= int(distance) <= 255:
                return "invalid value for argument distance"
            if row.get("check-gateway", "ping") not in ("arp", "ping", "bfd", "bfd-multihop"):
                return "invalid value for argument check-gateway"
        for key in REQUIRED.get(menu, ()):
            if not row.get(key):
                return f"missing value for {key}"
        if menu == LOG_RULES and row["action"] not in self._names(LOG_ACTION):
            return "input does not match any value of action"
        if menu == LOG_ACTION and row["target"] == "remote":
            try:
                ip_address(row.get("remote", "0.0.0.0"))
            except ValueError:
                return "invalid value for argument remote"
            if row.get("remote-protocol", "udp") not in ("udp", "tcp"):
                return "input does not match any value of remote-protocol"
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
        derived = {
            "vlan": self._names(VLAN),
            "wifi": self._names(WIFI),
            "wg": self._names(WG_MENU),
        }
        interfaces = [
            r
            for r in data[INTERFACE]
            if r.get("type") not in derived or r.get("name") in derived[r["type"]]
        ]
        known = {r.get("name") for r in interfaces}
        for kind, menu_path in (("vlan", VLAN), ("wifi", WIFI), ("wg", WG_MENU)):
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
        """A crude ``/export`` of the writable menus, passphrases hidden as RouterOS does;
        WireGuard keys are shown, as an export with ``show-sensitive`` has them, so that the
        integration's removal of them is tested (#152)."""
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


def _truth(text: str) -> str:
    return "true" if text.lower() in ("yes", "true", "on") else "false"


def _bad(detail: str) -> JSONResponse:
    return JSONResponse({"error": 400, "message": "Bad Request", "detail": detail}, status_code=400)


FW_FILTER = "/rest/ip/firewall/filter"
FW_FILTER6 = "/rest/ipv6/firewall/filter"
FW_NAT = "/rest/ip/firewall/nat"
SCHEDULER = "/rest/system/scheduler"
LOG_ACTION = "/rest/system/logging/action"
LOG_RULES = "/rest/system/logging"
SNMP = "/rest/snmp"
INTERFACE_LIST = "/rest/interface/list"
IP_ROUTE = "/rest/ip/route"
IPV6_ROUTE = "/rest/ipv6/route"
IPV6_ADDRESS_MENU = "/rest/ipv6/address"
WG_MENU = "/rest/interface/wireguard"
WG_PEERS = "/rest/interface/wireguard/peers"
NETWATCH = "/rest/tool/netwatch"
#: UPnP (#176; written since #513)
UPNP = "/rest/ip/upnp"
UPNP_INTERFACES = "/rest/ip/upnp/interfaces"
SCRIPT_VERBS = ("add", "remove", "set", "unset")
SCRIPT_MENUS = {
    "/ip firewall filter": FW_FILTER,
    "/ipv6 firewall filter": FW_FILTER6,
    "/ip firewall nat": FW_NAT,
    "/system scheduler": SCHEDULER,
    "/system logging action": LOG_ACTION,
    "/system logging": LOG_RULES,
    "/ip route": IP_ROUTE,
    "/tool netwatch": NETWATCH,
    "/ipv6 route": IPV6_ROUTE,
    "/ip address": "/rest/ip/address",
    "/ipv6 address": IPV6_ADDRESS_MENU,
    "/interface wireguard": WG_MENU,
    "/interface wireguard peers": WG_PEERS,
    "/ip upnp interfaces": UPNP_INTERFACES,
}
FILTER_ACTIONS = frozenset(
    {"accept", "drop", "reject", "jump", "return", "passthrough", "log", "tarpit"}
)
NAT_ACTIONS = frozenset({"dst-nat", "src-nat", "masquerade", "redirect", "accept", "jump"})
POLICIES = frozenset(
    {"read", "write", "test", "policy", "reboot", "ftp", "password", "sniff", "sensitive", "romon"}
)


def _script_words(line: str) -> list[str]:
    """The words of one script line: quoted strings unquoted (with their backslash escapes),
    ``[find where x="y"]`` kept whole with its quotes."""
    words: list[str] = []
    cur, depth, quoted, started, i = "", 0, False, False, 0
    while i < len(line):
        ch = line[i]
        if quoted:
            if ch == "\\" and i + 1 < len(line):
                i += 1
                cur += ("\\" if depth else "") + line[i]
            elif ch == '"':
                quoted = False
                cur += ch if depth else ""
            else:
                cur += ch
        elif ch == '"':
            quoted, started = True, True
            cur += ch if depth else ""
        elif ch in "[]":
            depth += 1 if ch == "[" else -1
            cur += ch
        elif ch == " " and not depth:
            if cur or started:
                words.append(cur)
            cur, started = "", False
        else:
            cur += ch
        i += 1
    if cur or started:
        words.append(cur)
    return words


EXPORT = "/rest/export"
PPPOE_CLIENT = "/rest/interface/pppoe-client"
PPPOE_MONITOR = "/rest/interface/pppoe-client/monitor"
BONDING_MONITOR = "/rest/interface/bonding/monitor-slaves"


def add_bond(sim: MikrotikSimulator, mode: str = "802.3ad") -> MikrotikSimulator:
    """A LAG ``bond1`` over two more ports, ether6 and ether7 (#157): LACP with the hash over
    layer 3 and 4, fast LACPDUs; ether7 is up but not aggregated (no LACP partner). The
    ``monitor-slaves`` fields are taken from the RouterOS manual, not a real device (#21)."""

    def extend(path: str, *rows: dict[str, Any]) -> None:
        old = [{k: v for k, v in r.items() if k != ".id"} for r in sim.data[path]]
        sim.data[path] = _ids(*old, *rows)

    extend(
        "/rest/interface",
        _iface("ether6", "ether", _mac(0, 0x16), slave="true"),
        _iface("ether7", "ether", _mac(0, 0x16), slave="true"),
        _iface("bond1", "bond", _mac(0, 0x16), comment="nas"),
    )
    extend("/rest/interface/ethernet", _ether("ether6", "1Gbps"), _ether("ether7", "1Gbps"))
    sim.data["/rest/interface/bonding"] = _ids(
        {
            "name": "bond1",
            "mode": mode,
            "slaves": "ether6,ether7",
            "transmit-hash-policy": "layer-3-and-4",
            "lacp-rate": "1sec",
            "lacp-mode": "active",
            "min-links": "1",
            "mtu": "1500",
            "disabled": "false",
            "running": "true",
            "comment": "nas",
        }
    )
    common = {"partner-sys-priority": "65535"}
    sim.bond_members["bond1"] = [
        {
            "interface": "ether6",
            "active": "true",
            "lacp-port-number": "1",
            "actor-state": "active,short-timeout,aggregation,synchronization,collecting,"
            "distributing",
            "partner-sys-id": "02:00:00:00:30:01",
            "partner-port-number": "1",
            "partner-key": "9",
            "partner-state": "active,short-timeout,aggregation,synchronization,collecting,"
            "distributing",
            **common,
        },
        {
            "interface": "ether7",
            "active": "false",
            "lacp-port-number": "2",
            "actor-state": "active,short-timeout,aggregation,defaulted",
            "partner-sys-id": "00:00:00:00:00:00",
            "partner-port-number": "0",
            "partner-key": "0",
            "partner-state": "",
            **common,
        },
    ]
    return sim


def add_second_wan(sim: MikrotikSimulator) -> MikrotikSimulator:
    """Two static default routes as a failover group (#150, #463): the cable line through
    203.0.113.1 (distance 1, ``check-gateway=ping``, comment ``cable``) instead of the DHCP
    one, and an LTE router at 198.51.100.1 (distance 5, comment ``lte``) watched by a netwatch
    entry with the same comment that pings 203.0.113.53. Fields from the RouterOS manual, not a
    real device (#21)."""
    routes = [r for r in sim.data[IP_ROUTE] if r.get("dst-address") != "0.0.0.0/0"]
    common = {"dst-address": "0.0.0.0/0", "routing-table": "main", "static": "true"}
    common |= {"dynamic": "false", "disabled": "false"}
    cable = {"gateway": "203.0.113.1", "distance": "1", "check-gateway": "ping"}
    cable |= {"comment": "cable", "active": "true", **common}
    lte = {"gateway": "198.51.100.1", "distance": "5", "comment": "lte", "active": "false"}
    sim.data[IP_ROUTE] = [*routes, *({".id": sim._id(), **r} for r in (cable, lte | common))]
    sim.data[NETWATCH] = [
        {
            ".id": sim._id(),
            "host": "203.0.113.53",
            "status": "up",
            "interval": "10s",
            "comment": "lte",
            "disabled": "false",
            "up-script": "/ip route enable [find comment=lte]",
            "down-script": "/ip route disable [find comment=lte]",
        }
    ]
    return sim


BRIDGE_MONITOR = "/rest/interface/bridge/monitor"
BRIDGE_PORT_MONITOR = "/rest/interface/bridge/port/monitor"
POE_MONITOR = "/rest/interface/ethernet/poe/monitor"
TRACEROUTE = "/rest/tool/traceroute"
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
    FW_FILTER,
    FW_FILTER6,
    FW_NAT,
    SCHEDULER,
    LOG_ACTION,
    LOG_RULES,
    IP_ROUTE,
    NETWATCH,
    IPV6_ROUTE,
    IPV6_ADDRESS_MENU,
    WG_MENU,
    WG_PEERS,
    UPNP_INTERFACES,
)
REQUIRED = {
    UPNP_INTERFACES: ("interface", "type"),
    WG_MENU: ("name",),
    WG_PEERS: ("interface", "public-key"),
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
    SCHEDULER: ("name",),
    LOG_ACTION: ("name", "target"),
    LOG_RULES: ("topics", "action"),
}
#: Properties that name interfaces (checked against ``/interface``).
REFERENCES = {
    VLAN: ("interface",),
    IP_ADDRESS: ("interface",),
    IPV6_ADDRESS_MENU: ("interface",),
    WG_PEERS: ("interface",),
    BRIDGE_PORT: ("interface", "bridge"),
    BRIDGE_VLAN: ("bridge", "tagged", "untagged"),
    DHCP_SERVER: ("interface",),
}
_STATIC = {"disabled": "false", "dynamic": "false"}
DEFAULTS: dict[str, dict[str, str]] = {
    UPNP_INTERFACES: {"forced-ip": "0.0.0.0", **_STATIC},
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
    FW_FILTER: {"invalid": "false", "bytes": "0", "packets": "0", **_STATIC},
    FW_FILTER6: {"invalid": "false", "bytes": "0", "packets": "0", **_STATIC},
    FW_NAT: {"invalid": "false", "bytes": "0", "packets": "0", **_STATIC},
    LOG_ACTION: {"default": "false"},
    LOG_RULES: {"invalid": "false", **_STATIC},
    SCHEDULER: {"interval": "0s", "run-count": "0", "invalid": "false", **_STATIC},
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
