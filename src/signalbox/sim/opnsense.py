"""Simulator of the OPNsense REST API endpoints the ``opnsense`` adapter reads and writes.

The answers follow the JSON shapes in ``docs/adapters/opnsense.md`` (from the public API docs,
not yet confirmed on a real device, issue #21). Sample network, documentation addresses only:

- LAN ``igb0`` untagged, 192.0.2.1/24 and 2001:db8:1::1/64, Kea DHCP
- VLAN 20 "IoT" on ``igb0``, 198.51.100.1/24, Kea DHCP with its own options
- VLAN 30 "Guest" on ``igb0``, 203.0.113.1/24, ISC DHCP
- VLAN 40 "Lab" defined but not assigned; WAN ``igb1`` (uplink, 2001:db8:ffff::2/64)
- Unbound with forwarders and host overrides; ARP and NDP entries; DHCP leases
- the dashboard's health widgets (uptime, load, memory, ZFS disks, two CPU sensors), the
  clock in Europe/Berlin and ntpd in sync with a local GPS-backed server

Failure switches on :class:`OpnsenseSimulator`: ``api_enabled=False`` (404 on everything),
``delay`` (seconds before every answer), ``malformed`` (endpoints answering broken JSON),
``fail`` (a status code per endpoint);
a wrong key or secret is answered with 401. ``data`` can be edited by tests.

Writes (VLAN devices, interface assignments, Kea subnets and reservations, configuration
history) change ``data``, so the read endpoints show the result: configuration endpoints at
once, the interface overview after ``/api/interfaces/assignment/reconfigure`` (it shows the
running interfaces). Every write stores a revision of the configuration history; a revision
downloads as a ``config.xml`` serialising the configuration part of ``data``, and
``revert_backup`` puts it back. Write failure switches: ``invalid`` (path or path prefix ->
validation messages, answered as ``{"result": "failed", "validations": {...}}``) and ``fail``
(also by prefix); the simulated firewall validates fields itself, too (descriptions, tags,
networks, pools, MACs).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import copy
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

KEY = "sim-key"
SECRET = "sim-secret"


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


def sample_data() -> dict[str, Any]:
    """Answers by endpoint path (a fresh copy every call)."""
    lan_ifaces = {"lan": ("LAN", True), "opt1": ("IoT", True), "opt2": ("Guest", False)}
    data: dict[str, Any] = {
        "/api/core/firmware/status": {
            "status": "update",
            "status_msg": "There are 3 updates available.",
            "product": {
                "product_name": "OPNsense",
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
                    v6=["2001:db8:ffff::2/64"],
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
                            },
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
            "total": 1,
            "rows": [
                {
                    "address": "192.0.2.100",
                    "hwaddr": "02:00:00:00:00:21",
                    "hostname": "laptop",
                    "if_name": "lan",
                    "if_descr": "LAN",
                }
            ],
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
                    "active_interface": _opt(
                        {"lan": ("LAN", True), "opt1": ("IoT", True), "opt2": ("Guest", False)}
                    ),
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
    }
    return copy.deepcopy(data)


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
CONFIG = (INTERFACES, VLANS, KEA)
_WRITE = re.compile(
    r"^/api/(interfaces/vlan_settings|interfaces/assignment|kea/dhcpv4|kea/service|core/backup)"
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
    #: "26.7.6": assignment rows with addresses; "26.7": only device, description, lock.
    assignment_api: str = "26.7.6"
    #: Assigned interfaces that are locked against removal.
    locked: set[str] = field(default_factory=set)
    #: Write requests received: (path, body).
    posts: list[tuple[str, Any]] = field(default_factory=list)
    #: Time zone of the firewall (System: Settings: General), for ``system_time``'s datetime.
    timezone: str = "Europe/Berlin"

    def local_time(self) -> str:
        """``Sun Nov 22 17:12:00 CET 2026``, PHP's ``date("D M j G:i:s T Y")``."""
        try:
            now = datetime.now(ZoneInfo(self.timezone))
        except (ZoneInfoNotFoundError, ValueError):
            now = datetime.now(UTC)
        return f"{now:%a %b} {now.day} {now.hour}:{now:%M:%S} {now.tzname()} {now.year}"

    def authorised(self, header: str | None) -> bool:
        if not header or not header.startswith("Basic "):
            return False
        try:
            user, _, password = base64.b64decode(header[6:]).decode().partition(":")
        except (binascii.Error, UnicodeDecodeError):
            return False
        return secrets.compare_digest(user, self.api_key) and secrets.compare_digest(
            password, self.api_secret
        )

    def app(self) -> FastAPI:
        app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

        @app.api_route("/{path:path}", methods=["GET", "POST"])
        async def answer(path: str, request: Request) -> Response:
            # OPNsense routes camelCase and snake_case actions alike (snake_case is canonical)
            path = "/" + "/".join(_snake(part) for part in path.split("/"))
            self.requests.append(path)
            if not self.api_enabled:
                return JSONResponse({"errorMessage": "Endpoint not found"}, status_code=404)
            if not self.authorised(request.headers.get("authorization")):
                return JSONResponse(
                    {"status": 401, "message": "Authentication Failed"},
                    status_code=401,
                    headers={"WWW-Authenticate": 'Basic realm="api"'},
                )
            if self.delay:
                await asyncio.sleep(self.delay)
            status = _prefixed(self.fail, path)
            if status is not None:
                return JSONResponse({"message": "simulated failure"}, status_code=status)
            invalid = _prefixed(self.invalid, path)
            if invalid is not None:
                return JSONResponse({"result": "failed", "validations": invalid})
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
            if path in (KEA, *grids):
                return JSONResponse(self._kea_answer(path))
            if path == SYSTEM_TIME and isinstance(self.data[path], dict):
                return JSONResponse({**self.data[path], "datetime": self.local_time()})
            return JSONResponse(self.data[path])

        return app
