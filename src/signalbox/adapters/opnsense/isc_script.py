#!/usr/local/bin/python3
"""signalbox-isc-dhcp: print the ISC DHCP settings of an OPNsense firewall as JSON (#242).

OPNsense's API has no endpoint for them (only leases and the service state): ranges, options,
static maps and failover live in the ``<dhcpd>`` and ``<dhcpdv6>`` sections of /conf/config.xml,
which is readable by root only and holds every secret of the firewall. This script is the
whole reading access Signalbox gets: it runs as root through an SSH key whose ``authorized_keys``
entry forces this command (docs/adapters/opnsense.md, "ISC DHCP settings"), takes no argument
and no input, and prints only what is listed in :data:`FIELDS`: a fixed set of fields per
interface, each checked against its format (an address, a MAC, a host name, a number). Nothing
else of the configuration, no other section and no field that is not listed (DDNS keys, for
example) is ever printed, whatever the file contains.

The file is the single source of truth of what Signalbox may read; the setup installs it
verbatim as /usr/local/sbin/signalbox-isc-dhcp (root:wheel, 0755), and the Signalbox package
ships this same file. Standard library only.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET
from typing import Any

CONFIG = "/conf/config.xml"
VERSION = 1

_NAME = re.compile(r"^[A-Za-z0-9_]{1,32}$")
_MAC = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_DUID = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){2,127}$")
_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
_NUMBER = re.compile(r"^[0-9]{1,10}$")


def _address(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _mac(value: str) -> str | None:
    value = value.strip()
    return value.lower().replace("-", ":") if _MAC.match(value) else None


def _duid(value: str) -> str | None:
    value = value.strip()
    return value.lower() if _DUID.match(value) else None


def _host(value: str) -> str | None:
    value = value.strip()
    return value if _HOST.match(value) else None


def _number(value: str) -> int | None:
    value = value.strip()
    return int(value) if _NUMBER.match(value) else None


def _peer(value: str) -> str | None:
    return _address(value) or _host(value)


#: What is printed per interface: element -> (one or many, format check). "one" is the first
#: valid element of that name, "many" every valid one. Anything not listed here is dropped.
FIELDS: dict[str, tuple[str, Any]] = {
    "gateway": ("one", _address),
    "domain": ("one", _host),
    "defaultleasetime": ("one", _number),
    "maxleasetime": ("one", _number),
    "failover_peerip": ("one", _peer),
    "dnsserver": ("many", _address),
    "ntpserver": ("many", _address),
}
#: What is printed per static map, by section.
MAP_FIELDS: dict[str, dict[str, Any]] = {
    "dhcpd": {"mac": _mac, "ipaddr": _address, "hostname": _host},
    "dhcpdv6": {"duid": _duid, "ipaddrv6": _address, "hostname": _host},
}
SECTIONS = ("dhcpd", "dhcpdv6")
#: The router advertisement modes of ``<dhcpdv6><if><ramode>`` (Services: Router Advertisements).
RA_MODES = frozenset({"disabled", "router", "unmanaged", "managed", "assist", "stateless_dhcp"})


def _text(node: ET.Element, tag: str) -> list[str]:
    return [(c.text or "").strip() for c in node.findall(tag)]


def _router_advertisement(node: ET.Element) -> dict[str, Any]:
    """The router advertisement settings of an interface of ``<dhcpdv6>`` (#151): the mode, the
    DNS servers and search list announced, and whether it announces no default route. Printed
    only when set."""
    out: dict[str, Any] = {}
    mode = (_text(node, "ramode") or [""])[0].strip()
    if mode in RA_MODES:
        out["ramode"] = mode
    dns = [a for a in (_address(t) for t in _text(node, "radnsserver")) if a is not None]
    if dns:
        out["radnsserver"] = dns
    search = [
        h
        for t in _text(node, "radomainsearchlist")
        for h in (_host(w) for w in t.split()[:8])
        if h is not None
    ]
    if search:
        out["radomainsearchlist"] = search
    if node.find("ranodefault") is not None:
        out["ranodefault"] = True
    return out


def _interface(section: str, node: ET.Element) -> dict[str, Any]:
    out: dict[str, Any] = {"enable": node.find("enable") is not None}
    start = _address((_text(node, "range/from") or [""])[0])
    end = _address((_text(node, "range/to") or [""])[0])
    if start and end:
        out["range"] = {"from": start, "to": end}
    for tag, (kind, check) in FIELDS.items():
        values = [v for v in (check(t) for t in _text(node, tag)) if v is not None]
        if kind == "one":
            if values:
                out[tag] = values[0]
        else:
            out[tag] = values
    if section == "dhcpdv6":
        out |= _router_advertisement(node)
    maps = []
    for entry in node.findall("staticmap"):
        row = {}
        for tag, check in MAP_FIELDS[section].items():
            value = check((_text(entry, tag) or [""])[0])
            if value is not None:
                row[tag] = value
        keys = list(MAP_FIELDS[section])
        if keys[0] in row and keys[1] in row:  # MAC (or DUID) and address; a name alone is none
            maps.append(row)
    out["staticmap"] = maps
    return out


def extract(xml_text: str) -> dict[str, Any]:
    """The printable settings of a config.xml text (see the module docstring)."""
    root = ET.fromstring(xml_text)
    result: dict[str, Any] = {"version": VERSION}
    for section in SECTIONS:
        node = root.find(section)
        result[section] = {
            child.tag: _interface(section, child)
            for child in (list(node) if node is not None else [])
            if _NAME.match(child.tag)
        }
    return result


def main(path: str = CONFIG) -> int:
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        print(json.dumps(extract(text), sort_keys=True))
    except (OSError, ET.ParseError) as exc:
        print(f"signalbox-isc-dhcp: {type(exc).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
