"""Parsers of the operational-mode and ``ip`` text of EdgeOS and VyOS (#403).

Only text that is old and stable is read: ``ip -o link/addr`` and ``ip route`` of the iproute2 of
EdgeOS 1.x (no JSON there), the key/value block of ``show version``, the lease tables of
``show dhcp leases`` (EdgeOS) and ``show dhcp server leases`` (VyOS), and the ``lldpctl``-style
block of ``show lldp neighbors detail``.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv6Interface,
    ip_address,
    ip_interface,
    ip_network,
)

from signalbox.adapters.edgeos.collect import Answer
from signalbox.lldp import age_seconds, int_of
from signalbox.model import (
    DhcpLease,
    IPAddress,
    IPInterface,
    IPNetwork,
    LeaseState,
    normalise_id_kind,
)


def _int(text: str | None) -> int | None:
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return None


# --- version ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Version:
    """The software of the router: ``edgeos`` (Ubiquiti) or ``vyos``, and its version."""

    flavor: str  # edgeos | vyos | unknown
    text: str | None
    major: int | None = None
    minor: int | None = None
    patch: int | None = None
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def vyos(self) -> bool:
        return self.flavor == "vyos"

    @property
    def name(self) -> str:
        return {"edgeos": "EdgeOS", "vyos": "VyOS"}.get(self.flavor, "EdgeOS")

    def at_least(self, major: int, minor: int = 0) -> bool:
        return self.major is not None and (self.major, self.minor or 0) >= (major, minor)


_NUMBERS = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def version(answer: Answer) -> Version:
    """``show version``: ``Version: v2.0.9-hotfix.7`` (EdgeOS) or ``Version: VyOS 1.3.3``."""
    fields: dict[str, str] = {}
    for line in answer.lines("version"):
        key, sep, value = line.partition(":")
        if sep and value.strip() and key.strip() not in fields:
            fields[key.strip()] = value.strip()
    text = fields.get("Version")
    if text is None:
        return Version("unknown", None, fields=fields)
    flavor = "vyos" if "vyos" in text.lower() or "Release train" in fields else "edgeos"
    found = _NUMBERS.search(text)
    if found is None:
        return Version(flavor, text, fields=fields)
    return Version(
        flavor,
        text,
        int(found.group(1)),
        int(found.group(2)),
        int(found.group(3)) if found.group(3) else None,
        fields,
    )


# --- ip -o --------------------------------------------------------------------------------

_LINK = re.compile(
    r"^(\d+):\s+(?P<name>[^:@\s]+)(?:@(?P<parent>[^:\s]+))?:\s+<(?P<flags>[^>]*)>\s+mtu\s+"
    r"(?P<mtu>\d+).*?\bstate\s+(?P<state>\w+).*?link/(?P<type>\w+)(?:\s+(?P<mac>[0-9a-f:]{17}))?"
)


@dataclass
class Link:
    name: str
    parent: str | None
    flags: set[str]
    mtu: int | None
    state: str
    kind: str  # ether, loopback, ppp, none
    mac: str | None

    @property
    def up(self) -> bool:
        """Carrier and oper state (``UP``; a tunnel reports ``UNKNOWN`` with the flag)."""
        return "LOWER_UP" in self.flags and self.state in ("UP", "UNKNOWN")

    @property
    def admin_up(self) -> bool:
        return "UP" in self.flags


def links(answer: Answer) -> dict[str, Link]:
    out: dict[str, Link] = {}
    for line in answer.lines("link"):
        m = _LINK.match(line.strip())
        if m is None:
            continue
        mtu = int(m["mtu"])
        out[m["name"]] = Link(
            name=m["name"],
            parent=m["parent"],
            flags=set(m["flags"].split(",")),
            mtu=mtu if 68 <= mtu <= 65535 else None,
            state=m["state"],
            kind=m["type"],
            mac=m["mac"] if m["mac"] and m["mac"] != "00:00:00:00:00:00" else None,
        )
    return out


def addresses(answer: Answer) -> dict[str, list[IPInterface]]:
    """``ip -o addr show``: global addresses (no link-local, no loopback) by interface."""
    out: dict[str, list[IPInterface]] = {}
    for line in answer.lines("addr"):
        parts = line.split()
        if len(parts) < 4 or parts[2] not in ("inet", "inet6"):
            continue
        name = parts[1].rstrip(":").split("@")[0]
        scope = parts[parts.index("scope") + 1] if "scope" in parts[:-1] else "global"
        if scope != "global" or name == "lo":
            continue
        with contextlib.suppress(ValueError):
            out.setdefault(name, []).append(ip_interface(parts[3]))
    return out


@dataclass(frozen=True)
class Route:
    destination: IPNetwork
    gateway: IPAddress | None
    dev: str | None
    protocol: str | None
    metric: int | None
    kind: str  # unicast, blackhole, unreachable, prohibit
    scope: str | None


def routes(answer: Answer) -> list[Route]:
    """``ip route show`` and ``ip -6 route show`` (text)."""
    out: list[Route] = []
    for section in ("route", "route6"):
        for line in answer.lines(section):
            words = line.split()
            if not words:
                continue
            kind = "unicast"
            if words[0] in ("blackhole", "unreachable", "prohibit", "unicast"):
                kind = words.pop(0)
                kind = "unicast" if kind == "unicast" else kind
            if not words:
                continue
            dest = words[0]
            try:
                destination = ip_network(
                    ("::/0" if section == "route6" else "0.0.0.0/0") if dest == "default" else dest,
                    strict=False,
                )
            except ValueError:
                continue
            attrs = {words[i]: words[i + 1] for i in range(1, len(words) - 1) if words[i] in KEYS}
            gateway: IPAddress | None = None
            if "via" in attrs:
                with contextlib.suppress(ValueError):
                    gateway = ip_address(attrs["via"].split("%")[0])
            out.append(
                Route(
                    destination=destination,
                    gateway=gateway,
                    dev=attrs.get("dev"),
                    protocol=attrs.get("proto"),
                    metric=_int(attrs.get("metric")),
                    kind=kind,
                    scope=attrs.get("scope"),
                )
            )
    return out


KEYS = ("via", "dev", "proto", "metric", "scope", "src")


@dataclass(frozen=True)
class SysNet:
    device: bool = False
    wireless: bool = False
    speed: int | None = None
    duplex: str | None = None


def sysnet(answer: Answer) -> dict[str, SysNet]:
    out: dict[str, SysNet] = {}
    for line in answer.lines("sysnet"):
        parts = line.split()
        if len(parts) < 5:
            continue
        speed = _int(parts[3])
        out[parts[0]] = SysNet(
            device=parts[1] == "1",
            wireless=parts[2] == "1",
            speed=speed if speed and speed > 0 else None,
            duplex=parts[4] if parts[4] in ("full", "half") else None,
        )
    return out


# --- DHCP leases ----------------------------------------------------------------------------

_STAMP = re.compile(r"(\d{4})/(\d\d)/(\d\d)\s+(\d\d):(\d\d):(\d\d)")
_STATES = {
    "active": LeaseState.ACTIVE,
    "free": LeaseState.EXPIRED,
    "expired": LeaseState.EXPIRED,
    "abandoned": LeaseState.DECLINED,
    "backup": LeaseState.EXPIRED,
}


def _stamp(match: re.Match[str]) -> datetime:
    y, mo, d, h, mi, s = (int(x) for x in match.groups())
    return datetime(y, mo, d, h, mi, s, tzinfo=UTC)


@dataclass(frozen=True)
class Lease:
    pool: str | None
    lease: DhcpLease


def dhcp_leases(answer: Answer) -> list[Lease] | None:
    """The lease table of ``show dhcp leases`` (EdgeOS, no state column) or ``show dhcp server
    leases`` (VyOS, with state and start). None: neither command printed a table."""
    seen = False
    out: list[Lease] = []
    for section in ("dhcp-leases", "dhcp-leases-server"):
        text = answer.text(section)
        if not text.strip():
            continue
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 3 or not re.fullmatch(r"[0-9a-fA-F.:]+", parts[0]):
                if parts and parts[0].lower().startswith("ip"):
                    seen = True
                continue
            seen = True
            try:
                address = ip_address(parts[0])
            except ValueError:
                continue
            if not re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", parts[1]):
                continue
            state = _STATES.get(parts[2].lower())
            rest_at = 3 if state is not None else 2
            stamps = list(_STAMP.finditer(line))
            starts = _stamp(stamps[0]) if len(stamps) == 2 else None
            expires = _stamp(stamps[-1]) if stamps else None
            tail = line[stamps[-1].end() :].split() if stamps else parts[rest_at:]
            if state is not None and tail and re.fullmatch(r"[\d:]+|-", tail[0]):
                tail = tail[1:]  # VyOS: the "Remaining" column
            pool = tail[0] if tail else None
            name = " ".join(tail[1:]) or None
            out.append(
                Lease(
                    pool,
                    DhcpLease(
                        address=address,
                        mac=parts[1].lower(),
                        hostname=name if name and name != "-" else None,
                        state=state or LeaseState.ACTIVE,
                        starts=starts,
                        expires=expires,
                    ),
                )
            )
    return out if seen else None


# --- LLDP ------------------------------------------------------------------------------------


@dataclass
class LldpNeighbour:
    interface: str
    chassis: str = ""
    system_name: str | None = None
    description: str | None = None
    management: str | None = None
    port: str | None = None
    capabilities: list[str] = field(default_factory=list)
    via: str | None = None
    chassis_kind: str | None = None
    port_description: str | None = None
    ttl: int | None = None
    age: int | None = None
    max_frame_size: int | None = None
    port_vlan: int | None = None
    vlans: list[int] = field(default_factory=list)
    med_device_type: str | None = None


_CAPS = {
    "bridge": "bridge",
    "router": "router",
    "wlan": "wlan-access-point",
    "station": "station",
    "telephone": "telephone",
    "repeater": "repeater",
    "docsis": "docsis-cable-device",
    "other": "other",
}


def lldp(answer: Answer) -> list[LldpNeighbour]:
    """``show lldp neighbors detail`` (the lldpctl block per interface)."""
    out: list[LldpNeighbour] = []
    current: LldpNeighbour | None = None
    last: str | None = None
    for raw in answer.text("lldp").splitlines():
        line = raw.strip()
        if line.startswith("Interface:"):
            name = line[len("Interface:") :].split(",")[0].strip()
            current = LldpNeighbour(interface=name)
            for part in line.split(",")[1:]:
                label, _, text = part.partition(":")
                if label.strip() == "via":
                    current.via = text.strip()
            age_text = line.partition("Time:")[2].strip()
            current.age = age_seconds(age_text) if age_text else None
            out.append(current)
            last = None
            continue
        if current is None or not line or line.startswith("---"):
            continue
        key, sep, value = line.partition(":")
        value = value.strip()
        if not sep:
            if last == "SysDescr" and current.description:
                current.description += " " + line
            continue
        last = key
        if key == "ChassisID":
            kind, _, rest = value.partition(" ")
            current.chassis = rest.strip().lower() if kind == "mac" else (rest or value).strip()
            current.chassis_kind = normalise_id_kind(kind)
        elif key == "SysName":
            current.system_name = value or None
        elif key == "SysDescr":
            current.description = value or None
        elif key == "MgmtIP" and current.management is None:
            current.management = value or None
        elif key == "PortID":
            kind, _, rest = value.partition(" ")
            current.port = (rest or value).strip() or None
            if kind == "mac" and current.port:
                current.port = current.port.lower()
        elif key == "PortDescr" and value:
            current.port_description = value
            if current.port is None:
                current.port = value
        elif key == "TTL":
            current.ttl = int_of(value)
        elif key == "MFS":
            current.max_frame_size = int_of(value)
        elif key == "VLAN":
            vid = int_of(value)
            if vid is not None and 1 <= vid <= 4094:
                if vid not in current.vlans:
                    current.vlans.append(vid)
                if "pvid: yes" in value.lower():
                    current.port_vlan = vid
        elif key == "Device Type":
            current.med_device_type = value
        elif key == "Capability":
            name, _, state = value.rpartition(",")
            word = name.split()[0].lower() if name.split() else ""
            if (
                state.strip().lower() == "on"
                and word in _CAPS
                and _CAPS[word] not in (current.capabilities)
            ):
                current.capabilities.append(_CAPS[word])
    return [n for n in out if n.chassis]


def wireguard_keys(answer: Answer) -> dict[str, str]:
    """``@@wg-keys``: ``wg0 <public key>`` per WireGuard interface."""
    out: dict[str, str] = {}
    for line in answer.lines("wg-keys"):
        parts = line.split()
        if len(parts) == 2:
            out[parts[0]] = parts[1]
    return out


def is_v4(address: IPAddress | IPInterface) -> bool:
    return isinstance(address, IPv4Address | IPv4Interface)


def is_v6(address: IPInterface) -> bool:
    return isinstance(address, IPv6Interface)
