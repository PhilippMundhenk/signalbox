"""The Linux integration's reading of ``ip -j``, ``/proc``, ``/sys``, ``ss``, ``df`` and sshd's
configuration (#240): system, ports, segments, subnets, uplinks, services and health.

Port roles (ADR 0008) from ``ip -d`` ``linkinfo``: ``bridge`` (members: ``master``), ``vlan``
(parent: ``link``), ``bond``/``team`` (lag), ``dsa`` user ports (jacks on their ``conduit``, which
is the CPU port), ``wireguard``/``tun``/``gre``/``ipip``/``sit``/``ppp``... (tunnel),
``veth``/``dummy``/``macvlan``... (virtual). Without a kind: a Wi-Fi interface where
``/sys/class/net/<name>/wireless`` exists, a jack where the interface has a ``device`` (a NIC).
"""

from __future__ import annotations

import contextlib
import fnmatch
import json
import shlex
from dataclasses import dataclass, field
from ipaddress import IPv4Interface, IPv6Interface, ip_address, ip_interface
from typing import Any

from signalbox.adapters.linux.collect import Answer
from signalbox.model import (
    IPAddress,
    IPInterface,
    PortKind,
    PortRole,
    StorageKind,
    StorageUsage,
    TemperatureSensor,
)

TUNNEL_KINDS = frozenset(
    {"wireguard", "tun", "gre", "gretap", "ip6gre", "ipip", "sit", "ip6tnl", "vti", "ppp", "vxlan"}
)
VIRTUAL_KINDS = frozenset({"veth", "dummy", "macvlan", "macvtap", "ipvlan", "ifb", "nlmon", "vrf"})
#: File systems that are not storage (kernel, pseudo and container plumbing).
PSEUDO_FS = frozenset(
    {
        "devtmpfs",
        "proc",
        "sysfs",
        "cgroup",
        "cgroup2",
        "squashfs",
        "efivarfs",
        "autofs",
        "fuse.lxcfs",
        "nsfs",
        "ramfs",
        "overlay",
    }
)


def _json(text: str) -> Any:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _int(text: str | None) -> int | None:
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return None


# --- system --------------------------------------------------------------------------------


def os_release(answer: Answer) -> dict[str, str]:
    out: dict[str, str] = {}
    text = answer.files("os").get("/etc/os-release", "")
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip():
            with contextlib.suppress(ValueError):
                parts = shlex.split(value)
                out[key.strip()] = parts[0] if parts else ""
    return out


def hardware(answer: Answer) -> tuple[str | None, str | None]:
    """(vendor, model): the device tree model (Raspberry Pi and other boards) or DMI."""
    files = answer.files("model")
    tree = files.get("/proc/device-tree/model", "").replace("\x00", "").strip()
    if tree:
        vendor = "Raspberry Pi" if tree.startswith("Raspberry Pi") else None
        return vendor, tree
    vendor = files.get("/sys/class/dmi/id/sys_vendor", "").strip() or None
    model = files.get("/sys/class/dmi/id/product_name", "").strip() or None
    return vendor, model


# --- links and addresses ---------------------------------------------------------------------


@dataclass
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


@dataclass
class Link:
    name: str
    raw: dict[str, Any]
    kind: str | None = None  # linkinfo info_kind
    master: str | None = None
    parent: str | None = None  # VLAN parent (``link``), DSA conduit
    vlan: int | None = None
    vlan_filtering: bool = False
    flags: list[str] = field(default_factory=list)
    addresses: list[IPInterface] = field(default_factory=list)
    dynamic: bool = False  # an address with a lifetime (DHCP, SLAAC)

    @property
    def admin_up(self) -> bool:
        return "UP" in self.flags

    @property
    def up(self) -> bool:
        state = self.raw.get("operstate")
        if state == "UP":
            return True
        if state == "UNKNOWN":  # tunnels and dummies report no carrier state
            return "LOWER_UP" in self.flags and self.admin_up
        return False


def links(answer: Answer) -> dict[str, Link]:
    data = _json(answer.text("link"))
    out: dict[str, Link] = {}
    for row in data if isinstance(data, list) else []:
        if not isinstance(row, dict) or not isinstance(row.get("ifname"), str):
            continue
        info: dict[str, Any] = row["linkinfo"] if isinstance(row.get("linkinfo"), dict) else {}
        data_: dict[str, Any] = info["info_data"] if isinstance(info.get("info_data"), dict) else {}
        kind = info.get("info_kind") if isinstance(info.get("info_kind"), str) else None
        link = Link(
            name=row["ifname"],
            raw=row,
            kind=kind,
            master=row.get("master") if isinstance(row.get("master"), str) else None,
            flags=[str(f) for f in row.get("flags") or []],
        )
        if kind == "vlan":
            link.vlan = _int(data_.get("id"))
            link.parent = row.get("link") if isinstance(row.get("link"), str) else None
        elif kind == "dsa":
            conduit = data_.get("conduit", data_.get("master"))
            link.parent = conduit if isinstance(conduit, str) else None
        elif kind == "bridge":
            link.vlan_filtering = data_.get("vlan_filtering") in (1, True)
        out[link.name] = link
    addrs = _json(answer.text("addr"))
    for row in addrs if isinstance(addrs, list) else []:
        if not isinstance(row, dict) or row.get("ifname") not in out:
            continue
        link = out[row["ifname"]]
        for a in row.get("addr_info") or []:
            if not isinstance(a, dict) or a.get("family") not in ("inet", "inet6"):
                continue
            try:
                iface = ip_interface(f"{a['local']}/{a['prefixlen']}")
            except (KeyError, ValueError):
                continue
            if a.get("dynamic") is True:
                link.dynamic = True
            link.addresses.append(iface)
    return out


def global_addresses(link: Link) -> list[IPInterface]:
    """Addresses of a network (no loopback, no link-local)."""
    return [
        a
        for a in link.addresses
        if not a.is_loopback and not a.is_link_local and not (a.version == 6 and a.ip.is_link_local)
    ]


def role_of(link: Link, sys: SysNet | None, conduits: set[str]) -> tuple[PortRole | None, PortKind]:
    kind = link.kind
    if link.name in conduits:
        return PortRole.CPU, PortKind.ETHERNET
    if kind == "bridge":
        return PortRole.BRIDGE, PortKind.BRIDGE
    if kind == "vlan":
        return PortRole.VLAN, PortKind.VIRTUAL
    if kind in ("bond", "team"):
        return PortRole.LAG, PortKind.LAG
    if kind == "dsa":
        return PortRole.JACK, PortKind.ETHERNET
    if kind in TUNNEL_KINDS or link.raw.get("link_type") in ("ppp", "none"):
        return PortRole.TUNNEL, PortKind.VIRTUAL
    if kind in VIRTUAL_KINDS or link.raw.get("link_netnsid") is not None:
        return PortRole.VIRTUAL, PortKind.VIRTUAL
    if sys is not None and sys.wireless:
        return PortRole.WIRELESS, PortKind.WIRELESS
    if kind is None and sys is not None and sys.device:
        return PortRole.JACK, PortKind.ETHERNET
    if kind is not None:
        return PortRole.VIRTUAL, PortKind.VIRTUAL
    return None, PortKind.ETHERNET


def bridge_vlans(answer: Answer) -> dict[str, list[tuple[int, bool, bool]]]:
    """``bridge -j vlan show``: port -> [(vlan, pvid, untagged)] (new and old JSON shape)."""
    data = _json(answer.text("bridge-vlan"))
    rows: list[tuple[Any, Any]] = []
    if isinstance(data, list):
        rows = [(r.get("ifname"), r.get("vlans")) for r in data if isinstance(r, dict)]
    elif isinstance(data, dict):
        rows = list(data.items())
    out: dict[str, list[tuple[int, bool, bool]]] = {}
    for name, vlans in rows:
        if not isinstance(name, str) or not isinstance(vlans, list):
            continue
        for v in vlans:
            if not isinstance(v, dict) or _int(v.get("vlan")) is None:
                continue
            flags = [str(f) for f in v.get("flags") or []]
            end = _int(v.get("vlanEnd")) or int(v["vlan"])
            for vid in range(int(v["vlan"]), min(end, 4094) + 1):
                out.setdefault(name, []).append((vid, "PVID" in flags, "Egress Untagged" in flags))
    return out


@dataclass
class Route:
    dev: str | None
    gateway: IPAddress | None
    protocol: str | None
    metric: int


def default_routes(answer: Answer) -> list[Route]:
    out: list[Route] = []
    for name in ("route", "route6"):
        data = _json(answer.text(name))
        for row in data if isinstance(data, list) else []:
            if not isinstance(row, dict) or row.get("dst") != "default":
                continue
            gw: IPAddress | None = None
            with contextlib.suppress(ValueError, TypeError):
                gw = ip_address(str(row.get("gateway")))
            dev = row.get("dev") if isinstance(row.get("dev"), str) else None
            proto = row.get("protocol") if isinstance(row.get("protocol"), str) else None
            out.append(Route(dev, gw, proto, _int(row.get("metric")) or 0))
    return sorted(out, key=lambda r: (r.gateway is None or r.gateway.version != 4, r.metric))


def forwarding(answer: Answer) -> bool | None:
    values = answer.lines("forward")
    if not values:
        return None
    return any(v.strip() == "1" for v in values)


# --- listening sockets and processes -------------------------------------------------------------


@dataclass(frozen=True)
class Listener:
    proto: str  # tcp / udp
    address: IPAddress | None  # None: every address
    port: int


def listeners(answer: Answer) -> list[Listener]:
    """``ss -Hltun``: ``tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*``."""
    out: list[Listener] = []
    for line in answer.lines("listen"):
        parts = line.split()
        if len(parts) < 5 or parts[0] not in ("tcp", "udp"):
            continue
        host, _, port = parts[4].rpartition(":")
        host = host.strip("[]").split("%")[0]
        number = _int(port)
        if number is None:
            continue
        address: IPAddress | None = None
        if host not in ("*", "0.0.0.0", "::", ""):
            try:
                address = ip_address(host)
            except ValueError:
                continue
        out.append(Listener(parts[0], address, number))
    return out


def running(answer: Answer) -> dict[str, tuple[bool, bool | None]]:
    """unit -> (active, enabled); without systemd (a container) the process list decides."""
    units: dict[str, tuple[bool, bool | None]] = {}
    for line in answer.lines("units"):
        parts = line.split()
        if not parts:
            continue
        active = len(parts) > 1 and parts[1] in ("active", "activating", "reloading")
        enabled: bool | None = None
        if len(parts) > 2:
            enabled = parts[2] in ("enabled", "static", "alias", "indirect", "generated")
        units[parts[0]] = (active, enabled)
    return units


PROCESS_NAMES = {
    "sshd": "ssh",
    "dnsmasq": "dnsmasq",
    "kea-dhcp4": "kea-dhcp4-server",
    "dhcpd": "isc-dhcp-server",
    "systemd-network": "systemd-networkd",
    "AdGuardHome": "AdGuardHome",
    "pihole-FTL": "pihole-FTL",
    "unbound": "unbound",
    "chronyd": "chrony",
    "systemd-timesyn": "systemd-timesyncd",
}


def services_running(answer: Answer) -> set[str]:
    """The services that run (by unit, or by process name), under the unit names Debian uses."""
    out = {u for u, (active, _) in running(answer).items() if active}
    aliases = {"sshd": "ssh", "chronyd": "chrony"}
    out = {aliases.get(u, u) for u in out}
    for proc in answer.lines("procs"):
        name = PROCESS_NAMES.get(proc.strip())
        if name:
            out.add(name)
    return out


# --- sshd ------------------------------------------------------------------------------------


def sshd_settings(answer: Answer) -> dict[str, list[str]]:
    """Effective global options of ``sshd_config`` (first value wins, ``Include`` expanded at
    its place, everything after the first ``Match`` ignored); keys lower-case."""
    files = answer.files("sshd")
    out: dict[str, list[str]] = {}
    seen: set[str] = set()

    def read(path: str) -> bool:
        if path in seen:
            return True
        seen.add(path)
        for raw in files.get(path, "").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            key, _, rest = line.replace("=", " ", 1).partition(" ")
            key = key.lower()
            values = rest.split()
            if key == "match":
                return False
            if key == "include":
                for pattern in values:
                    if not pattern.startswith("/"):
                        pattern = "/etc/ssh/" + pattern
                    for other in sorted(p for p in files if fnmatch.fnmatch(p, pattern)):
                        if not read(other):
                            return False
                continue
            if key in ("listenaddress", "port"):  # these accumulate
                out.setdefault(key, []).extend(values)
            elif key not in out:
                out[key] = values
        return True

    read("/etc/ssh/sshd_config")
    return out


# --- health ----------------------------------------------------------------------------------


def uptime(answer: Answer) -> int | None:
    parts = answer.text("uptime").split()
    try:
        return int(float(parts[0]))
    except (IndexError, ValueError):
        return None


def load_average(answer: Answer) -> tuple[float, float, float] | None:
    parts = answer.text("loadavg").split()
    try:
        return float(parts[0]), float(parts[1]), float(parts[2])
    except (IndexError, ValueError):
        return None


def memory(answer: Answer) -> tuple[int | None, int | None]:
    values: dict[str, int] = {}
    for line in answer.lines("meminfo"):
        key, _, rest = line.partition(":")
        parts = rest.split()
        if parts and (n := _int(parts[0])) is not None:
            values[key.strip()] = n * 1024 if len(parts) > 1 and parts[1] == "kB" else n
    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    if total is None or available is None:
        return total, None
    return total, max(total - available, 0)


def storage(answer: Answer) -> list[StorageUsage]:
    """``df -P -T -B1``: system (``/``), temporary (tmpfs), data (the rest)."""
    out: list[StorageUsage] = []
    seen: set[str] = set()
    for line in answer.lines("df")[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        fstype, mount = parts[1], " ".join(parts[6:])
        if fstype in PSEUDO_FS and mount != "/":
            continue
        if mount.startswith(("/dev", "/sys", "/proc", "/run/user")) or mount in seen:
            continue
        total, used = _int(parts[2]), _int(parts[3])
        if not total:
            continue
        seen.add(mount)
        if mount == "/":
            kind = StorageKind.SYSTEM
        elif fstype == "tmpfs":
            kind = StorageKind.TEMPORARY
        elif mount.startswith("/boot"):
            kind = StorageKind.OTHER
        else:
            kind = StorageKind.DATA
        out.append(StorageUsage(name=mount, kind=kind, total_bytes=total, used_bytes=used))
    return out


def temperatures(answer: Answer) -> list[TemperatureSensor]:
    out: list[TemperatureSensor] = []
    names: dict[str, int] = {}
    for line in answer.lines("thermal"):
        name, _, value = line.rpartition(" ")
        milli = _int(value)
        if milli is None or not name.strip():
            continue
        base = name.strip()
        names[base] = names.get(base, 0) + 1
        label = base if names[base] == 1 else f"{base}-{names[base]}"
        out.append(TemperatureSensor(name=label, value_c=milli / 1000))
    return out


def resolvers(answer: Answer) -> list[IPAddress]:
    out: list[IPAddress] = []
    for line in answer.files("resolv").get("/etc/resolv.conf", "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            with contextlib.suppress(ValueError):
                a = ip_address(parts[1].split("%")[0])
                if not a.is_loopback and a not in out:
                    out.append(a)
    return out


def network_of(addresses: list[IPInterface], address: IPAddress) -> IPInterface | None:
    """The interface address whose network contains *address*."""
    for a in addresses:
        if (
            isinstance(a, IPv4Interface | IPv6Interface)
            and address.version == a.version
            and address in a.network
        ):
            return a
    return None
