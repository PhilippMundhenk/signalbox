"""DHCP and DNS servers of a Linux gateway from their configuration files and lease tables
(#240): dnsmasq, Kea (``kea-dhcp4``), ISC dhcpd and systemd-networkd's DHCP server.

Each parser returns :class:`Scope` objects (one address range of one server, the options it
hands out) and leases; the adapter maps a scope to a segment by its interface or by the
network of one of the device's addresses. Only what the files say is reported: an option
without a value in the file and without a documented default stays empty.
"""

from __future__ import annotations

import contextlib
import csv
import fnmatch
import io
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Interface, IPv4Network, IPv6Network, ip_address, ip_network
from typing import Any

from signalbox.model import (
    DhcpLease,
    DhcpOption,
    DhcpRoute,
    HostRecord,
    IPAddress,
    LeaseState,
    Reservation,
    normalise_mac,
)

MAC = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")

#: dnsmasq ``option:<name>`` names of the typed fields, and of a few common options.
DNSMASQ_NAMES = {
    "router": 3,
    "dns-server": 6,
    "domain-name": 15,
    "ntp-server": 42,
    "domain-search": 119,
    "classless-static-route": 121,
    "tftp-server": 66,
    "bootfile-name": 67,
    "time-offset": 2,
    "netbios-ns": 44,
    "mtu": 26,
    "wpad": 252,
    "vendor-encap": 43,
    "server-ip-address": 150,
}
#: Kea ``option-data`` names of the typed fields.
KEA_NAMES = {
    "routers": 3,
    "domain-name-servers": 6,
    "domain-name": 15,
    "ntp-servers": 42,
    "domain-search": 119,
    "classless-static-route": 121,
    "tftp-server-name": 66,
    "boot-file-name": 67,
}


@dataclass
class Scope:
    server: str  # dnsmasq, kea, isc, networkd
    key: str  # unique per server (the id of the DhcpServer)
    interface: str | None = None
    network: IPv4Network | IPv6Network | None = None
    pools: list[tuple[IPAddress, IPAddress]] = field(default_factory=list)
    lease_seconds: int | None = None
    router: IPAddress | None = None
    dns: list[IPAddress] = field(default_factory=list)
    ntp: list[IPAddress] = field(default_factory=list)
    domain: str | None = None
    search: list[str] = field(default_factory=list)
    routes: list[DhcpRoute] = field(default_factory=list)
    reservations: list[Reservation] = field(default_factory=list)
    options: list[DhcpOption] = field(default_factory=list)
    authoritative: bool | None = None
    failover_peer: str | None = None
    #: dnsmasq: the ``set:``/``tag:`` tags of the range
    tags: set[str] = field(default_factory=set)
    #: Kea subnet id
    kea_id: int | None = None
    #: dnsmasq: the first address of the range (finds the network when no netmask is given)
    start: IPAddress | None = None


def _addresses(values: list[str]) -> list[IPAddress]:
    out: list[IPAddress] = []
    for v in values:
        with contextlib.suppress(ValueError):
            a = ip_address(v.strip().strip('"'))
            if a not in out:
                out.append(a)
    return out


def _mac(text: str) -> str | None:
    text = text.strip()
    if not MAC.match(text):
        return None
    try:
        return normalise_mac(text)
    except ValueError:  # pragma: no cover - the pattern already checks
        return None


def _routes(values: list[str]) -> list[DhcpRoute]:
    """``192.0.2.0/24,192.0.2.1`` pairs (dnsmasq), or Kea's ``net - gw`` / ``net gw``."""
    words = [w for v in values for w in re.split(r"[\s,]+", v) if w and w != "-"]
    out: list[DhcpRoute] = []
    for i in range(0, len(words) - 1, 2):
        with contextlib.suppress(ValueError):
            out.append(
                DhcpRoute(destination=IPv4Network(words[i], strict=False), gateway=words[i + 1])
            )
    return out


def _set_option(scope: Scope, code: int, name: str | None, values: list[str]) -> None:
    values = [v.strip().strip('"') for v in values if v.strip()]
    if code == 3:
        found = _addresses(values)
        scope.router = found[0] if found else scope.router
    elif code == 6:
        scope.dns = _addresses(values)
    elif code == 42:
        scope.ntp = _addresses(values)
    elif code == 15:
        scope.domain = values[0] if values else None
    elif code == 119:
        scope.search = [v for vs in values for v in re.split(r"[\s,]+", vs) if v]
    elif code == 121:
        scope.routes = _routes(values)
    elif code in (51, 66, 67):
        return  # lease time and boot options: not mapped
    else:
        scope.options = [o for o in scope.options if o.code != code]
        scope.options.append(DhcpOption(code=code, name=name, value=",".join(values)))


def duration(text: str) -> int | None:
    """dnsmasq lease times: ``12h``, ``30m``, ``45s``, ``1d``, ``1w``, seconds; None: infinite."""
    text = text.strip().lower()
    match = re.match(r"^(\d+)([smhdw]?)$", text)
    if not match:
        return None
    unit = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[match.group(2)]
    return int(match.group(1)) * unit


def _epoch(value: int) -> datetime:
    return datetime.fromtimestamp(value, UTC)


# --- dnsmasq ---------------------------------------------------------------------------------


@dataclass
class Dnsmasq:
    scopes: list[Scope] = field(default_factory=list)
    port: int = 53
    listen: list[IPAddress] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)
    no_resolv: bool = False
    hosts: list[HostRecord] = field(default_factory=list)
    authoritative: bool = False
    #: some configuration at all (dnsmasq installed and configured)
    configured: bool = False


def _lines(files: dict[str, str]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for text in files.values():
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            out.append((key.strip(), value.strip()))
    return out


def parse_dnsmasq(files: dict[str, str]) -> Dnsmasq:
    out = Dnsmasq(configured=bool(files))
    lines = _lines(files)
    global_scope = Scope("dnsmasq", "global")
    tagged: list[tuple[set[str], int, str | None, list[str]]] = []
    domain: str | None = None
    n = 0
    for key, value in lines:
        items = [v.strip() for v in value.split(",")] if value else []
        if key == "port":
            out.port = int(value) if value.isdigit() else 53
        elif key == "listen-address":
            out.listen += [a for a in _addresses(items) if a not in out.listen]
        elif key == "interface":
            out.interfaces += items
        elif key == "server" and value and not value.startswith("/"):
            out.servers.append(value.split("@")[0])
        elif key == "no-resolv":
            out.no_resolv = True
        elif key == "dhcp-authoritative":
            out.authoritative = True
        elif key == "domain" and items:
            domain = items[0]
        elif key == "host-record" and items:
            names = [i for i in items if not _addresses([i])]
            for a in _addresses(items):
                out.hosts += [HostRecord(name=nm, address=a) for nm in names[:1]]
        elif key == "address" and value.startswith("/"):
            parts = value.strip("/").split("/")
            if len(parts) == 2 and parts[0] not in ("", "#") and _addresses([parts[1]]):
                out.hosts.append(HostRecord(name=parts[0], address=_addresses([parts[1]])[0]))
        elif key == "dhcp-range" and items:
            scope = Scope("dnsmasq", f"dnsmasq-{n}")
            n += 1
            rest: list[str] = []
            for item in items:
                if item.startswith(("set:", "tag:")):
                    scope.tags.add(item.split(":", 1)[1])
                elif item.startswith("interface:"):
                    scope.interface = item.split(":", 1)[1]
                    scope.tags.add(scope.interface)
                elif item.startswith("constructor:"):
                    scope.interface = item.split(":", 1)[1]
                else:
                    rest.append(item)
            addrs = _addresses(rest)
            if not addrs or addrs[0].version != 4:
                continue  # IPv6 ranges (constructor, SLAAC) are not read
            static = "static" in rest
            last = rest[-1]
            if last == "infinite":
                scope.lease_seconds = None
            elif not _addresses([last]) and duration(last) is not None:
                scope.lease_seconds = duration(last)
            else:
                scope.lease_seconds = 3600  # dnsmasq's default lease time
            scope.start = addrs[0]
            mask = None
            if not static and len(addrs) >= 2:
                scope.pools.append((addrs[0], addrs[1]))
                mask = addrs[2] if len(addrs) >= 3 else None
            elif static and len(addrs) >= 2:
                mask = addrs[1]
            if mask is not None:
                with contextlib.suppress(ValueError):
                    scope.network = ip_network(f"{addrs[0]}/{mask}", strict=False)
            out.scopes.append(scope)
        elif key == "dhcp-host" and items:
            mac = next((m for m in map(_mac, items) if m), None)
            addr = next((a for a in _addresses(items) if a.version == 4), None)
            names = [
                i
                for i in items
                if i
                and not _mac(i)
                and not _addresses([i])
                and duration(i) is None
                and i != "infinite"
                and ":" not in i
                and not i.startswith("[")
            ]
            if mac and addr:
                global_scope.reservations.append(
                    Reservation(mac=mac, address=addr, hostname=names[0] if names else None)
                )
        elif key in ("dhcp-option", "dhcp-option-force") and items:
            tags = set()
            while items and items[0].startswith(("tag:", "encap:", "vendor:")):
                head = items.pop(0)
                if head.startswith("tag:"):
                    tags.add(head[4:])
            if not items or items[0].startswith("option6:"):
                continue
            head = items[0]
            name: str | None = None
            if head.startswith("option:"):
                name = head[7:]
                code = DNSMASQ_NAMES.get(name)
            else:
                code = int(head) if head.isdigit() else None
            if code is None or not 1 <= code <= 254:
                continue
            tagged.append((tags, code, name, items[1:]))
    for scope in out.scopes:
        scope.domain = domain
        scope.authoritative = out.authoritative
        for tags, code, name, values in tagged:
            if not tags or tags & scope.tags:
                _set_option(scope, code, name, values)
        scope.reservations = list(global_scope.reservations)  # narrowed by the adapter
    return out


def dnsmasq_leases(text: str) -> list[DhcpLease]:
    """``/var/lib/misc/dnsmasq.leases``: ``<expiry> <mac> <ip> <name|*> <client id|*>``;
    after a ``duid`` line, IPv6: ``<expiry> <iaid> <ip6> <name|*> <duid>``."""
    out: list[DhcpLease] = []
    v6 = False
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "duid":
            v6 = True
            continue
        if len(parts) < 4 or not parts[0].isdigit():
            continue
        expiry = int(parts[0])
        expires = _epoch(expiry) if expiry else None
        name = parts[3] if parts[3] != "*" else None
        client = parts[4] if len(parts) > 4 and parts[4] != "*" else None
        try:
            address = ip_address(parts[2])
        except ValueError:
            continue
        mac = None if v6 else _mac(parts[1])
        if mac is None and client is None:
            continue
        out.append(
            DhcpLease(address=address, mac=mac, client_id=client, hostname=name, expires=expires)
        )
    return out


# --- Kea ---------------------------------------------------------------------------------------


def strip_comments(text: str) -> str:
    """Kea's JSON allows ``#``, ``//`` and ``/* */`` comments; strings are kept as they are."""
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
            out.append(c)
        elif c == "#" or text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _kea_options(scope: Scope, data: Any) -> None:
    for o in data if isinstance(data, list) else []:
        if not isinstance(o, dict) or o.get("space", "dhcp4") != "dhcp4":
            continue
        name = o.get("name") if isinstance(o.get("name"), str) else None
        code = o.get("code") if isinstance(o.get("code"), int) else KEA_NAMES.get(name or "")
        if code is None or not 1 <= code <= 254 or not isinstance(o.get("data"), str):
            continue
        values = [o["data"]] if code in (15, 66, 67) else o["data"].split(",")
        _set_option(scope, code, name, values)


@dataclass
class Kea:
    scopes: list[Scope] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)
    configured: bool = False
    error: str | None = None


def parse_kea(text: str) -> Kea:
    try:
        data = json.loads(strip_comments(text))
    except ValueError as exc:
        return Kea(configured=True, error=f"kea-dhcp4.conf is not valid JSON: {exc}")
    root = data.get("Dhcp4") if isinstance(data, dict) else None
    if not isinstance(root, dict):
        return Kea(configured=True, error="kea-dhcp4.conf has no Dhcp4 section")
    out = Kea(configured=True)
    ifaces = root.get("interfaces-config", {}).get("interfaces", [])
    out.interfaces = [str(i).split("/")[0] for i in ifaces if isinstance(i, str)]
    peer = _kea_peer(root)
    subnets: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for s in root.get("subnet4") or []:
        subnets.append((s, {}))
    for shared in root.get("shared-networks") or []:
        if isinstance(shared, dict):
            for s in shared.get("subnet4") or []:
                subnets.append((s, shared))
    for s, shared in subnets:
        if not isinstance(s, dict):
            continue
        try:
            network = ip_network(str(s.get("subnet")), strict=False)
        except ValueError:
            continue
        sid = s.get("id") if isinstance(s.get("id"), int) else None
        scope = Scope("kea", f"kea-{sid if sid is not None else len(out.scopes)}", network=network)
        scope.kea_id = sid
        scope.interface = s.get("interface") or shared.get("interface") or None
        lifetime = s.get("valid-lifetime", shared.get("valid-lifetime", root.get("valid-lifetime")))
        scope.lease_seconds = lifetime if isinstance(lifetime, int) else 4000  # Kea's default
        auth = s.get("authoritative", shared.get("authoritative", root.get("authoritative")))
        scope.authoritative = auth if isinstance(auth, bool) else False
        for p in s.get("pools") or []:
            text_pool = str(p.get("pool", "")) if isinstance(p, dict) else ""
            if "-" in text_pool:
                a, _, b = text_pool.partition("-")
                found = _addresses([a, b])
                if len(found) == 2:
                    scope.pools.append((found[0], found[1]))
            elif "/" in text_pool:
                with contextlib.suppress(ValueError):
                    net = ip_network(text_pool.strip(), strict=False)
                    scope.pools.append((net[0], net[-1]))
        for level in (root, shared, s):
            _kea_options(scope, level.get("option-data"))
        for r in s.get("reservations") or []:
            if not isinstance(r, dict):
                continue
            mac = _mac(str(r.get("hw-address", "")))
            addr = _addresses([str(r.get("ip-address", ""))])
            if mac and addr:
                host = r.get("hostname") if isinstance(r.get("hostname"), str) else None
                scope.reservations.append(Reservation(mac=mac, address=addr[0], hostname=host))
        scope.failover_peer = peer
        out.scopes.append(scope)
    return out


def _kea_peer(root: dict[str, Any]) -> str | None:
    for hook in root.get("hooks-libraries") or []:
        if not isinstance(hook, dict) or "libdhcp_ha" not in str(hook.get("library", "")):
            continue
        ha = (hook.get("parameters") or {}).get("high-availability") or []
        for cfg in ha if isinstance(ha, list) else []:
            me = cfg.get("this-server-name")
            for p in cfg.get("peers") or []:
                if isinstance(p, dict) and p.get("name") != me and p.get("role") != "backup":
                    return str(p.get("name") or p.get("url") or "") or None
    return None


def kea_leases(text: str) -> list[tuple[int | None, DhcpLease]]:
    """``kea-leases4.csv`` (memfile): the last row of an address wins. (subnet id, lease)."""
    rows: dict[str, tuple[int | None, DhcpLease]] = {}
    for row in csv.DictReader(io.StringIO(text)):
        try:
            address = ip_address(row["address"])
            expire = int(row.get("expire") or 0)
            lifetime = int(row.get("valid_lifetime") or 0)
        except (KeyError, ValueError):
            continue
        state = {"0": LeaseState.ACTIVE, "1": LeaseState.DECLINED, "2": LeaseState.EXPIRED}.get(
            str(row.get("state", "0")).strip(), LeaseState.ACTIVE
        )
        mac = _mac(row.get("hwaddr") or "")
        client = (row.get("client_id") or "").strip() or None
        if mac is None and client is None:
            rows.pop(str(address), None)
            continue
        expires = _epoch(expire) if expire else None
        starts = expires - timedelta(seconds=lifetime) if expires and lifetime else None
        sid = int(row["subnet_id"]) if (row.get("subnet_id") or "").isdigit() else None
        rows[str(address)] = (
            sid,
            DhcpLease(
                address=address,
                mac=mac,
                client_id=client,
                hostname=(row.get("hostname") or "").strip().rstrip(".") or None,
                state=state,
                starts=starts,
                expires=expires,
            ),
        )
    return list(rows.values())


# --- ISC dhcpd -------------------------------------------------------------------------------


def _tokens(text: str) -> list[str]:
    out: list[str] = []
    for raw in text.splitlines():
        line = raw
        if "#" in line:  # comments, but not inside strings
            quoted = False
            for i, c in enumerate(line):
                if c == '"':
                    quoted = not quoted
                elif c == "#" and not quoted:
                    line = line[:i]
                    break
        out += re.findall(r'"[^"]*"|[{};,]|[^\s{};,"]+', line)
    return out


@dataclass
class _Block:
    head: list[str]
    body: list[_Block | list[str]] = field(default_factory=list)


def _blocks(tokens: list[str]) -> list[_Block | list[str]]:
    stack: list[_Block] = [_Block([])]
    current: list[str] = []
    for t in tokens:
        if t == ";":
            if current:
                stack[-1].body.append(current)
            current = []
        elif t == "{":
            block = _Block(current)
            stack[-1].body.append(block)
            stack.append(block)
            current = []
        elif t == "}":
            if current:
                stack[-1].body.append(current)
            current = []
            if len(stack) > 1:
                stack.pop()
        else:
            current.append(t)
    return stack[0].body


def _isc_statement(scope: Scope, words: list[str]) -> None:
    if not words:
        return
    values = [w for w in words[2:] if w != ","]
    if words[0] == "range" and len(words) >= 2:
        found = _addresses([w for w in words[1:] if w != "dynamic-bootp"])
        if len(found) == 2:
            scope.pools.append((found[0], found[1]))
        elif len(found) == 1:
            scope.pools.append((found[0], found[0]))
    elif words[0] == "default-lease-time" and len(words) > 1 and words[1].isdigit():
        scope.lease_seconds = int(words[1])
    elif words[0] == "authoritative":
        scope.authoritative = True
    elif words[0] == "not" and words[1:2] == ["authoritative"]:
        scope.authoritative = False
    elif words[0] == "option" and len(words) >= 3:
        name = words[1]
        code = {
            "routers": 3,
            "domain-name-servers": 6,
            "domain-name": 15,
            "ntp-servers": 42,
            "domain-search": 119,
        }.get(name)
        if code is not None:
            _set_option(scope, code, name, values)


def _isc_host(words: list[_Block | list[str]]) -> Reservation | None:
    mac = addr = None
    for w in words:
        if isinstance(w, list) and w[:2] == ["hardware", "ethernet"] and len(w) > 2:
            mac = _mac(w[2])
        elif isinstance(w, list) and w[:1] == ["fixed-address"] and len(w) > 1:
            found = _addresses([w[1]])
            addr = found[0] if found else None
    return Reservation(mac=mac, address=addr) if mac and addr else None


def parse_isc(text: str) -> list[Scope]:
    body = _blocks(_tokens(text))
    defaults = Scope("isc", "global", lease_seconds=43200)  # dhcpd's default lease time
    defaults.authoritative = False
    hosts: list[Reservation] = []
    found: list[tuple[_Block, list[list[str]]]] = []
    peer: str | None = None

    def walk(items: list[_Block | list[str]], inherited: list[list[str]]) -> None:
        nonlocal peer
        own = [w for w in items if isinstance(w, list)]
        for item in items:
            if isinstance(item, list):
                continue
            head = item.head
            if head[:1] == ["subnet"]:
                found.append((item, inherited + own))
            elif head[:1] in (["shared-network"], ["group"]):
                walk(item.body, inherited + own)
            elif head[:1] == ["host"]:
                r = _isc_host(item.body)
                if r:
                    hosts.append(r)
            elif head[:2] == ["failover", "peer"] and len(head) > 2:
                peer = head[2].strip('"')

    walk(body, [])
    for w in body:
        if isinstance(w, list):
            _isc_statement(defaults, w)
    scopes: list[Scope] = []
    for n, (block, inherited) in enumerate(found):
        head = block.head
        try:
            network = ip_network(f"{head[1]}/{head[3]}", strict=False)
        except (IndexError, ValueError):
            continue
        scope = Scope(
            "isc",
            f"isc-{n}",
            network=network,
            lease_seconds=defaults.lease_seconds,
            authoritative=defaults.authoritative,
        )
        for w in inherited:
            _isc_statement(scope, w)
        for item in block.body:
            if isinstance(item, list):
                _isc_statement(scope, item)
            elif item.head[:1] == ["pool"]:
                for w in item.body:
                    if isinstance(w, list) and w[:2] == ["failover", "peer"] and len(w) > 2:
                        scope.failover_peer = w[2].strip('"')
                    elif isinstance(w, list):
                        _isc_statement(scope, w)
            elif item.head[:1] == ["host"]:
                r = _isc_host(item.body)
                if r:
                    hosts.append(r)
        scope.reservations = [r for r in hosts if r.address in network]
        scopes.append(scope)
    for scope in scopes:  # hosts declared after their subnet
        assert scope.network is not None
        scope.reservations = [r for r in hosts if r.address in scope.network]
    return scopes


def _isc_time(words: list[str]) -> datetime | None:
    """``starts 3 2026/11/20 10:00:00`` (UTC), ``ends never``, ``ends epoch 1795400000``."""
    if len(words) >= 3 and words[1] == "epoch" and words[2].isdigit():
        return _epoch(int(words[2]))
    if len(words) >= 4:
        with contextlib.suppress(ValueError):
            return datetime.strptime(f"{words[2]} {words[3]}", "%Y/%m/%d %H:%M:%S").replace(
                tzinfo=UTC
            )
    return None


def isc_leases(text: str) -> list[DhcpLease]:
    """``dhcpd.leases``: later entries of an address replace earlier ones."""
    out: dict[str, DhcpLease] = {}
    for item in _blocks(_tokens(text)):
        if isinstance(item, list) or item.head[:1] != ["lease"] or len(item.head) < 2:
            continue
        try:
            address = ip_address(item.head[1])
        except ValueError:
            continue
        fields: dict[str, Any] = {}
        for w in item.body:
            if not isinstance(w, list) or not w:
                continue
            if w[0] in ("starts", "ends"):
                fields[w[0]] = _isc_time(w)
            elif w[:2] == ["binding", "state"] and len(w) > 2:
                fields["state"] = w[2]
            elif w[:2] == ["hardware", "ethernet"] and len(w) > 2:
                fields["mac"] = _mac(w[2])
            elif w[0] == "uid" and len(w) > 1:
                fields["uid"] = w[1].strip('"')
            elif w[0] == "client-hostname" and len(w) > 1:
                fields["hostname"] = w[1].strip('"')
        if not fields.get("mac") and not fields.get("uid"):
            continue
        state = {
            "active": LeaseState.ACTIVE,
            "free": LeaseState.EXPIRED,
            "expired": LeaseState.EXPIRED,
            "released": LeaseState.EXPIRED,
            "abandoned": LeaseState.DECLINED,
            "backup": LeaseState.EXPIRED,
        }.get(fields.get("state", "active"), LeaseState.ACTIVE)
        starts, ends = fields.get("starts"), fields.get("ends")
        out[str(address)] = DhcpLease(
            address=address,
            mac=fields.get("mac"),
            client_id=fields.get("uid") or None,
            hostname=fields.get("hostname") or None,
            state=state,
            starts=starts,
            expires=ends if not (starts and ends and ends < starts) else None,
        )
    return list(out.values())


# --- systemd-networkd ------------------------------------------------------------------------


def _ini(text: str) -> list[tuple[str, dict[str, list[str]]]]:
    out: list[tuple[str, dict[str, list[str]]]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            out.append((line[1:-1].strip(), {}))
        elif out and "=" in line:
            key, _, value = line.partition("=")
            out[-1][1].setdefault(key.strip(), []).append(value.strip())
    return out


def _yes(values: list[str] | None, default: bool) -> bool:
    if not values:
        return default
    return values[-1].lower() in ("yes", "true", "1", "on")


def parse_networkd(files: dict[str, str], names: list[str]) -> list[Scope]:
    """``.network`` files with ``DHCPServer=yes``: the pool from ``PoolOffset``/``PoolSize`` of
    the first IPv4 ``Address=`` (defaults: from the first address after the network address to
    the last before the broadcast), lease time 1 h, router and DNS: the server itself."""
    out: list[Scope] = []
    seen: set[str] = set()
    for path, text in sorted(files.items(), key=lambda x: x[0].rsplit("/", 1)[-1]):
        base = path.rsplit("/", 1)[-1]
        if base in seen:  # /etc overrides /run
            continue
        seen.add(base)
        sections = _ini(text)
        match = [v for name, s in sections if name == "Match" for v in s.get("Name", [])]
        patterns = [p for v in match for p in v.split()]
        network = {k: v for name, s in sections if name == "Network" for k, v in s.items()}
        if not _yes(network.get("DHCPServer"), False):
            continue
        server = {k: v for name, s in sections if name == "DHCPServer" for k, v in s.items()}
        address = None
        for value in network.get("Address", []):
            with contextlib.suppress(ValueError):
                address = IPv4Interface(value)
                break
        if address is None:
            continue
        iface = next((n for n in names if any(fnmatch.fnmatch(n, p) for p in patterns)), None)
        net = address.network
        offset = int(server.get("PoolOffset", ["0"])[-1] or 0)
        first = max(offset, 1)
        size_text = server.get("PoolSize", [""])[-1]
        last = net.num_addresses - 2
        if size_text.isdigit():
            last = min(first + int(size_text) - 1, last)
        scope = Scope(
            "networkd", f"networkd-{base.rsplit('.', 1)[0]}", interface=iface, network=net
        )
        if first <= last:
            scope.pools.append((net[first], net[last]))
        lease = server.get("DefaultLeaseTimeSec", [""])[-1]
        scope.lease_seconds = duration(lease) if lease else 3600
        if _yes(server.get("EmitRouter"), True):
            routers = _addresses(server.get("Router", []))
            scope.router = routers[0] if routers else address.ip
        if _yes(server.get("EmitDNS"), True):
            scope.dns = _addresses(" ".join(server.get("DNS", [])).split())
        if _yes(server.get("EmitNTP"), True):
            scope.ntp = _addresses(" ".join(server.get("NTP", [])).split())
        for name, s in sections:
            if name != "DHCPServerStaticLease":
                continue
            mac = _mac((s.get("MACAddress") or [""])[-1])
            addr = _addresses(s.get("Address") or [])
            if mac and addr:
                scope.reservations.append(Reservation(mac=mac, address=addr[0]))
        out.append(scope)
    return out
