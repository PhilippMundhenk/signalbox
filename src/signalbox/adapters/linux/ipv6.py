"""IPv6 router advertisements and DHCPv6 of a Linux host (#151): ``radvd.conf`` and dnsmasq.

Read only from files (radvd's configuration, dnsmasq's ``enable-ra`` and IPv6 ``dhcp-range``
lines); a host that sends router advertisements with something else (systemd-networkd's
``IPv6SendRA``, kea, the kernel's own) reports nothing.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from ipaddress import IPv6Address, IPv6Network, ip_address

from signalbox.model import RaMode

_COMMENT = re.compile(r"(^|\s)(#|//).*$", re.M)
_TOKEN = re.compile(r"[{};]|[^\s{};]+")


@dataclass
class RaInterface:
    """One ``interface`` block of radvd.conf (or the dnsmasq equivalent)."""

    name: str | None = None
    #: Network of the range (dnsmasq without an interface name): finds the segment by prefix.
    network: IPv6Network | None = None
    send: bool = True
    managed: bool = False
    other: bool = False
    lifetime: int | None = None
    #: (prefix, on-link, autonomous)
    prefixes: list[tuple[IPv6Network, bool | None, bool | None]] = field(default_factory=list)
    rdnss: list[IPv6Address] = field(default_factory=list)
    dnssl: list[str] = field(default_factory=list)
    #: dnsmasq: a DHCPv6 server answers (stateful range or ra-stateless)
    dhcpv6: bool = False
    dhcpv6_stateful: bool = False
    lease_seconds: int | None = None
    pool: tuple[IPv6Address, IPv6Address] | None = None


def _on(value: str) -> bool:
    return value.lower() in ("on", "1", "yes", "true")


def _int(value: str) -> int | None:
    return int(value) if value.isdigit() else None


def parse_radvd(text: str) -> list[RaInterface]:
    """The ``interface`` blocks of radvd.conf. ``AdvSendAdvert``, ``AdvManagedFlag``,
    ``AdvOtherConfigFlag``, ``AdvDefaultLifetime`` (default: 3 * MaxRtrAdvInterval, 1800 s for
    the defaults), ``prefix ... { AdvOnLink; AdvAutonomous }`` (both default ``on``),
    ``RDNSS`` and ``DNSSL`` blocks. A block without ``AdvSendAdvert on`` sends nothing."""
    tokens = _TOKEN.findall(_COMMENT.sub("", text))
    out: list[RaInterface] = []
    i = 0
    while i < len(tokens):
        if tokens[i] == "interface" and i + 2 < len(tokens) and tokens[i + 2] == "{":
            block = RaInterface(name=tokens[i + 1], send=False)
            i = _interface(tokens, i + 3, block)
            out.append(block)
        else:
            i += 1
    return out


def _statements(tokens: list[str], i: int) -> tuple[list[list[str]], list[list[str]], int]:
    """Split a block body into plain statements and nested blocks (head tokens, body flattened
    by the caller); returns the index after the closing brace."""
    plain: list[list[str]] = []
    nested: list[list[str]] = []
    cur: list[str] = []
    while i < len(tokens):
        t = tokens[i]
        if t == "}":
            return plain, nested, i + 1
        if t == ";":
            if cur:
                plain.append(cur)
            cur = []
        elif t == "{":
            body, _, i = _statements(tokens, i + 1)
            nested.append([*cur, "{", *(x for stmt in body for x in (*stmt, ";"))])
            cur = []
            continue
        else:
            cur.append(t)
        i += 1
    return plain, nested, i


def _interface(tokens: list[str], i: int, block: RaInterface) -> int:
    plain, nested, i = _statements(tokens, i)
    for stmt in plain:
        key, args = stmt[0].lower(), stmt[1:]
        value = args[0] if args else ""
        if key == "advsendadvert":
            block.send = _on(value)
        elif key == "advmanagedflag":
            block.managed = _on(value)
        elif key == "advotherconfigflag":
            block.other = _on(value)
        elif key == "advdefaultlifetime":
            block.lifetime = _int(value)
    for head in nested:
        brace = head.index("{")
        words, body = head[:brace], head[brace + 1 :]
        kind = words[0].lower() if words else ""
        flags = {
            s[0].lower(): s[1].lower()
            for s in _split(body)
            if len(s) > 1 and s[0].startswith("Adv")
        }
        if kind == "prefix" and len(words) > 1:
            with contextlib.suppress(ValueError):
                block.prefixes.append(
                    (
                        IPv6Network(words[1], strict=False),
                        _on(flags["advonlink"]) if "advonlink" in flags else True,
                        _on(flags["advautonomous"]) if "advautonomous" in flags else True,
                    )
                )
        elif kind == "rdnss":
            for word in words[1:]:
                with contextlib.suppress(ValueError):
                    a = ip_address(word)
                    if isinstance(a, IPv6Address):
                        block.rdnss.append(a)
        elif kind == "dnssl":
            block.dnssl += words[1:]
    return i


def _split(body: list[str]) -> list[list[str]]:
    out: list[list[str]] = []
    cur: list[str] = []
    for t in body:
        if t == ";":
            if cur:
                out.append(cur)
            cur = []
        else:
            cur.append(t)
    return out


def _duration(text: str) -> int | None:
    match = re.fullmatch(r"(\d+)([smhdw]?)", text.lower())
    if not match:
        return None
    return (
        int(match.group(1))
        * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[match.group(2)]
    )


def parse_dnsmasq6(files: dict[str, str]) -> list[RaInterface]:
    """IPv6 ``dhcp-range`` lines of dnsmasq with ``enable-ra``. ``ra-only`` and ``slaac``-less
    ranges send advertisements only; ``ra-stateless`` adds a stateless DHCPv6 server (O flag); a
    range of addresses is a stateful server (M flag). ``constructor:<if>`` and
    ``interface:<if>`` name the interface, else the range's prefix finds the network.
    ``dhcp-option=option6:dns-server,[addr]`` and ``option6:domain-search`` are announced in
    both. Without ``enable-ra`` dnsmasq answers DHCPv6 but sends no advertisements."""
    lines: list[tuple[str, str]] = []
    for text in files.values():
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                key, _, value = line.partition("=")
                lines.append((key.strip(), value.strip()))
    ra = any(k == "enable-ra" for k, _ in lines)
    dns: list[IPv6Address] = []
    search: list[str] = []
    for key, value in lines:
        if key not in ("dhcp-option", "dhcp-option-force"):
            continue
        parts = [p.strip() for p in value.split(",")]
        parts = [p for p in parts if not p.startswith("tag:")]
        if parts and parts[0] == "option6:dns-server":
            for p in parts[1:]:
                with contextlib.suppress(ValueError):
                    a = ip_address(p.strip("[]"))
                    if isinstance(a, IPv6Address) and not a.is_unspecified:
                        dns.append(a)
        elif parts and parts[0] == "option6:domain-search":
            search += parts[1:]
    out: list[RaInterface] = []
    for key, value in lines:
        if key != "dhcp-range":
            continue
        items = [i.strip() for i in value.split(",")]
        name: str | None = None
        words = []
        for item in items:
            if item.startswith(("interface:", "constructor:")):
                name = item.split(":", 1)[1]
            elif not item.startswith(("set:", "tag:")):
                words.append(item)
        addrs = []
        for w in words:
            with contextlib.suppress(ValueError):
                a = ip_address(w.strip("[]"))
                if isinstance(a, IPv6Address):
                    addrs.append(a)
        if not addrs:
            continue
        ra_only = "ra-only" in words
        stateless = "ra-stateless" in words
        stateful = not ra_only and not stateless
        length = next((int(w) for w in words if w.isdigit() and 1 <= int(w) <= 128), 64)
        start = addrs[0]
        net = None if name else IPv6Network((start, length), strict=False)
        pool = (addrs[0], addrs[1]) if len(addrs) >= 2 and not addrs[0].is_unspecified else None
        lease = next((_duration(w) for w in reversed(words) if _duration(w) is not None), None)
        out.append(
            RaInterface(
                name=name,
                network=net,
                send=ra,
                managed=ra and stateful,
                other=ra and (stateful or stateless),
                rdnss=dns,
                dnssl=search,
                dhcpv6=stateful or stateless,
                dhcpv6_stateful=stateful,
                lease_seconds=lease if stateful or stateless else None,
                pool=pool if stateful else None,
            )
        )
    return out


def mode_of(block: RaInterface) -> RaMode:
    if not block.send:
        return RaMode.OFF
    if block.managed:
        return RaMode.STATEFUL
    if block.other:
        return RaMode.STATELESS
    return RaMode.SLAAC
