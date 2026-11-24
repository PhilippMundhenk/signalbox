"""Remote syslog targets of rsyslog and syslog-ng (#180), from their configuration files.

rsyslog: the legacy forms ``*.* @host:514`` (UDP) and ``*.* @@host:514`` (TCP, ``@@(o)`` too)
and ``action(type="omfwd" target=... port=... protocol=... StreamDriverMode="1")`` (TLS). The
selector before a legacy action is kept as the topic. syslog-ng: ``destination`` blocks with
``network(...)``, ``syslog(...)``, ``udp(...)`` or ``tcp(...)``; a destination is enabled when a
``log`` statement names it. Includes are not followed beyond the files read (``rsyslog.d``,
``conf.d``); a target in a template or behind a macro is not seen.
"""

from __future__ import annotations

import re

from signalbox.model import LOG_PORTS, LogKind, LogTarget, LogTransport

_LEGACY = re.compile(r"^\s*(?P<sel>[^\s#]+)\s+(?P<at>@@?)(?:\([^)]*\))?(?P<dest>\S+)")
_OMFWD = re.compile(r"action\s*\((?P<body>[^)]*\btype\s*=\s*\"omfwd\"[^)]*)\)", re.I | re.S)
_PARAM = re.compile(r"(\w+)\s*=\s*\"([^\"]*)\"")
_NG_DEST = re.compile(r"destination\s+(?P<name>[\w.-]+)\s*\{(?P<body>.*?)\}\s*;", re.S)
_NG_DRIVER = re.compile(
    r"\b(?P<driver>network|syslog|udp|tcp|udp6|tcp6)\s*\(\s*\"?(?P<host>[^\"\s)]+)\"?(?P<opts>.*)",
    re.S,
)
_NG_LOG = re.compile(r"\blog\s*\{(?P<body>.*?)\}\s*;", re.S)


def _strip_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _host_port(dest: str) -> tuple[str, int | None]:
    dest = dest.split(";", 1)[0]
    if dest.startswith("["):
        host, _, rest = dest[1:].partition("]")
        port = rest.removeprefix(":")
        return host, int(port) if port.isdigit() else None
    if dest.count(":") == 1:
        host, _, port = dest.partition(":")
        return host, int(port) if port.isdigit() else None
    return dest, None


def rsyslog(files: dict[str, str]) -> list[LogTarget]:
    out: list[LogTarget] = []
    for text in files.values():
        for line in text.splitlines():
            m = _LEGACY.match(line)
            if m is None:
                continue
            host, port = _host_port(m.group("dest"))
            if not host:
                continue
            out.append(
                LogTarget(
                    kind=LogKind.SYSLOG,
                    address=host,
                    port=port or LOG_PORTS[LogKind.SYSLOG],
                    transport=LogTransport.TCP if m.group("at") == "@@" else LogTransport.UDP,
                    name="rsyslog",
                    topics=[m.group("sel")],
                )
            )
        for m in _OMFWD.finditer(_strip_comments(text)):
            params = {k.lower(): v for k, v in _PARAM.findall(m.group("body"))}
            host = params.get("target", "").strip()
            if not host:
                continue
            proto = params.get("protocol", "udp").lower()
            tls = params.get("streamdrivermode") == "1"
            port = params.get("port", "")
            out.append(
                LogTarget(
                    kind=LogKind.SYSLOG,
                    address=host,
                    port=int(port) if port.isdigit() else LOG_PORTS[LogKind.SYSLOG],
                    transport=LogTransport.TLS
                    if tls
                    else LogTransport.TCP
                    if proto == "tcp"
                    else LogTransport.UDP,
                    name="rsyslog",
                )
            )
    return out


def syslog_ng(files: dict[str, str]) -> list[LogTarget]:
    text = "\n".join(_strip_comments(t) for t in files.values())
    used: set[str] = set()
    for m in _NG_LOG.finditer(text):
        used.update(re.findall(r"destination\s*\(\s*([\w.-]+)\s*\)", m.group("body")))
    out: list[LogTarget] = []
    for m in _NG_DEST.finditer(text):
        d = _NG_DRIVER.search(m.group("body"))
        if d is None:
            continue
        opts = d.group("opts")
        transport = re.search(r"transport\s*\(\s*\"?(\w+)", opts)
        proto = transport.group(1).lower() if transport else ""
        if not proto:
            proto = "tcp" if d.group("driver").startswith("tcp") else "udp"
            proto = "tcp" if d.group("driver") == "syslog" else proto
        port = re.search(r"port\s*\(\s*(\d+)", opts)
        out.append(
            LogTarget(
                kind=LogKind.SYSLOG,
                address=d.group("host"),
                port=int(port.group(1)) if port else LOG_PORTS[LogKind.SYSLOG],
                transport=LogTransport.TLS
                if proto == "tls"
                else LogTransport.TCP
                if proto == "tcp"
                else LogTransport.UDP,
                enabled=m.group("name") in used,
                name=m.group("name"),
            )
        )
    return out


def targets(files: dict[str, str]) -> list[LogTarget]:
    rs = {p: t for p, t in files.items() if "rsyslog" in p}
    ng = {p: t for p, t in files.items() if "syslog-ng" in p}
    return [*rsyslog(rs), *syslog_ng(ng)]
