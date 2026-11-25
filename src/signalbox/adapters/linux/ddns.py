"""Dynamic DNS clients on Linux: ddclient and inadyn (#450), from their files.

Read: ``/etc/ddclient.conf`` (or ``/etc/ddclient/ddclient.conf``), ``/etc/inadyn.conf`` (or
``/etc/inadyn/inadyn.conf``) and the clients' cache files (ddclient ``ddclient.cache``, inadyn
``<name>.cache`` with the file's modification time). Per name: provider, hostname, address
family, whether the updates use HTTPS, when the last update happened, its result and the address
it announced.

**Secrets never get past this module.** The configuration files hold the account name, password
or token of the provider. Three layers keep them out:

1. the read script on the device removes every ``key = value`` whose key names a credential
   (:data:`collect.DDNS_CLEAN`) *before* the text leaves the device, and reads a file Signalbox
   may not open directly only through the sudoers rule for exactly that file (``cat`` of the
   file, piped through that filter on the device);
2. :func:`scrub` removes the same parts again, before any line is parsed, so an older script or a
   device whose filter failed cannot leak (the test feeds a raw file);
3. the parsers keep an allow-list of keys (``protocol``, ``use``, ``ssl``, ``if``, ``hostname``,
   ``provider`` and the like) and nothing else: no value is kept "because it was there", and no
   line is logged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Literal

from signalbox.adapters import Gap
from signalbox.adapters.linux.collect import Answer
from signalbox.model import DdnsResult, DynamicDns, IPAddress, Uplink, object_id

#: A ``key = value`` whose key names a credential, to the end of the line (the value may be quoted
#: and hold spaces and commas, so the rest of the line goes). The same rule as the device filter.
SECRET = re.compile(
    r"[A-Za-z_-]*(?:pass|token|secret|key|login|user|auth|cred)[A-Za-z_-]*\s*=.*",
    re.IGNORECASE,
)
HOST = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,63}\.?$"
)
#: What ddclient says in a cache line after ``status=``: these are a success.
GOOD = frozenset({"good", "nochg", "ok", "success", "updated"})
CONF_FILES = (
    "/etc/ddclient.conf",
    "/etc/ddclient/ddclient.conf",
    "/etc/inadyn.conf",
    "/etc/inadyn/inadyn.conf",
)
DDCLIENT_CACHE = (
    "/var/cache/ddclient/ddclient.cache",
    "/var/lib/ddclient/ddclient.cache",
    "/var/run/ddclient.cache",
    "/run/ddclient.cache",
)
INADYN_CACHE_DIR = "/var/cache/inadyn"

_PROVIDERS = (
    ("duckdns", "duckdns"),
    ("cloudflare", "cloudflare"),
    ("no-ip", "noip"),
    ("noip", "noip"),
    ("dyndns", "dyndns2"),
)
_BOOL = {"yes": True, "true": True, "1": True, "on": True, "no": False, "false": False, "0": False}


def scrub(text: str) -> str:
    """The text without any credential part: every ``key = value`` whose key names a credential
    is cut to its key (``password =``), to the end of the line."""
    return "\n".join(
        SECRET.sub(lambda m: m.group(0).split("=", 1)[0] + "=", ln) for ln in text.splitlines()
    )


def provider(name: str) -> str:
    low = name.lower()
    return next((p for key, p in _PROVIDERS if key in low), "other")


@dataclass
class Client:
    """One name of a client, before the cache is joined."""

    client: str  # "ddclient" or "inadyn"
    hostname: str
    provider: str = "other"
    families: list[Literal[4, 6]] = field(default_factory=lambda: [4])
    tls: bool | None = None
    interface: str | None = None


def _hostname(token: str) -> str | None:
    token = token.strip().strip("\"'").rstrip(",;").lower()
    return token if HOST.match(token) else None


# ddclient ---------------------------------------------------------------------------------

_PAIR = re.compile(r"""([A-Za-z0-9_.-]+)\s*=\s*("[^"]*"|'[^']*'|[^,\s]*)""")


def ddclient_conf(text: str) -> list[Client]:
    """The names of a ``ddclient.conf``: ``key=value`` settings (all sticky, a later line
    overrides) and bare words, which are host names and close the stanza they complete. A line may
    end in ``\\`` and go on."""
    lines: list[str] = []
    carry = ""
    for raw in scrub(text).splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if line.endswith("\\"):
            carry += line[:-1] + " "
            continue
        lines.append(carry + line)
        carry = ""
    if carry:
        lines.append(carry)
    settings: dict[str, str] = {}
    out: list[Client] = []
    for line in lines:
        for m in _PAIR.finditer(line):
            settings[m.group(1).lower()] = m.group(2).strip("\"'")
        rest = _PAIR.sub(" ", line)
        for word in re.split(r"[\s,]+", rest):
            host = _hostname(word) if word else None
            if host is None:
                continue
            out.append(_ddclient_client(host, settings))
    return out


def _ddclient_client(host: str, s: dict[str, str]) -> Client:
    families: list[Literal[4, 6]] = []
    pairs: tuple[tuple[str, Literal[4, 6]], ...] = (("use", 4), ("usev4", 4), ("usev6", 6))
    for key, family in pairs:
        value = s.get(key, "").lower()
        if value and value not in ("disabled", "no", "none"):
            families.append(family)
    if _BOOL.get(s.get("ipv6", "").lower()) and 6 not in families:
        families.append(6)
    # ddclient 3.9 had ``use=`` for IPv4 only; 3.10 and 3.11 add usev4 and usev6
    if not families:
        families = [4]
    tls = _BOOL.get(s.get("ssl", "").lower())
    iface = s.get("if") or None
    return Client(
        "ddclient",
        host,
        provider(s.get("protocol", "")),
        sorted(set(families)),
        tls,
        iface,
    )


# inadyn ------------------------------------------------------------------------------------

_BLOCK = re.compile(r"^\s*(provider|custom)\s+([^\s{]+)\s*\{?\s*$", re.IGNORECASE)
_KV = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=\s*(.*?)\s*;?\s*$")


def inadyn_conf(text: str) -> list[Client]:
    """The ``provider`` and ``custom`` blocks of an ``inadyn.conf``: ``hostname`` (one name or a
    ``{ "a", "b" }`` list) and ``ssl``. A built-in ``provider`` uses HTTPS unless ``ssl = false``
    (*guess for 2.x, #21*); a ``custom`` one only where it says so."""
    out: list[Client] = []
    kind = ""
    name = ""
    body: dict[str, str] = {}

    def close() -> None:
        if not kind:
            return
        tls = _BOOL.get(body.get("ssl", "").lower())
        if tls is None and kind == "provider":
            tls = True
        for host in re.findall(r"[^\s,{}\"']+", body.get("hostname", "")):
            h = _hostname(host)
            if h:
                out.append(Client("inadyn", h, provider(name), [4], tls))

    for raw in scrub(text).splitlines():
        line = raw.split("#", 1)[0].rstrip()
        block = _BLOCK.match(line)
        if block:
            close()
            kind, name = block.group(1).lower(), block.group(2).split(":", 1)[0]
            body = {}
            continue
        if line.strip().startswith("}") and "{" not in line:
            close()
            kind, body = "", {}
            continue
        kv = _KV.match(line)
        if kv and kind:
            body[kv.group(1).lower()] = kv.group(2)
    close()
    return out


# caches ------------------------------------------------------------------------------------

#: The keys read from a ddclient cache line; everything else (should a version write an account
#: name there) is dropped.
_CACHE_KEYS = frozenset({"ip", "ip4", "ip6", "mtime", "atime", "status", "host"})


@dataclass
class CacheEntry:
    address: IPAddress | None = None
    stamp: int | None = None
    status: str = ""


def _address(value: str) -> IPAddress | None:
    try:
        return ip_address(value.strip().strip("\"'"))
    except ValueError:
        return None


def ddclient_cache(text: str) -> dict[str, CacheEntry]:
    """``mtime=1,atime=2,status=good,ip=203.0.113.4 host.example`` lines of ``ddclient.cache``
    (the host last, or a ``host=`` key); ``mtime`` is the last successful update."""
    out: dict[str, CacheEntry] = {}
    for raw in scrub(text).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        keys = {m.group(1).lower(): m.group(2) for m in _PAIR.finditer(line)}
        tail = (
            line.rsplit(None, 1)[-1] if " " in line and "=" not in line.rsplit(None, 1)[-1] else ""
        )
        host = _hostname(keys.get("host", "") or tail)
        if host is None:
            continue
        keys = {k: v for k, v in keys.items() if k in _CACHE_KEYS}
        stamp = keys.get("mtime", "")
        out[host] = CacheEntry(
            _address(keys.get("ip") or keys.get("ip4") or keys.get("ip6") or ""),
            int(stamp) if stamp.isdigit() else None,
            keys.get("status", "").lower(),
        )
    return out


def inadyn_cache(path: str, text: str, stamp: int | None) -> tuple[str, CacheEntry] | None:
    """``/var/cache/inadyn/<name>.cache`` holds the address; the file's time is the last update
    (*guess for 2.x, #21*: older versions kept one ``inadyn.cache``)."""
    name = path.rsplit("/", 1)[-1].removesuffix(".cache")
    host = _hostname(name)
    first = scrub(text).split(None, 1)
    if host is None or not first:
        return None
    return host, CacheEntry(_address(first[0]), stamp)


# the answer --------------------------------------------------------------------------------


def read(
    device_id: str, answer: Answer, uplinks: list[Uplink]
) -> tuple[list[DynamicDns], list[Gap]]:
    """The clients named in the files of ``ddns-conf``, with ``ddns-cache`` and ``ddns-mtime``;
    nothing for a device whose script predates the section. A configuration file that is there
    but not readable is an optional gap."""
    if not answer.has("ddns-conf"):
        return [], []
    clients: list[Client] = []
    for path, text in answer.files("ddns-conf").items():
        clients += inadyn_conf(text) if "inadyn" in path else ddclient_conf(text)
    cache: dict[str, CacheEntry] = {}
    times: dict[str, int] = {}
    for ln in answer.lines("ddns-mtime"):
        epoch, _, path = ln.strip().partition(" ")
        if epoch.isdigit():
            times[path.strip()] = int(epoch)
    for path, text in answer.files("ddns-cache").items():
        if "inadyn" in path:
            one = inadyn_cache(path, text, times.get(path))
            if one:
                cache[one[0]] = one[1]
        else:
            cache.update(ddclient_cache(text))
    names = {n: up.id for up in uplinks for n in (up.name, up.id.rsplit("/", 1)[-1])}
    out: dict[str, DynamicDns] = {}
    for c in clients:
        entry = cache.get(c.hostname)
        stamp = entry.stamp if entry else None
        result = DdnsResult.UNKNOWN
        if entry and entry.status:
            result = DdnsResult.OK if entry.status in GOOD else DdnsResult.ERROR
        elif entry and stamp:
            result = DdnsResult.OK
        key = f"{c.client}-{c.hostname}"
        out[key] = DynamicDns(
            id=object_id(device_id, "ddns", key),
            device_id=device_id,
            provider=c.provider,
            hostname=c.hostname,
            uplink_id=names.get(c.interface or ""),
            families=c.families,
            enabled=True,
            last_update=datetime.fromtimestamp(stamp, UTC) if stamp else None,
            last_result=result,
            published_address=entry.address if entry else None,
            tls=c.tls,
        )
    # a cache the login may not open is not a gap: sudo is never used for it (least privilege)
    unreadable = answer.unreadable("ddns-conf")
    gaps: list[Gap] = []
    if unreadable:
        files = ", ".join(sorted(set(unreadable)))
        gaps.append(
            Gap(
                message=f"dynamic DNS: {files} not readable, so the client's names or its last "
                "update are not known",
                fix="Run Set up automatically or Repair Signalbox's access again (it adds a "
                "read-only rule for the configuration file), or accept that the dynamic DNS "
                "client is not read.",
                optional=True,
                message_id="linux.ddnsUnreadable",
                fix_id="linux.ddnsUnreadable.fix",
                params={"files": files},
            )
        )
    return [out[k] for k in sorted(out)], gaps
