"""OpenVPN on OpenWrt (#153, #527): the UCI ``openvpn`` config and the status file.

Every ``config openvpn '<name>'`` section is a tunnel: a section with ``client '1'`` or a
``remote`` is a client, one with ``server`` a server. The runtime state is the status file
(``/var/run/openvpn.<name>.status``, or the section's ``status`` option) read with ``file read``:
it needs the ACL entry ``/var/run/openvpn.*.status``; without it ``up`` and the connected clients
stay unknown and the findings that need them stay quiet. Status format 2 and 3 (``status_version``
2 or 3) carry the time as epoch seconds: a fresh ``TIME`` line means the server runs and its
``CLIENT_LIST`` rows are the sessions; format 1 (the default) has only local-time text, so it
gives the clients without their connection time and ``up`` stays unknown (*guess*: the file
layouts are from the OpenVPN 2.4 to 2.6 manual; the update interval of OpenWrt's init script is
not assumed, a status older than 15 minutes counts as stopped).
Static keys (``secret``), ``tls_auth``, ``tls_crypt``, passwords and key files are dropped by
:func:`scrub` the moment the answer arrives; only the flags ``tls_auth_set`` and
``tls_crypt_set`` remain. Covered: OpenWrt 21.02 to 24.10 and later (the section type has been
``openvpn`` since the package began).
"""

from __future__ import annotations

import contextlib
import re
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from typing import Any, Literal

from signalbox.model import (
    IPNetwork,
    Tunnel,
    TunnelKind,
    TunnelRole,
    TunnelSession,
    object_id,
)

#: A status file older than this (seconds) belongs to a stopped instance.
STATUS_MAX_AGE = 900
#: Where the init script writes the status of a section unless ``status`` is set.
STATUS_GLOB = "/var/run/openvpn.*.status"

#: Options whose value is (the path of) a key, a password or a static secret: dropped.
SECRET_OPTIONS = (
    "secret",
    "tls_auth",
    "tls_crypt",
    "tls_crypt_v2",
    "askpass",
    "auth_user_pass",
    "key",
    "pkcs12",
    "cryptoapicert",
)


def scrub(answer: dict[str, Any]) -> dict[str, Any]:
    """The ``uci get openvpn`` answer without static keys and the like (in place; also
    returned): ``tls_auth``, ``tls_crypt`` and ``tls_crypt_v2`` become the flags ``<name>_set``."""
    values = answer.get("values")
    for section in values.values() if isinstance(values, dict) else []:
        if not isinstance(section, dict):
            continue
        for option in SECRET_OPTIONS:
            had = section.pop(option, None)
            if (option.startswith("tls_") or option == "secret") and had not in (None, "", []):
                section[f"{option}_set"] = "1"
    return answer


def _list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [value.strip()] if isinstance(value, str) and value.strip() else []


def _flag(value: Any) -> bool:
    return str(value).lower() in ("1", "true", "yes", "on")


def _network(text: str) -> IPNetwork | None:
    """``10.8.0.0 255.255.255.0`` (address and mask, as OpenVPN writes them) or CIDR."""
    parts = text.split()
    with contextlib.suppress(ValueError):
        if len(parts) == 2:
            return ip_network(f"{parts[0]}/{parts[1]}", strict=False)
        if len(parts) == 1:
            return ip_network(parts[0], strict=False)
    return None


def _routes(section: dict[str, Any]) -> list[IPNetwork]:
    out: list[IPNetwork] = []
    for line in [*_list(section.get("push")), *(f"route {r}" for r in _list(section.get("route")))]:
        words = line.replace('"', "").split(None, 1)
        if len(words) == 2 and words[0] == "route":
            n = _network(" ".join(words[1].split()[:2]))
            if n is not None and n not in out:
                out.append(n)
    return out


def _proto(value: Any) -> Literal["udp", "tcp"] | None:
    text = str(value or "").lower()
    return "udp" if text.startswith("udp") else "tcp" if text.startswith("tcp") else None


def status_path(name: str, section: dict[str, Any]) -> str:
    """Where the status of the section is: its ``status`` option (the first word), else the
    init script's ``/var/run/openvpn.<name>.status``."""
    words = str(section.get("status") or "").split()
    return words[0] if words else f"/var/run/openvpn.{name}.status"


def status_paths(uci: dict[str, Any]) -> dict[str, str]:
    """Section name to status file path, of the enabled server and client sections."""
    values = uci.get("values")
    return {
        name: status_path(name, section)
        for name, section in sorted(values.items() if isinstance(values, dict) else [])
        if isinstance(section, dict)
        and section.get(".type") == "openvpn"
        and _flag(section.get("enabled", "1"))
    }


class Status:
    """What a status file says: when it was written (None: format 1, no epoch) and the
    clients. Never anything else of the file."""

    def __init__(self, updated: datetime | None, sessions: list[TunnelSession]) -> None:
        self.updated = updated
        self.sessions = sessions

    def up(self, now: datetime) -> bool | None:
        if self.updated is None:
            return None
        return (now - self.updated).total_seconds() <= STATUS_MAX_AGE


def _address(text: str) -> Any:
    host = text.strip().split("/")[0]
    with contextlib.suppress(ValueError):
        return ip_address(host)
    return None


def parse_status(text: str) -> Status | None:
    """Parse a status file of format 1, 2 (comma) or 3 (tab); None: not a status file."""
    updated: datetime | None = None
    sessions: list[TunnelSession] = []
    known = False
    in_v1 = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        sep = "\t" if "\t" in line else ","
        row = [c.strip() for c in line.split(sep)]
        head = row[0]
        if head == "TITLE" or head.startswith("OpenVPN "):
            known = True
        if head == "TIME" and len(row) >= 3 and row[2].isdigit():
            updated = datetime.fromtimestamp(int(row[2]), UTC)
        elif head == "CLIENT_LIST" and len(row) >= 8:
            # CLIENT_LIST, Common Name, Real Address, Virtual Address, Virtual IPv6 Address,
            # Bytes Received, Bytes Sent, Connected Since, Connected Since (time_t), ...
            since = None
            if len(row) > 8 and row[8].isdigit():
                since = datetime.fromtimestamp(int(row[8]), UTC)
            sessions.append(
                TunnelSession(
                    common_name=None if row[1] in ("", "UNDEF") else row[1],
                    virtual_address=_address(row[3]) or _address(row[4]),
                    connected_since=since,
                )
            )
        elif head == "OpenVPN CLIENT LIST":
            in_v1 = True
        elif head == "ROUTING TABLE" or head == "GLOBAL STATS" or head == "END":
            in_v1 = False
        elif in_v1 and len(row) >= 5 and head not in ("Updated", "Common Name"):
            # a format 1 client row: the name only (the time is local text, not epoch)
            sessions.append(TunnelSession(common_name=None if head in ("", "UNDEF") else head))
    return Status(updated, sessions) if known else None


def tunnels(
    uci: dict[str, Any],
    device_id: str,
    statuses: dict[str, Status] | None = None,
    now: datetime | None = None,
) -> list[Tunnel]:
    """Tunnels of the ``openvpn`` sections of a :func:`scrub`bed ``uci get openvpn`` answer;
    ``statuses`` (section name to parsed status file) gives ``up`` and the clients of servers."""
    at = now or datetime.now(UTC)
    values = uci.get("values")
    out: list[Tunnel] = []
    for name, section in sorted(values.items() if isinstance(values, dict) else []):
        if not isinstance(section, dict) or section.get(".type") != "openvpn":
            continue
        remotes = _list(section.get("remote"))
        is_client = _flag(section.get("client")) or (bool(remotes) and not section.get("server"))
        is_server = bool(section.get("server")) or _flag(section.get("server_bridge"))
        role = TunnelRole.CLIENT if is_client else TunnelRole.SERVER if is_server else None
        # a section with certificates or a TLS role uses TLS; a static-key tunnel does not
        tls = not _flag(section.get("secret_set")) and (
            any(section.get(o) for o in ("ca", "cert", "tls_server", "tls_client"))
            or bool(is_server or is_client)
        )
        has_key = any(
            _flag(section.get(f"{o}_set")) for o in ("tls_auth", "tls_crypt", "tls_crypt_v2")
        )
        port = str(section.get("port") or "").strip()
        if not port and remotes and len(remotes[0].split()) > 1:
            port = remotes[0].split()[1]
        nets = _network(str(section.get("server") or "")) if is_server else None
        cipher = ",".join(
            dict.fromkeys(
                c
                for c in [
                    *re.split(r"[:,\s]+", str(section.get("cipher") or "")),
                    *re.split(r"[:,\s]+", str(section.get("data_ciphers") or "")),
                ]
                if c
            )
        )
        name_clean = re.sub(r"[^A-Za-z0-9_.-]", "_", name) or "openvpn"
        disabled = not _flag(section.get("enabled", "1"))
        status = (statuses or {}).get(name)
        up: bool | None = False if disabled else None
        sessions: list[TunnelSession] | None = None
        if status is not None and not disabled:
            up = status.up(at)
            if is_server and role is TunnelRole.SERVER:
                sessions = [] if up is False else status.sessions
        out.append(
            Tunnel(
                id=object_id(device_id, "tunnel", f"openvpn-{name_clean}"),
                device_id=device_id,
                kind=TunnelKind.OPENVPN,
                name=f"openvpn-{name_clean}",
                description=name,
                up=up,
                enabled=not disabled,
                listen_port=int(port)
                if is_server and port.isdigit() and 1 <= int(port) <= 65535
                else None,
                role=role,
                protocol=_proto(section.get("proto")),
                cipher=cipher or None,
                tls_auth=(has_key if tls else None),
                tunnel_network=nets if is_server else None,
                pushed_routes=_routes(section),
                remote_gateway=remotes[0].split()[0] if remotes and is_client else None,
                sessions=sessions,
            )
        )
    return out
