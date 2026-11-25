"""OpenVPN on OpenWrt (#153): the UCI ``openvpn`` config, configuration only.

Every ``config openvpn '<name>'`` section is a tunnel: a section with ``client '1'`` or a
``remote`` is a client, one with ``server`` a server. The runtime state (status file, ``ubus
service list``) is not part of the read-only ACL, so ``up`` and the connected clients stay
unknown; the findings that need them stay quiet. Static keys (``secret``), ``tls_auth``,
``tls_crypt``, passwords and key files are dropped by :func:`scrub` the moment the answer
arrives; only the flags ``tls_auth_set`` and ``tls_crypt_set`` remain. Covered: OpenWrt 21.02
to 24.10 and later (the section type has been ``openvpn`` since the package began).
"""

from __future__ import annotations

import contextlib
import re
from ipaddress import ip_network
from typing import Any, Literal

from signalbox.model import IPNetwork, Tunnel, TunnelKind, TunnelRole, object_id

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


def tunnels(uci: dict[str, Any], device_id: str) -> list[Tunnel]:
    """Tunnels of the ``openvpn`` sections of a :func:`scrub`bed ``uci get openvpn`` answer."""
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
        out.append(
            Tunnel(
                id=object_id(device_id, "tunnel", f"openvpn-{name_clean}"),
                device_id=device_id,
                kind=TunnelKind.OPENVPN,
                name=f"openvpn-{name_clean}",
                description=name,
                up=False if disabled else None,
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
            )
        )
    return out
