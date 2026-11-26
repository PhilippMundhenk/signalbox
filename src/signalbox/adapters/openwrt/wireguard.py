"""WireGuard on OpenWrt (#152): UCI ``proto wireguard`` interfaces and ``getWgInstances``.

The ``network`` UCI config holds ``private_key`` (interface) and ``preshared_key`` (peer)
next to the public data. :func:`scrub` drops both the moment the answer arrives: the private
key is deleted, the pre-shared key becomes the flag ``preshared_key_set``. Nothing here
copies, stores or logs a key that is not a public key.
"""

from __future__ import annotations

import contextlib
import re
from datetime import UTC, datetime
from ipaddress import ip_interface, ip_network
from typing import Any

from signalbox.model import (
    WIREGUARD_KEY,
    IPInterface,
    IPNetwork,
    Tunnel,
    TunnelPeer,
    object_id,
    port_id,
)

SECRET_OPTIONS = ("private_key", "preshared_key")


def scrub(answer: dict[str, Any]) -> dict[str, Any]:
    """The ``uci get`` answer without private and pre-shared keys (in place; also returned)."""
    values = answer.get("values")
    for section in values.values() if isinstance(values, dict) else []:
        if not isinstance(section, dict):
            continue
        section.pop("private_key", None)
        if str(section.pop("preshared_key", None) or "").strip():
            section["preshared_key_set"] = "1"
    return answer


def drop_keys(answer: dict[str, Any]) -> dict[str, Any]:
    """The ``uci get network`` answer without private and pre-shared keys and without the flag
    :func:`scrub` leaves (in place; also returned): what the writer, the backup and a restore
    see (#152). A restore therefore neither sets nor deletes a key."""
    values = answer.get("values")
    for section in values.values() if isinstance(values, dict) else []:
        if isinstance(section, dict):
            for option in SECRET_OPTIONS:
                section.pop(option, None)
    return answer


def _list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return str(value).replace(",", " ").split() if isinstance(value, str) else []


def _flag(value: Any) -> bool:
    return str(value).lower() in ("1", "true", "yes", "on")


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def _key(value: Any) -> str | None:
    text = value.strip() if isinstance(value, str) else ""
    return text if re.fullmatch(WIREGUARD_KEY, text) else None


def _networks(values: Any) -> list[IPNetwork]:
    out: list[IPNetwork] = []
    for part in _list(values):
        with contextlib.suppress(ValueError):
            out.append(ip_network(part, strict=False))
    return out


def _addresses(values: Any) -> list[IPInterface]:
    out: list[IPInterface] = []
    for part in _list(values):
        with contextlib.suppress(ValueError):
            addr = ip_interface(part)
            if not addr.ip.is_link_local and not addr.ip.is_loopback:
                out.append(addr)
    return out


def _endpoint(value: Any) -> tuple[str | None, int | None]:
    """``203.0.113.5:51820``, ``[2001:db8::1]:51820``, ``(none)``."""
    text = value.strip() if isinstance(value, str) else ""
    if not text or text == "(none)":
        return None, None
    host, sep, port = text.rpartition(":")
    if not sep or not port.isdigit() or not 1 <= int(port) <= 65535:
        return text.strip("[]") or None, None
    return host.strip("[]") or None, int(port)


def interfaces(uci: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    values = uci.get("values")
    if not isinstance(values, dict):
        return []
    return [
        (str(s.get(".name", n)), s)
        for n, s in values.items()
        if isinstance(s, dict) and s.get(".type") == "interface" and s.get("proto") == "wireguard"
    ]


def instances(answer: Any) -> dict[str, dict[str, Any]]:
    """``luci.wireguard getWgInstances``: ``{"wg0": {"public_key", "listen_port", "peers"}}``
    (luci-proto-wireguard; a guess for other releases). Only public data is looked at."""
    data = answer.get("instances", answer) if isinstance(answer, dict) else {}
    return {k: v for k, v in data.items() if isinstance(v, dict)} if isinstance(data, dict) else {}


def _peers(name: str, uci: dict[str, Any], runtime: dict[str, Any]) -> list[TunnelPeer]:
    running: dict[str, dict[str, Any]] = {}
    for p in runtime.get("peers") or []:
        if isinstance(p, dict) and (k := _key(p.get("public_key"))):
            running[k] = p
    out: dict[str, TunnelPeer] = {}
    values = uci.get("values")
    for section in values.values() if isinstance(values, dict) else []:
        if not isinstance(section, dict) or section.get(".type") != f"wireguard_{name}":
            continue
        key = _key(section.get("public_key"))
        if key is None or key in out:
            continue
        host = str(section.get("endpoint_host") or "").strip() or None
        port = _int(section.get("endpoint_port"))
        live = running.get(key, {})
        seen_host, seen_port = _endpoint(live.get("endpoint"))
        stamp = _int(live.get("latest_handshake"))
        keepalive = _int(section.get("persistent_keepalive"))
        out[key] = TunnelPeer(
            public_key=key,
            name=str(section.get("description") or "").strip() or None,
            endpoint_host=host or seen_host,
            endpoint_port=(port if host else seen_port) if (host or seen_host) else None,
            allowed_ips=_networks(section.get("allowed_ips")),
            latest_handshake=datetime.fromtimestamp(stamp, UTC) if stamp else None,
            rx_bytes=_nonneg(live.get("transfer_rx")),
            tx_bytes=_nonneg(live.get("transfer_tx")),
            keepalive_seconds=keepalive if keepalive is not None and 0 <= keepalive <= 65535 else 0,
            preshared_key=_flag(section.get("preshared_key_set")),
            enabled=not _flag(section.get("disabled")),
            signalbox_key=str(section.get("signalbox") or "").strip() or None,
        )
    return list(out.values())


def _route_target(section: dict[str, Any]) -> IPNetwork | None:
    """``option target`` of a ``route`` (with ``netmask``) or ``route6`` section."""
    target = str(section.get("target") or "").strip()
    if not target:
        return None
    if "/" not in target and section.get("netmask"):
        target = f"{target}/{section['netmask']}"
    try:
        return ip_network(target, strict=False)
    except ValueError:
        return None


def routes(uci: dict[str, Any], name: str) -> list[IPNetwork]:
    """What the configuration routes into interface *name*: ``route``/``route6`` sections of
    the interface, and the allowed IPs of peers with ``route_allowed_ips``."""
    out: list[IPNetwork] = []
    values = uci.get("values")
    for section in values.values() if isinstance(values, dict) else []:
        if not isinstance(section, dict) or _flag(section.get("disabled")):
            continue
        kind = section.get(".type")
        if kind in ("route", "route6") and section.get("interface") == name:
            if (net := _route_target(section)) is not None:
                out.append(net)
        elif kind == f"wireguard_{name}" and _flag(section.get("route_allowed_ips")):
            out += _networks(section.get("allowed_ips"))
    return out


def _nonneg(value: Any) -> int | None:
    n = _int(value)
    return n if n is not None and n >= 0 else None


def tunnels(
    uci: dict[str, Any],
    runtime: dict[str, dict[str, Any]],
    device_id: str,
    up: dict[str, bool],
    ports: set[str],
) -> list[Tunnel]:
    """Tunnels of the ``proto wireguard`` interfaces (*uci* is :func:`scrub`bed), with the
    running state of ``getWgInstances`` (*runtime*, by interface name) where there is one."""
    out = []
    for name, section in interfaces(uci):
        live = runtime.get(name, {})
        listen = _int(section.get("listen_port")) or _int(live.get("listen_port"))
        mtu = _int(section.get("mtu"))
        addresses = _addresses(section.get("addresses"))
        if not addresses:  # old style: ipaddr (+ netmask)
            for ip in _list(section.get("ipaddr")):
                with contextlib.suppress(ValueError):
                    mask = section.get("netmask") or "255.255.255.255"
                    addresses.append(ip_interface(ip if "/" in ip else f"{ip}/{mask}"))
        disabled = _flag(section.get("disabled"))
        out.append(
            Tunnel(
                id=object_id(device_id, "tunnel", name),
                device_id=device_id,
                name=name,
                port_id=port_id(device_id, name) if name in ports else None,
                up=False if disabled else up.get(name),
                enabled=not disabled,
                listen_port=listen if listen and 1 <= listen <= 65535 else None,
                public_key=_key(live.get("public_key")),
                signalbox_key=str(section.get("signalbox") or "").strip() or None,
                addresses=addresses,
                mtu=mtu if mtu is not None and 68 <= mtu <= 65535 else None,
                routes=routes(uci, name),
                peers=_peers(name, uci, live),
            )
        )
    return out
