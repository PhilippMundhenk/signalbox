"""MikroTik IPsec and OpenVPN (#153): ``/ip/ipsec`` and ``/interface/ovpn-*`` as tunnels.

Read policy only. A tunnel is one IPsec peer with its identity (how it authenticates: only the
method, never ``secret``, ``password``, ``eap-password`` or keys), its profile (RouterOS 7.1
and later; before that the peer holds ``enc-algorithm`` and friends itself, which is read the
same way), the policies that name it (the child SAs, with ``ph2-state``) and the active peer
(``/ip/ipsec/active-peers``). Menus an older or smaller router does not have are skipped
(404), a menu the group may not read is an optional gap. RouterOS 6 has no REST API, so it is
not read at all (the adapter says so already); RouterOS 7.1 to 7.x are covered, the exact field
spelling of ``ph2-state`` and of the OpenVPN menus is a *guess* until a CHR run (#21).

OpenVPN: ``/interface/ovpn-server/server`` (one object: the server) with the connected clients
of ``/interface/ovpn-server`` and ``/interface/ovpn-client``. RouterOS has no tls-auth or
tls-crypt (no ``tls_auth``: it stays unknown, so the rule is quiet) and lists ciphers as
``blowfish128,aes128,aes256``.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from ipaddress import ip_address
from typing import Any, Literal

from signalbox.adapters import ipsec
from signalbox.model import (
    Tunnel,
    TunnelAuth,
    TunnelChild,
    TunnelKind,
    TunnelRole,
    TunnelSession,
    object_id,
)

PEERS = "/rest/ip/ipsec/peer"
IDENTITIES = "/rest/ip/ipsec/identity"
PROFILES = "/rest/ip/ipsec/profile"
PROPOSALS = "/rest/ip/ipsec/proposal"
POLICIES = "/rest/ip/ipsec/policy"
ACTIVE = "/rest/ip/ipsec/active-peers"
OVPN_SERVER = "/rest/interface/ovpn-server/server"
OVPN_SESSIONS = "/rest/interface/ovpn-server"
OVPN_CLIENTS = "/rest/interface/ovpn-client"

_SECRET = re.compile(r"secret|password|passphrase|private|preshared|psk|^key$|remote-key", re.I)


def clean(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The rows without any field that can hold a secret, dropped before anything looks at
    them; kept as a flag only where the method needs it (``secret-set``)."""
    out = []
    for row in rows:
        kept = {k: v for k, v in row.items() if not _SECRET.search(k)}
        kept["secret-set"] = any(_SECRET.search(k) and v not in ("", None) for k, v in row.items())
        out.append(kept)
    return out


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return value is True or _text(value).lower() in ("true", "yes", "on")


def _names(value: Any) -> list[str]:
    parts = value if isinstance(value, list) else _text(value).split(",")
    return [p.strip() for p in parts if isinstance(p, str) and p.strip()]


def _duration(value: Any) -> int | None:
    """RouterOS time (``1h2m3s``, ``1d``, ``00:10:00``) in seconds."""
    text = _text(value).replace(" ", "")
    m = re.fullmatch(r"(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?", text)
    if m and any(m.groups()):
        w, d, h, mi, s = (int(g) if g else 0 for g in m.groups())
        return (((w * 7 + d) * 24 + h) * 60 + mi) * 60 + s
    m = re.fullmatch(r"(?:(\d+)d)?(\d+):(\d+):(\d+)", text)
    if m:
        d, h, mi, s = (int(g) if g else 0 for g in m.groups())
        return ((d * 24 + h) * 60 + mi) * 60 + s
    return int(text) if text.isdigit() else None


def _auth(method: str) -> TunnelAuth | None:
    low = method.lower()
    if low.startswith("pre-shared-key"):
        return TunnelAuth.PSK
    if low.startswith("eap"):
        return TunnelAuth.EAP
    if low in ("digital-signature", "rsa-key", "rsa-signature", "ecdsa-signature"):
        return TunnelAuth.CERTIFICATE
    return None


def _address(value: str) -> str | None:
    """The peer's address without ``/32``; a wildcard (``0.0.0.0/0``, ``::/0``) is None."""
    return ipsec.gateway(value.split("/")[0] if not value.endswith("/0") else "")


def ipsec_tunnels(
    device_id: str,
    peers: list[dict[str, Any]],
    identities: list[dict[str, Any]],
    profiles: list[dict[str, Any]],
    proposals: list[dict[str, Any]],
    policies: list[dict[str, Any]],
    active: list[dict[str, Any]] | None,
    now: datetime,
) -> list[Tunnel]:
    """One tunnel per peer. *active* None: ``active-peers`` not read (``up`` stays unknown)."""
    by_profile = {_text(p.get("name")): p for p in profiles}
    by_proposal = {_text(p.get("name")): p for p in proposals}
    out: list[Tunnel] = []
    for row in peers:
        name = _text(row.get("name"))
        if not name or _flag(row.get("dynamic")):
            continue
        profile = by_profile.get(_text(row.get("profile")), row)
        mode = _text(row.get("exchange-mode")).lower()
        version: Literal[1, 2] = 2 if mode.startswith("ike2") else 1
        remote = _address(_text(row.get("address")))
        method = next(
            (
                _auth(_text(i.get("auth-method")))
                for i in identities
                if _text(i.get("peer")) == name and _auth(_text(i.get("auth-method")))
            ),
            None,
        )
        props = ipsec.parts(
            _names(profile.get("enc-algorithm")),
            _names(profile.get("hash-algorithm")),
            _names(profile.get("dh-group")),
        )
        mine = [
            p
            for p in policies
            if _text(p.get("peer")) == name
            and not _flag(p.get("template"))
            and not _flag(p.get("dynamic"))
        ]
        children: list[TunnelChild] = []
        peer_active = [
            a
            for a in active or []
            if remote is not None and _text(a.get("remote-address")).split("[")[0] == remote
        ]
        uptime = _duration(peer_active[0].get("uptime")) if peer_active else None
        for pol in mine:
            proposal_row = by_proposal.get(_text(pol.get("proposal")), {})
            props += [
                p
                for p in ipsec.parts(
                    _names(proposal_row.get("enc-algorithms")),
                    _names(proposal_row.get("auth-algorithms")),
                    _names(proposal_row.get("pfs-group"))
                    if _text(proposal_row.get("pfs-group")) != "none"
                    else [],
                )
                if p not in props
            ]
            state = _text(pol.get("ph2-state")).lower()
            children.append(
                TunnelChild(
                    name=f"{_text(pol.get('src-address'))} - {_text(pol.get('dst-address'))}"[:80],
                    local_networks=ipsec.networks(_text(pol.get("src-address"))),
                    remote_networks=ipsec.networks(_text(pol.get("dst-address"))),
                    established=(state == "established") if state else None,
                    rekey_seconds=_duration(proposal_row.get("lifetime")),
                    last_rekey=now - timedelta(seconds=uptime)
                    if uptime is not None and state == "established"
                    else None,
                    enabled=not _flag(pol.get("disabled")),
                )
            )
        lifetime = _text(profile.get("dpd-interval"))
        out.append(
            Tunnel(
                id=object_id(device_id, "tunnel", f"ipsec-{name}"),
                device_id=device_id,
                kind=TunnelKind.IPSEC,
                name=f"ipsec-{name}",
                description=_text(row.get("comment")) or name,
                up=None if active is None else bool(peer_active),
                enabled=not _flag(row.get("disabled")),
                ike_version=version,
                aggressive=mode.startswith("aggressive"),
                remote_gateway=remote,
                auth=method,
                proposals=props,
                dpd=lifetime not in ("", "disable", "disabled")
                if "dpd-interval" in profile
                else None,
                children=children,
            )
        )
    return out


def _proto(value: Any) -> Literal["udp", "tcp"] | None:
    text = _text(value).lower()
    return "udp" if text == "udp" else "tcp" if text == "tcp" else None


def openvpn_tunnels(
    device_id: str,
    server: dict[str, Any] | None,
    sessions: list[dict[str, Any]],
    clients: list[dict[str, Any]],
) -> list[Tunnel]:
    """The OpenVPN server (one tunnel; ``sessions`` lists who is connected) and each client
    interface."""
    out: list[Tunnel] = []
    # the menu exists on every RouterOS 7 router: the server is a tunnel once it is switched on
    if server is not None and (_flag(server.get("enabled")) or sessions):
        port = _text(server.get("port"))
        clients_now = []
        for s in sessions:
            name = _text(s.get("user"))
            try:
                virtual = ip_address(_text(s.get("client-address")).split("/")[0])
            except ValueError:
                virtual = None
            clients_now.append(
                TunnelSession(
                    common_name=name or None,
                    virtual_address=virtual,
                )
            )
        enabled = _flag(server.get("enabled"))
        out.append(
            Tunnel(
                id=object_id(device_id, "tunnel", "ovpn-server"),
                device_id=device_id,
                kind=TunnelKind.OPENVPN,
                name="ovpn-server",
                description="OpenVPN server",
                up=enabled,
                enabled=enabled,
                listen_port=int(port) if port.isdigit() and 1 <= int(port) <= 65535 else None,
                role=TunnelRole.SERVER,
                protocol=_proto(server.get("protocol")),
                cipher=",".join(_names(server.get("cipher"))) or None,
                sessions=clients_now,
            )
        )
    for row in clients:
        name = _text(row.get("name"))
        if not name:
            continue
        disabled = _flag(row.get("disabled"))
        out.append(
            Tunnel(
                id=object_id(device_id, "tunnel", name),
                device_id=device_id,
                kind=TunnelKind.OPENVPN,
                name=name,
                description=_text(row.get("comment")) or None,
                port_id=None,
                up=False if disabled else (_flag(row.get("running")) if "running" in row else None),
                enabled=not disabled,
                role=TunnelRole.CLIENT,
                protocol=_proto(row.get("protocol")),
                cipher=",".join(_names(row.get("cipher"))) or None,
                remote_gateway=_text(row.get("connect-to")) or None,
                listen_port=None,
            )
        )
    return out
