"""OPNsense IPsec and OpenVPN (#153): connections, child SAs and instances as tunnels.

Read only, with the privileges *VPN: IPsec* and *VPN: OpenVPN: Instances* (names are a
*guess*, #21). The endpoints exist since 23.7 (swanctl "Connections", OpenVPN "Instances");
older releases keep their tunnels in the legacy pages, which have no API and are not read.
Both spellings of the actions (``search_connection`` and ``searchConnection``) are handled by
the HTTP client. What was covered, from the public ``opnsense/core`` models of 24.7, 25.1,
25.7 and 26.1 (the grid columns are a *guess* where a release was not checked, #21):

* ``/api/ipsec/connections/search_connection``: ``uuid``, ``enabled``, ``description``,
  ``version`` (``IKEv1``/``IKEv2``/``0``), ``aggressive``, ``remote_addrs``, ``proposals``,
  ``dpd_delay``; ``search_child``: ``connection`` (uuid), ``local_ts``, ``remote_ts``,
  ``esp_proposals``, ``rekey_time``; ``search_local``/``search_remote``: ``connection`` and
  ``auth`` (``psk``, ``pubkey``, ``eap-*``). Pre-shared keys (``secret`` of the key list) and
  certificate references are never asked for.
* ``/api/ipsec/sessions/search_phase1`` and ``search_phase2``: the running IKE and child SAs.
* ``/api/openvpn/instances/search``: ``role``, ``proto``, ``port``, ``server`` (virtual
  network), ``route``, ``tls_key`` (whether a static key is chosen, never the key),
  ``data-ciphers``/``cipher``; ``/api/openvpn/service/search_sessions``: connected clients.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
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

CONNECTIONS = "/api/ipsec/connections/search_connection"
CHILDREN = "/api/ipsec/connections/search_child"
LOCALS = "/api/ipsec/connections/search_local"
PHASE1 = "/api/ipsec/sessions/search_phase1"
PHASE2 = "/api/ipsec/sessions/search_phase2"
OVPN_INSTANCES = "/api/openvpn/instances/search"
OVPN_SESSIONS = "/api/openvpn/service/search_sessions"
IPSEC_PRIVILEGE = "VPN: IPsec (page-vpn-ipsec)"
OPENVPN_PRIVILEGE = "VPN: OpenVPN: Instances (page-openvpn-instances)"


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int | float):
        return str(value)
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return _text(value).lower() in ("1", "true", "yes", "on", "enabled")


def _seconds(value: Any) -> int | None:
    """Seconds from ``3600``, ``3600s`` or ``1h``; None for anything else."""
    text = _text(value).lower()
    m = re.fullmatch(r"(\d+)\s*(s|m|h|d)?", text)
    if m is None:
        return None
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2) or ""]


def _version(value: Any) -> Literal[1, 2] | None:
    text = _text(value).lower()
    if text in ("1", "ikev1"):
        return 1
    if text in ("2", "ikev2"):
        return 2
    return None  # 0 / "IKE": both versions are accepted


def _auth(value: str) -> TunnelAuth | None:
    low = value.lower()
    if low == "psk":
        return TunnelAuth.PSK
    if low.startswith("eap"):
        return TunnelAuth.EAP
    if low in ("pubkey", "rsa", "ecdsa") or low.startswith(("pubkey", "cert")):
        return TunnelAuth.CERTIFICATE
    return None


def _keys(row: dict[str, Any], *names: str) -> set[str]:
    return {_text(row.get(n)) for n in names if _text(row.get(n))}


def _name(uuid: str) -> str:
    return f"ipsec-{uuid[:8]}" if uuid else "ipsec"


def ipsec_tunnels(
    device_id: str,
    connections: list[dict[str, Any]],
    children: list[dict[str, Any]],
    locals_: list[dict[str, Any]],
    phase1: list[dict[str, Any]] | None,
    phase2: list[dict[str, Any]] | None,
    now: datetime,
) -> list[Tunnel]:
    """One tunnel per connection with its children. *phase1* and *phase2* are the running
    SAs; None: not read (no privilege), then ``up`` and ``established`` stay unknown."""
    out: list[Tunnel] = []
    for row in connections:
        uuid = _text(row.get("uuid"))
        label = _text(row.get("description"))
        mine_keys = {uuid} | ({label} if label else set())
        auth = None
        for loc in locals_:
            if _text(loc.get("connection")) == uuid and _auth(_text(loc.get("auth"))):
                auth = _auth(_text(loc.get("auth")))
                break
        sessions1 = [
            p for p in phase1 or [] if mine_keys & _keys(p, "name", "phase1desc", "description")
        ]
        up: bool | None = None
        if phase1 is not None:
            up = any(
                _text(p.get("state") or p.get("status")).lower()
                in ("established", "up", "connected", "1")
                or _flag(p.get("connected"))
                for p in sessions1
            )
        kids: list[TunnelChild] = []
        for child in children:
            if _text(child.get("connection")) != uuid:
                continue
            cuuid = _text(child.get("uuid"))
            cname = _text(child.get("description")) or f"child-{cuuid[:8]}"
            established: bool | None = None
            rekeyed: datetime | None = None
            if phase2 is not None:
                own = [c for c in children if _text(c.get("connection")) == uuid]
                ikeids = {_text(p.get("ikeid")) for p in sessions1} - {""}
                match = [
                    s
                    for s in phase2
                    if _keys(s, "name", "phase2desc", "description") & {cuuid, cname}
                    or (len(own) == 1 and _text(s.get("ikeid")) in ikeids)
                ]
                established = bool(match) if sessions1 else (False if up is False else None)
                if match:
                    age = _seconds(match[0].get("install-time") or match[0].get("install_time"))
                    rekeyed = now - timedelta(seconds=age) if age is not None else None
            kids.append(
                TunnelChild(
                    name=cname,
                    local_networks=ipsec.networks(_text(child.get("local_ts"))),
                    remote_networks=ipsec.networks(_text(child.get("remote_ts"))),
                    established=established,
                    rekey_seconds=_seconds(child.get("rekey_time")),
                    last_rekey=rekeyed,
                    enabled=_flag(child.get("enabled")),
                )
            )
        props = ipsec.proposals(_text(row.get("proposals")))
        for child in children:
            if _text(child.get("connection")) == uuid:
                props += [
                    p for p in ipsec.proposals(_text(child.get("esp_proposals"))) if p not in props
                ]
        out.append(
            Tunnel(
                id=object_id(device_id, "tunnel", _name(uuid)),
                device_id=device_id,
                kind=TunnelKind.IPSEC,
                name=_name(uuid),
                description=label or None,
                up=up,
                enabled=_flag(row.get("enabled")),
                ike_version=_version(row.get("version")),
                aggressive=_flag(row.get("aggressive")) if "aggressive" in row else None,
                remote_gateway=ipsec.gateway(_text(row.get("remote_addrs"))),
                auth=auth,
                proposals=props,
                dpd=bool(_seconds(row.get("dpd_delay"))) if "dpd_delay" in row else None,
                children=kids,
            )
        )
    return out


def _stamp(value: Any, now: datetime) -> datetime | None:
    text = _text(value)
    if not text:
        return None
    if re.fullmatch(r"\d{9,11}(\.\d+)?", text):
        return datetime.fromtimestamp(float(text), UTC)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%a %b %d %H:%M:%S %Y", "%a %b  %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _proto(value: Any) -> Literal["udp", "tcp"] | None:
    text = _text(value).lower()
    return "udp" if text.startswith("udp") else "tcp" if text.startswith("tcp") else None


def openvpn_tunnels(
    device_id: str,
    instances: list[dict[str, Any]],
    sessions: list[dict[str, Any]] | None,
    now: datetime,
) -> list[Tunnel]:
    out: list[Tunnel] = []
    for row in instances:
        uuid = _text(row.get("uuid"))
        label = _text(row.get("description"))
        role_text = _text(row.get("role")).lower()
        role = (
            TunnelRole.SERVER
            if role_text == "server"
            else TunnelRole.CLIENT
            if role_text == "client"
            else None
        )
        mine = [
            s
            for s in sessions or []
            if (_text(s.get("description")) == label and label)
            or _text(s.get("id")) == uuid
            or _text(s.get("uuid")) == uuid
        ]
        up: bool | None = None
        clients: list[TunnelSession] | None = None
        if sessions is not None and role is TunnelRole.CLIENT:
            up = any(_text(s.get("status")).lower() in ("connected", "up", "ok") for s in mine)
        if sessions is not None and role is TunnelRole.SERVER:
            clients = []
            for s in mine:
                name = _text(s.get("common_name") or s.get("username"))
                addr = _text(s.get("virtual_address") or s.get("virtual-address"))
                try:
                    virtual = ip_address(addr.split("/")[0])
                except ValueError:
                    virtual = None
                if name or virtual:
                    clients.append(
                        TunnelSession(
                            common_name=name or None,
                            virtual_address=virtual,
                            connected_since=_stamp(s.get("connected_since"), now),
                        )
                    )
        ciphers = [
            c
            for c in re.split(
                r"[,:\s]+", f"{_text(row.get('cipher'))},{_text(row.get('data-ciphers'))}"
            )
            if c
        ]
        nets = ipsec.networks(_text(row.get("server")))
        port = _text(row.get("port"))
        out.append(
            Tunnel(
                id=object_id(device_id, "tunnel", f"ovpn-{uuid[:8]}" if uuid else "ovpn"),
                device_id=device_id,
                kind=TunnelKind.OPENVPN,
                name=f"ovpn-{uuid[:8]}" if uuid else "ovpn",
                description=label or None,
                up=up,
                enabled=_flag(row.get("enabled")),
                listen_port=int(port)
                if role is TunnelRole.SERVER and port.isdigit() and 1 <= int(port) <= 65535
                else None,
                role=role,
                protocol=_proto(row.get("proto")),
                cipher=",".join(dict.fromkeys(ciphers)) or None,
                tls_auth=bool(_text(row.get("tls_key"))) if "tls_key" in row else None,
                tunnel_network=nets[0] if nets else None,
                pushed_routes=ipsec.networks(_text(row.get("push_route") or row.get("route"))),
                remote_gateway=ipsec.gateway(_text(row.get("remote")))
                if role is TunnelRole.CLIENT
                else None,
                sessions=clients,
            )
        )
    return out
