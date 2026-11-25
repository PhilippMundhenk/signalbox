"""UniFi site-to-site and remote-access VPN (#527), read from ``rest/networkconf``.

Rows with ``purpose`` ``site-vpn`` (a site-to-site connection) or ``remote-user-vpn`` (the
gateway as a server) and a ``vpn_type`` of ``ipsec-vpn``, ``openvpn-client`` or
``openvpn-server`` are tunnels of the gateway. *Guess (#21), from the field names of the
classic controller API of Network 7 and 8, not from a vendor document*: ``ipsec_peer_ip`` (the
other gateway), ``ipsec_key_exchange`` (``ikev1``, ``ikev2``), ``ipsec_encryption``,
``ipsec_hash``, ``ipsec_dh_group`` (IKE) and ``ipsec_esp_encryption``, ``ipsec_esp_hash``,
``ipsec_esp_dh_group`` (ESP, falling back to the IKE values), ``ipsec_pfs``,
``ipsec_dynamic_routing`` (BGP: no static remote networks), ``remote_vpn_subnets`` (the
other site's networks) and the local networks (``ip_subnets`` or ``local_networks``, else
none), ``enabled``. The pre-shared key (``x_ipsec_pre_shared_key``) is only asked whether it
is set and never kept: UniFi site-to-site IPsec authenticates with it. L2TP, PPTP and WireGuard
entries are not tunnels of the model here (WireGuard keys of the controller are not read).
A row without a ``vpn_type`` is left out. The integration API has no VPN list: nothing is read
there. State (``up``, ``established``) is not in the network row: unknown.
"""

from __future__ import annotations

import re
from typing import Any

from signalbox.adapters import ipsec
from signalbox.model import (
    CryptoProposal,
    Tunnel,
    TunnelAuth,
    TunnelChild,
    TunnelKind,
    TunnelRole,
    object_id,
)


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = _text(value).lower()
    return True if text in ("1", "true", "yes", "on") else False if text in ("0", "false") else None


def _list(value: Any) -> str:
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    return _text(value)


def _proposal(row: dict[str, Any], prefix: str, fallback: str = "") -> CryptoProposal | None:
    enc = _text(row.get(f"{prefix}_encryption") or row.get(f"{fallback}_encryption")).lower()
    hashed = _text(row.get(f"{prefix}_hash") or row.get(f"{fallback}_hash")).lower()
    group = ipsec.dh_group(
        str(row.get(f"{prefix}_dh_group") or row.get(f"{fallback}_dh_group") or "")
    )
    if not (enc or hashed or group):
        return None
    return CryptoProposal(encryption=enc or None, integrity=hashed or None, dh_group=group)


def _ipsec(row: dict[str, Any], device_id: str, name: str, ident: str) -> Tunnel:
    proposals = [
        p for p in (_proposal(row, "ipsec"), _proposal(row, "ipsec_esp", "ipsec")) if p is not None
    ]
    unique = [p for i, p in enumerate(proposals) if p not in proposals[:i]]
    version = _text(row.get("ipsec_key_exchange")).lower()
    remote = ipsec.networks(_list(row.get("remote_vpn_subnets")))
    local = ipsec.networks(_list(row.get("ip_subnets") or row.get("local_networks")))
    return Tunnel(
        id=object_id(device_id, "tunnel", ident),
        device_id=device_id,
        kind=TunnelKind.IPSEC,
        name=ident,
        description=name or None,
        enabled=_flag(row.get("enabled")) is not False,
        ike_version=1 if version.endswith("v1") else 2 if version.endswith("v2") else None,
        remote_gateway=ipsec.gateway(_text(row.get("ipsec_peer_ip"))),
        # the key is asked for, never kept
        auth=TunnelAuth.PSK if row.get("x_ipsec_pre_shared_key") else None,
        proposals=unique,
        children=[TunnelChild(name=name or ident, local_networks=local, remote_networks=remote)]
        if remote or local
        else [],
    )


def _openvpn(row: dict[str, Any], device_id: str, name: str, ident: str, kind: str) -> Tunnel:
    server = kind.endswith("server")
    return Tunnel(
        id=object_id(device_id, "tunnel", ident),
        device_id=device_id,
        kind=TunnelKind.OPENVPN,
        name=ident,
        description=name or None,
        enabled=_flag(row.get("enabled")) is not False,
        role=TunnelRole.SERVER if server else TunnelRole.CLIENT,
        # the client's configuration file is not read: no cipher, no TLS key flag
        tunnel_network=next(iter(ipsec.networks(_text(row.get("ip_subnet")))), None)
        if server
        else None,
    )


def tunnels(rows: list[dict[str, Any]], device_id: str) -> list[Tunnel]:
    """The tunnels of the VPN rows of ``rest/networkconf``, in the order of the controller."""
    out: list[Tunnel] = []
    seen: set[str] = set()
    for row in rows:
        purpose = _text(row.get("purpose")).lower()
        kind = _text(row.get("vpn_type")).lower()
        if purpose not in ("site-vpn", "remote-user-vpn") or not kind:
            continue
        name = _text(row.get("name"))
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_") or _text(row.get("_id")) or "vpn"
        if kind.startswith("ipsec"):
            ident = f"ipsec-{slug}"
        elif kind.startswith("openvpn"):
            ident = f"openvpn-{slug}"
        else:
            continue
        if ident in seen:
            continue
        seen.add(ident)
        out.append(
            _ipsec(row, device_id, name, ident)
            if kind.startswith("ipsec")
            else _openvpn(row, device_id, name, ident, kind)
        )
    return out
