"""strongSwan on OpenWrt (#527): the connections of ``/etc/swanctl/swanctl.conf``.

The file is read with ``file read`` (ACL entry ``/etc/swanctl/swanctl.conf``). Only the
``connections`` section is used: IKE version, aggressive mode (IKEv1), gateway, how each side
authenticates, the proposals and the children (traffic selectors, rekey time). The ``secrets``
section (pre-shared keys, private key passphrases, EAP passwords) is dropped by :func:`parse`
the moment the text is tokenised; no value of it is ever held beyond that function. Key and
certificate *file names* (``certs``, ``pubkeys``) are not read either: the certificate's subject
is not in the configuration, so ``certificate_subject`` stays unknown.

The state of the security associations is not known (the vici socket is not reachable through
rpcd): ``up`` and ``established`` stay None. The legacy ``ipsec.conf`` of strongSwan 5.x
(``strongswan-ipsec``, OpenWrt before 21.02) is not read. ``include`` lines are not followed
(*guess*: OpenWrt's default file has none; the layout is that of strongSwan 5.9 and 6.0).
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
    object_id,
)

PATH = "/etc/swanctl/swanctl.conf"

_LINE = re.compile(r"^\s*([\w.\-%]+)\s*=\s*(.*?)\s*$")
_OPEN = re.compile(r"^\s*([\w.\-%]+)\s*\{\s*$")


def _value(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text.split("#", 1)[0].strip()


def parse(text: str) -> dict[str, Any]:
    """The ``connections`` of a swanctl.conf as nested dicts of text; every other section,
    ``secrets`` above all, is skipped while reading."""
    root: dict[str, Any] = {}
    stack: list[dict[str, Any] | None] = [root]
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "}" or line.startswith("}"):
            if len(stack) > 1:
                stack.pop()
            continue
        # ``name { ... }`` on one line (empty section) or opening a block
        opened = _OPEN.match(line)
        if opened is not None:
            name = opened.group(1)
            top = stack[-1]
            if top is None or (len(stack) == 1 and name != "connections"):
                stack.append(None)  # a section we do not read (secrets, pools, authorities)
                continue
            child: dict[str, Any] = {}
            top[name] = child
            stack.append(child)
            continue
        top = stack[-1]
        kv = _LINE.match(line)
        if top is not None and kv is not None and len(stack) > 1:
            top[kv.group(1)] = _value(kv.group(2))
    return root


def _flag(value: Any) -> bool | None:
    text = str(value or "").strip().lower()
    if text in ("yes", "true", "1", "on"):
        return True
    if text in ("no", "false", "0", "off"):
        return False
    return None


def _auth(conn: dict[str, Any]) -> TunnelAuth | None:
    """How the device authenticates itself: the ``local`` section's ``auth`` (``local1``,
    ``local-xyz`` rounds are looked at in order; the first round decides)."""
    for key in sorted(k for k in conn if k == "local" or k.startswith("local")):
        section = conn.get(key)
        if not isinstance(section, dict):
            continue
        method = str(section.get("auth") or "pubkey").lower()
        if method == "psk":
            return TunnelAuth.PSK
        if method.startswith("eap"):
            return TunnelAuth.EAP
        if method in ("pubkey", "rsa", "ecdsa") or method.startswith(("pubkey", "ike:")):
            return TunnelAuth.CERTIFICATE
    return None


def _children(conn: dict[str, Any]) -> list[TunnelChild]:
    out: list[TunnelChild] = []
    block = conn.get("children")
    for name, c in sorted(block.items() if isinstance(block, dict) else []):
        if not isinstance(c, dict):
            continue
        rekey = str(c.get("rekey_time") or "")
        out.append(
            TunnelChild(
                name=name,
                local_networks=ipsec.networks(str(c.get("local_ts") or "")),
                remote_networks=ipsec.networks(str(c.get("remote_ts") or "")),
                rekey_seconds=_seconds(rekey),
            )
        )
    return out


def _seconds(text: str) -> int | None:
    """``1h``, ``3600``, ``30m``, ``1d`` (strongSwan time values; a bare number is seconds)."""
    m = re.fullmatch(r"(\d+)\s*([smhd]?)", text.strip().lower())
    if m is None:
        return None
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def tunnels(conf: dict[str, Any], device_id: str) -> list[Tunnel]:
    """One tunnel per connection of a :func:`parse`d swanctl.conf."""
    connections = conf.get("connections")
    out: list[Tunnel] = []
    for name, conn in sorted(connections.items() if isinstance(connections, dict) else []):
        if not isinstance(conn, dict):
            continue
        clean = re.sub(r"[^A-Za-z0-9_.-]", "_", name) or "ipsec"
        proposals: list[CryptoProposal] = ipsec.proposals(str(conn.get("proposals") or ""))
        block = conn.get("children")
        # a child's ESP proposals add to the list so that a weak one is seen
        for c in block.values() if isinstance(block, dict) else []:
            if isinstance(c, dict):
                for p in ipsec.proposals(str(c.get("esp_proposals") or "")):
                    if p not in proposals:
                        proposals.append(p)
        dpd = _seconds(str(conn.get("dpd_delay") or ""))
        version = str(conn.get("version") or "0").strip()
        out.append(
            Tunnel(
                id=object_id(device_id, "tunnel", f"ipsec-{clean}"),
                device_id=device_id,
                kind=TunnelKind.IPSEC,
                name=f"ipsec-{clean}",
                description=name,
                ike_version=1 if version == "1" else 2 if version == "2" else None,
                aggressive=_flag(conn.get("aggressive")),
                remote_gateway=ipsec.gateway(str(conn.get("remote_addrs") or "")),
                auth=_auth(conn),
                proposals=proposals,
                dpd=None if dpd is None else dpd > 0,
                children=_children(conn),
            )
        )
    return out
