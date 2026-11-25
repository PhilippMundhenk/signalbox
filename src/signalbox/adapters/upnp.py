"""Parsers shared by the UPnP / NAT-PMP readers (#176, ADR 0029).

miniupnpd (OpenWrt, OPNsense, pfSense) writes its mappings to a lease file, one per line:
``PROTO:external port:internal address:internal port:expiry (unix time, 0: never):description``
(the description may hold colons), and takes permission rules as text,
``allow|deny <external ports> <internal address/prefix> <internal ports>``.
"""

from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Any

from signalbox.model import DynamicPortMapping, MappingOrigin, UpnpAclRule


def _ports(text: str) -> tuple[int, int] | None:
    first, _, last = text.strip().partition("-")
    try:
        a = int(first)
        b = int(last) if last else a
    except ValueError:
        return None
    return (a, b) if 0 <= a <= b <= 65535 else None


def acl_rule(action: Any, external: Any, internal: Any, internal_ports: Any) -> UpnpAclRule | None:
    """One rule from its four parts; ``None`` when a part is not understood."""
    verb = str(action or "").strip().lower()
    ext = _ports(str(external or ""))
    ports = _ports(str(internal_ports or ""))
    if verb not in ("allow", "deny") or ext is None or ports is None:
        return None
    try:
        network = ip_network(str(internal or "").strip(), strict=False)
    except ValueError:
        return None
    return UpnpAclRule(
        allow=verb == "allow",
        external_first=ext[0],
        external_last=ext[1],
        internal_network=network,
        internal_first=ports[0],
        internal_last=ports[1],
    )


def acl_text(text: Any) -> UpnpAclRule | None:
    """``allow 1024-65535 192.0.2.0/24 1024-65535``."""
    parts = str(text or "").split()
    return acl_rule(*parts) if len(parts) == 4 else None


def origin_of(description: str | None) -> MappingOrigin:
    """miniupnpd names its NAT-PMP and PCP mappings ``NAT-PMP <port> <proto>`` and ``PCP ...``
    (*guess*, #21); everything else came through UPnP IGD."""
    text = (description or "").strip().upper()
    if text.startswith("NAT-PMP"):
        return MappingOrigin.NAT_PMP
    if text.startswith("PCP"):
        return MappingOrigin.PCP
    return MappingOrigin.UPNP


def lease_file(text: str, now: datetime) -> list[DynamicPortMapping]:
    """The mappings of a miniupnpd lease file. Lines that do not parse and mappings that have
    expired are left out."""
    out: list[DynamicPortMapping] = []
    for line in text.splitlines():
        parts = line.strip().split(":", 5)
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        try:
            address = ip_address(parts[2])
            external, internal, expiry = int(parts[1]), int(parts[3]), int(parts[4])
        except ValueError:
            continue
        if proto not in ("tcp", "udp") or not (1 <= external <= 65535 and 1 <= internal <= 65535):
            continue
        left = 0 if expiry == 0 else int(expiry - now.timestamp())
        if expiry and left <= 0:
            continue
        description = parts[5].strip() if len(parts) > 5 and parts[5].strip() else None
        out.append(
            DynamicPortMapping(
                protocol="tcp" if proto == "tcp" else "udp",
                external_port=external,
                internal_address=address,
                internal_port=internal,
                description=description,
                lease_seconds=left,
                created_by=origin_of(description),
            )
        )
    return out
