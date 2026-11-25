"""OPNsense captive portal (#460): the zones of *Services: Captive Portal*.

``/api/captiveportal/settings/search_zones`` (``searchZones`` before 24.7, see :mod:`compat`)
lists the zones: ``uuid``, ``zoneid``, ``enabled``, ``description``, ``interfaces`` (identifiers
such as ``opt2``, comma separated), ``authservers`` (names of the authentication servers,
comma separated; empty: *no authentication*, the guest only accepts the terms),
``hardtimeout`` (minutes, 0: none) and ``idletimeout``. The rows also name the TLS certificate
and the allowed addresses, which are not read.

How a zone authenticates is derived from ``authservers``: empty is click-through; a name that
the voucher server lists (``/api/captiveportal/voucher/list_providers``) is voucher; *Local
Database* is a password (local users); any other server (RADIUS, LDAP) is RADIUS. Voucher
beats RADIUS beats password where a zone lists several. Neither the vouchers
(``/api/captiveportal/voucher/...``) nor the RADIUS secrets are ever read.

The privilege is *Services: Captive Portal* (``page-services-captiveportal``), a *guess* for
the name and for the row fields (#21): the setup asks for it only where the firewall offers it,
and a 403 is an optional gap naming it. Covered: 24.7, 25.1, 25.7 and 26.1 (the zone model has
kept these fields since 18.7; the API since 19.1, *guess*).
"""

from __future__ import annotations

import re
from typing import Any

from signalbox.model import CaptivePortal, PortalAuth, object_id

ZONES = "/api/captiveportal/settings/search_zones"
PROVIDERS = "/api/captiveportal/voucher/list_providers"
PRIVILEGE = "Services: Captive Portal (page-services-captiveportal)"
#: The authentication server of the local user database.
LOCAL = "local database"


def _text(value: Any) -> str:
    if isinstance(value, dict):  # an option list: {"key": {"value": ..., "selected": 1}}
        return ",".join(
            str(k) for k, o in value.items() if isinstance(o, dict) and o.get("selected")
        )
    return value.strip() if isinstance(value, str) else ""


def _names(value: Any) -> list[str]:
    return [n for n in re.split(r"[,\s]+", _text(value)) if n]


def _servers(value: Any) -> list[str]:
    # server names can hold spaces ("Local Database"): split on commas only
    return [n.strip() for n in _text(value).split(",") if n.strip()]


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def providers(data: Any) -> set[str]:
    """The voucher provider names from ``list_providers`` (a list of names, or of rows)."""
    items = data.get("rows", data) if isinstance(data, dict) else data
    out: set[str] = set()
    for item in items if isinstance(items, list) else []:
        name = item.get("name") if isinstance(item, dict) else item
        if isinstance(name, str) and name.strip():
            out.add(name.strip().lower())
    return out


def auth_of(servers: list[str], vouchers: set[str]) -> PortalAuth:
    if not servers:
        return PortalAuth.CLICK_THROUGH
    low = [s.lower() for s in servers]
    if any(s in vouchers for s in low):
        return PortalAuth.VOUCHER
    if any(s != LOCAL for s in low):
        return PortalAuth.RADIUS
    return PortalAuth.PASSWORD


def zones(
    device_id: str,
    rows: list[dict[str, Any]],
    segment_of: dict[str, str],
    vouchers: set[str],
) -> list[CaptivePortal]:
    """One portal per zone; ``segment_of``: interface identifier -> segment id."""
    out: list[CaptivePortal] = []
    seen: set[str] = set()
    for n, row in enumerate(rows):
        zone = _text(row.get("zoneid")) or _text(row.get("uuid")) or str(n)
        name = _text(row.get("description")) or f"zone {zone}"
        key = zone if zone not in seen else f"{zone}-{n}"
        seen.add(key)
        segments = sorted({segment_of[i] for i in _names(row.get("interfaces")) if i in segment_of})
        hard = _int(row.get("hardtimeout"))
        out.append(
            CaptivePortal(
                id=object_id(device_id, "portal", key),
                device_id=device_id,
                name=name,
                segments=segments,
                auth=auth_of(_servers(row.get("authservers")), vouchers),
                session_minutes=hard if hard and hard > 0 else None,
                enabled=_text(row.get("enabled")).lower() in ("1", "true", "yes", "on"),
            )
        )
    return out
