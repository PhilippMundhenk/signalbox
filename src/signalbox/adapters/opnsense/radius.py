"""RADIUS servers of OPNsense's user manager (System > Access > Servers; #162).

Only the list of RADIUS authentication servers is read. The endpoint and the row fields are a
*guess* (#21): ``/api/auth/server/search`` with rows ``name``, ``type`` (``radius``), ``host``,
``radius_auth_port``, ``radius_acct_port`` and ``radius_secret``. The secret is only tested
for presence and never kept. A firewall without the endpoint (404) reports nothing; a 403 is an
optional gap naming the privilege. FreeRADIUS (plugin) is not read.
"""

from __future__ import annotations

from typing import Any

from signalbox.model import RadiusPurpose, RadiusServer

SERVERS = "/api/auth/server/search"
PRIVILEGE = "System: Access: Servers (page-system-authservers)"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else str(value) if isinstance(value, int) else ""


def _port(value: Any) -> int | None:
    try:
        number = int(_text(value))
    except ValueError:
        return None
    return number if 1 <= number <= 65535 else None


def servers(rows: list[dict[str, Any]]) -> list[RadiusServer]:
    out: list[RadiusServer] = []
    for row in rows:
        host = _text(row.get("host"))
        if _text(row.get("type")).lower() != "radius" or not host:
            continue
        out.append(
            RadiusServer(
                name=_text(row.get("name")) or host,
                address=host,
                auth_port=_port(row.get("radius_auth_port")) or 1812,
                acct_port=_port(row.get("radius_acct_port")),
                purposes=[RadiusPurpose.LOGIN],
                secret_set=bool(_text(row.get("radius_secret")))
                if "radius_secret" in row
                else None,
            )
        )
    return out
