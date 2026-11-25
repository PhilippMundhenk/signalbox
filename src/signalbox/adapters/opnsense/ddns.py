"""OPNsense dynamic DNS (#154): the accounts of the ``os-ddclient`` plugin.

``/api/dyndns/accounts/search_item`` (``searchItem`` before 24.7, see :mod:`compat`) lists the
accounts: ``enabled``, ``service`` (``dyndns2``, ``cloudflare``, ``duckdns``, ``noip``, ...),
``protocol``, ``hostnames`` (comma separated), ``interface`` and ``description``. The same rows
hold ``username`` and ``password`` (a token for some providers): they are never read. The plugin
keeps the last announced address in the ddclient cache and has no API for it, so neither the
address nor the result of the last update is known (``unknown``); the plugin is an optional
package, a 404 means it is not installed. Privilege *Services: Dynamic DNS*
(``page-services-dyndns``), *guess* (#21). Covered: os-ddclient 1.x (24.1 to 25.1) and the
rewrite for 25.7 and 26.1, which keep the endpoint and these fields (*guess*, #21).
"""

from __future__ import annotations

import re
from typing import Any

from signalbox.model import DynamicDns, object_id

ACCOUNTS = "/api/dyndns/accounts/search_item"
PRIVILEGE = "Services: Dynamic DNS (page-services-dyndns)"

_PROVIDERS = (
    ("duckdns", "duckdns"),
    ("cloudflare", "cloudflare"),
    ("noip", "noip"),
    ("no-ip", "noip"),
    ("dyndns2", "dyndns2"),
    ("dyndns", "dyndns2"),
)


def provider(*names: str) -> str:
    for name in names:
        low = name.lower()
        for key, normal in _PROVIDERS:
            if key in low:
                return normal
    return "other"


def _text(value: Any) -> str:
    if isinstance(value, dict):  # an option list: {"key": {"value": ..., "selected": 1}}
        for key, option in value.items():
            if isinstance(option, dict) and option.get("selected"):
                return str(key).strip()
        return ""
    return value.strip() if isinstance(value, str) else ""


def clients(device_id: str, rows: list[dict[str, Any]], wan_uplink: str | None) -> list[DynamicDns]:
    """One client per hostname of every account (an account may list several)."""
    out: list[DynamicDns] = []
    for n, row in enumerate(rows):
        names = [h for h in re.split(r"[,\s]+", _text(row.get("hostnames"))) if h]
        key = _text(row.get("uuid")) or str(n)
        service = provider(_text(row.get("service")), _text(row.get("protocol")))
        iface = _text(row.get("interface"))
        enabled = _text(row.get("enabled")).lower() in ("1", "true", "yes", "on")
        for i, host in enumerate(names):
            out.append(
                DynamicDns(
                    id=object_id(device_id, "ddns", key if len(names) == 1 else f"{key}-{i}"),
                    device_id=device_id,
                    provider=service,
                    hostname=host,
                    uplink_id=wan_uplink if iface in ("", "wan") else None,
                    enabled=enabled,
                )
            )
    return out
