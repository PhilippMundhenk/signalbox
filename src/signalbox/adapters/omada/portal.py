"""Omada captive portals (#460): the portal profiles of the site.

The Open API path and the fields are a *guess* (#21), from the controller's *Hotspot / Portal*
settings: ``…/portals`` (else ``…/hotspot/portals``) answers rows with ``id`` (or ``portalId``),
``name``, ``enable``, ``authType`` (0 no authentication, 1 simple password, 2 hotspot: local
users and vouchers, 3 external RADIUS server, 4 external portal server), ``timeout`` (seconds a
guest stays logged in; 0 or missing: not known) and the SSIDs it is on, as ``ssidList`` (rows
with ``ssidId`` and ``name``, or plain names) or ``ssidIds``. A portal on a wired network
lists ``networkIds`` (``…/lan-networks`` ids). A controller that does not know either path
reports no portals. Covered: controller 5.x and 6.x, which both have the Open API.

Vouchers, passwords, the RADIUS secret and the contents of the portal page are never read.
"""

from __future__ import annotations

from typing import Any

from signalbox.model import CaptivePortal, PortalAuth, object_id

#: Under the site path, in the order they are tried (*guess*).
PATHS = ("portals", "hotspot/portals")

AUTH = {
    0: PortalAuth.CLICK_THROUGH,
    1: PortalAuth.PASSWORD,
    2: PortalAuth.VOUCHER,
    3: PortalAuth.RADIUS,
    4: PortalAuth.EXTERNAL,
}


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else str(value) if isinstance(value, int) else ""


def _flag(value: Any, default: bool = True) -> bool:
    return value if isinstance(value, bool) else default


def _ssids(row: dict[str, Any]) -> tuple[set[str], set[str]]:
    """(SSID ids, SSID names) a portal row lists."""
    ids = (
        {_text(i) for i in row.get("ssidIds", []) if _text(i)}
        if isinstance(row.get("ssidIds"), list)
        else set()
    )
    names: set[str] = set()
    for item in row.get("ssidList", []) if isinstance(row.get("ssidList"), list) else []:
        if isinstance(item, dict):
            if _text(item.get("ssidId")):
                ids.add(_text(item.get("ssidId")))
            if _text(item.get("name")):
                names.add(_text(item.get("name")))
        elif _text(item):
            names.add(_text(item))
    return ids, names


def portals(
    device_id: str,
    rows: list[dict[str, Any]],
    wlans: list[tuple[str, str, str]],
    segment_of: dict[str, str],
) -> list[CaptivePortal]:
    """One portal per row. ``wlans``: (WLAN id, SSID id, SSID name) of the site's access points;
    ``segment_of``: network id -> segment id."""
    out: list[CaptivePortal] = []
    seen: set[str] = set()
    for n, row in enumerate(rows):
        key = _text(row.get("id") or row.get("portalId")) or str(n)
        name = _text(row.get("name")) or f"portal {key}"
        if key in seen:
            continue
        seen.add(key)
        ids, names = _ssids(row)
        covered = sorted(w for w, sid, ssid in wlans if sid in ids or ssid in names)
        nets = row.get("networkIds")
        segments = sorted(
            {segment_of[_text(i)] for i in nets if _text(i) in segment_of}
            if isinstance(nets, list)
            else set()
        )
        timeout = _int(row.get("timeout"))
        kind = _int(row.get("authType"))
        out.append(
            CaptivePortal(
                id=object_id(device_id, "portal", key),
                device_id=device_id,
                name=name,
                segments=segments,
                wlans=covered,
                auth=AUTH.get(kind) if kind is not None else None,
                session_minutes=timeout // 60 if timeout and timeout >= 60 else None,
                enabled=_flag(row.get("enable")),
            )
        )
    return out
