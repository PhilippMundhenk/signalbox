"""MikroTik hotspot (#460): ``/ip/hotspot`` servers with their server profiles.

- ``/rest/ip/hotspot``: ``name``, ``interface`` (a bridge, VLAN or Wi-Fi interface), ``profile``
  (the server profile), ``disabled``, ``idle-timeout``.
- ``/rest/ip/hotspot/profile``: ``name``, ``login-by`` (comma list of ``mac``, ``http-chap``,
  ``http-pap``, ``https``, ``cookie``, ``mac-cookie``, ``trial``), ``use-radius`` (``yes``/``no``).
- ``/rest/ip/hotspot/user/profile``: ``name``, ``session-timeout`` (RouterOS time, ``0s``: none).
  The profile ``default`` is the one users get unless they say otherwise.

How the guest logs in is derived: ``use-radius`` is RADIUS; ``trial`` without a password method
(``http-chap``, ``http-pap``, ``https``) is click-through (the *trial* login needs no
credentials); a password method is a password (hotspot users, which also carry vouchers made
with the user generator: they cannot be told apart); ``mac`` or ``cookie`` alone: not known.
Hotspot users, their passwords and vouchers (``/ip/hotspot/user``) are never read.

All of this is a *guess* for RouterOS 7 and 6.49 alike (#21); the menus and fields exist in both.
A hotspot is on one interface, so it covers one network.
"""

from __future__ import annotations

from typing import Any

from signalbox.model import CaptivePortal, PortalAuth, object_id

HOTSPOT = "/rest/ip/hotspot"
PROFILE = "/rest/ip/hotspot/profile"
USER_PROFILE = "/rest/ip/hotspot/user/profile"

_PASSWORD_LOGINS = {"http-chap", "http-pap", "https"}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _yes(value: Any) -> bool:
    return _text(value).lower() in ("yes", "true")


def auth_of(profile: dict[str, Any]) -> PortalAuth | None:
    if _yes(profile.get("use-radius")):
        return PortalAuth.RADIUS
    methods = {m.strip() for m in _text(profile.get("login-by")).split(",") if m.strip()}
    if methods & _PASSWORD_LOGINS:
        return PortalAuth.PASSWORD
    if "trial" in methods:
        return PortalAuth.CLICK_THROUGH
    return None


def hotspots(
    device_id: str,
    rows: list[dict[str, Any]],
    profiles: list[dict[str, Any]],
    user_profiles: list[dict[str, Any]],
    segment_of: dict[str, str],
    seconds: Any,
) -> list[CaptivePortal]:
    """One portal per hotspot server. ``seconds``: the adapter's RouterOS time parser."""
    by_name = {_text(p.get("name")): p for p in profiles}
    default = next((u for u in user_profiles if _text(u.get("name")) == "default"), {})
    timeout = seconds(default.get("session-timeout")) if default else None
    out: list[CaptivePortal] = []
    seen: set[str] = set()
    for n, row in enumerate(rows):
        name = _text(row.get("name")) or f"hotspot{n + 1}"
        if name in seen:
            continue
        seen.add(name)
        seg = segment_of.get(_text(row.get("interface")))
        out.append(
            CaptivePortal(
                id=object_id(device_id, "portal", name),
                device_id=device_id,
                name=name,
                segments=[seg] if seg else [],
                auth=auth_of(by_name.get(_text(row.get("profile")), {})),
                session_minutes=timeout // 60 if timeout and timeout >= 60 else None,
                enabled=not _yes(row.get("disabled")),
            )
        )
    return out
