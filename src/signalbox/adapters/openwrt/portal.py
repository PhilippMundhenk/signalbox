"""OpenWrt captive portals (#460): openNDS and nodogsplash, both optional packages.

A router without them has no ``opennds`` or ``nodogsplash`` UCI config, which reads as nothing
to report. Section types: ``opennds`` (one section), ``nodogsplash`` (one or more sections; 4.x
writes them as ``config nodogsplash``).

- ``enabled`` (default on where the section exists), ``gatewayinterface`` (the device the portal
  sits on, ``br-lan`` or a VLAN device; the network it covers), ``sessiontimeout`` (minutes a
  guest stays logged in, default 1440 for openNDS and 1200 for nodogsplash; 0: no limit).
- How the guest logs in: ``fasremoteip`` (an external Forwarding Authentication Service) is
  external; a ``binauth`` script is a password (the script decides, usually a user and password
  or a voucher; *guess*); otherwise the built-in splash page, where the guest only accepts the
  terms: click-through. A ``preauth`` script (nodogsplash) replaces the page: not known.
  Neither the ``faskey`` nor the voucher or user data is read.

Option names and defaults are from the packages' READMEs, *guess* (#21). Covered: openNDS 9 to
10 (OpenWrt 22.03 to 25.12) and nodogsplash 4.x.
"""

from __future__ import annotations

from typing import Any

from signalbox.model import CaptivePortal, PortalAuth, object_id

#: UCI config -> (section type, default session timeout in minutes).
CONFIGS = {"opennds": ("opennds", 1440), "nodogsplash": ("nodogsplash", 1200)}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any, default: bool) -> bool:
    text = _text(value).lower()
    if not text:
        return default
    return text in ("1", "true", "yes", "on", "enabled")


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def auth_of(section: dict[str, Any]) -> PortalAuth | None:
    if _text(section.get("fasremoteip")):
        return PortalAuth.EXTERNAL
    if _text(section.get("binauth")):
        return PortalAuth.PASSWORD
    if _text(section.get("preauth")):
        return None
    return PortalAuth.CLICK_THROUGH


def portals(
    device_id: str,
    config: str,
    sections: list[tuple[str, dict[str, Any]]],
    segment_of: Any,
) -> list[CaptivePortal]:
    """One portal per section of ``config`` (``opennds`` or ``nodogsplash``).
    ``segment_of``: ``gatewayinterface`` -> segment id or None."""
    default = CONFIGS[config][1]
    out: list[CaptivePortal] = []
    for n, (name, s) in enumerate(sections):
        key = config if len(sections) == 1 else f"{config}-{n + 1}"
        seg = segment_of(_text(s.get("gatewayinterface")))
        timeout = _int(s.get("sessiontimeout"))
        minutes = default if timeout is None else timeout
        out.append(
            CaptivePortal(
                id=object_id(device_id, "portal", key),
                device_id=device_id,
                name=_text(s.get("gatewayname")) or config,
                segments=[seg] if seg else [],
                auth=auth_of(s),
                session_minutes=minutes if minutes > 0 else None,
                enabled=_flag(s.get("enabled"), True),
                vendor_extra={"section": name},
            )
        )
    return out
