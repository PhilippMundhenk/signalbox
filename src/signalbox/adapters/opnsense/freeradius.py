"""FreeRADIUS on OPNsense (plugin ``os-freeradius``) as a RADIUS server (#519, ADR 0030).

Read only: ``/api/freeradius/general/get`` (is the server on), ``/api/freeradius/service/status``
(is it running) and the clients grid ``/api/freeradius/client/search_client`` (the NAS list: the
access points, switches and routers that may ask the server). The endpoints, field names and the
privilege are a *guess* (#21) from the plugin sources (``net/freeradius``), the same for 24.7,
25.1, 25.7 and 26.1; the camelCase spelling of older releases is tried by the HTTP layer. The
shared secret of a client is only tested for presence and never kept; the users and their
passwords (``/api/freeradius/user``) are not read at all. A firewall without the plugin (404)
reports nothing; a 403 is an optional gap naming the privilege.
"""

from __future__ import annotations

from typing import Any

from signalbox.model import RadiusPurpose, RadiusServer

GENERAL = "/api/freeradius/general/get"
STATUS = "/api/freeradius/service/status"
CLIENTS = "/api/freeradius/client/search_client"
PRIVILEGE = "Services: FreeRADIUS (page-services-freeradius)"
DEFAULT_AUTH_PORT = 1812
DEFAULT_ACCT_PORT = 1813


def _flag(value: Any) -> bool | None:
    text = str(value).strip().lower() if isinstance(value, (str, int)) else ""
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return None


def enabled(general: Any) -> bool | None:
    """The ``enabled`` flag of the general settings (``{"freeradius": {"general": {...}}}``)."""
    node = general
    for key in ("freeradius", "general"):
        node = node.get(key) if isinstance(node, dict) else None
    return _flag(node.get("enabled")) if isinstance(node, dict) else None


def running(status: Any) -> bool | None:
    """``{"status": "running"}`` or ``"stopped"``; None when the answer says neither."""
    text = str(status.get("status", "")).strip().lower() if isinstance(status, dict) else ""
    return True if text == "running" else False if text in ("stopped", "disabled") else None


def server(
    general: Any, status: Any, rows: list[dict[str, Any]] | None, address: str
) -> RadiusServer | None:
    """The FreeRADIUS server of this firewall, or None when it is off, stopped or not read.

    ``address`` is the firewall itself. With enabled NAS clients the server is used for Wi-Fi and
    802.1X; ``secret_set`` is true when every enabled client has a shared secret, false when one
    lacks it. The secrets themselves are never kept."""
    if enabled(general) is not True or running(status) is False or not address:
        return None
    purposes: list[RadiusPurpose] = []
    secret_set: bool | None = None
    if rows is not None:
        active = [r for r in rows if _flag(r.get("enabled")) is not False]
        if active:
            purposes = [RadiusPurpose.WLAN, RadiusPurpose.DOT1X]
            if all("secret" in r for r in active):
                secret_set = all(bool(str(r.get("secret") or "").strip()) for r in active)
    return RadiusServer(
        name="FreeRADIUS",
        address=address,
        auth_port=DEFAULT_AUTH_PORT,
        acct_port=DEFAULT_ACCT_PORT,
        purposes=purposes,
        secret_set=secret_set,
        local=True,
    )
