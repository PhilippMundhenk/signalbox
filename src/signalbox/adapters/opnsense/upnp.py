"""UPnP IGD / NAT-PMP of the plugin ``os-upnp`` (miniupnpd) on OPNsense (#176, ADR 0029).

``/api/miniupnpd/settings/get`` answers ``{"miniupnpd": {"general": {"enabled": "1",
"enable_upnp": "1", "enable_natpmp": "1", "iface_array": {...}, "secure_mode"...}}}`` (interface
identifiers selected as in every option list); ``/api/miniupnpd/service/status`` answers
``{"status": "running"}``. The permission rules are the text fields ``permuser1`` to
``permuser4`` (``allow 1024-65535 192.0.2.0/24 1024-65535``). The active mappings have no API
(miniupnpd keeps them in a lease file on the firewall): they are not read.

The plugin is optional (404: nothing to report); a 403 is an optional gap naming the privilege.
All endpoint and field names are a *guess* (#21): they are from the plugin's model and the
pfSense package it derives from, not seen on a running system.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from signalbox.adapters.upnp import acl_text
from signalbox.model import (
    DeviceUpnp,
    ManagementService,
    ServiceKind,
    UpnpAclRule,
    UpnpProtocol,
    object_id,
)

SETTINGS = "/api/miniupnpd/settings/get"
STATUS = "/api/miniupnpd/service/status"
PRIVILEGE = "Services: UPnP IGD & PCP (page-services-upnp)"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _on(value: Any) -> bool:
    return value is True or value == 1 or _text(value).lower() in ("1", "true", "yes")


def _selected(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [k for k, v in value.items() if isinstance(v, dict) and _on(v.get("selected"))]
    return [n for n in _text(value).replace(",", " ").split() if n]


def state(
    device_id: str, settings: Any, status: Any, segment_of: Mapping[str, str]
) -> tuple[ManagementService, DeviceUpnp] | None:
    """The service and its state; ``None`` when the answer has no ``general`` section."""
    root = settings.get("miniupnpd") if isinstance(settings, dict) else None
    general = root.get("general") if isinstance(root, dict) else None
    if not isinstance(general, dict):
        return None
    protocols: list[UpnpProtocol] = []
    if "enable_upnp" not in general or _on(general.get("enable_upnp")):
        protocols.append(UpnpProtocol.IGD)
    if _on(general.get("enable_natpmp")):
        protocols.append(UpnpProtocol.NAT_PMP)
    names = _selected(general.get("iface_array") or general.get("interfaces"))
    segments = sorted({segment_of[n] for n in names if n in segment_of})
    secure: bool | None = None
    if "secure_mode" in general:
        secure = _on(general.get("secure_mode"))
    elif "allow_third_party_mapping" in general:  # pfSense wording: the opposite
        secure = not _on(general.get("allow_third_party_mapping"))
    rules: list[UpnpAclRule] = []
    for n in range(1, 5):
        if (rule := acl_text(general.get(f"permuser{n}"))) is not None:
            rules.append(rule)
    running = _text(status.get("status")).lower() if isinstance(status, dict) else ""
    enabled = _on(general.get("enabled")) and running not in ("stopped", "disabled")
    service = ManagementService(
        id=object_id(device_id, "service", "upnp"),
        device_id=device_id,
        kind=ServiceKind.UPNP,
        name="upnp",
        enabled=enabled and bool(protocols),
        segments=segments if names and len(segments) == len(names) else [],
    )
    return service, DeviceUpnp(
        protocols=protocols, secure_mode=secure, allow_rules=rules, mappings_complete=False
    )
