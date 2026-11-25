"""Access control of Wi-Fi networks from UCI ``wireless`` (#162): MAC filter, RADIUS servers of
an enterprise SSID, dynamic VLAN.

hostapd options (OpenWrt 21.02, 22.03, 23.05 and later spell them the same): ``macfilter``
(``disable``, ``allow``, ``deny``), ``maclist`` (list, or a space separated string in old
configs), ``auth_server``, ``auth_port``, ``auth_secret``, ``acct_server``, ``acct_port``,
``acct_secret``, ``dynamic_vlan`` (0, 1, 2). The secrets are only tested for presence; the MAC
addresses are only counted.
"""

from __future__ import annotations

from typing import Any

from signalbox.model import (
    MacFilter,
    MacFilterMode,
    RadiusEndpoint,
    RadiusPurpose,
    RadiusRef,
    RadiusServer,
)


def _list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if str(v).strip()]
    return str(value).split() if value not in (None, "") else []


def _port(value: Any) -> int | None:
    try:
        port = int(str(value))
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def mac_filter(section: dict[str, Any]) -> MacFilter | None:
    mode = {"allow": MacFilterMode.ALLOW, "deny": MacFilterMode.DENY}.get(
        str(section.get("macfilter", "")).strip()
    )
    return None if mode is None else MacFilter(mode=mode, count=len(_list(section.get("maclist"))))


def radius_ref(section: dict[str, Any]) -> RadiusRef | None:
    """The RADIUS servers of a wifi-iface; None without ``auth_server``."""
    host = str(section.get("auth_server") or "").strip()
    if not host:
        return None
    acct = str(section.get("acct_server") or "").strip()
    return RadiusRef(
        auth=[RadiusEndpoint(address=host, port=_port(section.get("auth_port")))],
        acct=[RadiusEndpoint(address=acct, port=_port(section.get("acct_port")))] if acct else [],
        secret_set=bool(str(section.get("auth_secret") or "").strip()),
    )


def dynamic_vlan(section: dict[str, Any]) -> bool | None:
    if "dynamic_vlan" not in section:
        return None
    return str(section["dynamic_vlan"]).strip() in ("1", "2")


def servers(refs: list[RadiusRef]) -> list[RadiusServer]:
    """One entry per distinct authentication server (the device has no names for them)."""
    out: dict[str, RadiusServer] = {}
    for ref in refs:
        acct = ref.acct[0].port if ref.acct else None
        for ep in ref.auth:
            key = f"{ep.address}:{ep.port or 1812}"
            if key not in out:
                out[key] = RadiusServer(
                    name=key,
                    address=ep.address,
                    auth_port=ep.port,
                    acct_port=acct,
                    purposes=[RadiusPurpose.WLAN],
                    secret_set=ref.secret_set,
                )
    return list(out.values())
