"""RADIUS profiles, 802.1X on ports, port security and Wi-Fi MAC filters of UniFi (#162).

All field names are from the controller's own UI payloads and **guesses for a real controller**
(#21): ``rest/radiusprofile`` (``name``, ``auth_servers`` and ``acct_servers`` as lists of
``ip``, ``port``, ``x_secret``; ``use_usg_auth_server`` for the gateway's own server,
``vlan_enabled``), ``rest/wlanconf`` (``radiusprofile_id``, ``mac_filter_enabled``,
``mac_filter_policy`` ``allow`` or ``deny``, ``mac_filter_list``), ``rest/portconf``
(``dot1x_ctrl``: ``force_authorized``, ``auto``, ``mac_based``, ``multi_host``;
``dot1x_idle_timeout``) and ``port_overrides`` (``port_security_enabled``,
``port_security_mac_address``). The secrets (``x_secret``) are only tested for presence; the MAC
addresses are only counted.
"""

from __future__ import annotations

from typing import Any

from signalbox.model import (
    AccessControlMode,
    MacFilter,
    MacFilterMode,
    PortAccessControl,
    RadiusEndpoint,
    RadiusPurpose,
    RadiusRef,
    RadiusServer,
)

PROFILES = "rest/radiusprofile"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _port(value: Any) -> int | None:
    try:
        number = int(str(value))
    except ValueError:
        return None
    return number if 1 <= number <= 65535 else None


def _servers(value: Any) -> list[dict[str, Any]]:
    return [s for s in value if isinstance(s, dict)] if isinstance(value, list) else []


def ref_of(profile: dict[str, Any]) -> RadiusRef | None:
    auth = [s for s in _servers(profile.get("auth_servers")) if _text(s.get("ip"))]
    if not auth:
        return None
    acct = [s for s in _servers(profile.get("acct_servers")) if _text(s.get("ip"))]
    return RadiusRef(
        auth=[RadiusEndpoint(address=_text(s["ip"]), port=_port(s.get("port"))) for s in auth],
        acct=[RadiusEndpoint(address=_text(s["ip"]), port=_port(s.get("port"))) for s in acct],
        secret_set=all(bool(_text(s.get("x_secret"))) for s in auth),
    )


def servers_of(profiles: list[dict[str, Any]]) -> list[RadiusServer]:
    """One entry per authentication server of every profile (purpose: Wi-Fi and 802.1X)."""
    out: dict[str, RadiusServer] = {}
    for profile in profiles:
        acct = _servers(profile.get("acct_servers"))
        for s in _servers(profile.get("auth_servers")):
            address = _text(s.get("ip"))
            if not address:
                continue
            key = f"{address}:{_port(s.get('port')) or 1812}"
            out.setdefault(
                key,
                RadiusServer(
                    name=_text(profile.get("name")) or key,
                    address=address,
                    auth_port=_port(s.get("port")),
                    acct_port=_port(acct[0].get("port")) if acct else None,
                    purposes=[RadiusPurpose.WLAN, RadiusPurpose.DOT1X],
                    secret_set=bool(_text(s.get("x_secret"))),
                ),
            )
    return list(out.values())


def mac_filter(conf: dict[str, Any]) -> MacFilter | None:
    if conf.get("mac_filter_enabled") is not True:
        return None
    mode = (
        MacFilterMode.DENY
        if _text(conf.get("mac_filter_policy")) == "deny"
        else MacFilterMode.ALLOW
    )
    listed = conf.get("mac_filter_list")
    return MacFilter(mode=mode, count=len(listed) if isinstance(listed, list) else 0)


def port_access(profile: dict[str, Any], row: dict[str, Any]) -> PortAccessControl | None:
    """802.1X of the port profile and port security of the port; None when neither is on."""
    control = _text(profile.get("dot1x_ctrl"))
    macs = row.get("port_security_mac_address")
    secured = row.get("port_security_enabled") is True
    if control in ("auto", "mac_based", "multi_host"):
        mode = AccessControlMode.MAC_AUTH if control == "mac_based" else AccessControlMode.DOT1X
        return PortAccessControl(
            mode=mode, max_macs=len(macs) if secured and isinstance(macs, list) else None
        )
    if secured:
        return PortAccessControl(
            mode=AccessControlMode.STATIC_MACS,
            max_macs=len(macs) if isinstance(macs, list) else None,
        )
    return None
