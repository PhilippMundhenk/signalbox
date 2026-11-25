"""RADIUS servers, 802.1X, port security and Wi-Fi MAC filters of RouterOS (#162).

* ``/radius``: ``address``, ``service`` (``wireless,login,ppp,hotspot,dot1x,...``),
  ``authentication-port``, ``accounting-port``, ``secret`` (only tested for presence; the REST
  API shows it to a user with the ``sensitive`` policy), ``disabled``. RouterOS 6 and 7.
* ``/interface/dot1x/server`` (RouterOS 7.1 and later): ``interface``, ``auth-types``
  (``dot1x``, ``mac-auth``), ``guest-vlan-id``, ``server-fail-vlan-id``, ``reject-vlan-id``.
  Older versions have no menu: nothing is reported (an optional menu).
* Bridge port ``learn=no`` is port security without a learning limit: only static host entries
  are served, reported as ``static-macs`` *(guess for #21: no real-device check)*.
* ``/interface/wifi/access-list`` (RouterOS 7; ``/interface/wireless/access-list`` in 6):
  entries with a ``mac-address`` and ``action``. A list that rejects everything not listed
  (an entry without ``mac-address`` and ``action=reject``) is an allow-list; entries that only
  reject MACs are a deny-list. Entries with ``interface`` apply to that interface, others to
  all *(guess)*. Only counted.
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

RADIUS = "/rest/radius"
DOT1X_SERVER = "/rest/interface/dot1x/server"

_SERVICES = {
    "wireless": RadiusPurpose.WLAN,
    "dot1x": RadiusPurpose.DOT1X,
    "ppp": RadiusPurpose.VPN,
    "ipsec": RadiusPurpose.VPN,
    "hotspot": RadiusPurpose.LOGIN,
    "login": RadiusPurpose.LOGIN,
}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return value is True or _text(value).lower() in ("true", "yes", "on")


def _int(value: Any) -> int | None:
    try:
        return int(_text(value))
    except ValueError:
        return None


def _port(value: Any, default: int) -> int:
    number = _int(value)
    return number if number is not None and 1 <= number <= 65535 else default


def _vlan(value: Any) -> int | None:
    number = _int(value)
    return number if number is not None and 1 <= number <= 4094 else None


def radius_servers(rows: list[dict[str, Any]]) -> list[RadiusServer]:
    out: list[RadiusServer] = []
    for row in rows:
        address = _text(row.get("address"))
        if not address or _flag(row.get("disabled")):
            continue
        services = [s.strip() for s in _text(row.get("service")).split(",") if s.strip()]
        purposes: list[RadiusPurpose] = []
        for service in services or ["wireless", "login", "ppp", "hotspot", "dot1x"]:
            purpose = _SERVICES.get(service)
            if purpose is not None and purpose not in purposes:
                purposes.append(purpose)
        out.append(
            RadiusServer(
                name=_text(row.get("comment")) or address,
                address=address,
                auth_port=_port(row.get("authentication-port"), 1812),
                acct_port=_port(row.get("accounting-port"), 1813),
                purposes=purposes,
                secret_set=bool(_text(row.get("secret"))) if "secret" in row else None,
            )
        )
    return out


def wlan_radius(servers: list[RadiusServer]) -> RadiusRef | None:
    """The RADIUS servers an enterprise SSID asks: those of the service ``wireless``."""
    wireless = [s for s in servers if RadiusPurpose.WLAN in s.purposes]
    if not wireless:
        return None
    known = [s.secret_set for s in wireless]
    return RadiusRef(
        auth=[RadiusEndpoint(address=s.address, port=s.auth_port) for s in wireless],
        acct=[RadiusEndpoint(address=s.address, port=s.acct_port) for s in wireless],
        secret_set=None if None in known else all(known),
    )


def dot1x_ports(rows: list[dict[str, Any]]) -> dict[str, PortAccessControl]:
    """``/interface/dot1x/server`` entries by interface name."""
    out: dict[str, PortAccessControl] = {}
    for row in rows:
        name = _text(row.get("interface"))
        if not name or _flag(row.get("disabled")):
            continue
        types = {t.strip() for t in _text(row.get("auth-types") or "dot1x").split(",")}
        mode = {
            (True, True): AccessControlMode.DOT1X_OR_MAC,
            (True, False): AccessControlMode.DOT1X,
            (False, True): AccessControlMode.MAC_AUTH,
        }.get(("dot1x" in types, "mac-auth" in types), AccessControlMode.DOT1X)
        out[name] = PortAccessControl(
            mode=mode,
            guest_vlan=_vlan(row.get("guest-vlan-id")),
            auth_fail_vlan=_vlan(row.get("reject-vlan-id"))
            or _vlan(row.get("server-fail-vlan-id")),
        )
    return out


def learning_off(row: dict[str, Any]) -> PortAccessControl | None:
    """A bridge port that does not learn addresses (port security with static entries)."""
    if _text(row.get("learn")).lower() in ("no", "false"):
        return PortAccessControl(mode=AccessControlMode.STATIC_MACS, sticky=False)
    return None


def mac_filter(rows: list[dict[str, Any]], interface: str) -> MacFilter | None:
    """MAC filter of a Wi-Fi interface from the access list; None without MAC entries."""
    mine = [
        r
        for r in rows
        if not _flag(r.get("disabled")) and _text(r.get("interface")) in ("", interface)
    ]
    listed = [r for r in mine if _text(r.get("mac-address"))]
    if not listed:
        return None
    catch_all = any(
        not _text(r.get("mac-address")) and _text(r.get("action")) == "reject" for r in mine
    )
    if catch_all:
        accepted = [r for r in listed if _text(r.get("action") or "accept") == "accept"]
        return MacFilter(mode=MacFilterMode.ALLOW, count=len(accepted))
    rejected = [r for r in listed if _text(r.get("action")) == "reject"]
    return MacFilter(mode=MacFilterMode.DENY, count=len(rejected)) if rejected else None
