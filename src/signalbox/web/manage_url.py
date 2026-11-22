"""The address of a device's own web interface (#214), derived for ``/api/devices``.

Never contains credentials: only scheme, host and port are taken, never a user name, password,
path or query. ``None`` when nothing is known.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any
from urllib.parse import urlsplit

from signalbox.model import ManagementService, ServiceKind

#: Adapters whose ``url`` setting is the device's web address (scheme optional, default https).
_URL_ADAPTERS = {"opnsense", "openwrt", "mikrotik", "omada"}
#: Adapters whose ``address`` setting is the switch's address; the web UI is plain http.
_ADDRESS_ADAPTERS = {"prosafe", "easysmart"}
_DEFAULT_PORT = {"https": 443, "http": 80}
_UNSPECIFIED = (IPv4Address("0.0.0.0"), IPv6Address("::"))


def _host(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _origin(scheme: str, host: str, port: int | None) -> str:
    suffix = "" if port in (None, _DEFAULT_PORT[scheme]) else f":{port}"
    return f"{scheme}://{_host(host)}{suffix}"


def _from_config(adapter: str, config: dict[str, Any]) -> str | None:
    if adapter in _ADDRESS_ADAPTERS:
        value = str(config.get("address") or "").strip()
        return _origin("http", value, None) if value and not set(value) & set("/@?#") else None
    if adapter != "fritzbox" and adapter not in _URL_ADAPTERS:
        return None
    value = str(config.get("url") or "").strip()
    if not value:
        return None
    if "://" not in value:
        value = f"https://{value}"
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in _DEFAULT_PORT or not parts.hostname:
        return None
    if adapter == "fritzbox":  # the configured port is TR-064, the web UI is on 443
        return _origin("https", parts.hostname, None)
    return _origin(parts.scheme, parts.hostname, port)


def _listens_on(service: ManagementService, address: str) -> bool:
    if not service.listen:
        return True
    try:
        mine = ip_address(address)
    except ValueError:
        return False
    return any(
        a == mine or (a in _UNSPECIFIED and a.version == mine.version) for a in service.listen
    )


def _from_services(services: list[ManagementService], address: str | None) -> str | None:
    address = (address or "").strip("[]")
    if not address or set(address) & set("/@?# "):
        return None
    for kind in (ServiceKind.HTTPS, ServiceKind.HTTP):
        for s in sorted(services, key=lambda x: x.port or 0):
            if s.kind == kind and s.enabled and s.port is not None and _listens_on(s, address):
                return _origin(kind.value, address, s.port)
    return None


def manage_url(
    adapter: str,
    config: dict[str, Any],
    services: list[ManagementService],
    management_address: str | None,
) -> str | None:
    """A reported https (then http) service on the management address, else the adapter's
    own settings, else ``None``."""
    return _from_services(services, management_address) or _from_config(adapter, config)
