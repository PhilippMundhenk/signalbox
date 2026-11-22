"""The link to a device's own web interface (#214)."""

from __future__ import annotations

from typing import Any

import pytest

from signalbox.model import ManagementService, ServiceKind
from signalbox.web.manage_url import manage_url


def svc(kind: ServiceKind, port: int | None, **kw: Any) -> ManagementService:
    kw.setdefault("enabled", True)
    return ManagementService(
        id=f"d/service/{kind.value}-{port}", device_id="d", kind=kind, port=port, **kw
    )


@pytest.mark.parametrize(
    ("adapter", "config", "expected"),
    [
        ("opnsense", {"url": "192.0.2.1"}, "https://192.0.2.1"),
        ("opnsense", {"url": "https://opnsense.lan:8443/x"}, "https://opnsense.lan:8443"),
        ("openwrt", {"url": "https://192.0.2.2/ubus"}, "https://192.0.2.2"),
        ("mikrotik", {"url": "192.0.2.3"}, "https://192.0.2.3"),
        ("omada", {"url": "https://192.0.2.5:8043"}, "https://192.0.2.5:8043"),
        ("omada", {"url": "https://u:secret@192.0.2.5"}, "https://192.0.2.5"),
        ("fritzbox", {"url": "https://fritz.box:49443"}, "https://fritz.box"),
        ("fritzbox", {"url": "fritz.box"}, "https://fritz.box"),
        ("prosafe", {"address": "192.0.2.10"}, "http://192.0.2.10"),
        ("easysmart", {"address": "192.0.2.11"}, "http://192.0.2.11"),
        ("opnsense", {"url": "https://[2001:db8::1]:8443"}, "https://[2001:db8::1]:8443"),
        ("opnsense", {}, None),
        ("opnsense", {"url": "ftp://x"}, None),
        ("opnsense", {"url": "https://x:bad"}, None),
        ("prosafe", {"address": "a/b"}, None),
        ("unknown", {"url": "192.0.2.1"}, None),
    ],
)
def test_from_adapter_settings(adapter: str, config: dict[str, Any], expected: str | None) -> None:
    assert manage_url(adapter, config, [], None) == expected


def test_service_wins_over_settings() -> None:
    cfg = {"url": "192.0.2.1"}
    both = [svc(ServiceKind.HTTP, 80), svc(ServiceKind.HTTPS, 8443, name="www-ssl")]
    assert manage_url("mikrotik", cfg, both, "192.0.2.9") == "https://192.0.2.9:8443"
    only_http = [svc(ServiceKind.HTTP, 8080)]
    assert manage_url("mikrotik", cfg, only_http, "192.0.2.9") == "http://192.0.2.9:8080"
    https = [svc(ServiceKind.HTTPS, 443)]
    assert manage_url("mikrotik", cfg, https, "2001:db8::9") == "https://[2001:db8::9]"
    listening = [svc(ServiceKind.HTTPS, 443, listen=["0.0.0.0"])]
    assert manage_url("mikrotik", cfg, listening, "192.0.2.9") == "https://192.0.2.9"


def test_services_that_do_not_count() -> None:
    cfg = {"url": "192.0.2.1"}
    fallback = "https://192.0.2.1"
    for s in (
        svc(ServiceKind.HTTPS, 443, enabled=False),
        svc(ServiceKind.HTTPS, None),
        svc(ServiceKind.SSH, 22),
        svc(ServiceKind.HTTPS, 443, listen=["192.0.2.77"]),
        svc(ServiceKind.HTTPS, 443, listen=["2001:db8::1"]),
    ):
        assert manage_url("mikrotik", cfg, [s], "192.0.2.9") == fallback
    https = [svc(ServiceKind.HTTPS, 443)]
    assert manage_url("mikrotik", cfg, https, None) == fallback
    assert manage_url("mikrotik", cfg, https, "bad/host") == fallback
    narrow = [svc(ServiceKind.HTTPS, 443, listen=["192.0.2.9"])]
    assert manage_url("mikrotik", cfg, narrow, "not-an-ip") == fallback
