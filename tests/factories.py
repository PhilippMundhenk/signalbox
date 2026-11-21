"""Small builders for model objects used across the tests (documentation addresses only)."""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_address, ip_interface
from typing import Any

from signalbox.model import (
    Device,
    DeviceRole,
    Port,
    Site,
    Snapshot,
    Source,
    port_id,
)

T0 = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
SITE = Site(id="home", name="Home")


def device(
    device_id: str, role: DeviceRole = DeviceRole.GATEWAY, adapter: str = "test", **kw: Any
) -> Device:
    return Device(
        id=device_id,
        site_id=kw.pop("site_id", SITE.id),
        name=kw.pop("name", device_id),
        role=role,
        adapter=adapter,
        source=Source(adapter=adapter, device_id=device_id),
        **kw,
    )


def port(device_id: str, name: str, **kw: Any) -> Port:
    return Port(id=port_id(device_id, name), device_id=device_id, name=name, **kw)


def snapshot(dev: Device, **kw: Any) -> Snapshot:
    return Snapshot(device=dev, observed_at=kw.pop("observed_at", T0), **kw)


def ip(text: str) -> Any:
    return ip_address(text)


def iface(text: str) -> Any:
    return ip_interface(text)
