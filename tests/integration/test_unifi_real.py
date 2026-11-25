"""The UniFi adapter against the real UniFi Network application in Docker (#432).

The application (tools/integration/unifi/controller.py, Network 8, 9 and 10 in turn) is set
up through its own first-run API and holds the site "default" without any adopted device: the
default network, the VLAN networks IoT (20, 198.51.100.0/24) and Guest (30, 203.0.113.0/24)
with DHCP, and a local account with the read-only role (IT_UNIFI_USER/PASSWORD). There is no
gateway, switch or access point: ports, radios, uplinks and clients stay simulator-only
(tests/test_unifi*.py).
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import SecretStr

from integration.conftest import Target
from signalbox.adapters import AdapterContext
from signalbox.adapters.unifi import UnifiAdapter, UnifiConfig
from signalbox.model import DeviceRole, DeviceStatus
from signalbox.testing import assert_contract

DEV = "unifi1"
TIMEOUT = 60.0


@pytest.fixture(scope="session")
def ctrl(target: Callable[[str], Target]) -> dict[str, str]:
    t = target("unifi")
    assert t.pin, "IT_UNIFI_PIN"
    return {"URL": t.url, "PIN": t.pin, "USER": t.username, "PASSWORD": t.password, **t.extra}


def adapter(
    ctrl: dict[str, str],
    password: str | None = None,
    site: str = "default",
    pin: str | None = None,
) -> UnifiAdapter:
    config = UnifiConfig(
        url=ctrl["URL"],
        site=site,
        username=ctrl["USER"],
        password=SecretStr(password if password is not None else ctrl["PASSWORD"]),
    )
    ctx = AdapterContext(
        site_id="home",
        device_id=DEV,
        device_name="UniFi",
        role=DeviceRole.OTHER,
        config=config,
        pinned_fingerprint=pin or ctrl["PIN"],
        timeout=TIMEOUT,
    )
    return UnifiAdapter(ctx)


async def test_read_contract_and_version(ctrl: dict[str, str]) -> None:
    a = adapter(ctrl)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    assert snap.status is DeviceStatus.OK, snap.errors
    assert (snap.device.vendor, snap.device.model) == ("Ubiquiti", "UniFi Network Application")
    assert snap.device.firmware is not None
    assert snap.device.firmware.current == ctrl["VERSION"], snap.device.firmware
    assert ctrl["VERSION"].split(".")[0] == ctrl["MAJOR"]


async def test_site_by_internal_name_and_by_description(ctrl: dict[str, str]) -> None:
    for site in ("default", "Default"):
        a = adapter(ctrl, site=site)
        try:
            snap = await a.observe()
        finally:
            await a.close()
        assert snap.status is DeviceStatus.OK, (site, snap.errors)
    a = adapter(ctrl, site="no-such-site")
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is not DeviceStatus.OK


async def test_networks_and_dhcp(ctrl: dict[str, str]) -> None:
    a = adapter(ctrl)
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is DeviceStatus.OK, snap.errors
    by_vlan = {s.vlan: s for s in snap.segments}
    assert None in by_vlan or 1 in by_vlan, "the default network"
    refused = ctrl.get("REFUSED", "[]")
    for vlan, name in ((20, "IoT"), (30, "Guest")):
        if name in refused:
            continue
        assert vlan in by_vlan, sorted(str(v) for v in by_vlan)
        assert by_vlan[vlan].name == name
    # the default network of a new site has DHCP; so do the two test networks
    assert snap.dhcp_servers, "no DHCP server read"
    for server in snap.dhcp_servers:
        assert server.enabled
        assert server.pools and server.pools[0].start < server.pools[0].end
    if "IoT" not in refused:
        iot = next(d for d in snap.dhcp_servers if d.segment_id == by_vlan[20].id)
        assert str(iot.pools[0].start) == "198.51.100.100"
        assert str(iot.pools[0].end) == "198.51.100.199"
        assert iot.lease_seconds == 86400


async def test_health_and_time(ctrl: dict[str, str]) -> None:
    a = adapter(ctrl)
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is DeviceStatus.OK, snap.errors
    assert snap.extra_devices == [], "no device is adopted"
    assert snap.device.health is not None
    t = snap.device.time
    assert t is not None and t.clock is not None, t
    offset = t.offset_seconds()
    assert offset is not None and abs(offset) < 600, t


async def test_wrong_password_and_pin(ctrl: dict[str, str]) -> None:
    a = adapter(ctrl, password="wrong-" + ctrl["PASSWORD"])
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is DeviceStatus.AUTH_FAILED, snap.errors
    a = adapter(ctrl, pin="00" * 32)
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is DeviceStatus.UNTRUSTED, snap.errors
