"""Device health and time (#178, #179): model, capability, observe() completion, contract."""

import asyncio
from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError

from factories import (
    SITE,
    T0,
    MiB,
    device,
    device_time,
    fan,
    health,
    ntp_server,
    psu,
    snapshot,
    storage,
    ups,
)
from signalbox.adapters import (
    API_VERSION,
    SINCE,
    AdapterContractError,
    Capability,
    Manifest,
    Observation,
    check_manifest,
)
from signalbox.merge import merge
from signalbox.model import (
    Device,
    DeviceHealth,
    DeviceRole,
    DeviceTime,
    NtpClient,
    StorageKind,
    TemperatureSensor,
    json_schema,
)
from signalbox.testing import assert_contract, health_problems, problems, time_problems
from test_adapters import Fake, ctx


class Healthy(Fake):
    manifest = Manifest(
        **{
            **Fake.manifest.model_dump(exclude={"capabilities", "api_version", "config"}),
            "api_version": "1.2",
            "capabilities": frozenset({Capability.INTERFACES, Capability.HEALTH, Capability.TIME}),
            "config": Fake.manifest.config,
        }
    )
    managed = False

    async def read_interfaces(self) -> Observation:
        base = await super().read_interfaces()
        if not self.managed:
            return base
        d = self.context.device_id
        sw = Device(id=f"{d}/sw1", site_id="x", name="Switch", role=DeviceRole.SWITCH, adapter="x")
        return base.model_copy(update={"devices": [sw]})

    async def read_health(self) -> Observation:
        d = self.context.device_id
        own = health(boot_time=None, uptime_seconds=3600, fans=[fan()], power_supplies=[psu()])
        values = {d: own}
        if self.managed:
            values[f"{d}/sw1"] = DeviceHealth(boot_time=T0, cpu_load_pct=5)
        return Observation(health=values)

    async def read_time(self) -> Observation:
        d = self.context.device_id
        value = DeviceTime(
            clock=T0,
            timezone="Etc/UTC",
            ntp_client=NtpClient(enabled=True, servers=["pool.ntp.org"]),
            ntp_server=ntp_server(f"{self.context.site_id}/segment/native"),
        )
        return Observation(time={d: value})


def test_health_and_time_need_api_1_2() -> None:
    assert API_VERSION == "1.4"  # 1.3: vpn (#239), 1.4: firewall (#135)
    assert SINCE[Capability.HEALTH] == SINCE[Capability.TIME] == "1.2"
    check_manifest(Healthy.manifest)
    check_manifest(Fake.manifest)  # a 1.0 adapter keeps working
    old = Healthy.manifest.model_copy(update={"api_version": "1.1"})
    with pytest.raises(
        AdapterContractError, match=r"declares health, which needs adapter API 1\.2"
    ):
        check_manifest(old)
    with pytest.raises(AdapterContractError, match="not an adapter API version"):
        check_manifest(Fake.manifest.model_copy(update={"api_version": "one"}))


def test_declared_health_must_be_implemented() -> None:
    class Missing(Fake):
        manifest = Healthy.manifest

    with pytest.raises(AdapterContractError, match=r"does not implement Reads(Health|Time)"):
        Missing(ctx())


async def test_observe_puts_health_and_time_on_the_device() -> None:
    snap = await assert_contract(Healthy(ctx()))
    h = snap.device.health
    assert h is not None and h.uptime_seconds == 3600
    assert h.boot_time is not None
    assert abs((snap.observed_at - timedelta(hours=1) - h.boot_time).total_seconds()) < 1
    t = snap.device.time
    assert t is not None and t.clock == T0 and t.read_at is not None
    assert t.uncertainty_seconds is not None and t.uncertainty_seconds >= 0
    assert snap.device.capabilities == ["health", "interfaces", "time"]


async def test_observe_fills_managed_devices_and_derives_uptime() -> None:
    a = Healthy(ctx())
    a.managed = True
    snap = await assert_contract(a)
    (sw,) = snap.extra_devices
    assert sw.health is not None and sw.health.cpu_load_pct == 5
    assert sw.health.uptime_seconds is not None and sw.health.uptime_seconds > 0
    assert sw.time is None
    net = merge([SITE], [snap])
    assert net.device("ap1/sw1") == sw


async def test_adapter_set_read_at_is_kept() -> None:
    class Own(Healthy):
        async def read_time(self) -> Observation:
            value = device_time(offset_seconds=90, uncertainty_seconds=0.5)
            return Observation(time={self.context.device_id: value})

    snap = await Own(ctx()).observe()
    assert snap.device.time == device_time(offset_seconds=90, uncertainty_seconds=0.5)


async def test_failed_health_read_is_partial() -> None:
    from signalbox.adapters import AdapterError

    class Broken(Healthy):
        async def read_health(self) -> Observation:
            raise AdapterError("no /system/resource")

    snap = await Broken(ctx()).observe()
    assert snap.device.health is None
    assert [e.capability for e in snap.errors] == ["health"]
    assert "declares health but no device has health" in problems(Broken(ctx()), snap)


def test_contract_reports_undeclared_and_inconsistent_values() -> None:
    adapter = Fake(ctx())
    good = asyncio.run(adapter.observe())
    naive = datetime(2026, 1, 1)
    bad_health = health(
        memory_used_bytes=300 * MiB,
        boot_time=naive,
        storage=[storage("/", total_bytes=1, used_bytes=2)],
        fans=[fan(name=" ")],
    )
    bad_time = DeviceTime(
        clock=naive,
        timezone=" ",
        ntp_client=NtpClient(enabled=True, servers=[""], last_sync=naive),
        ntp_server=ntp_server("elsewhere/segment/1"),
    )
    dev = good.device.model_copy(update={"health": bad_health, "time": bad_time})
    text = "\n".join(problems(adapter, good.model_copy(update={"device": dev})))
    for needle in [
        "health reported without declaring health",
        "time reported without declaring time",
        "memory used",
        "storage / used 2 > total 1",
        "has no name",
        "health time 2026-01-01 00:00:00 has no time zone",
        "time 2026-01-01 00:00:00 has no time zone",
        "clock without read_at",
        "empty time zone",
        "empty NTP server name",
        "NTP server segment elsewhere/segment/1",
    ]:
        assert needle in text, needle
    assert health_problems("x", health()) == []
    assert time_problems("x", device_time(), "home/segment/") == []
    assert health_problems("x", health(ups=[ups(last_test=naive)]))


def test_derived_values() -> None:
    h = health(memory_used_bytes=192 * MiB, temperatures=[])
    assert h.memory_used_pct() == 75
    assert h.max_temperature_c() is None
    assert DeviceHealth().memory_used_pct() is None
    hot = health(
        temperatures=[
            TemperatureSensor(name="a", value_c=40),
            TemperatureSensor(name="b", value_c=81),
        ]
    )
    assert hot.max_temperature_c() == 81
    assert storage("/overlay", total_bytes=200, used_bytes=50).used_pct() == 25
    assert storage("/tmp", StorageKind.TEMPORARY).used_pct() is None
    assert device_time(offset_seconds=-420).offset_seconds() == -420
    assert DeviceTime(clock=T0).offset_seconds() is None
    from signalbox.adapters import _complete_health

    both = health()
    assert _complete_health(both, T0) is both  # reported values are kept as they are
    assert _complete_health(DeviceHealth(boot_time=T0 + timedelta(1)), T0).uptime_seconds == 0


def test_validation_bounds() -> None:
    with pytest.raises(ValidationError):
        DeviceHealth(cpu_load_pct=101)
    with pytest.raises(ValidationError):
        DeviceHealth(memory_used_bytes=-1)
    with pytest.raises(ValidationError):
        DeviceHealth(load_average=(1.0, 2.0))  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        NtpClient(enabled=True, stratum=17)
    with pytest.raises(ValidationError):
        DeviceTime(utc_offset_minutes=24 * 60)


def test_round_trip_and_schema() -> None:
    dev = device("gw", health=health(ups=[ups()], fans=[fan()]), time=device_time(3))
    snap = snapshot(dev)
    assert type(snap).model_validate_json(snap.model_dump_json()) == snap
    defs = json_schema()["$defs"]
    for name in ("DeviceHealth", "DeviceTime", "NtpClient", "NtpServer", "UpsStatus"):
        assert name in defs, name
    assert "ntp_servers" in defs["DhcpServer"]["properties"]
