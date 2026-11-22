"""Device health rules (#130, #131, #178): passing, failing and silent cases."""

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from factories import SITE, T0, MiB, device, fan, health, psu, snapshot, storage, ups
from signalbox.merge import merge
from signalbox.model import (
    DeviceRole,
    DeviceStatus,
    Network,
    RebootReason,
    StorageKind,
    TemperatureSensor,
)
from signalbox.rules import evaluate
from signalbox.rules.builtin import RULES as BUILTIN
from signalbox.rules.health import RULES, reboot, resources
from signalbox.secrets import load_vault
from signalbox.sightings import (
    BOOT,
    CPU,
    History,
    ValueChange,
    ValueHistory,
    boot_value,
    observed_values,
    parse_boot,
)
from signalbox.store import Store

ROUND = timedelta(minutes=5)


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    s = Store(tmp_path / "db.sqlite", load_vault(tmp_path, env={}))
    s.put_site(SITE)
    yield s
    s.close()


def net(*healths: Any, status: DeviceStatus = DeviceStatus.OK) -> Network:
    """One access point per health value: ap1, ap2, ..."""
    snaps = [
        snapshot(device(f"ap{i}", DeviceRole.AP, name=f"ap-{i}", health=h), status=status)
        for i, h in enumerate(healths, 1)
    ]
    return merge([SITE], snaps)


def run(n: Network, history: History | None = None) -> list[tuple[str, str, str]]:
    return sorted(
        (f.rule_id, f.severity.value, f.message)
        for f in evaluate(n, RULES, None, history or History(now=T0, since=T0, observations=1))
    )


def test_all_rules_registered_and_healthy_device_is_quiet() -> None:
    ids = {r.id for r in BUILTIN}
    assert {r.id for r in RULES} <= ids
    assert run(net(health())) == []


def test_silent_without_data() -> None:
    from signalbox.model import DeviceHealth

    assert run(net(None)) == []
    assert run(net(DeviceHealth())) == []
    empty = health(
        memory_total_bytes=None,
        cpu_load_pct=None,
        storage=[storage("/overlay", total_bytes=None, used_bytes=1)],
        temperatures=[],
        fans=[fan(ok=None, rpm=0)],
        power_supplies=[psu(ok=None)],
        ups=[ups(on_battery=None, runtime_seconds=None, last_test=None)],
        uptime_seconds=None,
    )
    assert run(net(empty)) == []
    assert run(net(empty), History.empty()) == []


def test_memory_and_temperature() -> None:
    hot = [
        TemperatureSensor(name="cpu", value_c=96.0, limit_c=95.0),
        TemperatureSensor(name="board", value_c=86.0),  # generic limit 85 °C
        TemperatureSensor(name="phy", value_c=80.0),
    ]
    out = run(net(health(memory_used_bytes=246 * MiB, temperatures=hot)))
    assert out == sorted(
        [
            ("device.resources", "warning", "ap-1 has 96 % of its memory in use"),
            (
                "device.resources",
                "warning",
                "ap-1 sensor cpu is at 96 °C, above its limit of 95 °C",
            ),
            (
                "device.resources",
                "warning",
                "ap-1 sensor board is at 86 °C, above the generic limit of 85 °C",
            ),
        ]
    )
    # 89 % and below the limits: quiet
    assert run(net(health(memory_used_bytes=228 * MiB))) == []


def test_storage_full() -> None:
    disks = [
        storage("/overlay", total_bytes=100 * MiB, used_bytes=95 * MiB),
        storage("/data", StorageKind.DATA, total_bytes=100 * MiB, used_bytes=99 * MiB),
        storage("/tmp", StorageKind.TEMPORARY, total_bytes=100 * MiB, used_bytes=100 * MiB),
        storage("/mnt", StorageKind.OTHER, total_bytes=100 * MiB, used_bytes=100 * MiB),
        storage("/boot", total_bytes=100 * MiB, used_bytes=89 * MiB),
    ]
    assert run(net(health(storage=disks))) == sorted(
        [
            ("health.storage-full", "warning", "ap-1 system storage /overlay is 95 % full"),
            ("health.storage-full", "error", "ap-1 storage /data is 99 % full"),
        ]
    )


def test_fans_and_power_supplies() -> None:
    h = health(
        fans=[fan("fan1", rpm=0, ok=False), fan("fan2", rpm=None, ok=False), fan("fan3")],
        power_supplies=[psu("psu1"), psu("psu2", ok=False)],
    )
    assert run(net(h)) == [
        ("health.fan-failed", "warning", "ap-1 reports fan fan1 as failed (0 rpm)"),
        ("health.fan-failed", "warning", "ap-1 reports fan fan2 as failed"),
        ("health.psu-failed", "warning", "ap-1 reports power supply psu2 as failed"),
    ]


def test_ups() -> None:
    good = ups("ok")
    bad = ups("rack", on_battery=True, charge_pct=80.0, runtime_seconds=300, load_pct=55.0)
    old = ups("old", charge_pct=None, last_test=T0 - timedelta(days=200), load_pct=None)
    weak = ups("weak", runtime_seconds=599, load_pct=None, on_battery=True, charge_pct=None)
    out = run(net(health(ups=[good, bad, old, weak])))
    assert out == sorted(
        [
            (
                "health.ups-on-battery",
                "warning",
                "UPS rack (on ap-1) runs on battery, 80 % charged",
            ),
            ("health.ups-on-battery", "warning", "UPS weak (on ap-1) runs on battery"),
            (
                "health.ups-runtime-low",
                "warning",
                "UPS rack (on ap-1) has a runtime of 5 minutes at 55 % load, less than 10 minutes",
            ),
            (
                "health.ups-runtime-low",
                "warning",
                "UPS weak (on ap-1) has a runtime of 9 minutes, less than 10 minutes",
            ),
            ("health.ups-not-tested", "info", "UPS old (on ap-1) was last tested 200 days ago"),
        ]
    )
    # without a history (no time to compare with) the test age is not checked
    assert [r for r, _, _ in run(net(health(ups=[old])), History.empty())] == []


def test_uptime_very_long() -> None:
    assert run(net(health(uptime_seconds=400 * 86400))) == [
        ("health.uptime-very-long", "info", "ap-1 has been running for 400 days without a restart")
    ]
    assert run(net(health(uptime_seconds=364 * 86400))) == []


# CPU and reboots: through the store -----------------------------------------------------


def rounds(store: Store, *nets: Network) -> History:
    """Record one round per network, five minutes apart; the history after the last one."""
    at = T0
    for n in nets:
        store.record_history(n, at)
        at += ROUND
    return store.history(at - ROUND, 30)


def cpu_findings(store: Store, *loads: float | None) -> list[str]:
    nets = [net(health(cpu_load_pct=load)) for load in loads]
    h = rounds(store, *nets)
    return [f.message for f in evaluate(nets[-1], [resources], None, h)]


def test_cpu_one_spike_is_quiet(store: Store) -> None:
    assert cpu_findings(store, 50.0, 95.0) == []


def test_cpu_sustained(store: Store) -> None:
    assert cpu_findings(store, 50.0, 95.0, 97.0) == [
        "ap-1 has a CPU load of 97 %, high since 2026-01-15 12:05 UTC"
    ]


def test_cpu_back_to_normal_and_no_value(store: Store) -> None:
    assert cpu_findings(store, 95.0, 95.0, 40.0) == []
    # not reported this round: the stored state stays, but nothing is checked
    assert cpu_findings(store, 95.0, None) == []


def test_cpu_reevaluation_without_new_round(store: Store) -> None:
    """Rules evaluated again on the same round do not count it twice."""
    n = net(health(cpu_load_pct=95.0))
    store.record_history(net(health(cpu_load_pct=10.0)), T0)
    store.record_history(n, T0 + ROUND)
    later = store.history(T0 + 2 * ROUND, 30)
    assert evaluate(n, [resources], None, later) == []


def booted(at: Any, reason: RebootReason | None = None, **kw: Any) -> Network:
    return net(health(boot_time=at, last_reboot_reason=reason, **kw))


def reboot_findings(store: Store, *nets: Network) -> list[tuple[str, str]]:
    h = rounds(store, *nets)
    return [(f.severity.value, f.message) for f in evaluate(nets[-1], [reboot], None, h)]


BOOT0 = T0 - timedelta(days=3)


def test_boot_jitter_is_not_a_reboot(store: Store) -> None:
    # a derived boot time moves by about a second, across a minute boundary
    jitter = [BOOT0 + timedelta(seconds=s) for s in (29.4, 30.6, 29.8, 31.0)]
    assert reboot_findings(store, *(booted(b) for b in jitter)) == []
    assert len(store.history(T0, 30).boots["ap1"].changes) >= 1  # recorded, then ignored


def test_single_reboot(store: Store) -> None:
    at = T0 + timedelta(minutes=7)
    out = reboot_findings(store, booted(BOOT0), booted(BOOT0), booted(at, RebootReason.POWER))
    assert out == [("info", "ap-1 restarted at 2026-01-15 12:07 UTC (reason: power)")]


def test_upgrade_reboot_is_quiet(store: Store) -> None:
    at = T0 + timedelta(minutes=7)
    assert reboot_findings(store, booted(BOOT0), booted(at, RebootReason.UPGRADE)) == []


def test_user_reboot_is_quiet(store: Store) -> None:
    at = T0 + timedelta(minutes=7)
    assert reboot_findings(store, booted(BOOT0), booted(at, RebootReason.USER)) == []


def test_repeated_reboots(store: Store) -> None:
    boots = [BOOT0] + [T0 + timedelta(minutes=4 + 5 * i) for i in range(3)]
    nets = [booted(b, RebootReason.WATCHDOG if i else None) for i, b in enumerate(boots)]
    assert reboot_findings(store, *nets) == [
        (
            "warning",
            "ap-1 restarted 3 times in the last 24 hours, last at 2026-01-15 12:14 UTC "
            "(reason: watchdog)",
        )
    ]


def test_old_reboot_and_first_sighting_are_quiet(store: Store) -> None:
    assert reboot_findings(store, booted(BOOT0)) == []
    old = ValueChange(
        at=T0 - timedelta(hours=25), old=boot_value(BOOT0, None), new=boot_value(T0, None)
    )
    h = History(
        now=T0,
        since=BOOT0,
        observations=10,
        boots={
            "ap1": ValueHistory(
                first_seen=BOOT0, last_seen=T0, value=old.new, since=old.at, changes=[old]
            )
        },
    )
    assert evaluate(booted(T0), [reboot], None, h) == []
    assert evaluate(booted(T0), [reboot], None, History.empty()) == []


def test_unreachable_device_records_nothing() -> None:
    n = net(health(cpu_load_pct=95.0), status=DeviceStatus.UNREACHABLE)
    assert not any(kind in (BOOT, CPU) for kind, _ in observed_values(n))
    seen = observed_values(net(health(cpu_load_pct=95.0, last_reboot_reason=RebootReason.CRASH)))
    assert seen[(CPU, "ap1")] == "high"
    assert parse_boot(str(seen[(BOOT, "ap1")])) == (BOOT0, "crash")
    assert parse_boot(boot_value(BOOT0, None)) == (BOOT0, None)


def test_device_deletion_forgets_boots(store: Store) -> None:
    store.record_history(booted(BOOT0, cpu_load_pct=95.0), T0)
    assert "ap1" in store.history(T0, 30).boots and "ap1" in store.history(T0, 30).cpu
    store.delete_device("ap1")
    h = store.history(T0, 30)
    assert h.boots == {} and h.cpu == {}
