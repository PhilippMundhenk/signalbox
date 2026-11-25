"""The PoE budget check and the PoE model (#116, #159)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import SecretStr

from factories import SITE, device, port
from signalbox.adapters import AdapterContext
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.adapters.openwrt import poe as openwrt_poe
from signalbox.model import (
    DeviceRole,
    Network,
    PoeMode,
    PoePriority,
    PoeStatus,
    PoeSupply,
    Port,
    PortPoe,
)
from signalbox.rules import Finding, Severity, evaluate
from signalbox.rules.poe_checks import poe_budget
from signalbox.sim.mikrotik import PASSWORD, MikrotikSimulator
from signalbox.sim.openwrt import OpenWrtSim, create_app
from signalbox.sim.server import serve
from signalbox.sim.snmp import SnmprecTransport, adapter_for, typical_switch
from signalbox.testing import assert_contract

SW = DeviceRole.SWITCH


def run(net: Network) -> list[Finding]:
    return [f for f in evaluate(net, [poe_budget]) if f.rule_id == poe_budget.id]


def lab(supply: PoeSupply | None, **ports: PortPoe) -> Network:
    return Network(
        sites=[SITE],
        devices=[device("sw", SW, name="Switch", poe=supply)],
        ports=[port("sw", name, poe=state) for name, state in ports.items()],
    )


# --- the model ---------------------------------------------------------------------------


def test_a_bool_is_read_as_the_enabled_flag() -> None:
    assert port("sw", "1", poe=True).poe == PortPoe(enabled=True)
    assert port("sw", "1", poe=False).poe == PortPoe(enabled=False)
    assert port("sw", "1").poe is None
    assert Port.model_validate({"id": "x", "device_id": "d", "name": "1", "poe": True}).poe


def test_a_class_above_8_is_refused() -> None:
    with pytest.raises(ValueError):
        PortPoe(power_class=9)


# --- poe.budget --------------------------------------------------------------------------


def test_budget_near_the_limit_is_a_warning() -> None:
    (f,) = run(lab(PoeSupply(budget_w=65, used_w=58)))
    assert f.severity is Severity.WARNING and f.objects == ["sw"]
    assert f.message == "Switch delivers 58 W of its 65 W PoE budget (89 %)."
    assert f.message_id == "poe.budgetNear" and f.fix_id == "poe.budget.fix"
    assert f.params == {"device": "Switch", "used": "58", "budget": "65", "percent": 89}


def test_budget_used_up_is_an_error() -> None:
    (f,) = run(lab(PoeSupply(budget_w=60, used_w=61.5)))
    assert f.severity is Severity.ERROR and f.message_id == "poe.budgetOver"


def test_the_sum_of_the_ports_is_used_without_a_total() -> None:
    net = lab(
        PoeSupply(budget_w=30),
        p1=PortPoe(power_w=14.0, status=PoeStatus.DELIVERING),
        p2=PortPoe(power_w=12.0, status=PoeStatus.DELIVERING),
    )
    (f,) = run(net)
    assert f.params["used"] == "26"


@pytest.mark.parametrize(
    "supply",
    [None, PoeSupply(), PoeSupply(budget_w=65), PoeSupply(budget_w=0, used_w=5)],
)
def test_no_budget_or_no_reading_stays_quiet(supply: PoeSupply | None) -> None:
    assert not run(lab(supply))


def test_a_comfortable_draw_is_fine() -> None:
    assert not run(lab(PoeSupply(budget_w=65, used_w=30)))


def test_a_port_above_its_class_is_a_warning() -> None:
    net = lab(None, p3=PortPoe(power_class=2, power_w=11.0, status=PoeStatus.DELIVERING))
    (f,) = run(net)
    assert f.severity is Severity.WARNING and f.objects == ["sw/port/p3"]
    assert f.message_id == "poe.classExceeded"
    assert f.params == {
        "device": "Switch",
        "port": "p3",
        "power": "11",
        "class": 2,
        "limit": "7",
    }


def test_a_port_within_its_class_or_without_one_is_fine() -> None:
    assert not run(lab(None, p1=PortPoe(power_class=4, power_w=25.0)))
    assert not run(lab(None, p1=PortPoe(power_w=80.0)))
    assert not run(lab(None, p1=PortPoe(power_class=0, power_w=15.4 * 1.04)))


def test_poe_on_without_a_device_is_info() -> None:
    net = lab(
        None,
        p1=PortPoe(enabled=True, status=PoeStatus.SEARCHING),
        p2=PortPoe(enabled=True, status=PoeStatus.SEARCHING),
        p3=PortPoe(enabled=True, status=PoeStatus.DELIVERING, power_w=5.0),
        p4=PortPoe(enabled=False, status=PoeStatus.DISABLED),
    )
    (f,) = run(net)
    assert f.severity is Severity.INFO and f.objects == ["sw"]
    assert f.message == "Switch: PoE is on but no powered device is detected on p1, p2."
    assert f.message_id == "poe.idle"


def test_unknown_state_is_not_flagged_as_idle() -> None:
    assert not run(lab(None, p1=PortPoe(enabled=True), p2=PortPoe(enabled=False)))


# --- SNMP (POWER-ETHERNET-MIB) ----------------------------------------------------------


def _peth() -> str:
    port_t, main = "1.3.6.1.2.1.105.1.1.1", "1.3.6.1.2.1.105.1.3.1.1"
    rows = [
        f"{main}.2.1|66|65",
        f"{main}.4.1|66|18",
        f"{port_t}.3.1.1|2|1",
        f"{port_t}.6.1.1|2|3",
        f"{port_t}.7.1.1|2|2",
        f"{port_t}.10.1.1|2|5",
        f"{port_t}.3.1.2|2|1",
        f"{port_t}.6.1.2|2|2",
        f"{port_t}.3.1.3|2|2",
        f"{port_t}.6.1.3|2|1",
        f"{port_t}.6.2.1|2|3",  # a second group: not mapped
    ]
    return typical_switch() + "\n".join(rows) + "\n"


async def test_snmp_reads_budget_and_ports() -> None:
    a = adapter_for(SnmprecTransport(_peth()))
    snap = await a.observe()
    await a.close()
    assert snap.device.poe == PoeSupply(budget_w=65, used_w=18)
    ports = {p.name: p.poe for p in snap.ports if p.poe}
    assert ports["Gi1"] == PortPoe(
        enabled=True,
        status=PoeStatus.DELIVERING,
        power_class=4,
        priority=PoePriority.HIGH,
    )
    assert ports["Gi2"] == PortPoe(enabled=True, status=PoeStatus.SEARCHING)
    assert ports["Gi3"] == PortPoe(enabled=False, status=PoeStatus.DISABLED)
    assert len(ports) == 3


async def test_snmp_without_the_mib_has_no_poe() -> None:
    a = adapter_for(SnmprecTransport(typical_switch()))
    snap = await a.observe()
    await a.close()
    assert snap.device.poe is None and not any(p.poe for p in snap.ports)


# --- MikroTik ---------------------------------------------------------------------------

MK = MikrotikSimulator()


@pytest.fixture(scope="module")
def mk_url() -> Iterator[str]:
    with serve(MK.app()) as u:
        yield u


async def mikrotik(url: str) -> Any:
    config = MikrotikConfig(url=url, password=SecretStr(PASSWORD), allow_insecure_http=True)
    a = MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id="rt",
            device_name="Router",
            role=DeviceRole.GATEWAY,
            config=config,
            timeout=5.0,
        )
    )
    try:
        return await assert_contract(a)
    finally:
        await a.close()


async def test_mikrotik_reads_poe_out(mk_url: str) -> None:
    MK.__dict__.update(MikrotikSimulator().__dict__)
    snap = await mikrotik(mk_url)
    ports = {p.name: p.poe for p in snap.ports if p.poe}
    assert ports["ether4"] == PortPoe(
        enabled=True,
        status=PoeStatus.DELIVERING,
        power_w=5.8,
        voltage_v=48.1,
        current_ma=120,
    )
    assert ports["ether5"] == PortPoe(enabled=False, status=PoeStatus.DISABLED)
    assert not [e for e in snap.errors if e.message_id == "mikrotik.poeMonitor"]


async def test_mikrotik_without_the_monitor_keeps_the_settings(mk_url: str) -> None:
    MK.__dict__.update(MikrotikSimulator().__dict__)
    MK.read_only_monitor = True
    snap = await mikrotik(mk_url)
    ports = {p.name: p.poe for p in snap.ports if p.poe}
    assert ports["ether4"] == PortPoe(enabled=True)
    assert any(g.message_id == "mikrotik.poeMonitor" for g in snap.errors)


# --- OpenWrt (realtek-poe) --------------------------------------------------------------


def test_openwrt_poe_info_is_read() -> None:
    info = {
        "budget": 65,
        "consumption": 12.5,
        "ports": {
            "lan1": {"mode": "PoE+", "status": "Delivering power", "consumption": 7500},
            "lan2": {"mode": "PoE", "status": "Searching", "consumption": 0},
            "lan3": {"status": "Disabled"},
            "lan4": {"status": "Fault: overcurrent", "consumption": 3.2},
            "lan5": "garbage",
        },
    }
    supply, ports = openwrt_poe.read(info)
    assert supply == PoeSupply(budget_w=65, used_w=12.5)
    assert ports["lan1"] == PortPoe(
        enabled=True, status=PoeStatus.DELIVERING, mode=PoeMode.AT, power_w=7.5
    )
    assert ports["lan2"].status is PoeStatus.SEARCHING and ports["lan2"].mode is PoeMode.AF
    assert ports["lan3"].enabled is False
    assert ports["lan4"].status is PoeStatus.FAULT and ports["lan4"].power_w == 3.2
    assert "lan5" not in ports
    assert openwrt_poe.read("nothing") == (None, {})


async def test_openwrt_reads_the_ubus_object_when_present() -> None:
    sim = OpenWrtSim()
    sim.poe_info = {
        "budget": 60,
        "consumption": 9,
        "ports": {"lan1": {"mode": "PoE", "status": "Delivering power", "consumption": 9000}},
    }
    with serve(create_app(sim)) as url:
        cfg = OpenWrtConfig(
            url=f"{url}/ubus", password=SecretStr(sim.password), allow_insecure_http=True
        )
        a = OpenWrtAdapter(
            AdapterContext(
                site_id="home",
                device_id="sw1",
                device_name="Switch",
                role=DeviceRole.SWITCH,
                config=cfg,
            )
        )
        try:
            obs = await a.read_interfaces()
        finally:
            await a.close()
    assert obs.poe == {"sw1": PoeSupply(budget_w=60, used_w=9)}
    lan1 = next(p for p in obs.ports if p.name == "lan1")
    assert lan1.poe is not None and lan1.poe.power_w == 9.0
