"""Writing 802.1Q port membership to ProSAFE Plus and Easy Smart switches (issue #44).

Against Switchyard's simulators; needs the extra ``signalbox-net[switches]`` (skipped without
it unless ``REQUIRE_SWITCH_TESTS`` is set, as in tests/test_plusswitch.py).
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

import pytest
from pydantic import SecretStr

import signalbox.adapters.plusswitch as plus
from factories import SITE
from signalbox.adapters import AdapterContext, AdapterError, AuthFailed, Backup
from signalbox.adapters.plusswitch import (
    EasySmartAdapter,
    EasySmartConfig,
    ProsafeAdapter,
    ProsafeConfig,
    writes,
)
from signalbox.changes import Change, ChangeKind, PortValue, RouterValue, observed_port, plan
from signalbox.deploy import Deployer, matches
from signalbox.desired import parse
from signalbox.history import ChangeStatus
from signalbox.merge import merge
from signalbox.model import DeviceRole, Network
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.store import DeviceRecord

try:
    from switchyard.easysmart.sim import SIM_MODULUS, EasySmartSimulator, SimEasySmart
    from switchyard.nsdp import tags as NT
    from switchyard.sim import BAD_VALUE, SimSwitch, Simulator
except ImportError:  # pragma: no cover - depends on the installation
    if os.environ.get("REQUIRE_SWITCH_TESTS"):
        raise
    pytest.skip("Switchyard is not installed", allow_module_level=True)

DEV = "sw1"
ENV = {
    "SIGNALBOX_AUTH_PASSWORD": "x" * 12,
    "SIGNALBOX_DEPLOY_ENABLED": "true",
    "SIGNALBOX_OBSERVE_TIMEOUT_SECONDS": "3",  # shorter Easy Smart discovery
}


class RefusingSwitch(SimSwitch):
    """A NETGEAR switch that refuses 802.1Q VLAN writes while ``refuse`` is set."""

    refuse = False

    def _set(self, tag: int, value: bytes) -> int:
        if self.refuse and tag == NT.VLAN_DOT1Q:
            return BAD_VALUE
        return super()._set(tag, value)


class RefusingEasySmart(SimEasySmart):
    refuse = False

    def _set_one(self, tag: int, v: bytes) -> int:
        from switchyard.easysmart import tags as ET

        if self.refuse and tag == ET.DOT1Q_VLAN:
            return 7503
        return super()._set_one(tag, v)


def netgear(mode: str = "dot1q") -> Any:
    sw = RefusingSwitch("02:00:00:00:10:01", ip="192.0.2.10", name="office")
    if mode == "dot1q":
        sw.vlan_mode = 4
        sw.dot1q = {1: ([1, 2, 3, 4, 5, 6, 7], []), 10: ([1, 8], [1])}
        sw.pvid = {**sw.pvid, 8: 10}
    elif mode == "port":
        sw.vlan_mode = 1
    return sw


def tplink(mode: str = "dot1q") -> Any:
    sw = RefusingEasySmart("02:00:00:00:20:01", ip="192.0.2.11", name="garage", generation="B")
    if mode == "dot1q":
        sw.config["dot1q"] = True
        sw.config["vlans"] = {
            1: {"members": [1, 2, 3, 4, 5, 6, 7], "tagged": [], "name": "Default"},
            10: {"members": [1, 8], "tagged": [1], "name": "cameras"},
        }
        sw.config["pvid"] = {**sw.config["pvid"], 8: 10}
    elif mode == "port":
        sw.config["port_vlan"] = True
    return sw


@pytest.fixture(autouse=True)
def _forget_refused() -> None:
    plus._REFUSED.clear()


@pytest.fixture
async def started() -> AsyncIterator[Callable[..., Any]]:
    sims: list[Any] = []

    async def start(cls: type, switch: Any) -> int:
        sim = (Simulator if cls is ProsafeAdapter else EasySmartSimulator)([switch])
        port: int = await sim.start()
        sims.append(sim)
        return port

    yield start
    for sim in sims:
        sim.stop()


def context(cls: type, port: int, password: str | None = None) -> AdapterContext:
    if cls is ProsafeAdapter:
        config: Any = ProsafeConfig(address="127.0.0.1", password=SecretStr(password or "password"))
    else:
        config = EasySmartConfig(address="127.0.0.1", password=SecretStr(password or "admin"))
    extra: dict[str, Any] = {"client_port": 0, "device_port": port}
    if cls is EasySmartAdapter:
        extra["rsa_modulus"] = SIM_MODULUS
    return AdapterContext(
        site_id="home",
        device_id=DEV,
        device_name="Switch",
        role=DeviceRole.SWITCH,
        config=config,
        timeout=4.0,
        extra=extra,
    )


async def network(adapter: Any) -> Network:
    snap = await adapter.observe()
    assert snap.status.value == "ok", snap.errors
    return merge([SITE], [snap])


def port_change(net: Network, port: int, untagged: Any, tagged: list[int]) -> Change:
    pid = f"{DEV}/port/{port}"
    return Change(
        kind=ChangeKind.PORT,
        device_id=DEV,
        site_id="home",
        key=pid,
        old=observed_port(net, pid),
        new=PortValue(untagged=untagged, tagged=tagged),
    )


CLASSES = [ProsafeAdapter, EasySmartAdapter]


def table_of(switch: Any) -> tuple[dict[int, tuple[list[int], list[int]]], dict[int, int]]:
    if isinstance(switch, SimSwitch):
        return {k: (sorted(m), sorted(t)) for k, (m, t) in switch.dot1q.items()}, dict(switch.pvid)
    vlans = switch.config["vlans"]
    return (
        {k: (sorted(v["members"]), sorted(v["tagged"])) for k, v in vlans.items()},
        dict(switch.config["pvid"]),
    )


@pytest.mark.parametrize("cls", CLASSES)
async def test_port_change_applies_and_its_inverse_restores(
    cls: type, started: Callable[..., Any]
) -> None:
    switch = netgear() if cls is ProsafeAdapter else tplink()
    port = await started(cls, switch)
    a = cls(context(cls, port))
    before = await network(a)
    # port 3: untagged VLAN 20 (new), tagged 10; port 8 back to the native network (VLAN 10
    # keeps port 1 tagged and 3 tagged, so it stays)
    changes = [port_change(before, 3, 20, [10]), port_change(before, 8, "native", [])]
    calls = await a.plan_changes(changes, {})
    assert [c.payload for c in calls] == [
        {"port": 3, "untagged": 20, "tagged": [10]},
        {"port": 8, "untagged": 1, "tagged": []},
    ]
    assert "PVID 20" in calls[0].description
    result = await a.apply(changes, {}, 60)
    assert result.confirm_deadline is None and result.calls == calls
    after = await network(cls(context(cls, port)))
    assert all(matches(after, c, c.new, {}) for c in changes)
    vlans, pvid = table_of(switch)
    assert vlans[20] == ([3], []) and pvid[3] == 20 and pvid[8] == 1
    assert vlans[10] == ([1, 3], [1, 3])
    inverse = [c.inverse() for c in reversed(changes)]
    await cls(context(cls, port)).apply(inverse, {}, 60)
    again = await network(cls(context(cls, port)))
    assert all(matches(again, c, c.new, {}) for c in inverse)
    vlans, pvid = table_of(switch)
    assert 20 not in vlans  # left empty by the inverse: deleted
    assert pvid[8] == 10 and pvid[3] == 1
    await a.confirm()


@pytest.mark.parametrize("cls", CLASSES)
async def test_trunk_without_untagged_keeps_or_moves_the_pvid(
    cls: type, started: Callable[..., Any]
) -> None:
    switch = netgear() if cls is ProsafeAdapter else tplink()
    port = await started(cls, switch)
    before = await network(cls(context(cls, port)))
    changes = [port_change(before, 2, None, [10]), port_change(before, 1, None, [10])]
    await cls(context(cls, port)).apply(changes, {}, 60)
    after = await network(cls(context(cls, port)))
    assert all(matches(after, c, c.new, {}) for c in changes)
    _, pvid = table_of(switch)
    assert pvid[2] == 10 and pvid[1] == 10


@pytest.mark.parametrize("cls", CLASSES)
async def test_backup_and_restore_round_trip(cls: type, started: Callable[..., Any]) -> None:
    switch = netgear() if cls is ProsafeAdapter else tplink()
    port = await started(cls, switch)
    original = table_of(switch)
    backup = await cls(context(cls, port)).backup()
    assert backup.format == "switchyard-dot1q-json" and backup.device_id == DEV
    assert "password" not in backup.content
    before = await network(cls(context(cls, port)))
    await cls(context(cls, port)).apply([port_change(before, 5, 30, [10])], {}, 60)
    assert table_of(switch) != original
    await cls(context(cls, port)).restore(backup)
    assert table_of(switch) == original
    await cls(context(cls, port)).restore(backup)  # nothing to do
    assert table_of(switch) == original


@pytest.mark.parametrize("cls", CLASSES)
@pytest.mark.parametrize("mode", ["port", "off"])
async def test_only_in_8021q_mode(cls: type, mode: str, started: Callable[..., Any]) -> None:
    switch = netgear(mode) if cls is ProsafeAdapter else tplink(mode)
    port = await started(cls, switch)
    before = await network(cls(context(cls, port)))
    change = port_change(before, 3, 20, [])
    word = "port_basic" if mode == "port" else "disabled"
    with pytest.raises(AdapterError, match=f"in {word} mode.*only in 802.1Q mode"):
        await cls(context(cls, port)).apply([change], {}, 60)
    with pytest.raises(AdapterError, match=r"only in 802\.1Q mode"):
        await cls(context(cls, port)).backup()
    assert table_of(switch)[0].keys() == {1}  # untouched (no VLAN 20 anywhere)


@pytest.mark.parametrize("cls", CLASSES)
async def test_refused_write_is_an_adapter_error(cls: type, started: Callable[..., Any]) -> None:
    switch = netgear() if cls is ProsafeAdapter else tplink()
    port = await started(cls, switch)
    before = await network(cls(context(cls, port)))
    switch.refuse = True
    with pytest.raises(AdapterError) as info:
        await cls(context(cls, port)).apply([port_change(before, 3, 20, [])], {}, 60)
    assert "password" not in str(info.value).lower() and "admin" not in str(info.value)


@pytest.mark.parametrize("cls", CLASSES)
async def test_wrong_password_is_not_resent_for_writes(
    cls: type, started: Callable[..., Any]
) -> None:
    switch = netgear() if cls is ProsafeAdapter else tplink()
    port = await started(cls, switch)
    bad = context(cls, port, password="wrong")
    for _ in range(2):
        with pytest.raises(AuthFailed):
            await cls(bad).backup()
    if cls is ProsafeAdapter:
        assert switch.failed_logins == 1  # the second attempt never reached the switch
    with pytest.raises(AuthFailed, match="not sent again"):
        await cls(bad).apply([], {}, 60)


async def test_switchyard_checks_become_adapter_errors(started: Callable[..., Any]) -> None:
    switch = netgear()
    switch.max_vlans = 2
    port = await started(ProsafeAdapter, switch)
    before = await network(ProsafeAdapter(context(ProsafeAdapter, port)))
    with pytest.raises(AdapterError, match=r"VLAN table refused: .*at most 2 VLANs"):
        await ProsafeAdapter(context(ProsafeAdapter, port)).apply(
            [port_change(before, 3, 20, [])], {}, 60
        )


def _change(key: str, new: Any, kind: ChangeKind = ChangeKind.PORT, dev: str = DEV) -> Change:
    return Change(kind=kind, device_id=dev, site_id="home", key=key, old=new, new=new)


def test_checks_without_a_switch() -> None:
    ok = PortValue(untagged="native")
    with pytest.raises(AdapterError, match="only change ports"):
        writes.port_number(
            DEV, _change("k", RouterValue(address="192.0.2.1/24"), ChangeKind.ROUTER)
        )  # type: ignore[arg-type]
    with pytest.raises(AdapterError, match="not a change of this switch"):
        writes.port_number(DEV, _change("sw2/port/1", ok, dev="sw2"))
    for key in ("other/port/1", f"{DEV}/port/x", f"{DEV}/port/0"):
        with pytest.raises(AdapterError, match="is not a port"):
            writes.port_number(DEV, _change(key, ok))
    with pytest.raises(AdapterError, match="cannot be sent tagged"):
        writes.wanted(_change(f"{DEV}/port/1", PortValue(untagged=10, tagged=[1])))
    with pytest.raises(AdapterError, match="no VLAN at all"):
        writes.wanted(_change(f"{DEV}/port/1", PortValue()))
    with pytest.raises(AdapterError, match="outside 1-4093"):
        writes.wanted(_change(f"{DEV}/port/1", PortValue(untagged=4094)))
    with pytest.raises(AdapterError, match="both untagged and tagged"):
        writes.wanted(_change(f"{DEV}/port/1", PortValue(untagged=10, tagged=[10, 20])))
    assert writes.wanted(_change(f"{DEV}/port/1", PortValue(untagged=10, tagged=[30, 20]))) == (
        10,
        [20, 30],
    )
    removal = Change(
        kind=ChangeKind.PORT, device_id=DEV, site_id="home", key=f"{DEV}/port/1", old=ok
    )
    with pytest.raises(AdapterError, match="no VLAN at all"):
        writes.wanted(removal)
    table = writes.Table.read(
        {"mode": "dot1q_basic", "dot1q": [{"id": 1, "members": [1, 2]}, "junk"], "pvid": {}},
        "h",
    )
    with pytest.raises(AdapterError, match="has 2 ports, not port 3"):
        writes.apply(table, DEV, [_change(f"{DEV}/port/3", ok)], 2)
    with pytest.raises(AdapterError, match="no VLAN settings"):
        writes.Table.read(None, "h")
    assert writes.Table.read({"mode": "dot1q_basic", "pvid": "x"}, "h").pvid == {}
    for bad in ("nonsense", '{"vlans": [], "pvid": {}}', '{"vlans": [{"id": 1}], "pvid": {}}'):
        with pytest.raises(AdapterError, match="not a switch VLAN table"):
            writes.Table.from_json(bad)


async def test_restore_refuses_other_formats() -> None:
    a = ProsafeAdapter(context(ProsafeAdapter, 9))
    with pytest.raises(AdapterError, match="format 'other'"):
        await a.restore(
            Backup(device_id=DEV, taken_at=datetime.now(UTC), format="other", content="{}")
        )


# --- a whole deployment ------------------------------------------------------------------

WANT = """
sites:
  home:
    ports:
      - {device: sw1, port: "3", untagged: 20, tagged: [10]}
      - {device: sw1, port: "8", untagged: native}
"""


def on_port(cls: type, port: int) -> type:
    """The adapter class reaching the simulator's port (the Deployer passes no extra)."""

    class OnPort(cls):  # type: ignore[valid-type,misc]
        ports: ClassVar[dict[str, int]] = {"client_port": 0, "device_port": port}

        def _option(self, name: str, default: int) -> int:
            if name == "rsa_modulus":
                return int(SIM_MODULUS)
            return self.ports.get(name, default)

    return OnPort


@pytest.fixture
def services(tmp_path: Path) -> Iterator[Callable[[type, int], Services]]:
    made: list[Services] = []

    def make(cls: type, port: int) -> Services:
        aid = cls.manifest.id
        s = build(tmp_path, env=ENV, adapters={aid: on_port(cls, port)}, rules=RULES)
        s.store.put_site(SITE)
        rec = DeviceRecord(
            id=DEV, site_id="home", name="Switch", role=DeviceRole.SWITCH, adapter=aid
        )
        cfg = {"address": "127.0.0.1", "password": "password" if aid == "prosafe" else "admin"}
        s.store.put_device(rec.model_copy(update={"allow_writes": True}), cfg, cls.manifest.config)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


@pytest.mark.parametrize("cls", CLASSES)
async def test_deployment_from_desired_state_and_revert(
    cls: type, started: Callable[..., Any], services: Callable[[type, int], Services]
) -> None:
    switch = netgear() if cls is ProsafeAdapter else tplink()
    port = await started(cls, switch)
    original = table_of(switch)
    svc = services(cls, port)
    await svc.runner.observe_all()
    p = plan(parse(WANT), svc.runner.network(), RULES)
    assert len(p.changes) == 2
    d = Deployer(svc.runner)
    rec = await d.prepare(p, "camera port on VLAN 20", "tester")
    d.approve(rec.id, "tester")
    done = await d.deploy(rec.id)
    assert done.status is ChangeStatus.APPLIED, svc.store.events(rec.id)
    assert all(r.backup_id for r in done.devices)
    assert plan(parse(WANT), svc.runner.network(), RULES).changes == []
    back = await d.revert(rec.id, "undo", "tester")
    d.approve(back.id, "tester")
    assert (await d.deploy(back.id)).status is ChangeStatus.APPLIED
    assert table_of(switch) == original
