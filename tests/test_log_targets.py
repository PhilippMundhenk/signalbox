"""Log and monitoring targets (#180, ADR 0018): model, observe(), contract checks."""

import pytest
from pydantic import ValidationError

from factories import SITE, device, snapshot
from signalbox.adapters import Observation
from signalbox.merge import merge
from signalbox.model import Device, DeviceRole, LogKind, LogTarget, LogTransport
from signalbox.testing import assert_contract, log_target_problems, problems
from test_adapters import Fake, ctx


def test_target_address_endpoint_and_kinds() -> None:
    t = LogTarget(kind=LogKind.SYSLOG, address=" [2001:db8::5] ")
    assert t.address == "2001:db8::5" and str(t.ip()) == "2001:db8::5"
    assert t.endpoint() == "[2001:db8::5]:514"  # the usual port of the kind
    named = LogTarget(kind=LogKind.OTHER, address="logs.home.example")
    assert named.ip() is None and named.endpoint() == "logs.home.example"
    assert LogTarget(kind=LogKind.IPFIX, address="192.0.2.5", port=9995).endpoint() == (
        "192.0.2.5:9995"
    )
    with pytest.raises(ValidationError):
        LogTarget(kind=LogKind.SYSLOG, address="  ")
    with pytest.raises(ValidationError):
        LogTarget(kind=LogKind.SYSLOG, address="192.0.2.5", port=0)


def test_sends_to_and_not_read() -> None:
    on = LogTarget(kind=LogKind.SYSLOG, address="192.0.2.5")
    off = LogTarget(kind=LogKind.SYSLOG, address="192.0.2.6", enabled=False)
    flow = LogTarget(kind=LogKind.NETFLOW, address="192.0.2.5")
    dev = device("gw", log_targets=[on, off, flow])
    assert dev.sends_to(LogKind.SYSLOG) == [on] and dev.sends_to(LogKind.NETFLOW) == [flow]
    assert device("gw").log_targets is None and device("gw").sends_to(LogKind.SYSLOG) == []


class Logging(Fake):
    managed = False

    async def read_interfaces(self) -> Observation:
        base = await super().read_interfaces()
        d = self.context.device_id
        values = {d: [LogTarget(kind=LogKind.SYSLOG, address="192.0.2.5")]}
        devices = []
        if self.managed:
            sw = Device(id=f"{d}/sw1", site_id="x", name="Sw", role=DeviceRole.SWITCH, adapter="x")
            devices = [sw]
            values[sw.id] = []
        return base.model_copy(update={"log_targets": values, "devices": devices})


async def test_observe_puts_targets_on_the_devices() -> None:
    a = Logging(ctx())
    a.managed = True
    snap = await assert_contract(a)
    assert [t.address for t in snap.device.log_targets or []] == ["192.0.2.5"]
    (sw,) = snap.extra_devices
    assert sw.log_targets == []
    net = merge([SITE], [snap])
    assert net.device(snap.device.id) == snap.device


async def test_targets_without_a_target_read_stay_unread() -> None:
    snap = await assert_contract(Fake(ctx()))
    assert snap.device.log_targets is None


def test_contract_problems() -> None:
    t = LogTarget(kind=LogKind.NETFLOW, address="192.0.2.5", transport=LogTransport.TLS)
    bad = LogTarget(kind=LogKind.SYSLOG, address="192.0.2.5 514")
    assert log_target_problems("gw", [t, t, bad]) == [
        "gw: log target 192.0.2.5:2055: TLS on a netflow target",
        "gw: log target netflow 192.0.2.5:2055 listed twice",
        "gw: log target 192.0.2.5:2055: TLS on a netflow target",
        "gw: log target address '192.0.2.5 514' is not an address",
    ]
    assert log_target_problems("gw", [LogTarget(kind=LogKind.SYSLOG, address="192.0.2.5")]) == []


def test_contract_needs_the_interfaces_capability() -> None:
    a = Fake(ctx())
    dev = device("ap1", site_id="home", capabilities=[], log_targets=[])
    out = problems(a, snapshot(dev))
    assert "log targets reported without declaring interfaces" in out
