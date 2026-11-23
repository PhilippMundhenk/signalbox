import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import SecretStr

import signalbox.adapters as api
from factories import iface, port
from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterContext,
    AdapterContractError,
    AuthFailed,
    Capability,
    Manifest,
    Observation,
    SystemInfo,
    Unreachable,
    UntrustedCertificate,
    load_adapters,
)
from signalbox.model import (
    Band,
    DeviceRole,
    DeviceStatus,
    Firmware,
    Membership,
    Neighbour,
    PortMembership,
    Radio,
    Security,
    Segment,
    Source,
    Subnet,
    Wlan,
    port_id,
    segment_id,
)
from signalbox.testing import assert_contract, problems


class FakeConfig(AdapterConfig):
    host: str
    password: SecretStr


class Fake(Adapter):
    manifest = Manifest(
        id="fake",
        name="Fake",
        version="1.0",
        api_version="1.0",
        vendor="Example",
        roles=frozenset({DeviceRole.AP}),
        capabilities=frozenset({Capability.INTERFACES, Capability.WIRELESS}),
        config=FakeConfig,
    )
    fail: dict[str, BaseException] = {}

    def _maybe_fail(self, what: str) -> None:
        exc = self.fail.get(what)
        if exc is not None:
            raise exc

    async def read_system(self) -> SystemInfo:
        self._maybe_fail("system")
        return SystemInfo(vendor="Example", model="X1", firmware=Firmware(current="1.0"))

    async def read_interfaces(self) -> Observation:
        self._maybe_fail("interfaces")
        d = self.context.device_id
        seg = segment_id(self.context.site_id, None)
        return Observation(
            ports=[port(d, "lan")],
            segments=[
                Segment(
                    id=seg,
                    site_id=self.context.site_id,
                    members=[PortMembership(port_id=port_id(d, "lan"), mode=Membership.UNTAGGED)],
                )
            ],
            subnets=[
                Subnet(
                    id=f"{d}/subnet/lan",
                    segment_id=seg,
                    interface=iface("192.0.2.2/24"),
                    device_id=d,
                )
            ],
            neighbours=[
                Neighbour(
                    id=f"{d}/neighbour/1",
                    local_port_id=port_id(d, "lan"),
                    chassis_id="02:00:00:00:00:99",
                )
            ],
        )

    async def read_wireless(self) -> Observation:
        self._maybe_fail("wireless")
        d = self.context.device_id
        return Observation(
            radios=[Radio(id=f"{d}/radio/0", device_id=d, name="radio0", band=Band.GHZ_5)],
            wlans=[
                Wlan(
                    id=f"{d}/wlan/0",
                    device_id=d,
                    ssid="Example",
                    radio_id=f"{d}/radio/0",
                    security=Security.WPA2,
                    segment_id=segment_id(self.context.site_id, None),
                )
            ],
        )


def ctx(**kw: Any) -> AdapterContext:
    return AdapterContext(
        site_id="home",
        device_id=kw.pop("device_id", "ap1"),
        device_name="AP 1",
        role=DeviceRole.AP,
        config=kw.pop("config", FakeConfig(host="192.0.2.2", password=SecretStr("x"))),
        **kw,
    )


async def test_observe_builds_a_valid_snapshot() -> None:
    snap = await assert_contract(Fake(ctx()))
    assert snap.status is DeviceStatus.OK
    assert snap.device.vendor == "Example" and snap.device.firmware == Firmware(current="1.0")
    assert snap.device.capabilities == ["interfaces", "wireless"]
    assert all(p.source == Source(adapter="fake", device_id="ap1") for p in snap.ports)
    assert all(p.observed_at == snap.observed_at for p in snap.ports)
    assert len(snap.wlans) == 1


async def test_failed_capability_is_partial_with_error() -> None:
    Fake.fail = {"wireless": api.AdapterError("ubus call refused")}
    snap = await Fake(ctx()).observe()
    assert snap.status is DeviceStatus.PARTIAL
    assert [(e.capability, e.message) for e in snap.errors] == [("wireless", "ubus call refused")]
    assert snap.ports and not snap.wlans


@pytest.mark.parametrize(
    ("exc", "status"),
    [
        (Unreachable("connection refused"), DeviceStatus.UNREACHABLE),
        (OSError("no route"), DeviceStatus.UNREACHABLE),
        (AuthFailed("wrong key"), DeviceStatus.AUTH_FAILED),
        (UntrustedCertificate("ab" * 32, None), DeviceStatus.UNTRUSTED),
    ],
)
async def test_system_failures_set_status(exc: BaseException, status: DeviceStatus) -> None:
    Fake.fail = {"system": exc}
    adapter = Fake(ctx())
    snap = await adapter.observe()
    assert snap.status is status
    assert snap.errors[0].capability == "system" and not snap.ports
    if status is DeviceStatus.UNTRUSTED:
        assert adapter.presented_fingerprint == "ab" * 32


def test_untrusted_certificate_message() -> None:
    assert "not yet trusted" in str(UntrustedCertificate("ab", None))
    exc = UntrustedCertificate("cd", "ab")
    assert "new certificate" in str(exc) and exc.pinned == "ab" and exc.fingerprint == "cd"


async def test_timeout_becomes_readable_error() -> None:
    class Slow(Fake):
        async def read_wireless(self) -> Observation:
            await asyncio.sleep(1)
            raise AssertionError("not reached")  # pragma: no cover

    snap = await Slow(ctx(timeout=0.01)).observe()
    assert snap.errors[0].message == "no answer within 0.01 s"


async def test_error_without_message_uses_type_name() -> None:
    Fake.fail = {"interfaces": Unreachable()}
    snap = await Fake(ctx()).observe()
    assert snap.errors[0].message == "Unreachable"


async def test_wrong_return_type_is_a_contract_error() -> None:
    class Bad(Fake):
        async def read_wireless(self) -> Observation:
            return []  # type: ignore[return-value]

    with pytest.raises(AdapterContractError, match="not Observation"):
        await Bad(ctx()).observe()


def test_declared_capability_must_be_implemented() -> None:
    class Liar(Adapter):
        manifest = Fake.manifest.model_copy(update={"capabilities": frozenset({Capability.DHCP})})

        async def read_system(self) -> SystemInfo:  # pragma: no cover
            return SystemInfo()

    with pytest.raises(AdapterContractError, match="ReadsDhcp"):
        Liar(ctx())


def test_config_type_is_checked() -> None:
    class Other(AdapterConfig):
        pass

    with pytest.raises(AdapterContractError, match="FakeConfig"):
        Fake(ctx(config=Other()))


async def test_close_is_optional() -> None:
    await Fake(ctx()).close()


def test_problems_lists_every_contract_break() -> None:
    adapter = Fake(ctx())
    good = asyncio.run(adapter.observe())
    d = "ap1"
    bad = good.model_copy(
        update={
            "status": DeviceStatus.PARTIAL,
            "ports": [*good.ports, port("other", "x", source=Source(adapter="x", device_id="o"))],
            "segments": [
                Segment(
                    id="elsewhere/segment/1",
                    site_id="home",
                    members=[
                        PortMembership(port_id=port_id(d, "ghost"), mode=Membership.UNTAGGED),
                        PortMembership(port_id=port_id(d, "ghost"), mode=Membership.UNTAGGED),
                    ],
                    source=Source(adapter="fake", device_id=d),
                )
            ],
            "wlans": [
                w.model_copy(update={"radio_id": "nope", "segment_id": "nope"}) for w in good.wlans
            ],
            "neighbours": [
                n.model_copy(update={"local_port_id": "nope", "id": "x/1"}) for n in good.neighbours
            ],
            "device": good.device.model_copy(update={"id": "zzz"}),
        }
    )
    found = "\n".join(problems(adapter, bad))
    for needle in [
        "device id/site zzz",
        "status partial",
        "ports id other/port/x",
        "ports other/port/x has device_id other",
        "has source",
        "segment id elsewhere/segment/1",
        "unknown port ap1/port/ghost",
        "lists a port twice",
        "references unknown segment home/segment/native",
        "unknown radio nope",
        "wlan ap1/wlan/0 references unknown segment nope",
        "neighbour x/1 on unknown port nope",
        "neighbours id x/1",
    ]:
        assert needle in found, needle


@pytest.mark.filterwarnings("ignore:Pydantic serializer warnings")
def test_problems_detects_lossy_json() -> None:
    adapter = Fake(ctx())
    snap = asyncio.run(adapter.observe())
    odd = snap.model_copy(update={"errors": [], "ports": snap.ports})
    object.__setattr__(odd, "ports", tuple(snap.ports))  # a tuple does not round-trip as itself
    assert "JSON round trip" in "\n".join(problems(adapter, odd))


async def test_assert_contract_fails_loudly() -> None:
    Fake.fail = {"wireless": api.AdapterError("boom")}
    with pytest.raises(AssertionError, match="read error wireless: boom"):
        await assert_contract(Fake(ctx()))


def _eps(monkeypatch: pytest.MonkeyPatch, *targets: object) -> None:
    eps = [SimpleNamespace(name=f"ep{i}", load=lambda t=t: t) for i, t in enumerate(targets)]
    monkeypatch.setattr(api, "entry_points", lambda group: eps)


def test_load_adapters(monkeypatch: pytest.MonkeyPatch) -> None:
    _eps(monkeypatch, Fake)
    assert load_adapters() == {"fake": Fake}


def test_load_adapters_rejects_non_adapters(monkeypatch: pytest.MonkeyPatch) -> None:
    _eps(monkeypatch, object)
    with pytest.raises(AdapterContractError, match="not an Adapter"):
        load_adapters()


def test_load_adapters_rejects_duplicates(monkeypatch: pytest.MonkeyPatch) -> None:
    _eps(monkeypatch, Fake, Fake)
    with pytest.raises(AdapterContractError, match="two adapters"):
        load_adapters()


def test_load_adapters_rejects_other_api_major(monkeypatch: pytest.MonkeyPatch) -> None:
    class Future(Fake):
        manifest = Fake.manifest.model_copy(update={"api_version": "2.0"})

    _eps(monkeypatch, Future)
    with pytest.raises(AdapterContractError, match=r"adapter API 2\.0"):
        load_adapters()


def test_manifest_id_pattern() -> None:
    with pytest.raises(ValueError):
        Fake.manifest.model_validate({**Fake.manifest.model_dump(), "id": "Bad Id"})


async def test_extra_devices_are_stamped_and_checked() -> None:
    from signalbox.model import Device

    class Controller(Fake):
        async def read_interfaces(self) -> Observation:
            base = await super().read_interfaces()
            d = self.context.device_id
            managed = Device(
                id=f"{d}/sw1", site_id="x", name="Switch 1", role=DeviceRole.SWITCH, adapter="x"
            )
            return base.model_copy(
                update={
                    "devices": [managed, managed],
                    "device_status": {
                        f"{d}/sw1": DeviceStatus.UNREACHABLE,
                        "other": DeviceStatus.OK,
                    },
                    "ports": [*base.ports, port(f"{d}/sw1", "1")],
                }
            )

    a = Controller(ctx())
    snap = await assert_contract(a)
    (sw,) = snap.extra_devices
    assert sw.managed_by == "ap1" and sw.site_id == "home" and sw.adapter == "fake"
    assert snap.extra_status == {"ap1/sw1": DeviceStatus.UNREACHABLE}
    bad = snap.model_copy(
        update={
            "extra_devices": [sw.model_copy(update={"id": "elsewhere", "managed_by": None})],
            "extra_status": {"ghost": DeviceStatus.OK},
            "ports": [*snap.ports, port("ap1/sw1", "9").model_copy(update={"id": "ap1/x"})],
        }
    )
    text = "\n".join(problems(a, bad))
    assert "extra device id elsewhere" in text
    assert "has managed_by None" in text
    assert "status for unknown device ghost" in text
    assert "ports ap1/port/1" in text or "has device_id ap1/sw1" in text
