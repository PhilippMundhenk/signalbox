import asyncio
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import SecretStr

from factories import SITE, iface, port
from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterError,
    Capability,
    Manifest,
    Observation,
    SystemInfo,
    UntrustedCertificate,
)
from signalbox.config import Config, ObserveConfig
from signalbox.model import (
    AccountPrivilege,
    DeviceAccount,
    DeviceRole,
    DeviceStatus,
    Link,
    LinkOrigin,
    Network,
    Subnet,
    segment_id,
)
from signalbox.rules import Finding, Result, Severity, found, rule
from signalbox.runner import Runner
from signalbox.secrets import load_vault
from signalbox.store import DeviceRecord, Store


class Cfg(AdapterConfig):
    url: str
    password: SecretStr


class Dev(Adapter):
    manifest = Manifest(
        id="dev",
        name="Dev",
        version="1",
        api_version="1.0",
        vendor="Example",
        roles=frozenset({DeviceRole.GATEWAY}),
        capabilities=frozenset({Capability.INTERFACES}),
        config=Cfg,
    )
    closed = 0
    seen: list[str] = []

    async def read_system(self) -> SystemInfo:
        cfg = self.context.config
        assert isinstance(cfg, Cfg)
        Dev.seen.append(cfg.password.get_secret_value())
        if cfg.url == "untrusted" and self.context.pinned_fingerprint != "fp1":
            raise UntrustedCertificate("fp1", self.context.pinned_fingerprint)
        if cfg.url == "untrusted64" and self.context.pinned_fingerprint != "a" * 64:
            raise UntrustedCertificate("a" * 64, self.context.pinned_fingerprint)
        if cfg.url == "crash":
            raise RuntimeError("adapter bug")
        return SystemInfo(vendor="Example")

    async def read_interfaces(self) -> Observation:
        d = self.context.device_id
        cfg = self.context.config
        if isinstance(cfg, Cfg) and cfg.url == "partial":
            raise AdapterError("not allowed to read ports", fix="Give the user port rights.")
        seg = segment_id(self.context.site_id, None)
        return Observation(
            ports=[port(d, "lan")],
            subnets=[
                Subnet(
                    id=f"{d}/subnet/lan",
                    segment_id=seg,
                    interface=iface("192.0.2.1/24"),
                    device_id=d,
                    gateway=True,
                )
            ],
        )

    async def close(self) -> None:
        Dev.closed += 1


@rule("test.per-device", "Per device", Severity.WARNING, "x")
def per_device(net: Network) -> Iterator[Result]:
    for d in net.devices:
        yield found(f"{d.id}", [d.id])


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    s = Store(tmp_path / "db.sqlite", load_vault(tmp_path, env={}))
    s.put_site(SITE)
    yield s
    s.close()


def add(store: Store, device_id: str, url: str = "ok", adapter: str = "dev", **kw: object) -> None:
    rec = DeviceRecord(
        id=device_id,
        site_id="home",
        name=device_id.upper(),
        role=DeviceRole.GATEWAY,
        adapter=adapter,
        **kw,  # type: ignore[arg-type]
    )
    store.put_device(rec, {"url": url, "password": f"pw-{device_id}"}, Cfg)


def runner(store: Store, **kw: object) -> Runner:
    cfg = Config(observe=ObserveConfig(interval_seconds=10, concurrency=2))
    return Runner(store=store, adapters={"dev": Dev}, rules=[per_device], config=cfg, **kw)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _reset() -> None:
    Dev.closed = 0
    Dev.seen = []


async def test_observe_all_stores_snapshots_and_findings(store: Store) -> None:
    add(store, "gw")
    add(store, "off", enabled=False)
    events: list[int] = []
    r = runner(store, listeners=[lambda net, f: events.append(len(f))])
    net, findings = await r.observe_all()
    assert [d.id for d in net.devices] == ["gw"]
    assert Dev.seen == ["pw-gw"] and Dev.closed == 1
    assert [f.message for f in findings] == ["gw"]
    assert [x.finding.message for x in store.findings()] == ["gw"]
    assert events == [1] and r.last_run is not None


async def test_problems_become_snapshots_not_crashes(store: Store) -> None:
    add(store, "crash", url="crash")
    add(store, "ghost", adapter="missing")
    r = runner(store)
    net, findings = await r.observe_all()
    assert net.statuses == {"crash": DeviceStatus.UNREACHABLE, "ghost": DeviceStatus.UNREACHABLE}
    messages = {e.device_id: e.message for e in net.errors}
    assert messages["crash"] == "adapter error: RuntimeError: adapter bug"
    assert messages["ghost"] == "adapter 'missing' is not installed"
    assert {f.rule_id for f in findings} == {"signalbox.read", "test.per-device"}


async def test_unusable_settings(store: Store) -> None:
    add(store, "gw")
    store._db.execute("UPDATE devices SET config = '{}'")
    rec = store.device("gw")
    assert rec is not None
    snap = await runner(store).observe_device(rec)
    assert snap.status is DeviceStatus.AUTH_FAILED
    assert snap.errors[0].message == "settings unusable: url: Field required"


async def test_changed_secret_key(store: Store, tmp_path: Path) -> None:
    add(store, "gw")
    other = Store(tmp_path / "db.sqlite", load_vault(tmp_path / "other-key", env={}))
    try:
        (rec,) = other.devices()  # listing still works, the secrets are just not readable
        assert rec.secrets_set == []
        snap = await runner(other).observe_device(rec)
    finally:
        other.close()
    assert snap.status is DeviceStatus.AUTH_FAILED
    assert "secret key changed" in snap.errors[0].message


async def test_untrusted_certificate_flow(store: Store) -> None:
    add(store, "gw", url="untrusted")
    r = runner(store)
    rec = store.device("gw")
    assert rec is not None
    snap = await r.observe_device(rec)
    assert snap.status is DeviceStatus.UNTRUSTED
    rec = store.device("gw")
    assert rec is not None and rec.pending_fingerprint == "fp1"
    store.trust_fingerprint("gw", "fp1")
    rec = store.device("gw")
    assert rec is not None
    assert (await r.observe_device(rec)).status is DeviceStatus.OK


def test_network_adds_derived_links_unless_manual(store: Store) -> None:
    manual = Link(id="m", a="a/port/1", b="b/port/1", origin=LinkOrigin.MANUAL)
    store.put_link(manual)
    same = Link(id="d1", a="b/port/1", b="a/port/1", origin=LinkOrigin.LLDP)
    new = Link(id="d2", a="b/port/2", b="c/port/1", origin=LinkOrigin.LLDP)
    r = runner(store, link_sources=[lambda net: [same, new, new]])
    assert [link.id for link in r.network().links] == ["d2", "m"]
    assert [link.id for link in runner(store).network().links] == ["m"]


async def test_failing_listener_is_logged(store: Store, caplog: pytest.LogCaptureFixture) -> None:
    def bad(net: Network, findings: list[Finding]) -> None:
        raise RuntimeError("listener bug")

    runner(store, listeners=[bad]).evaluate()
    assert "listener failed" in caplog.text


async def test_run_forever_trigger_and_stop(store: Store) -> None:
    add(store, "gw")
    r = runner(store)
    task = asyncio.create_task(r.run_forever())
    for _ in range(100):
        if Dev.closed >= 1:
            break
        await asyncio.sleep(0.01)
    r.trigger()
    for _ in range(100):
        if Dev.closed >= 2:
            break
        await asyncio.sleep(0.01)
    assert Dev.closed >= 2
    r.stop()
    await asyncio.wait_for(task, 2)


async def test_run_forever_survives_a_failed_round(
    store: Store, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    r = runner(store)
    calls = 0

    async def boom() -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            r.stop()
        raise RuntimeError("db gone")

    monkeypatch.setattr(r, "observe_all", boom)
    r.config.observe.interval_seconds = 10
    task = asyncio.create_task(r.run_forever())
    await asyncio.sleep(0.05)
    r.trigger()
    await asyncio.wait_for(task, 2)
    assert calls == 2 and "observation round failed" in caplog.text


async def test_interval_timeout_starts_next_round(store: Store) -> None:
    r = runner(store)
    rounds = 0

    async def count() -> None:
        nonlocal rounds
        rounds += 1
        if rounds == 2:
            r.stop()

    r.observe_all = count  # type: ignore[method-assign]
    object.__setattr__(r.config.observe, "interval_seconds", 0.01)
    await asyncio.wait_for(r.run_forever(), 2)
    assert rounds == 2


async def test_trigger_during_a_round_is_not_lost(store: Store) -> None:
    r = runner(store)  # interval 10 s: a lost trigger would make this test time out
    rounds = 0

    async def slow_round() -> None:
        nonlocal rounds
        rounds += 1
        if rounds == 1:
            r.trigger()  # arrives while the first round is still running
        else:
            r.stop()

    r.observe_all = slow_round  # type: ignore[method-assign]
    await asyncio.wait_for(r.run_forever(), 2)
    assert rounds == 2


# --- accounts (#175) -------------------------------------------------------------------------


class AccountDev(Dev):
    manifest = Dev.manifest.model_copy(update={"least_privilege": AccountPrivilege.READ})

    async def read_interfaces(self) -> Observation:
        base = await super().read_interfaces()
        d = self.context.device_id
        own = DeviceAccount(name="alice", privilege=AccountPrivilege.ADMIN, is_signalbox=True)
        return base.model_copy(
            update={
                "accounts": {d: [own]},
                "signalbox_privilege": {d: AccountPrivilege.ADMIN},
            }
        )


async def test_listeners_get_no_account_names_and_writes_need_a_write_login(
    store: Store,
) -> None:
    add(store, "gw", adapter="acc")
    add(store, "rw", adapter="acc", allow_writes=True)
    seen: list[Network] = []
    cfg = Config(observe=ObserveConfig(interval_seconds=10, concurrency=2))
    r = Runner(
        store=store,
        adapters={"acc": AccountDev},
        rules=[per_device],
        config=cfg,
        listeners=[lambda net, f: seen.append(net)],
    )
    net, _ = await r.observe_all()
    assert [a.name for a in net.device("gw").accounts or []] == ["alice"]  # type: ignore[union-attr]
    assert net.device("gw").signalbox_account_needed is AccountPrivilege.READ  # type: ignore[union-attr]
    assert net.device("rw").signalbox_account_needed is AccountPrivilege.WRITE  # type: ignore[union-attr]
    (shared,) = seen
    assert all(d.accounts is None for d in shared.devices)
    assert "alice" not in shared.model_dump_json()
