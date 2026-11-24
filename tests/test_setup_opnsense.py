"""Automatic setup of OPNsense through its API with root's key (#231), against the simulator."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import (
    AdapterContext,
    AdapterError,
    AuthFailed,
    SetupRequest,
    StepState,
    UntrustedCertificate,
)
from signalbox.adapters.opnsense import OpnsenseAdapter, OpnsenseConfig
from signalbox.adapters.opnsense.provision import READ_PRIVILEGES, WRITE_PRIVILEGES, _saved
from signalbox.model import DeviceRole, DeviceStatus
from signalbox.sim.opnsense import KEY, SECRET, OpnsenseSimulator
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve

ROOT = Path(__file__).parent.parent
SIM = OpnsenseSimulator()


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> TlsFiles:
    return self_signed_certificate(tmp_path_factory.mktemp("tls"))


@pytest.fixture(scope="module")
def url(tls: TlsFiles) -> Iterator[str]:
    with serve(SIM.app(), tls=tls) as served:
        yield served


@pytest.fixture(autouse=True)
def sim() -> OpnsenseSimulator:
    SIM.__dict__.update(OpnsenseSimulator().__dict__)
    return SIM


def request(url: str, trust: str | None, **kw: Any) -> SetupRequest:
    return SetupRequest(
        config=kw.pop("config", {"url": url}),
        admin_user=kw.pop("user", KEY),
        admin_secret=SecretStr(kw.pop("secret", SECRET)),
        trust=trust,
        timeout=5,
        **kw,
    )


def test_privileges_are_those_of_the_integration_test_image() -> None:
    tested = json.loads((ROOT / "tools/integration/opnsense/privileges.json").read_text())
    assert list(READ_PRIVILEGES) == tested["signalbox-read"]
    assert list(WRITE_PRIVILEGES) == tested["signalbox-write"]


async def test_accounts_extra_adds_the_user_manager_privilege(
    url: str, tls: TlsFiles, sim: OpnsenseSimulator
) -> None:
    """Optional extra (#349): without it the read user has no user manager privilege; with it
    the new key lists the accounts, and ticking it off again takes the privilege away."""
    offered = OpnsenseAdapter.manifest.admin_login
    assert offered is not None and [e.id for e in offered.extras] == ["accounts"]
    plain = await OpnsenseAdapter.plan_setup(request(url, tls.fingerprint))
    assert "page-system-usermanager" not in plain.steps[1].detail
    with_extra = request(url, tls.fingerprint, extras=["accounts"])
    plan = await OpnsenseAdapter.plan_setup(with_extra)
    assert plan.steps[1].detail.splitlines() == sorted(
        [*READ_PRIVILEGES, "page-system-usermanager"]
    )
    result = await OpnsenseAdapter.apply_setup(with_extra)
    assert result.ok, result.steps
    adapter = OpnsenseAdapter(
        AdapterContext(
            site_id="home",
            device_id="fw",
            device_name="fw",
            role=DeviceRole.GATEWAY,
            config=OpnsenseConfig(
                url=url,
                api_key=result.secrets["api_key"],
                api_secret=result.secrets["api_secret"],
            ),
            pinned_fingerprint=result.certificate,
        )
    )
    try:
        snap = await adapter.observe()
    finally:
        await adapter.close()
    assert snap.status is DeviceStatus.OK and not snap.errors
    assert {a.name for a in snap.device.accounts or []} >= {"root", "signalbox"}
    # setup again without the extra: back to the documented privileges
    await OpnsenseAdapter.apply_setup(request(url, tls.fingerprint))
    user = next(u for u in sim.accounts.users if u["name"] == "signalbox")
    assert sorted(user["priv"]) == sorted(READ_PRIVILEGES)


def test_saved_answers() -> None:
    assert _saved("/x", {"status": "ok"}) == {"status": "ok"}
    with pytest.raises(AdapterError, match=r"user\.name: taken"):
        _saved("/x", {"result": "failed", "validations": {"user.name": "taken"}})
    with pytest.raises(AdapterError, match="unexpected answer"):
        _saved("/x", [])


async def test_untrusted_certificate_sends_no_key(
    url: str, tls: TlsFiles, sim: OpnsenseSimulator
) -> None:
    plan = await OpnsenseAdapter.plan_setup(request(url, None))
    assert not plan.trusted and plan.fingerprint == tls.fingerprint
    assert plan.fingerprint_kind == "certificate" and sim.requests == []
    with pytest.raises(UntrustedCertificate):
        await OpnsenseAdapter.apply_setup(request(url, "ab" * 32))


async def test_setup_read_then_write_then_remove(
    url: str, tls: TlsFiles, sim: OpnsenseSimulator
) -> None:
    plan = await OpnsenseAdapter.plan_setup(request(url, tls.fingerprint))
    assert plan.trusted and [s.id for s in plan.steps] == ["user", "privileges", "key"]
    assert "Create the user signalbox (read-only)" in plan.steps[0].title
    assert plan.steps[1].detail.splitlines() == sorted(READ_PRIVILEGES)
    assert [u["name"] for u in sim.accounts.users] == ["root"]

    result = await OpnsenseAdapter.apply_setup(request(url, tls.fingerprint))
    assert result.ok, result.steps
    assert result.settings == {"url": url} and result.certificate == tls.fingerprint
    key = result.secrets["api_key"].get_secret_value()
    secret = result.secrets["api_secret"].get_secret_value()
    user = next(u for u in sim.accounts.users if u["name"] == "signalbox")
    assert sorted(user["priv"]) == sorted(READ_PRIVILEGES) and user["groups"] == []
    for step in result.steps:
        for text in (step.detail, step.message, step.title):
            assert key not in text and secret not in text and SECRET not in text

    # the new key reads the firewall
    adapter = OpnsenseAdapter(
        AdapterContext(
            site_id="home",
            device_id="fw",
            device_name="fw",
            role=DeviceRole.GATEWAY,
            config=OpnsenseConfig(url=url, api_key=SecretStr(key), api_secret=SecretStr(secret)),
            pinned_fingerprint=result.certificate,
        )
    )
    try:
        snap = await adapter.observe()
    finally:
        await adapter.close()
    assert snap.status is DeviceStatus.OK

    # again with writes: privileges updated, a new key replaces the old one
    user["groups"] = ["admins"]
    plan = await OpnsenseAdapter.plan_setup(request(url, tls.fingerprint, allow_writes=True))
    assert plan.steps[0].state is StepState.TODO and "admins" in plan.steps[0].detail
    again = await OpnsenseAdapter.apply_setup(request(url, tls.fingerprint, allow_writes=True))
    assert again.ok and "older keys deleted: 1" in again.steps[2].message
    assert sorted(user["priv"]) == sorted(WRITE_PRIVILEGES) and user["groups"] == []
    assert [k["key"] for k in sim.accounts.keys] == [again.secrets["api_key"].get_secret_value()]
    # nothing to change but the key
    same = await OpnsenseAdapter.plan_setup(request(url, tls.fingerprint, allow_writes=True))
    assert same.steps[0].state is StepState.UNCHANGED

    gone = await OpnsenseAdapter.apply_setup(request(url, tls.fingerprint, remove=True))
    assert gone.ok and not gone.secrets
    assert [u["name"] for u in sim.accounts.users] == ["root"] and sim.accounts.keys == []
    twice = await OpnsenseAdapter.plan_setup(request(url, tls.fingerprint, remove=True))
    assert twice.steps[0].state is StepState.UNCHANGED


async def test_refusals(url: str, tls: TlsFiles, sim: OpnsenseSimulator) -> None:
    with pytest.raises(AuthFailed) as refused:
        await OpnsenseAdapter.plan_setup(request(url, tls.fingerprint, secret="wrong-secret"))
    assert "wrong-secret" not in str(refused.value)
    for config, text in (({}, "address"), ({"url": "ftp://x"}, "address")):
        with pytest.raises(AdapterError, match=text):
            await OpnsenseAdapter.plan_setup(request(url, tls.fingerprint, config=config))
    with pytest.raises(AdapterError, match="only over https"):
        await OpnsenseAdapter.plan_setup(request(url, None, config={"url": "http://192.0.2.1"}))
    # a system user of that name is left alone
    sim.accounts.users[0]["name"] = "signalbox"
    with pytest.raises(AdapterError, match="system user"):
        await OpnsenseAdapter.plan_setup(request(url, tls.fingerprint))
    sim.accounts.users[0]["name"] = "root"
    # a key of a user without the user manager's privileges: 403
    await OpnsenseAdapter.apply_setup(request(url, tls.fingerprint))
    user_key = sim.accounts.keys[0]
    with pytest.raises(AuthFailed, match="403"):
        await OpnsenseAdapter.plan_setup(
            request(url, tls.fingerprint, user=user_key["key"], secret=user_key["secret"])
        )


async def test_failed_steps(url: str, tls: TlsFiles, sim: OpnsenseSimulator) -> None:
    sim.accounts.keyless = True
    result = await OpnsenseAdapter.apply_setup(request(url, tls.fingerprint))
    assert not result.ok and result.steps[2].state is StepState.FAILED
    assert "no key in the answer" in result.steps[2].message
    sim.accounts.keyless = False
    sim.invalid["/api/auth/user/set"] = {"user.descr": "too long"}
    bad = await OpnsenseAdapter.apply_setup(request(url, tls.fingerprint, allow_writes=True))
    assert not bad.ok and "user.descr: too long" in bad.steps[0].message
    assert bad.steps[2].state is StepState.SKIPPED
    sim.fail["/api/auth/user/get"] = 500
    with pytest.raises(AdapterError, match="HTTP 500"):
        await OpnsenseAdapter.apply_setup(request(url, tls.fingerprint))
    sim.fail.clear()
    real = sim.accounts.answer
    sim.accounts.answer = lambda path, body: {} if "/get/" in path else real(path, body)  # type: ignore[method-assign]
    with pytest.raises(AdapterError, match="unexpected answer"):
        await OpnsenseAdapter.plan_setup(request(url, tls.fingerprint))
    sim.accounts.answer = lambda path, body: None  # type: ignore[method-assign]
    with pytest.raises(AdapterError, match="404"):
        await OpnsenseAdapter.plan_setup(request(url, tls.fingerprint))
