"""Automatic setup of MikroTik through the REST API as admin (#231), against the simulator."""

from __future__ import annotations

import re
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
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.adapters.mikrotik.provision import READ_POLICY, WRITE_POLICY, granted
from signalbox.model import DeviceRole, DeviceStatus
from signalbox.sim.mikrotik import MikrotikSimulator
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve

ROOT = Path(__file__).parent.parent
SIM = MikrotikSimulator()
ADMIN = "admin-password"


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> TlsFiles:
    return self_signed_certificate(tmp_path_factory.mktemp("tls"))


@pytest.fixture(scope="module")
def url(tls: TlsFiles) -> Iterator[str]:
    with serve(SIM.app(), tls=tls) as served:
        yield served


@pytest.fixture(autouse=True)
def sim() -> MikrotikSimulator:
    SIM.__dict__.update(MikrotikSimulator(username="admin", password=ADMIN).__dict__)
    return SIM


def request(url: str, trust: str | None, **kw: Any) -> SetupRequest:
    return SetupRequest(
        config=kw.pop("config", {"url": url, "username": "signalbox"}),
        admin_user=kw.pop("user", "admin"),
        admin_secret=SecretStr(kw.pop("secret", ADMIN)),
        trust=trust,
        timeout=5,
        **kw,
    )


def test_policies_are_the_documented_ones() -> None:
    docs = (ROOT / "docs/adapters/mikrotik.md").read_text()
    found = re.findall(r"policy=(\S+)", docs.replace("\\\n    ", ""))
    assert READ_POLICY in found and WRITE_POLICY in found
    vm = (ROOT / "tools/integration/mikrotik/vm.py").read_text()
    assert READ_POLICY[:40] in vm
    assert granted(READ_POLICY) == {"read", "api", "rest-api"}


async def test_untrusted(url: str, tls: TlsFiles, sim: MikrotikSimulator) -> None:
    plan = await MikrotikAdapter.plan_setup(request(url, None))
    assert not plan.trusted and plan.fingerprint == tls.fingerprint and sim.requests == []
    with pytest.raises(UntrustedCertificate):
        await MikrotikAdapter.apply_setup(request(url, None))


async def test_setup_change_remove(url: str, tls: TlsFiles, sim: MikrotikSimulator) -> None:
    plan = await MikrotikAdapter.plan_setup(request(url, tls.fingerprint))
    assert [s.state for s in plan.steps] == [StepState.TODO, StepState.TODO]
    assert "password=***" in plan.steps[1].detail
    result = await MikrotikAdapter.apply_setup(request(url, tls.fingerprint))
    assert result.ok, result.steps
    password = result.secrets["password"].get_secret_value()
    assert result.settings == {"url": url, "username": "signalbox"}
    users = {u["name"]: u for u in sim.data["/rest/user"]}
    assert users["signalbox"]["group"] == "signalbox-read" and "password" not in users["signalbox"]
    group = next(g for g in sim.data["/rest/user/group"] if g["name"] == "signalbox-read")
    assert group["policy"] == READ_POLICY
    assert all(password not in s.detail + s.message for s in result.steps)
    adapter = MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id="r",
            device_name="r",
            role=DeviceRole.GATEWAY,
            config=MikrotikConfig(url=url, password=SecretStr(password)),
            pinned_fingerprint=result.certificate,
        )
    )
    try:
        assert (await adapter.observe()).status in (DeviceStatus.OK, DeviceStatus.PARTIAL)
    finally:
        await adapter.close()

    # a policy changed by hand is put back; the user moves to the write group
    group["policy"] = "read,api"
    again = await MikrotikAdapter.apply_setup(request(url, tls.fingerprint))
    assert again.ok and again.steps[0].state is StepState.DONE
    assert group["policy"] == READ_POLICY
    same = await MikrotikAdapter.plan_setup(request(url, tls.fingerprint))
    assert same.steps[0].state is StepState.UNCHANGED and "Update the user" in same.steps[1].title
    write = await MikrotikAdapter.apply_setup(request(url, tls.fingerprint, allow_writes=True))
    assert write.ok and users["signalbox"]["group"] == "signalbox-write"

    gone = await MikrotikAdapter.apply_setup(request(url, tls.fingerprint, remove=True))
    assert gone.ok and [s.state for s in gone.steps] == [StepState.DONE] * 3
    assert {u["name"] for u in sim.data["/rest/user"]} == {"admin"}
    assert {g["name"] for g in sim.data["/rest/user/group"]} == {"read", "full"}
    assert "signalbox" not in sim.logins
    twice = await MikrotikAdapter.plan_setup(request(url, tls.fingerprint, remove=True))
    assert [s.state for s in twice.steps] == [StepState.UNCHANGED] * 3


async def test_remove_keeps_groups_in_use(url: str, tls: TlsFiles, sim: MikrotikSimulator) -> None:
    await MikrotikAdapter.apply_setup(request(url, tls.fingerprint))
    sim.data["/rest/user"].append({".id": "*99", "name": "other", "group": "signalbox-read"})
    gone = await MikrotikAdapter.apply_setup(request(url, tls.fingerprint, remove=True))
    group = next(s for s in gone.steps if s.id == "group-signalbox-read")
    assert group.state is StepState.UNCHANGED and "other" in group.message


async def test_refusals(url: str, tls: TlsFiles, sim: MikrotikSimulator) -> None:
    with pytest.raises(AuthFailed) as refused:
        await MikrotikAdapter.plan_setup(request(url, tls.fingerprint, secret="wrong-secret"))
    assert "wrong-secret" not in str(refused.value)
    for config, text in (
        ({}, "address"),
        ({"url": "ftp://x"}, "address"),
        ({"url": "http://192.0.2.1"}, "only over https"),
        ({"url": url, "username": "admin"}, "must not be the admin"),
        ({"url": url, "username": "a b"}, "not a RouterOS user name"),
    ):
        with pytest.raises(AdapterError, match=text):
            await MikrotikAdapter.plan_setup(request(url, tls.fingerprint, config=config))
    sim.fail_write["/rest/user"] = 500
    failed = await MikrotikAdapter.apply_setup(request(url, tls.fingerprint))
    assert not failed.ok and failed.steps[1].state is StepState.FAILED
    sim.fail["/rest/user"] = 500
    with pytest.raises(AdapterError):
        await MikrotikAdapter.plan_setup(request(url, tls.fingerprint))
    sim.fail.clear()
    sim.data["/rest/user"] = {"not": "a list"}
    with pytest.raises(AdapterError, match="unexpected answer"):
        await MikrotikAdapter.plan_setup(request(url, tls.fingerprint))


async def test_setup_waits_until_the_new_login_works(
    url: str, tls: TlsFiles, sim: MikrotikSimulator, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RouterOS answers 401 for a moment after the user is created (#520): setup waits for it,
    so the first call with the new login (a trace, say) succeeds."""
    monkeypatch.setattr("signalbox.adapters.mikrotik.provision.LOGIN_POLL", 0.0)
    sim.login_lag = 3
    result = await MikrotikAdapter.apply_setup(request(url, tls.fingerprint, traces=True))
    assert result.ok, result.steps
    assert sim.refusals["signalbox"] == 0
    adapter = MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id="r",
            device_name="r",
            role=DeviceRole.GATEWAY,
            config=MikrotikConfig(url=url, password=result.secrets["password"]),
            pinned_fingerprint=result.certificate,
        )
    )
    try:
        assert (await adapter.observe()).status in (DeviceStatus.OK, DeviceStatus.PARTIAL)
    finally:
        await adapter.close()


async def test_setup_fails_when_the_new_login_stays_refused(
    url: str, tls: TlsFiles, sim: MikrotikSimulator, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("signalbox.adapters.mikrotik.provision.LOGIN_POLL", 0.0)
    monkeypatch.setattr("signalbox.adapters.mikrotik.provision.LOGIN_WAIT", 0.05)
    sim.login_lag = 10**6
    result = await MikrotikAdapter.apply_setup(request(url, tls.fingerprint))
    assert not result.ok
    assert result.steps[1].state is StepState.FAILED and "still refuses" in result.steps[1].message
