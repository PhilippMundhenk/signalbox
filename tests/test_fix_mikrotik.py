"""Fix it on MikroTik (#267): group policies through REST, the REST service over SSH, and the
read errors that name the remedies; against the simulators."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import (
    AdapterContext,
    AdapterError,
    AuthFailed,
    RemedyRequest,
    SetupRequest,
    StepState,
    Unreachable,
    UntrustedCertificate,
    UntrustedHostKey,
)
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.adapters.mikrotik.provision import READ_POLICY, WRITE_POLICY, granted
from signalbox.model import DeviceRole, DeviceStatus
from signalbox.sim.mikrotik import MikrotikSimulator
from signalbox.sim.mikrotik_ssh import ADMIN_PASSWORD, MikrotikSsh, serve_ssh
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve

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


def request(url: str, trust: str | None, remedy: str = "policies", **kw: Any) -> RemedyRequest:
    return RemedyRequest(
        remedy=remedy,
        config={"url": url, "username": "signalbox"},
        secrets={"password": SecretStr("stored-password")},
        admin_user=kw.pop("user", "admin"),
        admin_secret=SecretStr(kw.pop("secret", ADMIN)),
        allow_writes=kw.pop("allow_writes", False),
        port=kw.pop("port", None),
        trust=trust,
        timeout=5,
    )


async def set_up(url: str, tls: TlsFiles, writes: bool = False) -> str:
    result = await MikrotikAdapter.apply_setup(
        SetupRequest(
            config={"url": url, "username": "signalbox"},
            admin_user="admin",
            admin_secret=SecretStr(ADMIN),
            allow_writes=writes,
            trust=tls.fingerprint,
            timeout=5,
        )
    )
    assert result.ok
    return result.secrets["password"].get_secret_value()


def group(sim: MikrotikSimulator, name: str) -> dict[str, Any]:
    return next(g for g in sim.data["/rest/user/group"] if g["name"] == name)


def test_remedies_are_declared() -> None:
    remedies = {r.id: r for r in MikrotikAdapter.manifest.remedies}
    assert set(remedies) == {"policies", "rest-service"}
    assert remedies["rest-service"].transport == "SSH as admin"


async def test_policies_added_and_read_again(
    url: str, tls: TlsFiles, sim: MikrotikSimulator
) -> None:
    password = await set_up(url, tls)
    g = group(sim, "signalbox-read")
    g["policy"] = "read,!api,!rest-api,!write"
    sim.no_policy = {"/rest/system/resource"}

    untrusted = await MikrotikAdapter.plan_remedy(request(url, None))
    assert not untrusted.trusted and untrusted.fingerprint == tls.fingerprint
    with pytest.raises(UntrustedCertificate):
        await MikrotikAdapter.apply_remedy(request(url, None))
    plan = await MikrotikAdapter.plan_remedy(request(url, tls.fingerprint))
    assert [(s.id, s.state) for s in plan.steps] == [("policies", StepState.TODO)]
    assert plan.steps[0].detail.splitlines()[1:] == ["+ api", "+ rest-api"]
    assert g["policy"] == "read,!api,!rest-api,!write"  # a plan changes nothing

    done = await MikrotikAdapter.apply_remedy(request(url, tls.fingerprint))
    assert done.ok and done.steps[0].state is StepState.DONE
    assert granted(g["policy"]) == {"read", "api", "rest-api"}
    assert "!write" in g["policy"]
    assert all(ADMIN not in s.detail + s.message for s in done.steps)
    assert password not in repr(done)

    again = await MikrotikAdapter.plan_remedy(request(url, tls.fingerprint))
    assert again.steps[0].state is StepState.UNCHANGED


async def test_write_policies_only_with_allow_changes(
    url: str, tls: TlsFiles, sim: MikrotikSimulator
) -> None:
    await set_up(url, tls)
    g = group(sim, "signalbox-read")
    g["policy"] = READ_POLICY
    plan = await MikrotikAdapter.plan_remedy(request(url, tls.fingerprint))
    assert plan.steps[0].state is StepState.UNCHANGED
    done = await MikrotikAdapter.apply_remedy(request(url, tls.fingerprint, allow_writes=True))
    assert done.ok and granted(g["policy"]) == granted(WRITE_POLICY)
    # nothing else of the group is touched
    assert [x["name"] for x in sim.data["/rest/user/group"]].count("signalbox-read") == 1


async def test_refusals(url: str, tls: TlsFiles, sim: MikrotikSimulator) -> None:
    with pytest.raises(AdapterError, match="no user 'signalbox'"):
        await MikrotikAdapter.plan_remedy(request(url, tls.fingerprint))
    await set_up(url, tls)
    next(u for u in sim.data["/rest/user"] if u["name"] == "signalbox")["group"] = "full"
    with pytest.raises(AdapterError, match="only a group of its own") as caught:
        await MikrotikAdapter.plan_remedy(request(url, tls.fingerprint))
    assert caught.value.fix
    with pytest.raises(AuthFailed):
        await MikrotikAdapter.plan_remedy(request(url, tls.fingerprint, secret="wrong"))
    with pytest.raises(AdapterError, match="no remedy"):
        await MikrotikAdapter.plan_remedy(request(url, tls.fingerprint, remedy="nope"))
    with pytest.raises(AdapterError, match="https"):
        await MikrotikAdapter.plan_remedy(request("http://192.0.2.1", None))


async def test_failed_patch_is_reported(url: str, tls: TlsFiles, sim: MikrotikSimulator) -> None:
    await set_up(url, tls)
    group(sim, "signalbox-read")["policy"] = "read"
    sim.fail_write = {"/rest/user/group": 500}
    sim.read_only = True
    done = await MikrotikAdapter.apply_remedy(request(url, tls.fingerprint))
    assert not done.ok and done.steps[0].state is StepState.FAILED


async def test_permission_error_names_the_remedy(
    url: str, tls: TlsFiles, sim: MikrotikSimulator
) -> None:
    password = await set_up(url, tls)
    sim.no_policy = {"/rest/system/resource"}
    adapter = MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id="r",
            device_name="r",
            role=DeviceRole.GATEWAY,
            config=MikrotikConfig(url=url, password=SecretStr(password)),
            pinned_fingerprint=tls.fingerprint,
        )
    )
    try:
        snap = await adapter.observe()
    finally:
        await adapter.close()
    assert snap.status is DeviceStatus.AUTH_FAILED or snap.errors
    assert any(e.remedy == "policies" for e in snap.errors), snap.errors


async def test_unreachable_names_the_remedy() -> None:
    adapter = MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id="r",
            device_name="r",
            role=DeviceRole.GATEWAY,
            config=MikrotikConfig(url="https://127.0.0.1:1", password=SecretStr("x")),
            pinned_fingerprint="ab" * 32,
            timeout=2,
        )
    )
    try:
        with pytest.raises(Unreachable) as caught:
            await adapter.http.get_json("/rest/system/resource")
    finally:
        await adapter.close()
    assert caught.value.remedy == "rest-service"


# --- the REST service over SSH ----------------------------------------------------------------


async def test_certificate_and_service_created(url: str) -> None:
    device = MikrotikSsh()
    async with serve_ssh(device) as (port, fingerprint):
        base = request("https://127.0.0.1", None, "rest-service", port=port, secret=ADMIN_PASSWORD)
        untrusted = await MikrotikAdapter.plan_remedy(base)
        assert not untrusted.trusted and untrusted.fingerprint == fingerprint
        assert untrusted.fingerprint_kind == "ssh-host-key" and device.commands == []
        with pytest.raises(UntrustedHostKey):
            await MikrotikAdapter.apply_remedy(base)

        trusted = request(
            "https://127.0.0.1", fingerprint, "rest-service", port=port, secret=ADMIN_PASSWORD
        )
        plan = await MikrotikAdapter.plan_remedy(trusted)
        assert [(s.id, s.state) for s in plan.steps] == [
            ("ca", StepState.TODO),
            ("server-certificate", StepState.TODO),
            ("www-ssl", StepState.TODO),
            ("check", StepState.TODO),
        ]
        assert not device.certs and device.disabled

        done = await MikrotikAdapter.apply_remedy(trusted)
        assert done.ok, done.steps
        assert device.certs == {"signalbox-ca": True, "signalbox-www": True}
        assert device.certificate == "signalbox-www" and not device.disabled
        assert device.address == []  # no list: reachable from everywhere, left alone
        assert ADMIN_PASSWORD not in repr(done)

        again = await MikrotikAdapter.plan_remedy(trusted)
        assert all(s.state is StepState.UNCHANGED for s in again.steps)


async def test_existing_certificate_is_reused_and_address_extended() -> None:
    device = MikrotikSsh(
        certs={"signalbox-ca": True, "signalbox-www": True},
        address=["198.51.100.0/24"],
        disabled=False,
    )
    async with serve_ssh(device) as (port, fingerprint):
        trusted = request(
            "https://127.0.0.1", fingerprint, "rest-service", port=port, secret=ADMIN_PASSWORD
        )
        plan = await MikrotikAdapter.plan_remedy(trusted)
        states = {s.id: s.state for s in plan.steps}
        assert states["ca"] is states["server-certificate"] is StepState.UNCHANGED
        assert states["www-ssl"] is StepState.TODO
        done = await MikrotikAdapter.apply_remedy(trusted)
        assert done.ok, done.steps
        assert device.address == ["198.51.100.0/24", "192.0.2.50/32"]  # the others stay
        assert device.certificate == "signalbox-www"
        assert device.certs == {"signalbox-ca": True, "signalbox-www": True}


async def test_address_list_that_includes_us_is_left_alone() -> None:
    device = MikrotikSsh(
        certificate="signalbox-www", address=["192.0.2.0/24"], disabled=True, certs={}
    )
    async with serve_ssh(device) as (port, fingerprint):
        trusted = request(
            "https://127.0.0.1", fingerprint, "rest-service", port=port, secret=ADMIN_PASSWORD
        )
        done = await MikrotikAdapter.apply_remedy(trusted)
        assert done.ok and device.address == ["192.0.2.0/24"] and not device.disabled


async def test_ssh_failures() -> None:
    device = MikrotikSsh(address=["198.51.100.0/24"], sessions=2)
    async with serve_ssh(device) as (port, fingerprint):
        trusted = request(
            "https://127.0.0.1", fingerprint, "rest-service", port=port, secret=ADMIN_PASSWORD
        )
        with pytest.raises(AdapterError, match="which address") as caught:
            await MikrotikAdapter.plan_remedy(trusted)
        assert caught.value.fix
        device.sessions = 1
        device.refuse_set = "failure: not allowed"
        done = await MikrotikAdapter.apply_remedy(trusted)
        assert not done.ok
        assert [s.state for s in done.steps][-2:] == [StepState.FAILED, StepState.SKIPPED]
        wrong = request("https://127.0.0.1", fingerprint, "rest-service", port=port, secret="no")
        with pytest.raises(AuthFailed):
            await MikrotikAdapter.plan_remedy(wrong)
        device.refuse_set = ""
        device.admin_password = "other"
        with pytest.raises(AuthFailed):
            await MikrotikAdapter.plan_remedy(trusted)
