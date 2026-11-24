"""Fix it on OPNsense (#215): missing privileges for the stored key's user, against the
simulator; and the read error that names the remedy."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import (
    AdapterContext,
    AdapterError,
    RemedyRequest,
    SetupRequest,
    StepState,
    UntrustedCertificate,
)
from signalbox.adapters.opnsense import OpnsenseAdapter, OpnsenseConfig
from signalbox.adapters.opnsense.provision import READ_PRIVILEGES, WRITE_PRIVILEGES
from signalbox.model import DeviceRole
from signalbox.sim.opnsense import KEY, SECRET, OpnsenseSimulator
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve

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


async def set_up(url: str, tls: TlsFiles, writes: bool = False) -> dict[str, str]:
    result = await OpnsenseAdapter.apply_setup(
        SetupRequest(
            config={"url": url},
            admin_user=KEY,
            admin_secret=SecretStr(SECRET),
            allow_writes=writes,
            trust=tls.fingerprint,
            timeout=5,
        )
    )
    assert result.ok
    return {k: v.get_secret_value() for k, v in result.secrets.items()}


def request(url: str, trust: str | None, key: str, **kw: Any) -> RemedyRequest:
    return RemedyRequest(
        remedy=kw.pop("remedy", "privileges"),
        config={"url": url},
        secrets={"api_key": SecretStr(key), "api_secret": SecretStr("stored-secret")},
        admin_user=KEY,
        admin_secret=SecretStr(SECRET),
        allow_writes=kw.pop("allow_writes", False),
        trust=trust,
        timeout=5,
    )


async def test_adds_only_the_missing_privileges(
    url: str, tls: TlsFiles, sim: OpnsenseSimulator
) -> None:
    keys = await set_up(url, tls)
    user = next(u for u in sim.accounts.users if u["name"] == "signalbox")
    user["priv"] = [p for p in user["priv"] if p != "page-status-ntp"] + ["page-all"]
    user["groups"] = ["admins"]
    keys_before = list(sim.accounts.keys)

    untrusted = await OpnsenseAdapter.plan_remedy(request(url, None, keys["api_key"]))
    assert not untrusted.trusted and untrusted.fingerprint == tls.fingerprint
    plan = await OpnsenseAdapter.plan_remedy(request(url, tls.fingerprint, keys["api_key"]))
    assert [(s.id, s.state) for s in plan.steps] == [("privileges", StepState.TODO)]
    assert plan.steps[0].detail.splitlines()[1:] == ["+ page-status-ntp"]

    done = await OpnsenseAdapter.apply_remedy(
        request(url, tls.fingerprint, keys["api_key"], allow_writes=True)
    )
    assert done.ok and done.secrets == {} and done.settings == {}
    assert sorted(user["priv"]) == sorted({*WRITE_PRIVILEGES, "page-all"})
    assert user["groups"] == ["admins"] and sim.accounts.keys == keys_before
    for step in done.steps:
        for text in (step.detail, step.message, step.title):
            assert keys["api_key"] not in text and SECRET not in text

    again = await OpnsenseAdapter.plan_remedy(
        request(url, tls.fingerprint, keys["api_key"], allow_writes=True)
    )
    assert again.steps[0].state is StepState.UNCHANGED
    assert set(READ_PRIVILEGES) <= set(user["priv"])


async def test_refusals(url: str, tls: TlsFiles, sim: OpnsenseSimulator) -> None:
    with pytest.raises(AdapterError, match="no user with the stored API key"):
        await OpnsenseAdapter.plan_remedy(request(url, tls.fingerprint, "unknown-key"))
    with pytest.raises(AdapterError, match="no stored API key"):
        await OpnsenseAdapter.plan_remedy(request(url, tls.fingerprint, ""))
    with pytest.raises(AdapterError, match="no remedy"):
        await OpnsenseAdapter.plan_remedy(request(url, tls.fingerprint, "k", remedy="nope"))
    sim.accounts.keys.append({"id": "r1", "key": "root-key", "secret": "s", "username": "root"})
    with pytest.raises(AdapterError, match="only a user of its own"):
        await OpnsenseAdapter.apply_remedy(request(url, tls.fingerprint, "root-key"))
    sim.accounts.keys.append({"id": "g1", "key": "ghost-key", "secret": "s", "username": "ghost"})
    with pytest.raises(AdapterError, match="lists no user 'ghost'"):
        await OpnsenseAdapter.plan_remedy(request(url, tls.fingerprint, "ghost-key"))
    with pytest.raises(UntrustedCertificate):
        await OpnsenseAdapter.apply_remedy(request(url, "ab" * 32, "k"))


async def test_a_refused_read_names_the_remedy(
    url: str, tls: TlsFiles, sim: OpnsenseSimulator
) -> None:
    keys = await set_up(url, tls)
    sim.fail["/api/ntpd"] = 403
    sim.fail["/api/diagnostics/interface/get_arp"] = 403
    adapter = OpnsenseAdapter(
        AdapterContext(
            site_id="home",
            device_id="fw",
            device_name="fw",
            role=DeviceRole.GATEWAY,
            config=OpnsenseConfig(
                url=url,
                api_key=SecretStr(keys["api_key"]),
                api_secret=SecretStr(keys["api_secret"]),
            ),
            pinned_fingerprint=tls.fingerprint,
            timeout=5,
        )
    )
    try:
        snap = await adapter.observe()
    finally:
        await adapter.close()
    denied = [e for e in snap.errors if "403" in e.message and not e.message.startswith("accounts")]
    assert denied and all(e.remedy == "privileges" for e in denied), snap.errors
