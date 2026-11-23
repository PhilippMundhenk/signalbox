"""The automatic setup (#231) against the real OPNsense in QEMU, with root's API key.

The VM has no user ``signalbox`` (its test users are ``signalbox-read`` and
``signalbox-write``): the setup creates it with the documented privileges and a key, the firewall
is read with that key, the setup runs again with changes allowed (privileges updated, the old
key deleted), and the removal deletes the user. Runs as a CI step of its own right after the
boot, before the other OPNsense tests; every test leaves no user ``signalbox`` behind.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
from pydantic import SecretStr

from integration.conftest import Target
from signalbox.adapters import (
    AdapterContext,
    AuthFailed,
    RemedyRequest,
    SetupRequest,
    SetupResult,
    StepState,
    UntrustedCertificate,
)
from signalbox.adapters.https import DeviceHttp
from signalbox.adapters.opnsense import OpnsenseAdapter, OpnsenseConfig
from signalbox.adapters.opnsense.provision import READ_PRIVILEGES, WRITE_PRIVILEGES
from signalbox.model import DeviceRole, DeviceStatus
from signalbox.testing import assert_contract

TIMEOUT = 60.0


@pytest.fixture(scope="module")
def fw(target: Callable[[str], Target]) -> Target:
    t = target("opnsense")
    assert t.pin and t.extra.get("ROOT_KEY") and t.extra.get("ROOT_SECRET"), "IT_OPNSENSE_ROOT_*"
    return t


def request(fw: Target, trust: str | None, **kw: Any) -> SetupRequest:
    return SetupRequest(
        config={"url": fw.url},
        admin_user=fw.extra["ROOT_KEY"],
        admin_secret=SecretStr(kw.pop("secret", fw.extra["ROOT_SECRET"])),
        trust=trust,
        timeout=TIMEOUT,
        **kw,
    )


async def root_answers(fw: Target) -> str:
    """What the user manager shows now (keys and secrets cut), for failure messages."""
    http = DeviceHttp(
        fw.url,
        pinned_fingerprint=fw.pin,
        timeout=TIMEOUT,
        auth=(fw.extra["ROOT_KEY"], fw.extra["ROOT_SECRET"]),
    )
    out: dict[str, Any] = {}
    try:
        body = {"current": 1, "rowCount": -1, "searchPhrase": ""}
        # keys first (the annotation keeps the start); values cut, never secrets or hashes
        keys = await http.post_json("/api/auth/user/search_api_key", body)
        out["keys"] = [
            {k: (str(v)[:6] if k in ("key", "id") else v) for k, v in r.items()}
            for r in keys.get("rows", [])
        ]
        users = await http.post_json("/api/auth/user/search", body)
        out["users"] = [r.get("name") for r in users.get("rows", [])]
        for row in users.get("rows", []):
            if row.get("name") == "signalbox":
                got = await http.get_json(f"/api/auth/user/get/{row['uuid']}")
                user = got.get("user", {})
                out["get"] = {
                    k: len([n for n, o in v.items() if o.get("selected")])
                    if isinstance(v, dict)
                    else v
                    for k, v in user.items()
                    if k in ("name", "scope", "scrambled_password", "priv", "group_memberships")
                }
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        await http.close()
    return json.dumps(out, default=str)[:2500]


async def read_with(fw: Target, result: SetupResult) -> Any:
    a = OpnsenseAdapter(
        AdapterContext(
            site_id="home",
            device_id="fw",
            device_name="fw",
            role=DeviceRole.GATEWAY,
            config=OpnsenseConfig(
                url=str(result.settings["url"]),
                api_key=result.secrets["api_key"],
                api_secret=result.secrets["api_secret"],
            ),
            pinned_fingerprint=result.certificate,
            timeout=TIMEOUT,
        )
    )
    try:
        return await a.observe()
    finally:
        await a.close()


@pytest.fixture
async def clean(fw: Target) -> AsyncIterator[None]:
    """Remove the user signalbox afterwards, whatever the test did."""
    yield
    await OpnsenseAdapter.apply_setup(request(fw, fw.pin, remove=True))


def check(result: SetupResult, answers: str) -> None:
    failed = [s for s in result.steps if s.state is StepState.FAILED]
    assert result.ok, f"{[(s.id, s.message) for s in failed]}\nuser manager:\n{answers}"


async def test_untrusted_and_refused(fw: Target) -> None:
    plan = await OpnsenseAdapter.plan_setup(request(fw, None))
    assert not plan.trusted and plan.fingerprint == fw.pin
    with pytest.raises(UntrustedCertificate):
        await OpnsenseAdapter.apply_setup(request(fw, "ab" * 32))
    with pytest.raises(AuthFailed):
        await OpnsenseAdapter.plan_setup(request(fw, fw.pin, secret="not-the-secret"))


async def test_setup_read_write_remove(fw: Target, clean: None) -> None:
    plan = await OpnsenseAdapter.plan_setup(request(fw, fw.pin))
    assert plan.trusted and plan.steps[0].state is StepState.TODO, await root_answers(fw)
    assert "Create the user signalbox" in plan.steps[0].title

    result = await OpnsenseAdapter.apply_setup(request(fw, fw.pin))
    check(result, await root_answers(fw))
    assert result.certificate == fw.pin
    snap = await read_with(fw, result)
    assert snap.status is DeviceStatus.OK, (snap.errors, await root_answers(fw))
    a = OpnsenseAdapter(
        AdapterContext(
            site_id="home",
            device_id="fw",
            device_name="fw",
            role=DeviceRole.GATEWAY,
            config=OpnsenseConfig(
                url=fw.url,
                api_key=result.secrets["api_key"],
                api_secret=result.secrets["api_secret"],
            ),
            pinned_fingerprint=fw.pin,
            timeout=TIMEOUT,
        )
    )
    try:
        await assert_contract(a)
    finally:
        await a.close()

    # as documented: exactly these privileges, no groups; again: nothing but a new key
    same = await OpnsenseAdapter.plan_setup(request(fw, fw.pin))
    assert same.steps[0].state is StepState.UNCHANGED, (same.steps[0], await root_answers(fw))
    assert same.steps[1].detail.splitlines() == sorted(READ_PRIVILEGES)

    write = await OpnsenseAdapter.apply_setup(request(fw, fw.pin, allow_writes=True))
    check(write, await root_answers(fw))
    assert write.steps[0].state is StepState.DONE
    assert "older keys deleted: 1" in write.steps[2].message, await root_answers(fw)
    assert (await read_with(fw, write)).status is DeviceStatus.OK
    old = await read_with(fw, result)
    assert old.status is DeviceStatus.AUTH_FAILED, "the old key still works"
    again = await OpnsenseAdapter.plan_setup(request(fw, fw.pin, allow_writes=True))
    assert again.steps[0].state is StepState.UNCHANGED
    assert again.steps[1].detail.splitlines() == sorted(WRITE_PRIVILEGES)

    gone = await OpnsenseAdapter.apply_setup(request(fw, fw.pin, remove=True))
    check(gone, await root_answers(fw))
    assert (await read_with(fw, write)).status is DeviceStatus.AUTH_FAILED
    twice = await OpnsenseAdapter.plan_setup(request(fw, fw.pin, remove=True))
    assert twice.steps[0].state is StepState.UNCHANGED


async def test_the_key_of_the_new_user_cannot_manage_users(fw: Target, clean: None) -> None:
    result = await OpnsenseAdapter.apply_setup(request(fw, fw.pin))
    check(result, await root_answers(fw))
    http = DeviceHttp(
        fw.url,
        pinned_fingerprint=fw.pin,
        timeout=TIMEOUT,
        auth=(
            result.secrets["api_key"].get_secret_value(),
            result.secrets["api_secret"].get_secret_value(),
        ),
    )
    try:
        with pytest.raises(AuthFailed, match="403"):
            await http.post_json("/api/auth/user/search", {})
    finally:
        await http.close()


async def test_fix_adds_a_missing_privilege(fw: Target, clean: None) -> None:
    """Fix it (#215): the user signalbox loses page-status-ntp, the read names the remedy, the
    fix adds the privilege back (nothing else changes) and the next read is complete."""
    result = await OpnsenseAdapter.apply_setup(request(fw, fw.pin))
    check(result, await root_answers(fw))
    root = DeviceHttp(
        fw.url,
        pinned_fingerprint=fw.pin,
        timeout=TIMEOUT,
        auth=(fw.extra["ROOT_KEY"], fw.extra["ROOT_SECRET"]),
    )
    try:
        users = await root.post_json(
            "/api/auth/user/search", {"current": 1, "rowCount": -1, "searchPhrase": ""}
        )
        uuid = next(r["uuid"] for r in users["rows"] if r.get("name") == "signalbox")
        fewer = [p for p in READ_PRIVILEGES if p != "page-status-ntp"]
        body = {
            "user": {
                "name": "signalbox",
                "descr": "Signalbox (set up automatically)",
                "scrambled_password": "1",
                "priv": ",".join(fewer),
                "group_memberships": "",
            }
        }
        await root.post_json(f"/api/auth/user/set/{uuid}", body)
    finally:
        await root.close()
    before = await read_with(fw, result)
    assert any(e.remedy == "privileges" for e in before.errors), (
        before.errors,
        await root_answers(fw),
    )

    fix = RemedyRequest(
        remedy="privileges",
        config={"url": fw.url},
        secrets=dict(result.secrets),
        admin_user=fw.extra["ROOT_KEY"],
        admin_secret=SecretStr(fw.extra["ROOT_SECRET"]),
        trust=fw.pin,
        timeout=TIMEOUT,
    )
    plan = await OpnsenseAdapter.plan_remedy(fix)
    assert plan.steps[0].state is StepState.TODO, (plan.steps, await root_answers(fw))
    assert plan.steps[0].detail.splitlines()[1:] == ["+ page-status-ntp"]
    done = await OpnsenseAdapter.apply_remedy(fix)
    check(done, await root_answers(fw))
    after = await read_with(fw, result)  # the same key still works
    assert after.status is DeviceStatus.OK, (after.errors, await root_answers(fw))
    again = await OpnsenseAdapter.plan_remedy(fix)
    assert again.steps[0].state is StepState.UNCHANGED
