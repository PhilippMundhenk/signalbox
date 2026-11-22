"""The automatic setup (#231) against the real RouterOS CHR, through REST as admin.

The CHR has the groups ``signalbox-read`` and ``signalbox-write`` of the setup guide (for the
other tests, with the users ``signalbox`` and ``signalbox-write``) but no user
``signalbox-auto``: the setup creates it, the router is read with it, it moves to the write
group, and the removal deletes it and keeps the groups the other users are in. Runs as a CI
step of its own after the other MikroTik tests.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import (
    AdapterContext,
    AuthFailed,
    SetupRequest,
    SetupResult,
    StepState,
    UntrustedCertificate,
)
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.model import DeviceRole, DeviceStatus
from signalbox.testing import assert_contract

from .conftest import Target

LOGIN = "signalbox-auto"
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def chr_(target: Callable[[str], Target]) -> Target:
    t = target("mikrotik")
    assert t.pin and t.extra.get("ADMIN_PASSWORD"), "IT_MIKROTIK_PIN and ADMIN_PASSWORD"
    return t


def request(t: Target, trust: str | None, **kw: Any) -> SetupRequest:
    return SetupRequest(
        config={"url": t.url, "username": LOGIN},
        admin_user="admin",
        admin_secret=SecretStr(kw.pop("secret", t.extra["ADMIN_PASSWORD"])),
        trust=trust,
        timeout=60,
        **kw,
    )


def context(t: Target, result: SetupResult) -> AdapterContext:
    return AdapterContext(
        site_id="home",
        device_id="chr",
        device_name="CHR",
        role=DeviceRole.GATEWAY,
        config=MikrotikConfig(
            url=str(result.settings["url"]), username=LOGIN, password=result.secrets["password"]
        ),
        pinned_fingerprint=result.certificate,
        timeout=60,
    )


async def observe(t: Target, result: SetupResult) -> Any:
    a = MikrotikAdapter(context(t, result))
    try:
        return await a.observe()
    finally:
        await a.close()


def check(result: SetupResult) -> None:
    assert result.ok, [(s.id, s.message) for s in result.steps if s.state is StepState.FAILED]


@pytest.fixture
async def clean(chr_: Target) -> AsyncIterator[None]:
    yield
    await MikrotikAdapter.apply_setup(request(chr_, chr_.pin, remove=True))


async def test_untrusted_and_refused(chr_: Target) -> None:
    plan = await MikrotikAdapter.plan_setup(request(chr_, None))
    assert not plan.trusted and plan.fingerprint == chr_.pin
    with pytest.raises(UntrustedCertificate):
        await MikrotikAdapter.apply_setup(request(chr_, "ab" * 32))
    with pytest.raises(AuthFailed):
        await MikrotikAdapter.plan_setup(request(chr_, chr_.pin, secret="not-the-password"))


async def test_setup_read_write_remove(chr_: Target, clean: None) -> None:
    plan = await MikrotikAdapter.plan_setup(request(chr_, chr_.pin))
    group, user = plan.steps
    # the image's group has the documented policies: RouterOS's own spelling compares equal
    assert group.state is StepState.UNCHANGED, group
    assert user.state is StepState.TODO and "Create the user signalbox-auto" in user.title

    result = await MikrotikAdapter.apply_setup(request(chr_, chr_.pin))
    check(result)
    assert result.certificate == chr_.pin
    snap = await observe(chr_, result)
    assert snap.status in (DeviceStatus.OK, DeviceStatus.PARTIAL), snap.errors
    a = MikrotikAdapter(context(chr_, result))
    try:
        await assert_contract(a)
    finally:
        await a.close()

    write = await MikrotikAdapter.apply_setup(request(chr_, chr_.pin, allow_writes=True))
    check(write)
    assert write.steps[0].state is StepState.UNCHANGED and "Update the user" in write.steps[1].title
    assert (await observe(chr_, write)).status in (DeviceStatus.OK, DeviceStatus.PARTIAL)
    assert (await observe(chr_, result)).status is DeviceStatus.AUTH_FAILED, "old password"

    gone = await MikrotikAdapter.apply_setup(request(chr_, chr_.pin, remove=True))
    check(gone)
    states = {s.id: s for s in gone.steps}
    assert states["user"].state is StepState.DONE
    assert states["group-signalbox-read"].state is StepState.UNCHANGED
    assert "signalbox" in states["group-signalbox-read"].message
    assert (await observe(chr_, write)).status is DeviceStatus.AUTH_FAILED
