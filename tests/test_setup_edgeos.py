"""Automatic setup of an EdgeRouter or VyOS router over SSH (#495) against the simulator: the
version is read before the plan is built, EdgeOS and VyOS up to 1.3 get ``level operator``,
VyOS 1.4 and newer a user without a level and a plan that says so."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import (
    AdapterContext,
    AdapterError,
    AuthFailed,
    SetupRequest,
    StepState,
)
from signalbox.adapters.edgeos import EdgeosAdapter, EdgeosConfig
from signalbox.adapters.ssh import sha256_hex
from signalbox.model import DeviceRole, DeviceStatus
from signalbox.sim.edgeos import EdgeosSim, serve_ssh
from signalbox.testing import assert_contract

ADMIN = ("setup-admin", "admin-pass-for-the-test")


def box(profile: str, **kw: Any) -> EdgeosSim:
    return EdgeosSim(profile=profile, admin=ADMIN, **kw)


def request(port: int, trust: str | None, **kw: Any) -> SetupRequest:
    return SetupRequest(
        config=kw.pop("config", {"host": "127.0.0.1", "username": "signalbox"}),
        admin_user=kw.pop("user", ADMIN[0]),
        admin_secret=SecretStr(kw.pop("secret", ADMIN[1])),
        port=port,
        trust=trust,
        timeout=10,
        **kw,
    )


@pytest.mark.parametrize("profile", ["edgeos-2.0", "edgeos-1.10", "vyos-1.3"])
async def test_levels_where_the_version_has_them(profile: str) -> None:
    device = box(profile)
    async with serve_ssh(device) as (port, fingerprint):
        first = await EdgeosAdapter.plan_setup(request(port, None))
        assert not first.trusted and first.fingerprint == fingerprint and not first.steps
        assert device.scripts == []  # nothing is sent before the host key is confirmed
        plan = await EdgeosAdapter.plan_setup(request(port, fingerprint))
        assert [(s.id, s.state) for s in plan.steps] == [
            ("user", StepState.TODO),
            ("key", StepState.TODO),
            ("host-key", StepState.TODO),
        ]
        assert "level operator" in plan.steps[0].detail
        assert not device.users  # the plan changed nothing
        result = await EdgeosAdapter.apply_setup(request(port, fingerprint))
        assert result.ok, result.steps
        assert result.settings == {"host": "127.0.0.1", "port": port, "username": "signalbox"}
        assert result.certificate == sha256_hex(fingerprint)
        assert device.users == {"signalbox": "operator"}
        private = result.secrets["private_key"].get_secret_value()
        sent = "\n".join(device.scripts)
        assert private not in sent and ADMIN[1] not in sent
        assert "plaintext-password" not in sent  # key only
        for step in result.steps:
            assert ADMIN[1] not in step.detail + step.message and private not in step.detail
        # the stored settings read the router
        ctx = AdapterContext(
            site_id="home",
            device_id="er2",
            device_name="er2",
            role=DeviceRole.GATEWAY,
            config=EdgeosConfig(**result.settings, private_key=SecretStr(private)),
            pinned_fingerprint=result.certificate,
            timeout=5,
        )
        adapter = EdgeosAdapter(ctx)
        try:
            snap = await assert_contract(adapter)
        finally:
            await adapter.close()
        assert snap.status in (DeviceStatus.OK, DeviceStatus.PARTIAL)
        # a re-run replaces the key; removal deletes the user
        again = await EdgeosAdapter.apply_setup(request(port, fingerprint))
        assert again.ok and device.users == {"signalbox": "operator"}
        removed = await EdgeosAdapter.apply_setup(request(port, fingerprint, remove=True))
        assert removed.ok and not removed.settings and not removed.secrets
        assert device.users == {} and device.keys == []
        nothing = await EdgeosAdapter.plan_setup(request(port, fingerprint, remove=True))
        assert {s.state for s in nothing.steps} == {StepState.UNCHANGED}


async def test_vyos_without_levels_says_full_rights() -> None:
    """VyOS 1.4 and newer (the profile has no ``level`` option): the user is created without a
    level, and the plan says so in a step of its own; no command carries ``level``."""
    device = box("vyos-1.4")
    async with serve_ssh(device) as (port, fingerprint):
        plan = await EdgeosAdapter.plan_setup(request(port, fingerprint))
        steps = {s.id: s for s in plan.steps}
        assert list(steps) == ["user", "key", "full-rights", "host-key"]
        assert steps["user"].title_id == "setup.edgeos.createUserNoLevel"
        assert "level" not in steps["user"].detail
        note = steps["full-rights"]
        assert note.state is StepState.UNCHANGED and "VyOS 1.4.0" in note.title
        assert "full rights" in note.title and "key only" in note.title
        assert note.title_id == "setup.edgeos.fullRights"
        result = await EdgeosAdapter.apply_setup(request(port, fingerprint))
        assert result.ok, result.steps
        assert device.users == {"signalbox": None}
        assert not any("level" in line for line in device.applied)
        assert any("authentication public-keys signalbox key" in line for line in device.applied)
        assert not any("password" in line for line in device.applied)
        removed = await EdgeosAdapter.apply_setup(request(port, fingerprint, remove=True))
        assert removed.ok and device.users == {}


async def test_vyos_14_that_still_has_levels_gets_operator() -> None:
    device = box("vyos-1.4", levels=True)
    async with serve_ssh(device) as (port, fingerprint):
        plan = await EdgeosAdapter.plan_setup(request(port, fingerprint))
        assert [s.id for s in plan.steps] == ["user", "key", "host-key"]
        result = await EdgeosAdapter.apply_setup(request(port, fingerprint))
        assert result.ok and device.users == {"signalbox": "operator"}


async def test_a_refused_level_fails_the_step_and_skips_the_rest() -> None:
    """EdgeOS profile, but the router refuses the line (an unknown build): the step fails with
    the router's message, nothing after it runs."""
    device = box("edgeos-2.0", levels=False)
    async with serve_ssh(device) as (port, fingerprint):
        result = await EdgeosAdapter.apply_setup(request(port, fingerprint))
    assert not result.ok and not result.secrets
    states = {s.id: s.state for s in result.steps}
    assert states["user"] is StepState.FAILED and states["key"] is StepState.SKIPPED
    assert result.steps[0].message_id == "edgeos.stepFailed"


async def test_a_user_with_more_than_read_access_is_never_touched() -> None:
    device = box("edgeos-2.0")
    device.users["signalbox"] = "admin"
    async with serve_ssh(device) as (port, fingerprint):
        with pytest.raises(AdapterError) as err:
            await EdgeosAdapter.plan_setup(request(port, fingerprint))
        assert err.value.message_id == "edgeos.loginPrivileged"
        with pytest.raises(AdapterError) as gone:
            await EdgeosAdapter.apply_setup(request(port, fingerprint, remove=True))
        assert gone.value.message_id == "edgeos.loginNotOurs"
    assert device.users == {"signalbox": "admin"} and device.applied == []


@pytest.mark.parametrize("login", ["root", "vyos", "Bad Name", ADMIN[0]])
async def test_login_names(login: str) -> None:
    device = box("edgeos-2.0")
    async with serve_ssh(device) as (port, fingerprint):
        with pytest.raises(AdapterError):
            await EdgeosAdapter.plan_setup(
                request(port, fingerprint, config={"host": "127.0.0.1", "username": login})
            )


async def test_wrong_admin_password() -> None:
    device = box("edgeos-2.0")
    async with serve_ssh(device) as (port, fingerprint):
        with pytest.raises(AuthFailed):
            await EdgeosAdapter.plan_setup(request(port, fingerprint, secret="wrong"))
    assert device.users == {}


async def test_not_a_router() -> None:
    device = box("edgeos-2.0")

    device.setup = lambda script: (0, b"@@end\n", "")  # type: ignore[method-assign]
    async with serve_ssh(device) as (port, fingerprint):
        with pytest.raises(AdapterError) as err:
            await EdgeosAdapter.plan_setup(request(port, fingerprint))
    assert err.value.message_id == "edgeos.notEdgeos"


@pytest.mark.parametrize("profile", ["edgeos-2.0", "vyos-1.4"])
async def test_the_preview_covers_the_plan(profile: str) -> None:
    """What the form shows before the admin login (#279) names every step of the plan."""
    assert EdgeosAdapter.manifest.admin_login is not None
    preview = EdgeosAdapter.manifest.admin_login.preview
    device = box(profile)
    async with serve_ssh(device) as (port, fingerprint):
        plan = await EdgeosAdapter.plan_setup(request(port, fingerprint))
        assert {s.id for s in plan.steps} <= {p.id for p in preview if not p.remove}
        assert (await EdgeosAdapter.apply_setup(request(port, fingerprint))).ok
        gone = await EdgeosAdapter.plan_setup(request(port, fingerprint, remove=True))
        assert gone.steps and {s.id for s in gone.steps} <= {p.id for p in preview if p.remove}
