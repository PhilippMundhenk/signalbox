"""Automatic setup of a Linux device over SSH (#240) against the simulator, then reading with
the login it created."""

from __future__ import annotations

import re
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
    UntrustedHostKey,
)
from signalbox.adapters.linux import LinuxAdapter, LinuxConfig
from signalbox.adapters.linux.collect import FORBIDDEN
from signalbox.adapters.linux.provision import parse_sections
from signalbox.adapters.linux.setup import KEY_COMMENT, SUDOERS_PATH, commands, sudoers
from signalbox.model import DeviceRole, DeviceStatus
from signalbox.sim.linux import (
    ADMIN_PASSWORD,
    ADMIN_USER,
    ROOT_PASSWORD,
    LinuxSim,
    User,
    serve_ssh,
)
from signalbox.testing import assert_contract

DOCS = Path(__file__).parent.parent / "docs" / "adapters" / "linux.md"


def request(port: int, trust: str | None, **kw: Any) -> SetupRequest:
    config = kw.pop("config", {"host": "127.0.0.1", "username": "signalbox"})
    return SetupRequest(
        config=config,
        admin_user=kw.pop("user", "root"),
        admin_secret=SecretStr(kw.pop("secret", ROOT_PASSWORD)),
        port=port,
        trust=trust,
        timeout=10,
        **kw,
    )


def test_sudoers_rule_and_commands_are_documented() -> None:
    text = DOCS.read_text()
    assert sudoers("signalbox") in text
    block = re.search(r"```sh\n(.*?)```", text, re.S)
    assert block and block.group(1) == commands()
    assert "dump" not in sudoers() and "private" not in sudoers()


@pytest.mark.parametrize(
    ("user", "secret", "sudo"),
    [
        ("root", ROOT_PASSWORD, None),
        (ADMIN_USER, ADMIN_PASSWORD, "password"),
        (ADMIN_USER, ADMIN_PASSWORD, "nopasswd"),
    ],
)
async def test_plan_apply_read_rerun_remove(user: str, secret: str, sudo: str | None) -> None:
    box = LinuxSim()
    if sudo:
        box.users[ADMIN_USER].sudo = sudo
    async with serve_ssh(box) as (port, fingerprint):
        first = await LinuxAdapter.plan_setup(request(port, None, user=user, secret=secret))
        assert not first.trusted and first.fingerprint == fingerprint and not first.steps
        assert box.scripts == []  # nothing before the host key is confirmed
        plan = await LinuxAdapter.plan_setup(request(port, fingerprint, user=user, secret=secret))
        assert plan.trusted
        assert [(s.id, s.state) for s in plan.steps] == [
            ("user", StepState.TODO),
            ("key", StepState.TODO),
            ("sudoers", StepState.TODO),
            ("host-key", StepState.TODO),
        ]
        assert "signalbox" not in box.users  # the plan changed nothing
        result = await LinuxAdapter.apply_setup(
            request(port, fingerprint, user=user, secret=secret)
        )
        assert result.ok, result.steps
        assert result.settings == {"host": "127.0.0.1", "port": port, "username": "signalbox"}
        private = result.secrets["private_key"].get_secret_value()
        assert private.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
        assert box.users["signalbox"].keys[0].endswith(KEY_COMMENT)
        assert box.sudoers_files[SUDOERS_PATH] == sudoers("signalbox")
        sent = "\n".join(box.scripts)
        assert private not in sent and secret not in sent
        for step in result.steps:
            assert secret not in step.detail + step.message and private not in step.detail
        # the stored settings read the device
        ctx = AdapterContext(
            site_id="home",
            device_id="gw2",
            device_name="gw2",
            role=DeviceRole.GATEWAY,
            config=LinuxConfig(**result.settings, private_key=SecretStr(private)),
            pinned_fingerprint=result.certificate,
            timeout=5,
        )
        adapter = LinuxAdapter(ctx)
        try:
            snap = await assert_contract(adapter)
        finally:
            await adapter.close()
        assert snap.status is DeviceStatus.OK
        assert not any(w in s for s in box.scripts for w in FORBIDDEN)
        # a re-run: the user and the rule exist, a new key replaces the old one
        again = await LinuxAdapter.apply_setup(request(port, fingerprint, user=user, secret=secret))
        states = {s.id: s.state for s in again.steps}
        assert states["user"] is StepState.UNCHANGED and states["sudoers"] is StepState.UNCHANGED
        assert states["key"] is StepState.DONE
        # removal
        removed = await LinuxAdapter.apply_setup(
            request(port, fingerprint, user=user, secret=secret, remove=True)
        )
        assert removed.ok and not removed.settings and not removed.secrets
        assert "signalbox" not in box.users and SUDOERS_PATH not in box.sudoers_files
        nothing = await LinuxAdapter.plan_setup(
            request(port, fingerprint, user=user, secret=secret, remove=True)
        )
        assert {s.state for s in nothing.steps} == {StepState.UNCHANGED}


async def test_without_wireguard_no_sudoers_rule() -> None:
    box = LinuxSim(wg_installed=False)
    async with serve_ssh(box) as (port, fp):
        result = await LinuxAdapter.apply_setup(request(port, fp))
    assert result.ok
    assert {s.id: s.state for s in result.steps}["sudoers"] is StepState.UNCHANGED
    assert box.sudoers_files == {}


async def test_refusals() -> None:
    box = LinuxSim()
    box.users["signalbox"] = User(groups={"sudo"})
    async with serve_ssh(box) as (port, fp):
        with pytest.raises(AdapterError, match="group"):
            await LinuxAdapter.plan_setup(request(port, fp))
        with pytest.raises(AdapterError, match="not deleted"):
            await LinuxAdapter.plan_setup(request(port, fp, remove=True))
        with pytest.raises(UntrustedHostKey):
            await LinuxAdapter.apply_setup(request(port, "SHA256:" + "A" * 43))
        with pytest.raises(AuthFailed, match="admin login"):
            await LinuxAdapter.plan_setup(request(port, fp, secret="wrong"))
        box.users["nosudo"] = User(password="example-x")
        with pytest.raises(AuthFailed, match="sudo") as err:
            await LinuxAdapter.plan_setup(request(port, fp, user="nosudo", secret="example-x"))
        assert "example-x" not in str(err.value)
        box.users[ADMIN_USER].sudo = "password"
        with pytest.raises(AuthFailed):  # wrong sudo password: the SSH login fails first
            await LinuxAdapter.plan_setup(request(port, fp, user=ADMIN_USER, secret="nope"))
    for name in ("root", "pi", "Bad Name"):
        with pytest.raises(AdapterError):
            await LinuxAdapter.plan_setup(request(22, None, config={"host": "x", "username": name}))
    with pytest.raises(AdapterError, match="address"):
        await LinuxAdapter.plan_setup(request(22, None, config={"host": ""}))


async def test_failing_step_is_reported_and_redacted() -> None:
    box = LinuxSim(visudo=False)
    async with serve_ssh(box) as (port, fp):
        result = await LinuxAdapter.apply_setup(request(port, fp))
    assert not result.ok
    states = {s.id: s.state for s in result.steps}
    assert states["sudoers"] is StepState.FAILED and states["host-key"] is StepState.SKIPPED
    assert not result.secrets


async def test_inspect_not_linux() -> None:
    class Odd(LinuxSim):
        def setup(self, script: str) -> tuple[int, bytes, str]:
            return 0, f"no sections {ROOT_PASSWORD}".encode(), ""

    box = Odd()
    async with serve_ssh(box) as (port, fp):
        with pytest.raises(AdapterError, match="like Linux") as err:
            await LinuxAdapter.plan_setup(request(port, fp))
    assert ROOT_PASSWORD not in str(err.value)


def test_parse_sections() -> None:
    assert parse_sections("x\n@@a\n1\n@@b\n") == {"a": ["1"], "b": []}
