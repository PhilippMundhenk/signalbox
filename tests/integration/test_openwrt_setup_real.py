"""The automatic setup (#231) against the real OpenWrt (x86-64 in QEMU), over SSH as root.

The image has the packages and the write ACL of the setup guide already (for the other tests,
with the logins ``signalbox`` and ``signalbox-write``), but no login ``signalbox-auto``: the
setup creates it over dropbear (host key trusted on first use here), with changes allowed so the
ACL file stays as the other logins need it, the router is read with it, then the setup runs
read-only (the ACL file loses its write part, which is put back at the end), and the removal
deletes the login and keeps the ACL file that the other logins still use. Runs as a CI step of
its own after the other OpenWrt tests.

    IT_OPENWRT_ROOT_PASSWORD   root's password on the image
    IT_OPENWRT_SSH_PORT        the host port forwarded to the router's port 22
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import (
    AdapterContext,
    AuthFailed,
    RemedyRequest,
    SetupRequest,
    SetupResult,
    StepState,
)
from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.adapters.openwrt.provision import ACL_PATH, RESTART
from signalbox.adapters.openwrt.setup import READ_ACL, WRITE_ACL
from signalbox.adapters.ssh import PinnedSsh
from signalbox.model import DeviceRole, DeviceStatus
from signalbox.testing import assert_contract

from .conftest import Target

LOGIN = "signalbox-auto"
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def ow(target: Callable[[str], Target]) -> Target:
    t = target("openwrt")
    assert t.extra.get("ROOT_PASSWORD") and t.extra.get("SSH_PORT"), "IT_OPENWRT_ROOT_*"
    return t


@pytest.fixture
async def host_key(ow: Target) -> str:
    plan = await OpenWrtAdapter.plan_setup(request(ow, None))
    assert not plan.trusted and plan.fingerprint.startswith("SHA256:") and not plan.steps
    return plan.fingerprint


def request(t: Target, trust: str | None, **kw: Any) -> SetupRequest:
    return SetupRequest(
        config={"url": t.url, "username": LOGIN},
        admin_user="root",
        admin_secret=SecretStr(kw.pop("secret", t.extra["ROOT_PASSWORD"])),
        port=int(t.extra["SSH_PORT"]),
        trust=trust,
        timeout=60,
        **kw,
    )


async def shell(t: Target, key: str, script: str) -> str:
    ssh = PinnedSsh(t.host, int(t.extra["SSH_PORT"]), "root", t.extra["ROOT_PASSWORD"], key, 30)
    async with ssh:
        return (await ssh.run(script)).text


async def read_with(t: Target, result: SetupResult) -> Any:
    a = OpenWrtAdapter(
        AdapterContext(
            site_id="lab",
            device_id="openwrt",
            device_name="OpenWrt (QEMU)",
            role=DeviceRole.GATEWAY,
            config=OpenWrtConfig(
                url=str(result.settings["url"]),
                username=str(result.settings["username"]),
                password=result.secrets["password"],
            ),
            pinned_fingerprint=result.certificate,
            timeout=30,
        )
    )
    try:
        return await a.observe()
    finally:
        await a.close()


def check(result: SetupResult) -> None:
    failed = [
        (s.id, s.message, s.detail[:300]) for s in result.steps if s.state is StepState.FAILED
    ]
    assert result.ok, failed


@pytest.fixture
async def restored(ow: Target, host_key: str) -> AsyncIterator[None]:
    """Afterwards: no login signalbox-auto, and the write ACL the other logins need."""
    yield
    await OpenWrtAdapter.apply_setup(request(ow, host_key, remove=True))
    text = await shell(ow, host_key, f"cat {ACL_PATH}\n")
    if json.loads(text) != WRITE_ACL:
        acl = json.dumps(WRITE_ACL, indent=2)
        await shell(
            ow,
            host_key,
            f"cat > {ACL_PATH} <<'END'\n{acl}\nEND\n{RESTART}",
        )


async def test_refused_admin_login_and_host_key(ow: Target, host_key: str) -> None:
    with pytest.raises(AuthFailed):
        await OpenWrtAdapter.plan_setup(request(ow, host_key, secret="not-the-password"))
    other = await OpenWrtAdapter.plan_setup(request(ow, "SHA256:" + "A" * 43))
    assert not other.trusted and other.fingerprint == host_key


async def test_setup_read_write_remove(ow: Target, host_key: str, restored: None) -> None:
    plan = await OpenWrtAdapter.plan_setup(request(ow, host_key, allow_writes=True))
    steps = {s.id: s for s in plan.steps}
    assert steps["packages"].state is StepState.UNCHANGED, steps["packages"]
    assert steps["acl"].state is StepState.UNCHANGED, "the image has the write ACL"
    assert "Create the rpcd login signalbox-auto" in steps["login"].title
    assert steps["certificate"].detail == f"SHA-256 {ow.fingerprint()}", "uhttpd's certificate"

    result = await OpenWrtAdapter.apply_setup(request(ow, host_key, allow_writes=True))
    check(result)
    assert result.certificate == ow.fingerprint()
    snap = await read_with(ow, result)
    assert snap.status is DeviceStatus.OK, snap.errors
    a = OpenWrtAdapter(
        AdapterContext(
            site_id="lab",
            device_id="openwrt",
            device_name="OpenWrt (QEMU)",
            role=DeviceRole.GATEWAY,
            config=OpenWrtConfig(url=ow.url, username=LOGIN, password=result.secrets["password"]),
            pinned_fingerprint=result.certificate,
            timeout=30,
        )
    )
    try:
        await assert_contract(a)
    finally:
        await a.close()
    rpcd = await shell(ow, host_key, "uci -q -X show rpcd\n")
    assert f"username='{LOGIN}'" in rpcd and "$1$" in rpcd

    # read-only: the ACL file without the write part, the login without write
    down = await OpenWrtAdapter.apply_setup(request(ow, host_key))
    check(down)
    assert {s.id: s.state for s in down.steps}["acl"] is StepState.DONE
    assert json.loads(await shell(ow, host_key, f"cat {ACL_PATH}\n")) == READ_ACL
    assert (await read_with(ow, down)).status is DeviceStatus.OK
    assert (await read_with(ow, result)).status is DeviceStatus.AUTH_FAILED, "old password"

    # remove: the login goes; the ACL file stays for signalbox and signalbox-write
    gone = await OpenWrtAdapter.apply_setup(request(ow, host_key, remove=True))
    check(gone)
    acl = next(s for s in gone.steps if s.id == "acl")
    assert acl.state is StepState.UNCHANGED and "signalbox-write" in acl.message
    assert (await read_with(ow, down)).status is DeviceStatus.AUTH_FAILED
    assert LOGIN not in await shell(ow, host_key, "uci -q -X show rpcd\n")


# --- Fix it (#215) --------------------------------------------------------------------------------


def remedy(t: Target, trust: str, name: str) -> RemedyRequest:
    """*Fix it* for the image's login with write access, as the API builds it."""
    return RemedyRequest(
        remedy=name,
        config={"url": t.url, "username": t.write_username or "signalbox-write"},
        secrets={"password": SecretStr(t.write_password or "")},
        admin_user="root",
        admin_secret=SecretStr(t.extra["ROOT_PASSWORD"]),
        port=int(t.extra["SSH_PORT"]),
        allow_writes=True,
        trust=trust,
        timeout=60,
    )


async def read_write_login(t: Target) -> Any:
    a = OpenWrtAdapter(
        AdapterContext(
            site_id="lab",
            device_id="openwrt",
            device_name="OpenWrt (QEMU)",
            role=DeviceRole.GATEWAY,
            config=OpenWrtConfig(
                url=t.url,
                username=t.write_username or "signalbox-write",
                password=SecretStr(t.write_password or ""),
            ),
            pinned_fingerprint=t.fingerprint(),
            timeout=30,
        )
    )
    try:
        return await a.observe()
    finally:
        await a.close()


async def test_fix_an_outdated_permission_file(ow: Target, host_key: str, restored: None) -> None:
    old = json.loads(json.dumps(WRITE_ACL))
    old["signalbox"]["read"]["ubus"]["luci-rpc"].remove("getNetworkDevices")
    await shell(
        ow, host_key, f"cat > {ACL_PATH} <<'END'\n{json.dumps(old, indent=2)}\nEND\n{RESTART}"
    )
    before = await read_write_login(ow)
    gaps = [e for e in before.errors if e.remedy == "access"]
    assert gaps and "getNetworkDevices" in gaps[0].message, before.errors

    plan = await OpenWrtAdapter.plan_remedy(remedy(ow, host_key, "access"))
    states = {s.id: s.state for s in plan.steps}
    assert states == {
        "packages": StepState.UNCHANGED,
        "acl": StepState.TODO,
        "login": StepState.UNCHANGED,
        "restart": StepState.TODO,
    }, plan.steps
    result = await OpenWrtAdapter.apply_remedy(remedy(ow, host_key, "access"))
    check(result)
    assert json.loads(await shell(ow, host_key, f"cat {ACL_PATH}\n")) == WRITE_ACL
    after = await read_write_login(ow)
    assert not [e for e in after.errors if e.remedy == "access"], after.errors
    assert after.status is DeviceStatus.OK, after.errors


async def test_fix_starts_a_stopped_lldpd(ow: Target, host_key: str) -> None:
    """The image has lldpd: the packages are found installed (apk or opkg), the stopped daemon
    is started. Installing from the feeds is offline in CI: simulator only (#21)."""
    await shell(ow, host_key, "/etc/init.d/lldpd stop\nsleep 1\n")
    plan = await OpenWrtAdapter.plan_remedy(remedy(ow, host_key, "lldp"))
    states = {s.id: s.state for s in plan.steps}
    assert states["lldp-packages"] is StepState.UNCHANGED, plan.steps
    assert states["lldpd"] is StepState.TODO
    try:
        check(await OpenWrtAdapter.apply_remedy(remedy(ow, host_key, "lldp")))
        assert (await shell(ow, host_key, "pidof lldpd >/dev/null && echo up\n")).strip() == "up"
        again = await OpenWrtAdapter.plan_remedy(remedy(ow, host_key, "lldp"))
        assert {s.id: s.state for s in again.steps}["lldpd"] is StepState.UNCHANGED
    finally:
        await shell(ow, host_key, "/etc/init.d/lldpd start\n")
