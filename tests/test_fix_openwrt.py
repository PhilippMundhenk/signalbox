"""Fix it on OpenWrt over SSH (#215) against the simulated router: the remedies' steps."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterError, RemedyRequest, StepState, UntrustedHostKey
from signalbox.adapters.openwrt import OpenWrtAdapter
from signalbox.adapters.openwrt.provision import ACL_PATH
from signalbox.adapters.openwrt.setup import READ_ACL, WRITE_ACL
from signalbox.sim.openwrt import OpenWrtSim
from signalbox.sim.openwrt_ssh import LLDP_PACKAGES, ROOT_PASSWORD, OpenWrtSsh, serve_ssh

STORED = "stored-login-password"


def login(name: str, read: list[str], write: list[str] | None = None) -> dict[str, Any]:
    options = {"username": [name], "password": ["$1$x$y"], "read": read}
    if write is not None:
        options["write"] = write
    return {"type": "login", "options": options}


@pytest.fixture
def device() -> OpenWrtSsh:
    dev = OpenWrtSsh(http=OpenWrtSim())
    dev.rpcd["cfg02"] = login("signalbox", ["signalbox"], ["signalbox"])
    dev.files[ACL_PATH] = json.dumps(WRITE_ACL).encode()
    return dev


@pytest.fixture
async def ssh(device: OpenWrtSsh) -> AsyncIterator[tuple[int, str]]:
    async with serve_ssh(device) as served:
        yield served


def request(port: int, trust: str | None, remedy: str = "access", **kw: Any) -> RemedyRequest:
    return RemedyRequest(
        remedy=remedy,
        config=kw.pop("config", {"url": "127.0.0.1", "username": "signalbox"}),
        secrets={"password": SecretStr(STORED)},
        admin_user="root",
        admin_secret=SecretStr(kw.pop("secret", ROOT_PASSWORD)),
        port=port,
        allow_writes=kw.pop("allow_writes", True),
        trust=trust,
        timeout=10,
    )


def states(steps: list[Any]) -> dict[str, StepState]:
    return {s.id: s.state for s in steps}


async def test_untrusted_host_key_sends_nothing(ssh: tuple[int, str], device: OpenWrtSsh) -> None:
    port, fingerprint = ssh
    plan = await OpenWrtAdapter.plan_remedy(request(port, None))
    assert not plan.trusted and plan.fingerprint == fingerprint and not plan.steps
    assert device.scripts == []
    with pytest.raises(UntrustedHostKey):
        await OpenWrtAdapter.apply_remedy(request(port, None))


async def test_access_rewrites_an_outdated_acl_and_keeps_the_password(
    ssh: tuple[int, str], device: OpenWrtSsh
) -> None:
    port, fingerprint = ssh
    old = json.loads(json.dumps(WRITE_ACL))
    old["signalbox"]["read"]["ubus"].pop("luci-rpc")
    device.files[ACL_PATH] = json.dumps(old).encode()
    assert device.http is not None
    device.http.denied = {"luci-rpc.getNetworkDevices"}
    password = device.rpcd["cfg02"]["options"]["password"]

    plan = await OpenWrtAdapter.plan_remedy(request(port, fingerprint))
    assert plan.trusted
    assert states(plan.steps) == {
        "packages": StepState.UNCHANGED,
        "acl": StepState.TODO,
        "login": StepState.UNCHANGED,
        "restart": StepState.TODO,
    }
    assert json.loads(device.files[ACL_PATH]) == old, "the plan changes nothing"

    result = await OpenWrtAdapter.apply_remedy(request(port, fingerprint))
    assert result.ok, result.steps
    assert result.settings == {} and result.secrets == {} and result.certificate is None
    assert json.loads(device.files[ACL_PATH]) == WRITE_ACL
    assert device.rpcd["cfg02"]["options"]["password"] == password
    assert device.restarts == ["rpcd"] and device.http.denied == set()
    for script in device.scripts:
        assert ROOT_PASSWORD not in script and STORED not in script

    # read-only device: the ACL without the write part; nothing else needed
    again = await OpenWrtAdapter.plan_remedy(request(port, fingerprint, allow_writes=False))
    assert states(again.steps)["acl"] is StepState.TODO
    done = await OpenWrtAdapter.apply_remedy(request(port, fingerprint, allow_writes=False))
    assert done.ok and json.loads(device.files[ACL_PATH]) == READ_ACL


async def test_access_installs_missing_packages_and_lists_the_acl_group(
    ssh: tuple[int, str], device: OpenWrtSsh
) -> None:
    port, fingerprint = ssh
    device.installed.discard("rpcd-mod-luci")
    device.rpcd["cfg02"] = login("signalbox", [])
    result = await OpenWrtAdapter.apply_remedy(request(port, fingerprint))
    assert result.ok, result.steps
    assert states(result.steps) == {
        "packages": StepState.DONE,
        "acl": StepState.UNCHANGED,
        "login": StepState.DONE,
        "restart": StepState.DONE,
    }
    assert "rpcd-mod-luci" in device.installed
    assert device.rpcd["cfg02"]["options"]["read"] == ["signalbox"]
    assert device.rpcd["cfg02"]["options"]["write"] == ["signalbox"]
    assert device.restarts == ["rpcd", "uhttpd"]


async def test_root_login_and_missing_login(ssh: tuple[int, str], device: OpenWrtSsh) -> None:
    port, fingerprint = ssh
    root = await OpenWrtAdapter.plan_remedy(
        request(port, fingerprint, config={"url": "127.0.0.1", "username": "root"})
    )
    login_step = next(s for s in root.steps if s.id == "login")
    assert login_step.state is StepState.UNCHANGED and "root" in login_step.message
    with pytest.raises(AdapterError, match="no rpcd login 'ghost'") as err:
        await OpenWrtAdapter.plan_remedy(
            request(port, fingerprint, config={"url": "127.0.0.1", "username": "ghost"})
        )
    assert err.value.fix and "Set the device up again" in err.value.fix
    with pytest.raises(AdapterError, match="no remedy"):
        await OpenWrtAdapter.plan_remedy(request(port, fingerprint, remedy="network"))


async def test_lldp_installs_and_starts_lldpd(ssh: tuple[int, str], device: OpenWrtSsh) -> None:
    port, fingerprint = ssh
    device.installed -= LLDP_PACKAGES
    device.lldpd_running = False
    assert device.http is not None
    device.http.lldpd = False
    plan = await OpenWrtAdapter.plan_remedy(request(port, fingerprint, remedy="lldp"))
    assert [s.id for s in plan.steps] == ["lldp-packages", "lldpd", "acl", "login", "restart"]
    assert "apk add lldpd luci-app-lldpd" in plan.steps[0].detail
    assert plan.steps[0].state is StepState.TODO and plan.steps[1].state is StepState.TODO

    result = await OpenWrtAdapter.apply_remedy(request(port, fingerprint, remedy="lldp"))
    assert result.ok, result.steps
    assert device.installed >= LLDP_PACKAGES and device.lldpd_running and device.http.lldpd

    again = await OpenWrtAdapter.plan_remedy(request(port, fingerprint, remedy="lldp"))
    assert states(again.steps)["lldp-packages"] is StepState.UNCHANGED
    assert states(again.steps)["lldpd"] is StepState.UNCHANGED


async def test_lldp_offline_stops_at_the_install(ssh: tuple[int, str], device: OpenWrtSsh) -> None:
    port, fingerprint = ssh
    device.installed -= LLDP_PACKAGES
    device.manager = "opkg"
    device.offline = True
    result = await OpenWrtAdapter.apply_remedy(request(port, fingerprint, remedy="lldp"))
    assert not result.ok
    assert "opkg install lldpd luci-app-lldpd" in result.steps[0].detail
    assert states(result.steps) == {
        "lldp-packages": StepState.FAILED,
        "lldpd": StepState.SKIPPED,
        "acl": StepState.UNCHANGED,
        "login": StepState.UNCHANGED,
        "restart": StepState.SKIPPED,
    }
    assert device.restarts == []


async def test_errors_are_redacted(ssh: tuple[int, str], device: OpenWrtSsh) -> None:
    port, fingerprint = ssh
    device.rpcd["cfg02"] = login("signalbox", [])
    device.rpcd["cfg02"]["options"]["read"] = []

    original = device._uci

    def echo(words: list[str]) -> tuple[int, str]:
        if words[:1] == ["add_list"]:
            return 1, f"uci: refused ({STORED} {ROOT_PASSWORD})"
        return original(words)

    device._uci = echo  # type: ignore[method-assign]
    result = await OpenWrtAdapter.apply_remedy(request(port, fingerprint))
    failed = next(s for s in result.steps if s.state is StepState.FAILED)
    assert failed.id == "login" and STORED not in failed.message
    assert ROOT_PASSWORD not in failed.message and "***" in failed.message
