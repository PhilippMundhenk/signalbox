"""Automatic setup of OpenWrt over SSH (#231) against the simulated router."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import (
    AdapterError,
    AuthFailed,
    SetupRequest,
    StepState,
    Unreachable,
    UntrustedHostKey,
)
from signalbox.adapters.openwrt import OpenWrtAdapter
from signalbox.adapters.openwrt.provision import (
    ACL_PATH,
    certificate_fingerprint,
    md5_crypt,
    parse_logins,
)
from signalbox.adapters.openwrt.setup import READ_ACL, WRITE_ACL
from signalbox.adapters.provision import Redactor, same_fingerprint
from signalbox.sim.openwrt import OpenWrtSim
from signalbox.sim.openwrt_ssh import ROOT_PASSWORD, OpenWrtSsh, serve_ssh
from signalbox.sim.server import free_port

DOCS = Path(__file__).parent.parent / "docs" / "adapters" / "openwrt.md"


@pytest.fixture
def device() -> OpenWrtSsh:
    return OpenWrtSsh(http=OpenWrtSim(), certificate=b"\x30\x82fake-der")


@pytest.fixture
async def ssh(device: OpenWrtSsh) -> AsyncIterator[tuple[int, str]]:
    async with serve_ssh(device) as served:
        yield served


def request(port: int, trust: str | None, **kw: Any) -> SetupRequest:
    config = kw.pop("config", {"url": "192.0.2.2", "username": "signalbox"})
    return SetupRequest(
        config=config,
        admin_user=kw.pop("user", "root"),
        admin_secret=SecretStr(kw.pop("secret", ROOT_PASSWORD)),
        port=port,
        trust=trust,
        timeout=10,
        **kw,
    )


def local(req: SetupRequest) -> SetupRequest:
    """The simulator listens on 127.0.0.1 (the address of the settings is a documentation one)."""
    return req.model_copy(update={"config": {**req.config, "url": "127.0.0.1"}})


def test_md5_crypt_matches_openssl() -> None:
    # openssl passwd -1 -salt abcdefgh p4ss-W0rd
    assert md5_crypt("p4ss-W0rd", "abcdefgh") == "$1$abcdefgh$ICSXZS6Mrcq5lA4ugMRFp0"
    assert md5_crypt("a" * 40, "xy") == "$1$xy$pUub5uX9loeQqtCXjIwBI0"


def test_write_acl_is_the_documented_one() -> None:
    text = DOCS.read_text()
    block = re.search(r"```json\n(.*?)```", text.split("### Login with write access", 1)[1], re.S)
    assert block and json.loads(block.group(1)) == WRITE_ACL
    assert WRITE_ACL["signalbox"]["read"] == READ_ACL["signalbox"]["read"]


def test_parse_logins_and_certificate() -> None:
    text = (
        "rpcd.cfg01=rpcd\nrpcd.cfg01.socket='/var/run/ubus/ubus.sock'\n"
        "rpcd.cfg02=login\nrpcd.cfg02.username='signalbox'\nrpcd.cfg02.read='signalbox' 'x'\n"
        "rpcd.cfg03=login\nrpcd.cfg03.username='it'\\''s'\nbroken\nrpcd.cfg03.read='unclosed\nrpcd.x$(reboot)=login\n"
    )
    logins = parse_logins(text)
    assert [(x.section, x.username, x.read) for x in logins] == [
        ("cfg02", "signalbox", ["signalbox", "x"]),
        ("cfg03", "it's", []),
    ]
    der = b"\x30\x82\x01\x02"
    assert certificate_fingerprint(der) == hashlib.sha256(der).hexdigest()
    assert certificate_fingerprint(b"") is None
    assert certificate_fingerprint(b"-----BEGIN CERTIFICATE-----\n!!\n") is None


def test_redactor_and_fingerprints() -> None:
    redact = Redactor()
    redact.add("abc", None, "s3cret-value")
    assert redact("x s3cret-value y abc") == "x *** y ***"
    assert same_fingerprint("SHA256:AbC=", "sha256:AbC")
    assert not same_fingerprint("SHA256:AbC", "SHA256:abc")
    assert same_fingerprint("AB:CD", "abcd")
    assert not same_fingerprint(None, "abcd")


async def test_untrusted_host_key_sends_no_password(
    ssh: tuple[int, str], device: OpenWrtSsh
) -> None:
    port, fingerprint = ssh
    plan = await OpenWrtAdapter.plan_setup(local(request(port, None)))
    assert not plan.trusted and plan.fingerprint == fingerprint and not plan.steps
    assert plan.fingerprint_kind == "ssh-host-key" and "dropbearkey" in plan.compare
    assert device.scripts == []
    other = await OpenWrtAdapter.plan_setup(local(request(port, "SHA256:" + "A" * 43)))
    assert not other.trusted
    with pytest.raises(UntrustedHostKey):
        await OpenWrtAdapter.apply_setup(local(request(port, None)))


async def test_plan_changes_nothing(ssh: tuple[int, str], device: OpenWrtSsh) -> None:
    port, fingerprint = ssh
    device.installed.discard("rpcd-mod-luci")
    plan = await OpenWrtAdapter.plan_setup(local(request(port, fingerprint)))
    assert plan.trusted
    steps = {s.id: s for s in plan.steps}
    assert steps["packages"].state is StepState.TODO
    assert steps["packages"].detail == "apk update && apk add rpcd-mod-luci\n"
    assert steps["acl"].state is StepState.TODO and '"luci.lldpd"' in steps["acl"].detail
    assert "Create the rpcd login signalbox (read-only)" in steps["login"].title
    assert "password='***'" in steps["login"].detail
    assert (
        steps["certificate"].detail
        == f"SHA-256 {hashlib.sha256(device.certificate or b'').hexdigest()}"
    )
    assert ACL_PATH not in device.files and len(device.rpcd) == 1
    assert device.restarts == []


async def test_setup_read_only_then_writes_then_remove(
    ssh: tuple[int, str], device: OpenWrtSsh
) -> None:
    port, fingerprint = ssh
    device.manager = "opkg"
    device.installed = {"uhttpd", "rpcd", "luci"}
    result = await OpenWrtAdapter.apply_setup(local(request(port, fingerprint)))
    assert result.ok, result.steps
    assert [s.state for s in result.steps] == [StepState.DONE] * 5
    assert {"uhttpd-mod-ubus", "rpcd-mod-file", "rpcd-mod-luci"} <= device.installed
    assert json.loads(device.files[ACL_PATH]) == READ_ACL
    assert device.restarts == ["rpcd", "uhttpd"]
    password = result.secrets["password"].get_secret_value()
    assert len(password) == 32 and result.settings == {
        "url": "https://127.0.0.1/ubus",
        "username": "signalbox",
    }
    assert result.certificate == hashlib.sha256(device.certificate or b"").hexdigest()
    login = next(s for s in device.rpcd.values() if s["options"].get("username") == ["signalbox"])
    assert login["options"]["read"] == ["signalbox"] and "write" not in login["options"]
    assert login["options"]["password"][0].startswith("$1$")
    # nothing secret in clear on the wire's scripts or in the report
    assert all(password not in s for s in device.scripts)
    assert all(password not in s.detail + s.message for s in result.steps)
    assert all(ROOT_PASSWORD not in s.detail + s.message for s in result.steps)
    # the HTTP side accepts the new login
    http = device.http
    assert http is not None and http._known("signalbox", password)
    assert not http._known("signalbox", "wrong") and not http._known("nobody", password)

    # again with changes allowed: ACL with write part, login lists write, nothing installed
    device.restarts.clear()
    again = await OpenWrtAdapter.apply_setup(local(request(port, fingerprint, allow_writes=True)))
    assert again.ok
    states = {s.id: s.state for s in again.steps}
    assert states["packages"] is StepState.UNCHANGED and states["acl"] is StepState.DONE
    assert json.loads(device.files[ACL_PATH]) == WRITE_ACL
    logins = [s for s in device.rpcd.values() if s["options"].get("username") == ["signalbox"]]
    assert len(logins) == 1 and logins[0]["options"]["write"] == ["signalbox"]
    assert device.restarts == ["rpcd"]
    assert again.secrets["password"].get_secret_value() != password

    # back to read-only: write list gone
    down = await OpenWrtAdapter.apply_setup(local(request(port, fingerprint)))
    assert down.ok and "write" not in logins[0]["options"]

    # remove: login and ACL file go, packages stay
    plan = await OpenWrtAdapter.plan_setup(local(request(port, fingerprint, remove=True)))
    assert [s.state for s in plan.steps] == [StepState.TODO] * 3 + [StepState.UNCHANGED]
    gone = await OpenWrtAdapter.apply_setup(local(request(port, fingerprint, remove=True)))
    assert gone.ok and not gone.secrets and not gone.settings
    assert ACL_PATH not in device.files and list(device.rpcd) == ["cfg01"]
    assert "rpcd-mod-luci" in device.installed
    # nothing left: removing again changes nothing
    twice = await OpenWrtAdapter.apply_setup(local(request(port, fingerprint, remove=True)))
    assert [s.state for s in twice.steps] == [StepState.UNCHANGED] * 4


async def test_remove_keeps_an_acl_other_logins_use(
    ssh: tuple[int, str], device: OpenWrtSsh
) -> None:
    port, fingerprint = ssh
    device.files[ACL_PATH] = json.dumps(WRITE_ACL).encode()
    device.rpcd["cfg02"] = {
        "type": "login",
        "options": {"username": ["signalbox-write"], "read": ["signalbox"], "write": ["signalbox"]},
    }
    device.rpcd["cfg03"] = {"type": "login", "options": {"username": ["signalbox"]}}
    device.rpcd["cfg04"] = {"type": "login", "options": {"username": ["signalbox"]}}
    plan = await OpenWrtAdapter.plan_setup(local(request(port, fingerprint, allow_writes=True)))
    steps = {s.id: s for s in plan.steps}
    assert steps["acl"].state is StepState.UNCHANGED
    assert "Update the rpcd login" in steps["login"].title
    assert "uci delete rpcd.cfg04" in steps["login"].detail
    done = await OpenWrtAdapter.apply_setup(local(request(port, fingerprint, allow_writes=True)))
    assert done.ok and "cfg04" not in device.rpcd
    gone = await OpenWrtAdapter.apply_setup(local(request(port, fingerprint, remove=True)))
    acl = next(s for s in gone.steps if s.id == "acl")
    assert acl.state is StepState.UNCHANGED and "signalbox-write" in acl.message
    assert ACL_PATH in device.files and "cfg03" not in device.rpcd


async def test_failure_stops_and_is_reported(ssh: tuple[int, str], device: OpenWrtSsh) -> None:
    port, fingerprint = ssh
    device.installed.discard("rpcd-mod-file")
    device.offline = True
    result = await OpenWrtAdapter.apply_setup(local(request(port, fingerprint)))
    assert not result.ok and not result.secrets
    assert [s.state for s in result.steps][:3] == [
        StepState.FAILED,
        StepState.SKIPPED,
        StepState.SKIPPED,
    ]
    assert "unable to fetch" in result.steps[0].message
    assert ACL_PATH not in device.files


async def test_errors(ssh: tuple[int, str], device: OpenWrtSsh) -> None:
    port, fingerprint = ssh
    with pytest.raises(AuthFailed) as refused:
        await OpenWrtAdapter.plan_setup(local(request(port, fingerprint, secret="wrong-secret")))
    assert "wrong-secret" not in str(refused.value)
    with pytest.raises(Unreachable):
        await OpenWrtAdapter.plan_setup(local(request(free_port(), fingerprint)))
    for config, text in (
        ({}, "address"),
        ({"url": "ftp://x"}, "address"),
        ({"url": "192.0.2.2", "username": "root"}, "must not be the admin"),
        ({"url": "192.0.2.2", "username": "Bad Name"}, "lower-case"),
    ):
        with pytest.raises(AdapterError, match=text):
            await OpenWrtAdapter.plan_setup(request(port, fingerprint, config=config))
    # not OpenWrt: the inspection does not answer as expected
    device.run = lambda script: (0, b"hello", "")  # type: ignore[method-assign]
    with pytest.raises(AdapterError, match="did not answer like OpenWrt"):
        await OpenWrtAdapter.apply_setup(local(request(port, fingerprint)))


async def test_unknown_command_fails_the_step(ssh: tuple[int, str], device: OpenWrtSsh) -> None:
    assert ssh
    assert device.run("frobnicate")[0] == 127
    assert device.run("uci set rpcd.nope.x='1'")[0] == 1
    assert device.run("uci -q delete rpcd.cfg01.nothing")[0] == 1
    assert device.run("uci frob rpcd.cfg01")[0] == 1
    assert device.run("uci set")[0] == 1
    http = OpenWrtSim()
    assert not http._known("x", None)


async def test_http_certificate_is_not_read(ssh: tuple[int, str], device: OpenWrtSsh) -> None:
    port, fingerprint = ssh
    req = request(port, fingerprint, config={"url": "http://127.0.0.1", "username": "sb"})
    plan = await OpenWrtAdapter.plan_setup(req)
    assert "certificate" not in {s.id for s in plan.steps}
