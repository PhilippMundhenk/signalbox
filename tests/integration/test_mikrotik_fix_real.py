"""*Fix it* (#267) against the real RouterOS CHR: break a policy, then fix it; break the REST
service (address list, certificate), then fix it over SSH.

Runs as a CI step of its own after the automatic setup tests. Every test restores what it broke,
so the other MikroTik tests find the router as the image preparation left it.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import (
    AdapterContext,
    RemedyRequest,
    SetupRequest,
    StepState,
    Unreachable,
)
from signalbox.adapters.https import DeviceHttp, peer_certificate
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig, get_menu
from signalbox.adapters.mikrotik.provision import READ_POLICY
from signalbox.adapters.ssh import PinnedSsh
from signalbox.model import DeviceRole, DeviceStatus

from .conftest import Target

LOGIN = "signalbox-fix"
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def chr_(target: Callable[[str], Target]) -> Target:
    t = target("mikrotik")
    assert t.pin and t.extra.get("ADMIN_PASSWORD") and t.extra.get("SSH_PORT")
    return t


def admin_http(t: Target) -> DeviceHttp:
    return DeviceHttp(
        t.url,
        pinned_fingerprint=t.pin,
        timeout=60,
        auth=("admin", t.extra["ADMIN_PASSWORD"]),
    )


def remedy(t: Target, name: str, trust: str | None, **kw: Any) -> RemedyRequest:
    return RemedyRequest(
        remedy=name,
        config={"url": t.url, "username": LOGIN},
        admin_user="admin",
        admin_secret=SecretStr(t.extra["ADMIN_PASSWORD"]),
        allow_writes=kw.pop("allow_writes", False),
        port=kw.pop("port", None),
        trust=trust,
        timeout=60,
    )


async def read_as(t: Target, password: str) -> Any:
    a = MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id="chr",
            device_name="CHR",
            role=DeviceRole.GATEWAY,
            config=MikrotikConfig(url=t.url, username=LOGIN, password=SecretStr(password)),
            pinned_fingerprint=t.pin,
            timeout=20,
        )
    )
    try:
        return await a.observe()
    finally:
        await a.close()


async def test_policies_broken_then_fixed(chr_: Target) -> None:
    result = await MikrotikAdapter.apply_setup(
        SetupRequest(
            config={"url": chr_.url, "username": LOGIN},
            admin_user="admin",
            admin_secret=SecretStr(chr_.extra["ADMIN_PASSWORD"]),
            trust=chr_.pin,
            timeout=60,
        )
    )
    assert result.ok
    password = result.secrets["password"].get_secret_value()
    http = admin_http(chr_)
    try:
        groups = await get_menu(http, "/rest/user/group")
        gid = next(g[".id"] for g in groups if g["name"] == "signalbox-read")
        broken = "read,!api,!rest-api,!write,!policy,!password,!sensitive,!reboot,!test,!sniff"
        await http.request("PATCH", f"/rest/user/group/{gid}", json={"policy": broken})
        try:
            snap = await read_as(chr_, password)
            assert snap.status is not DeviceStatus.OK, "the broken group still reads"

            plan = await MikrotikAdapter.plan_remedy(remedy(chr_, "policies", chr_.pin))
            assert plan.steps[0].state is StepState.TODO, plan.steps
            done = await MikrotikAdapter.apply_remedy(remedy(chr_, "policies", chr_.pin))
            assert done.ok, [(s.id, s.state, s.message) for s in done.steps]
            snap = await read_as(chr_, password)
            assert snap.status in (DeviceStatus.OK, DeviceStatus.PARTIAL), snap.errors
            again = await MikrotikAdapter.plan_remedy(remedy(chr_, "policies", chr_.pin))
            assert again.steps[0].state is StepState.UNCHANGED
        finally:
            await http.request("PATCH", f"/rest/user/group/{gid}", json={"policy": READ_POLICY})
    finally:
        await http.close()
        await MikrotikAdapter.apply_setup(
            SetupRequest(
                config={"url": chr_.url, "username": LOGIN},
                admin_user="admin",
                admin_secret=SecretStr(chr_.extra["ADMIN_PASSWORD"]),
                trust=chr_.pin,
                timeout=60,
                remove=True,
            )
        )


@pytest.fixture
async def ssh(chr_: Target) -> AsyncIterator[tuple[PinnedSsh, str]]:
    """An admin SSH session (host key read first) and the service's original settings."""
    port = int(chr_.extra["SSH_PORT"])
    probe = await MikrotikAdapter.plan_remedy(remedy(chr_, "rest-service", None, port=port))
    assert not probe.trusted
    session = PinnedSsh(
        "127.0.0.1", port, "admin", chr_.extra["ADMIN_PASSWORD"], probe.fingerprint, 60
    )
    async with session as s:
        got = await s.command(":put [/ip service get www-ssl available-from]")
        original = ",".join(a for a in re.split(r"[,;\s]+", got.text.strip()) if a)
        yield s, probe.fingerprint
        restore = "/ip service set www-ssl certificate=signalbox-www disabled=no"
        await s.command(f"{restore} address={original}" if original else f'{restore} address=""')
        back = await s.command(":put [/ip service get www-ssl available-from]")
        assert re.split(r"[,;\s]+", back.text.strip()) == original.split(",")


async def rest_reachable(t: Target) -> bool:
    try:
        await peer_certificate(t.host, t.port, 5)
    except Unreachable:
        return False
    return True


async def test_service_address_and_certificate_fixed_over_ssh(
    chr_: Target, ssh: tuple[PinnedSsh, str]
) -> None:
    session, fingerprint = ssh
    port = int(chr_.extra["SSH_PORT"])
    # an address list that excludes the router's view of this machine: nothing answers
    await session.command("/ip service set www-ssl address=203.0.113.9/32")
    assert not await rest_reachable(chr_)
    plan = await MikrotikAdapter.plan_remedy(remedy(chr_, "rest-service", fingerprint, port=port))
    states = {s.id: s.state for s in plan.steps}
    assert states["www-ssl"] is StepState.TODO and "203.0.113.9/32" in plan.steps[-2].detail
    done = await MikrotikAdapter.apply_remedy(remedy(chr_, "rest-service", fingerprint, port=port))
    assert done.ok, [(s.id, s.state, s.message) for s in done.steps]
    assert await rest_reachable(chr_)

    # no certificate: the existing signalbox-www is set again (the pin stays the same)
    await session.command("/ip service set www-ssl certificate=none")
    plan = await MikrotikAdapter.plan_remedy(remedy(chr_, "rest-service", fingerprint, port=port))
    assert {s.id: s.state for s in plan.steps}["www-ssl"] is StepState.TODO
    done = await MikrotikAdapter.apply_remedy(remedy(chr_, "rest-service", fingerprint, port=port))
    assert done.ok, [(s.id, s.state, s.message) for s in done.steps]
    http = admin_http(chr_)
    try:
        assert await get_menu(http, "/rest/system/resource")
    finally:
        await http.close()
    again = await MikrotikAdapter.plan_remedy(remedy(chr_, "rest-service", fingerprint, port=port))
    assert all(s.state is StepState.UNCHANGED for s in again.steps), again.steps
