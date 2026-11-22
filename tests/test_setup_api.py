"""POST /api/devices/setup and /api/devices/setup/apply (#231) with the OpenWrt simulators."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from factories import SITE
from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterContractError,
    AdminLogin,
    Manifest,
    SetupPlan,
    SetupRequest,
    SetupResult,
    SystemInfo,
    UntrustedHostKey,
    check_setup,
)
from signalbox.adapters.openwrt import OpenWrtAdapter
from signalbox.model import DeviceRole
from signalbox.service import Services, build
from signalbox.sim.openwrt import OpenWrtSim, create_app
from signalbox.sim.openwrt_ssh import ROOT_PASSWORD, OpenWrtSsh, serve_ssh_in_thread
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve
from signalbox.web.app import create_app as web_app
from test_runner import Dev

PW = "correct-horse-battery"


class Broken(Dev):
    """Declares an admin login but raises (no setup hooks of its own: checked separately)."""

    manifest = Dev.manifest.model_copy(
        update={"id": "broken", "admin_login": AdminLogin(transport="none")}
    )

    @classmethod
    async def plan_setup(cls, request: SetupRequest) -> SetupPlan:
        raise UntrustedHostKey("SHA256:" + "B" * 43, request.trust)

    @classmethod
    async def apply_setup(cls, request: SetupRequest) -> SetupResult:
        if request.remove:
            return SetupResult(ok=False, steps=[])
        raise UntrustedHostKey("SHA256:" + "B" * 43, request.trust)


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> TlsFiles:
    return self_signed_certificate(tmp_path_factory.mktemp("tls"))


@pytest.fixture
def http() -> OpenWrtSim:
    return OpenWrtSim()


@pytest.fixture
def https_url(http: OpenWrtSim, tls: TlsFiles) -> Iterator[str]:
    with serve(create_app(http), tls=tls) as url:
        yield url


@pytest.fixture
def device(http: OpenWrtSim, tls: TlsFiles) -> OpenWrtSsh:
    return OpenWrtSsh(http=http, certificate=tls.cert.read_bytes())


@pytest.fixture
def ssh(device: OpenWrtSsh) -> Iterator[tuple[int, str]]:
    with serve_ssh_in_thread(device) as served:
        yield served


@pytest.fixture
def services(tmp_path: Path) -> Iterator[Services]:
    svc = build(
        tmp_path,
        env={"SIGNALBOX_AUTH_PASSWORD": PW},
        adapters={"openwrt": OpenWrtAdapter, "dev": Dev, "broken": Broken},
        rules=[],
        link_sources=[],
    )
    svc.store.put_site(SITE)
    yield svc
    svc.close()


@pytest.fixture
def client(services: Services) -> Iterator[TestClient]:
    with TestClient(web_app(services, run_background=False)) as c:
        assert c.post("/api/login", json={"password": PW}).status_code == 200
        yield c


def body(url: str, port: int, **kw: Any) -> dict[str, Any]:
    device = {
        "name": "Access point",
        "site_id": "home",
        "role": "ap",
        "adapter": "openwrt",
        "allow_writes": kw.pop("allow_writes", False),
        "config": {"url": url, "username": "signalbox", "password": ""},
        **kw.pop("device", {}),
    }
    return {
        "device": device,
        "admin": {"user": "root", "secret": kw.pop("secret", ROOT_PASSWORD), "port": port},
        **kw,
    }


def test_adapters_list_the_admin_login(client: TestClient) -> None:
    info = {a["id"]: a for a in client.get("/api/adapters").json()}
    assert info["openwrt"]["admin_login"]["port_default"] == 22
    assert info["dev"]["admin_login"] is None


def test_plan_trust_apply_read_remove(
    client: TestClient,
    services: Services,
    ssh: tuple[int, str],
    https_url: str,
    tls: TlsFiles,
    device: OpenWrtSsh,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    port, fingerprint = ssh
    first = client.post("/api/devices/setup", json=body(https_url, port))
    assert first.status_code == 200
    plan = first.json()
    assert plan == {
        "fingerprint": fingerprint,
        "fingerprint_kind": "ssh-host-key",
        "trusted": False,
        "compare": plan["compare"],
        "steps": [],
    }
    planned = client.post("/api/devices/setup", json=body(https_url, port, trust=fingerprint))
    steps = planned.json()["steps"]
    assert [s["id"] for s in steps] == ["packages", "acl", "login", "restart", "certificate"]
    assert services.store.devices() == []

    done = client.post("/api/devices/setup/apply", json=body(https_url, port, trust=fingerprint))
    assert done.status_code == 200, done.text
    res = done.json()
    assert res["ok"] and res["device"]["id"] == "access-point"
    assert res["device"]["pinned_fingerprint"] == tls.fingerprint
    assert res["device"]["secrets_set"] == ["password"]
    rec = services.store.device("access-point")
    assert rec is not None and rec.config["username"] == "signalbox"
    # the new login reads the router over the pinned certificate
    read = client.post("/api/devices/access-point/test").json()
    assert read["status"] == "ok", read
    # no secret in any answer or log line
    stored = services.store.adapter_config("access-point", OpenWrtAdapter.manifest.config)
    password = stored.password.get_secret_value()  # type: ignore[attr-defined]
    for text in (first.text, planned.text, done.text, caplog.text):
        assert password not in text and ROOT_PASSWORD not in text
    assert "automatic setup of access-point (openwrt): done" in caplog.text

    # editing: again with changes allowed updates the same device
    edit = body(https_url, port, trust=fingerprint, allow_writes=True)
    edit["device"]["device_id"] = "access-point"
    again = client.post("/api/devices/setup/apply", json=edit).json()
    assert again["ok"] and again["device"]["allow_writes"] is True
    assert [d.id for d in services.store.devices()] == ["access-point"]

    gone = client.post(
        "/api/devices/setup/apply", json=body(https_url, port, trust=fingerprint, remove=True)
    ).json()
    assert gone["ok"] and gone["device"] is None
    assert client.post("/api/devices/access-point/test").json()["status"] == "auth-failed"


def test_refusals(client: TestClient, ssh: tuple[int, str], https_url: str) -> None:
    port, fingerprint = ssh
    cases = [
        (body(https_url, port, device={"adapter": "nope"}), 422, "not installed"),
        (body(https_url, port, device={"adapter": "dev", "role": "gateway"}), 422, "cannot be set"),
        (body(https_url, port, device={"role": "other"}), 422, "devices can be"),
        (body(https_url, port, device={"device_id": "ghost"}), 404, "No such device"),
        (body(https_url, port, trust="nope"), 422, "trust"),
        (body(https_url, port, secret=""), 422, "secret"),
    ]
    for payload, code, text in cases:
        r = client.post("/api/devices/setup", json=payload)
        assert r.status_code == code and text in r.json()["message"], (payload, r.text)
    no_trust = client.post("/api/devices/setup/apply", json=body(https_url, port))
    assert no_trust.status_code == 422 and "fingerprint" in no_trust.json()["message"]
    bad_form = body(https_url, port, trust=fingerprint, device={"config": {"url": ""}})
    r = client.post("/api/devices/setup/apply", json=bad_form)
    assert r.status_code == 422 and "url" in r.json()["message"]
    wrong = client.post(
        "/api/devices/setup", json=body(https_url, port, trust=fingerprint, secret="not-it-x")
    )
    assert wrong.status_code == 422 and wrong.json()["error"] == "auth_failed"
    assert "not-it-x" not in wrong.text
    gone = client.post("/api/devices/setup", json=body(https_url, 1, trust=fingerprint))
    assert gone.json()["error"] == "unreachable"
    other = client.post(
        "/api/devices/setup",
        json=body(
            https_url, port, trust=fingerprint, device={"config": {"url": "x", "username": "root"}}
        ),
    )
    assert other.json()["error"] == "setup_failed"
    changed = client.post(
        "/api/devices/setup/apply", json=body(https_url, port, trust="SHA256:" + "A" * 43)
    )
    assert changed.status_code == 409 and changed.json()["fingerprint"] == fingerprint
    broken = body(
        https_url,
        port,
        trust=fingerprint,
        device={"adapter": "broken", "role": "gateway", "config": {"url": "ok"}},
    )
    assert client.post("/api/devices/setup", json=broken).status_code == 409
    assert client.post("/api/devices/setup/apply", json=broken).status_code == 409
    removed = client.post("/api/devices/setup/apply", json={**broken, "remove": True}).json()
    assert removed == {"ok": False, "steps": [], "device": None}


def test_failed_setup_saves_nothing(
    client: TestClient, services: Services, ssh: tuple[int, str], https_url: str, device: OpenWrtSsh
) -> None:
    port, fingerprint = ssh
    device.installed.discard("rpcd-mod-luci")
    device.offline = True
    res = client.post("/api/devices/setup/apply", json=body(https_url, port, trust=fingerprint))
    assert res.status_code == 200 and res.json()["ok"] is False
    assert res.json()["steps"][0]["state"] == "failed" and services.store.devices() == []


def test_setup_hooks_are_required() -> None:
    class Half(Adapter):
        manifest = Manifest(
            id="half",
            name="Half",
            version="1",
            api_version="1.2",
            vendor="x",
            roles=frozenset({DeviceRole.OTHER}),
            capabilities=frozenset(),
            config=AdapterConfig,
            admin_login=AdminLogin(transport="x"),
        )

        async def read_system(self) -> SystemInfo:
            return SystemInfo()

    with pytest.raises(AdapterContractError, match="plan_setup"):
        check_setup(Half)
    check_setup(Dev)
    check_setup(OpenWrtAdapter)


async def test_default_hooks_raise() -> None:
    from pydantic import SecretStr

    req = SetupRequest(admin_user="a", admin_secret=SecretStr("b"))
    with pytest.raises(NotImplementedError):
        await Dev.plan_setup(req)
    with pytest.raises(NotImplementedError):
        await Dev.apply_setup(req)
