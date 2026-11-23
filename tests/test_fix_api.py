"""POST /api/devices/{id}/fix and /fix/apply (#215) with the OpenWrt simulators: a read gap
names its remedy, the plan shows the steps, the fix runs and the device is read again."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from factories import SITE
from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterContractError,
    AdminLogin,
    Manifest,
    Remedy,
    RemedyRequest,
    SetupPlan,
    SetupRequest,
    SetupResult,
    SystemInfo,
    check_setup,
)
from signalbox.adapters.openwrt import OpenWrtAdapter
from signalbox.adapters.openwrt.provision import ACL_PATH
from signalbox.adapters.openwrt.setup import WRITE_ACL
from signalbox.model import DeviceRole, Network, ReadError
from signalbox.rules import READ_ERRORS, evaluate
from signalbox.service import Services, build
from signalbox.sim.openwrt import OpenWrtSim, create_app
from signalbox.sim.openwrt_ssh import LLDP_PACKAGES, ROOT_PASSWORD, OpenWrtSsh, serve_ssh_in_thread
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve
from signalbox.web.app import create_app as web_app
from test_runner import Dev

PW = "correct-horse-battery"


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


def make_services(path: Path, **env: str) -> Services:
    svc = build(
        path,
        env={"SIGNALBOX_AUTH_PASSWORD": PW, **env},
        adapters={"openwrt": OpenWrtAdapter, "dev": Dev},
        rules=[],
        link_sources=[],
    )
    svc.store.put_site(SITE)
    return svc


@pytest.fixture
def services(tmp_path: Path) -> Iterator[Services]:
    svc = make_services(tmp_path)
    yield svc
    svc.close()


@pytest.fixture
def client(services: Services) -> Iterator[TestClient]:
    with TestClient(web_app(services, run_background=False)) as c:
        assert c.post("/api/login", json={"password": PW}).status_code == 200
        yield c


def set_up(client: TestClient, url: str, port: int, fingerprint: str, writes: bool) -> None:
    body = {
        "device": {
            "name": "Access point",
            "site_id": "home",
            "role": "ap",
            "adapter": "openwrt",
            "allow_writes": writes,
            "config": {"url": url, "username": "signalbox", "password": ""},
        },
        "admin": {"user": "root", "secret": ROOT_PASSWORD, "port": port},
        "trust": fingerprint,
    }
    res = client.post("/api/devices/setup/apply", json=body)
    assert res.status_code == 200 and res.json()["ok"], res.text


def fix(port: int, trust: str | None = None, **kw: Any) -> dict[str, Any]:
    return {
        "remedy": kw.pop("remedy", "access"),
        "admin": {"user": "root", "secret": kw.pop("secret", ROOT_PASSWORD), "port": port},
        "trust": trust,
    }


def test_adapters_list_their_remedies(client: TestClient) -> None:
    info = {a["id"]: a for a in client.get("/api/adapters").json()}
    assert [r["id"] for r in info["openwrt"]["remedies"]] == ["access", "lldp"]
    assert info["dev"]["remedies"] == []


def test_gap_plan_fix_and_read_again(
    client: TestClient,
    services: Services,
    ssh: tuple[int, str],
    https_url: str,
    device: OpenWrtSsh,
    http: OpenWrtSim,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    port, fingerprint = ssh
    set_up(client, https_url, port, fingerprint, writes=True)
    # an older permission file: the port structure is refused
    old = json.loads(json.dumps(WRITE_ACL))
    old["signalbox"]["read"]["ubus"].pop("luci-rpc")
    device.files[ACL_PATH] = json.dumps(old).encode()
    http.denied = {"luci-rpc.getNetworkDevices"}
    read = client.post("/api/devices/access-point/test").json()
    assert read["status"] == "partial"
    gap = next(e for e in read["errors"] if "getNetworkDevices" in e["message"])
    assert gap["remedy"] == "access" and "permission file" in gap["fix"]

    untrusted = client.post("/api/devices/access-point/fix", json=fix(port)).json()
    assert untrusted["trusted"] is False and untrusted["fingerprint"] == fingerprint
    assert untrusted["remedy"]["id"] == "access"
    planned = client.post("/api/devices/access-point/fix", json=fix(port, fingerprint))
    steps = {s["id"]: s["state"] for s in planned.json()["steps"]}
    assert steps == {
        "packages": "unchanged",
        "acl": "todo",
        "login": "unchanged",
        "restart": "todo",
    }
    assert json.loads(device.files[ACL_PATH]) == old

    done = client.post("/api/devices/access-point/fix/apply", json=fix(port, fingerprint))
    assert done.status_code == 200, done.text
    res = done.json()
    assert res["ok"] and res["reading"]["status"] == "ok", res["reading"]
    assert json.loads(device.files[ACL_PATH]) == WRITE_ACL
    stored = services.store.adapter_config("access-point", OpenWrtAdapter.manifest.config)
    password = stored.password.get_secret_value()  # type: ignore[attr-defined]
    for text in (untrusted.__repr__(), planned.text, done.text, caplog.text):
        assert password not in text and ROOT_PASSWORD not in text
    assert "fix access of access-point (openwrt): done" in caplog.text
    # the device keeps its login: the next reading works with the stored password
    assert client.post("/api/devices/access-point/test").json()["status"] == "ok"


def test_refusals(
    client: TestClient,
    services: Services,
    ssh: tuple[int, str],
    https_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    port, fingerprint = ssh
    assert client.post("/api/devices/ghost/fix", json=fix(port)).status_code == 404
    set_up(client, https_url, port, fingerprint, writes=False)
    # a read-side remedy needs the admin login and the confirmation, not Allow changes (#278)
    r = client.post("/api/devices/access-point/fix", json=fix(port, fingerprint))
    assert r.status_code == 200, r.text
    # a remedy that is not read-side does
    manifest = OpenWrtAdapter.manifest
    plain = Remedy(id="lldp", title="Install LLDP")
    monkeypatch.setattr(
        OpenWrtAdapter, "manifest", manifest.model_copy(update={"remedies": (plain,)})
    )
    r = client.post("/api/devices/access-point/fix", json=fix(port, fingerprint, remedy="lldp"))
    assert r.status_code == 422 and r.json()["error"] == "not_allowed"
    monkeypatch.setattr(OpenWrtAdapter, "manifest", manifest)
    rec = services.store.device("access-point")
    assert rec is not None
    services.store.put_device(
        rec.model_copy(update={"allow_writes": True}),
        dict(rec.config),
        OpenWrtAdapter.manifest.config,
    )
    cases = [
        (fix(port, fingerprint, remedy="network"), 422, "not_supported"),
        (fix(port, fingerprint, remedy="Bad!"), 422, None),
        (fix(port, "nope"), 422, None),
        (fix(port, fingerprint, secret="not-it-x"), 422, "auth_failed"),
        (fix(1, fingerprint), 422, "unreachable"),
        (fix(port, "SHA256:" + "A" * 43), 200, None),
    ]
    for payload, code, kind in cases:
        r = client.post("/api/devices/access-point/fix", json=payload)
        assert r.status_code == code, (payload, r.text)
        if kind:
            assert r.json()["error"] == kind
        assert "not-it-x" not in r.text
    no_trust = client.post("/api/devices/access-point/fix/apply", json=fix(port))
    assert no_trust.status_code == 422 and "fingerprint" in no_trust.json()["message"]
    changed = client.post(
        "/api/devices/access-point/fix/apply", json=fix(port, "SHA256:" + "A" * 43)
    )
    assert changed.status_code == 409 and changed.json()["fingerprint"] == fingerprint
    # a device whose integration has no remedies
    services.store.put_device(
        rec.model_copy(update={"id": "dev1", "adapter": "dev", "allow_writes": True}),
        {"url": "x", "password": "y"},
        Dev.manifest.config,
    )
    r = client.post("/api/devices/dev1/fix", json=fix(port, fingerprint))
    assert r.json()["error"] == "not_supported"


def test_failed_fix_reads_nothing(
    client: TestClient, ssh: tuple[int, str], https_url: str, device: OpenWrtSsh
) -> None:
    port, fingerprint = ssh
    set_up(client, https_url, port, fingerprint, writes=True)
    device.installed.discard("rpcd-mod-luci")
    device.offline = True
    res = client.post("/api/devices/access-point/fix/apply", json=fix(port, fingerprint)).json()
    assert res["ok"] is False and res["reading"] is None
    assert res["steps"][0]["state"] == "failed"


@pytest.mark.parametrize(
    "env", [{"SIGNALBOX_SETUP_FIXES": "false"}, {"SIGNALBOX_SETUP_ENABLED": "false"}]
)
def test_switched_off(tmp_path: Path, env: dict[str, str]) -> None:
    svc = make_services(tmp_path / "off", **env)
    try:
        with TestClient(web_app(svc, run_background=False)) as c:
            assert c.post("/api/login", json={"password": PW}).status_code == 200
            assert all(a["remedies"] == [] for a in c.get("/api/adapters").json())
            for path in ("/api/devices/x/fix", "/api/devices/x/fix/apply"):
                r = c.post(path, json=fix(22, "SHA256:" + "A" * 43))
                assert r.status_code == 403 and r.json()["error"] == "disabled"
                assert "setup.fixes" in r.json()["message"]
    finally:
        svc.close()


def test_read_findings_carry_the_remedy() -> None:
    net = Network(
        errors=[
            ReadError(device_id="ap", capability="neighbours", message="m", remedy="lldp"),
            ReadError(device_id="ap", capability="dhcp", message="n"),
        ]
    )
    found = [f for f in evaluate(net, [READ_ERRORS]) if f.rule_id == READ_ERRORS.id]
    assert sorted((f.remedy or "") for f in found) == ["", "lldp"]


def test_remedy_hooks_are_required() -> None:
    def adapter(**kw: Any) -> type[Adapter]:
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
                **kw,
            )

            async def read_system(self) -> SystemInfo:
                return SystemInfo()

            @classmethod
            async def plan_setup(cls, request: SetupRequest) -> SetupPlan:
                raise NotImplementedError

            @classmethod
            async def apply_setup(cls, request: SetupRequest) -> SetupResult:
                raise NotImplementedError

        return Half

    r = Remedy(id="r", title="R")
    with pytest.raises(AdapterContractError, match="no admin_login"):
        check_setup(adapter(remedies=(r,)))
    with pytest.raises(AdapterContractError, match="plan_remedy"):
        check_setup(adapter(remedies=(r,), admin_login=AdminLogin(transport="x")))

    class Twice(adapter(remedies=(r, r), admin_login=AdminLogin(transport="x"))):  # type: ignore[misc]
        @classmethod
        async def plan_remedy(cls, request: RemedyRequest) -> SetupPlan:
            raise NotImplementedError

        @classmethod
        async def apply_remedy(cls, request: RemedyRequest) -> SetupResult:
            raise NotImplementedError

    with pytest.raises(AdapterContractError, match="twice"):
        check_setup(Twice)
    check_setup(OpenWrtAdapter)


async def test_default_remedy_hooks_raise() -> None:
    req = RemedyRequest(remedy="x", admin_user="a", admin_secret=SecretStr("b"))
    with pytest.raises(NotImplementedError):
        await Dev.plan_remedy(req)
    with pytest.raises(NotImplementedError):
        await Dev.apply_remedy(req)


def test_fix_password_comes_last(
    client: TestClient,
    ssh: tuple[int, str],
    https_url: str,
    device: OpenWrtSsh,
    http: OpenWrtSim,
) -> None:
    """#279: the identity is fetched without the password; apply takes it once and refuses a
    plan with steps the user did not see."""
    port, fingerprint = ssh
    set_up(client, https_url, port, fingerprint, writes=True)
    device.installed -= LLDP_PACKAGES
    device.lldpd_running = False
    http.lldpd = False
    anon = fix(port, fingerprint, remedy="lldp")
    del anon["admin"]["secret"]
    scripts = len(device.scripts)
    r = client.post("/api/devices/access-point/fix", json=anon)
    assert r.status_code == 200 and r.json()["trusted"] is False and r.json()["steps"] == []
    assert len(device.scripts) == scripts  # nothing sent
    assert client.post("/api/devices/access-point/fix/apply", json=anon).status_code == 422
    changed = client.post(
        "/api/devices/access-point/fix/apply",
        json={**fix(port, fingerprint, remedy="lldp"), "plan_ids": ["acl"]},
    )
    assert changed.status_code == 409 and changed.json()["error"] == "plan_changed"
    assert not device.installed >= LLDP_PACKAGES
    info = {a["id"]: a for a in client.get("/api/adapters").json()}
    lldp = next(r for r in info["openwrt"]["remedies"] if r["id"] == "lldp")
    seen = [s["id"] for s in lldp["preview"]]
    done = client.post(
        "/api/devices/access-point/fix/apply",
        json={**fix(port, fingerprint, remedy="lldp"), "plan_ids": seen},
    )
    assert done.status_code == 200 and done.json()["ok"], done.text
