"""The optional SSH step (#242) through POST /api/devices/setup[/apply]: OPNsense, ISC script."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from factories import SITE
from signalbox.adapters.openwrt import OpenWrtAdapter
from signalbox.adapters.opnsense import OpnsenseAdapter
from signalbox.adapters.opnsense.provision import SCRIPT_PATH
from signalbox.service import Services, build
from signalbox.sim.opnsense import KEY, SECRET, OpnsenseSimulator
from signalbox.sim.opnsense_ssh import ROOT_PASSWORD, OpnsenseSsh, serve_ssh_in_thread
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve
from signalbox.web.app import create_app as web_app

PW = "correct-horse-battery"


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> TlsFiles:
    return self_signed_certificate(tmp_path_factory.mktemp("tls"))


@pytest.fixture
def url(tls: TlsFiles) -> Iterator[str]:
    with serve(OpnsenseSimulator().app(), tls=tls) as served:
        yield served


@pytest.fixture
def firewall() -> OpnsenseSsh:
    return OpnsenseSsh()


@pytest.fixture
def ssh(firewall: OpnsenseSsh) -> Iterator[tuple[int, str]]:
    with serve_ssh_in_thread(firewall) as served:
        yield served


@pytest.fixture
def services(tmp_path: Path) -> Iterator[Services]:
    svc = build(
        tmp_path,
        env={"SIGNALBOX_AUTH_PASSWORD": PW},
        adapters={"opnsense": OpnsenseAdapter, "openwrt": OpenWrtAdapter},
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


def body(url: str, tls: TlsFiles, ssh: tuple[int, str] | None, **kw: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "device": {
            "name": "Firewall",
            "site_id": "home",
            "role": "gateway",
            "adapter": "opnsense",
            "config": {"url": url, "api_key": "", "api_secret": ""},
        },
        "admin": {"user": KEY, "secret": SECRET},
        "trust": tls.fingerprint,
    }
    if ssh is not None:
        out["ssh"] = {"secret": ROOT_PASSWORD, "port": ssh[0], "trust": kw.pop("ssh_trust", ssh[1])}
    return {**out, **kw}


def test_the_form_is_told_about_the_option(client: TestClient) -> None:
    info = {a["id"]: a for a in client.get("/api/adapters").json()}
    option = info["opnsense"]["admin_login"]["ssh_option"]
    assert option["port_default"] == 22 and "ISC DHCP" in option["label"]
    assert info["openwrt"]["admin_login"]["ssh_option"] is None


def test_ssh_host_key_then_apply_saves_the_key_encrypted(
    client: TestClient,
    services: Services,
    url: str,
    tls: TlsFiles,
    ssh: tuple[int, str],
    firewall: OpnsenseSsh,
) -> None:
    first = client.post("/api/devices/setup", json=body(url, tls, ssh, ssh_trust=None))
    plan = first.json()
    assert first.status_code == 200 and plan["trusted"] and plan["ssh_trusted"] is False
    assert plan["ssh_fingerprint"] == ssh[1] and plan["steps"] == []
    assert ROOT_PASSWORD not in first.text

    ok = client.post("/api/devices/setup", json=body(url, tls, ssh)).json()
    assert [s["id"] for s in ok["steps"]][-2:] == ["isc-script", "isc-key"]

    done = client.post("/api/devices/setup/apply", json=body(url, tls, ssh))
    assert done.status_code == 200 and done.json()["ok"], done.text
    assert ROOT_PASSWORD not in done.text and "OPENSSH PRIVATE KEY" not in done.text
    assert SCRIPT_PATH in firewall.files
    record = services.store.device(done.json()["device"]["id"])
    assert record is not None
    config = services.store.adapter_config(record.id, OpnsenseAdapter.manifest.config)
    assert config.isc_ssh_host_key == ssh[1] and config.isc_ssh_port == ssh[0]  # type: ignore[attr-defined]
    assert config.isc_ssh_key is not None  # type: ignore[attr-defined]

    gone = client.post(
        "/api/devices/setup/apply",
        json=body(
            url,
            tls,
            ssh,
            remove=True,
            device={**body(url, tls, None)["device"], "device_id": record.id},
        ),
    )
    assert gone.json()["ok"] and SCRIPT_PATH not in firewall.files


def test_wrong_ssh_host_key_is_refused(
    client: TestClient, url: str, tls: TlsFiles, ssh: tuple[int, str], firewall: OpnsenseSsh
) -> None:
    wrong = "SHA256:" + "B" * 43
    r = client.post("/api/devices/setup/apply", json=body(url, tls, ssh, ssh_trust=wrong))
    assert r.status_code == 409 and r.json()["error"] == "untrusted"
    assert r.json()["fingerprint"] == ssh[1] and firewall.files == {}


def test_an_integration_without_the_option_refuses_it(
    client: TestClient, url: str, tls: TlsFiles, ssh: tuple[int, str]
) -> None:
    payload = body(url, tls, ssh)
    payload["device"]["adapter"] = "openwrt"
    payload["device"]["role"] = "ap"
    r = client.post("/api/devices/setup", json=payload)
    assert r.status_code == 422 and r.json()["error"] == "not_supported"


def test_ssh_secret_is_never_echoed(
    client: TestClient, url: str, tls: TlsFiles, ssh: tuple[int, str], firewall: OpnsenseSsh
) -> None:
    firewall.python = False
    r = client.post("/api/devices/setup", json=body(url, tls, ssh))
    assert r.status_code == 422 and "python3 is missing" in r.json()["message"]
    assert ROOT_PASSWORD not in r.text
    bad = body(url, tls, ssh)
    bad["ssh"]["secret"] = ""
    assert client.post("/api/devices/setup", json=bad).status_code == 422
    assert ROOT_PASSWORD not in client.post("/api/devices/setup", json=bad).text


def test_both_identities_are_fetched_without_any_password(
    client: TestClient, url: str, tls: TlsFiles, ssh: tuple[int, str], firewall: OpnsenseSsh
) -> None:
    """#290: certificate and SSH host key come before the passwords, which are asked once."""
    payload = body(url, tls, ssh)
    payload["admin"] = {"user": ""}
    payload["ssh"] = {"port": ssh[0]}
    del payload["trust"]
    r = client.post("/api/devices/setup", json=payload)
    assert r.status_code == 200, r.text
    plan = r.json()
    assert plan["trusted"] is False and plan["fingerprint"] == tls.fingerprint
    assert plan["ssh_trusted"] is False and plan["ssh_fingerprint"] == ssh[1]
    assert plan["steps"] == [] and firewall.scripts == [] and firewall.files == {}

    # without the SSH option only the certificate is fetched
    del payload["ssh"]
    plain = client.post("/api/devices/setup", json=payload).json()
    assert plain["ssh_fingerprint"] is None and plain["ssh_trusted"] is None

    # one run with both passwords and both confirmations: no further question
    done = client.post("/api/devices/setup/apply", json=body(url, tls, ssh))
    assert done.status_code == 200 and done.json()["ok"], done.text
