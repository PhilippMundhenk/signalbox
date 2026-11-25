import asyncio
import io
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from factories import SITE
from signalbox.model import Security, Site, Wlan
from signalbox.service import Services, build, data_dir_from
from signalbox.web import auth as authmod
from signalbox.web.app import create_app, public_network
from signalbox.web.auth import Auth, Locked, announce, reset_password
from test_runner import Dev, per_device

PW = "correct-horse-battery"
JSON = {"content-type": "application/json"}


@pytest.fixture
def services(tmp_path: Path) -> Iterator[Services]:
    svc = build(
        tmp_path,
        env={"SIGNALBOX_AUTH_PASSWORD": PW},
        adapters={"dev": Dev},
        rules=[per_device],
        link_sources=[],
    )
    svc.store.put_site(SITE)
    yield svc
    svc.close()


@pytest.fixture
def client(services: Services) -> Iterator[TestClient]:
    with TestClient(create_app(services, run_background=False)) as c:
        yield c


@pytest.fixture
def logged_in(client: TestClient) -> TestClient:
    r = client.post("/api/login", json={"password": PW})
    assert r.status_code == 200
    return client


def device_body(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "Main Gateway",
        "site_id": "home",
        "role": "gateway",
        "adapter": "dev",
        "config": {"url": "ok", "password": "device-pw"},
    }
    body.update(kw)
    return body


def test_health_and_headers(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert client.get("/api/health").headers["cache-control"] == "no-store"


def test_api_requires_login(client: TestClient) -> None:
    r = client.get("/api/devices")
    assert r.status_code == 401 and r.json()["error"] == "login_required"
    assert client.get("/api/session").json()["authenticated"] is False


def test_session_endpoint_is_open_cheap_and_has_no_secrets(client: TestClient) -> None:
    r = client.get("/api/session")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert set(r.json()) == {"authenticated", "password_fixed", "version"}
    assert r.json()["authenticated"] is False
    client.post("/api/login", json={"password": PW})
    assert client.get("/api/session").json()["authenticated"] is True
    client.post("/api/logout")
    body = client.get("/api/session")
    assert body.json()["authenticated"] is False and PW not in body.text


def test_login_logout(client: TestClient) -> None:
    assert client.post("/api/login", json={"password": "nope"}).status_code == 401
    r = client.post("/api/login", json={"password": PW})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert client.get("/api/session").json()["authenticated"] is True
    client.post("/api/logout")
    assert client.get("/api/devices").status_code == 401


def test_login_lockout(client: TestClient) -> None:
    for _ in range(authmod.MAX_FAILURES):
        client.post("/api/login", json={"password": "wrong"})
    r = client.post("/api/login", json={"password": PW})
    assert r.status_code == 429 and r.json()["retry_after"] > 0


@pytest.mark.parametrize(
    ("headers", "status", "code"),
    [
        ({"origin": "http://evil.example", **JSON}, 403, "bad_origin"),
        ({"sec-fetch-site": "cross-site", **JSON}, 403, "bad_origin"),
        ({"content-type": "text/plain"}, 415, "bad_content_type"),
    ],
)
def test_cross_site_and_content_type_refused(
    logged_in: TestClient, headers: dict[str, str], status: int, code: str
) -> None:
    r = logged_in.post("/api/sites", content=b'{"name": "x"}', headers=headers)
    assert r.status_code == status and r.json()["error"] == code


def test_body_too_large(logged_in: TestClient) -> None:
    r = logged_in.post("/api/sites", content=b"x" * 300_000, headers=JSON)
    assert r.status_code == 413


def test_sites_crud(logged_in: TestClient) -> None:
    r = logged_in.post("/api/sites", json={"name": "Second House"})
    assert r.status_code == 201 and r.json() == {"id": "second-house", "name": "Second House"}
    assert logged_in.put("/api/sites/second-house", json={"name": "Office"}).json()["name"] == (
        "Office"
    )
    assert logged_in.put("/api/sites/nope", json={"name": "x"}).status_code == 404
    assert logged_in.delete("/api/sites/second-house").status_code == 204
    assert [s["id"] for s in logged_in.get("/api/sites").json()] == ["home"]


def test_moving_a_device_to_another_site_updates_the_views_at_once(
    logged_in: TestClient, services: Services
) -> None:
    """#368: the stored snapshot carries the site; a save must not leave the old one in view."""
    services.store.put_site(Site(id="away", name="Away"))
    r = logged_in.post("/api/devices", json=device_body())
    assert r.status_code == 201, r.text
    rec = services.store.device("main-gateway")
    assert rec is not None
    asyncio.run(services.runner.observe_device(rec))
    before = logged_in.get("/api/network").json()
    assert {d["site_id"] for d in before["devices"]} == {"home"}
    assert any(sub["segment_id"].startswith("home/segment/") for sub in before["subnets"])

    r = logged_in.put(
        "/api/devices/main-gateway", json=device_body(site_id="away", config={"url": "ok"})
    )
    assert r.status_code == 200 and r.json()["site_id"] == "away"

    # no read in between: the snapshot was re-stamped by the save
    net = logged_in.get("/api/network").json()
    assert [d["site_id"] for d in net["devices"]] == ["away"]
    assert net["subnets"] and all(
        sub["segment_id"].startswith("away/segment/") for sub in net["subnets"]
    )
    assert not any(seg["id"].startswith("home/") for seg in net["segments"])
    assert all(seg["site_id"] == "away" for seg in net["segments"])
    topology = logged_in.get("/api/topology").json()
    assert [n["site_id"] for n in topology["nodes"]] == ["away"]
    assert not any(sid.startswith("home/") for sid in topology["segments"])

    # renaming is carried over as well
    logged_in.put(
        "/api/devices/main-gateway",
        json=device_body(site_id="away", name="Edge", config={"url": "ok"}),
    )
    assert [d["name"] for d in logged_in.get("/api/network").json()["devices"]] == ["Edge"]


def test_device_lifecycle(logged_in: TestClient) -> None:
    r = logged_in.post("/api/devices", json=device_body())
    assert r.status_code == 201, r.text
    dev = r.json()
    assert dev["id"] == "main-gateway" and dev["secrets_set"] == ["password"]
    assert "device-pw" not in r.text and dev["config"] == {"url": "ok"}

    # editing without the password keeps it
    r = logged_in.put(
        "/api/devices/main-gateway", json=device_body(name="GW", config={"url": "ok"})
    )
    assert r.status_code == 200 and r.json()["name"] == "GW"

    r = logged_in.post("/api/devices/main-gateway/test")
    assert r.json()["status"] == "ok" and r.json()["counts"]["ports"] == 1
    assert Dev.seen[-1] == "device-pw"
    assert logged_in.get("/api/devices/main-gateway").json()["status"] == "ok"
    assert [d["id"] for d in logged_in.get("/api/devices").json()] == ["main-gateway"]

    assert logged_in.delete("/api/devices/main-gateway").status_code == 204
    assert logged_in.get("/api/devices/main-gateway").status_code == 404
    assert logged_in.put("/api/devices/main-gateway", json=device_body()).status_code == 404
    assert logged_in.post("/api/devices/main-gateway/test").status_code == 404


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (device_body(adapter="nope"), "adapter 'nope' is not installed"),
        (device_body(role="ap"), "Dev devices can be: gateway"),
        (device_body(config={"url": "ok"}), "password: Field required"),
        (device_body(site_id="mars"), "unknown site mars"),
        (device_body(name=""), "name: String should have at least 1 character"),
    ],
)
def test_device_validation(logged_in: TestClient, body: dict[str, Any], message: str) -> None:
    r = logged_in.post("/api/devices", json=body)
    assert r.status_code == 422 and message in r.json()["message"]


def test_certificate_trust_flow(logged_in: TestClient, services: Services) -> None:
    logged_in.post("/api/devices", json=device_body(config={"url": "untrusted", "password": "p"}))
    r = logged_in.post("/api/devices/main-gateway/test").json()
    assert r["status"] == "untrusted-certificate" and r["pending_fingerprint"] == "fp1"
    bad = logged_in.post("/api/devices/main-gateway/trust", json={"fingerprint": "zz"})
    assert bad.status_code == 422
    other = logged_in.post("/api/devices/main-gateway/trust", json={"fingerprint": "a" * 64})
    assert other.status_code == 422 and "not the certificate" in other.json()["message"]
    services.store.set_pending_fingerprint("main-gateway", "f" * 64)
    ok = logged_in.post("/api/devices/main-gateway/trust", json={"fingerprint": "f" * 64})
    assert ok.status_code == 200
    assert logged_in.get("/api/devices/main-gateway").json()["pinned_fingerprint"] == "f" * 64


def test_network_findings_rules_observe(logged_in: TestClient, services: Services) -> None:
    logged_in.post("/api/devices", json=device_body())
    logged_in.post("/api/devices/main-gateway/test")
    services.runner.evaluate()
    net = logged_in.get("/api/network").json()
    assert [d["id"] for d in net["devices"]] == ["main-gateway"]
    findings = logged_in.get("/api/findings").json()
    assert [f["finding"]["message"] for f in findings] == ["main-gateway"]
    assert logged_in.get("/api/findings?resolved=true").status_code == 200
    rules = {r["id"]: r for r in logged_in.get("/api/rules").json()}
    assert set(rules) == {"signalbox.read", "ack.expired", "test.per-device"}
    assert rules["test.per-device"]["severity"] == "warning" and rules["test.per-device"]["enabled"]
    assert logged_in.post("/api/observe").status_code == 202
    adapters = logged_in.get("/api/adapters").json()
    assert adapters[0]["id"] == "dev" and adapters[0]["secret_fields"] == ["password"]
    assert "url" in adapters[0]["config_schema"]["properties"]


def test_rules_show_settings(tmp_path: Path) -> None:
    (tmp_path / "signalbox.yaml").write_text(
        "rules: {test.per-device: {enabled: false, severity: error}}\n"
    )
    svc = build(tmp_path, env={"SIGNALBOX_AUTH_PASSWORD": PW}, adapters={}, rules=[per_device])
    try:
        with TestClient(create_app(svc, run_background=False)) as c:
            c.post("/api/login", json={"password": PW})
            rule = next(r for r in c.get("/api/rules").json() if r["id"] == "test.per-device")
            assert rule == rule | {"enabled": False, "severity": "error"}
    finally:
        svc.close()


def test_rules_expose_parameters(tmp_path: Path) -> None:
    from signalbox.rules.health import storage_full

    (tmp_path / "signalbox.yaml").write_text(
        "rules:\n"
        "  health.storage-full:\n"
        "    params: {warn_pct: 80}\n"
        "    scopes: [{match: {site: lab}, params: {warn_pct: 95}}]\n"
        "  signalbox.read:\n"
        "    scopes: [{match: {site: lab}, enabled: false}]\n"
    )
    svc = build(
        tmp_path, env={"SIGNALBOX_AUTH_PASSWORD": PW}, adapters={}, rules=[per_device, storage_full]
    )
    try:
        with TestClient(create_app(svc, run_background=False)) as c:
            c.post("/api/login", json={"password": PW})
            rules = {r["id"]: r for r in c.get("/api/rules").json()}
            plain = rules["test.per-device"]["parameters"]
            assert plain == {"schema": None, "defaults": {}, "values": {}, "scopes": []}
            p = rules["health.storage-full"]["parameters"]
            assert p["schema"]["properties"]["warn_pct"]["unit"] == "%"
            assert p["defaults"]["warn_pct"] == 90 and p["values"]["warn_pct"] == 80
            (scope,) = p["scopes"]
            assert scope["match"] == {"site": "lab"} and scope["values"]["warn_pct"] == 95
            (engine,) = rules["signalbox.read"]["parameters"]["scopes"]
            assert engine["enabled"] is False and engine["params"] == {}
    finally:
        svc.close()


def test_links(logged_in: TestClient) -> None:
    r = logged_in.post("/api/links", json={"a": "gw/port/lan", "b": "ap/port/lan"})
    assert r.status_code == 201
    link = r.json()
    assert link["origin"] == "manual" and link["kind"] == "cable"
    assert [x["id"] for x in logged_in.get("/api/links").json()] == [link["id"]]
    assert logged_in.delete(f"/api/links/{link['id']}").status_code == 204
    assert logged_in.get("/api/links").json() == []


def test_public_network_hides_passphrase_fingerprints() -> None:
    from signalbox.model import Network

    net = Network(
        wlans=[
            Wlan(
                id="ap/wlan/0",
                device_id="ap",
                ssid="Example",
                radio_id="ap/radio/0",
                security=Security.WPA2,
                passphrase_fingerprint="0123456789abcdef",
            )
        ]
    )
    data = public_network(net)
    assert "passphrase_fingerprint" not in data["wlans"][0]


def test_password_change_when_fixed(logged_in: TestClient) -> None:
    r = logged_in.post("/api/password", json={"current": PW, "new": "another-password"})
    assert r.status_code == 409


def test_generated_password_and_change(tmp_path: Path) -> None:
    svc = build(tmp_path, env={}, adapters={}, rules=[], link_sources=[])
    try:
        out = io.StringIO()
        auth = Auth(svc.store, None, 1, announce_to=out)
        generated = out.getvalue().split("Web interface password: ")[1].split()[0]
        assert auth.check(generated) and not auth.fixed
        # a second start reads the stored hash and prints nothing
        assert Auth(svc.store, None, 1, announce_to=io.StringIO()).check(generated)
        new = reset_password(svc.store)
        assert Auth(svc.store, None, 1).check(new)

        app = create_app(svc, run_background=False)
        with TestClient(app) as c:
            c.post("/api/login", json={"password": new})
            assert (
                c.post("/api/password", json={"current": "x", "new": "long-enough-pw"}).status_code
                == 403
            )
            assert c.post("/api/password", json={"current": new, "new": "short"}).status_code == 422
            r = c.post("/api/password", json={"current": new, "new": "long-enough-pw"})
            assert r.status_code == 200
            assert c.get("/api/devices").status_code == 401  # sessions end on change
            assert c.post("/api/login", json={"password": "long-enough-pw"}).status_code == 200
    finally:
        svc.close()


def test_auth_sessions_expire_and_lock_table_is_bounded(
    services: Services, monkeypatch: pytest.MonkeyPatch
) -> None:
    auth = Auth(services.store, PW, 1)
    token = auth.login(PW, "c")
    assert token and auth.valid(token) and not auth.valid(None) and not auth.valid("x")
    auth.sessions[token] = 0
    assert not auth.valid(token) and token not in auth.sessions

    monkeypatch.setattr(authmod, "MAX_TRACKED_CLIENTS", 2)
    monkeypatch.setattr(authmod, "MAX_FAILURES", 1)
    for client in ("a", "b", "c", "d"):
        assert auth.login("wrong", client) is None
    assert len(auth.locked) <= 2
    with pytest.raises(Locked):
        auth.login(PW, "d")
    monkeypatch.setattr(authmod, "MAX_FAILURES", 5)
    for client in ("x", "y", "z"):
        auth.login("wrong", client)
    assert len(auth.failures) <= 2


def test_announce_default_stream(capsys: pytest.CaptureFixture[str]) -> None:
    announce("pw123")
    assert "pw123" in capsys.readouterr().err


def test_background_runner_starts_and_stops(services: Services) -> None:
    with TestClient(create_app(services, run_background=True)) as c:
        assert c.get("/health").status_code == 200


def test_data_dir_from() -> None:
    assert str(data_dir_from(None, env={})) == "/data"
    assert str(data_dir_from(None, env={"SIGNALBOX_DATA": "/x"})) == "/x"
    assert str(data_dir_from("/y", env={"SIGNALBOX_DATA": "/x"})) == "/y"


def test_api_doc_is_current() -> None:
    import importlib.util

    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("gen_api_doc", root / "tools" / "gen_api_doc.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert (root / "docs" / "API.md").read_text() == mod.render(), "run python tools/gen_api_doc.py"


def test_topology_endpoint(logged_in: TestClient) -> None:
    logged_in.post("/api/devices", json=device_body())
    logged_in.post("/api/devices/main-gateway/test")
    topo = logged_in.get("/api/topology").json()
    assert [n["id"] for n in topo["nodes"]] == ["main-gateway"]
    assert topo["edges"] == []
    [lan] = topo["nodes"][0]["ports"]
    assert (lan["role"], lan["external"], lan["lower"]) == (None, None, [])
    # the port structure (#252): one port without a role is a root of its own
    tree = logged_in.get("/api/devices/main-gateway/port-tree").json()
    assert tree == [
        {"id": "main-gateway/port/lan", "node": "port", "children": [], "members": [], "wlans": []}
    ]
    assert logged_in.get("/api/devices/nope/port-tree").json() == []
    [raw] = logged_in.get("/api/network").json()["ports"]
    assert raw["external"] is None


def test_mqtt_bridge_wired_into_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import signalbox.mqtt as m
    from test_mqtt import FakeClient

    fake = FakeClient()
    monkeypatch.setattr(m, "_default_client", lambda: fake)
    monkeypatch.setattr(m.MqttBridge.__init__, "__defaults__", ("", lambda: fake, False))
    svc = build(
        tmp_path,
        env={
            "SIGNALBOX_AUTH_PASSWORD": PW,
            "SIGNALBOX_MQTT_ENABLED": "1",
            "SIGNALBOX_MQTT_HOST": "b",
        },
        adapters={},
        rules=[],
        link_sources=[],
    )
    try:
        with TestClient(create_app(svc, run_background=False)) as c:
            assert c.get("/health").json()["mqtt"] == "connecting"
            assert len(svc.runner.listeners) == 1
        assert "loop_stop" in fake.calls
    finally:
        svc.close()


def test_web_interface_is_served_under_the_csp(client: TestClient) -> None:
    r = client.get("/")
    assert r.status_code == 200 and '<script type="module" src="app.js">' in r.text
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert client.get("/views/findings.js").status_code == 200


def test_web_interface_has_no_inline_code_or_markup_injection() -> None:
    """Strict CSP and no untrusted text as HTML: no inline script/style, no innerHTML."""
    from signalbox.web.app import STATIC

    files = sorted(p for p in STATIC.rglob("*") if p.suffix in {".html", ".js"})
    assert len(files) > 10
    bad = ("innerHTML", "outerHTML", "insertAdjacentHTML", "style=", "eval(", "<script>")
    for path in files:
        text = path.read_text()
        for needle in bad:
            assert needle not in text, f"{path.name} contains {needle}"


def test_form_test_before_saving(logged_in: TestClient, services: Services) -> None:
    """The device form reads the device with unsaved settings and stores nothing."""
    r = logged_in.post("/api/devices/test", json=device_body())
    assert r.status_code == 200
    res = r.json()
    assert res["status"] == "ok" and res["counts"]["ports"] == 1
    assert res["device"] == {"vendor": "Example", "model": None, "firmware": None}
    assert services.store.devices() == [] and services.store.snapshots() == []

    partial = logged_in.post(
        "/api/devices/test", json=device_body(config={"url": "partial", "password": "p"})
    ).json()
    assert partial["status"] == "partial"
    assert partial["errors"][0]["fix"] == "Give the user port rights."

    bad = [
        (device_body(adapter="nope"), 422, "not installed"),
        (device_body(role="ap"), 422, "Dev devices can be: gateway"),
        (device_body(config={"url": "ok"}), 422, "password: Field required"),
        (device_body(device_id="ghost"), 404, "No such device"),
    ]
    for body, code, message in bad:
        r = logged_in.post("/api/devices/test", json=body)
        assert r.status_code == code and message in r.json()["message"], body


def test_form_test_trust_and_save(logged_in: TestClient, services: Services) -> None:
    """A certificate trusted while testing the form is used for the test and pinned on save."""
    body = device_body(config={"url": "untrusted64", "password": "p"})
    res = logged_in.post("/api/devices/test", json=body).json()
    assert res["status"] == "untrusted-certificate" and res["pending_fingerprint"] == "a" * 64
    body["trust_fingerprint"] = "a" * 64
    assert logged_in.post("/api/devices/test", json=body).json()["status"] == "ok"
    bad = logged_in.post("/api/devices/test", json={**body, "trust_fingerprint": "nope"})
    assert bad.status_code == 422
    saved = logged_in.post("/api/devices", json=body).json()
    assert saved["pinned_fingerprint"] == "a" * 64 and saved["pending_fingerprint"] is None
    assert logged_in.post("/api/devices/main-gateway/test").json()["status"] == "ok"


def test_form_test_while_editing_keeps_stored_secrets(logged_in: TestClient) -> None:
    """Editing: an empty password field tests with the stored password and the stored pin."""
    Dev.seen.clear()
    body = device_body(
        config={"url": "untrusted64", "password": "stored-pw"}, trust_fingerprint="a" * 64
    )
    logged_in.post("/api/devices", json=body)
    edit = device_body(config={"url": "untrusted64", "password": ""}, device_id="main-gateway")
    res = logged_in.post("/api/devices/test", json=edit).json()
    assert res["status"] == "ok" and Dev.seen[-1] == "stored-pw"
    # the stored device is unchanged by the test
    assert logged_in.get("/api/devices/main-gateway").json()["name"] == "Main Gateway"


def test_devices_carry_manage_url_key(logged_in: TestClient) -> None:
    logged_in.post("/api/devices", json=device_body())
    assert logged_in.get("/api/devices").json()[0]["manage_url"] is None  # unknown adapter
    assert logged_in.get("/api/devices/main-gateway").json()["manage_url"] is None
