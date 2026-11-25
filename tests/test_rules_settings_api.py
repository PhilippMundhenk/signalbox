"""Rule parameters and scopes edited in the UI (#454): layers, validation, apply, reset."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from signalbox.rules import load_rules
from signalbox.service import Services, build
from signalbox.web.app import create_app

PW = "correct-horse-battery"
RULE = "health.storage-full"
URL = f"/api/rules/{RULE}/settings"


def make(tmp_path: Path, yaml_text: str = "") -> Services:
    if yaml_text:
        (tmp_path / "signalbox.yaml").write_text(yaml_text)
    return build(tmp_path, env={"SIGNALBOX_AUTH_PASSWORD": PW}, adapters={}, rules=load_rules())


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    svc = make(tmp_path)
    with TestClient(create_app(svc, run_background=False)) as c:
        c.post("/api/login", json={"password": PW})
        yield c
    svc.close()


def rule(c: TestClient, rule_id: str = RULE) -> dict[str, Any]:
    out: dict[str, Any] = next(r for r in c.get("/api/rules").json() if r["id"] == rule_id)
    return out


def test_save_applies_at_once_and_shows_the_source(client: TestClient) -> None:
    before = rule(client)["parameters"]
    assert before["sources"]["warn_pct"] == "default"
    r = client.put(URL, json={"params": {"warn_pct": 70}})
    assert r.status_code == 200
    p = rule(client)["parameters"]
    assert p["values"]["warn_pct"] == 70 and p["sources"]["warn_pct"] == "ui"
    assert p["sources"]["error_pct"] == "default"
    # reset to default: without the key the value is gone
    client.put(URL, json={"params": {}})
    p = rule(client)["parameters"]
    assert p["values"]["warn_pct"] == before["defaults"]["warn_pct"]
    assert p["sources"]["warn_pct"] == "default"


def test_scopes_follow_the_file_scopes_and_survive_a_restart(tmp_path: Path) -> None:
    svc = make(
        tmp_path,
        f"rules:\n  {RULE}:\n    params: {{warn_pct: 80}}\n"
        "    scopes: [{match: {site: lab}, params: {warn_pct: 95}}]\n",
    )
    with TestClient(create_app(svc, run_background=False)) as c:
        c.post("/api/login", json={"password": PW})
        body = {
            "params": {"error_pct": 97},
            "scopes": [{"match": {"tag": "critical"}, "params": {"warn_pct": 60}}],
        }
        assert c.put(URL, json=body).status_code == 200
        p = rule(c)["parameters"]
        assert [(s["source"], s["match"]) for s in p["scopes"]] == [
            ("file", {"site": "lab"}),
            ("ui", {"tag": "critical"}),
        ]
        assert p["sources"]["warn_pct"] == "file" and p["sources"]["error_pct"] == "ui"
        assert p["scopes"][1]["values"]["warn_pct"] == 60
        # the file is untouched
        assert "critical" not in (tmp_path / "signalbox.yaml").read_text()
    svc.close()
    again = make(tmp_path)
    try:
        assert again.config.rules[RULE].params == {"warn_pct": 80, "error_pct": 97}
        assert len(again.config.rules[RULE].scopes) == 2
    finally:
        again.close()


def test_a_parameter_of_the_file_is_read_only(tmp_path: Path) -> None:
    svc = make(tmp_path, f"rules:\n  {RULE}:\n    params: {{warn_pct: 80}}\n")
    with TestClient(create_app(svc, run_background=False)) as c:
        c.post("/api/login", json={"password": PW})
        r = c.put(URL, json={"params": {"warn_pct": 70}})
        assert r.status_code == 409 and r.json()["error"] == "config_file"
        assert f"rules.{RULE}.params.warn_pct" in r.json()["message"]
        assert rule(c)["parameters"]["values"]["warn_pct"] == 80
        assert c.put(URL, json={"params": {"error_pct": 99}}).status_code == 200
    svc.close()


@pytest.mark.parametrize(
    ("rule_id", "body", "message"),
    [
        (RULE, {"params": {"warn_pct": "high"}}, f"rules.{RULE}.params.warn_pct"),
        (RULE, {"params": {"nope": 1}}, f"rules.{RULE}.params.nope"),
        (RULE, {"params": {"warn_pct": 1e9}}, f"rules.{RULE}.params.warn_pct"),
        (
            RULE,
            {"scopes": [{"match": {"site": "a"}, "params": {"warn_pct": -5}}]},
            f"rules.{RULE}.scopes[0].params.warn_pct",
        ),
        (RULE, {"scopes": [{"match": {}}]}, f"rules.{RULE}.scopes[0].match"),
        (RULE, {"scopes": [{"match": {"colour": "x"}}]}, f"rules.{RULE}.scopes[0].match.colour"),
        (RULE, {"scopes": [{"match": {"site": "x" * 201}}]}, "at most 200 characters"),
        (RULE, {"scopes": [{"match": {"site": "x"}}] * 51}, "at most 50 scopes"),
        (RULE, {"other": 1}, f"rules.{RULE}.other"),
        ("no.such-rule", {"params": {"a": 1}}, "rules.no.such-rule: not an installed rule"),
        ("signalbox.read", {"params": {"a": 1}}, "has no parameters"),
    ],
)
def test_validation_names_the_path(
    client: TestClient, rule_id: str, body: dict[str, Any], message: str
) -> None:
    r = client.put(f"/api/rules/{rule_id}/settings", json=body)
    assert r.status_code == 422, r.text
    assert message in r.json()["message"]
    # nothing was saved
    assert rule(client)["parameters"]["sources"]["warn_pct"] == "default"


def test_scopes_of_a_rule_without_parameters(client: TestClient) -> None:
    body = {"scopes": [{"match": {"site": "lab"}, "enabled": False}]}
    assert client.put("/api/rules/signalbox.read/settings", json=body).status_code == 200
    (s,) = rule(client, "signalbox.read")["parameters"]["scopes"]
    assert s["source"] == "ui" and s["enabled"] is False


def test_reset_removes_the_ui_settings(client: TestClient) -> None:
    client.put(URL, json={"params": {"warn_pct": 70}})
    assert client.delete(URL).status_code == 204
    assert rule(client)["parameters"]["sources"]["warn_pct"] == "default"
    assert client.delete(URL).status_code == 204  # idempotent


def test_writes_need_the_login_and_a_same_origin_request(tmp_path: Path) -> None:
    svc = make(tmp_path)
    try:
        with TestClient(create_app(svc, run_background=False)) as c:
            assert c.put(URL, json={"params": {"warn_pct": 70}}).status_code == 401
            assert c.delete(URL).status_code == 401
            c.post("/api/login", json={"password": PW})
            r = c.put(URL, json={"params": {"warn_pct": 70}}, headers={"Origin": "http://evil"})
            assert r.status_code == 403
            assert rule(c)["parameters"]["sources"]["warn_pct"] == "default"
    finally:
        svc.close()


def test_scope_options_list_the_inventory(client: TestClient) -> None:
    client.post("/api/sites", json={"name": "Lab"})
    o = client.get("/api/rules/scope-options").json()
    assert o["site"] == [{"value": "lab", "label": "Lab"}]
    assert {x["value"] for x in o["device_role"]} == {"gateway", "switch", "ap", "other"}
    assert "guest" in {x["value"] for x in o["segment_purpose"]}
    assert set(o) == {"site", "device", "device_role", "segment", "segment_purpose", "tag"}
