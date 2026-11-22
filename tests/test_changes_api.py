import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from factories import SITE
from signalbox.model import DeviceRole, Link, LinkOrigin
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.store import DeviceRecord
from signalbox.web.app import create_app
from test_deploy import ENV, WANT
from writable import WConfig, Writable, snapshot_json


@pytest.fixture
def svc(tmp_path: Path) -> Iterator[Services]:
    Writable.reset()
    s = build(tmp_path, env=ENV, adapters={"w": Writable}, rules=RULES, link_sources=[])
    s.store.put_site(SITE)
    for dev, role in (("gw", DeviceRole.GATEWAY), ("ap", DeviceRole.AP)):
        rec = DeviceRecord(id=dev, site_id="home", name=dev, role=role, adapter="w")
        s.store.put_device(rec, {"host": "192.0.2.9", "password": "pw"}, WConfig)
    s.store.put_link(Link(id="up", a="gw/port/lan", b="ap/port/lan", origin=LinkOrigin.MANUAL))
    s.store.set_secret("psk", "the new passphrase")
    yield s
    s.close()


@pytest.fixture
def client(svc: Services) -> Iterator[TestClient]:
    with TestClient(create_app(svc, run_background=False)) as c:
        c.post("/api/login", json={"password": ENV["SIGNALBOX_AUTH_PASSWORD"]})
        yield c


def wait(c: TestClient, cid: str) -> dict:  # type: ignore[type-arg]
    for _ in range(100):
        rec = c.get(f"/api/changes/{cid}").json()
        if rec["status"] not in ("approved", "deploying"):
            return rec  # type: ignore[no-any-return]
        time.sleep(0.05)
    raise AssertionError("deployment did not finish")


def allow_writes(c: TestClient) -> None:
    for dev, role in (("gw", "gateway"), ("ap", "ap")):
        body = {
            "name": dev,
            "site_id": "home",
            "role": role,
            "adapter": "w",
            "allow_writes": True,
            "config": {"host": "192.0.2.9"},
        }
        assert c.put(f"/api/devices/{dev}", json=body).json()["allow_writes"] is True


def test_full_flow_through_the_api(client: TestClient, svc: Services) -> None:
    import asyncio

    asyncio.run(svc.runner.observe_all())
    assert client.post("/api/changes", json={"reason": "x"}).status_code == 409  # nothing declared
    client.put("/api/desired", json={"yaml": WANT})
    refused = client.post("/api/changes", json={"reason": "IoT"})
    assert refused.status_code == 422 and "not allowed" in refused.json()["message"]
    allow_writes(client)
    rec = client.post("/api/changes", json={"reason": "IoT network"}).json()
    cid = rec["id"]
    assert rec["status"] == "planned" and rec["plan"]["changes"][0]["text"]
    assert rec["events"][0]["event"] == "planned"
    assert client.post(f"/api/changes/{cid}/deploy").status_code == 409  # not approved
    assert client.post(f"/api/changes/{cid}/approve", json={}).json()["status"] == "approved"
    assert client.post(f"/api/changes/{cid}/approve", json={}).status_code == 409
    assert client.post(f"/api/changes/{cid}/deploy").status_code == 202
    done = wait(client, cid)
    assert done["status"] == "applied"
    assert [d["status"] for d in done["devices"]] == ["confirmed", "confirmed"]
    log = client.get("/api/changes").json()
    assert log["deploy_enabled"] and log["changes"][0]["id"] == cid
    backups = client.get("/api/backups?device=gw").json()
    assert len(backups) == 1 and "content" not in backups[0]
    # revert
    back = client.post(f"/api/changes/{cid}/revert", json={"reason": "not needed"}).json()
    assert back["reverts"] == cid
    client.post(f"/api/changes/{back['id']}/approve", json={})
    client.post(f"/api/changes/{back['id']}/deploy")
    assert wait(client, back["id"])["status"] == "applied"
    assert client.post(f"/api/changes/{cid}/revert", json={"reason": "x"}).status_code == 409
    # restore a backup
    before = snapshot_json("gw")
    r = client.post(f"/api/backups/{backups[0]['id']}/restore", json={"reason": "old config"})
    assert r.status_code == 201
    client.post(f"/api/changes/{r.json()['id']}/approve", json={})
    client.post(f"/api/changes/{r.json()['id']}/deploy")
    assert wait(client, r.json()["id"])["status"] == "applied"
    assert snapshot_json("gw") == before
    assert client.post("/api/backups/nope/restore", json={"reason": "x"}).status_code == 409


def test_refusals_and_reject(client: TestClient, svc: Services) -> None:
    import asyncio

    asyncio.run(svc.runner.observe_all())
    assert client.get("/api/changes/nope").status_code == 404
    assert client.post("/api/changes/nope/deploy").status_code == 404
    assert client.post("/api/changes/nope/reject").status_code == 409
    client.put("/api/desired", json={"yaml": "sites: {home: {ports: [{device: zz, port: '1'}]}}"})
    assert "zz" in client.post("/api/changes", json={"reason": "x"}).json()["message"]
    (svc.data_dir / "desired" / "bad.yaml").write_text("sites: [")
    assert client.post("/api/changes", json={"reason": "x"}).status_code == 422
    (svc.data_dir / "desired" / "bad.yaml").unlink()
    client.put("/api/desired", json={"yaml": WANT})
    allow_writes(client)
    cid = client.post("/api/changes", json={"reason": "x"}).json()["id"]
    svc.config.deploy.enabled = False
    client.post(f"/api/changes/{cid}/approve", json={})
    assert "turned off" in client.post(f"/api/changes/{cid}/deploy").json()["message"]
    assert client.post(f"/api/changes/{cid}/reject").json()["status"] == "rejected"
