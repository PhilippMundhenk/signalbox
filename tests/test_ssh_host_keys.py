"""SSH host keys pinned per device (#526, ADR 0031): first trust stored, later runs without a
prompt, a changed key stops before any password with a warning and a finding, re-trust by name,
forget, and removal with the device. Against the simulated OpenWrt (SSH and ubus)."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from factories import SITE, T0, snapshot
from factories import device as observed
from signalbox.adapters.openwrt import OpenWrtAdapter
from signalbox.adapters.ssh import sha256_hex, ssh_fingerprint
from signalbox.merge import merge
from signalbox.model import SshHostKeyChange
from signalbox.rules import Severity, evaluate
from signalbox.rules.ssh_host_keys import RULES, host_key_changed
from signalbox.secrets import load_vault
from signalbox.service import Services, build
from signalbox.sim.openwrt_ssh import ROOT_PASSWORD, OpenWrtSsh, serve_ssh_in_thread
from signalbox.store import SCHEMA, DeviceRecord, Store, StoreError
from signalbox.web.app import create_app as web_app
from test_runner import Dev
from test_setup_api import PW, body
from test_setup_api import device as device
from test_setup_api import http as http
from test_setup_api import https_url as https_url
from test_setup_api import ssh as ssh
from test_setup_api import tls as tls

OTHER = "SHA256:" + "B" * 43


@pytest.fixture
def services(tmp_path: Path) -> Iterator[Services]:
    svc = build(
        tmp_path,
        env={"SIGNALBOX_AUTH_PASSWORD": PW},
        adapters={"openwrt": OpenWrtAdapter, "dev": Dev},
        rules=list(RULES),
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


def identity(payload: dict[str, Any]) -> dict[str, Any]:
    """The same request without the password: only the identity is fetched."""
    out = {**payload, "admin": {k: v for k, v in payload["admin"].items() if k != "secret"}}
    out.pop("trust", None)
    return out


def stored(url: str, port: int, **kw: Any) -> dict[str, Any]:
    """The setup of the stored device again (Repair Signalbox's access)."""
    return body(url, port, device={"device_id": "access-point"}, allow_writes=True, **kw)


def set_up(client: TestClient, url: str, port: int, fingerprint: str) -> None:
    done = client.post(
        "/api/devices/setup/apply", json=body(url, port, trust=fingerprint, allow_writes=True)
    )
    assert done.status_code == 200 and done.json()["ok"], done.text


def open_findings(services: Services) -> list[str]:
    services.runner.evaluate()
    return [r.finding.rule_id for r in services.store.findings()]


def test_first_trust_is_stored_and_later_runs_need_no_prompt(
    client: TestClient, services: Services, ssh: tuple[int, str], https_url: str
) -> None:
    port, fingerprint = ssh
    first = client.post("/api/devices/setup", json=identity(body(https_url, port))).json()
    assert first["host_key"] == {"state": "new", "fingerprint": fingerprint}
    set_up(client, https_url, port, fingerprint)
    keys = services.store.ssh_host_keys("access-point")
    assert keys.pin is not None and keys.pin.fingerprint == fingerprint
    assert keys.pin.algorithm == "ssh-ed25519" and keys.pin.action == "setup"
    assert keys.changed is None and keys.history == []
    shown = client.get("/api/devices").json()[0]["ssh_host_key"]
    assert shown["pin"]["fingerprint"] == fingerprint and shown["changed"] is None

    # the second run: the plan says the key is the confirmed one, no prompt needed
    again = client.post("/api/devices/setup", json=identity(stored(https_url, port))).json()
    assert again["host_key"]["state"] == "known"
    assert again["host_key"]["confirmed_at"] == keys.pin.confirmed_at.isoformat()
    rerun = client.post("/api/devices/setup/apply", json=stored(https_url, port, trust=fingerprint))
    assert rerun.status_code == 200 and rerun.json()["ok"], rerun.text
    after = services.store.ssh_host_keys("access-point")
    assert after.pin == keys.pin and after.history == []
    # the same key through Fix it: known as well
    fix = client.post(
        "/api/devices/access-point/fix",
        json={"remedy": "access", "admin": {"user": "root", "port": port}},
    ).json()
    assert fix["host_key"]["state"] == "known"
    assert "ssh.host-key-changed" not in open_findings(services)


def test_changed_key_stops_before_the_password_and_warns(
    client: TestClient,
    services: Services,
    ssh: tuple[int, str],
    https_url: str,
    device: OpenWrtSsh,
) -> None:
    port, fingerprint = ssh
    set_up(client, https_url, port, fingerprint)
    pinned = services.store.ssh_host_keys("access-point").pin
    assert pinned is not None
    # the device is reinstalled: the same router answers with a new host key
    with serve_ssh_in_thread(device) as (port2, fingerprint2):
        assert fingerprint2 != fingerprint
        device.passwords.clear()
        scripts = len(device.scripts)
        plan = client.post("/api/devices/setup", json=identity(stored(https_url, port2))).json()
        assert plan["host_key"] == {
            "state": "changed",
            "fingerprint": fingerprint2,
            "pinned": fingerprint,
            "algorithm": "ssh-ed25519",
            "confirmed_at": pinned.confirmed_at.isoformat(),
            "action": "setup",
        }
        # a run with the new key is refused before the adapter runs
        new = client.post(
            "/api/devices/setup/apply", json=stored(https_url, port2, trust=fingerprint2)
        )
        assert new.status_code == 409 and new.json()["error"] == "host_key_changed"
        answer = new.json()
        assert answer["message_id"] == "hostKey.changed"
        assert answer["params"]["old"] == fingerprint and answer["params"]["new"] == fingerprint2
        # a run with the old key meets the new one in the handshake
        old = client.post(
            "/api/devices/setup/apply", json=stored(https_url, port2, trust=fingerprint)
        )
        assert old.status_code == 409 and old.json()["error"] == "host_key_changed"
        # the same through the job of the UI, Fix it and fix all
        job = client.post(
            "/api/devices/setup/jobs", json=stored(https_url, port2, trust=fingerprint2)
        )
        assert job.status_code == 409
        fix = {
            "remedy": "access",
            "admin": {"user": "root", "secret": ROOT_PASSWORD, "port": port2},
        }
        refused = client.post(
            "/api/devices/access-point/fix/apply", json={**fix, "trust": fingerprint2}
        )
        assert refused.status_code == 409 and refused.json()["error"] == "host_key_changed"
        handshake = client.post(
            "/api/devices/access-point/fix/apply", json={**fix, "trust": fingerprint}
        )
        assert handshake.status_code == 409 and handshake.json()["error"] == "host_key_changed"
        items = [{"device_id": "access-point", "body": {**fix, "trust": fingerprint2}}]
        assert client.post("/api/fixes/jobs", json={"items": items}).status_code == 409
        fix_plan = client.post(
            "/api/devices/access-point/fix",
            json={"remedy": "access", "admin": {"user": "root", "port": port2}},
        ).json()
        assert fix_plan["host_key"]["state"] == "changed"
        # the simulator never received a password, nothing ran on it
        assert device.passwords == []
        assert len(device.scripts) == scripts
        # the change is recorded and reported until it is decided
        keys = services.store.ssh_host_keys("access-point")
        assert keys.pin == pinned
        assert keys.changed is not None and keys.changed.fingerprint == fingerprint2
        assert "ssh.host-key-changed" in open_findings(services)
        change = services.runner.network().device("access-point")
        assert change is not None and change.ssh_host_key_change is not None
        assert change.ssh_host_key_change.presented == fingerprint2

        # re-trust: only the key the device presented can be named
        wrong = client.post(
            "/api/devices/access-point/ssh-host-key/trust", json={"fingerprint": OTHER}
        )
        assert wrong.status_code == 409
        assert (
            client.post(
                "/api/devices/ghost/ssh-host-key/trust", json={"fingerprint": OTHER}
            ).status_code
            == 404
        )
        ok = client.post(
            "/api/devices/access-point/ssh-host-key/trust", json={"fingerprint": fingerprint2}
        )
        assert ok.status_code == 200
        view = ok.json()["ssh_host_key"]
        assert view["pin"]["fingerprint"] == fingerprint2 and view["pin"]["action"] == "retrust"
        assert view["changed"] is None
        assert [p["fingerprint"] for p in view["history"]] == [fingerprint]
        assert view["history"][0]["retired_by"] == "retrust"
        assert "ssh.host-key-changed" not in open_findings(services)
        # now the run goes through with the new pin, and the password is sent
        done = client.post(
            "/api/devices/setup/apply", json=stored(https_url, port2, trust=fingerprint2)
        )
        assert done.status_code == 200 and done.json()["ok"], done.text
        assert ROOT_PASSWORD in device.passwords


def test_forget_and_delete_remove_the_pin(
    client: TestClient, services: Services, ssh: tuple[int, str], https_url: str
) -> None:
    port, fingerprint = ssh
    set_up(client, https_url, port, fingerprint)
    assert client.delete("/api/devices/ghost/ssh-host-key").status_code == 404
    gone = client.delete("/api/devices/access-point/ssh-host-key").json()["ssh_host_key"]
    assert gone["pin"] is None and gone["history"][0]["retired_by"] == "forget"
    # the next contact is a first contact again
    plan = client.post("/api/devices/setup", json=identity(stored(https_url, port))).json()
    assert plan["host_key"]["state"] == "new"
    rerun = client.post("/api/devices/setup/apply", json=stored(https_url, port, trust=fingerprint))
    assert rerun.json()["ok"]
    keys = services.store.ssh_host_keys("access-point")
    assert keys.pin is not None and len(keys.history) == 1
    assert client.delete("/api/devices/access-point").status_code == 204
    empty = services.store.ssh_host_keys("access-point")
    assert empty.pin is None and empty.history == [] and empty.changed is None


def test_a_read_over_ssh_sees_the_change_and_trusting_it_there_retrusts(
    client: TestClient, services: Services
) -> None:
    """Linux and EdgeOS pin the confirmed host key for reading as hex SHA-256 (#240)."""
    store = services.store
    pin = "SHA256:" + "C" * 43
    pin_hex = sha256_hex(pin)
    assert pin_hex is not None and ssh_fingerprint(pin_hex) == pin
    rec = DeviceRecord(
        id="gw",
        site_id="home",
        name="Gateway",
        role="gateway",
        adapter="dev",
        pinned_fingerprint=pin_hex,
    )
    store.put_device(rec, {"url": "untrusted64", "password": "p"}, Dev.manifest.config)
    store.pin_ssh_host_key("gw", pin, None, "setup")
    assert client.post("/api/devices/gw/test").json()["status"] == "untrusted-certificate"
    keys = store.ssh_host_keys("gw")
    assert keys.changed is not None and keys.changed.action == "read"
    assert sha256_hex(keys.changed.fingerprint) == "a" * 64
    assert "ssh.host-key-changed" in open_findings(services)
    assert client.post("/api/devices/gw/trust", json={"fingerprint": "a" * 64}).status_code == 200
    keys = store.ssh_host_keys("gw")
    assert keys.changed is None and keys.pin is not None
    assert sha256_hex(keys.pin.fingerprint) == "a" * 64
    # a device whose read pin is not its SSH key is left alone
    other = rec.model_copy(update={"id": "gw2", "pinned_fingerprint": "b" * 64})
    store.put_device(other, {"url": "untrusted64", "password": "p"}, Dev.manifest.config)
    store.pin_ssh_host_key("gw2", pin, None, "setup")
    client.post("/api/devices/gw2/test")
    assert store.ssh_host_keys("gw2").changed is None


# store ------------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    s = Store(tmp_path / "db.sqlite", load_vault(tmp_path, env={}))
    s.put_site(SITE)
    s.put_device(
        DeviceRecord(id="gw", site_id="home", name="Gateway", role="gateway", adapter="dev"),
        {"url": "u", "password": "p"},
        Dev.manifest.config,
    )
    yield s
    s.close()


def test_store_pins_notes_retrusts_and_forgets(store: Store) -> None:
    key1, key2 = "SHA256:" + "A" * 43, OTHER
    assert store.note_ssh_host_key_change("gw", key1, None, "setup") is False  # no pin yet
    with pytest.raises(StoreError, match="unknown device"):
        store.pin_ssh_host_key("ghost", key1, None, "setup")
    first = store.pin_ssh_host_key("gw", key1, None, "setup")
    # the same key again keeps the pin; a missing algorithm is completed
    same = store.pin_ssh_host_key("gw", key1, "ssh-ed25519", "fix:access")
    assert same.confirmed_at == first.confirmed_at and same.action == "setup"
    assert same.algorithm == "ssh-ed25519"
    assert store.note_ssh_host_key_change("gw", key1, None, "setup") is False
    assert store.note_ssh_host_key_change("gw", key2, "ssh-rsa", "fix:access") is True
    seen = store.ssh_host_keys("gw").changed
    assert seen is not None and seen.action == "fix:access"
    assert store.note_ssh_host_key_change("gw", key2, "ssh-rsa", "read") is True
    assert store.ssh_host_keys("gw").changed == seen  # the first sighting is kept
    assert list(store.ssh_host_key_changes()) == ["gw"]
    with pytest.raises(StoreError, match="not the changed"):
        store.retrust_ssh_host_key("gw", key1)
    new = store.retrust_ssh_host_key("gw", key2)
    assert new.fingerprint == key2 and new.algorithm == "ssh-rsa" and new.action == "retrust"
    keys = store.ssh_host_keys("gw")
    assert keys.changed is None and [p.fingerprint for p in keys.history] == [key1]
    assert store.ssh_host_key_changes() == {}
    assert store.forget_ssh_host_key("gw") is True
    assert store.forget_ssh_host_key("gw") is False
    assert [p.fingerprint for p in store.ssh_host_keys("gw").history] == [key2, key1]


def test_migration_adds_the_tables_and_keeps_the_devices(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite"
    db = sqlite3.connect(path, isolation_level=None)
    for number, script in enumerate(SCHEMA[:9], start=1):
        db.executescript(f"BEGIN; {script}; PRAGMA user_version = {number}; COMMIT;")
    db.execute("INSERT INTO sites (id, name) VALUES ('home', 'Home')")
    db.execute(
        "INSERT INTO devices (id, site_id, name, role, adapter, config, pinned_fingerprint) "
        "VALUES ('gw', 'home', 'Gateway', 'gateway', 'dev', '{}', ?)",
        ("a" * 64,),
    )
    db.close()
    store = Store(path, load_vault(tmp_path, env={}))
    try:
        assert store._db.execute("PRAGMA user_version").fetchone()[0] == len(SCHEMA) == 10
        rec = store.device("gw")
        assert rec is not None and rec.pinned_fingerprint == "a" * 64  # the certificate pin
        assert store.ssh_host_keys("gw").pin is None
        store.pin_ssh_host_key("gw", OTHER, None, "setup")
        assert store.ssh_host_keys("gw").pin is not None
    finally:
        store.close()


# rule -------------------------------------------------------------------------------


def test_rule_reports_a_changed_key_and_stays_quiet_otherwise() -> None:
    change = SshHostKeyChange(
        pinned="SHA256:" + "A" * 43,
        pinned_since=T0,
        presented=OTHER,
        seen_at=T0 + timedelta(days=3),
    )
    net = merge(
        [SITE],
        [
            snapshot(observed("gw", name="Gateway", ssh_host_key_change=change)),
            snapshot(observed("sw")),
        ],
    )
    (f,) = [f for f in evaluate(net, [host_key_changed]) if f.rule_id == host_key_changed.id]
    assert f.objects == ["gw"] and f.message_id == "hostKey.changed.finding"
    assert f.severity is Severity.WARNING and f.fix_id == "hostKey.changed.fix"
    assert f.params == {
        "device": "Gateway",
        "date": "2026-01-15",
        "old": change.pinned,
        "new": OTHER,
    }
    quiet = merge([SITE], [snapshot(observed("gw"))])
    assert evaluate(quiet, [host_key_changed]) == []
