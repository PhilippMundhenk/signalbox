"""Setup and Fix it reuse the device's certificate pin, and every SSH host key type a device
offers is pinned (#535, ADR 0031 addendum).

A known certificate needs no prompt; a changed one is refused before the adapter runs (nothing
reaches the simulated OPNsense API, so no key or password is sent), recorded as the certificate
waiting to be trusted, reported, and trusted again only by its full fingerprint. Against the
simulated OpenWrt, a device offering Ed25519, ECDSA and RSA keys has all three pinned at the
first trust, so dropping one type is no change, while another key of a pinned type is.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

import asyncssh
import pytest
from fastapi.testclient import TestClient

from factories import SITE
from signalbox.adapters.openwrt import OpenWrtAdapter
from signalbox.adapters.opnsense import OpnsenseAdapter
from signalbox.adapters.provision import key_family
from signalbox.adapters.ssh import host_key_fingerprint
from signalbox.hostkeys import certificate_hex, certificate_state, refused
from signalbox.rules.certificate_checks import RULES as CERTIFICATE_RULES
from signalbox.rules.ssh_host_keys import RULES as SSH_RULES
from signalbox.service import Services, build
from signalbox.sim.openwrt import OpenWrtSim, create_app
from signalbox.sim.openwrt_ssh import ROOT_PASSWORD, OpenWrtSsh, serve_ssh_in_thread
from signalbox.sim.opnsense import KEY, SECRET, OpnsenseSimulator
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve
from signalbox.store import SCHEMA, DeviceRecord, Store
from signalbox.web.app import create_app as web_app

PW = "correct-horse-battery"


@pytest.fixture
def services(tmp_path: Path) -> Iterator[Services]:
    svc = build(
        tmp_path / "data",
        env={"SIGNALBOX_AUTH_PASSWORD": PW},
        adapters={"opnsense": OpnsenseAdapter, "openwrt": OpenWrtAdapter},
        rules=[*CERTIFICATE_RULES, *SSH_RULES],
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


@pytest.fixture
def tls(tmp_path: Path) -> TlsFiles:
    return self_signed_certificate(tmp_path / "tls")


@pytest.fixture
def sim() -> OpnsenseSimulator:
    return OpnsenseSimulator()


@pytest.fixture
def url(sim: OpnsenseSimulator, tls: TlsFiles) -> Iterator[str]:
    with serve(sim.app(), tls=tls) as served:
        yield served


def opn(url: str, stored: bool = False, **kw: Any) -> dict[str, Any]:
    device = {
        "name": "Firewall",
        "site_id": "home",
        "role": "gateway",
        "adapter": "opnsense",
        "config": {"url": url, "api_key": "", "api_secret": ""},
    }
    if stored:
        device["device_id"] = "firewall"
    return {"device": device, "admin": {"user": KEY, "secret": SECRET}, **kw}


def identity(payload: dict[str, Any]) -> dict[str, Any]:
    """The same request without the secret and the trust: only the identity is fetched."""
    out = {**payload, "admin": {k: v for k, v in payload["admin"].items() if k != "secret"}}
    out.pop("trust", None)
    return out


FIX = {"remedy": "privileges", "admin": {"user": KEY, "secret": SECRET}}


def set_up_firewall(client: TestClient, url: str, fingerprint: str) -> None:
    done = client.post("/api/devices/setup/apply", json=opn(url, trust=fingerprint))
    assert done.status_code == 200 and done.json()["ok"], done.text
    assert done.json()["device"]["id"] == "firewall"


def move(services: Services, url: str) -> None:
    """The stored firewall answers at another address now (its certificate pin stays)."""
    rec = services.store.device("firewall")
    assert rec is not None
    cfg = services.store.adapter_config("firewall", OpnsenseAdapter.manifest.config)
    values = {**cfg.model_dump(mode="json"), "url": url}
    for name in ("api_key", "api_secret"):
        values[name] = getattr(cfg, name).get_secret_value()
    services.store.put_device(rec, values, OpnsenseAdapter.manifest.config)


def test_known_certificate_needs_no_prompt(
    client: TestClient, services: Services, url: str, tls: TlsFiles, sim: OpnsenseSimulator
) -> None:
    first = client.post("/api/devices/setup", json=identity(opn(url))).json()
    assert first["host_key"] == {
        "kind": "certificate",
        "state": "new",
        "fingerprint": tls.fingerprint,
    }
    set_up_firewall(client, url, tls.fingerprint)
    rec = services.store.device("firewall")
    assert rec is not None and rec.pinned_fingerprint == tls.fingerprint
    assert rec.pinned_since is not None

    # the stored device again: the certificate is the pinned one, no prompt needed
    again = client.post("/api/devices/setup", json=identity(opn(url, stored=True))).json()
    assert again["host_key"] == {
        "kind": "certificate",
        "state": "known",
        "fingerprint": tls.fingerprint,
        "pinned": tls.fingerprint,
        "confirmed_at": rec.pinned_since.isoformat(),
    }
    rerun = client.post(
        "/api/devices/setup/apply", json=opn(url, stored=True, trust=tls.fingerprint)
    )
    assert rerun.status_code == 200 and rerun.json()["ok"], rerun.text
    # Fix it: known as well, and it runs with the pinned certificate
    plan = client.post("/api/devices/firewall/fix", json=identity(FIX)).json()
    assert plan["host_key"]["state"] == "known" and plan["host_key"]["kind"] == "certificate"
    fixed = client.post("/api/devices/firewall/fix/apply", json={**FIX, "trust": tls.fingerprint})
    assert fixed.status_code == 200, fixed.text
    after = services.store.device("firewall")
    assert after is not None and after.pinned_fingerprint == tls.fingerprint
    assert after.pending_fingerprint is None
    assert services.store.certificate_history("firewall") == []


def test_changed_certificate_is_refused_before_any_password(
    client: TestClient,
    services: Services,
    url: str,
    tls: TlsFiles,
    sim: OpnsenseSimulator,
    tmp_path: Path,
) -> None:
    set_up_firewall(client, url, tls.fingerprint)
    rec = services.store.device("firewall")
    assert rec is not None and rec.pinned_since is not None
    old = tls.fingerprint
    # the firewall is reinstalled: a new self-signed certificate
    other = self_signed_certificate(tmp_path / "other")
    new = other.fingerprint
    assert new != old
    with serve(sim.app(), tls=other) as url2:
        move(services, url2)
        sim.requests.clear()
        plan = client.post("/api/devices/setup", json=identity(opn(url2, stored=True))).json()
        assert plan["host_key"] == {
            "kind": "certificate",
            "state": "changed",
            "fingerprint": new,
            "pinned": old,
            "confirmed_at": rec.pinned_since.isoformat(),
        }
        # recorded as the certificate waiting to be trusted, as a reading records it
        waiting = services.store.device("firewall")
        assert waiting is not None and waiting.pending_fingerprint == new
        assert waiting.pinned_fingerprint == old

        # a run with the new certificate is refused before the adapter runs
        refused_new = client.post(
            "/api/devices/setup/apply", json=opn(url2, stored=True, trust=new)
        )
        assert refused_new.status_code == 409
        answer = refused_new.json()
        assert answer["error"] == "certificate_changed"
        assert answer["message_id"] == "certificate.changed"
        assert answer["fix_id"] == "certificate.changed.fix"
        assert answer["params"]["old"] == old and answer["params"]["new"] == new
        assert answer["params"]["date"] == rec.pinned_since.strftime("%Y-%m-%d")
        assert answer["host_key"]["state"] == "changed"
        assert SECRET not in refused_new.text
        # a run with the old certificate meets the new one in the handshake
        handshake = client.post("/api/devices/setup/apply", json=opn(url2, stored=True, trust=old))
        assert handshake.status_code == 409
        assert handshake.json()["error"] == "certificate_changed"
        # the job of the UI, Fix it and fix all
        job = client.post("/api/devices/setup/jobs", json=opn(url2, stored=True, trust=new))
        assert job.status_code == 409 and job.json()["error"] == "certificate_changed"
        for trust in (new, old):
            fix = client.post("/api/devices/firewall/fix/apply", json={**FIX, "trust": trust})
            assert fix.status_code == 409 and fix.json()["error"] == "certificate_changed"
        items = [{"device_id": "firewall", "body": {**FIX, "trust": new}}]
        assert client.post("/api/fixes/jobs", json={"items": items}).status_code == 409
        fix_plan = client.post("/api/devices/firewall/fix", json=identity(FIX)).json()
        assert fix_plan["host_key"]["state"] == "changed"
        # nothing reached the firewall's API: no key and no password was sent
        assert sim.requests == []

        # a reading sees the same change: reported until it is decided
        reading = client.post("/api/devices/firewall/test").json()
        assert reading["status"] == "untrusted-certificate"
        services.runner.evaluate()
        found = [r.finding for r in services.store.findings()]
        assert any(f.rule_id == "signalbox.read" and "not trusted" in f.message for f in found)

        # re-trust: only the certificate the device presented, named in full
        assert client.post("/api/devices/firewall/trust", json={"fingerprint": "0" * 64}).is_error
        ok = client.post("/api/devices/firewall/trust", json={"fingerprint": new})
        assert ok.status_code == 200
        history = client.get("/api/devices").json()[0]["certificate_history"]
        assert [h["fingerprint"] for h in history] == [old]
        assert history[0]["retired_by"] == "trust"
        assert datetime.fromisoformat(history[0]["pinned_since"]) == rec.pinned_since
        # now the setup knows the new certificate and goes through with it
        known = client.post("/api/devices/setup", json=identity(opn(url2, stored=True))).json()
        assert known["host_key"]["state"] == "known" and known["host_key"]["fingerprint"] == new
        done = client.post("/api/devices/setup/apply", json=opn(url2, stored=True, trust=new))
        assert done.status_code == 200 and done.json()["ok"], done.text
        assert sim.requests != []


def test_undated_pin_and_stale_certificate_in_a_request(services: Services, tls: TlsFiles) -> None:
    store = services.store
    rec = DeviceRecord(
        id="fw",
        site_id="home",
        name="Firewall",
        role="gateway",
        adapter="opnsense",
        pinned_fingerprint="ab" * 32,
        pinned_since=None,
    )
    store.put_device(
        rec,
        {"url": "https://192.0.2.1", "api_key": "k", "api_secret": "s"},
        OpnsenseAdapter.manifest.config,
    )
    # a pin from before Signalbox recorded its date
    store._db.execute("UPDATE devices SET pinned_since = NULL WHERE id = 'fw'")
    stored = store.device("fw")
    assert stored is not None and stored.pinned_since is None
    assert certificate_state(stored, "AB:" * 31 + "AB") == {
        "kind": "certificate",
        "state": "known",
        "fingerprint": "ab" * 32,
        "pinned": "ab" * 32,
        "confirmed_at": None,
    }
    assert certificate_hex("SHA256:" + "A" * 43) is None and certificate_hex("zz" * 32) is None
    # a certificate the device never presented: a plain refusal, nothing is recorded
    stale = refused(store, "fw", "Firewall", ["cd" * 32])
    assert stale is not None and stale["error"] == "untrusted"
    # the same once the device presented it: the warning, without a date
    store.set_pending_fingerprint("fw", "cd" * 32)
    changed = refused(store, "fw", "Firewall", ["cd" * 32])
    assert changed is not None and changed["message_id"] == "certificate.changedUndated"
    assert "since" not in changed["message"]
    # the pinned one, SSH keys and no device: nothing to refuse
    assert refused(store, "fw", "Firewall", ["ab" * 32, None]) is None
    assert refused(store, None, "Firewall", ["cd" * 32]) is None
    store.trust_fingerprint("fw", "cd" * 32)
    old = store.certificate_history("fw")
    assert [p.fingerprint for p in old] == ["ab" * 32] and old[0].pinned_since is None
    store.delete_device("fw")
    assert store.certificate_history("fw") == []


# SSH: every host key type the device offers (#535) -----------------------------------------


def _keys(*algs: str) -> list[asyncssh.SSHKey]:
    return [
        asyncssh.generate_private_key(a, key_size=2048)
        if a == "ssh-rsa"
        else asyncssh.generate_private_key(a)
        for a in algs
    ]


@pytest.fixture
def router(tmp_path: Path) -> Iterator[tuple[str, OpenWrtSsh]]:
    tls = self_signed_certificate(tmp_path / "router-tls")
    http = OpenWrtSim()
    device = OpenWrtSsh(http=http, certificate=tls.cert.read_bytes())
    device.host_keys = _keys("ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa")
    with serve(create_app(http), tls=tls) as served:
        yield served, device


def wrt(url: str, port: int, stored: bool = False, **kw: Any) -> dict[str, Any]:
    device = {
        "name": "Access point",
        "site_id": "home",
        "role": "ap",
        "adapter": "openwrt",
        "allow_writes": True,
        "config": {"url": url, "username": "signalbox", "password": ""},
    }
    if stored:
        device["device_id"] = "access-point"
    return {
        "device": device,
        "admin": {"user": "root", "secret": ROOT_PASSWORD, "port": port},
        **kw,
    }


def test_every_offered_key_type_is_pinned(
    client: TestClient, services: Services, router: tuple[str, OpenWrtSsh]
) -> None:
    url, device = router
    ed, ecdsa, rsa = (host_key_fingerprint(k) for k in device.host_keys)
    with serve_ssh_in_thread(device) as (port, presented):
        assert presented == ed
        first = client.post("/api/devices/setup", json=identity(wrt(url, port))).json()
        assert first["host_key"]["state"] == "new" and first["host_key"]["fingerprint"] == ed
        offered = {k["fingerprint"]: k["algorithm"] for k in first["host_key"]["offered"]}
        assert offered == {ecdsa: "ecdsa-sha2-nistp256", rsa: "ssh-rsa"}
        done = client.post("/api/devices/setup/apply", json=wrt(url, port, trust=ed))
        assert done.status_code == 200 and done.json()["ok"], done.text
    keys = services.store.ssh_host_keys("access-point")
    assert keys.pin is not None and keys.pin.fingerprint == ed
    assert keys.pin.algorithm == "ssh-ed25519"
    assert {p.fingerprint: p.algorithm for p in keys.also} == offered
    assert all(p.action == "setup" for p in keys.also)
    shown = client.get("/api/devices").json()[0]["ssh_host_key"]
    assert {p["fingerprint"] for p in shown["also"]} == {ecdsa, rsa}

    # the device drops its Ed25519 key: it negotiates ECDSA, which is pinned, so no change
    device.host_keys = device.host_keys[1:]
    with serve_ssh_in_thread(device) as (port2, presented2):
        assert presented2 == ecdsa
        plan = client.post("/api/devices/setup", json=identity(wrt(url, port2, True))).json()
        assert plan["host_key"]["state"] == "known"
        assert plan["host_key"]["algorithm"] == "ecdsa-sha2-nistp256"
        assert "offered" not in plan["host_key"]
        run = client.post("/api/devices/setup/apply", json=wrt(url, port2, True, trust=ecdsa))
        assert run.status_code == 200 and run.json()["ok"], run.text
    services.runner.evaluate()
    assert "ssh.host-key-changed" not in [r.finding.rule_id for r in services.store.findings()]

    # another ECDSA key: a key of a pinned type that differs is a change, nothing is sent
    device.host_keys = _keys("ecdsa-sha2-nistp256")
    other = host_key_fingerprint(device.host_keys[0])
    with serve_ssh_in_thread(device) as (port3, _):
        device.passwords.clear()
        plan = client.post("/api/devices/setup", json=identity(wrt(url, port3, True))).json()
        assert plan["host_key"]["state"] == "changed" and plan["host_key"]["pinned"] == ed
        refused_run = client.post(
            "/api/devices/setup/apply", json=wrt(url, port3, True, trust=other)
        )
        assert refused_run.status_code == 409
        assert refused_run.json()["error"] == "host_key_changed"
        assert device.passwords == []
    # re-trust names one key: the other types confirmed with the old one go to the history
    client.post("/api/devices/access-point/ssh-host-key/trust", json={"fingerprint": other})
    after = services.store.ssh_host_keys("access-point")
    assert after.pin is not None and after.pin.fingerprint == other and after.also == []
    assert {p.fingerprint for p in after.history} == {ed, ecdsa, rsa}


def test_offered_keys_store_rules(services: Services) -> None:
    store: Store = services.store
    rec = DeviceRecord(id="ap", site_id="home", name="AP", role="ap", adapter="openwrt")
    store.put_device(
        rec,
        {"url": "https://192.0.2.2", "username": "signalbox", "password": "x"},
        OpenWrtAdapter.manifest.config,
    )
    ed, ec, ec2, rsa = ("SHA256:" + c * 43 for c in "ABCD")
    # nothing pinned: nothing is added
    assert store.pin_offered_ssh_host_keys("ap", {ec: "ecdsa-sha2-nistp256"}, "setup") == []
    store.pin_ssh_host_key("ap", ed, "ssh-ed25519", "setup")
    also = store.pin_offered_ssh_host_keys(
        "ap",
        {
            ed: "ssh-ed25519",  # the confirmed key itself
            ec: "ecdsa-sha2-nistp256",
            ec2: "ecdsa-sha2-nistp384",  # a second key of a type already added
            rsa: "rsa-sha2-512",
        },
        "setup",
    )
    assert [p.fingerprint for p in also] == [ec, rsa]
    keys = store.ssh_host_keys("ap")
    assert keys.match(rsa) is not None and keys.match(ec2) is None
    # a key of a pinned type is still a change; the pinned ones are not
    assert store.note_ssh_host_key_change("ap", ec, None, "read") is False
    assert store.note_ssh_host_key_change("ap", ec2, None, "read") is True
    # the same key again keeps its pin and the other types
    store.pin_ssh_host_key("ap", ed, "ssh-ed25519", "setup")
    assert len(store.ssh_host_keys("ap").also) == 2
    assert store.forget_ssh_host_key("ap")
    gone = store.ssh_host_keys("ap")
    assert gone.pin is None and gone.also == [] and len(gone.history) == 3
    assert [key_family(a) for a in ("ssh-ed25519", "ecdsa-sha2-nistp521", "ssh-rsa", "x")] == [
        "ed25519",
        "ecdsa",
        "rsa",
        "x",
    ]


def test_schema_11_adds_the_columns(tmp_path: Path, services: Services) -> None:
    assert len(SCHEMA) == 11
    cols = {r[1] for r in services.store._db.execute("PRAGMA table_info(ssh_host_keys)")}
    assert "offered" in cols
    tables = {r[0] for r in services.store._db.execute("SELECT name FROM sqlite_master")}
    assert "certificate_pins" in tables
