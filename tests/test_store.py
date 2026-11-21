import os
import sqlite3
import stat
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from factories import SITE, T0, device, snapshot
from signalbox import config as cfgmod
from signalbox.adapters import AdapterConfig
from signalbox.config import ConfigError, load
from signalbox.model import DeviceRole, Link, LinkKind, LinkOrigin, Site
from signalbox.rules import Finding, Severity
from signalbox.secrets import SecretError, Vault, load_vault
from signalbox.store import SCHEMA, DeviceRecord, Store, StoreError, slug


class DevConfig(AdapterConfig):
    url: str
    username: str = "signalbox"
    password: SecretStr
    api_secret: SecretStr | None = None


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    s = Store(tmp_path / "db.sqlite", load_vault(tmp_path, env={}))
    s.put_site(SITE)
    yield s
    s.close()


def rec(**kw: object) -> DeviceRecord:
    base: dict[str, object] = {
        "id": "gw",
        "site_id": "home",
        "name": "Gateway",
        "role": DeviceRole.GATEWAY,
        "adapter": "test",
    }
    return DeviceRecord.model_validate(base | kw)


# config ----------------------------------------------------------------------------------


def test_config_first_start_writes_commented_file(tmp_path: Path) -> None:
    cfg = load(tmp_path / "data", env={})
    text = (tmp_path / "data" / "signalbox.yaml").read_text()
    assert "SIGNALBOX_SERVER_PORT" in text and text == cfgmod.TEMPLATE
    assert cfg.server.port == 8080 and cfg.auth.password is None and not cfg.mqtt.enabled


def test_config_template_matches_defaults(tmp_path: Path) -> None:
    assert load(tmp_path, env={}) == cfgmod.Config()


def test_config_file_and_env(tmp_path: Path) -> None:
    (tmp_path / "signalbox.yaml").write_text(
        "server: {port: 9000}\nmqtt: {host: broker}\nrules: {dhcp.one-server: {enabled: false}}\n"
    )
    cfg = load(
        tmp_path,
        env={
            "SIGNALBOX_SERVER_PORT": "9100",
            "SIGNALBOX_OBSERVE_INTERVAL_SECONDS": "60",
            "SIGNALBOX_MQTT_ENABLED": "true",
            "SIGNALBOX_AUTH_PASSWORD": "pw",
            "SIGNALBOX_SECRET_KEY": "ignored here",
            "OTHER": "x",
        },
    )
    assert cfg.server.port == 9100 and cfg.observe.interval_seconds == 60
    assert cfg.mqtt.enabled and cfg.mqtt.host == "broker"
    assert cfg.auth.password is not None and cfg.auth.password.get_secret_value() == "pw"
    assert not cfg.rules["dhcp.one-server"].enabled


@pytest.mark.parametrize(
    ("content", "env", "message"),
    [
        ("server: [", {}, "not valid YAML"),
        ("- a\n", {}, "mapping at the top level"),
        ("server: {port: 0}\n", {}, "server.port"),
        ("colour: red\n", {}, "colour"),
        ("", {"SIGNALBOX_SERVER_COLOUR": "red"}, "unknown setting SIGNALBOX_SERVER_COLOUR"),
    ],
)
def test_config_errors_are_readable(
    tmp_path: Path, content: str, env: dict[str, str], message: str
) -> None:
    (tmp_path / "signalbox.yaml").write_text(content)
    with pytest.raises(ConfigError, match=message):
        load(tmp_path, env=env)


def test_config_empty_file(tmp_path: Path) -> None:
    (tmp_path / "signalbox.yaml").write_text("")
    assert load(tmp_path, env={}).server.port == 8080


def test_config_uses_process_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIGNALBOX_SERVER_PORT", "8181")
    assert load(tmp_path).server.port == 8181


# secrets ---------------------------------------------------------------------------------


def test_vault_key_file_created_private(tmp_path: Path) -> None:
    vault = load_vault(tmp_path / "d", env={})
    key = tmp_path / "d" / "secret.key"
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600
    token = vault.encrypt("hunter2")
    assert "hunter2" not in token and vault.decrypt(token) == "hunter2"
    assert load_vault(tmp_path / "d", env={}).decrypt(token) == "hunter2"


def test_vault_key_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("SIGNALBOX_SECRET_KEY", key)
    vault = load_vault(tmp_path)
    assert not (tmp_path / "secret.key").exists()
    assert Vault(key.encode()).decrypt(vault.encrypt("x")) == "x"


def test_vault_errors() -> None:
    with pytest.raises(SecretError, match="not a valid Fernet key"):
        Vault(b"short")
    a, b = Vault(Fernet.generate_key()), Vault(Fernet.generate_key())
    with pytest.raises(SecretError, match="secret key changed"):
        b.decrypt(a.encrypt("x"))


# store -----------------------------------------------------------------------------------


def test_slug() -> None:
    assert slug("Living Room AP") == "living-room-ap"
    assert slug("AP", ["ap", "ap-2"]) == "ap-3"
    assert slug("!!!") == "device"


def test_settings(store: Store) -> None:
    assert store.get_setting("x") is None
    store.set_setting("x", "1")
    store.set_setting("x", "2")
    assert store.get_setting("x") == "2"


def test_sites(store: Store) -> None:
    store.put_site(Site(id="home", name="Home renamed"))
    store.put_site(Site(id="office", name="Office"))
    assert [s.name for s in store.sites()] == ["Home renamed", "Office"]
    store.delete_site("office")
    assert [s.id for s in store.sites()] == ["home"]


def test_device_secrets_encrypted_and_kept(store: Store, tmp_path: Path) -> None:
    saved = store.put_device(rec(), {"url": "https://192.0.2.1", "password": "pw1"}, DevConfig)
    assert saved.secrets_set == ["password"] and saved.config == {
        "url": "https://192.0.2.1",
        "username": "signalbox",
    }
    db = sqlite3.connect(tmp_path / "db.sqlite")
    raw = db.execute("SELECT * FROM devices").fetchone()
    db.close()
    assert "pw1" not in repr(raw)

    # editing without a password keeps the stored one; a new one replaces it
    store.put_device(rec(name="GW"), {"url": "https://192.0.2.2", "password": ""}, DevConfig)
    cfg = store.adapter_config("gw", DevConfig)
    assert isinstance(cfg, DevConfig) and cfg.url == "https://192.0.2.2"
    assert cfg.password.get_secret_value() == "pw1"
    store.put_device(rec(), {"url": "x", "password": "pw2", "api_secret": "s"}, DevConfig)
    cfg = store.adapter_config("gw", DevConfig)
    assert isinstance(cfg, DevConfig)
    assert cfg.password.get_secret_value() == "pw2"
    assert cfg.api_secret is not None and cfg.api_secret.get_secret_value() == "s"
    assert [d.id for d in store.devices()] == ["gw"]
    assert store.device("nope") is None


def test_device_without_secrets(store: Store) -> None:
    class Plain(AdapterConfig):
        url: str

    saved = store.put_device(rec(), {"url": "http://192.0.2.1"}, Plain)
    assert saved.secrets_set == []
    assert store.adapter_config("gw", Plain) == Plain(url="http://192.0.2.1")


def test_device_validation_errors(store: Store) -> None:
    with pytest.raises(StoreError, match="password: Field required"):
        store.put_device(rec(), {"url": "x"}, DevConfig)
    with pytest.raises(StoreError, match="unknown site"):
        store.put_device(rec(site_id="mars"), {"url": "x", "password": "p"}, DevConfig)
    with pytest.raises(StoreError, match="unknown device"):
        store.adapter_config("nope", DevConfig)
    with pytest.raises(ValueError):
        rec(id="Bad ID")


def test_site_with_devices_cannot_be_deleted(store: Store) -> None:
    store.put_device(rec(), {"url": "x", "password": "p"}, DevConfig)
    with pytest.raises(StoreError, match="still has devices"):
        store.delete_site("home")


def test_certificate_trust(store: Store) -> None:
    store.put_device(rec(), {"url": "x", "password": "p"}, DevConfig)
    store.set_pending_fingerprint("gw", "ab")
    with pytest.raises(StoreError, match="not the certificate"):
        store.trust_fingerprint("gw", "cd")
    store.trust_fingerprint("gw", "ab")
    d = store.device("gw")
    assert d is not None and d.pinned_fingerprint == "ab" and d.pending_fingerprint is None
    # editing the device keeps the pin
    store.put_device(rec(name="x"), {"url": "y"}, DevConfig)
    d = store.device("gw")
    assert d is not None and d.pinned_fingerprint == "ab"
    with pytest.raises(StoreError, match="unknown device"):
        store.trust_fingerprint("nope", "ab")


def test_links(store: Store) -> None:
    link = Link(
        id="l1", a="gw/port/1", b="ap/port/1", kind=LinkKind.CABLE, origin=LinkOrigin.MANUAL
    )
    store.put_link(link)
    store.put_link(link.model_copy(update={"b": "ap/port/2"}))
    assert [x.b for x in store.links()] == ["ap/port/2"]
    store.delete_link("l1")
    assert store.links() == []


def test_snapshots_follow_devices(store: Store) -> None:
    store.put_device(rec(), {"url": "x", "password": "p"}, DevConfig)
    snap = snapshot(device("gw"))
    store.save_snapshot(snap)
    store.save_snapshot(snap.model_copy(update={"observed_at": T0 + timedelta(minutes=5)}))
    assert [s.observed_at for s in store.snapshots()] == [T0 + timedelta(minutes=5)]
    store.delete_device("gw")
    assert store.snapshots() == [] and store.devices() == []


def finding(fid: str) -> Finding:
    return Finding(id=fid, rule_id="r", severity=Severity.ERROR, title="t", message=fid)


def test_findings_history(store: Store) -> None:
    t1, t2, t3 = T0, T0 + timedelta(minutes=5), T0 + timedelta(minutes=10)
    store.record_findings([finding("a"), finding("b")], t1)
    store.record_findings([finding("a")], t2)
    open_ = store.findings()
    assert [(r.finding.id, r.first_seen, r.last_seen) for r in open_] == [("a", t1, t2)]
    every = {r.finding.id: r for r in store.findings(include_resolved=True)}
    assert every["b"].resolved_at == t2
    # b comes back: a new first_seen, no longer resolved
    store.record_findings([finding("a"), finding("b")], t3)
    every = {r.finding.id: r for r in store.findings(include_resolved=True)}
    assert every["b"].resolved_at is None and every["b"].first_seen == t3
    assert every["a"].first_seen == t1
    store.record_findings([], t3)
    assert store.prune_resolved(T0 + timedelta(hours=1)) == 2
    assert store.findings(include_resolved=True) == []


def test_reopen_keeps_data_and_refuses_newer_schema(tmp_path: Path) -> None:
    vault = load_vault(tmp_path, env={})
    s = Store(tmp_path / "db.sqlite", vault)
    s.put_site(SITE)
    s.close()
    again = Store(tmp_path / "db.sqlite", vault)
    assert again.sites() == [SITE]
    again._db.execute(f"PRAGMA user_version = {len(SCHEMA) + 1}")
    again.close()
    with pytest.raises(StoreError, match="newer Signalbox"):
        Store(tmp_path / "db.sqlite", vault)


def test_failed_transaction_rolls_back(store: Store) -> None:
    with pytest.raises(RuntimeError), store._tx() as db:
        db.execute("INSERT INTO settings (key, value) VALUES ('k', 'v')")
        raise RuntimeError("boom")
    assert store.get_setting("k") is None
