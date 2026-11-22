"""SQLite storage: sites, devices (credentials encrypted), links, snapshots, findings history."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from signalbox.adapters import AdapterConfig, Backup
from signalbox.history import BackupInfo, ChangeEvent, ChangeRecord
from signalbox.model import DeviceRole, DeviceStatus, Link, Network, Site, Snapshot
from signalbox.rules import Finding
from signalbox.secrets import SecretError, Vault
from signalbox.sightings import (
    ANSWERED,
    CLIENT,
    CLIENT_SEGMENT,
    DEVICE,
    PORT,
    ClientHistory,
    DeviceHistory,
    History,
    LinkChange,
    PortHistory,
    SegmentChange,
    SegmentSighting,
    StatusChange,
    observed_values,
)

SCHEMA = [
    # version 1
    """
    CREATE TABLE sites (id TEXT PRIMARY KEY, name TEXT NOT NULL);
    CREATE TABLE devices (
        id TEXT PRIMARY KEY,
        site_id TEXT NOT NULL REFERENCES sites(id),
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        adapter TEXT NOT NULL,
        config TEXT NOT NULL,
        secrets TEXT,
        pinned_fingerprint TEXT,
        pending_fingerprint TEXT,
        enabled INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE links (id TEXT PRIMARY KEY, a TEXT NOT NULL, b TEXT NOT NULL, kind TEXT NOT NULL);
    CREATE TABLE snapshots (
        device_id TEXT PRIMARY KEY, observed_at TEXT NOT NULL, data TEXT NOT NULL
    );
    CREATE TABLE findings (
        id TEXT PRIMARY KEY,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        resolved_at TEXT,
        data TEXT NOT NULL
    );
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    """,
    # version 2: change tracking (#39) and per-device write permission (#38)
    """
    ALTER TABLE devices ADD COLUMN allow_writes INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE changes (
        id TEXT PRIMARY KEY, created_at TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL
    );
    CREATE TABLE change_events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        change_id TEXT NOT NULL,
        at TEXT NOT NULL,
        device_id TEXT,
        event TEXT NOT NULL,
        detail TEXT NOT NULL
    );
    CREATE TABLE backups (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        change_id TEXT,
        taken_at TEXT NOT NULL,
        format TEXT NOT NULL,
        content TEXT NOT NULL
    );
    """,
    # version 3: observation history for rules and the UI (#185)
    """
    CREATE TABLE sightings (
        kind TEXT NOT NULL,
        key TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        value TEXT,
        value_since TEXT NOT NULL,
        last_ok TEXT,
        PRIMARY KEY (kind, key)
    );
    CREATE TABLE sighting_changes (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        key TEXT NOT NULL,
        at TEXT NOT NULL,
        old TEXT NOT NULL,
        new TEXT NOT NULL
    );
    CREATE INDEX sighting_changes_at ON sighting_changes (at);
    """,
]


class StoreError(Exception):
    pass


class DeviceRecord(BaseModel):
    """A configured device. ``config`` holds the non-secret adapter settings."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    site_id: str
    name: str = Field(min_length=1, max_length=100)
    role: DeviceRole
    adapter: str
    config: dict[str, Any] = Field(default_factory=dict)
    #: Names of secret settings that are stored (values are never returned).
    secrets_set: list[str] = Field(default_factory=list)
    pinned_fingerprint: str | None = None
    pending_fingerprint: str | None = None
    enabled: bool = True
    #: Changes may be deployed to this device (off by default; see docs/CHANGES.md).
    allow_writes: bool = False


class FindingRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding: Finding
    first_seen: datetime
    last_seen: datetime
    resolved_at: datetime | None = None


def slug(text: str, taken: Iterable[str] = ()) -> str:
    """A device or site id from a name: lower case, dashes, unique among ``taken``."""
    base = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:50] or "device"
    used = set(taken)
    candidate, n = base, 2
    while candidate in used:
        candidate, n = f"{base}-{n}", n + 1
    return candidate


def _secret_fields(cls: type[AdapterConfig]) -> set[str]:
    out = set()
    for name, info in cls.model_fields.items():
        ann = info.annotation
        if ann is SecretStr or (ann is not None and SecretStr in getattr(ann, "__args__", ())):
            out.add(name)
    return out


def _validate(cls: type[AdapterConfig], values: dict[str, Any]) -> AdapterConfig:
    try:
        return cls.model_validate(values)
    except ValidationError as exc:
        msg = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        raise StoreError(msg) from exc


class Store:
    def __init__(self, path: Path, vault: Vault) -> None:
        self.path = path
        self.vault = vault
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA journal_mode = WAL")
        try:
            self._migrate()
        except BaseException:
            self._db.close()
            raise

    def close(self) -> None:
        self._db.close()

    # One connection is shared by the web threads and the runner: reads take the lock too, so
    # they never see a half-written transaction or interleave with one on the same connection.
    def _all(self, sql: str, args: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def _one(self, sql: str, args: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        rows = self._all(sql, args)
        return rows[0] if rows else None

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")

    def _migrate(self) -> None:
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version > len(SCHEMA):
            raise StoreError(
                f"the database was written by a newer Signalbox (schema {version}); "
                "update Signalbox or restore a backup"
            )
        for number, script in enumerate(SCHEMA[version:], start=version + 1):
            with self._lock:
                self._db.executescript(f"BEGIN; {script}; PRAGMA user_version = {number}; COMMIT;")

    # settings ---------------------------------------------------------------------------

    def get_setting(self, key: str) -> str | None:
        row = self._one("SELECT value FROM settings WHERE key = ?", (key,))
        return None if row is None else str(row[0])

    def set_setting(self, key: str, value: str) -> None:
        with self._tx() as db:
            db.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    # secrets (Wi-Fi passphrases of the desired state), encrypted ---------------------------

    # Besides the named secrets the deployer keeps (#188), never listed and never returned by the
    # API: the value a secret had before it was last replaced (``secret-previous:<name>``), the
    # passphrase a change replaced (``secret-version:<name>@<change id>``, for its revert) and the
    # passphrase Signalbox last put on an SSID (``wlan-passphrase:<device>/<ssid>``). Secret
    # names cannot contain "@" (the API refuses them), so a version never shadows a secret.

    def set_secret(self, name: str, value: str) -> None:
        old = self.get_setting(f"secret:{name}")
        if old is not None and self.vault.decrypt(old) != value:
            self.set_setting(f"secret-previous:{name}", old)
        self.set_setting(f"secret:{name}", self.vault.encrypt(value))

    def get_secret(self, name: str) -> str | None:
        """A secret's value; ``<name>@<change id>`` is a version kept by a deployment."""
        prefix = "secret-version:" if "@" in name else "secret:"
        return self._decrypted(prefix + name)

    def previous_secret(self, name: str) -> str | None:
        """The value ``name`` had before it was last replaced (None: never replaced)."""
        return self._decrypted(f"secret-previous:{name}")

    def _decrypted(self, key: str) -> str | None:
        token = self.get_setting(key)
        return None if token is None else self.vault.decrypt(token)

    def secret_names(self) -> list[str]:
        rows = self._all("SELECT key FROM settings WHERE key LIKE 'secret:%' ORDER BY key")
        return [str(r[0])[len("secret:") :] for r in rows]

    def delete_secret(self, name: str) -> None:
        with self._tx() as db:
            for key in (f"secret:{name}", f"secret-previous:{name}"):
                db.execute("DELETE FROM settings WHERE key = ?", (key,))

    def put_secret_version(self, version: str, value: str) -> None:
        """Keep ``value`` (encrypted) as ``<name>@<change id>``; :meth:`get_secret` reads it."""
        if "@" not in version:
            raise ValueError(f"not a secret version: {version!r}")
        self.set_setting(f"secret-version:{version}", self.vault.encrypt(value))

    def delete_secret_version(self, version: str) -> None:
        with self._tx() as db:
            db.execute("DELETE FROM settings WHERE key = ?", (f"secret-version:{version}",))

    def secret_versions(self) -> list[str]:
        rows = self._all("SELECT key FROM settings WHERE key LIKE 'secret-version:%' ORDER BY key")
        return [str(r[0])[len("secret-version:") :] for r in rows]

    def wlan_passphrase(self, device_id: str, ssid: str) -> tuple[str | None, list[str]]:
        """What the last applied change left on an SSID: the passphrase Signalbox set (None:
        unknown) and the secret versions that change still needs (for its revert, and the one
        it set)."""
        raw = self._decrypted(f"wlan-passphrase:{device_id}/{ssid}")
        data = json.loads(raw) if raw is not None else {}
        return data.get("value"), list(data.get("versions", []))

    def set_wlan_passphrase(
        self, device_id: str, ssid: str, value: str | None, versions: Iterable[str] = ()
    ) -> None:
        key = f"wlan-passphrase:{device_id}/{ssid}"
        kept = sorted(versions)
        if value is None and not kept:
            with self._tx() as db:
                db.execute("DELETE FROM settings WHERE key = ?", (key,))
        else:
            data = json.dumps({"value": value, "versions": kept})
            self.set_setting(key, self.vault.encrypt(data))

    def forget_wlan_passphrases(self, device_id: str) -> None:
        """Forget what Signalbox deployed to the SSIDs of a device (restored, or deleted)."""
        mark = f"wlan-passphrase:{device_id}/"
        with self._tx() as db:
            db.execute("DELETE FROM settings WHERE substr(key, 1, ?) = ?", (len(mark), mark))

    # sites ------------------------------------------------------------------------------

    def sites(self) -> list[Site]:
        rows = self._all("SELECT id, name FROM sites ORDER BY id")
        return [Site(id=r["id"], name=r["name"]) for r in rows]

    def put_site(self, site: Site) -> None:
        with self._tx() as db:
            db.execute(
                "INSERT INTO sites (id, name) VALUES (?, ?) "
                "ON CONFLICT(id) DO UPDATE SET name = excluded.name",
                (site.id, site.name),
            )

    def delete_site(self, site_id: str) -> None:
        with self._tx() as db:
            used = db.execute("SELECT COUNT(*) FROM devices WHERE site_id = ?", (site_id,))
            if used.fetchone()[0]:
                raise StoreError("the site still has devices; move or delete them first")
            db.execute("DELETE FROM sites WHERE id = ?", (site_id,))

    # devices ----------------------------------------------------------------------------

    def _record(self, row: sqlite3.Row) -> DeviceRecord:
        try:
            secrets = json.loads(self.vault.decrypt(row["secrets"])) if row["secrets"] else {}
        except SecretError:
            secrets = {}  # shown as "not set"; reading the device reports the reason
        return DeviceRecord(
            id=row["id"],
            site_id=row["site_id"],
            name=row["name"],
            role=row["role"],
            adapter=row["adapter"],
            config=json.loads(row["config"]),
            secrets_set=sorted(secrets),
            pinned_fingerprint=row["pinned_fingerprint"],
            pending_fingerprint=row["pending_fingerprint"],
            enabled=bool(row["enabled"]),
            allow_writes=bool(row["allow_writes"]),
        )

    def devices(self) -> list[DeviceRecord]:
        rows = self._all("SELECT * FROM devices ORDER BY id")
        return [self._record(r) for r in rows]

    def device(self, device_id: str) -> DeviceRecord | None:
        row = self._one("SELECT * FROM devices WHERE id = ?", (device_id,))
        return None if row is None else self._record(row)

    def put_device(
        self,
        record: DeviceRecord,
        values: dict[str, Any],
        config_cls: type[AdapterConfig],
    ) -> DeviceRecord:
        """Create or update a device from form values.

        A secret setting that is missing or empty keeps its stored value, so the UI never needs
        to see a password to change the address. Raises StoreError with readable messages.
        """
        secret_names = _secret_fields(config_cls)
        old_row = self._one("SELECT * FROM devices WHERE id = ?", (record.id,))
        old_secrets: dict[str, str] = (
            json.loads(self.vault.decrypt(old_row["secrets"]))
            if old_row is not None and old_row["secrets"]
            else {}
        )
        merged = {k: v for k, v in values.items() if not (k in secret_names and v in (None, ""))}
        for name in secret_names:
            if name not in merged and name in old_secrets:
                merged[name] = old_secrets[name]
        cfg = _validate(config_cls, merged)
        plain = cfg.model_dump(mode="json", exclude=secret_names)
        secrets = {
            name: value.get_secret_value()
            for name in secret_names
            if isinstance(value := getattr(cfg, name), SecretStr)
        }
        with self._tx() as db:
            if not db.execute("SELECT 1 FROM sites WHERE id = ?", (record.site_id,)).fetchone():
                raise StoreError(f"unknown site {record.site_id}")
            db.execute(
                "INSERT INTO devices (id, site_id, name, role, adapter, config, secrets, "
                "pinned_fingerprint, pending_fingerprint, enabled, allow_writes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
                "site_id = excluded.site_id, name = excluded.name, role = excluded.role, "
                "adapter = excluded.adapter, config = excluded.config, "
                "secrets = excluded.secrets, enabled = excluded.enabled, "
                "allow_writes = excluded.allow_writes",
                (
                    record.id,
                    record.site_id,
                    record.name,
                    record.role.value,
                    record.adapter,
                    json.dumps(plain, sort_keys=True),
                    self.vault.encrypt(json.dumps(secrets)) if secrets else None,
                    record.pinned_fingerprint,
                    record.pending_fingerprint,
                    int(record.enabled),
                    int(record.allow_writes),
                ),
            )
        stored = self.device(record.id)
        assert stored is not None
        return stored

    def adapter_config(self, device_id: str, config_cls: type[AdapterConfig]) -> AdapterConfig:
        row = self._one("SELECT * FROM devices WHERE id = ?", (device_id,))
        if row is None:
            raise StoreError(f"unknown device {device_id}")
        values = json.loads(row["config"])
        if row["secrets"]:
            values.update(json.loads(self.vault.decrypt(row["secrets"])))
        return _validate(config_cls, values)

    def delete_device(self, device_id: str) -> None:
        self.forget_wlan_passphrases(device_id)
        with self._tx() as db:
            db.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            db.execute("DELETE FROM snapshots WHERE device_id = ?", (device_id,))
            # its history, its ports' and that of the devices it manages (``<id>/...``)
            for table in ("sightings", "sighting_changes"):
                db.execute(
                    f"DELETE FROM {table} WHERE kind IN (?, ?) "
                    "AND (key = ? OR substr(key, 1, ?) = ?)",
                    (DEVICE, PORT, device_id, len(device_id) + 1, f"{device_id}/"),
                )

    def set_pending_fingerprint(self, device_id: str, fingerprint: str | None) -> None:
        with self._tx() as db:
            db.execute(
                "UPDATE devices SET pending_fingerprint = ? WHERE id = ?", (fingerprint, device_id)
            )

    def trust_fingerprint(self, device_id: str, fingerprint: str) -> None:
        """Pin the certificate the device presented. Only the pending one can be trusted."""
        record = self.device(device_id)
        if record is None:
            raise StoreError(f"unknown device {device_id}")
        if record.pending_fingerprint != fingerprint:
            raise StoreError("this is not the certificate the device presented last")
        with self._tx() as db:
            db.execute(
                "UPDATE devices SET pinned_fingerprint = ?, pending_fingerprint = NULL "
                "WHERE id = ?",
                (fingerprint, device_id),
            )

    # links ------------------------------------------------------------------------------

    def links(self) -> list[Link]:
        rows = self._all("SELECT id, a, b, kind FROM links ORDER BY id")
        return [Link(id=r["id"], a=r["a"], b=r["b"], kind=r["kind"], origin="manual") for r in rows]

    def put_link(self, link: Link) -> None:
        with self._tx() as db:
            db.execute(
                "INSERT INTO links (id, a, b, kind) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO "
                "UPDATE SET a = excluded.a, b = excluded.b, kind = excluded.kind",
                (link.id, link.a, link.b, link.kind.value),
            )

    def delete_link(self, link_id: str) -> None:
        with self._tx() as db:
            db.execute("DELETE FROM links WHERE id = ?", (link_id,))

    # snapshots --------------------------------------------------------------------------

    def save_snapshot(self, snapshot: Snapshot) -> None:
        with self._tx() as db:
            db.execute(
                "INSERT INTO snapshots (device_id, observed_at, data) VALUES (?, ?, ?) "
                "ON CONFLICT(device_id) DO UPDATE SET observed_at = excluded.observed_at, "
                "data = excluded.data",
                (snapshot.device.id, snapshot.observed_at.isoformat(), snapshot.model_dump_json()),
            )

    def snapshots(self) -> list[Snapshot]:
        rows = self._all(
            "SELECT s.data FROM snapshots s JOIN devices d ON d.id = s.device_id "
            "ORDER BY s.device_id"
        )
        return [Snapshot.model_validate_json(r["data"]) for r in rows]

    # findings ---------------------------------------------------------------------------

    def record_findings(self, findings: Iterable[Finding], now: datetime) -> None:
        """Store the current findings; findings no longer present are marked resolved."""
        current = {f.id: f for f in findings}
        stamp = now.isoformat()
        with self._tx() as db:
            for f in current.values():
                db.execute(
                    "INSERT INTO findings (id, first_seen, last_seen, resolved_at, data) "
                    "VALUES (?, ?, ?, NULL, ?) ON CONFLICT(id) DO UPDATE SET "
                    "last_seen = excluded.last_seen, data = excluded.data, "
                    "first_seen = CASE WHEN findings.resolved_at IS NULL "
                    "THEN findings.first_seen ELSE excluded.first_seen END, resolved_at = NULL",
                    (f.id, stamp, stamp, f.model_dump_json()),
                )
            open_ids = [
                r[0] for r in db.execute("SELECT id FROM findings WHERE resolved_at IS NULL")
            ]
            for fid in open_ids:
                if fid not in current:
                    db.execute("UPDATE findings SET resolved_at = ? WHERE id = ?", (stamp, fid))

    def findings(self, include_resolved: bool = False) -> list[FindingRecord]:
        sql = "SELECT * FROM findings"
        if not include_resolved:
            sql += " WHERE resolved_at IS NULL"
        rows = self._all(sql + " ORDER BY first_seen, id")
        return [
            FindingRecord(
                finding=Finding.model_validate_json(r["data"]),
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
                resolved_at=r["resolved_at"],
            )
            for r in rows
        ]

    # change tracking (append-only) ------------------------------------------------------

    def put_change(self, record: ChangeRecord) -> None:
        with self._tx() as db:
            db.execute(
                "INSERT INTO changes (id, created_at, status, data) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET status = excluded.status, data = excluded.data",
                (
                    record.id,
                    record.created_at.isoformat(),
                    record.status.value,
                    record.model_dump_json(),
                ),
            )

    def change(self, change_id: str) -> ChangeRecord | None:
        row = self._one("SELECT data FROM changes WHERE id = ?", (change_id,))
        return None if row is None else ChangeRecord.model_validate_json(row["data"])

    def changes(self, limit: int = 200) -> list[ChangeRecord]:
        rows = self._all(
            "SELECT data FROM changes ORDER BY created_at DESC, id DESC LIMIT ?", (limit,)
        )
        return [ChangeRecord.model_validate_json(r["data"]) for r in rows]

    def add_event(
        self, change_id: str, at: datetime, device_id: str | None, event: str, detail: str = ""
    ) -> None:
        with self._tx() as db:
            db.execute(
                "INSERT INTO change_events (change_id, at, device_id, event, detail) "
                "VALUES (?, ?, ?, ?, ?)",
                (change_id, at.isoformat(), device_id, event, detail),
            )

    def events(self, change_id: str | None = None) -> list[ChangeEvent]:
        sql = "SELECT * FROM change_events"
        args: tuple[Any, ...] = ()
        if change_id is not None:
            sql, args = sql + " WHERE change_id = ?", (change_id,)
        return [
            ChangeEvent(
                seq=r["seq"],
                change_id=r["change_id"],
                at=r["at"],
                device_id=r["device_id"],
                event=r["event"],
                detail=r["detail"],
            )
            for r in self._all(sql + " ORDER BY seq", args)
        ]

    def put_backup(self, backup: Backup, change_id: str | None) -> str:
        backup_id = f"{backup.device_id}-{backup.taken_at.strftime('%Y%m%dT%H%M%S%f')}"
        with self._tx() as db:
            db.execute(
                "INSERT INTO backups (id, device_id, change_id, taken_at, format, content) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    backup_id,
                    backup.device_id,
                    change_id,
                    backup.taken_at.isoformat(),
                    backup.format,
                    self.vault.encrypt(backup.content),
                ),
            )
        return backup_id

    def backup(self, backup_id: str) -> Backup | None:
        row = self._one("SELECT * FROM backups WHERE id = ?", (backup_id,))
        if row is None:
            return None
        return Backup(
            device_id=row["device_id"],
            taken_at=row["taken_at"],
            format=row["format"],
            content=self.vault.decrypt(row["content"]),
        )

    def backups(self, device_id: str | None = None) -> list[BackupInfo]:
        sql = (
            "SELECT id, device_id, change_id, taken_at, format, length(content) AS size "
            "FROM backups"
        )
        args: tuple[Any, ...] = ()
        if device_id is not None:
            sql, args = sql + " WHERE device_id = ?", (device_id,)
        return [
            BackupInfo(
                id=r["id"],
                device_id=r["device_id"],
                change_id=r["change_id"],
                taken_at=r["taken_at"],
                format=r["format"],
                size=r["size"],
            )
            for r in self._all(sql + " ORDER BY taken_at DESC", args)
        ]

    def prune_resolved(self, before: datetime) -> int:
        with self._tx() as db:
            cur = db.execute(
                "DELETE FROM findings WHERE resolved_at IS NOT NULL AND resolved_at < ?",
                (before.isoformat(),),
            )
            return cur.rowcount

    # observation history (#185) ---------------------------------------------------------

    def record_history(self, net: Network, now: datetime) -> None:
        """Record one observation round: sightings, last values and their changes."""
        stamp = now.isoformat()
        seen = observed_values(net)
        with self._tx() as db:
            known = {
                (r["kind"], r["key"]): r["value"]
                for r in db.execute("SELECT kind, key, value FROM sightings")
            }
            for (kind, key), value in seen.items():
                ok = stamp if kind == DEVICE and DeviceStatus(str(value)) in ANSWERED else None
                if (kind, key) not in known:
                    db.execute(
                        "INSERT INTO sightings (kind, key, first_seen, last_seen, value, "
                        "value_since, last_ok) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (kind, key, stamp, stamp, value, stamp, ok),
                    )
                    continue
                old = known[(kind, key)]
                if value is not None and value != old:
                    if old is not None:
                        db.execute(
                            "INSERT INTO sighting_changes (kind, key, at, old, new) "
                            "VALUES (?, ?, ?, ?, ?)",
                            (kind, key, stamp, old, value),
                        )
                    db.execute(
                        "UPDATE sightings SET value = ?, value_since = ? "
                        "WHERE kind = ? AND key = ?",
                        (value, stamp, kind, key),
                    )
                db.execute(
                    "UPDATE sightings SET last_seen = ?, last_ok = coalesce(?, last_ok) "
                    "WHERE kind = ? AND key = ?",
                    (stamp, ok, kind, key),
                )
            db.execute(
                "INSERT INTO settings (key, value) VALUES ('history:since', ?) "
                "ON CONFLICT(key) DO NOTHING",
                (stamp,),
            )
            db.execute(
                "INSERT INTO settings (key, value) VALUES ('history:observations', '1') "
                "ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1"
            )

    def prune_history(self, before: datetime) -> int:
        """Delete sightings not seen since ``before`` and older changes."""
        stamp = before.isoformat()
        with self._tx() as db:
            gone = db.execute("DELETE FROM sightings WHERE last_seen < ?", (stamp,)).rowcount
            db.execute("DELETE FROM sighting_changes WHERE at < ?", (stamp,))
            return int(gone)

    def history(self, now: datetime, days: int) -> History:
        """The recorded history as rules and the UI see it."""
        changes: dict[tuple[str, str], list[sqlite3.Row]] = {}
        for r in self._all("SELECT * FROM sighting_changes ORDER BY seq"):
            changes.setdefault((r["kind"], r["key"]), []).append(r)
        devices: dict[str, DeviceHistory] = {}
        clients: dict[str, ClientHistory] = {}
        ports: dict[str, PortHistory] = {}
        segments: dict[str, list[SegmentSighting]] = {}
        for r in self._all("SELECT * FROM sightings ORDER BY kind, key"):
            kind, key = r["kind"], str(r["key"])
            own = changes.get((kind, key), [])
            if kind == DEVICE:
                devices[key] = DeviceHistory(
                    first_seen=r["first_seen"],
                    last_seen=r["last_seen"],
                    last_ok=r["last_ok"],
                    status=r["value"],
                    status_since=r["value_since"],
                    changes=[StatusChange(at=c["at"], old=c["old"], new=c["new"]) for c in own],
                )
            elif kind == PORT:
                ports[key] = PortHistory(
                    first_seen=r["first_seen"],
                    last_seen=r["last_seen"],
                    up=r["value"] == "up",
                    since=r["value_since"],
                    changes=[LinkChange(at=c["at"], up=c["new"] == "up") for c in own],
                )
            elif kind == CLIENT:
                clients[key] = ClientHistory(
                    mac=key,
                    first_seen=r["first_seen"],
                    last_seen=r["last_seen"],
                    segment_id=r["value"],
                    moves=[SegmentChange(at=c["at"], old=c["old"], new=c["new"]) for c in own],
                )
            elif kind == CLIENT_SEGMENT:
                mac, _, seg = key.partition(" ")
                segments.setdefault(mac, []).append(
                    SegmentSighting(
                        segment_id=seg, first_seen=r["first_seen"], last_seen=r["last_seen"]
                    )
                )
        for mac, seen in segments.items():
            if mac in clients:
                ordered = sorted(seen, key=lambda s: (s.first_seen, s.segment_id))
                clients[mac] = clients[mac].model_copy(update={"segments": ordered})
        return History(
            now=now,
            since=self.get_setting("history:since"),
            observations=int(self.get_setting("history:observations") or 0),
            days=days,
            devices=devices,
            clients=clients,
            ports=ports,
        )
