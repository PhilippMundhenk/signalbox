"""Transactional deployment and rollback (components "deployment" #38 and "rollback" #40).

A deployment applies an approved plan as one transaction across devices. Per device, in plan
order:

1. **lock** the device and read it again; every change's ``old`` value must still be what the
   device has (no blind overwrites)
2. **backup** the full configuration (stored encrypted with the change record)
3. **apply** through the integration; devices that can roll back by themselves get a deadline
4. **verify**: read again, every change's ``new`` value must be there, the device must answer,
   and the checks must not report new errors
5. **confirm**, or roll this device back

When a device fails, the devices already changed in this deployment are rolled back in reverse
order (inverse changes first, the backup if that fails). Every step is written to the change
record and the event log.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from signalbox.adapters import Adapter, AdapterContext, AdapterError, WritesConfig
from signalbox.changes import (
    Change,
    ChangeKind,
    Plan,
    PlanError,
    WlanValue,
    observed_dhcp,
    observed_port,
    observed_router,
    observed_wlan,
    revert_plan,
)
from signalbox.history import ChangeRecord, ChangeStatus, DeviceResult, DeviceStatus
from signalbox.model import DeviceStatus as ReadStatus
from signalbox.model import Network, Snapshot, passphrase_fingerprint
from signalbox.rules import Severity, evaluate
from signalbox.runner import Runner
from signalbox.store import Store

log = logging.getLogger(__name__)


class DeployError(Exception):
    """A deployment cannot start (not approved, writes off, device not writable, ...)."""


def _now() -> datetime:
    return datetime.now(UTC)


def current_value(net: Network, c: Change) -> Any:
    """What the device has now for the object a change touches (comparable with old/new)."""
    if c.kind is ChangeKind.ROUTER:
        return observed_router(net, c.device_id, c.key)
    if c.kind is ChangeKind.DHCP:
        return observed_dhcp(net, c.device_id, c.key)
    if c.kind is ChangeKind.RESERVATION:
        from signalbox.changes import ReservationValue

        sid, mac = c.key.rsplit("/", 1)
        for srv in net.dhcp_servers:
            if srv.device_id == c.device_id and srv.segment_id == sid:
                for r in srv.reservations:
                    if r.mac == mac:
                        return ReservationValue(mac=r.mac, address=r.address, hostname=r.hostname)
        return None
    if c.kind is ChangeKind.PORT:
        return observed_port(net, c.key)
    return observed_wlan(net, c.device_id, c.key)


#: Fields of a planned value that are left to the device when the plan has None for them.
UNSPECIFIED: dict[ChangeKind, tuple[str, ...]] = {
    ChangeKind.WLAN: (
        "pmf",
        "roaming_80211r",
        "roaming_80211k",
        "roaming_80211v",
        "client_isolation",
    ),
    ChangeKind.DHCP: ("lease_seconds",),
}


def matches(net: Network, c: Change, want: Any, secrets: Mapping[str, str]) -> bool:
    """Whether the device has ``want`` (old or new value of ``c``) for the changed object."""
    have = current_value(net, c)
    if want is not None and have is not None:
        # None in a planned value means "not specified": whatever the device reports is fine
        loose = [f for f in UNSPECIFIED.get(c.kind, ()) if getattr(want, f) is None]
        want = want.model_copy(update={f: getattr(have, f) for f in loose})
        if c.kind is ChangeKind.DHCP and not want.enabled:
            # a switched-off server serves no pool; not every device reports the configured one
            have = have.model_copy(update={"pool": None})
            want = want.model_copy(update={"pool": None})
    if c.kind is ChangeKind.WLAN and want is not None and have is not None:
        name = want.passphrase_secret
        if name and name in secrets:
            w = next(x for x in net.wlans if x.device_id == c.device_id and x.ssid == c.key)
            fp = passphrase_fingerprint(c.key, secrets[name])
            if w.passphrase_fingerprint not in (None, fp):
                return False
        want = want.model_copy(update={"passphrase_secret": None})
    if c.kind is ChangeKind.PORT and want is None:
        from signalbox.changes import PortValue

        want = PortValue()
    return bool(have == want)


class Deployer:
    def __init__(self, runner: Runner, secrets: Mapping[str, str] | None = None) -> None:
        self.runner = runner
        self.store: Store = runner.store
        self.locks: dict[str, asyncio.Lock] = {}
        self._extra_secrets = dict(secrets or {})

    # records ------------------------------------------------------------------------------

    def _event(self, rec: ChangeRecord, device: str | None, event: str, detail: str = "") -> None:
        self.store.add_event(rec.id, _now(), device, event, detail)

    def _save(self, rec: ChangeRecord) -> None:
        self.store.put_change(rec)

    def secrets(self, plan: Plan) -> dict[str, str]:
        names = {
            v.passphrase_secret
            for c in plan.changes
            for v in (c.new, c.old)
            if isinstance(v, WlanValue) and v.passphrase_secret
        }
        out = dict(self._extra_secrets)
        for name in names:
            value = self.store.get_secret(name)
            if value is None:
                raise DeployError(f"secret {name!r} is not stored")
            out[name] = value
        return out

    def owner(self, device_id: str) -> str:
        """The configured device that reaches ``device_id`` (itself, or its controller)."""
        dev = self.runner.network().device(device_id)
        return dev.managed_by if dev is not None and dev.managed_by else device_id

    def adapter(self, device_id: str) -> Adapter:
        rec = self.store.device(self.owner(device_id))
        if rec is None:
            raise DeployError(f"device {device_id} is not configured")
        cls = self.runner.adapters.get(rec.adapter)
        if cls is None:
            raise DeployError(f"adapter {rec.adapter!r} is not installed")
        ctx = AdapterContext(
            site_id=rec.site_id,
            device_id=rec.id,
            device_name=rec.name,
            role=rec.role,
            config=self.store.adapter_config(rec.id, cls.manifest.config),
            pinned_fingerprint=rec.pinned_fingerprint,
            timeout=self.runner.config.observe.timeout_seconds,
        )
        return cls(ctx)

    def _writable(self, device_id: str, kinds: set[ChangeKind]) -> None:
        rec = self.store.device(self.owner(device_id))
        if rec is None:
            raise DeployError(f"device {device_id} is not configured")
        if not rec.allow_writes:
            raise DeployError(f"{rec.name}: changes are not allowed on this device (settings)")
        cls = self.runner.adapters.get(rec.adapter)
        if cls is None:
            raise DeployError(f"adapter {rec.adapter!r} is not installed")
        missing = kinds - set(cls.manifest.writes)
        if missing:
            names = ", ".join(sorted(k.value for k in missing))
            raise DeployError(
                f"{rec.name}: the {cls.manifest.name} integration cannot change {names}"
            )

    async def prepare(
        self,
        plan: Plan,
        reason: str,
        author: str,
        desired_commit: str | None = None,
        reverts: str | None = None,
        restore_backup_id: str | None = None,
    ) -> ChangeRecord:
        """Record a planned change and ask each integration for its vendor calls."""
        if not plan.changes and restore_backup_id is None:
            raise DeployError("the plan contains no changes")
        if not reason.strip():
            raise DeployError("say why (the reason is kept in the change log)")
        secrets = self.secrets(plan)
        results = []
        for dev in plan.devices():
            kinds = {c.kind for c in plan.for_device(dev)}
            self._writable(dev, kinds)
            adapter = self.adapter(dev)
            assert isinstance(adapter, WritesConfig)
            try:
                calls = await adapter.plan_changes(plan.for_device(dev), secrets)
            except (AdapterError, OSError, TimeoutError) as exc:
                raise DeployError(f"{dev}: {exc}") from exc
            finally:
                await adapter.close()
            results.append(DeviceResult(device_id=dev, calls=calls))
        stamp = _now()
        rid = "chg-" + hashlib.sha256(f"{stamp.isoformat()}{plan.id}".encode()).hexdigest()[:10]
        rec = ChangeRecord(
            id=rid,
            created_at=stamp,
            author=author,
            reason=reason.strip(),
            plan=plan,
            desired_commit=desired_commit,
            devices=results,
            reverts=reverts,
            restore_backup_id=restore_backup_id,
        )
        self._save(rec)
        self._event(rec, None, "planned", f"{len(plan.changes)} change(s), {reason.strip()}")
        return rec

    def approve(self, change_id: str, author: str, override: str | None = None) -> ChangeRecord:
        rec = self._get(change_id)
        if rec.status is not ChangeStatus.PLANNED:
            raise DeployError(f"the change is {rec.status.value}, not planned")
        if rec.plan.blocking and not (override and override.strip()):
            raise DeployError(
                "the plan creates error findings; give a reason to override, or fix the plan"
            )
        rec.status = ChangeStatus.APPROVED
        rec.override = override.strip() if override else None
        self._save(rec)
        self._event(
            rec, None, "approved", f"by {author}" + (f"; override: {override}" if override else "")
        )
        return rec

    def reject(self, change_id: str, author: str) -> ChangeRecord:
        rec = self._get(change_id)
        if rec.status not in (ChangeStatus.PLANNED, ChangeStatus.APPROVED):
            raise DeployError(f"the change is {rec.status.value}")
        rec.status = ChangeStatus.REJECTED
        self._save(rec)
        self._event(rec, None, "rejected", f"by {author}")
        return rec

    def _get(self, change_id: str) -> ChangeRecord:
        rec = self.store.change(change_id)
        if rec is None:
            raise DeployError("no such change")
        return rec

    # deployment ---------------------------------------------------------------------------

    async def _observe(self, device_id: str) -> Snapshot:
        rec = self.store.device(self.owner(device_id))
        assert rec is not None
        return await self.runner.observe_device(rec)

    async def deploy(self, change_id: str) -> ChangeRecord:
        """Apply an approved change. Never raises for device problems: see the record."""
        if not self.runner.config.deploy.enabled:
            raise DeployError("deploying is turned off (deploy.enabled in the configuration)")
        rec = self._get(change_id)
        if rec.status is not ChangeStatus.APPROVED:
            raise DeployError(f"the change is {rec.status.value}; it must be approved first")
        devices = [r.device_id for r in rec.devices]
        for dev in devices:
            self._writable(dev, {c.kind for c in rec.plan.for_device(dev)})
        secrets = self.secrets(rec.plan)
        rec.status = ChangeStatus.DEPLOYING
        self._save(rec)
        self._event(rec, None, "deploying")
        done: list[str] = []
        failed = False
        for dev in devices:
            result = rec.result(dev)
            if failed:
                result.status = DeviceStatus.SKIPPED
                continue
            lock = self.locks.setdefault(self.owner(dev), asyncio.Lock())
            async with lock:
                ok = await self._deploy_device(rec, dev, secrets)
            self._save(rec)
            if ok:
                done.append(dev)
            else:
                failed = True
        if failed:
            # the failing device itself must be untouched (failed before changing) or restored
            complete = all(
                r.status in (DeviceStatus.FAILED, DeviceStatus.ROLLED_BACK, DeviceStatus.SKIPPED)
                for r in rec.devices
                if r.device_id not in done
            )
            for dev in reversed(done):
                complete &= await self._roll_back(rec, dev, secrets)
                self._save(rec)
            rec.status = ChangeStatus.ROLLED_BACK if complete else ChangeStatus.FAILED
        else:
            rec.status = ChangeStatus.APPLIED
            if rec.reverts:
                original = self.store.change(rec.reverts)
                if original is not None:
                    original.reverted_by = rec.id
                    self._save(original)
        self._record_passphrases(rec, secrets)
        self._save(rec)
        self._event(rec, None, rec.status.value)
        self.runner.evaluate()
        return rec

    async def _deploy_device(self, rec: ChangeRecord, dev: str, secrets: dict[str, str]) -> bool:
        result = rec.result(dev)
        result.started_at = _now()
        changes = rec.plan.for_device(dev)
        adapter = self.adapter(dev)
        assert isinstance(adapter, WritesConfig)
        try:
            snap = await self._observe(dev)
            if snap.status not in (ReadStatus.OK, ReadStatus.PARTIAL):
                return self._fail(rec, result, f"device could not be read: {snap.status.value}")
            net = self.runner.network()
            if rec.restore_backup_id is None:
                # A change already at its new value is not stale: an object shared by several
                # devices (an SSID of a controller's WLAN group) was changed through an
                # earlier device of this deployment. Applying it again changes nothing.
                stale = [
                    c
                    for c in changes
                    if not matches(net, c, c.old, secrets) and not matches(net, c, c.new, secrets)
                ]
                if stale:
                    return self._fail(
                        rec,
                        result,
                        "the device changed since the plan was made: "
                        + "; ".join(c.describe() for c in stale),
                    )
            try:
                backup = await adapter.backup()
            except Exception as exc:
                return self._fail(rec, result, f"backup failed: {exc}")
            result.backup_id = self.store.put_backup(backup, rec.id)
            result.status = DeviceStatus.BACKED_UP
            self._event(rec, dev, "backed-up", result.backup_id)
            if rec.restore_backup_id is None:
                self._keep_passphrases(rec, dev, changes, net, secrets)
            before = {
                f.id for f in evaluate(net, self.runner.active_rules(), self.runner.config.rules)
            }
            try:
                if rec.restore_backup_id is not None:
                    restore = self.store.backup(rec.restore_backup_id)
                    assert restore is not None
                    await adapter.restore(restore)
                    deadline = None
                else:
                    applied = await adapter.apply(
                        changes, secrets, self.runner.config.deploy.confirm_seconds
                    )
                    result.calls = applied.calls or result.calls
                    deadline = applied.confirm_deadline
            except Exception as exc:
                result.error = f"apply failed: {exc}"
                self._event(rec, dev, "apply-failed", str(exc))
                await self._restore(rec, dev, adapter)
                return False
            result.status = DeviceStatus.APPLIED
            self._event(
                rec, dev, "applied", f"confirm by {deadline.isoformat()}" if deadline else ""
            )
            problem = await self._verify(rec, dev, changes, secrets, before)
            if problem:
                result.error = f"verification failed: {problem}"
                self._event(rec, dev, "verify-failed", problem)
                await self._restore(rec, dev, adapter)
                return False
            if deadline is not None:
                try:
                    await adapter.confirm()
                except Exception as exc:
                    result.error = f"confirm failed: {exc}"
                    self._event(rec, dev, "confirm-failed", str(exc))
                    await self._restore(rec, dev, adapter)
                    return False
            result.status = DeviceStatus.CONFIRMED
            self._event(rec, dev, "confirmed")
            return True
        finally:
            result.finished_at = _now()
            await adapter.close()

    def _fail(self, rec: ChangeRecord, result: DeviceResult, message: str) -> bool:
        result.status = DeviceStatus.FAILED
        result.error = message
        self._event(rec, result.device_id, "failed", message)
        return False

    async def _verify(
        self,
        rec: ChangeRecord,
        dev: str,
        changes: list[Change],
        secrets: dict[str, str],
        before: set[str],
    ) -> str | None:
        snap = await self._observe(dev)
        if snap.status not in (ReadStatus.OK, ReadStatus.PARTIAL):
            return f"the device does not answer after the change ({snap.status.value})"
        net = self.runner.network()
        if rec.restore_backup_id is None:
            wrong = [c for c in changes if not matches(net, c, c.new, secrets)]
            if wrong:
                return "not applied as planned: " + "; ".join(c.describe() for c in wrong)
        new_errors = [
            f
            for f in evaluate(net, self.runner.active_rules(), self.runner.config.rules)
            if f.id not in before
            and f.severity is Severity.ERROR
            and not f.incomplete
            and f.rule_id not in {x.rule_id for x in rec.plan.new_findings}
        ]
        if new_errors and not rec.override:
            return "new errors: " + "; ".join(f.message for f in new_errors)
        return None

    async def _restore(self, rec: ChangeRecord, dev: str, adapter: WritesConfig) -> bool:
        """Put the backup of this deployment back on one device."""
        result = rec.result(dev)
        backup = self.store.backup(result.backup_id) if result.backup_id else None
        if backup is None:
            result.status = DeviceStatus.ROLLBACK_FAILED
            self._event(rec, dev, "rollback-failed", "no backup")
            return False
        try:
            await adapter.restore(backup)
            snap = await self._observe(dev)
            if snap.status not in (ReadStatus.OK, ReadStatus.PARTIAL):
                raise RuntimeError(
                    f"device does not answer after the restore ({snap.status.value})"
                )
        except Exception as exc:
            result.status = DeviceStatus.ROLLBACK_FAILED
            self._event(rec, dev, "rollback-failed", str(exc))
            return False
        result.status = DeviceStatus.ROLLED_BACK
        self._event(rec, dev, "rolled-back", "backup restored")
        return True

    async def _roll_back(self, rec: ChangeRecord, dev: str, secrets: dict[str, str]) -> bool:
        """Undo a device that was changed and confirmed in a deployment that failed later.

        Inverse changes first (small, fast); the backup when that does not work.
        """
        adapter = self.adapter(dev)
        assert isinstance(adapter, WritesConfig)
        result = rec.result(dev)
        try:
            if rec.restore_backup_id is None:
                undo = self._with_versions(rec, rec.plan.for_device(dev))
                inverse = [c.inverse() for c in reversed(undo)]
                try:
                    applied = await adapter.apply(
                        inverse, secrets, self.runner.config.deploy.confirm_seconds
                    )
                    await self._observe(dev)
                    net = self.runner.network()
                    if all(matches(net, c, c.new, secrets) for c in inverse):
                        if applied.confirm_deadline is not None:
                            await adapter.confirm()
                        result.status = DeviceStatus.ROLLED_BACK
                        self._event(rec, dev, "rolled-back", "inverse changes")
                        return True
                    self._event(rec, dev, "inverse-incomplete", "restoring the backup")
                except Exception as exc:
                    self._event(rec, dev, "inverse-failed", str(exc))
            return await self._restore(rec, dev, adapter)
        finally:
            await adapter.close()

    # passphrase versions (#188) -----------------------------------------------------------

    def _keep_passphrases(
        self,
        rec: ChangeRecord,
        dev: str,
        changes: list[Change],
        net: Network,
        secrets: dict[str, str],
    ) -> None:
        """Keep the passphrase each WLAN change replaces as a secret version for its inverse.

        The device reports at most a fingerprint, so the old value has to come from what
        Signalbox knows: the passphrase it last deployed to the SSID, the value the named secret
        had before it was replaced, or any stored secret. The fingerprint the device reports
        decides which; without one only the passphrase Signalbox deployed itself is trusted.
        """
        for c in changes:
            if c.kind is not ChangeKind.WLAN or not isinstance(c.old, WlanValue):
                continue
            new = c.new
            assert new is None or isinstance(new, WlanValue)
            name = new.passphrase_secret if new is not None else None
            if new is not None and not name:
                continue  # the passphrase is not touched
            w = next((x for x in net.wlans if x.device_id == c.device_id and x.ssid == c.key), None)
            if w is None:  # pragma: no cover - an update or removal has an observed WLAN
                continue
            found = self._previous_passphrase(c.device_id, c.key, w.passphrase_fingerprint, name)
            if found is None:
                if w.passphrase_fingerprint is not None:
                    self._event(
                        rec,
                        dev,
                        "passphrase-unknown",
                        f"SSID {c.key}: the passphrase it replaces is not known to Signalbox; "
                        "a revert keeps the new one (the backup has the old one)",
                    )
                continue
            value, source = found
            if name and value == secrets.get(name):
                continue  # the same passphrase: nothing is replaced
            base = (name or source or "passphrase").split("@", 1)[0]
            version = f"{base}@{rec.id}"
            n = 1
            while version in secrets and secrets[version] != value:
                n += 1
                version = f"{base}@{rec.id}.{n}"
            self.store.put_secret_version(version, value)
            secrets[version] = value
            rec.passphrase_versions[c.id] = version
            self._event(
                rec, dev, "passphrase-kept", f"SSID {c.key}: the replaced passphrase is {version}"
            )

    def _previous_passphrase(
        self, device_id: str, ssid: str, fp: str | None, name: str | None
    ) -> tuple[str, str | None] | None:
        """The passphrase an SSID has now and the secret it was found in, if Signalbox knows it."""
        deployed, _ = self.store.wlan_passphrase(device_id, ssid)
        if fp is None:
            return (deployed, None) if deployed is not None else None
        candidates: list[tuple[str | None, str | None]] = [(deployed, None)]
        names = ([name.split("@", 1)[0]] if name else []) + self.store.secret_names()
        for n in dict.fromkeys(names):
            candidates += [(self.store.previous_secret(n), n), (self.store.get_secret(n), n)]
        for value, source in candidates:
            if value is not None and passphrase_fingerprint(ssid, value) == fp:
                return value, source
        return None

    def _with_versions(self, rec: ChangeRecord, changes: list[Change]) -> list[Change]:
        """The changes with the kept passphrase versions as their old passphrase."""
        out = []
        for c in changes:
            version = rec.passphrase_versions.get(c.id)
            if (
                version
                and isinstance(c.old, WlanValue)
                and self.store.get_secret(version) is not None
            ):
                c = c.model_copy(
                    update={"old": c.old.model_copy(update={"passphrase_secret": version})}
                )
            out.append(c)
        return out

    def _record_passphrases(self, rec: ChangeRecord, secrets: Mapping[str, str]) -> None:
        """After a deployment: remember what is on each SSID now and prune versions.

        Only the latest applied change of an SSID can be reverted (a revert of an older one is
        refused because the device changed since), so a version lives as long as the latest
        applied change of its SSID needs it (to revert, or because it set that version), and not
        at all when its deployment did not apply.
        """
        if rec.status is not ChangeStatus.APPLIED:
            for kept in rec.passphrase_versions.values():
                self.store.delete_secret_version(kept)
            rec.passphrase_versions = {}
            return
        if rec.restore_backup_id is not None:
            for r in rec.devices:  # whatever the backup had is on the device now
                self.store.forget_wlan_passphrases(r.device_id)
            return
        for c in rec.plan.changes:
            if c.kind is not ChangeKind.WLAN:
                continue
            new = c.new
            assert new is None or isinstance(new, WlanValue)
            owned = {rec.passphrase_versions.get(c.id)}
            if new is not None and new.passphrase_secret and "@" in new.passphrase_secret:
                owned.add(new.passphrase_secret)  # a revert set a version: still in use
            owned.discard(None)
            value, before = self.store.wlan_passphrase(c.device_id, c.key)
            for version in set(before) - owned:
                self.store.delete_secret_version(version)
            if new is None:
                value = None
            elif new.passphrase_secret:
                value = secrets.get(new.passphrase_secret)
            self.store.set_wlan_passphrase(c.device_id, c.key, value, {v for v in owned if v})

    # revert and restore -------------------------------------------------------------------

    async def revert(self, change_id: str, reason: str, author: str) -> ChangeRecord:
        """A new planned change that undoes an applied one (checked like any plan)."""
        rec = self._get(change_id)
        if rec.status is not ChangeStatus.APPLIED:
            raise DeployError("only an applied change can be reverted")
        if rec.reverted_by:
            raise DeployError(f"already reverted by {rec.reverted_by}")
        if rec.restore_backup_id is not None:
            raise DeployError("a backup restore cannot be reverted; restore another backup")
        net = self.runner.network()
        secrets = self.secrets(rec.plan)
        moved = [c for c in rec.plan.changes if not matches(net, c, c.new, secrets)]
        if moved:
            raise DeployError(
                "the devices changed since; a revert would overwrite that: "
                + "; ".join(c.describe() for c in moved)
            )
        try:
            back = revert_plan(
                self._with_versions(rec, rec.plan.changes),
                net,
                self.runner.active_rules(),
                self.runner.config.rules,
            )
        except PlanError as exc:  # pragma: no cover - inverses of applied changes always plan
            raise DeployError(str(exc)) from exc
        return await self.prepare(back, reason, author, reverts=rec.id)

    async def restore_backup(self, backup_id: str, reason: str, author: str) -> ChangeRecord:
        """A planned change that puts a stored backup back on its device."""
        info = next((b for b in self.store.backups() if b.id == backup_id), None)
        if info is None:
            raise DeployError("no such backup")
        self._writable(info.device_id, set())
        plan = Plan(id=f"restore-{backup_id}", created_at=_now(), changes=[])
        rec = await self.prepare(plan, reason, author, restore_backup_id=backup_id)
        rec.devices = [DeviceResult(device_id=info.device_id)]
        self._save(rec)
        return rec
