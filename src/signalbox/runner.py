"""Reads every device on an interval, merges the network and records findings."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from signalbox.adapters import Adapter, AdapterContext
from signalbox.config import Config
from signalbox.merge import merge
from signalbox.model import (
    Device,
    DeviceStatus,
    Link,
    Network,
    ReadError,
    Snapshot,
    Source,
)
from signalbox.rules import Finding, Rule, evaluate
from signalbox.secrets import SecretError
from signalbox.store import DeviceRecord, Store, StoreError

log = logging.getLogger(__name__)

#: Hook for derived links (topology discovery); receives the network without derived links.
LinkSource = Callable[[Network], Iterable[Link]]


@dataclass
class Runner:
    store: Store
    adapters: Mapping[str, type[Adapter]]
    rules: list[Rule]
    config: Config
    link_sources: list[LinkSource] = field(default_factory=list)
    #: Called after every evaluation (MQTT export, UI push).
    listeners: list[Callable[[Network, list[Finding]], None]] = field(default_factory=list)
    _wake: asyncio.Event = field(default_factory=asyncio.Event)
    _stop: asyncio.Event = field(default_factory=asyncio.Event)
    last_run: datetime | None = None

    # one device -------------------------------------------------------------------------

    def _failed(self, rec: DeviceRecord, status: DeviceStatus, message: str) -> Snapshot:
        now = datetime.now(UTC)
        device = Device(
            id=rec.id,
            site_id=rec.site_id,
            name=rec.name,
            role=rec.role,
            adapter=rec.adapter,
            source=Source(adapter=rec.adapter, device_id=rec.id),
            observed_at=now,
        )
        error = ReadError(device_id=rec.id, capability="system", message=message)
        return Snapshot(device=device, observed_at=now, status=status, errors=[error])

    async def observe_device(self, rec: DeviceRecord) -> Snapshot:
        """Read one device and store the snapshot. Never raises for device or setup problems."""
        cls = self.adapters.get(rec.adapter)
        if cls is None:
            snap = self._failed(
                rec, DeviceStatus.UNREACHABLE, f"adapter {rec.adapter!r} is not installed"
            )
        else:
            try:
                cfg = self.store.adapter_config(rec.id, cls.manifest.config)
            except (StoreError, SecretError, ValueError) as exc:
                snap = self._failed(rec, DeviceStatus.AUTH_FAILED, f"settings unusable: {exc}")
            else:
                ctx = AdapterContext(
                    site_id=rec.site_id,
                    device_id=rec.id,
                    device_name=rec.name,
                    role=rec.role,
                    config=cfg,
                    pinned_fingerprint=rec.pinned_fingerprint,
                    timeout=self.config.observe.timeout_seconds,
                )
                adapter = cls(ctx)
                try:
                    snap = await adapter.observe()
                except Exception as exc:  # a broken adapter must be visible, not fatal
                    log.exception("adapter %s failed on %s", rec.adapter, rec.id)
                    snap = self._failed(
                        rec, DeviceStatus.UNREACHABLE, f"adapter error: {type(exc).__name__}: {exc}"
                    )
                finally:
                    await adapter.close()
                if adapter.presented_fingerprint != rec.pending_fingerprint:
                    self.store.set_pending_fingerprint(rec.id, adapter.presented_fingerprint)
        self.store.save_snapshot(snap)
        log.info("%s: %s", rec.id, snap.status.value)
        return snap

    # everything -------------------------------------------------------------------------

    def network(self) -> Network:
        enabled = {d.id for d in self.store.devices() if d.enabled}
        snaps = [s for s in self.store.snapshots() if s.device.id in enabled]
        manual = self.store.links()
        net = merge(self.store.sites(), snaps, manual)
        derived: dict[str, Link] = {}
        manual_pairs = {frozenset((link.a, link.b)) for link in manual}
        for source in self.link_sources:
            for link in source(net):
                if frozenset((link.a, link.b)) not in manual_pairs:
                    derived.setdefault(link.id, link)
        if not derived:
            return net
        return merge(self.store.sites(), snaps, [*manual, *derived.values()])

    def evaluate(self) -> tuple[Network, list[Finding]]:
        net = self.network()
        findings = evaluate(net, self.rules, self.config.rules)
        now = datetime.now(UTC)
        self.store.record_findings(findings, now)
        self.store.prune_resolved(now - timedelta(days=30))
        for listener in self.listeners:
            try:
                listener(net, findings)
            except Exception:
                log.exception("listener failed")
        return net, findings

    async def observe_all(self) -> tuple[Network, list[Finding]]:
        sem = asyncio.Semaphore(self.config.observe.concurrency)

        async def one(rec: DeviceRecord) -> None:
            async with sem:
                await self.observe_device(rec)

        await asyncio.gather(*(one(r) for r in self.store.devices() if r.enabled))
        self.last_run = datetime.now(UTC)
        return self.evaluate()

    # loop -------------------------------------------------------------------------------

    def trigger(self) -> None:
        """Read all devices now instead of waiting for the interval."""
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    async def run_forever(self) -> None:
        while not self._stop.is_set():
            # cleared before the round: a trigger that arrives during it starts the next one
            self._wake.clear()
            try:
                await self.observe_all()
            except Exception:
                log.exception("observation round failed")
            if self._stop.is_set():
                break
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), self.config.observe.interval_seconds)
