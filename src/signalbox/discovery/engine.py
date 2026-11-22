"""One discovery run at a time: plan the addresses, run every integration's probe on them,
collect the candidates (#203).

Started only by the user (``POST /api/discovery``); the last run's progress and candidates are
kept in memory until the next one. Candidates are suggestions: nothing a device answered is
stored or trusted, the ignore list (``discovery.ignored`` in the settings) holds only
integration and address.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from pydantic import SecretStr

from signalbox.adapters import Adapter, probes_broadcast, probes_hosts
from signalbox.config import DiscoveryConfig
from signalbox.discovery.probe import Candidate, HostProbe, NetworkProbe, RateLimiter
from signalbox.discovery.targets import RangeError, Target, plan, sort_key
from signalbox.model import DeviceRole
from signalbox.runner import Runner
from signalbox.store import Store

log = logging.getLogger(__name__)
IGNORED = "discovery.ignored"
#: How many timeouts one integration's probe of one address may take in total.
PROBE_BUDGET = 10


class DiscoveryError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


@dataclass
class Found:
    candidate: Candidate
    why: str
    found_at: datetime


@dataclass
class Run:
    started_at: datetime
    total: int
    scope: list[str]
    notes: list[str]
    state: str = "running"  # running, done, failed
    done: int = 0
    finished_at: datetime | None = None
    requests: int = 0
    found: dict[str, Found] = field(default_factory=dict)


def key_of(adapter: str, address: str) -> str:
    return f"{adapter}|{normal_host(address)}"


def normal_host(value: str) -> str:
    """The host of an address or URL as typed into a device form, for comparison."""
    text = value.strip()
    host = urlsplit(text).hostname if "://" in text else text.strip("[]")
    host = (host or "").lower()
    with contextlib.suppress(ValueError):
        return str(ipaddress.ip_address(host))
    return host


def _secret(annotation: Any) -> bool:
    return annotation is SecretStr or SecretStr in getattr(annotation, "__args__", ())


class Discovery:
    def __init__(
        self,
        store: Store,
        runner: Runner,
        adapters: Mapping[str, type[Adapter]],
        config: DiscoveryConfig,
        extra: Mapping[str, Any] | None = None,
    ) -> None:
        self.store = store
        self.runner = runner
        self.adapters = adapters
        self.config = config
        #: Settings for tests and simulators, handed to every probe (ports, broadcast targets).
        self.extra: Mapping[str, Any] = extra or {}
        self.run: Run | None = None
        self._task: asyncio.Task[None] | None = None

    # control ------------------------------------------------------------------------------

    def start(
        self, ranges: list[str], *, known_networks: bool = True, broadcast: bool = True
    ) -> dict[str, Any]:
        if not self.config.enabled:
            raise DiscoveryError(
                403,
                "disabled",
                "Finding devices is turned off in the configuration (discovery.enabled).",
            )
        if self.run is not None and self.run.state == "running":
            raise DiscoveryError(409, "busy", "A search is already running.")
        try:
            planned = plan(
                self.runner.network(),
                ranges,
                known_networks=known_networks,
                sweep_prefix=self.config.sweep_prefix,
                max_hosts=self.config.max_hosts,
            )
        except RangeError as exc:
            raise DiscoveryError(422, "invalid", str(exc)) from exc
        hosts = [cls for _, cls in sorted(self.adapters.items()) if probes_hosts(cls)]
        casts = (
            [cls for _, cls in sorted(self.adapters.items()) if probes_broadcast(cls)]
            if broadcast
            else []
        )
        if not (planned.targets and hosts) and not casts:
            raise DiscoveryError(
                422,
                "nothing_to_probe",
                "Nothing to search: add your router first, or enter an address or range.",
            )
        scope = list(planned.scope)
        if casts:
            names = ", ".join(c.manifest.name for c in casts)
            scope.append(f"broadcast in Signalbox's own network: {names}")
        run = Run(
            started_at=datetime.now(UTC),
            total=len(planned.targets) + len(casts),
            scope=scope,
            notes=list(planned.notes),
        )
        self.run = run
        self._task = asyncio.get_running_loop().create_task(
            self._execute(run, planned.targets if hosts else [], hosts, casts)
        )
        return self.status()

    async def stop(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    def ignore(self, key: str, ignored: bool = True) -> dict[str, Any]:
        keys = self._ignored()
        if ignored:
            keys.add(key)
        else:
            keys.discard(key)
        self.store.set_setting(IGNORED, json.dumps(sorted(keys)))
        return self.status()

    def _ignored(self) -> set[str]:
        raw = self.store.get_setting(IGNORED)
        try:
            value = json.loads(raw) if raw else []
        except ValueError:
            value = []
        return {str(k) for k in value} if isinstance(value, list) else set()

    # the run ------------------------------------------------------------------------------

    async def _execute(
        self,
        run: Run,
        targets: list[Target],
        hosts: list[type[Adapter]],
        casts: list[type[Adapter]],
    ) -> None:
        cfg = self.config
        limiter = RateLimiter(cfg.rate_per_second)
        gate = asyncio.Semaphore(cfg.concurrency)
        failed: set[str] = set()

        async def one(target: Target) -> None:
            async with gate:
                probe = HostProbe(
                    target.address, timeout=cfg.timeout_seconds, limiter=limiter, extra=self.extra
                )
                try:
                    for cls in hosts:
                        if probe.silent:
                            break
                        try:
                            found = await asyncio.wait_for(
                                cls.discover(probe), cfg.timeout_seconds * PROBE_BUDGET
                            )
                        except TimeoutError:
                            continue
                        except Exception as exc:  # a broken probe must not stop the run
                            self._failed(run, failed, cls, exc)
                            continue
                        if found is not None:
                            self._accept(run, cls, found, target)
                finally:
                    run.requests += probe.requests
                    await probe.close()
                    run.done += 1

        async def cast(cls: type[Adapter]) -> None:
            probe = NetworkProbe(cfg.timeout_seconds, limiter, self.extra)
            try:
                result = await cls.discover_broadcast(probe)
            except Exception as exc:
                self._failed(run, failed, cls, exc)
                result = None
            finally:
                run.done += 1
            if result is None:
                return
            for candidate in result.candidates:
                self._accept(run, cls, candidate, None)
            if result.note:
                run.notes.append(result.note)

        try:
            await asyncio.gather(*(one(t) for t in targets), *(cast(c) for c in casts))
        except Exception as exc:  # pragma: no cover - only a bug in the engine itself
            log.exception("discovery failed")
            run.notes.append(f"The search stopped: {exc}")
            run.state = "failed"
        else:
            run.state = "done"
        finally:
            run.finished_at = datetime.now(UTC)
            if run.state == "running":
                run.state = "failed"  # cancelled (shutdown)

    @staticmethod
    def _failed(run: Run, failed: set[str], cls: type[Adapter], exc: BaseException) -> None:
        aid = cls.manifest.id
        log.warning("discovery probe of %s failed: %r", aid, exc)
        if aid not in failed:
            failed.add(aid)
            run.notes.append(
                f"The {cls.manifest.name} probe failed ({type(exc).__name__}); "
                "its devices may be missing."
            )

    def _accept(
        self, run: Run, cls: type[Adapter], candidate: Candidate, target: Target | None
    ) -> None:
        m = cls.manifest
        fields = m.config.model_fields
        config = {
            k: v
            for k, v in candidate.config.items()
            if k in fields and not _secret(fields[k].annotation)
        }
        role = candidate.role
        if target is not None and target.gateway and DeviceRole.GATEWAY in m.roles:
            role = DeviceRole.GATEWAY  # the router of a known subnet
        if role not in m.roles:
            role = sorted(m.roles)[0]
        name = (candidate.name or candidate.model or m.name)[:100]
        final = candidate.model_copy(
            update={"adapter": m.id, "config": config, "role": role, "name": name}
        )
        key = key_of(m.id, final.address)
        if key not in run.found:
            why = target.why if target else "answered the broadcast"
            run.found[key] = Found(final, why, datetime.now(UTC))

    # status -------------------------------------------------------------------------------

    def _added(self) -> dict[tuple[str, str], str]:
        """(integration, host) of every added device → its id."""
        out: dict[tuple[str, str], str] = {}
        addresses = {s.device.id: s.device.management_address for s in self.store.snapshots()}
        for rec in self.store.devices():
            values = [v for v in rec.config.values() if isinstance(v, str) and v]
            if addresses.get(rec.id):
                values.append(str(addresses[rec.id]))
            for value in values:
                host = normal_host(value)
                if host:
                    out.setdefault((rec.adapter, host), rec.id)
        return out

    def status(self) -> dict[str, Any]:
        run = self.run
        base: dict[str, Any] = {
            "enabled": self.config.enabled,
            "state": run.state if run else "idle",
            "started_at": run.started_at.isoformat() if run else None,
            "finished_at": run.finished_at.isoformat() if run and run.finished_at else None,
            "total": run.total if run else 0,
            "done": run.done if run else 0,
            "requests": run.requests if run else 0,
            "scope": list(run.scope) if run else [],
            "notes": list(run.notes) if run else [],
            "candidates": [],
        }
        if run is None:
            return base
        added = self._added()
        ignored = self._ignored()
        names = {k: cls.manifest.name for k, cls in self.adapters.items()}
        rows = []
        for key, found in run.found.items():
            c = found.candidate
            rows.append(
                {
                    **c.model_dump(mode="json"),
                    "key": key,
                    "adapter_name": names.get(c.adapter, c.adapter),
                    "why": found.why,
                    "found_at": found.found_at.isoformat(),
                    "added": added.get((c.adapter, normal_host(c.address))),
                    "ignored": key in ignored,
                }
            )
        rows.sort(
            key=lambda r: (
                r["added"] is not None,
                r["ignored"],
                sort_key(r["address"]),
                r["adapter"],
            )
        )
        base["candidates"] = rows
        return base
