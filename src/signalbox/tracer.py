"""Running path traces (#253, docs/adr/0014): one run at a time, started by the user (*Trace
now*) or by the optional schedule (``traces.interval_hours``), never while ``traces.enabled``
is off.

A run plans pairs (source, target): by default every gateway whose integration can trace, and
Signalbox's own host, to every other gateway and to the internet target; or only from or to
one chosen device or address. Pairs run ``traces.concurrency`` at a time, each with one probe
per hop, ``traces.wait_seconds`` per hop and ``traces.timeout_seconds`` for the whole trace.
*Trace now* is refused within ``traces.min_gap_seconds`` of the last start. Each result is
stored as the latest trace of its pair (``Store.put_trace``); the findings are evaluated again
after the run.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any, Literal

from signalbox import tracehost
from signalbox.adapters import Adapter, AdapterContext, AdapterError, TraceAnswer, traces
from signalbox.config import Config
from signalbox.model import SIGNALBOX_SOURCE, IPAddress, Network, PathTrace, trace_id
from signalbox.runner import Runner
from signalbox.secrets import SecretError
from signalbox.store import Store, StoreError
from signalbox.traces import gateway_target, gateways, match, source_name

log = logging.getLogger(__name__)
Purpose = Literal["gateway", "internet", "address"]


class TraceError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


@dataclass(frozen=True)
class Pair:
    source: str
    target: IPAddress
    purpose: Purpose
    target_device: str | None = None

    @property
    def id(self) -> str:
        return trace_id(self.source, self.target)


@dataclass
class Tracer:
    store: Store
    runner: Runner
    adapters: Mapping[str, type[Adapter]]
    config: Config
    #: Host tracer (replaced by tests).
    host_trace: Any = field(default=tracehost.trace)
    running: bool = False
    started_at: datetime | None = None
    finished_at: datetime | None = None
    limited: bool = False
    scheduled: bool = False
    pairs: list[Pair] = field(default_factory=list)
    states: dict[str, str] = field(default_factory=dict)
    _task: asyncio.Task[None] | None = None
    _stop: asyncio.Event = field(default_factory=asyncio.Event)

    @property
    def settings(self) -> Any:
        return self.config.traces

    # what can trace ------------------------------------------------------------------------

    def sources(self, net: Network) -> list[dict[str, Any]]:
        """Every stored, enabled device with whether its integration can trace, and the
        permission it needs; Signalbox's host first when ``from_signalbox`` is on."""
        out: list[dict[str, Any]] = []
        if self.settings.from_signalbox:
            out.append(
                {
                    "id": SIGNALBOX_SOURCE,
                    "name": "Signalbox",
                    "role": None,
                    "supported": True,
                    "permission": "none (unprivileged UDP from Signalbox's host)",
                    "method": "UDP probes with IP_RECVERR",
                }
            )
        for rec in sorted(self.store.devices(), key=lambda r: r.name.lower()):
            if not rec.enabled:
                continue
            cls = self.adapters.get(rec.adapter)
            support = cls.manifest.traces if cls is not None and traces(cls) else None
            out.append(
                {
                    "id": rec.id,
                    "name": rec.name,
                    "role": rec.role.value,
                    "supported": support is not None,
                    "permission": support.permission if support else None,
                    "method": support.method if support else None,
                }
            )
        return out

    def _can_trace(self, device_id: str) -> bool:
        rec = self.store.device(device_id)
        cls = self.adapters.get(rec.adapter) if rec is not None else None
        return rec is not None and rec.enabled and cls is not None and traces(cls)

    def plan(
        self, net: Network, source: str | None = None, target: str | None = None
    ) -> list[Pair]:
        """The pairs of one run; ``source``: a device id or ``signalbox``, ``target``: a
        device id or an IP address (no host names: devices do not look anything up)."""
        if source is not None:
            if source == SIGNALBOX_SOURCE:
                if not self.settings.from_signalbox:
                    raise TraceError(422, "invalid", "Tracing from Signalbox is turned off.")
            elif not self._can_trace(source):
                raise TraceError(422, "not_supported", f"{source_name(net, source)} cannot trace.")
            sources = [source]
        else:
            gw = {d.id for d in gateways(net)}
            sources = [SIGNALBOX_SOURCE] if self.settings.from_signalbox else []
            sources += sorted(
                r.id for r in self.store.devices() if r.id in gw and self._can_trace(r.id)
            )
        pairs: list[Pair] = []
        for src in sources:
            if target is not None:
                pair = self._chosen(net, src, target)
                if pair is not None:
                    pairs.append(pair)
                continue
            for dev in gateways(net):
                if dev.id == src:
                    continue
                address = gateway_target(net, dev, src)
                if address is not None:
                    pairs.append(Pair(src, address, "gateway", dev.id))
            if self.settings.internet_target:
                pairs.append(Pair(src, ip_address(self.settings.internet_target), "internet"))
        if not pairs:
            raise TraceError(422, "nothing", "Nothing to trace: no source can reach a target.")
        unique = list(dict.fromkeys(pairs))
        self.limited = len(unique) > self.settings.max_pairs
        return unique[: self.settings.max_pairs]

    def _chosen(self, net: Network, source: str, target: str) -> Pair | None:
        dev = net.device(target)
        if dev is not None:
            if dev.id == source:
                return None
            address = gateway_target(net, dev, source)
            if address is None:
                raise TraceError(422, "invalid", f"{dev.name} has no address to trace to.")
            return Pair(
                source, address, "gateway" if dev.role.value == "gateway" else "address", dev.id
            )
        try:
            address = ip_address(target.strip())
        except ValueError:
            raise TraceError(
                422, "invalid", "Give a device or an IP address (no host names)."
            ) from None
        internet = str(address) == self.settings.internet_target
        return Pair(source, address, "internet" if internet else "address", match(net, address)[0])

    # a run ----------------------------------------------------------------------------------

    def start(
        self, source: str | None = None, target: str | None = None, scheduled: bool = False
    ) -> dict[str, Any]:
        if not self.settings.enabled:
            raise TraceError(
                403, "disabled", "Path traces are turned off in the configuration (traces.enabled)."
            )
        if self.running:
            raise TraceError(409, "running", "A trace run is already running.")
        now = datetime.now(UTC)
        gap = timedelta(seconds=self.settings.min_gap_seconds)
        if not scheduled and self.started_at is not None and now - self.started_at < gap:
            wait = int((gap - (now - self.started_at)).total_seconds()) + 1
            raise TraceError(
                429, "too_soon", f"The last run started just now; try again in {wait} s."
            )
        net = self.runner.network()
        self.pairs = self.plan(net, source, target)
        self.states = {p.id: "waiting" for p in self.pairs}
        self.running, self.scheduled = True, scheduled
        self.started_at, self.finished_at = now, None
        self._task = asyncio.get_running_loop().create_task(self._run(list(self.pairs)))
        return self.status()

    async def _run(self, pairs: list[Pair]) -> None:
        sem = asyncio.Semaphore(self.settings.concurrency)

        async def one(pair: Pair) -> None:
            async with sem:
                self.states[pair.id] = "running"
                result = await self.trace(pair)
                self.store.put_trace(result)
                self.states[pair.id] = "failed" if result.error else "done"

        try:
            await asyncio.gather(*(one(p) for p in pairs))
            self.store.prune_traces(datetime.now(UTC) - timedelta(days=self.config.history.days))
            await asyncio.to_thread(self.runner.evaluate)
        except Exception:
            log.exception("trace run failed")
        finally:
            self.running = False
            self.finished_at = datetime.now(UTC)

    async def trace(self, pair: Pair) -> PathTrace:
        """Run one trace; never raises for device problems (they become the trace's error)."""
        started = datetime.now(UTC)
        base: dict[str, Any] = {
            "id": pair.id,
            "source": pair.source,
            "target": pair.target,
            "target_device": pair.target_device,
            "purpose": pair.purpose,
            "started_at": started,
        }
        s = self.settings
        try:
            answer = await asyncio.wait_for(self._answer(pair), timeout=s.timeout_seconds)
        except TimeoutError:
            seconds = f"{s.timeout_seconds:g}"
            base |= {
                "error": f"no result within {seconds} s",
                "message_id": "trace.timeout",
                "params": {"seconds": seconds},
            }
        except NotImplementedError:
            base |= {
                "error": "this device cannot run traceroutes",
                "message_id": "trace.unsupported",
            }
        except AdapterError as exc:
            base |= {
                "error": str(exc) or type(exc).__name__,
                "fix": exc.fix,
                "remedy": exc.remedy,
                "message_id": exc.message_id,
                "fix_id": exc.fix_id,
                "params": dict(exc.params),
            }
        except (StoreError, SecretError, ValueError) as exc:
            base |= {
                "error": f"settings unusable: {exc}",
                "message_id": "trace.settings",
                "params": {"detail": str(exc)},
            }
        except Exception as exc:  # a broken adapter must be visible, not fatal
            log.exception("trace %s failed", pair.id)
            detail = f"{type(exc).__name__}: {exc}"
            base |= {
                "error": f"adapter error: {detail}",
                "message_id": "trace.adapter",
                "params": {"detail": detail},
            }
        else:
            hops = [h for h in answer.hops if h.ttl <= s.max_hops]
            base |= {"hops": hops, "reached": answer.reached}
        return PathTrace(**base, finished_at=datetime.now(UTC))

    async def _answer(self, pair: Pair) -> TraceAnswer:
        s = self.settings
        if pair.source == SIGNALBOX_SOURCE:
            answer: TraceAnswer = await self.host_trace(pair.target, s.max_hops, s.wait_seconds)
            return answer
        rec = self.store.device(pair.source)
        if rec is None:
            raise AdapterError("the device was removed", message_id="trace.removed")
        cls = self.adapters[rec.adapter]
        ctx = AdapterContext(
            site_id=rec.site_id,
            device_id=rec.id,
            device_name=rec.name,
            role=rec.role,
            config=self.store.adapter_config(rec.id, cls.manifest.config),
            pinned_fingerprint=rec.pinned_fingerprint,
            timeout=s.timeout_seconds,
        )
        adapter = cls(ctx)
        try:
            return await adapter.trace(pair.target, s.max_hops, s.wait_seconds)
        finally:
            await adapter.close()

    def status(self) -> dict[str, Any]:
        net_names: dict[str, str] = {r.id: r.name for r in self.store.devices()}
        net_names[SIGNALBOX_SOURCE] = "Signalbox"
        s = self.settings
        nxt = None
        if s.enabled and s.interval_hours and self.started_at:
            nxt = (self.started_at + timedelta(hours=s.interval_hours)).isoformat()
        return {
            "enabled": s.enabled,
            "interval_hours": s.interval_hours,
            "internet_target": s.internet_target or None,
            "running": self.running,
            "scheduled": self.scheduled,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "next_run": nxt,
            "limited": self.limited,
            "total": len(self.pairs),
            "done": sum(1 for v in self.states.values() if v in ("done", "failed")),
            "pairs": [
                {
                    "id": p.id,
                    "source": p.source,
                    "source_name": net_names.get(p.source, p.source),
                    "target": str(p.target),
                    "target_device": p.target_device,
                    "purpose": p.purpose,
                    "state": self.states.get(p.id, "waiting"),
                }
                for p in self.pairs
            ],
        }

    # schedule -------------------------------------------------------------------------------

    async def run_forever(self) -> None:
        """The optional schedule: every ``interval_hours`` (first run one interval after the
        start, so a restart does not trace at once)."""
        s = self.settings
        if not (s.enabled and s.interval_hours):
            return
        while not self._stop.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), s.interval_hours * 3600)
            if self._stop.is_set():
                break
            try:
                self.start(scheduled=True)
            except TraceError as exc:
                log.info("scheduled traces not started: %s", exc)

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
