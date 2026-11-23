"""Running the probe for foreign DHCP servers and routers (#184, docs/adr/0015): one run at a
time, started by the user (*Probe now*) or by the optional schedule (``probes.interval_hours``),
never while ``probes.enabled`` is off.

A run picks the interfaces of Signalbox's host that are up, not the loopback, on a network
Signalbox knows (an address in a subnet of a read device) and, when ``probes.interfaces`` lists
names, among those. Each gets one DHCPDISCOVER and one router solicitation
(:mod:`signalbox.probehost`), ``probes.wait_seconds`` of listening each. *Probe now* is refused
within ``probes.min_gap_seconds`` of the last start. Every answer is stored as a
:class:`~signalbox.model.ForeignServer` (``first_seen`` kept); an answer of an earlier run that
the same interface did not hear again is forgotten. The findings are evaluated after the run.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from signalbox import probehost
from signalbox.config import Config
from signalbox.model import ForeignServer, IPInterface, Network, SightingSource, foreign_server_id
from signalbox.probehost import Answer, HostInterface, Leg, Sockets
from signalbox.runner import Runner
from signalbox.store import Store

log = logging.getLogger(__name__)

#: Prefix of the probe's ``seen_by`` entries: ``signalbox/<interface>``.
LEG = "signalbox/"


class ProbeRunError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def segment_of(net: Network, iface: HostInterface) -> tuple[str | None, str | None]:
    """The known network (segment) and site of a host interface: a read device's subnet that
    holds one of its addresses (IPv4 first)."""
    addrs: list[IPInterface] = [*iface.ipv4, *[a for a in iface.ipv6 if not a.is_link_local]]
    for addr in addrs:
        for sub in sorted(net.subnets, key=lambda s: (not s.gateway, s.id)):
            if sub.interface.version == addr.version and addr.ip in sub.interface.network:
                seg = net.segment(sub.segment_id)
                dev = net.device(sub.device_id)
                site = seg.site_id if seg else (dev.site_id if dev else None)
                return sub.segment_id, site
    return None, None


@dataclass
class Prober:
    store: Store
    runner: Runner
    config: Config
    #: The socket layer (replaced by tests).
    sockets: Sockets = field(default_factory=probehost.HostSockets)
    running: bool = False
    scheduled: bool = False
    started_at: datetime | None = None
    finished_at: datetime | None = None
    #: Per interface: name, segment, site, state (waiting/running/done/failed/skipped), why.
    legs: list[dict[str, Any]] = field(default_factory=list)
    _task: asyncio.Task[None] | None = None
    _stop: asyncio.Event = field(default_factory=asyncio.Event)

    @property
    def settings(self) -> Any:
        return self.config.probes

    def plan(self, net: Network) -> list[tuple[HostInterface, str, str]]:
        """The interfaces to probe with their segment and site; the others become skipped
        legs with the reason."""
        try:
            interfaces = self.sockets.interfaces()
        except OSError as exc:
            raise ProbeRunError(
                500, "no_interfaces", f"The host's interfaces cannot be listed: {exc}"
            ) from None
        wanted = set(self.settings.interfaces)
        out: list[tuple[HostInterface, str, str]] = []
        self.legs = []
        for iface in sorted(interfaces, key=lambda i: i.name):
            if iface.loopback or (wanted and iface.name not in wanted):
                continue
            seg, site = segment_of(net, iface)
            why = None
            if not iface.up:
                why = "interface is down"
            elif seg is None or site is None:
                why = "not on a network Signalbox knows"
            leg = {"interface": iface.name, "segment_id": seg, "site_id": site}
            if why:
                self.legs.append(leg | {"state": "skipped", "errors": [why], "answers": 0})
                continue
            assert seg is not None and site is not None
            self.legs.append(leg | {"state": "waiting", "errors": [], "answers": 0})
            out.append((iface, seg, site))
        if not out:
            raise ProbeRunError(
                422,
                "nothing",
                "No interface of Signalbox's host is on a network Signalbox knows: the probe "
                "needs host networking (or a VLAN interface per network, docs/PROBES.md).",
            )
        return out

    def start(self, scheduled: bool = False) -> dict[str, Any]:
        s = self.settings
        if not s.enabled:
            raise ProbeRunError(
                403, "disabled", "Probes are turned off in the configuration (probes.enabled)."
            )
        if not (s.dhcp or s.router_solicitation):
            raise ProbeRunError(
                422, "nothing", "Both probes.dhcp and probes.router_solicitation are off."
            )
        if self.running:
            raise ProbeRunError(409, "running", "A probe is already running.")
        now = datetime.now(UTC)
        gap = timedelta(seconds=s.min_gap_seconds)
        if not scheduled and self.started_at is not None and now - self.started_at < gap:
            wait = int((gap - (now - self.started_at)).total_seconds()) + 1
            raise ProbeRunError(
                429, "too_soon", f"The last probe started just now; try again in {wait} s."
            )
        plan = self.plan(self.runner.network())
        self.running, self.scheduled = True, scheduled
        self.started_at, self.finished_at = now, None
        self._task = asyncio.get_running_loop().create_task(self._run(plan))
        return self.status()

    async def _run(self, plan: list[tuple[HostInterface, str, str]]) -> None:
        s = self.settings
        for leg in self.legs:
            if leg["state"] == "waiting":
                leg["state"] = "running"
        try:
            found = await probehost.probe(
                self.sockets,
                [iface for iface, _, _ in plan],
                s.wait_seconds,
                dhcp=s.dhcp,
                ra=s.router_solicitation,
            )
            self._keep(plan, found)
            self.store.prune_foreign(datetime.now(UTC) - timedelta(days=self.config.history.days))
            await asyncio.to_thread(self.runner.evaluate)
        except Exception:
            log.exception("probe run failed")
            for leg in self.legs:
                if leg["state"] == "running":
                    leg["state"] = "failed"
        finally:
            self.running = False
            self.finished_at = datetime.now(UTC)

    def _keep(self, plan: list[tuple[HostInterface, str, str]], found: dict[str, Leg]) -> None:
        now = datetime.now(UTC)
        stored = self.store.foreign_servers()
        for iface, seg, site in plan:
            result = found.get(iface.name, Leg(iface.name))
            heard = {self._server(a, seg, site, now).id for a in result.answers}
            for answer in result.answers:
                self.store.put_foreign(self._server(answer, seg, site, now))
            # forget what this interface heard before but not now, for each kind it probed
            probed = result.probed
            gone = [
                x.id
                for x in stored
                if x.seen_by == [LEG + iface.name]
                and x.kind in probed
                and x.segment_id == seg
                and x.id not in heard
            ]
            if gone:
                self.store.delete_foreign(gone)
            for leg in self.legs:
                if leg["interface"] == iface.name:
                    leg["answers"] = len(result.answers)
                    leg["errors"] = list(result.errors)
                    leg["state"] = "failed" if result.errors and not result.answers else "done"

    @staticmethod
    def _server(answer: Answer, seg: str, site: str, now: datetime) -> ForeignServer:
        key = answer.server_mac or str(answer.server_address)
        return ForeignServer(
            id=foreign_server_id(site, answer.kind, seg, key),
            site_id=site,
            segment_id=seg,
            kind=answer.kind,
            server_address=answer.server_address,
            server_mac=answer.server_mac,
            offered=answer.offered,
            first_seen=now,
            last_seen=now,
            source=SightingSource.PROBE,
            seen_by=[LEG + answer.interface],
        )

    def status(self) -> dict[str, Any]:
        s = self.settings
        nxt = None
        if s.enabled and s.interval_hours and self.started_at:
            nxt = (self.started_at + timedelta(hours=s.interval_hours)).isoformat()
        return {
            "enabled": s.enabled,
            "dhcp": s.dhcp,
            "router_solicitation": s.router_solicitation,
            "interval_hours": s.interval_hours,
            "running": self.running,
            "scheduled": self.scheduled,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "next_run": nxt,
            "legs": self.legs,
        }

    # schedule -------------------------------------------------------------------------------

    async def run_forever(self) -> None:
        """The optional schedule: every ``interval_hours`` (the first one interval after the
        start, so a restart does not probe at once)."""
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
            except ProbeRunError as exc:
                log.info("scheduled probe not started: %s", exc)

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
