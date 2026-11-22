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
from ipaddress import IPv4Network, IPv6Network
from typing import Any
from urllib.parse import urlsplit

from pydantic import SecretStr

from signalbox.adapters import Adapter, probes_broadcast, probes_hosts
from signalbox.config import DiscoveryConfig
from signalbox.discovery.probe import Candidate, HostProbe, NetworkProbe, RateLimiter
from signalbox.discovery.targets import RangeError, Target, plan, sort_key
from signalbox.model import DeviceRole, normalise_mac
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
class Member:
    """One answer: a candidate at one address, with what identifies the device behind it."""

    candidate: Candidate
    why: str
    found_at: datetime
    identities: frozenset[str]


@dataclass
class Found:
    """One device, found at one or more addresses (#224): the answers that share an identity
    (certificate fingerprint, MAC, serial number or what the probe reads) are one entry."""

    key: str
    members: list[Member]

    @property
    def identities(self) -> set[str]:
        return {i for m in self.members for i in m.identities}

    @property
    def keys(self) -> set[str]:
        return {key_of(m.candidate.adapter, m.candidate.address) for m in self.members}

    def best(self, networks: list[IPv4Network | IPv6Network]) -> Member:
        """The answer Signalbox reaches best: an address in a network it is in (a subnet of
        an added router), else the first that answered."""
        for member in self.members:
            if _in(member.candidate.address, networks):
                return member
        return self.members[0]


def _in(address: str, networks: list[IPv4Network | IPv6Network]) -> bool:
    try:
        ip = ipaddress.ip_address(normal_host(address))
    except ValueError:
        return False
    return any(ip.version == n.version and ip in n for n in networks)


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
    #: Networks of the routers added (their subnets): addresses in them are preferred.
    networks: list[IPv4Network | IPv6Network] = field(default_factory=list)
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


def identities_of(candidate: Candidate, cert: str | None = None) -> frozenset[str]:
    """What identifies the device behind a candidate, independent of its address."""
    out = set(candidate.identities)
    if candidate.mac:
        with contextlib.suppress(ValueError):
            out.add(f"mac:{normalise_mac(candidate.mac)}")
    if cert:
        out.add(f"cert:{cert}")
    return frozenset(out)


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
            networks=[s.interface.network for s in self.runner.network().subnets],
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
            for found in self.run.found.values() if self.run else []:
                if key in found.keys:  # an entry with several addresses: show it again as a whole
                    keys -= found.keys
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
                            self._accept(
                                run, cls, found, target, probe.certificate_of(found.config)
                            )
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
                self._accept(run, cls, candidate, None, None)
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
        self,
        run: Run,
        cls: type[Adapter],
        candidate: Candidate,
        target: Target | None,
        cert: str | None,
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
        why = target.why if target else "answered the broadcast"
        member = Member(final, why, datetime.now(UTC), identities_of(candidate, cert))
        key = key_of(m.id, final.address)
        same = [
            f
            for f in run.found.values()
            if f.members[0].candidate.adapter == m.id
            and (key in f.keys or f.identities & member.identities)
        ]
        if not same:
            run.found[key] = Found(key, [member])
            return
        first = same[0]
        for other in same[1:]:  # the new answer ties two entries together
            first.members.extend(other.members)
            del run.found[other.key]
        if key not in first.keys:
            first.members.append(member)
        else:  # the same address again (host probe and broadcast): keep what is known
            first.members = [
                Member(m.candidate, m.why, m.found_at, m.identities | member.identities)
                if key_of(m.candidate.adapter, m.candidate.address) == key
                else m
                for m in first.members
            ]

    # status -------------------------------------------------------------------------------

    def _known(self) -> list[tuple[str, str, set[str], set[str]]]:
        """(device id, integration, hosts, identities) of every added device (#224).

        Hosts: the settings, the management address, and the interface and uplink addresses
        of the last snapshot. Identities: the pinned certificate and the port MACs.
        """
        snaps = {s.device.id: s for s in self.store.snapshots()}
        out = []
        for rec in self.store.devices():
            hosts = {normal_host(v) for v in rec.config.values() if isinstance(v, str) and v}
            ids: set[str] = set()
            for pinned in (rec.pinned_fingerprint, rec.pending_fingerprint):
                if pinned:
                    ids.add("cert:" + "".join(c for c in pinned.lower() if c in "0123456789abcdef"))
            snap = snaps.get(rec.id)
            if snap is not None:
                if snap.device.management_address:
                    hosts.add(normal_host(snap.device.management_address))
                hosts.update(str(sub.interface.ip) for sub in snap.subnets)
                for uplink in snap.uplinks:
                    hosts.update(str(a.ip) for a in uplink.addresses)
                    if uplink.public_ipv4 is not None:
                        hosts.add(str(uplink.public_ipv4))
                ids.update(f"mac:{p.mac}" for p in snap.ports if p.mac)
            out.append((rec.id, rec.adapter, hosts - {""}, ids))
        return out

    def _added_id(
        self, known: list[tuple[str, str, set[str], set[str]]], found: Found
    ) -> str | None:
        hosts = {normal_host(m.candidate.address) for m in found.members}
        for m in found.members:
            url = m.candidate.config.get("url")
            if isinstance(url, str):
                hosts.add(normal_host(url))
        ids = found.identities
        for device_id, adapter, known_hosts, known_ids in known:
            if adapter == found.members[0].candidate.adapter and (
                hosts & known_hosts or ids & known_ids
            ):
                return device_id
        return None

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
        known = self._known()
        ignored = self._ignored()
        names = {k: cls.manifest.name for k, cls in self.adapters.items()}
        rows = []
        for found in run.found.values():
            best = found.best(run.networks)
            c = best.candidate
            addresses = [best.candidate.address] + [
                m.candidate.address for m in found.members if m is not best
            ]
            rows.append(
                {
                    **c.model_dump(mode="json", exclude={"identities"}),
                    "key": found.key,
                    "adapter_name": names.get(c.adapter, c.adapter),
                    "why": best.why,
                    "found_at": min(m.found_at for m in found.members).isoformat(),
                    "addresses": addresses,
                    "added": self._added_id(known, found),
                    "ignored": bool(found.keys & ignored),
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
