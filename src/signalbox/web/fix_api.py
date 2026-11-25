"""API of *Fix it* (#215, docs/adr/0012): a known remedy for a read problem of a stored device.

``POST /api/devices/{id}/fix`` asks the integration what the remedy would do (nothing is
changed); ``POST /api/devices/{id}/fix/apply`` runs it with the admin login, then reads the
device again and returns that reading. Only on a device with *Allow changes* (not needed for a
remedy that only adds what Signalbox reads through, #278), only for a remedy the integration
declares, never in the background, and off with ``setup.enabled: false`` or
``setup.fixes: false``. The admin login is used for that request only, as in the setup.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, SecretStr

from signalbox.adapters import (
    AdapterError,
    AuthFailed,
    RemedyRequest,
    SetupStep,
    StepState,
    Unreachable,
    UntrustedCertificate,
    UntrustedHostKey,
    remedies,
)
from signalbox.adapters.provision import Redactor, progress_sink
from signalbox.adapters.ssh import presented_endpoints, presented_host_keys
from signalbox.hostkeys import (
    certificate_state,
    changed,
    notice_certificate,
    refused,
    remember,
    with_offered,
)
from signalbox.hostkeys import notice as notice_host_keys
from signalbox.hostkeys import state as host_key_state
from signalbox.model import Snapshot
from signalbox.secrets import SecretError
from signalbox.service import Services
from signalbox.store import StoreError, _secret_fields
from signalbox.web.app import error, error_ids
from signalbox.web.setup_api import FINGERPRINT, NO_SECRET, AdminBody

log = logging.getLogger(__name__)


class FixBody(BaseModel):
    """Which remedy, the admin login for this one step and the confirmed fingerprint."""

    remedy: str = Field(pattern=r"^[a-z][a-z0-9_-]*$", max_length=64)
    admin: AdminBody
    trust: str | None = Field(None, pattern=FINGERPRINT)
    #: *Apply* only: the step ids the user saw before the login (see ``SetupBody.plan_ids``).
    plan_ids: list[str] | None = Field(None, max_length=100)


class FixItem(BaseModel):
    """One device and remedy of a run with several (#376): the same login and confirmation as a
    single *Fix it*. The admin login is used for this run only."""

    device_id: str = Field(max_length=200)
    body: FixBody


class FixRunBody(BaseModel):
    """The fixes the user ticked, in the order they run."""

    items: list[FixItem] = Field(min_length=1, max_length=50)


#: Finished runs stay readable this long (seconds), at most ``_MAX_RUNS`` runs are kept.
_RUN_TTL = 600.0
_MAX_RUNS = 5


@dataclass
class FixRunItem:
    """The state of one device of a run; only redacted reports, never the login."""

    device_id: str
    name: str
    remedy: str
    title: str
    #: ``pending``, ``running``, ``done``, ``failed``.
    state: str = "pending"
    steps: list[dict[str, Any]] = field(default_factory=list)
    current: str | None = None
    #: A failed item: ``code``, ``message`` and ``fix`` as the single *Fix it* answers.
    problem: dict[str, Any] | None = None
    #: The device read again afterwards: its status and how many read problems are left.
    reading: dict[str, Any] | None = None

    def view(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "name": self.name,
            "remedy": self.remedy,
            "title": self.title,
            "state": self.state,
            "steps": self.steps,
            "current": self.current,
            "problem": self.problem,
            "reading": self.reading,
        }


@dataclass
class FixRun:
    id: str
    state: str = "running"
    items: list[FixRunItem] = field(default_factory=list)
    ended: float = 0.0

    def view(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "state": self.state,
            "items": [i.view() for i in self.items],
            "done": sum(1 for i in self.items if i.state == "done"),
            "failed": sum(1 for i in self.items if i.state == "failed"),
        }


def fixes_enabled(services: Services) -> bool:
    setup = services.config.setup
    return setup.enabled and setup.fixes


def router(
    services: Services, test_json: Callable[[Snapshot, str | None], dict[str, Any]]
) -> APIRouter:
    store, runner = services.store, services.runner
    api = APIRouter(prefix="/api")

    def prepare(device_id: str, body: FixBody) -> tuple[Any, RemedyRequest] | JSONResponse:
        if not fixes_enabled(services):
            return error(
                403,
                "disabled",
                "Fix it is turned off in the configuration (setup.enabled, setup.fixes).",
            )
        rec = store.device(device_id)
        if rec is None:
            return error(404, "not_found", "No such device.")
        cls = services.adapters.get(rec.adapter)
        if cls is None:
            return error(422, "invalid", f"adapter {rec.adapter!r} is not installed")
        if body.remedy not in remedies(cls):
            return error(422, "not_supported", f"{cls.manifest.name} cannot fix this automatically")
        if not rec.allow_writes and not remedies(cls)[body.remedy].read_side:
            return error(
                422,
                "not_allowed",
                "Fix it changes the device: turn on Allow changes for it first.",
            )
        try:
            cfg = store.adapter_config(device_id, cls.manifest.config)
        except (StoreError, SecretError) as exc:
            return error(422, "invalid", str(exc))
        names = _secret_fields(cls.manifest.config)
        values = cfg.model_dump(mode="json", exclude=names)
        secrets = {
            n: v
            for n in names
            if isinstance(v := getattr(cfg, n, None), SecretStr) and v.get_secret_value()
        }
        request = RemedyRequest(
            remedy=body.remedy,
            config=values,
            secrets=secrets,
            admin_user=body.admin.user.strip(),
            admin_secret=body.admin.secret or NO_SECRET,
            port=body.admin.port,
            allow_writes=rec.allow_writes,
            # without the password only the fingerprint is fetched, nothing is sent (#279)
            trust=None if body.admin.secret is None else body.trust,
            timeout=max(30.0, services.config.observe.timeout_seconds),
            traces=services.config.traces.enabled,
        )
        return cls, request

    def changed_key(
        exc: AdapterError, device_id: str, seen: dict[str, str], action: str
    ) -> JSONResponse | None:
        """A refused handshake with another SSH host key (#526) or certificate (#535) than the
        device's pin: recorded (a finding) and answered with both."""
        rec = store.device(device_id)
        if rec is None:
            return None
        answer = changed(store, device_id, rec.name, exc, seen, action)
        if answer is None:
            return None
        if answer.get("error") == "certificate_changed":
            runner.trigger()  # read.untrusted and cert.renewed come from the reading
        else:
            runner.evaluate()
        return JSONResponse(answer, status_code=409)

    def redactor(request: RemedyRequest) -> Redactor:
        redact = Redactor()
        redact.add(request.admin_secret.get_secret_value())
        redact.add(*(s.get_secret_value() for s in request.secrets.values()))
        return redact

    def failure(exc: AdapterError, redact: Redactor) -> JSONResponse:
        if isinstance(exc, UntrustedHostKey | UntrustedCertificate):
            return error(
                409,
                "untrusted",
                "The device presented a different key than the one you confirmed.",
                fingerprint=exc.fingerprint,
            )
        code = (
            "auth_failed"
            if isinstance(exc, AuthFailed)
            else "unreachable"
            if isinstance(exc, Unreachable)
            else "fix_failed"
        )
        return error(
            422,
            code,
            redact(str(exc)),
            fix=redact(exc.fix) if exc.fix else None,
            **error_ids(exc, redact),
        )

    @api.post("/devices/{device_id}/fix", response_model=None)
    async def plan(device_id: str, body: FixBody) -> dict[str, Any] | JSONResponse:
        """What *Fix it* would do on this device with the admin login; nothing is changed.

        Without `trust`, or when the device presents another fingerprint, only the presented
        SSH host key or certificate is returned (`trusted: false`) and no login is sent.
        """
        ready = prepare(device_id, body)
        if isinstance(ready, JSONResponse):
            return ready
        cls, request = ready
        action = f"fix:{body.remedy}"
        seen: dict[str, str] = {}
        endpoints: dict[str, tuple[str, int]] = {}
        token = presented_host_keys.set(seen)
        where = presented_endpoints.set(endpoints)
        try:
            result = await cls.plan_remedy(request)
        except AdapterError as exc:
            return changed_key(exc, device_id, seen, action) or failure(exc, redactor(request))
        finally:
            presented_endpoints.reset(where)
            presented_host_keys.reset(token)
        remedy = remedies(cls)[body.remedy]
        # how the presented SSH host key (#526) or certificate (#535) compares with the pin
        if result.fingerprint_kind == "certificate":
            if notice_certificate(store, device_id, result.fingerprint):
                runner.trigger()
            known = certificate_state(store.device(device_id), result.fingerprint)
        else:
            if notice_host_keys(store, device_id, [result.fingerprint], seen, action):
                runner.evaluate()
            known = await with_offered(
                host_key_state(store.ssh_host_keys(device_id), result.fingerprint),
                seen,
                endpoints,
                request.timeout,
            )
        return {"remedy": remedy.model_dump(), **result.model_dump(mode="json"), "host_key": known}

    @api.post("/devices/{device_id}/fix/apply", response_model=None)
    async def apply(device_id: str, body: FixBody) -> dict[str, Any] | JSONResponse:
        """Run the remedy, then read the device again (`reading`, as Test connection answers).

        Needs `trust`. The device keeps its stored login and settings.
        """
        return await run_fix(device_id, body)

    async def run_fix(
        device_id: str, body: FixBody, *, reread_failed: bool = False
    ) -> dict[str, Any] | JSONResponse:
        ready = prepare(device_id, body)
        if isinstance(ready, JSONResponse):
            return ready
        cls, request = ready
        if body.admin.secret is None:
            return error(422, "invalid", "give the admin password for this step")
        if not request.trust:
            return error(422, "invalid", "confirm the device's fingerprint first")
        rec = store.device(device_id)
        # a confirmed SSH host key or certificate that is not the device's pin: refused before
        # the adapter is called, so no password is sent (#526, #535)
        stale = refused(store, device_id, rec.name if rec else device_id, [request.trust])
        if stale is not None:
            return JSONResponse(stale, status_code=409)
        seen: dict[str, str] = {}
        token = presented_host_keys.set(seen)
        try:
            return await run_pinned(device_id, body, cls, request, seen, reread_failed)
        finally:
            presented_host_keys.reset(token)

    async def run_pinned(
        device_id: str,
        body: FixBody,
        cls: Any,
        request: RemedyRequest,
        seen: dict[str, str],
        reread_failed: bool,
    ) -> dict[str, Any] | JSONResponse:
        action = f"fix:{body.remedy}"
        redact = redactor(request)
        if body.plan_ids is not None:
            try:
                planned = await cls.plan_remedy(request)
            except AdapterError as exc:
                return changed_key(exc, device_id, seen, action) or failure(exc, redact)
            if not planned.trusted:
                untrusted: AdapterError = (
                    UntrustedCertificate(planned.fingerprint, None)
                    if planned.fingerprint_kind == "certificate"
                    else UntrustedHostKey(planned.fingerprint, None)
                )
                return changed_key(untrusted, device_id, seen, action) or failure(untrusted, redact)
            new = [s.id for s in planned.steps if s.state is StepState.TODO]
            if set(new) - set(body.plan_ids):
                return error(
                    409,
                    "plan_changed",
                    "The device needs steps that were not in the plan you saw. Check the plan "
                    "and run it again; nothing was changed.",
                    plan=planned.model_dump(mode="json"),
                )
        try:
            result = await cls.apply_remedy(request)
        except AdapterError as exc:
            log.info("fix %s of %s (%s) failed", body.remedy, device_id, cls.manifest.id)
            answer = changed_key(exc, device_id, seen, action)
            if answer is not None:
                return answer
            if not isinstance(exc, UntrustedHostKey | UntrustedCertificate):
                remember(store, device_id, [request.trust], seen, action)
            return failure(exc, redact)
        remember(store, device_id, [request.trust], seen, action)  # the first trust (#526)
        log.info(
            "fix %s of %s (%s): %s",
            body.remedy,
            device_id,
            cls.manifest.id,
            "done" if result.ok else "failed",
        )
        steps = [s.model_dump(mode="json") for s in result.steps]
        reading = None
        rec = store.device(device_id)
        touched = any(s.state is StepState.DONE for s in result.steps)
        if rec is not None and (result.ok or (reread_failed and touched)):
            snap = await runner.observe_device(rec)
            after = store.device(device_id)
            reading = test_json(snap, after.pending_fingerprint if after else None)
            runner.trigger()
        return {"ok": result.ok, "steps": steps, "reading": reading}

    # all fixes of all devices (#376) ----------------------------------------------------

    @api.get("/fixes")
    def available() -> dict[str, Any]:
        """Every fix available across the stored devices (#376), from their last reading.

        Per device the remedies that the read problems and gaps name, each `mandatory` when a
        problem that blocks checks offers it and optional when only a missing extra does
        (LLDP). `manual: true`: the device does not allow changes and the remedy needs them,
        so only the manual steps (`causes[].fix`) are shown. Nothing is offered while Fix it
        is off (`enabled: false`). Reads the stored readings only; nothing is sent to a device.
        """
        counts = {"available": 0, "mandatory": 0, "optional": 0, "manual": 0}
        if not fixes_enabled(services):
            return {"enabled": False, "devices": [], "counts": counts}
        records = {r.id: r for r in store.devices() if r.enabled}
        devices: list[dict[str, Any]] = []
        for snap in store.snapshots():
            rec = records.get(snap.device.id)
            cls = services.adapters.get(rec.adapter) if rec else None
            if rec is None or cls is None:
                continue
            known = remedies(cls)
            items: dict[str, dict[str, Any]] = {}
            for err in snap.errors:
                remedy = known.get(err.remedy or "")
                if remedy is None:
                    continue
                item = items.setdefault(
                    remedy.id,
                    {
                        "remedy": remedy.id,
                        "title": remedy.title,
                        "description": remedy.description,
                        "preview": [p.model_dump(mode="json") for p in remedy.preview],
                        "read_side": remedy.read_side,
                        "mandatory": False,
                        "manual": not rec.allow_writes and not remedy.read_side,
                        "causes": [],
                    },
                )
                item["mandatory"] = item["mandatory"] or not err.optional
                item["causes"].append(
                    {
                        "capability": err.capability,
                        "message": err.message,
                        "message_id": err.message_id,
                        "fix": err.fix,
                        "fix_id": err.fix_id,
                        "params": err.params,
                        "optional": err.optional,
                    }
                )
            if not items:
                continue
            for item in items.values():
                if item["manual"]:
                    counts["manual"] += 1
                    continue
                counts["available"] += 1
                counts["mandatory" if item["mandatory"] else "optional"] += 1
            devices.append(
                {
                    "device_id": rec.id,
                    "name": rec.name,
                    "adapter": rec.adapter,
                    "allow_writes": rec.allow_writes,
                    "fixes": sorted(items.values(), key=lambda i: (not i["mandatory"], i["title"])),
                }
            )
        devices.sort(key=lambda d: str(d["name"]).lower())
        return {"enabled": True, "devices": devices, "counts": counts}

    runs: dict[str, FixRun] = {}
    running: set[asyncio.Task[None]] = set()

    def forget() -> None:
        now = time.monotonic()
        for rid in [r for r, v in runs.items() if v.ended and now - v.ended > _RUN_TTL]:
            del runs[rid]
        while len(runs) > _MAX_RUNS:
            oldest = next((r for r, v in runs.items() if v.ended), None)
            if oldest is None:
                break
            del runs[oldest]

    def settle(item: FixRunItem, answer: dict[str, Any] | JSONResponse) -> None:
        if isinstance(answer, JSONResponse):
            data = json.loads(bytes(answer.body))
            item.state = "failed"
            item.problem = {
                "code": data.get("error", "fix_failed"),
                "message": data.get("message", ""),
                "fix": data.get("fix"),
                "message_id": data.get("message_id"),
                "fix_id": data.get("fix_id"),
                "params": data.get("params"),
                "host_key": data.get("host_key"),
            }
            return
        item.steps = answer["steps"]
        item.state = "done" if answer["ok"] else "failed"
        if not answer["ok"]:
            failed: dict[str, Any] = next(
                (s for s in answer["steps"] if s.get("state") == "failed"), {}
            )
            item.problem = {
                "code": "fix_failed",
                "message": failed.get("message") or "",
                "fix": None,
            }
        reading = answer["reading"]
        if reading is not None:
            item.reading = {
                "status": reading.get("status"),
                "problems": sum(1 for e in reading.get("errors", []) if not e.get("optional")),
            }

    @api.post("/fixes/jobs", status_code=202, response_model=None)
    async def start(body: FixRunBody) -> dict[str, Any] | JSONResponse:
        """Run several fixes one after the other and return a job to poll (#376).

        Each item is one device and remedy with its own admin login and confirmed fingerprint,
        exactly as *apply* takes them; everything that can be refused without the device is
        refused at once (nothing runs then). The items run in order, a failure does not stop the
        run, and each touched device is read again. The logins live in this run only: the job
        holds redacted step reports and the outcome per device, no secret.
        """
        seen: set[tuple[str, str]] = set()
        prepared: list[FixRunItem] = []
        for entry in body.items:
            ready = prepare(entry.device_id, entry.body)
            if isinstance(ready, JSONResponse):
                return ready
            if entry.body.admin.secret is None:
                return error(422, "invalid", "give the admin password for every fix")
            if not ready[1].trust:
                return error(422, "invalid", "confirm the device's fingerprint first")
            rec = store.device(entry.device_id)
            stale = refused(
                store, entry.device_id, rec.name if rec else entry.device_id, [ready[1].trust]
            )
            if stale is not None:  # nothing runs: that device's key must be re-trusted first
                return JSONResponse(stale, status_code=409)
            key = (entry.device_id, entry.body.remedy)
            if key in seen:
                return error(422, "invalid", "the same fix is listed twice")
            seen.add(key)
            prepared.append(
                FixRunItem(
                    device_id=entry.device_id,
                    name=rec.name if rec else entry.device_id,
                    remedy=entry.body.remedy,
                    title=remedies(ready[0])[entry.body.remedy].title,
                )
            )
        forget()
        if sum(1 for r in runs.values() if not r.ended) >= _MAX_RUNS:
            return error(429, "busy", "Too many fix runs are going; wait for one to finish.")
        run = FixRun(id=secrets.token_urlsafe(16), items=prepared)
        runs[run.id] = run
        entries = list(body.items)

        async def work() -> None:
            for entry, item in zip(entries, run.items, strict=True):
                item.state = "running"

                def report(step: SetupStep, starting: bool, item: FixRunItem = item) -> None:
                    data = step.model_dump(mode="json")
                    if starting:
                        item.current = step.id
                    item.steps = [s for s in item.steps if s["id"] != step.id] + [data]
                    if not starting and item.current == step.id:
                        item.current = None

                progress_sink.set(report)
                try:
                    answer = await run_fix(entry.device_id, entry.body, reread_failed=True)
                except Exception as exc:  # the text may hold a secret: only the type is kept
                    log.warning("fix run item failed: %s", type(exc).__name__)
                    item.state = "failed"
                    item.problem = {
                        "code": "fix_failed",
                        "message": "The fix failed unexpectedly.",
                        "fix": None,
                    }
                else:
                    settle(item, answer)
                item.current = None
                entry.body.admin.secret = None  # the login is not needed any more
            run.state = "finished"
            run.ended = time.monotonic()

        task = asyncio.create_task(work())
        running.add(task)
        task.add_done_callback(running.discard)
        return {"id": run.id}

    @api.get("/fixes/jobs/{run_id}", response_model=None)
    async def progress(run_id: str) -> dict[str, Any] | JSONResponse:
        """The state of a run of several fixes: per device `pending`, `running`, `done` or
        `failed` with its steps, the problem and the reading afterwards."""
        run = runs.get(run_id)
        if run is None:
            return error(404, "not_found", "No such fix run (it may be too old).")
        return run.view()

    return api
