"""API of the automatic device setup with an admin login (#231, docs/adr/0009).

``POST /api/devices/setup`` asks the integration what it would do (nothing is changed);
``POST /api/devices/setup/apply`` does it and saves the device with the new login. The admin
login in the body is used for that request only: it is not stored, not logged and not part of
any answer or error (every text from the integration passes a redactor that knows it).
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
    SetupRequest,
    SetupResult,
    SetupStep,
    StepState,
    Unreachable,
    UntrustedCertificate,
    UntrustedHostKey,
    provisions,
)
from signalbox.adapters.provision import Redactor, progress_sink
from signalbox.adapters.ssh import presented_host_keys
from signalbox.hostkeys import changed_answer, refused, remember
from signalbox.hostkeys import notice as notice_host_keys
from signalbox.hostkeys import state as host_key_state
from signalbox.secrets import SecretError
from signalbox.service import Services
from signalbox.store import DeviceRecord, SshHostKeys, StoreError, _secret_fields, slug
from signalbox.web.app import DeviceTestBody, error, error_ids

log = logging.getLogger(__name__)
#: Placeholder for the secrets the setup generates, to validate the form before anything runs.
_PLACEHOLDER = "generated-by-the-automatic-setup"
#: A fingerprint as shown: SHA-256 in hex (certificate) or ``SHA256:<base64>`` (SSH host key).
FINGERPRINT = r"^(SHA256:[A-Za-z0-9+/]{43}=?|[0-9a-fA-F:]{64,95})$"


#: Stands in for the admin secret while none is given (#279): nothing may be sent with it, so
#: a request without a secret is only ever answered with the device's fingerprint.
NO_SECRET = SecretStr("-")


class AdminBody(BaseModel):
    user: str = Field(max_length=200)
    #: Never stored, logged or sent back. Missing: only the device's fingerprint is fetched,
    #: no credential is sent (the plan is shown and the identity confirmed before the password
    #: is asked for, #279); *apply* needs it.
    secret: SecretStr | None = Field(None, min_length=1, max_length=500)
    port: int | None = Field(None, ge=1, le=65535)


class SshBody(BaseModel):
    """The optional SSH step of an integration (``AdminLogin.ssh_option``, #242)."""

    #: Never stored, logged or sent back.
    secret: SecretStr | None = Field(None, min_length=1, max_length=500)
    port: int | None = Field(None, ge=1, le=65535)
    #: The SSH host key (``SHA256:...``) the user confirmed for it.
    trust: str | None = Field(None, pattern=FINGERPRINT)


class SetupBody(BaseModel):
    """The device form (as for Test connection) and the admin login for this one step."""

    device: DeviceTestBody
    admin: AdminBody
    #: Remove what the automatic setup created instead.
    remove: bool = False
    #: The SSH host key or certificate fingerprint the user confirmed.
    trust: str | None = Field(None, pattern=FINGERPRINT)
    #: Also run the integration's optional SSH step (only if its manifest offers one).
    ssh: SshBody | None = None
    #: Ids of the optional extras the user ticked (``AdminLogin.extras``, #278).
    extras: list[str] = Field(default_factory=list, max_length=20)
    #: *Apply* only: the ids of the steps the user saw in the plan before the login. If the
    #: real plan needs a step that is not among them, nothing runs and the plan is returned
    #: (409 ``plan_changed``) to be confirmed again (#279). Missing: no check (API clients).
    plan_ids: list[str] | None = Field(None, max_length=100)


#: Finished jobs stay readable this long (seconds), at most ``_MAX_JOBS`` jobs are kept.
_JOB_TTL = 600.0
_MAX_JOBS = 20


@dataclass
class SetupJob:
    """The progress of one setup run (#316). It never holds the admin login or the request:
    only the redacted steps the integration reports and the answer the run ended with."""

    id: str
    #: ``running`` until the run ended, then ``finished``.
    state: str = "running"
    #: The steps in the order they ran (reports as run, redacted).
    steps: list[dict[str, Any]] = field(default_factory=list)
    #: Id of the step that is running right now.
    current: str | None = None
    #: How it ended: the HTTP status and body *apply* would have answered.
    status: int | None = None
    result: dict[str, Any] | None = None
    ended: float = 0.0

    def view(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "state": self.state,
            "current": self.current,
            "steps": self.steps,
            "status": self.status,
            "result": self.result,
        }


def router(services: Services, device_json: Callable[[DeviceRecord], dict[str, Any]]) -> APIRouter:
    store, runner = services.store, services.runner
    api = APIRouter(prefix="/api")

    def prepare(body: SetupBody) -> tuple[Any, DeviceTestBody, SetupRequest] | JSONResponse:
        if not services.config.setup.enabled:
            return error(
                403,
                "disabled",
                "The automatic setup is turned off in the configuration (setup.enabled).",
            )
        form = body.device
        cls = services.adapters.get(form.adapter)
        if cls is None:
            return error(422, "invalid", f"adapter {form.adapter!r} is not installed")
        if form.role not in cls.manifest.roles:
            roles = ", ".join(sorted(r.value for r in cls.manifest.roles))
            return error(422, "invalid", f"{cls.manifest.name} devices can be: {roles}")
        if not provisions(cls):
            return error(
                422, "not_supported", f"{cls.manifest.name} cannot be set up automatically"
            )
        if form.device_id and store.device(form.device_id) is None:
            return error(404, "not_found", "No such device.")
        if body.ssh is not None and not (
            cls.manifest.admin_login and cls.manifest.admin_login.ssh_option
        ):
            return error(
                422, "not_supported", f"{cls.manifest.name} has no optional SSH step to run"
            )
        offered = (
            {e.id for e in cls.manifest.admin_login.extras} if cls.manifest.admin_login else set()
        )
        unknown = sorted(set(body.extras) - offered)
        if unknown:
            return error(
                422, "not_supported", f"{cls.manifest.name} has no optional extra {unknown[0]!r}"
            )
        ssh = body.ssh
        secret_names = _secret_fields(cls.manifest.config)
        plain = {k: v for k, v in form.config.items() if k not in secret_names}
        anonymous = body.admin.secret is None
        if ssh is not None and ssh.secret is None and not anonymous:
            return error(422, "invalid", "give the SSH password, or untick the SSH step")
        request = SetupRequest(
            config=plain,
            admin_user=body.admin.user.strip(),
            admin_secret=body.admin.secret or NO_SECRET,
            port=body.admin.port,
            allow_writes=form.allow_writes,
            remove=body.remove,
            extras=sorted(set(body.extras)),
            # without the password only the fingerprint is fetched: nothing is sent, nothing
            # is trusted yet (#279)
            trust=None if anonymous else body.trust,
            ssh_step=ssh is not None,
            identity_only=anonymous,
            ssh_secret=ssh.secret if ssh and not anonymous else None,
            ssh_port=ssh.port if ssh else None,
            ssh_trust=ssh.trust if ssh and not anonymous else None,
            timeout=max(30.0, services.config.observe.timeout_seconds),
            traces=services.config.traces.enabled,
        )
        return cls, form, request

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
            else "setup_failed"
        )
        return error(
            422,
            code,
            redact(str(exc)),
            fix=redact(exc.fix) if exc.fix else None,
            **error_ids(exc, redact),
        )

    def changed_key(
        exc: AdapterError, device_id: str | None, name: str, seen: dict[str, str]
    ) -> JSONResponse | None:
        """A refused handshake with another SSH host key than the device's pin (#526): the
        change is recorded (finding ``ssh.host-key-changed``) and answered with both keys."""
        if not isinstance(exc, UntrustedHostKey) or not device_id:
            return None
        if not notice_host_keys(store, device_id, [exc.fingerprint], seen, "setup"):
            return None
        runner.evaluate()
        keys = store.ssh_host_keys(device_id)
        return JSONResponse(changed_answer(name, keys, exc.fingerprint), status_code=409)

    def with_host_keys(
        out: dict[str, Any], plan: Any, device_id: str | None, seen: dict[str, str]
    ) -> dict[str, Any]:
        """A plan with how each presented SSH host key compares with the device's pin (#526):
        a changed one is recorded at once (nothing was sent with it)."""
        main = plan.fingerprint if plan.fingerprint_kind == "ssh-host-key" else None
        if notice_host_keys(store, device_id, [main, plan.ssh_fingerprint], seen, "setup"):
            runner.evaluate()
        keys = store.ssh_host_keys(device_id) if device_id else SshHostKeys()
        out["host_key"] = host_key_state(keys, main)
        out["ssh_host_key"] = host_key_state(keys, plan.ssh_fingerprint)
        return out

    def redactor(request: SetupRequest) -> Redactor:
        redact = Redactor()
        redact.add(request.admin_secret.get_secret_value())
        if request.ssh_secret is not None:
            redact.add(request.ssh_secret.get_secret_value())
        return redact

    @api.post("/devices/setup", response_model=None)
    async def plan(body: SetupBody) -> dict[str, Any] | JSONResponse:
        """What the automatic setup would do with this admin login; nothing is changed.

        Without `trust`, or when the device presents another fingerprint, only the presented
        SSH host key or certificate is returned (`trusted: false`) and no login is sent.
        """
        ready = prepare(body)
        if isinstance(ready, JSONResponse):
            return ready
        cls, form, request = ready
        seen: dict[str, str] = {}
        token = presented_host_keys.set(seen)
        try:
            result = await cls.plan_setup(request)
        except AdapterError as exc:
            return changed_key(exc, form.device_id, form.name, seen) or failure(
                exc, redactor(request)
            )
        finally:
            presented_host_keys.reset(token)
        return with_host_keys(dict(result.model_dump(mode="json")), result, form.device_id, seen)

    @api.post("/devices/setup/apply", response_model=None)
    async def apply(body: SetupBody) -> dict[str, Any] | JSONResponse:
        """Run the automatic setup (or its removal) and save the device with the new login.

        Needs `trust`. The generated password or API key goes into the device's encrypted
        settings and is never part of the answer. One request, answered when the run ended;
        the web UI uses ``/devices/setup/jobs`` instead to show the step that is running.
        """
        ready = prepare(body)
        if isinstance(ready, JSONResponse):
            return ready
        checked = require_login(body, ready[2])
        if checked is not None:
            return checked
        return await run_apply(body, *ready)

    def require_login(body: SetupBody, request: SetupRequest) -> JSONResponse | None:
        if body.admin.secret is None:
            return error(422, "invalid", "give the admin password for this step")
        if not request.trust:
            return error(422, "invalid", "confirm the device's fingerprint first")
        return None

    jobs: dict[str, SetupJob] = {}
    running: set[asyncio.Task[None]] = set()

    def forget() -> None:
        now = time.monotonic()
        for jid in [j for j, v in jobs.items() if v.ended and now - v.ended > _JOB_TTL]:
            del jobs[jid]
        while len(jobs) > _MAX_JOBS:
            oldest = next((j for j, v in jobs.items() if v.ended), None)
            if oldest is None:
                break
            del jobs[oldest]

    @api.post("/devices/setup/jobs", status_code=202, response_model=None)
    async def start(body: SetupBody) -> dict[str, Any] | JSONResponse:
        """Start the setup in the background and return a job to poll (#316).

        The same body and the same refusals as *apply*, answered at once for what can be
        checked without the device; whatever goes wrong later is the job's ``result``
        (``status`` and body as *apply* would have answered). The admin login lives in this run
        only: the job holds no request, no secret and only redacted step reports.
        """
        ready = prepare(body)
        if isinstance(ready, JSONResponse):
            return ready
        checked = require_login(body, ready[2])
        if checked is not None:
            return checked
        form, request = ready[1], ready[2]
        stale = refused(store, form.device_id, form.name, [request.trust, request.ssh_trust])
        if stale is not None:  # a changed SSH host key (#526): refused at once, nothing runs
            return JSONResponse(stale, status_code=409)
        forget()
        if sum(1 for j in jobs.values() if not j.ended) >= _MAX_JOBS:
            return error(429, "busy", "Too many setups are running; wait for one to finish.")
        job = SetupJob(id=secrets.token_urlsafe(16))
        jobs[job.id] = job

        def report(step: SetupStep, starting: bool) -> None:
            data = step.model_dump(mode="json")
            if starting:
                job.current = step.id
                if not any(s["id"] == step.id for s in job.steps):
                    job.steps.append(data)
                return
            job.steps = [data if s["id"] == step.id else s for s in job.steps]
            if all(s["id"] != step.id for s in job.steps):
                job.steps.append(data)
            if job.current == step.id:
                job.current = None

        async def work() -> None:
            progress_sink.set(report)
            try:
                answer = await run_apply(body, *ready)
            except Exception as exc:  # the text may hold a secret: only the type is kept
                log.warning("automatic setup job failed: %s", type(exc).__name__)
                job.status, job.result = (
                    500,
                    {"error": "setup_failed", "message": "The setup failed unexpectedly."},
                )
            else:
                if isinstance(answer, JSONResponse):
                    job.status, job.result = answer.status_code, json.loads(bytes(answer.body))
                else:
                    job.status, job.result = 200, answer
            job.current = None
            job.state = "finished"
            job.ended = time.monotonic()

        task = asyncio.create_task(work())
        running.add(task)
        task.add_done_callback(running.discard)
        return {"id": job.id}

    @api.get("/devices/setup/jobs/{job_id}", response_model=None)
    async def progress(job_id: str) -> dict[str, Any] | JSONResponse:
        """The state of a setup job: the steps so far, the one running, and the outcome."""
        job = jobs.get(job_id)
        if job is None:
            return error(404, "not_found", "No such setup run (it may be too old).")
        return job.view()

    async def run_apply(
        body: SetupBody, cls: Any, form: DeviceTestBody, request: SetupRequest
    ) -> dict[str, Any] | JSONResponse:
        # a confirmed SSH host key that is not the device's pin: refused before the adapter
        # is called, so no password is sent (#526)
        stale = refused(store, form.device_id, form.name, [request.trust, request.ssh_trust])
        if stale is not None:
            return JSONResponse(stale, status_code=409)
        seen: dict[str, str] = {}
        token = presented_host_keys.set(seen)
        try:
            return await run_pinned(body, cls, form, request, seen)
        finally:
            presented_host_keys.reset(token)

    async def run_pinned(
        body: SetupBody,
        cls: Any,
        form: DeviceTestBody,
        request: SetupRequest,
        seen: dict[str, str],
    ) -> dict[str, Any] | JSONResponse:
        device_id = form.device_id or slug(form.name, [d.id for d in store.devices()])
        secret_names = _secret_fields(cls.manifest.config)
        if not request.remove:
            # the rest of the form must be valid before anything changes on the device
            try:
                store.form_config(
                    form.device_id,
                    {**form.config, **dict.fromkeys(secret_names, _PLACEHOLDER)},
                    cls.manifest.config,
                )
            except (StoreError, SecretError) as exc:
                return error(422, "invalid", str(exc))
        redact = redactor(request)
        if body.plan_ids is not None:
            try:
                planned = await cls.plan_setup(request)
            except AdapterError as exc:
                return changed_key(exc, form.device_id, form.name, seen) or failure(exc, redact)
            if not planned.trusted:
                untrusted = UntrustedHostKey(planned.fingerprint, None)
                return changed_key(untrusted, form.device_id, form.name, seen) or failure(
                    untrusted, redact
                )
            if planned.ssh_trusted is False and planned.ssh_fingerprint:
                answer = changed_key(
                    UntrustedHostKey(planned.ssh_fingerprint, None), form.device_id, form.name, seen
                )
                if answer is not None:
                    return answer
            if planned.ssh_trusted is False:
                return error(
                    409,
                    "untrusted_ssh",
                    "Confirm the SSH host key first; the SSH password has not been sent.",
                    fingerprint=planned.ssh_fingerprint,
                    compare=planned.ssh_compare,
                )
            new = [s.id for s in planned.steps if s.state is StepState.TODO]
            if set(new) - set(body.plan_ids):
                return error(
                    409,
                    "plan_changed",
                    "The device needs steps that were not in the plan you saw. Check the plan "
                    "and run it again; nothing was changed.",
                    plan=planned.model_dump(mode="json"),
                )
        trusts = [request.trust, request.ssh_trust]
        try:
            result: SetupResult = await cls.apply_setup(request)
        except AdapterError as exc:
            log.info("automatic setup of %s (%s) failed", device_id, cls.manifest.id)
            answer = changed_key(exc, form.device_id, form.name, seen)
            if answer is not None:
                return answer
            if form.device_id and not isinstance(exc, UntrustedHostKey | UntrustedCertificate):
                remember(store, form.device_id, trusts, seen, "setup")
            return failure(exc, redact)
        log.info(
            "automatic %s of %s (%s): %s",
            "removal" if request.remove else "setup",
            device_id,
            cls.manifest.id,
            "done" if result.ok else "failed",
        )
        steps = [s.model_dump(mode="json") for s in result.steps]
        if form.device_id:  # the first trust of a stored device's SSH host key (#526)
            remember(store, form.device_id, trusts, seen, "setup")
        if request.remove or not result.ok:
            return {"ok": result.ok, "steps": steps, "device": None}
        old = store.device(form.device_id) if form.device_id else None
        values = {
            **form.config,
            **result.settings,
            **{k: v.get_secret_value() for k, v in result.secrets.items()},
        }
        rec = DeviceRecord(
            id=device_id,
            site_id=form.site_id,
            name=form.name,
            role=form.role,
            adapter=form.adapter,
            enabled=form.enabled,
            allow_writes=form.allow_writes,
            hosted_on=form.hosted_on if form.hosted_on != device_id else None,
            pinned_fingerprint=result.certificate
            or form.trust_fingerprint
            or (old.pinned_fingerprint if old else None),
            pending_fingerprint=None,
        )
        try:
            saved = store.put_device(rec, values, cls.manifest.config)
        except StoreError as exc:  # pragma: no cover - validated above
            return error(422, "invalid", redact(str(exc)), steps=steps)
        remember(store, saved.id, trusts, seen, "setup")  # a new device: its first trust
        runner.trigger()
        return {"ok": True, "steps": steps, "device": device_json(saved)}

    return api
