"""API of the automatic device setup with an admin login (#231, docs/adr/0009).

``POST /api/devices/setup`` asks the integration what it would do (nothing is changed);
``POST /api/devices/setup/apply`` does it and saves the device with the new login. The admin
login in the body is used for that request only: it is not stored, not logged and not part of
any answer or error (every text from the integration passes a redactor that knows it).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, SecretStr

from signalbox.adapters import (
    AdapterError,
    AuthFailed,
    SetupRequest,
    SetupResult,
    StepState,
    Unreachable,
    UntrustedCertificate,
    UntrustedHostKey,
    provisions,
)
from signalbox.adapters.provision import Redactor
from signalbox.secrets import SecretError
from signalbox.service import Services
from signalbox.store import DeviceRecord, StoreError, _secret_fields, slug
from signalbox.web.app import DeviceTestBody, error

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
            ssh_step=ssh is not None and not anonymous,
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
        return error(422, code, redact(str(exc)), fix=redact(exc.fix) if exc.fix else None)

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
        cls, _, request = ready
        try:
            result = await cls.plan_setup(request)
        except AdapterError as exc:
            return failure(exc, redactor(request))
        return dict(result.model_dump(mode="json"))

    @api.post("/devices/setup/apply", response_model=None)
    async def apply(body: SetupBody) -> dict[str, Any] | JSONResponse:
        """Run the automatic setup (or its removal) and save the device with the new login.

        Needs `trust`. The generated password or API key goes into the device's encrypted
        settings and is never part of the answer.
        """
        ready = prepare(body)
        if isinstance(ready, JSONResponse):
            return ready
        cls, form, request = ready
        if body.admin.secret is None:
            return error(422, "invalid", "give the admin password for this step")
        if not request.trust:
            return error(422, "invalid", "confirm the device's fingerprint first")
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
                return failure(exc, redact)
            if not planned.trusted:
                return failure(UntrustedHostKey(planned.fingerprint, None), redact)
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
        try:
            result: SetupResult = await cls.apply_setup(request)
        except AdapterError as exc:
            log.info("automatic setup of %s (%s) failed", device_id, cls.manifest.id)
            return failure(exc, redact)
        log.info(
            "automatic %s of %s (%s): %s",
            "removal" if request.remove else "setup",
            device_id,
            cls.manifest.id,
            "done" if result.ok else "failed",
        )
        steps = [s.model_dump(mode="json") for s in result.steps]
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
            pinned_fingerprint=result.certificate
            or form.trust_fingerprint
            or (old.pinned_fingerprint if old else None),
            pending_fingerprint=None,
        )
        try:
            saved = store.put_device(rec, values, cls.manifest.config)
        except StoreError as exc:  # pragma: no cover - validated above
            return error(422, "invalid", redact(str(exc)), steps=steps)
        runner.trigger()
        return {"ok": True, "steps": steps, "device": device_json(saved)}

    return api
