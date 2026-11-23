"""API of *Fix it* (#215, docs/adr/0012): a known remedy for a read problem of a stored device.

``POST /api/devices/{id}/fix`` asks the integration what the remedy would do (nothing is
changed); ``POST /api/devices/{id}/fix/apply`` runs it with the admin login, then reads the
device again and returns that reading. Only on a device with *Allow changes* (not needed for a
remedy that only adds what Signalbox reads through, #278), only for a remedy the integration
declares, never in the background, and off with ``setup.enabled: false`` or
``setup.fixes: false``. The admin login is used for that request only, as in the setup.
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
    RemedyRequest,
    Unreachable,
    UntrustedCertificate,
    UntrustedHostKey,
    remedies,
)
from signalbox.adapters.provision import Redactor
from signalbox.model import Snapshot
from signalbox.secrets import SecretError
from signalbox.service import Services
from signalbox.store import StoreError, _secret_fields
from signalbox.web.app import error
from signalbox.web.setup_api import FINGERPRINT, AdminBody

log = logging.getLogger(__name__)


class FixBody(BaseModel):
    """Which remedy, the admin login for this one step and the confirmed fingerprint."""

    remedy: str = Field(pattern=r"^[a-z][a-z0-9_-]*$", max_length=64)
    admin: AdminBody
    trust: str | None = Field(None, pattern=FINGERPRINT)


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
            admin_secret=body.admin.secret,
            port=body.admin.port,
            allow_writes=rec.allow_writes,
            trust=body.trust,
            timeout=max(30.0, services.config.observe.timeout_seconds),
        )
        return cls, request

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
        return error(422, code, redact(str(exc)), fix=redact(exc.fix) if exc.fix else None)

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
        try:
            result = await cls.plan_remedy(request)
        except AdapterError as exc:
            return failure(exc, redactor(request))
        remedy = remedies(cls)[body.remedy]
        return {"remedy": remedy.model_dump(), **result.model_dump(mode="json")}

    @api.post("/devices/{device_id}/fix/apply", response_model=None)
    async def apply(device_id: str, body: FixBody) -> dict[str, Any] | JSONResponse:
        """Run the remedy, then read the device again (`reading`, as Test connection answers).

        Needs `trust`. The device keeps its stored login and settings.
        """
        ready = prepare(device_id, body)
        if isinstance(ready, JSONResponse):
            return ready
        cls, request = ready
        if not request.trust:
            return error(422, "invalid", "confirm the device's fingerprint first")
        redact = redactor(request)
        try:
            result = await cls.apply_remedy(request)
        except AdapterError as exc:
            log.info("fix %s of %s (%s) failed", body.remedy, device_id, cls.manifest.id)
            return failure(exc, redact)
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
        if result.ok and rec is not None:
            snap = await runner.observe_device(rec)
            after = store.device(device_id)
            reading = test_json(snap, after.pending_fingerprint if after else None)
            runner.trigger()
        return {"ok": result.ok, "steps": steps, "reading": reading}

    return api
