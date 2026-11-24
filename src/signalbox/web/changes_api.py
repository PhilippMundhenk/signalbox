"""API for changes: create from the desired state, approve, deploy, revert, restore backups."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from signalbox import changes, desired
from signalbox.deploy import Deployer, DeployError
from signalbox.history import ChangeRecord
from signalbox.service import Services

AUTHOR = "web interface"


class ReasonBody(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


class ApproveBody(BaseModel):
    override: str | None = Field(None, max_length=1000)
    #: Explicitly allow a plan that may cut Signalbox off from a device (#295).
    allow_lockout: bool = False


def _commit(services: Services) -> str | None:
    folder = services.data_dir / desired.FOLDER
    git = shutil.which("git")
    if git is None or not (folder / ".git").exists():
        return None
    r = subprocess.run(
        [git, "-C", str(folder), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    return r.stdout.strip() or None


def record_json(rec: ChangeRecord, services: Services) -> dict[str, Any]:
    data = rec.model_dump(mode="json")
    data["plan"]["changes"] = [
        {**c.model_dump(mode="json"), "id": c.id, "action": c.action, "text": c.describe()}
        for c in rec.plan.changes
    ]
    data["plan"]["blocking"] = [f.model_dump(mode="json") for f in rec.plan.blocking]
    data["plan"]["devices"] = rec.plan.devices()
    data["events"] = [e.model_dump(mode="json") for e in services.store.events(rec.id)]
    return data


def summary(rec: ChangeRecord) -> dict[str, Any]:
    return {
        "id": rec.id,
        "created_at": rec.created_at.isoformat(),
        "author": rec.author,
        "reason": rec.reason,
        "status": rec.status.value,
        "changes": len(rec.plan.changes),
        "devices": [r.device_id for r in rec.devices],
        "reverts": rec.reverts,
        "reverted_by": rec.reverted_by,
        "restore_backup_id": rec.restore_backup_id,
    }


def router(services: Services, deployer: Deployer) -> APIRouter:
    api = APIRouter(prefix="/api")
    store, runner = services.store, services.runner
    tasks: dict[str, asyncio.Task[Any]] = {}

    def err(
        status: int,
        message: str,
        code: str = "invalid",
        message_id: str | None = None,
        **params: Any,
    ) -> JSONResponse:
        body: dict[str, Any] = {"error": code, "message": message}
        if message_id:
            body["message_id"] = message_id
            if params:
                body["params"] = params
        return JSONResponse(body, status_code=status)

    def failed(status: int, exc: Exception) -> JSONResponse:
        """The answer for a plan or deploy error, with its translation id and values (#204)."""
        body: dict[str, Any] = {"error": "invalid", "message": str(exc)}
        if getattr(exc, "message_id", None):
            body["message_id"] = exc.message_id  # type: ignore[attr-defined]
            body["params"] = dict(exc.params)  # type: ignore[attr-defined]
        if getattr(exc, "device", None):
            body["device"] = exc.device  # type: ignore[attr-defined]
        return JSONResponse(body, status_code=status)

    @api.get("/changes")
    def list_changes() -> dict[str, Any]:
        """The change log, newest first, and whether deploying is enabled."""
        return {
            "deploy_enabled": services.config.deploy.enabled,
            "changes": [summary(r) for r in store.changes()],
        }

    @api.post("/changes", status_code=201, response_model=None)
    async def create_change(body: ReasonBody) -> dict[str, Any] | JSONResponse:
        """Plan the desired state and record it as a change waiting for approval."""
        try:
            state = desired.load(services.data_dir)
        except desired.DesiredError as exc:
            return err(422, str(exc))
        if state is None:
            return err(
                409,
                "Nothing is declared in the desired state yet.",
                "no_desired_state",
                "api.noDesired",
            )
        try:
            p = changes.plan(
                state,
                runner.network(),
                runner.active_rules(),
                services.config.rules,
                secret=store.get_secret,
                signalbox_address=services.config.deploy.signalbox_address,
            )
            rec = await deployer.prepare(p, body.reason, AUTHOR, desired_commit=_commit(services))
        except (changes.PlanError, DeployError) as exc:
            return failed(422, exc)
        return record_json(rec, services)

    @api.get("/changes/{change_id}", response_model=None)
    def get_change(change_id: str) -> dict[str, Any] | JSONResponse:
        """One change with its plan, per-device results and event log."""
        rec = store.change(change_id)
        return (
            err(404, "No such change.", "not_found", "api.noChange")
            if rec is None
            else record_json(rec, services)
        )

    @api.post("/changes/{change_id}/approve", response_model=None)
    def approve(change_id: str, body: ApproveBody) -> dict[str, Any] | JSONResponse:
        """Approve a planned change (an override reason is needed when it creates errors)."""
        try:
            return record_json(
                deployer.approve(change_id, AUTHOR, body.override, body.allow_lockout), services
            )
        except DeployError as exc:
            return failed(409, exc)

    @api.post("/changes/{change_id}/reject", response_model=None)
    def reject(change_id: str) -> dict[str, Any] | JSONResponse:
        """Reject a change that was not deployed."""
        try:
            return record_json(deployer.reject(change_id, AUTHOR), services)
        except DeployError as exc:
            return failed(409, exc)

    @api.post("/changes/{change_id}/deploy", status_code=202, response_model=None)
    async def deploy(change_id: str) -> dict[str, Any] | JSONResponse:
        """Deploy an approved change in the background; poll the change for its progress."""
        if change_id in tasks and not tasks[change_id].done():
            return err(409, "This change is being deployed.", "invalid", "api.deploying")
        rec = store.change(change_id)
        if rec is None:
            return err(404, "No such change.", "not_found", "api.noChange")
        if not services.config.deploy.enabled:
            return err(
                409,
                "Deploying is turned off (deploy.enabled in the configuration).",
                "invalid",
                "api.deployDisabled",
            )
        if rec.status.value != "approved":
            return err(
                409,
                f"The change is {rec.status.value}; it must be approved first.",
                "invalid",
                "api.notApproved",
                state=rec.status.value,
            )
        tasks[change_id] = asyncio.create_task(deployer.deploy(change_id))
        await asyncio.sleep(0)
        return {"started": True}

    @api.post("/changes/{change_id}/revert", status_code=201, response_model=None)
    async def revert(change_id: str, body: ReasonBody) -> dict[str, Any] | JSONResponse:
        """Plan a new change that undoes an applied one."""
        try:
            return record_json(await deployer.revert(change_id, body.reason, AUTHOR), services)
        except DeployError as exc:
            return failed(409, exc)

    @api.get("/backups")
    def backups(device: str | None = None) -> list[dict[str, Any]]:
        """Configuration backups taken before changes (contents stay on the server)."""
        return [b.model_dump(mode="json") for b in store.backups(device)]

    @api.post("/backups/{backup_id}/restore", status_code=201, response_model=None)
    async def restore(backup_id: str, body: ReasonBody) -> dict[str, Any] | JSONResponse:
        """Plan putting a backup back on its device (approve and deploy like any change)."""
        try:
            rec = await deployer.restore_backup(backup_id, body.reason, AUTHOR)
        except DeployError as exc:
            return failed(409, exc)
        return record_json(rec, services)

    return api
