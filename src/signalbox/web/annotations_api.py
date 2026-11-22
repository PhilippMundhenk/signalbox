"""API for annotations and acknowledged findings (#186).

Declared ones (desired state) are read-only here; the API edits the ones kept in the database.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from signalbox import annotate, desired
from signalbox.model import (
    Acknowledgement,
    Annotation,
    Expected,
    annotation_target,
    finding_fingerprint,
)
from signalbox.service import Services


class AnnotationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str | None = Field(None, max_length=100)
    purpose: str | None = Field(None, max_length=200)
    owner: str | None = Field(None, max_length=100)
    notes: str | None = Field(None, max_length=2000)
    tags: list[str] = Field(default_factory=list, max_length=20)
    expected: Expected = Field(default_factory=Expected)


class AcknowledgeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(None, max_length=500)
    #: ``finding``: this finding only; ``target``: every finding of its rule naming ``target``.
    scope: Literal["finding", "target"] = "finding"
    target: str | None = Field(None, max_length=300)
    until: datetime | None = None
    #: Lapse when the finding's message changes (another address, a new count).
    lapse_on_change: bool = False


def router(services: Services) -> APIRouter:
    api = APIRouter(prefix="/api")
    data_dir, store, runner = services.data_dir, services.store, services.runner

    def _error(status: int, code: str, message: str) -> JSONResponse:
        return JSONResponse({"error": code, "message": message}, status_code=status)

    def _declared() -> tuple[list[Annotation], list[Acknowledgement]]:
        try:
            return annotate.declared(desired.load(data_dir))
        except desired.DesiredError:
            return [], []

    @api.get("/annotations")
    def get_annotations() -> dict[str, Any]:
        """Annotations and acknowledgements in effect, declared and stored (with `source`)."""
        net = runner.network()
        return {
            "annotations": [a.model_dump(mode="json") for a in net.annotations],
            "acknowledgements": [a.model_dump(mode="json") for a in net.acknowledgements],
        }

    @api.get("/annotations/export")
    def export() -> dict[str, str]:
        """The annotations and acknowledgements set in the UI as desired-state YAML."""
        return {
            "yaml": annotate.export(runner.network(), store.annotations(), store.acknowledgements())
        }

    @api.put("/annotations/{target:path}", response_model=None)
    def put_annotation(target: str, body: AnnotationBody) -> dict[str, Any] | JSONResponse:
        """Set the label, purpose, owner, notes, tags and expectations of an object."""
        try:
            key = annotation_target(target)
            note = Annotation(
                target=key,
                **body.model_dump(exclude={"expected"}),
                expected=body.expected,
                updated_at=datetime.now(UTC),
            )
        except ValidationError as exc:
            return _error(422, "invalid", "; ".join(str(e["msg"]) for e in exc.errors()))
        except ValueError as exc:
            return _error(422, "invalid", str(exc))
        if any(a.target == key for a in _declared()[0]):
            return _error(409, "declared", "Declared in the desired state; change it there.")
        store.put_annotation(note)
        runner.evaluate()
        return note.model_dump(mode="json")

    @api.delete("/annotations/{target:path}", status_code=204, response_model=None)
    def delete_annotation(target: str) -> JSONResponse | None:
        """Remove the annotation of an object set in the UI."""
        try:
            key = annotation_target(target)
        except ValueError as exc:
            return _error(422, "invalid", str(exc))
        if any(a.target == key for a in _declared()[0]):
            return _error(409, "declared", "Declared in the desired state; change it there.")
        if not store.delete_annotation(key):
            return _error(404, "not_found", "No such annotation.")
        runner.evaluate()
        return None

    @api.post("/findings/{finding_id}/acknowledge", status_code=201, response_model=None)
    def acknowledge(finding_id: str, body: AcknowledgeBody) -> dict[str, Any] | JSONResponse:
        """Acknowledge a current finding (or every finding of its rule about one object)."""
        rec = next((r for r in store.findings() if r.finding.id == finding_id), None)
        if rec is None:
            return _error(404, "not_found", "No such open finding.")
        f = rec.finding
        target = None
        if body.scope == "target":
            target = annotation_target(body.target) if body.target else None
            if target is None or target not in f.objects:
                return _error(422, "invalid", "The target must be one of the finding's objects.")
        now = datetime.now(UTC)
        try:
            ack = Acknowledgement(
                id=secrets.token_hex(8),
                rule_id=f.rule_id,
                finding_id=f.id if body.scope == "finding" else None,
                target=target,
                reason=(body.reason or "").strip() or None,
                at=now,
                until=body.until,
                fingerprint=finding_fingerprint(f.message) if body.lapse_on_change else None,
            )
        except ValidationError as exc:  # pragma: no cover - the body is already validated
            return _error(422, "invalid", str(exc))
        if ack.until is not None and not ack.active(now):
            return _error(422, "invalid", "The end date is in the past.")
        store.put_acknowledgement(ack)
        runner.evaluate()
        return ack.model_dump(mode="json")

    @api.delete("/acknowledgements/{ack_id}", status_code=204, response_model=None)
    def delete_acknowledgement(ack_id: str) -> JSONResponse | None:
        """Remove an acknowledgement set in the UI: the finding counts as a problem again."""
        if any(a.id == ack_id for a in _declared()[1]):
            return _error(409, "declared", "Declared in the desired state; change it there.")
        if not store.delete_acknowledgement(ack_id):
            return _error(404, "not_found", "No such acknowledgement.")
        runner.evaluate()
        return None

    return api
