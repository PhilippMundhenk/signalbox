"""API of path traces (#253, docs/adr/0014): the routed paths, *Trace now* and its progress.

A start answers 403 ``disabled`` while ``traces.enabled`` is off; reading the state is always
possible (it then says the feature is off and lists no traces).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from signalbox.service import Services
from signalbox.tracer import TraceError, Tracer
from signalbox.traces import routed_view


class TraceBody(BaseModel):
    #: A device id or ``signalbox``; empty: every gateway that can trace (and Signalbox).
    source: str | None = Field(None, min_length=1, max_length=100)
    #: A device id or an IP address; empty: every other gateway and the internet target.
    target: str | None = Field(None, min_length=1, max_length=100)


def router(services: Services, tracer: Tracer) -> APIRouter:
    api = APIRouter(prefix="/api")

    @api.get("/traces")
    def state() -> dict[str, Any]:
        """The last run's progress, the sources that can trace (with the permission each
        needs) and the routed paths of the stored traces with who is in front of whom."""
        net = services.runner.network()
        return {"status": tracer.status(), "sources": tracer.sources(net), **routed_view(net)}

    @api.post("/traces", status_code=202, response_model=None)
    async def start(body: TraceBody) -> dict[str, Any] | JSONResponse:
        """Trace now: all gateways to each other and to the internet target, or only from or
        to the chosen device (or address). One run at a time, not again right after one."""
        try:
            return tracer.start(body.source, body.target)
        except TraceError as exc:
            return JSONResponse({"error": exc.code, "message": str(exc)}, status_code=exc.status)

    @api.delete("/traces", status_code=204)
    def forget() -> None:
        """Forget every stored trace."""
        services.store.delete_traces()

    return api
