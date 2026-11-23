"""API of foreign DHCP servers and routers (#184, docs/adr/0015): every server seen answering
(from the devices and, while probes are on, Signalbox's own probe), *Probe now* and its state.

A start answers 403 ``disabled`` while ``probes.enabled`` is off; reading is always possible
(the devices' own sightings need no probe).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from signalbox.foreign import view
from signalbox.prober import Prober, ProbeRunError
from signalbox.service import Services


def router(services: Services, prober: Prober) -> APIRouter:
    api = APIRouter(prefix="/api")

    @api.get("/probes")
    def state() -> dict[str, Any]:
        """The last probe's state per interface and every DHCP server and router seen
        answering, with the known device it is (``known_as``; none: foreign)."""
        net = services.runner.network()
        return {"status": prober.status(), "servers": view(net)}

    @api.post("/probes", status_code=202, response_model=None)
    async def start() -> dict[str, Any] | JSONResponse:
        """Probe now: one DHCPDISCOVER and one router solicitation per interface of
        Signalbox's host on a known network. One run at a time, not again right after one."""
        try:
            return prober.start()
        except ProbeRunError as exc:
            return JSONResponse({"error": exc.code, "message": str(exc)}, status_code=exc.status)

    @api.delete("/probes", status_code=204)
    def forget() -> None:
        """Forget every stored probe answer (the devices' sightings stay)."""
        services.store.delete_foreign()

    return api
