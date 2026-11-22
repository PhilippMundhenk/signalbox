"""API of device discovery (#203): start a search, read its progress and candidates, ignore."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StringConstraints

from signalbox.discovery.engine import Discovery, DiscoveryError

Entry = Annotated[str, StringConstraints(min_length=1, max_length=100)]


class StartBody(BaseModel):
    #: Addresses, host names, networks (192.0.2.0/28) or ranges (192.0.2.10-20) to probe too.
    ranges: list[Entry] = Field(default_factory=list, max_length=32)
    #: Also probe the networks Signalbox knows from the routers already added.
    known_networks: bool = True
    #: Also send the broadcasts of the small switches' protocols.
    broadcast: bool = True


class IgnoreBody(BaseModel):
    key: str = Field(min_length=3, max_length=300)
    ignored: bool = True


def router(discovery: Discovery) -> APIRouter:
    api = APIRouter(prefix="/api")

    @api.get("/discovery")
    def status() -> dict[str, Any]:
        """Progress of the last search and the devices it found (marked when already added)."""
        return discovery.status()

    @api.post("/discovery", status_code=202, response_model=None)
    async def start(body: StartBody) -> dict[str, Any] | JSONResponse:
        """Search for devices now (known networks and the given ranges), without credentials."""
        try:
            return discovery.start(
                body.ranges, known_networks=body.known_networks, broadcast=body.broadcast
            )
        except DiscoveryError as exc:
            return JSONResponse({"error": exc.code, "message": str(exc)}, status_code=exc.status)

    @api.post("/discovery/ignore")
    def ignore(body: IgnoreBody) -> dict[str, Any]:
        """Hide a found device from the list (or show it again with `ignored: false`)."""
        return discovery.ignore(body.key, body.ignored)

    return api
