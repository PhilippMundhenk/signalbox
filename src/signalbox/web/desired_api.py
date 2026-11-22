"""API for the desired state and its secrets (Wi-Fi passphrases)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from signalbox import desired
from signalbox.service import Services


class DesiredBody(BaseModel):
    yaml: str = Field(max_length=200_000)
    message: str = Field("", max_length=500)


class SecretBody(BaseModel):
    value: str = Field(min_length=1, max_length=200)


SECRET_NAME = r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$"


def router(services: Services) -> APIRouter:
    api = APIRouter(prefix="/api")
    data_dir, store, runner = services.data_dir, services.store, services.runner

    def _error(status: int, code: str, message: str) -> JSONResponse:
        return JSONResponse({"error": code, "message": message}, status_code=status)

    @api.get("/desired")
    def get_desired() -> dict[str, Any]:
        """The desired state as YAML (empty when nothing is declared) and whether it is valid."""
        path = data_dir / desired.FOLDER / "network.yaml"
        text = path.read_text() if path.exists() else ""
        try:
            state = desired.load(data_dir)
        except desired.DesiredError as exc:
            return {"yaml": text, "valid": False, "error": str(exc), "sites": []}
        return {
            "yaml": text,
            "valid": True,
            "error": None,
            "sites": sorted(state.sites) if state else [],
        }

    @api.put("/desired", response_model=None)
    def put_desired(body: DesiredBody) -> dict[str, Any] | JSONResponse:
        """Validate and save the desired state (a git commit when the folder is a repository)."""
        try:
            commit = desired.save(data_dir, body.yaml, body.message)
        except desired.DesiredError as exc:
            return _error(422, "invalid", str(exc))
        runner.evaluate()
        return {"saved": True, "commit": commit}

    @api.post("/desired/import/{site_id}", response_model=None)
    def import_site(site_id: str) -> dict[str, str] | JSONResponse:
        """The observed state of a site as desired-state YAML, to start from what exists."""
        if site_id not in {s.id for s in store.sites()}:
            return _error(404, "not_found", "No such site.")
        return {"yaml": desired.dump(desired.from_network(runner.network(), site_id))}

    @api.get("/secrets")
    def secrets() -> list[str]:
        """Names of stored secrets (values are never returned)."""
        return store.secret_names()

    @api.put("/secrets/{name}", response_model=None)
    def put_secret(name: str, body: SecretBody) -> dict[str, bool] | JSONResponse:
        """Store a secret (encrypted), e.g. a Wi-Fi passphrase named in the desired state."""
        import re

        if not re.match(SECRET_NAME, name):
            return _error(422, "invalid", "Secret names use letters, digits, '.', '_' and '-'.")
        store.set_secret(name, body.value)
        return {"stored": True}

    @api.delete("/secrets/{name}", status_code=204)
    def delete_secret(name: str) -> None:
        """Delete a secret."""
        store.delete_secret(name)

    return api
