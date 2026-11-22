"""Out-of-process adapters (phase 4, #25).

A third-party integration can run as a separate program instead of inside Signalbox. Signalbox
starts the program for every request and talks one line of JSON each way over stdin/stdout:

- ``{"method": "manifest"}`` → ``{"result": {manifest}}`` (the config as JSON Schema)
- ``{"method": "observe", "context": {...}}`` → ``{"result": {snapshot}}`` or
  ``{"error": {"kind": "unreachable" | "auth" | "untrusted" | "error", "message": "...",
  "fingerprint": "..."}}``

The program gets only the settings of the device it reads (credentials included), no
environment variables except ``PATH``, and its working directory is a fresh temporary folder;
everything it returns is validated against the model before it is used. Programs written in
Python with the normal adapter API need one line: ``serve(MyAdapter)``.

Configured in ``signalbox.yaml``::

    plugins:
      remote_adapters:
        myrouter: ["/opt/signalbox-myrouter/bin/myrouter-adapter"]
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, ClassVar, TextIO

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, create_model

from signalbox.adapters import (
    API_VERSION,
    Adapter,
    AdapterConfig,
    AdapterContext,
    AdapterContractError,
    Capability,
    Manifest,
    SystemInfo,
    check_manifest,
)
from signalbox.model import DeviceRole, DeviceStatus, ReadError, Snapshot

MAX_ANSWER = 16 * 1024 * 1024


class RemoteError(AdapterContractError):
    """The program broke the protocol (no answer, bad JSON, wrong shape)."""


class RemoteManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    name: str
    version: str
    api_version: str
    vendor: str
    roles: list[DeviceRole]
    capabilities: list[Capability]
    description: str = ""
    #: JSON Schema of the settings: an object of string / integer / number / boolean
    #: properties; ``"format": "password"`` marks secrets.
    config_schema: dict[str, Any]


_TYPES: dict[str, type] = {"string": str, "integer": int, "number": float, "boolean": bool}


def config_model(adapter_id: str, schema: Mapping[str, Any]) -> type[AdapterConfig]:
    """A settings class from the program's JSON Schema (flat objects only)."""
    if schema.get("type") != "object":
        raise RemoteError(f"{adapter_id}: config_schema must be an object")
    required = set(schema.get("required", []))
    fields: dict[str, Any] = {}
    for name, prop in (schema.get("properties") or {}).items():
        if not isinstance(prop, dict) or prop.get("type") not in _TYPES:
            raise RemoteError(f"{adapter_id}: setting {name!r} needs a simple type")
        typ: Any = SecretStr if prop.get("format") == "password" else _TYPES[prop["type"]]
        desc = prop.get("description")
        if name in required:
            fields[name] = (typ, Field(description=desc))
        else:
            fields[name] = (typ | None, Field(prop.get("default"), description=desc))
    return create_model(
        f"{adapter_id.title().replace('-', '')}RemoteConfig", __base__=AdapterConfig, **fields
    )


async def _call(command: Sequence[str], request: dict[str, Any], timeout: float) -> Any:
    with tempfile.TemporaryDirectory(prefix="signalbox-remote-") as cwd:
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                limit=MAX_ANSWER,
            )
        except OSError as exc:
            raise RemoteError(f"cannot start {command[0]}: {exc}") from exc
        try:
            out, err = await asyncio.wait_for(
                proc.communicate((json.dumps(request) + "\n").encode()), timeout
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise
    line = out.decode(errors="replace").strip().splitlines()
    if not line:
        detail = err.decode(errors="replace").strip().splitlines()[-1:] or ["no output"]
        raise RemoteError(f"{command[0]} gave no answer (exit {proc.returncode}): {detail[0]}")
    try:
        answer = json.loads(line[-1])
    except json.JSONDecodeError as exc:
        raise RemoteError(f"{command[0]} answered with invalid JSON: {exc}") from exc
    if not isinstance(answer, dict) or ("result" not in answer and "error" not in answer):
        raise RemoteError(f"{command[0]} answered without result or error")
    return answer


def load_remote(adapter_id: str, command: Sequence[str], timeout: float = 30) -> type[Adapter]:
    """Ask the program for its manifest and build an adapter class that runs it."""
    answer = asyncio.run(_call(command, {"method": "manifest"}, timeout))
    if "error" in answer:
        raise RemoteError(f"{adapter_id}: manifest refused: {answer['error']}")
    try:
        rm = RemoteManifest.model_validate(answer["result"])
    except ValidationError as exc:
        raise RemoteError(f"{adapter_id}: invalid manifest: {exc}") from exc
    if rm.id != adapter_id:
        raise RemoteError(f"configured as {adapter_id!r} but the program says {rm.id!r}")
    manifest = Manifest(
        id=rm.id,
        name=rm.name,
        version=rm.version,
        api_version=rm.api_version,
        vendor=rm.vendor,
        roles=frozenset(rm.roles),
        capabilities=frozenset(rm.capabilities),
        config=config_model(rm.id, rm.config_schema),
        description=rm.description or f"runs out of process: {command[0]}",
    )
    check_manifest(manifest)
    return type(
        f"Remote{rm.id.title().replace('-', '')}Adapter",
        (RemoteAdapter,),
        {"manifest": manifest, "command": tuple(command)},
    )


class RemoteAdapter(Adapter):
    """Runs an adapter program for every observation (see the module documentation)."""

    command: ClassVar[tuple[str, ...]] = ()

    def __init__(self, context: AdapterContext) -> None:
        if not isinstance(context.config, self.manifest.config):
            raise AdapterContractError(f"{self.manifest.id}: wrong config type")
        self.context = context  # capabilities are implemented by the program

    async def read_system(self) -> SystemInfo:  # pragma: no cover - observe() is overridden
        raise NotImplementedError

    def _request(self) -> dict[str, Any]:
        ctx = self.context
        values = {
            k: v.get_secret_value() if isinstance(v, SecretStr) else v
            for k, v in ctx.config.model_dump().items()
        }
        return {
            "method": "observe",
            "context": {
                "site_id": ctx.site_id,
                "device_id": ctx.device_id,
                "device_name": ctx.device_name,
                "role": ctx.role.value,
                "config": values,
                "pinned_fingerprint": ctx.pinned_fingerprint,
                "timeout": ctx.timeout,
            },
        }

    async def observe(self) -> Snapshot:
        ctx = self.context
        try:
            answer = await _call(self.command, self._request(), ctx.timeout * 6)
        except TimeoutError:
            return self._failed(DeviceStatus.UNREACHABLE, "the adapter program did not answer")
        if "error" in answer:
            e = answer["error"] if isinstance(answer["error"], dict) else {}
            kind, message = e.get("kind"), str(e.get("message") or "error")
            if kind == "untrusted":
                self.presented_fingerprint = str(e.get("fingerprint") or "") or None
                return self._failed(DeviceStatus.UNTRUSTED, message)
            if kind == "auth":
                return self._failed(DeviceStatus.AUTH_FAILED, message)
            return self._failed(DeviceStatus.UNREACHABLE, message)
        try:
            snap = Snapshot.model_validate(answer["result"])
        except ValidationError as exc:
            raise RemoteError(f"{self.manifest.id}: invalid snapshot: {exc}") from exc
        dev = snap.device
        if dev.id != ctx.device_id or dev.site_id != ctx.site_id or dev.adapter != self.manifest.id:
            raise RemoteError(f"{self.manifest.id}: snapshot is for another device ({dev.id})")
        return snap

    def _failed(self, status: DeviceStatus, message: str) -> Snapshot:
        from signalbox.model import Device, Source

        now = datetime.now(UTC)
        ctx = self.context
        device = Device(
            id=ctx.device_id,
            site_id=ctx.site_id,
            name=ctx.device_name,
            role=ctx.role,
            adapter=self.manifest.id,
            source=Source(adapter=self.manifest.id, device_id=ctx.device_id),
            observed_at=now,
        )
        err = ReadError(device_id=ctx.device_id, capability="system", message=message)
        return Snapshot(device=device, observed_at=now, status=status, errors=[err])


# --- the program side -------------------------------------------------------------------------


def serve(cls: type[Adapter], stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    """Run a normal (in-process) adapter class as an out-of-process program."""
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    request = json.loads(stdin.readline() or "{}")
    m = cls.manifest

    def answer(data: dict[str, Any]) -> int:
        stdout.write(json.dumps(data) + "\n")
        stdout.flush()
        return 0

    if request.get("method") == "manifest":
        schema = m.config.model_json_schema()
        for name, info in m.config.model_fields.items():
            ann = info.annotation
            if ann is SecretStr or SecretStr in getattr(ann, "__args__", ()):
                schema["properties"][name] = {
                    "type": "string",
                    "format": "password",
                    "description": info.description,
                }
            elif "anyOf" in schema["properties"][name]:
                prop = schema["properties"][name]
                simple = [x for x in prop.pop("anyOf") if x.get("type") != "null"]
                prop.update(simple[0])
        return answer(
            {
                "result": {
                    "id": m.id,
                    "name": m.name,
                    "version": m.version,
                    "api_version": API_VERSION if m.api_version == API_VERSION else m.api_version,
                    "vendor": m.vendor,
                    "roles": sorted(r.value for r in m.roles),
                    "capabilities": sorted(c.value for c in m.capabilities),
                    "description": m.description,
                    "config_schema": {
                        "type": "object",
                        "properties": schema.get("properties", {}),
                        "required": schema.get("required", []),
                    },
                }
            }
        )
    if request.get("method") != "observe":
        return answer({"error": {"kind": "error", "message": "unknown method"}})
    c = request["context"]
    ctx = AdapterContext(
        site_id=c["site_id"],
        device_id=c["device_id"],
        device_name=c["device_name"],
        role=DeviceRole(c["role"]),
        config=m.config.model_validate(c["config"]),
        pinned_fingerprint=c.get("pinned_fingerprint"),
        timeout=float(c.get("timeout", 10)),
    )

    async def run() -> dict[str, Any]:
        adapter = cls(ctx)
        try:
            snap = await adapter.observe()
        finally:
            await adapter.close()
        if snap.status is DeviceStatus.UNTRUSTED:
            return {
                "error": {
                    "kind": "untrusted",
                    "message": snap.errors[0].message,
                    "fingerprint": adapter.presented_fingerprint,
                }
            }
        if snap.status is DeviceStatus.AUTH_FAILED:
            return {"error": {"kind": "auth", "message": snap.errors[0].message}}
        if snap.status is DeviceStatus.UNREACHABLE:
            return {"error": {"kind": "unreachable", "message": snap.errors[0].message}}
        return {"result": snap.model_dump(mode="json")}

    return answer(asyncio.run(run()))
