"""Automatic setup of an OPNsense firewall through its API with root's API key (#231).

The steps of docs/adapters/opnsense.md, "A least-privilege API user": a user ``signalbox``
with a scrambled password (no web interface login), no group memberships and exactly the
documented privileges (read, or read and write when changes are allowed), then a new API key
for it; keys of that user made before are deleted after the new one exists. Everything goes
through :class:`~signalbox.adapters.https.DeviceHttp`, so root's key is only sent to the
certificate the user confirmed.

The API of the user manager (``/api/auth/user/*``, OPNsense 24.7 and newer) is what the web
interface itself uses; see the "Automatic setup" section of the setup guide for what was
verified on the integration test image.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import quote

from pydantic import SecretStr

from signalbox.adapters import (
    AdapterError,
    SetupPlan,
    SetupRequest,
    SetupResult,
    UntrustedCertificate,
)
from signalbox.adapters.https import DeviceHttp, device_url
from signalbox.adapters.provision import Redactor, Step, plan_steps, run_steps

#: Privileges of the read user (docs: "A least-privilege API user"; the integration test image
#: gives its users exactly these, tools/integration/opnsense/privileges.json).
READ_PRIVILEGES: tuple[str, ...] = (
    "page-system-firmware-manualupdate",
    "page-status-interfaces",
    "page-interfaces-vlan-edit",
    "page-dhcp-kea-v4",
    "page-services-unbound",
    "page-diagnostics-arptable",
    "page-diagnostics-ndptable",
    "page-system-login-logout",
    "page-status-ntp",
)
#: Added for writing (docs: "A separate API user for writing").
WRITE_PRIVILEGES: tuple[str, ...] = (
    *READ_PRIVILEGES,
    "page-interfaces-assignnetworkports",
    "page-diagnostics-configurationhistory",
)

LOGIN = "signalbox"
DESCRIPTION = "Signalbox (set up automatically)"
USERS = "/api/auth/user/search"
KEYS = "/api/auth/user/search_api_key"
COMPARE = (
    "In the web interface, the browser's certificate details (SHA-256 fingerprint), or on the "
    "console: openssl x509 -in /var/etc/cert.pem -noout -fingerprint -sha256"
)
ALL = {"current": 1, "rowCount": -1, "searchPhrase": ""}


def _selected(value: Any) -> list[str]:
    """An OPNsense option list (``{"id": {"value": ..., "selected": 1}}``) or a CSV string."""
    if isinstance(value, dict):
        return sorted(k for k, v in value.items() if isinstance(v, dict) and v.get("selected"))
    if isinstance(value, str):
        return sorted(v for v in value.split(",") if v)
    return []


def _rows(answer: Any) -> list[dict[str, Any]]:
    rows = answer.get("rows") if isinstance(answer, dict) else None
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def _saved(path: str, answer: Any) -> dict[str, Any]:
    """An answer of an add/set/del action: ``{"result": "saved"}`` or validations."""
    done = ("saved", "deleted", "ok")
    if isinstance(answer, dict) and (
        str(answer.get("result", "")).lower() in done
        or str(answer.get("status", "")).lower() in done
    ):
        return answer
    if isinstance(answer, dict) and answer.get("validations"):
        problems = "; ".join(f"{k}: {v}" for k, v in sorted(answer["validations"].items()))
        raise AdapterError(f"{path}: refused: {problems}")
    result = answer.get("result") if isinstance(answer, dict) else None
    raise AdapterError(f"{path}: unexpected answer (result {result!r})")


class OpnsenseSetup:
    def __init__(self, request: SetupRequest) -> None:
        self.request = request
        self.redact = Redactor()
        self.redact.add(request.admin_user, request.admin_secret.get_secret_value())
        raw = str(request.config.get("url") or "").strip()
        if not raw:
            raise AdapterError("give the firewall's address first")
        try:
            self.url = device_url(raw)
        except ValueError as exc:
            raise AdapterError(str(exc)) from None
        if not self.url.startswith("https://"):
            raise AdapterError("the automatic setup sends root's API key only over https")
        self.privileges = sorted(WRITE_PRIVILEGES if request.allow_writes else READ_PRIVILEGES)
        self.key: dict[str, str] = {}

    def http(self) -> DeviceHttp:
        return DeviceHttp(
            self.url,
            pinned_fingerprint=self.request.trust,
            timeout=self.request.timeout,
            auth=(self.request.admin_user, self.request.admin_secret.get_secret_value()),
        )

    async def inspect(self, http: DeviceHttp) -> tuple[str | None, dict[str, Any]]:
        """The uuid and settings of the user ``signalbox`` (None, {}: there is none)."""
        await http.get_json("/api/core/firmware/status")
        for row in _rows(await http.post_json(USERS, ALL)):
            if row.get("name") == LOGIN:
                uuid = str(row.get("uuid", ""))
                answer = await http.get_json(f"/api/auth/user/get/{quote(uuid)}")
                user = answer.get("user") if isinstance(answer, dict) else None
                if not isinstance(user, dict):
                    raise AdapterError(f"/api/auth/user/get/{uuid}: unexpected answer")
                return uuid, user
        return None, {}

    def steps(self, http: DeviceHttp, uuid: str | None, user: dict[str, Any]) -> list[Step]:
        if user and str(user.get("scope", "user")) == "system":
            raise AdapterError(f"the user {LOGIN} is a system user; Signalbox leaves it alone")
        if self.request.remove:
            return [
                Step(
                    "user",
                    f"Delete the user {LOGIN} and its API keys",
                    f"POST /api/auth/user/del/{uuid}" if uuid else "",
                    needed=uuid is not None,
                    action=self._delete(http, uuid or ""),
                    note="" if uuid else f"there is no user {LOGIN}",
                )
            ]
        privs = _selected(user.get("priv"))
        groups = _selected(user.get("group_memberships"))
        what = "with write access" if self.request.allow_writes else "read-only"
        body = {
            "user": {
                "name": LOGIN,
                "descr": DESCRIPTION,
                "scrambled_password": "1",
                "priv": ",".join(self.privileges),
                "group_memberships": "",
            }
        }
        if uuid:
            change = []
            if privs != self.privileges:
                change.append(f"privileges: {', '.join(privs) or 'none'} → as documented")
            if groups:
                change.append(f"remove from the groups {', '.join(groups)}")
            user_step = Step(
                "user",
                f"Update the user {LOGIN} ({what})",
                f"POST /api/auth/user/set/{uuid}\n" + "\n".join(change),
                needed=bool(change),
                action=self._save(http, f"/api/auth/user/set/{quote(uuid)}", body),
                note="" if change else "privileges as documented, no groups",
            )
        else:
            user_step = Step(
                "user",
                f"Create the user {LOGIN} ({what}): scrambled password, no groups",
                "POST /api/auth/user/add",
                action=self._save(http, "/api/auth/user/add", body),
            )
        return [
            user_step,
            Step(
                "privileges",
                "Privileges (as in the setup guide)",
                "\n".join(self.privileges),
                needed=False,
                note="set with the user",
            ),
            Step(
                "key",
                f"Create a new API key for {LOGIN}; delete its older keys",
                f"POST /api/auth/user/add_api_key/{LOGIN}\nPOST /api/auth/user/del_api_key/<old>",
                action=self._new_key(http),
                note="the key is stored encrypted in Signalbox and never shown",
            ),
        ]

    def _save(
        self, http: DeviceHttp, path: str, body: dict[str, Any]
    ) -> Callable[[], Awaitable[str | None]]:
        async def run() -> str | None:
            _saved(path, await http.post_json(path, body))
            return None

        return run

    def _delete(self, http: DeviceHttp, uuid: str) -> Callable[[], Awaitable[str | None]]:
        async def run() -> str | None:
            path = f"/api/auth/user/del/{quote(uuid)}"
            _saved(path, await http.post_json(path, {}))
            return None

        return run

    def _new_key(self, http: DeviceHttp) -> Callable[[], Awaitable[str | None]]:
        async def run() -> str | None:
            path = f"/api/auth/user/add_api_key/{LOGIN}"
            answer = await http.post_json(path, {})
            key = answer.get("key") if isinstance(answer, dict) else None
            secret = answer.get("secret") if isinstance(answer, dict) else None
            if not (isinstance(key, str) and key and isinstance(secret, str) and secret):
                result = answer.get("result") if isinstance(answer, dict) else None
                raise AdapterError(f"{path}: no key in the answer (result {result!r})")
            self.redact.add(key, secret)
            self.key = {"key": key, "secret": secret}
            old = [
                str(r.get("id") or r.get("key"))
                for r in _rows(await http.post_json(KEYS, ALL))
                if LOGIN in (r.get("username"), r.get("user"), r.get("name"))
                and key not in (r.get("key"), r.get("id"))
                and (r.get("id") or r.get("key"))
            ]
            for ident in old:
                gone = f"/api/auth/user/del_api_key/{quote(ident, safe='=+/')}"
                _saved(gone, await http.post_json(gone, {}))
            return f"older keys deleted: {len(old)}" if old else None

        return run

    async def plan(self) -> SetupPlan:
        http = self.http()
        try:
            uuid, user = await self.inspect(http)
            steps = plan_steps(self.steps(http, uuid, user), self.redact)
        except UntrustedCertificate as exc:
            return SetupPlan(
                fingerprint=exc.fingerprint,
                fingerprint_kind="certificate",
                trusted=False,
                compare=COMPARE,
            )
        except AdapterError as exc:
            raise type(exc)(self.redact(str(exc)), fix=exc.fix) from None
        finally:
            await http.close()
        return SetupPlan(
            fingerprint=http.fingerprint or "",
            fingerprint_kind="certificate",
            trusted=True,
            compare=COMPARE,
            steps=steps,
        )

    async def apply(self) -> SetupResult:
        http = self.http()
        try:
            uuid, user = await self.inspect(http)
            ok, steps = await run_steps(self.steps(http, uuid, user), self.redact)
        except UntrustedCertificate:
            raise
        except AdapterError as exc:
            raise type(exc)(self.redact(str(exc)), fix=exc.fix) from None
        finally:
            await http.close()
        if self.request.remove or not ok:
            return SetupResult(ok=ok, steps=steps)
        return SetupResult(
            ok=True,
            steps=steps,
            settings={"url": self.url},
            secrets={
                "api_key": SecretStr(self.key["key"]),
                "api_secret": SecretStr(self.key["secret"]),
            },
            certificate=http.fingerprint,
        )
