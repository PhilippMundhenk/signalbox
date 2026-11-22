"""The user manager of the simulated OPNsense (``/api/auth/user/*``), for the setup (#231).

Answers like the MVC user controller of OPNsense 24.7 and newer as far as the automatic setup
uses it: ``search`` (grid rows), ``get/<uuid>`` (option lists with ``selected``), ``add``,
``set/<uuid>``, ``del/<uuid>``, ``add_api_key/<name>``, ``search_api_key`` and
``del_api_key/<id>``. Only root's key may call it; keys of other users answer 403 here (their
privileges do not include the user manager) and are accepted everywhere else.
"""

from __future__ import annotations

import secrets
import uuid as uuidlib
from dataclasses import dataclass, field
from typing import Any

#: The privileges the simulated firewall offers (a few more than Signalbox asks for).
PRIVILEGES = (
    "page-all",
    "page-system-firmware-manualupdate",
    "page-status-interfaces",
    "page-interfaces-vlan-edit",
    "page-dhcp-kea-v4",
    "page-services-unbound",
    "page-diagnostics-arptable",
    "page-diagnostics-ndptable",
    "page-system-login-logout",
    "page-status-ntp",
    "page-interfaces-assignnetworkports",
    "page-diagnostics-configurationhistory",
)
GROUPS = ("admins",)


def _options(names: tuple[str, ...], selected: list[str]) -> dict[str, Any]:
    return {n: {"value": n, "selected": int(n in selected)} for n in names}


@dataclass
class Users:
    users: list[dict[str, Any]] = field(
        default_factory=lambda: [
            {
                "uuid": "00000000-0000-4000-8000-000000000000",
                "name": "root",
                "scope": "system",
                "descr": "System Administrator",
                "priv": [],
                "groups": ["admins"],
            }
        ]
    )
    #: API keys: id, key, secret, username
    keys: list[dict[str, str]] = field(default_factory=list)
    #: answer add_api_key without a key (to test the error)
    keyless: bool = False

    def user_of(self, key: str, secret: str) -> str | None:
        for k in self.keys:
            if secrets.compare_digest(k["key"], key) and secrets.compare_digest(
                k["secret"], secret
            ):
                return k["username"]
        return None

    def answer(self, path: str, body: Any) -> Any:
        """Answer one request below /api/auth/user/ (None: not found)."""
        action, _, arg = path.removeprefix("/api/auth/user/").partition("/")
        body = body if isinstance(body, dict) else {}
        if action == "search":
            return {
                "rows": [{k: u[k] for k in ("uuid", "name", "scope", "descr")} for u in self.users],
                "total": len(self.users),
            }
        if action == "search_api_key":
            rows = [{"id": k["id"], "username": k["username"], "key": k["key"]} for k in self.keys]
            return {"rows": rows, "total": len(rows)}
        if action == "add_api_key":
            if self.keyless or not any(u["name"] == arg for u in self.users):
                return {"result": "failed"}
            key = {
                "id": secrets.token_urlsafe(12) + "+/=",
                "key": secrets.token_urlsafe(30),
                "secret": secrets.token_urlsafe(40),
                "username": arg,
            }
            self.keys.append(key)
            return {"result": "ok", "hostname": "signalbox-sim", **key}
        if action == "del_api_key":
            before = len(self.keys)
            self.keys = [k for k in self.keys if k["id"] != arg]
            return {"result": "deleted" if len(self.keys) < before else "failed"}
        user = next((u for u in self.users if u["uuid"] == arg), None)
        if action == "get":
            if user is None:
                return {}
            return {
                "user": {
                    "name": user["name"],
                    "scope": user["scope"],
                    "descr": user["descr"],
                    "priv": _options(PRIVILEGES, user["priv"]),
                    "group_memberships": _options(GROUPS, user["groups"]),
                }
            }
        if action in ("add", "set"):
            values = body.get("user") if isinstance(body.get("user"), dict) else {}
            if action == "set" and user is None:
                return {"result": "failed"}
            name = str(values.get("name") or (user or {}).get("name") or "")
            if not name:
                return {"result": "failed", "validations": {"user.name": "A name is required."}}
            if action == "add" and any(u["name"] == name for u in self.users):
                return {"result": "failed", "validations": {"user.name": "Name already exists."}}
            privs = [p for p in str(values.get("priv", "")).split(",") if p]
            unknown = [p for p in privs if p not in PRIVILEGES]
            if unknown:
                return {"result": "failed", "validations": {"user.priv": "Unknown option."}}
            if action == "add":
                user = {"uuid": str(uuidlib.uuid4()), "scope": "user", "priv": [], "groups": []}
                self.users.append(user)
            assert user is not None
            user.update(
                name=name,
                descr=str(values.get("descr", user.get("descr", ""))),
                priv=privs,
                groups=[g for g in str(values.get("group_memberships", "")).split(",") if g],
            )
            return {"result": "saved", "uuid": user["uuid"]}
        if action == "del":
            if user is None:
                return {"result": "failed"}
            self.users.remove(user)
            self.keys = [k for k in self.keys if k["username"] != user["name"]]
            return {"result": "deleted"}
        return None
