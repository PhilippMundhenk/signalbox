"""Automatic setup of a MikroTik router through the REST API as admin (#231).

The steps of docs/adapters/mikrotik.md: the group ``signalbox-read`` (policies ``read``,
``api``, ``rest-api``, everything else off), or ``signalbox-write`` when changes are allowed
(``write`` and ``sensitive`` too), and a user with a generated password in it. The REST API
needs ``www-ssl`` with a certificate first (setup guide, "HTTPS with a certificate"); the admin
password is only sent to the certificate the user confirmed (:class:`DeviceHttp`).
Removal deletes the user, and its group when no other user is in it.
"""

from __future__ import annotations

import re
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
from signalbox.adapters.mikrotik import get_menu, ros_error
from signalbox.adapters.provision import Redactor, Step, new_password, plan_steps, run_steps

#: The policies of the two groups, exactly as docs/adapters/mikrotik.md lists them.
READ_POLICY = (
    "read,api,rest-api,!write,!policy,!password,!sensitive,!reboot,!test,!sniff,!romon,!local,"
    "!telnet,!ssh,!ftp,!winbox,!web"
)
WRITE_POLICY = (
    "read,write,api,rest-api,sensitive,!policy,!password,!reboot,!test,!sniff,!romon,!local,"
    "!telnet,!ssh,!ftp,!winbox,!web"
)
GROUPS = {False: ("signalbox-read", READ_POLICY), True: ("signalbox-write", WRITE_POLICY)}
LOGIN_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,31}$")
COMMENT = "Signalbox (set up automatically)"
COMPARE = "On the router: /certificate print detail where name=<the www-ssl certificate>"


def granted(policy: Any) -> set[str]:
    """The policies a group has (``read,api,!write``: read and api)."""
    return {p for p in str(policy or "").split(",") if p and not p.startswith("!")}


class MikrotikSetup:
    def __init__(self, request: SetupRequest) -> None:
        self.request = request
        self.redact = Redactor()
        self.redact.add(request.admin_secret.get_secret_value())
        raw = str(request.config.get("url") or "").strip()
        if not raw:
            raise AdapterError("give the router's address first")
        try:
            self.url = device_url(raw)
        except ValueError as exc:
            raise AdapterError(str(exc)) from None
        if not self.url.startswith("https://"):
            raise AdapterError("the automatic setup sends the admin password only over https")
        self.login = str(request.config.get("username") or "signalbox").strip()
        if not LOGIN_NAME.match(self.login):
            raise AdapterError(f"not a RouterOS user name: {self.login!r}")
        if self.login in ("admin", request.admin_user):
            raise AdapterError(
                "the user to set up must not be the admin login: give Signalbox a user of its "
                "own, for example signalbox"
            )
        self.group, self.policy = GROUPS[request.allow_writes]
        self.password = new_password()
        self.redact.add(self.password)

    def http(self) -> DeviceHttp:
        return DeviceHttp(
            self.url,
            pinned_fingerprint=self.request.trust,
            timeout=self.request.timeout,
            auth=(self.request.admin_user, self.request.admin_secret.get_secret_value()),
        )

    async def inspect(self, http: DeviceHttp) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        users = await get_menu(http, "/rest/user")
        groups = await get_menu(http, "/rest/user/group")
        if not isinstance(users, list) or not isinstance(groups, list):
            raise AdapterError("/rest/user: unexpected answer")
        return (
            [u for u in users if isinstance(u, dict)],
            [g for g in groups if isinstance(g, dict)],
        )

    def _call(
        self, http: DeviceHttp, method: str, path: str, body: dict[str, Any] | None = None
    ) -> Callable[[], Awaitable[str | None]]:
        async def run() -> str | None:
            kw: dict[str, Any] = {} if body is None else {"json": body}
            response = await http.request(method, path, accept=(400, 500), **kw)
            if response.status_code >= 400:
                raise ros_error(path, response)
            return None

        return run

    def steps(
        self, http: DeviceHttp, users: list[dict[str, Any]], groups: list[dict[str, Any]]
    ) -> list[Step]:
        user = next((u for u in users if u.get("name") == self.login), None)
        if self.request.remove:
            return self.removal(http, user, users, groups)
        group = next((g for g in groups if g.get("name") == self.group), None)
        wanted = granted(self.policy)
        what = "with write access" if self.request.allow_writes else "read-only"
        if group is None:
            group_step = Step(
                "group",
                f"Create the user group {self.group} ({what})",
                f"PUT /rest/user/group name={self.group} policy={self.policy}",
                action=self._call(
                    http,
                    "PUT",
                    "/rest/user/group",
                    {"name": self.group, "policy": self.policy, "comment": COMMENT},
                ),
            )
        else:
            same = granted(group.get("policy")) == wanted
            gid = quote(str(group.get(".id", "")), safe="*")
            group_step = Step(
                "group",
                f"User group {self.group} ({what})",
                f"PATCH /rest/user/group/{group.get('.id')} policy={self.policy}",
                needed=not same,
                action=self._call(
                    http, "PATCH", f"/rest/user/group/{gid}", {"policy": self.policy}
                ),
                note="policies as in the setup guide" if same else "",
            )
        body = {"group": self.group, "password": self.password}
        if user is None:
            user_step = Step(
                "user",
                f"Create the user {self.login} in {self.group} with a generated password",
                f"PUT /rest/user name={self.login} group={self.group} password=***",
                action=self._call(
                    http, "PUT", "/rest/user", {"name": self.login, "comment": COMMENT, **body}
                ),
                note="the password is stored encrypted in Signalbox and never shown",
            )
        else:
            uid = quote(str(user.get(".id", "")), safe="*")
            user_step = Step(
                "user",
                f"Update the user {self.login}: group {self.group}, a new generated password",
                f"PATCH /rest/user/{user.get('.id')} group={self.group} password=***",
                action=self._call(http, "PATCH", f"/rest/user/{uid}", body),
                note="the password is stored encrypted in Signalbox and never shown",
            )
        return [group_step, user_step]

    def removal(
        self,
        http: DeviceHttp,
        user: dict[str, Any] | None,
        users: list[dict[str, Any]],
        groups: list[dict[str, Any]],
    ) -> list[Step]:
        steps = [
            Step(
                "user",
                f"Delete the user {self.login}",
                f"DELETE /rest/user/{user.get('.id')}" if user else "",
                needed=user is not None,
                action=self._call(
                    http, "DELETE", f"/rest/user/{quote(str((user or {}).get('.id', '')), safe='')}"
                ),
                note="" if user else f"there is no user {self.login}",
            )
        ]
        for name, _ in GROUPS.values():
            group = next((g for g in groups if g.get("name") == name), None)
            others = sorted(
                str(u.get("name"))
                for u in users
                if u.get("group") == name and u.get("name") != self.login
            )
            gid = quote(str((group or {}).get(".id", "")), safe="*")
            if group is None:
                note = "there is no such group"
            elif others:
                note = f"kept: {', '.join(others)} in it"
            else:
                note = ""
            steps.append(
                Step(
                    f"group-{name}",
                    f"Delete the user group {name}",
                    f"DELETE /rest/user/group/{(group or {}).get('.id')}" if not note else "",
                    needed=not note,
                    action=self._call(http, "DELETE", f"/rest/user/group/{gid}"),
                    note=note,
                )
            )
        return steps

    async def plan(self) -> SetupPlan:
        http = self.http()
        try:
            users, groups = await self.inspect(http)
            steps = plan_steps(self.steps(http, users, groups), self.redact)
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
            users, groups = await self.inspect(http)
            ok, steps = await run_steps(self.steps(http, users, groups), self.redact)
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
            settings={"url": self.url, "username": self.login},
            secrets={"password": SecretStr(self.password)},
            certificate=http.fingerprint,
        )
