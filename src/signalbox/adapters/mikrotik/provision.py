"""Automatic setup of a MikroTik router through the REST API as admin (#231).

The steps of docs/adapters/mikrotik.md: the group ``signalbox-read`` (policies ``read``,
``api``, ``rest-api``, everything else off), or ``signalbox-write`` when changes are allowed
(``write`` and ``sensitive`` too), and a user with a generated password in it. The REST API
needs ``www-ssl`` with a certificate first (setup guide, "HTTPS with a certificate"); the admin
password is only sent to the certificate the user confirmed (:class:`DeviceHttp`).
Removal deletes the user, and its group when no other user is in it.

*Fix it* (#267, docs/adr/0012), :class:`MikrotikFix`: ``policies`` (REST as admin) adds the
policies of the guide that the group of the stored user lacks; ``rest-service`` (SSH as admin,
because the REST API is what is down) creates the local CA and server certificate of the guide
when ``www-ssl`` has none, enables ``www-ssl`` and adds the address Signalbox connects from to
its ``address`` list when the list excludes it. Network settings are never touched.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import quote, urlsplit

from pydantic import SecretStr

from signalbox.adapters import (
    AdapterError,
    AuthFailed,
    RemedyRequest,
    SetupPlan,
    SetupRequest,
    SetupResult,
    UntrustedCertificate,
    UntrustedHostKey,
)
from signalbox.adapters.https import DeviceHttp, device_url
from signalbox.adapters.mikrotik import REMEDIES, get_menu, ros_error
from signalbox.adapters.provision import Redactor, Step, new_password, plan_steps, run_steps
from signalbox.adapters.ssh import PinnedSsh

#: After creating or changing the user RouterOS applies it a moment later (#520): the first
#: login with it can answer 401. Setup waits up to this long (seconds) for the new login.
LOGIN_WAIT = 20.0
LOGIN_POLL = 0.5

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
            raise AdapterError(
                "give the router's address first", message_id="mikrotik.addressFirst"
            )
        try:
            self.url = device_url(raw)
        except ValueError as exc:
            raise AdapterError(
                str(exc), message_id="mikrotik.badAddress", params={"detail": str(exc)}
            ) from None
        if not self.url.startswith("https://"):
            raise AdapterError(
                "the automatic setup sends the admin password only over https",
                message_id="mikrotik.setupHttpsOnly",
            )
        self.login = str(request.config.get("username") or "signalbox").strip()
        if not LOGIN_NAME.match(self.login):
            raise AdapterError(
                f"not a RouterOS user name: {self.login!r}",
                message_id="mikrotik.badUserName",
                params={"login": repr(self.login)},
            )
        if self.login in ("admin", request.admin_user):
            raise AdapterError(
                "the user to set up must not be the admin login: give Signalbox a user of its "
                "own, for example signalbox",
                message_id="mikrotik.userIsAdmin",
            )
        self.group, self.policy = GROUPS[request.allow_writes]
        if request.traces:  # path traces (#253): traceroute needs the policy test
            self.policy = self.policy.replace("!test", "test")
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
            raise AdapterError(
                "/rest/user: unexpected answer", message_id="mikrotik.usersUnexpected"
            )
        return (
            [u for u in users if isinstance(u, dict)],
            [g for g in groups if isinstance(g, dict)],
        )

    def _applied(self, http: DeviceHttp, call: Callable[[], Awaitable[str | None]]) -> Any:
        """``call``, then wait until the new login works (bounded retry on 401 with the password
        just set, nothing else: another status or an unreachable router ends the wait at once)."""

        async def run() -> str | None:
            await call()
            fresh = DeviceHttp(
                self.url,
                pinned_fingerprint=http.fingerprint or self.request.trust,
                timeout=self.request.timeout,
                auth=(self.login, self.password),
            )
            deadline = time.monotonic() + LOGIN_WAIT
            try:
                while True:
                    try:
                        await fresh.request("GET", "/rest/system/identity")
                        return None
                    except AuthFailed:
                        if time.monotonic() >= deadline:
                            raise AdapterError(
                                f"the router still refuses the new user {self.login} after "
                                f"{LOGIN_WAIT:g} s (HTTP 401)",
                                message_id="mikrotik.newLoginRefused",
                                params={"login": self.login, "seconds": f"{LOGIN_WAIT:g}"},
                            ) from None
                        await asyncio.sleep(LOGIN_POLL)
            finally:
                await fresh.close()

        return run

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
                action=self._applied(
                    http,
                    self._call(
                        http, "PUT", "/rest/user", {"name": self.login, "comment": COMMENT, **body}
                    ),
                ),
                note="the password is stored encrypted in Signalbox and never shown",
            )
        else:
            uid = quote(str(user.get(".id", "")), safe="*")
            user_step = Step(
                "user",
                f"Update the user {self.login}: group {self.group}, a new generated password",
                f"PATCH /rest/user/{user.get('.id')} group={self.group} password=***",
                action=self._applied(http, self._call(http, "PATCH", f"/rest/user/{uid}", body)),
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
                    http, "DELETE", f"/rest/user/{quote(str((user or {}).get('.id', '')), '*')}"
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
            raise exc.redacted(self.redact) from None
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
            raise exc.redacted(self.redact) from None
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


# --- fix it (#267) ------------------------------------------------------------------------------

#: Every policy the guide lists, to spell the ones a group lacks as ``!x``.
ALL_POLICIES = (
    *("read", "write", "api", "rest-api", "sensitive", "policy", "password", "reboot"),
    *("test", "sniff", "romon", "local", "telnet", "ssh", "ftp", "winbox", "web"),
)
FIX_READ = ("read", "api", "rest-api")
FIX_WRITE = ("write", "sensitive")
CA = "signalbox-ca"
SERVER = "signalbox-www"
#: The commands of docs/adapters/mikrotik.md, "HTTPS with a certificate".
CA_COMMANDS = (
    f"/certificate add name={CA} common-name={CA} days-valid=3650 key-usage=key-cert-sign,crl-sign",
    f"/certificate sign {CA}",
)
SERVER_COMMANDS = (
    f"/certificate add name={SERVER} common-name=router days-valid=3650 "
    "key-usage=digital-signature,key-encipherment,tls-server",
    f"/certificate sign {SERVER} ca={CA}",
)
SSH_COMPARE = (
    "On the router: /ip ssh export-host-key, then ssh-keygen -lf on the exported public key "
    "(the file is in /file), or the fingerprint your SSH client shows for it."
)
ROS_FAILURE = re.compile(
    r"failure:|syntax error|bad command name|expected end of command|invalid value|"
    r"no such item|input does not match|ambiguous value|missing value|not enough permissions"
)


def policy_string(policies: set[str]) -> str:
    """``read,api,!write,...``: the granted ones, every other known policy denied."""
    on = [p for p in ALL_POLICIES if p in policies]
    off = [f"!{p}" for p in ALL_POLICIES if p not in policies]
    return ",".join(on + off)


def _word(value: str) -> str:
    text = value.strip()
    return "" if text in ("none", "*0") else text


def _net_ok(text: str) -> bool:
    try:
        ip_network(text, strict=False)
    except ValueError:
        return False
    return True


class MikrotikFix:
    """*Fix it* on a stored router with the admin login (never stored)."""

    def __init__(self, request: RemedyRequest) -> None:
        if request.remedy not in {r.id for r in REMEDIES}:
            raise AdapterError(
                f"MikroTik has no remedy {request.remedy!r}",
                message_id="mikrotik.noRemedy",
                params={"remedy": repr(request.remedy)},
            )
        self.fix = request
        self.redact = Redactor()
        self.redact.add(request.admin_secret.get_secret_value())
        for secret in request.secrets.values():
            self.redact.add(secret.get_secret_value())
        raw = str(request.config.get("url") or "").strip()
        if not raw:
            raise AdapterError(
                "give the router's address first", message_id="mikrotik.addressFirst"
            )
        try:
            self.url = device_url(raw)
        except ValueError as exc:
            raise AdapterError(
                str(exc), message_id="mikrotik.badAddress", params={"detail": str(exc)}
            ) from None
        self.host = urlsplit(self.url).hostname or ""
        self.login = str(request.config.get("username") or "signalbox").strip()

    async def plan(self) -> SetupPlan:
        result = await (
            self._ssh(False) if self.fix.remedy == "rest-service" else self._rest(False)
        )
        assert isinstance(result, SetupPlan)
        return result

    async def apply(self) -> SetupResult:
        result = await (self._ssh(True) if self.fix.remedy == "rest-service" else self._rest(True))
        assert isinstance(result, SetupResult)
        return result

    # --- policies (REST) -----------------------------------------------------------------

    def _http(self) -> DeviceHttp:
        if not self.url.startswith("https://"):
            raise AdapterError(
                "Fix it sends the admin password only over https",
                message_id="mikrotik.fixHttpsOnly",
            )
        return DeviceHttp(
            self.url,
            pinned_fingerprint=self.fix.trust,
            timeout=self.fix.timeout,
            auth=(self.fix.admin_user, self.fix.admin_secret.get_secret_value()),
        )

    def policy_steps(
        self, http: DeviceHttp, users: list[dict[str, Any]], groups: list[dict[str, Any]]
    ) -> list[Step]:
        user = next((u for u in users if u.get("name") == self.login), None)
        if user is None:
            raise AdapterError(
                f"the router has no user {self.login!r}",
                fix="Set the device up again (device settings: Set up automatically, or the "
                "setup guide): Fix it only repairs the policies of an existing user's group.",
                message_id="mikrotik.noUser",
                fix_id="mikrotik.noUser.fix",
                params={"login": repr(self.login)},
            )
        name = str(user.get("group") or "")
        group = next((g for g in groups if g.get("name") == name), None)
        if not name.startswith("signalbox") or group is None:
            raise AdapterError(
                f"the user {self.login} is in the group {name!r}; Signalbox changes only a "
                "group of its own (signalbox-read, signalbox-write)",
                fix="Give the group the policies read, api and rest-api by hand, as the setup "
                "guide shows.",
                message_id="mikrotik.foreignGroup",
                fix_id="mikrotik.foreignGroup.fix",
                params={"login": self.login, "group": repr(name)},
            )
        wanted = {
            *FIX_READ,
            *(FIX_WRITE if self.fix.allow_writes else ()),
            *(("test",) if self.fix.traces else ()),  # path traces (#253)
        }
        have = granted(group.get("policy"))
        missing = [p for p in ALL_POLICIES if p in wanted and p not in have]
        policy = policy_string(have | wanted)
        gid = str(group.get(".id", ""))
        what = "with write access" if self.fix.allow_writes else "read-only"
        return [
            Step(
                "policies",
                f"Add the missing policies of the setup guide to the group {name} ({what})",
                f"PATCH /rest/user/group/{gid} policy={policy}\n"
                + "\n".join(f"+ {p}" for p in missing),
                needed=bool(missing),
                action=self._patch(http, f"/rest/user/group/{quote(gid, safe='*')}", policy),
                note="" if missing else "it has every documented policy",
            )
        ]

    def _patch(
        self, http: DeviceHttp, path: str, policy: str
    ) -> Callable[[], Awaitable[str | None]]:
        async def run() -> str | None:
            response = await http.request("PATCH", path, accept=(400, 500), json={"policy": policy})
            if response.status_code >= 400:
                raise ros_error(path, response)
            return None

        return run

    async def _rest(self, apply: bool) -> SetupPlan | SetupResult:
        http = self._http()
        try:
            users = await get_menu(http, "/rest/user")
            groups = await get_menu(http, "/rest/user/group")
            if not isinstance(users, list) or not isinstance(groups, list):
                raise AdapterError(
                    "/rest/user: unexpected answer", message_id="mikrotik.usersUnexpected"
                )
            steps = self.policy_steps(
                http,
                [u for u in users if isinstance(u, dict)],
                [g for g in groups if isinstance(g, dict)],
            )
            if apply:
                ok, done = await run_steps(steps, self.redact)
                return SetupResult(ok=ok, steps=done)
            reports = plan_steps(steps, self.redact)
        except UntrustedCertificate as exc:
            if apply:
                raise
            return SetupPlan(
                fingerprint=exc.fingerprint,
                fingerprint_kind="certificate",
                trusted=False,
                compare=COMPARE,
            )
        except AdapterError as exc:
            raise exc.redacted(self.redact) from None
        finally:
            await http.close()
        return SetupPlan(
            fingerprint=http.fingerprint or "",
            fingerprint_kind="certificate",
            trusted=True,
            compare=COMPARE,
            steps=reports,
        )

    # --- the REST service (SSH) ------------------------------------------------------------

    def _ssh_client(self) -> PinnedSsh:
        return PinnedSsh(
            self.host,
            self.fix.port or 22,
            self.fix.admin_user,
            self.fix.admin_secret.get_secret_value(),
            self.fix.trust,
            self.fix.timeout,
        )

    async def _cli(self, ssh: PinnedSsh, command: str, timeout: float | None = None) -> str:
        res = await ssh.command(command, timeout=timeout)
        text = res.text.strip()
        if res.code != 0 or ROS_FAILURE.search(text) or ROS_FAILURE.search(res.err):
            detail = (res.err or text)[:300]
            raise AdapterError(
                f"{command}: {detail}",
                message_id="mikrotik.commandFailed",
                params={"command": command, "detail": detail},
            )
        return text

    async def _available(self, ssh: PinnedSsh, get: Callable[[str], str]) -> str:
        """``available-from`` (RouterOS 7.25 calls ``address`` that), else ``address``."""
        try:
            return await self._cli(ssh, get("available-from"))
        except AdapterError:
            return await self._cli(ssh, get("address"))

    async def inspect(self, ssh: PinnedSsh) -> dict[str, Any]:
        def get(prop: str) -> str:
            return f":put [/ip service get www-ssl {prop}]"

        off = (await self._cli(ssh, get("disabled"))).lower()
        state: dict[str, Any] = {
            "disabled": off in ("true", "yes"),
            "address": [
                a for a in re.split(r"[,;\s]+", _word(await self._available(ssh, get))) if a
            ],
            "certificate": _word(await self._cli(ssh, get("certificate"))),
        }
        for key, name in (("ca", CA), ("server", SERVER)):
            found = await self._cli(ssh, f":put [:len [/certificate find where name={name}]]")
            state[key] = found.strip() not in ("", "0")
        active = await self._cli(ssh, "/user active print terse where via=ssh")
        mine = {
            m.group(1)
            for line in active.splitlines()
            if re.search(rf"\bname={re.escape(self.fix.admin_user)}\b", line)
            if (m := re.search(r"\baddress=([0-9a-fA-F:.]+)", line))
        }
        state["source"] = mine.pop() if len(mine) == 1 else None
        return state

    def ssh_steps(self, ssh: PinnedSsh, state: dict[str, Any]) -> list[Step]:
        steps: list[Step] = []
        long = max(180.0, self.fix.timeout)
        has_cert = bool(state["certificate"])
        if not has_cert:
            for sid, title, cmds, present in (
                (
                    "ca",
                    f"Create the local CA {CA} (as in the setup guide)",
                    CA_COMMANDS,
                    state["ca"],
                ),
                (
                    "server-certificate",
                    f"Create the server certificate {SERVER}, signed by {CA}",
                    SERVER_COMMANDS,
                    state["server"],
                ),
            ):
                steps.append(
                    Step(
                        sid,
                        title,
                        "\n".join(cmds),
                        needed=not present,
                        action=self._run(ssh, list(cmds), long),
                        note="exists already" if present else "",
                    )
                )
        else:
            steps.append(
                Step(
                    "certificate",
                    "Certificate of www-ssl",
                    "",
                    needed=False,
                    note=f"www-ssl uses {state['certificate']}",
                )
            )
        address = list(state["address"])
        source = state["source"]
        if address and source is None:
            raise AdapterError(
                "cannot tell which address Signalbox connects from (the router lists none or "
                "several admin SSH sessions)",
                fix="Add Signalbox's address to /ip service www-ssl address by hand.",
                message_id="mikrotik.unknownSource",
                fix_id="mikrotik.unknownSource.fix",
            )
        excluded = bool(address) and not any(
            ip_address(source) in ip_network(a, strict=False) for a in address if _net_ok(a)
        )
        if excluded:
            address.append(f"{source}{'/128' if ':' in str(source) else '/32'}")
        sets = []
        if not has_cert:
            sets.append(f"certificate={SERVER}")
        if state["disabled"]:
            sets.append("disabled=no")
        if excluded:
            sets.append("address=" + ",".join(address))
        command = "/ip service set www-ssl " + " ".join(sets) if sets else ""
        detail = command
        if excluded:
            detail += f"\n(Signalbox connects from {source}; the other addresses stay)"
        steps.append(
            Step(
                "www-ssl",
                "Service www-ssl: "
                + ("change as below" if sets else "as the setup guide wants it"),
                detail,
                needed=bool(sets),
                action=self._run(ssh, [command]) if sets else None,
                note="" if sets else "enabled, with a certificate, reachable from this machine",
            )
        )
        steps.append(
            Step(
                "check",
                "Read www-ssl again",
                "",
                needed=bool(sets),
                action=self._check(ssh),
            )
        )
        return steps

    def _run(
        self, ssh: PinnedSsh, commands: list[str], timeout: float | None = None
    ) -> Callable[[], Awaitable[str | None]]:
        async def run() -> str | None:
            for command in commands:
                await self._cli(ssh, command, timeout)
            return None

        return run

    def _check(self, ssh: PinnedSsh) -> Callable[[], Awaitable[str | None]]:
        async def run() -> str | None:
            state = await self.inspect(ssh)
            if state["disabled"] or not state["certificate"]:
                raise AdapterError(
                    "www-ssl is still disabled or has no certificate",
                    message_id="mikrotik.wwwSslStillOff",
                )
            return "www-ssl is enabled with a certificate"

        return run

    async def _ssh(self, apply: bool) -> SetupPlan | SetupResult:
        try:
            async with self._ssh_client() as ssh:
                state = await self.inspect(ssh)
                steps = self.ssh_steps(ssh, state)
                fingerprint = ssh.fingerprint or ""
                if apply:
                    ok, done = await run_steps(steps, self.redact)
                    return SetupResult(ok=ok, steps=done)
                reports = plan_steps(steps, self.redact)
        except UntrustedHostKey as exc:
            if apply:
                raise
            return SetupPlan(
                fingerprint=exc.fingerprint,
                fingerprint_kind="ssh-host-key",
                trusted=False,
                compare=SSH_COMPARE,
            )
        except AdapterError as exc:
            raise exc.redacted(self.redact) from None
        return SetupPlan(
            fingerprint=fingerprint,
            fingerprint_kind="ssh-host-key",
            trusted=True,
            compare=SSH_COMPARE,
            steps=reports,
        )
