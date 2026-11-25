"""Automatic setup of an EdgeRouter (EdgeOS) or VyOS router over SSH (#495, docs/adr/0009).

Optional, only on an explicit start and confirmation: the same result as the commands of the
setup guide. With an admin login (password over SSH) it creates the user ``signalbox`` with an
ed25519 key generated here (only the public half is sent) and no password. The version is read
before the plan is built, because the level of the user depends on it:

- EdgeOS 1.x/2.x and VyOS up to 1.3: ``level operator``, which may run ``show`` commands and
  change nothing.
- VyOS 1.4 and newer have no user levels (every local user is a full administrator). The user is
  then created without a level, and the plan says so in a step of its own: full rights, key-only
  login, and how to narrow it down (docs/adapters/edgeos.md, *Restricting the login on VyOS 1.4
  and newer*). Whether the level exists is checked on the router (the template of the option),
  so a 1.4 build that still has levels gets ``level operator``.

The configuration commands run as a ``vbash`` script (``commit`` and ``save`` at the end); the
router's own answer is searched for the messages of a refused command, because the script's exit
status does not tell. The host key confirmed for the admin login is pinned for reading.

Removal deletes the user (only if it is operator level where levels exist).
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import asyncssh
from pydantic import SecretStr

from signalbox.adapters import (
    AdapterError,
    PreviewStep,
    SetupPlan,
    SetupRequest,
    SetupResult,
    UntrustedHostKey,
)
from signalbox.adapters.edgeos import parse
from signalbox.adapters.edgeos.collect import WRAPPER, split
from signalbox.adapters.provision import Redactor, Step, plan_steps, run_steps
from signalbox.adapters.ssh import PinnedSsh, sha256_hex

LOGIN_NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,30}$")
#: Logins Signalbox never sets up: the usual defaults and system accounts.
REFUSED = frozenset({"root", "vyos", "ubnt", "admin", "operator", "daemon", "nobody"})
KEY_COMMENT = "signalbox"
COMPARE = (
    "On the router: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub prints the fingerprint "
    "(or the _ecdsa_ / _rsa_ key)."
)
#: Where the configuration template of the user level lives (EdgeOS, VyOS up to 1.3; present on
#: builds of 1.4 and newer only when they still have levels).
LEVEL_TEMPLATE = "/opt/vyatta/share/vyatta-cfg/templates/system/login/user/node.tag/level"
#: What the router prints when a configuration command or the commit is refused.
CONFIG_ERROR = re.compile(
    r"Commit failed|Set failed|Delete failed|Invalid command|is not valid|Configuration path.*not "
    r"valid|\[ .* \] failed|Traceback|ConfigError|Failed to commit",
    re.I,
)

#: The plain statement of the plan on VyOS without levels (shown in the plan and the result).
FULL_RIGHTS = (
    "{version} has no read-only login level: the user {login} is created WITHOUT one, so it has "
    "the full rights of an administrator. It logs in with the key only (no password). Narrow it "
    "down afterwards if you want (docs/adapters/edgeos.md)."
)


def _q(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


@dataclass
class DeviceState:
    version: parse.Version
    #: the user exists, and its level (None: none set)
    exists: bool
    level: str | None
    #: the configuration knows the option ``level`` (checked on the router)
    has_level: bool

    @property
    def levels(self) -> bool:
        """Whether the user can be created with ``level operator``."""
        v = self.version
        if v.vyos and v.at_least(1, 4):
            return self.has_level
        return True


class EdgeosSetup:
    def __init__(self, request: SetupRequest) -> None:
        self.request = request
        self.redact = Redactor()
        self.secret = request.admin_secret.get_secret_value()
        self.redact.add(self.secret)
        host = str(request.config.get("host") or "").strip()
        for prefix in ("ssh://", "https://", "http://"):
            host = host.removeprefix(prefix)
        self.host = host.split("/", 1)[0]
        if not self.host:
            raise AdapterError("give the router's address first", message_id="edgeos.addressNeeded")
        self.port = request.port or int(str(request.config.get("port") or 22))
        self.login = str(request.config.get("username") or "signalbox").strip()
        if not LOGIN_NAME.match(self.login):
            raise AdapterError(
                "the login to set up must be lower-case letters, digits, - and _ "
                f"(not {self.login!r})",
                message_id="edgeos.loginName",
                params={"login": repr(self.login)},
            )
        if self.login in REFUSED or self.login == request.admin_user:
            raise AdapterError(
                "the login to set up must not be the admin login or a default account: give "
                "Signalbox a login of its own, for example signalbox",
                message_id="edgeos.loginIsAdmin",
            )
        self.key = asyncssh.generate_private_key("ssh-ed25519", comment=KEY_COMMENT)
        self.private = self.key.export_private_key().decode()
        self.public = self.key.export_public_key("openssh").decode().strip()
        self.redact.add(self.private)

    def ssh(self) -> PinnedSsh:
        return PinnedSsh(
            self.host,
            self.port,
            self.request.admin_user,
            self.secret,
            self.request.trust,
            self.request.timeout,
        )

    async def inspect(self, ssh: PinnedSsh) -> DeviceState:
        script = (
            "# signalbox-setup: inspect\n"
            "export LC_ALL=C PATH=/opt/vyatta/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            f"W={WRAPPER}\n"
            '[ -x "$W" ] || { echo "@@end"; exit 0; }\n'
            'echo @@version; "$W" show version 2>/dev/null\n'
            f"echo @@level; [ -d {LEVEL_TEMPLATE} ] && echo yes\n"
            f"U={_q(self.login)}\n"
            "P=\"^set system login user '?$U'? \"\n"
            'echo @@user; "$W" show configuration commands 2>/dev/null | grep -E "${P}level "\n'
            'echo @@exists; "$W" show configuration commands 2>/dev/null | grep -c -E "$P"\n'
            "echo @@end\n"
        )
        res = await ssh.run(script)
        answer = split(res.text)
        if not answer.complete() or not answer.lines("version"):
            detail = self.redact((res.err or res.text).strip())[:300]
            raise AdapterError(
                f"the device did not answer like EdgeOS or VyOS: {detail}",
                message_id="edgeos.notEdgeos",
                params={"detail": detail},
            )
        version = parse.version(answer)
        level_line = " ".join(answer.lines("user")).split()
        count = " ".join(answer.lines("exists")).strip()
        return DeviceState(
            version=version,
            exists=count.isdigit() and int(count) > 0,
            level=level_line[-1].strip("'") if level_line else None,
            has_level="yes" in " ".join(answer.lines("level")).split(),
        )

    def _script(self, commands: list[str]) -> str:
        body = "\n".join(
            [
                "source /opt/vyatta/etc/functions/script-template",
                "configure",
                *commands,
                "commit",
                "save",
                "exit",
            ]
        )
        return (
            "# signalbox-setup: configure\n"
            "T=$(mktemp)\n"
            "cat > \"$T\" <<'SIGNALBOX'\n" + body + "\nSIGNALBOX\n"
            'vbash "$T" </dev/null 2>&1\n'
            'rm -f "$T"\n'
        )

    def _action(self, ssh: PinnedSsh, commands: list[str]) -> Callable[[], Awaitable[str | None]]:
        script = self._script(commands)

        async def act() -> str | None:
            res = await ssh.run(script, timeout=max(120.0, self.request.timeout))
            text = res.text + res.err
            if CONFIG_ERROR.search(text):
                tail = self.redact(text.strip()[-400:])
                raise AdapterError(
                    f"the router refused the configuration: {tail}",
                    message_id="edgeos.stepFailed",
                    params={"detail": tail},
                )
            return None

        return act

    def steps(self, ssh: PinnedSsh, state: DeviceState, fingerprint: str) -> list[Step]:
        if self.request.remove:
            return self.removal(ssh, state)
        login, v = _q(self.login), state.version
        if state.exists and state.level is not None and state.level != "operator":
            raise AdapterError(
                f"the user {self.login} exists with the level {state.level}: Signalbox's login "
                "must not have more than read access; choose another name",
                message_id="edgeos.loginPrivileged",
                params={"login": self.login, "level": state.level},
            )
        base = f"set system login user {login}"
        user = [f"{base} full-name {_q('Signalbox (reads the configuration)')}"]
        if state.levels:
            user.append(f"{base} level operator")
        key = [
            f"{base} authentication public-keys {KEY_COMMENT} type ssh-ed25519",
            f"{base} authentication public-keys {KEY_COMMENT} key {_q(self.public.split()[1])}",
        ]
        steps = [
            Step(
                "user",
                (
                    f"Create the user {self.login} with the level operator (read only: show "
                    "commands, no changes)"
                    if state.levels
                    else f"Create the user {self.login} (no level: see the note below)"
                ),
                "\n".join(user),
                action=self._action(ssh, user),
                note="the user exists; its settings are set again" if state.exists else "",
                title_id="setup.edgeos.createUser"
                if state.levels
                else "setup.edgeos.createUserNoLevel",
                params={"login": self.login},
            ),
            Step(
                "key",
                f"Let {self.login} log in with a new key generated by Signalbox (only the public "
                "key is sent; no password is set)",
                "\n".join(key),
                action=self._action(ssh, key),
                note="the private key is stored encrypted in Signalbox and never shown",
                title_id="setup.edgeos.key",
                params={"login": self.login},
            ),
        ]
        if not state.levels:
            text = FULL_RIGHTS.format(version=v.text or "this VyOS version", login=self.login)
            steps.append(
                Step(
                    "full-rights",
                    f"Note: {text}",
                    needed=False,
                    note="not a command: the user has full rights on this version",
                    title_id="setup.edgeos.fullRights",
                    params={"version": v.text or "VyOS", "login": self.login},
                )
            )
        steps.append(
            Step(
                "host-key",
                "Trust the router's SSH host key for reading (the one confirmed for this setup)",
                fingerprint,
                needed=True,
                title_id="setup.edgeos.hostKey",
            )
        )
        return steps

    def removal(self, ssh: PinnedSsh, state: DeviceState) -> list[Step]:
        if state.exists and state.level is not None and state.level != "operator":
            raise AdapterError(
                f"the user {self.login} has the level {state.level}: it is not the login the "
                "setup created, so it is not deleted",
                message_id="edgeos.loginNotOurs",
                params={"login": self.login, "level": state.level},
            )
        command = [f"delete system login user {_q(self.login)}"]
        return [
            Step(
                "user",
                f"Delete the user {self.login}",
                command[0] if state.exists else "",
                needed=state.exists,
                action=self._action(ssh, command),
                note="" if state.exists else f"there is no user {self.login}",
                title_id="setup.edgeos.deleteUser",
                params={"login": self.login},
            )
        ]

    async def plan(self) -> SetupPlan:
        try:
            async with self.ssh() as ssh:
                state = await self.inspect(ssh)
                fingerprint = ssh.fingerprint or ""
                steps = plan_steps(self.steps(ssh, state, fingerprint), self.redact)
        except UntrustedHostKey as exc:
            return SetupPlan(
                fingerprint=exc.fingerprint,
                fingerprint_kind="ssh-host-key",
                trusted=False,
                compare=COMPARE,
            )
        except AdapterError as exc:
            raise exc.redacted(self.redact) from None
        return SetupPlan(
            fingerprint=fingerprint,
            fingerprint_kind="ssh-host-key",
            trusted=True,
            compare=COMPARE,
            steps=steps,
        )

    async def apply(self) -> SetupResult:
        try:
            async with self.ssh() as ssh:
                state = await self.inspect(ssh)
                fingerprint = ssh.fingerprint or ""
                ok, steps = await run_steps(self.steps(ssh, state, fingerprint), self.redact)
        except UntrustedHostKey:
            raise
        except AdapterError as exc:
            raise exc.redacted(self.redact) from None
        if self.request.remove or not ok:
            return SetupResult(ok=ok, steps=steps)
        return SetupResult(
            ok=True,
            steps=steps,
            settings={"host": self.host, "port": self.port, "username": self.login},
            secrets={"private_key": SecretStr(self.private)},
            certificate=sha256_hex(fingerprint),
        )


PREVIEW = [
    PreviewStep(
        id="user",
        title="Create the user signalbox (level operator where the version has levels)",
        title_id="setup.edgeos.previewUser",
    ),
    PreviewStep(
        id="key",
        title="Authorize a new SSH key for it (public key only, no password)",
        title_id="setup.edgeos.previewKey",
    ),
    PreviewStep(
        id="full-rights",
        title="VyOS 1.4 and newer only: say that the user has full rights (no read-only level)",
        title_id="setup.edgeos.previewFullRights",
    ),
    PreviewStep(
        id="host-key",
        title="Trust the SSH host key you confirmed, for reading",
        title_id="setup.edgeos.previewHostKey",
    ),
    PreviewStep(
        id="user",
        title="Delete the user signalbox",
        title_id="setup.edgeos.previewDeleteUser",
        remove=True,
    ),
]
