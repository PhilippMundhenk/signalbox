"""Automatic setup of a Linux device over SSH with root or a sudo user (#240, docs/adr/0009).

The same result as the commands of the setup guide (:mod:`signalbox.adapters.linux.setup`): a
system user without password, sudo or groups; an ed25519 key generated here, of which only the
public half is sent (``authorized_keys``); with WireGuard or nftables installed, the sudoers
rule for the ``wg show`` and ``nft -j list ruleset`` read commands, checked with ``visudo -c``
before it is put in place. A sudo user's password goes to ``sudo -S`` on standard input,
never on a command line; with ``NOPASSWD`` it is not sent at all. The host key confirmed for
the admin login is pinned for reading,
so the user confirms one fingerprint.

Removal deletes the sudoers rule and the user with its home directory.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import asyncssh
from pydantic import SecretStr

from signalbox.adapters import (
    AdapterError,
    AuthFailed,
    SetupPlan,
    SetupRequest,
    SetupResult,
    UntrustedHostKey,
)
from signalbox.adapters.linux.setup import KEY_COMMENT, sudoers, sudoers_path
from signalbox.adapters.provision import Redactor, Step, plan_steps, run_steps
from signalbox.adapters.ssh import PinnedSsh, ShellResult, sha256_hex

LOGIN_NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,30}$")
#: Logins Signalbox never sets up: the admin's own and the usual system and admin accounts.
REFUSED = frozenset({"root", "pi", "admin", "ubuntu", "debian", "daemon", "bin", "sys", "nobody"})
#: Groups that give more than reading: a user in one of them is not Signalbox's.
PRIVILEGED = frozenset({"sudo", "wheel", "adm", "root", "admin", "docker", "lxd", "disk", "shadow"})
COMPARE = (
    "On the device: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub prints the fingerprint "
    "(or the _ecdsa_ / _rsa_ key)."
)


def _q(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


@dataclass
class DeviceState:
    exists: bool
    groups: set[str]
    keys: list[str]
    sudoers: str | None
    wg: bool
    nft: bool = False


def parse_sections(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    name = ""
    for line in text.splitlines():
        if line.startswith("@@"):
            name = line[2:].strip()
            out[name] = []
        elif name:
            out[name].append(line)
    return out


class LinuxSetup:
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
            raise AdapterError("give the device's address first")
        self.port = request.port or int(str(request.config.get("port") or 22))
        self.login = str(request.config.get("username") or "signalbox").strip()
        if not LOGIN_NAME.match(self.login):
            raise AdapterError(
                "the login to set up must be lower-case letters, digits, - and _ "
                f"(not {self.login!r})"
            )
        if self.login in REFUSED or self.login == request.admin_user:
            raise AdapterError(
                "the login to set up must not be the admin login or a system account: give "
                "Signalbox a login of its own, for example signalbox"
            )
        self.key = asyncssh.generate_private_key("ssh-ed25519", comment=KEY_COMMENT)
        self.private = self.key.export_private_key().decode()
        self.public = self.key.export_public_key("openssh").decode().strip()
        self.redact.add(self.private)
        self.command = "sh -s"
        self.prefix = b""

    def ssh(self) -> PinnedSsh:
        return PinnedSsh(
            self.host,
            self.port,
            self.request.admin_user,
            self.secret,
            self.request.trust,
            self.request.timeout,
        )

    async def elevate(self, ssh: PinnedSsh) -> None:
        """Root as it is; a sudo user with NOPASSWD, else with its password on stdin."""
        if self.request.admin_user == "root":
            return
        probe = await ssh.run("", command="sudo -n true")
        if probe.code == 0:
            self.command = "sudo -n sh -s"
        else:
            self.command, self.prefix = "sudo -S -p '' sh -s", self.secret.encode() + b"\n"

    async def run(self, ssh: PinnedSsh, script: str) -> ShellResult:
        return await ssh.run(script, command=self.command, prefix=self.prefix)

    async def inspect(self, ssh: PinnedSsh) -> DeviceState:
        await self.elevate(ssh)
        script = (
            "# signalbox-setup: inspect\n"
            f"U={_q(self.login)}\n"
            'echo @@user; getent passwd "$U"\n'
            'echo @@groups; id -nG "$U" 2>/dev/null\n'
            'echo @@keys; H=$(getent passwd "$U" | cut -d: -f6)\n'
            '[ -n "$H" ] && cat "$H/.ssh/authorized_keys" 2>/dev/null\n'
            f"echo @@sudoers; cat {sudoers_path(self.login)} 2>/dev/null\n"
            "echo @@wg; command -v wg\n"
            "echo @@nft; command -v nft\n"
            "echo @@end\n"
        )
        res = await self.run(ssh, script)
        parts = parse_sections(res.text)
        if "end" not in parts:
            detail = self.redact((res.err or res.text).strip())[:300]
            if "sudoers" in detail or "password" in detail:
                raise AuthFailed(
                    f"{self.request.admin_user} may not use sudo: {detail}",
                    fix="Give root's password, or a user that may use sudo (Raspberry Pi OS: "
                    "the user created at installation).",
                )
            raise AdapterError(f"the device did not answer like Linux: {detail}")
        sudo_text = "\n".join(parts.get("sudoers", [])).strip()
        return DeviceState(
            exists=bool([x for x in parts.get("user", []) if x.strip()]),
            groups=set(" ".join(parts.get("groups", [])).split()),
            keys=[x for x in parts.get("keys", []) if x.strip()],
            sudoers=sudo_text + "\n" if sudo_text else None,
            wg=bool([x for x in parts.get("wg", []) if x.strip()]),
            nft=bool([x for x in parts.get("nft", []) if x.strip()]),
        )

    def _action(self, ssh: PinnedSsh, script: str) -> Callable[[], Awaitable[str | None]]:
        async def act() -> str | None:
            res = await self.run(ssh, script)
            if res.code != 0:
                tail = (res.err or res.text).strip()[-400:]
                raise AdapterError(f"failed (exit status {res.code}): {self.redact(tail)}")
            return None

        return act

    def steps(self, ssh: PinnedSsh, state: DeviceState, fingerprint: str) -> list[Step]:
        if self.request.remove:
            return self.removal(ssh, state)
        bad = state.groups & PRIVILEGED
        if state.exists and bad:
            raise AdapterError(
                f"the user {self.login} exists and is in the group(s) {', '.join(sorted(bad))}: "
                "Signalbox's login must not have more than read access; choose another name"
            )
        u = f"U={_q(self.login)}\n"
        create = (
            "# signalbox-setup: user\nset -e\n"
            + u
            + 'useradd --system --create-home --shell /bin/sh "$U"\n'
        )
        key = (
            "# signalbox-setup: key\nset -e\n"
            + u
            + f"K={_q(self.public)}\n"
            + 'H=$(getent passwd "$U" | cut -d: -f6)\n'
            'install -d -m 700 -o "$U" -g "$(id -gn "$U")" "$H/.ssh"\n'
            'printf \'%s\\n\' "$K" > "$H/.ssh/authorized_keys"\n'
            'chown "$U": "$H/.ssh/authorized_keys"\n'
            'chmod 600 "$H/.ssh/authorized_keys"\n'
        )
        rule = sudoers(self.login)
        install_rule = (
            "# signalbox-setup: sudoers\nset -e\n"
            "T=$(mktemp)\n"
            "cat > \"$T\" <<'SIGNALBOX'\n" + rule.rstrip("\n") + "\nSIGNALBOX\n"
            'chmod 440 "$T"\n'
            'visudo -cf "$T" >/dev/null\n'
            f'mv "$T" {_q(sudoers_path(self.login))}\n'
        )
        steps = [
            Step(
                "user",
                f"Create the user {self.login} (no password, no sudo, no groups)",
                create if not state.exists else "",
                needed=not state.exists,
                action=self._action(ssh, create),
                note="" if not state.exists else "the user exists",
                title_id="setup.linux.createUser",
                params={"login": self.login},
            ),
            Step(
                "key",
                f"Let {self.login} log in with a new key generated by Signalbox "
                "(only the public key is sent; authorized_keys is replaced)",
                key,
                action=self._action(ssh, key),
                note="the private key is stored encrypted in Signalbox and never shown",
                title_id="setup.linux.key",
                params={"login": self.login},
            ),
        ]
        if state.wg or state.nft:
            steps.append(
                Step(
                    "sudoers",
                    f"Allow {self.login} the read-only commands (wg show, nft list ruleset) "
                    f"({sudoers_path(self.login)})",
                    install_rule,
                    needed=state.sudoers != rule,
                    action=self._action(ssh, install_rule),
                    note="" if state.sudoers != rule else "already as in the setup guide",
                    title_id="setup.linux.sudoers",
                    params={"login": self.login, "path": sudoers_path(self.login)},
                )
            )
        else:
            steps.append(
                Step(
                    "sudoers",
                    "No sudoers rule: neither WireGuard (wg) nor nftables (nft) is installed",
                    needed=False,
                    note="not needed",
                    title_id="setup.linux.noSudoers",
                )
            )
        steps.append(
            Step(
                "host-key",
                "Trust the device's SSH host key for reading (the one confirmed for this setup)",
                fingerprint,
                needed=True,
                title_id="setup.linux.hostKey",
            )
        )
        return steps

    def removal(self, ssh: PinnedSsh, state: DeviceState) -> list[Step]:
        u = f"U={_q(self.login)}\n"
        drop_rule = (
            f'# signalbox-setup: remove-sudoers\nP={_q(sudoers_path(self.login))}\nrm -f "$P"\n'
        )
        drop_user = (
            "# signalbox-setup: remove-user\nset -e\n"
            + u
            + 'userdel -r "$U" 2>/dev/null || userdel "$U"\n'
        )
        bad = state.groups & PRIVILEGED
        if state.exists and bad:
            raise AdapterError(
                f"the user {self.login} is in the group(s) {', '.join(sorted(bad))}: it is not "
                "the login the setup created, so it is not deleted"
            )
        return [
            Step(
                "sudoers",
                f"Delete the sudoers rule {sudoers_path(self.login)}",
                drop_rule if state.sudoers else "",
                needed=state.sudoers is not None,
                action=self._action(ssh, drop_rule),
                note="" if state.sudoers else "there is no such file",
                title_id="setup.linux.deleteSudoers",
                params={"path": sudoers_path(self.login)},
            ),
            Step(
                "user",
                f"Delete the user {self.login} and its home directory",
                drop_user if state.exists else "",
                needed=state.exists,
                action=self._action(ssh, drop_user),
                note="" if state.exists else f"there is no user {self.login}",
                title_id="setup.linux.deleteUser",
                params={"login": self.login},
            ),
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
            raise type(exc)(self.redact(str(exc)), fix=exc.fix) from None
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
            raise type(exc)(self.redact(str(exc)), fix=exc.fix) from None
        if self.request.remove or not ok:
            return SetupResult(ok=ok, steps=steps)
        return SetupResult(
            ok=True,
            steps=steps,
            settings={"host": self.host, "port": self.port, "username": self.login},
            secrets={"private_key": SecretStr(self.private)},
            certificate=sha256_hex(fingerprint),
        )
