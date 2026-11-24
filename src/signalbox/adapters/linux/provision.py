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
from dataclasses import dataclass, field

import asyncssh
from pydantic import SecretStr

from signalbox.adapters import (
    AdapterError,
    AuthFailed,
    PreviewStep,
    Remedy,
    RemedyRequest,
    SetupPlan,
    SetupRequest,
    SetupResult,
    UntrustedHostKey,
)
from signalbox.adapters.linux import distro
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
    #: ``iptables-save`` is installed (legacy iptables, read with the sudoers rule, #394)
    iptables: bool = False
    #: ``/etc/os-release`` as parsed, and the tools found (``nft``, ``wg``, ``tracepath``,
    #: ``bridge``, ``ip-json``: ``ip -j`` works) (#302)
    os_release: dict[str, str] = field(default_factory=dict)
    have: set[str] = field(default_factory=set)
    #: distribution marker files that exist (``distro.MARKERS``), for systems without os-release
    markers: set[str] = field(default_factory=set)

    @property
    def distro(self) -> distro.Distro:
        return distro.detect(self.os_release, self.markers)


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


def _os_release(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        key, sep, value = line.partition("=")
        if sep and key.strip():
            out[key.strip()] = value.strip().strip("\"'")
    return out


#: A stale pacman database (#394): the mirror no longer has the version the old database names.
#: Never answered with ``pacman -Sy <package>``: Arch does not support partial upgrades.
STALE_DATABASE = (
    "The package lists on the device are out of date. Installing a single package needs a full "
    "system update first (sudo pacman -Syu), which can take long on an old device. Signalbox "
    "reads legacy iptables without nftables."
)


def stale_database(output: str) -> bool:
    """pacman's ``error: failed retrieving file '<package>' from <mirror> ... 404``."""
    return "failed retrieving file" in output and "404" in output


#: Optional extras of the setup (unticked): id -> what the inspection reports when it is
#: already there (``ip-json``: ``ip -j`` works).
EXTRA_TOOLS = {
    "nftables": "nft",
    "iproute2": "ip-json",
    "wireguard": "wg",
    "tracepath": "tracepath",
}


class LinuxSetup:
    #: True for a *Fix it* run, whose install steps are the fix itself, not ticked extras (#395).
    part_of_fix = False

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
            raise AdapterError("give the device's address first", message_id="linux.addressNeeded")
        self.port = request.port or int(str(request.config.get("port") or 22))
        self.login = str(request.config.get("username") or "signalbox").strip()
        if not LOGIN_NAME.match(self.login):
            raise AdapterError(
                "the login to set up must be lower-case letters, digits, - and _ "
                f"(not {self.login!r})",
                message_id="linux.loginName",
                params={"login": repr(self.login)},
            )
        if self.login in REFUSED or self.login == request.admin_user:
            raise AdapterError(
                "the login to set up must not be the admin login or a system account: give "
                "Signalbox a login of its own, for example signalbox",
                message_id="linux.loginIsAdmin",
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
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH\n"
            f"U={_q(self.login)}\n"
            'echo @@user; getent passwd "$U"\n'
            'echo @@groups; id -nG "$U" 2>/dev/null\n'
            'echo @@keys; H=$(getent passwd "$U" | cut -d: -f6)\n'
            '[ -n "$H" ] && cat "$H/.ssh/authorized_keys" 2>/dev/null\n'
            f"echo @@sudoers; cat {sudoers_path(self.login)} 2>/dev/null\n"
            "echo @@wg; command -v wg\n"
            "echo @@nft; command -v nft\n"
            "echo @@ipt; command -v iptables-save\n"
            "echo @@os; cat /etc/os-release 2>/dev/null\n"
            "echo @@markers\n"
            "for f in /etc/debian_version /etc/arch-release /etc/alpine-release "
            "/etc/fedora-release /etc/redhat-release; do [ -e $f ] && echo $f; done\n"
            "echo @@have\n"
            "for t in nft wg tracepath bridge; do command -v $t >/dev/null 2>&1 && echo $t; done\n"
            "ip -j link show >/dev/null 2>&1 && echo ip-json\n"
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
                    message_id="linux.noSudo",
                    fix_id="linux.noSudo.fix",
                    params={"user": self.request.admin_user, "detail": detail},
                )
            raise AdapterError(
                f"the device did not answer like Linux: {detail}",
                message_id="linux.notLinux",
                params={"detail": detail},
            )
        sudo_text = "\n".join(parts.get("sudoers", [])).strip()
        return DeviceState(
            exists=bool([x for x in parts.get("user", []) if x.strip()]),
            groups=set(" ".join(parts.get("groups", [])).split()),
            keys=[x for x in parts.get("keys", []) if x.strip()],
            sudoers=sudo_text + "\n" if sudo_text else None,
            wg=bool([x for x in parts.get("wg", []) if x.strip()]),
            nft=bool([x for x in parts.get("nft", []) if x.strip()]),
            iptables=bool([x for x in parts.get("ipt", []) if x.strip()]),
            os_release=_os_release(parts.get("os", [])),
            have={x.strip() for x in parts.get("have", []) if x.strip()},
            markers={x.strip() for x in parts.get("markers", []) if x.strip()},
        )

    def _action(
        self,
        ssh: PinnedSsh,
        script: str,
        timeout: float | None = None,
        manager: str | None = None,
    ) -> Callable[[], Awaitable[str | None]]:
        async def act() -> str | None:
            res = await ssh.run(script, timeout=timeout, command=self.command, prefix=self.prefix)
            if res.code != 0:
                tail = (res.err or res.text).strip()[-400:]
                if manager == "pacman" and stale_database(tail):
                    raise AdapterError(
                        STALE_DATABASE,
                        message_id="linux.staleDatabase",
                    )
                raise AdapterError(
                    f"failed (exit status {res.code}): {self.redact(tail)}",
                    message_id="linux.stepFailed",
                    params={"code": res.code, "detail": self.redact(tail)},
                )
            return None

        return act

    def install_step(self, ssh: PinnedSsh, state: DeviceState, tool: str) -> Step:
        """Install what the reader uses, with the device's own package manager (#302)."""
        found = EXTRA_TOOLS[tool] in state.have and (tool != "iproute2" or "bridge" in state.have)
        what = distro.TOOLS[tool][0]
        command = state.distro.install(tool)
        if command is None and not found:
            ident = state.os_release.get("ID") or "unknown"
            raise AdapterError(
                f"the distribution ({ident}) is not known: Signalbox cannot install {what}. "
                "Untick it and install it yourself",
                fix="See docs/adapters/linux.md, Supported distributions.",
                message_id="linux.unknownDistro",
                fix_id="linux.unknownDistro.fix",
                params={"ident": ident, "what": what},
            )
        script = f"# signalbox-setup: install-{tool}\nset -e\n{command}\n"
        manager = state.distro.manager or ""
        if self.part_of_fix:
            # #395: a Fix it installs as its purpose; nothing was ticked, never claim so
            title, title_id = f"Install {what} with {manager} (this fix)", "setup.linux.installFix"
        else:
            title, title_id = (
                f"Install {what} with {manager} (you ticked this; optional)",
                "setup.linux.install",
            )
        return Step(
            f"install-{tool}",
            title,
            script if not found else "",
            needed=not found,
            action=self._action(
                ssh, script, timeout=max(300.0, self.request.timeout), manager=manager
            ),
            note="already installed" if found else "",
            title_id=title_id,
            params={"what": what, "manager": manager},
        )

    def steps(self, ssh: PinnedSsh, state: DeviceState, fingerprint: str) -> list[Step]:
        if self.request.remove:
            return self.removal(ssh, state)
        bad = state.groups & PRIVILEGED
        if state.exists and bad:
            raise AdapterError(
                f"the user {self.login} exists and is in the group(s) {', '.join(sorted(bad))}: "
                "Signalbox's login must not have more than read access; choose another name",
                message_id="linux.loginPrivileged",
                params={"login": self.login, "groups": ", ".join(sorted(bad))},
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
        ticked = [t for t in EXTRA_TOOLS if t in self.request.extras]
        steps[2:2] = [self.install_step(ssh, state, t) for t in ticked]
        if state.wg or state.nft or state.iptables or "wireguard" in ticked or "nftables" in ticked:
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
                "the login the setup created, so it is not deleted",
                message_id="linux.loginNotOurs",
                params={"login": self.login, "groups": ", ".join(sorted(bad))},
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


#: The remedies of *Fix it* (#215): install what the reader needs, read-side only.
REMEDIES = (
    Remedy(
        id="nftables",
        read_side=True,
        preview=[
            PreviewStep(
                id="install-nftables",
                title="Install nftables with the device's package manager",
                title_id="setup.linux.previewInstall",
            ),
            PreviewStep(
                id="sudoers",
                title="Allow the login the read-only wg show and nft list commands",
                title_id="setup.linux.previewSudoers",
            ),
        ],
        title="Install nftables",
        description="Over SSH as root or a sudo user: installs the package nftables with the "
        "device's package manager (apt, pacman, dnf or apk) and adds the read-only sudoers rule "
        "for nft -j list ruleset, so that Signalbox can read the firewall. No firewall rule or "
        "network setting is changed; the iptables rules in use stay as they are.",
    ),
)


class LinuxFix(LinuxSetup):
    """*Fix it* on a stored device: the steps of one remedy for the stored login."""

    part_of_fix = True

    def __init__(self, request: RemedyRequest) -> None:
        if request.remedy not in {r.id for r in REMEDIES}:
            raise AdapterError(
                f"Linux has no remedy {request.remedy!r}",
                message_id="linux.noRemedy",
                params={"remedy": repr(request.remedy)},
            )
        super().__init__(
            SetupRequest(
                config=request.config,
                admin_user=request.admin_user,
                admin_secret=request.admin_secret,
                port=request.port,
                trust=request.trust,
                timeout=request.timeout,
                extras=["nftables"],
            )
        )

    async def apply(self) -> SetupResult:
        result = await super().apply()
        # the stored login keeps its key: nothing is returned to store
        return SetupResult(ok=result.ok, steps=result.steps)

    def steps(self, ssh: PinnedSsh, state: DeviceState, fingerprint: str) -> list[Step]:
        rule = sudoers(self.login)
        install_rule = (
            "# signalbox-setup: sudoers\nset -e\n"
            "T=$(mktemp)\n"
            "cat > \"$T\" <<'SIGNALBOX'\n" + rule.rstrip("\n") + "\nSIGNALBOX\n"
            'chmod 440 "$T"\n'
            'visudo -cf "$T" >/dev/null\n'
            f'mv "$T" {_q(sudoers_path(self.login))}\n'
        )
        return [
            self.install_step(ssh, state, "nftables"),
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
            ),
        ]
