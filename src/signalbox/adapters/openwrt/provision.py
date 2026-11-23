"""Automatic setup of an OpenWrt router over SSH as root (#231, docs/adr/0009).

The same steps as the commands of the setup guide (:mod:`signalbox.adapters.openwrt.setup`):
the packages Signalbox reads through (apk or opkg, only the missing ones), the ACL file
``/usr/share/rpcd/acl.d/signalbox.json`` (read-only, or with the write part when changes are
allowed) and an rpcd login with a generated password, then ``rpcd`` is restarted. The password
is hashed here (md5-crypt, as ``uhttpd -m`` does), so only the hash reaches the router; every
script goes over standard input of ``sh -s``. The web server's certificate is read over the
same pinned SSH connection, so it can be pinned for reading without a second confirmation.

Removal deletes the login, and the ACL file unless another login still lists it; packages are
kept (LuCI needs most of them).

*Fix it* (#215, docs/adr/0012) uses the same connection and inspection for two remedies:
``access`` (missing packages, the ACL file, the ACL group in the stored login's section, rpcd
restarted; the password is left alone) and ``lldp`` (lldpd and luci-app-lldpd, lldpd started,
then the same permission steps). Nothing else on the router is touched.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from pydantic import SecretStr

from signalbox.adapters import (
    AdapterError,
    Remedy,
    RemedyRequest,
    SetupPlan,
    SetupRequest,
    SetupResult,
    UntrustedHostKey,
)
from signalbox.adapters.https import device_url
from signalbox.adapters.openwrt.setup import LLDP_PACKAGES, PACKAGES, READ_ACL, WRITE_ACL
from signalbox.adapters.provision import Redactor, Step, new_password, plan_steps, run_steps
from signalbox.adapters.ssh import PinnedSsh

ACL_PATH = "/usr/share/rpcd/acl.d/signalbox.json"
ACL_GROUP = "signalbox"
LOGIN_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
#: UCI section names as `uci -X` prints them; anything else is not put into a command
SECTION = re.compile(r"^[A-Za-z0-9_]+$")
#: rpcd restarted, and its session object back on ubus before the next login (CI: 25.12)
RESTART = "/etc/init.d/rpcd restart\nsleep 1\nubus -t 15 wait_for session\n"
COMPARE = (
    "On the router: dropbearkey -y -f /etc/dropbear/dropbear_ed25519_host_key (or the _rsa_ "
    "key) prints the fingerprint; ssh-keygen -lf on a copy of the public key shows the same."
)

# --- md5-crypt ($1$), what ``uhttpd -m`` writes and rpcd checks ----------------------------

_CRYPT64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def md5_crypt(password: str, salt: str) -> str:
    """``$1$<salt>$<hash>``, the MD5 crypt of FreeBSD and glibc (salt: up to 8 characters).

    Computed here so that the password itself never reaches the router; rpcd checks a login
    with musl's ``crypt()``, which knows this format.
    """
    pw, sa = password.encode(), salt[:8].encode()
    alt = hashlib.md5(pw + sa + pw).digest()
    ctx = hashlib.md5(pw + b"$1$" + sa)
    for left in range(len(pw), 0, -16):
        ctx.update(alt[: min(16, left)])
    bits = len(pw)
    while bits:
        ctx.update(b"\0" if bits & 1 else pw[:1])
        bits >>= 1
    final = ctx.digest()
    for r in range(1000):
        step = hashlib.md5()
        step.update(pw if r & 1 else final)
        if r % 3:
            step.update(sa)
        if r % 7:
            step.update(pw)
        step.update(final if r & 1 else pw)
        final = step.digest()

    def b64(a: int, b: int, c: int, n: int) -> str:
        v = (a << 16) | (b << 8) | c
        out = ""
        for _ in range(n):
            out += _CRYPT64[v & 0x3F]
            v >>= 6
        return out

    f = final
    text = (
        b64(f[0], f[6], f[12], 4)
        + b64(f[1], f[7], f[13], 4)
        + b64(f[2], f[8], f[14], 4)
        + b64(f[3], f[9], f[15], 4)
        + b64(f[4], f[10], f[5], 4)
        + b64(0, 0, f[11], 2)
    )
    return f"$1${salt[:8]}${text}"


# --- what is on the router -------------------------------------------------------------------


def _q(value: str) -> str:
    """Single-quoted for sh (and so for uci)."""
    return "'" + value.replace("'", "'\\''") + "'"


@dataclass
class Login:
    section: str
    username: str
    read: list[str]
    write: list[str]


@dataclass
class DeviceState:
    manager: str  # "apk" or "opkg"
    installed: set[str]
    acl: Any  # the parsed ACL file; None: missing, "": not JSON
    logins: list[Login]
    certificate: str | None  # SHA-256 of the web server certificate
    lldpd_running: bool = False


INSPECT = f"""# signalbox-setup: inspect
echo @@pm
if command -v apk >/dev/null 2>&1; then echo apk; apk info -e {PACKAGES} {LLDP_PACKAGES} 2>/dev/null
else echo opkg; opkg list-installed 2>/dev/null | cut -d' ' -f1; fi
echo @@acl
cat {ACL_PATH} 2>/dev/null
echo @@rpcd
uci -q -X show rpcd
echo @@lldpd
pidof lldpd >/dev/null 2>&1 && echo running
echo @@end
"""

#: The remedies of *Fix it* (#215); the read errors name them with ``remedy=``.
REMEDIES = (
    Remedy(
        id="access",
        title="Repair Signalbox's access",
        description="Over SSH as root: installs the packages Signalbox reads through that are "
        "missing, writes its permission file as in the setup guide (with the write part when "
        "changes are allowed), adds that permission to the stored login (its password stays) "
        "and restarts rpcd. Network settings are not touched.",
    ),
    Remedy(
        id="lldp",
        title="Install LLDP",
        description="Over SSH as root: installs lldpd and luci-app-lldpd if missing, starts "
        "lldpd (it then sends and receives LLDP on the router's ports), checks Signalbox's "
        "permissions and restarts rpcd. Network settings are not touched.",
    ),
)

CERTIFICATE = """# signalbox-setup: certificate
cat "$(uci -q get uhttpd.main.cert || echo /etc/uhttpd.crt)" 2>/dev/null
"""


def parse_sections(text: str) -> dict[str, str]:
    """The parts of the inspection's output, by their ``@@name`` line."""
    parts: dict[str, str] = {}
    name = ""
    for line in text.splitlines():
        if line.startswith("@@"):
            name = line[2:].strip()
            parts[name] = ""
        elif name:
            parts[name] += line + "\n"
    return parts


def parse_logins(text: str) -> list[Login]:
    """``uci -X show rpcd``: ``rpcd.cfg0a1b2c=login``, ``rpcd.cfg0a1b2c.read='a' 'b'``."""
    options: dict[str, dict[str, list[str]]] = {}
    types: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        parts = key.split(".")
        if not sep or len(parts) not in (2, 3) or parts[0] != "rpcd":
            continue
        try:
            values = shlex.split(value)
        except ValueError:
            continue
        if len(parts) == 2:
            types[parts[1]] = values[0] if values else ""
        else:
            options.setdefault(parts[1], {})[parts[2]] = values
    return [
        Login(
            section=name,
            username=(options.get(name, {}).get("username") or [""])[0],
            read=options.get(name, {}).get("read", []),
            write=options.get(name, {}).get("write", []),
        )
        for name, kind in types.items()
        if kind == "login" and SECTION.match(name)
    ]


def certificate_fingerprint(data: bytes) -> str | None:
    """SHA-256 of the certificate in uhttpd's file (DER as px5g writes it, or PEM)."""
    if not data.strip():
        return None
    if data.lstrip().startswith(b"-----BEGIN"):
        try:
            der = ssl.PEM_cert_to_DER_cert(data.decode("ascii", "replace").strip())
        except ValueError:
            return None
        return hashlib.sha256(der).hexdigest()
    return hashlib.sha256(data).hexdigest()


# --- the setup ---------------------------------------------------------------------------------


class OpenWrtSetup:
    """The automatic setup of one router: inspect, then plan, apply or remove."""

    def __init__(self, request: SetupRequest) -> None:
        self.request = request
        self.redact = Redactor()
        self.redact.add(request.admin_secret.get_secret_value())
        raw = str(request.config.get("url") or "").strip()
        if not raw:
            raise AdapterError("give the router's address first")
        try:
            self.url = device_url(raw, path="/ubus")
        except ValueError as exc:
            raise AdapterError(str(exc)) from None
        self.host = urlsplit(self.url).hostname or ""
        self.port = request.port or 22
        self.login = str(request.config.get("username") or "signalbox").strip()
        if not LOGIN_NAME.match(self.login):
            raise AdapterError(
                "the login to set up must be lower-case letters, digits, - and _ "
                f"(not {self.login!r})"
            )
        if self.login in ("root", request.admin_user):
            raise AdapterError(
                "the login to set up must not be the admin login: give Signalbox a login of "
                "its own, for example signalbox"
            )
        self.password = new_password()
        self.hash = md5_crypt(self.password, new_password(8))
        self.redact.add(self.password, self.hash)

    def ssh(self) -> PinnedSsh:
        return PinnedSsh(
            self.host,
            self.port,
            self.request.admin_user,
            self.request.admin_secret.get_secret_value(),
            self.request.trust,
            self.request.timeout,
        )

    async def inspect(self, ssh: PinnedSsh) -> DeviceState:
        res = await ssh.run(INSPECT)
        parts = parse_sections(res.text)
        if "end" not in parts or "rpcd" not in parts:
            raise AdapterError(
                "the device did not answer like OpenWrt: "
                + self.redact((res.err or res.text).strip())[:300]
            )
        pm = parts.get("pm", "").split()
        acl_text = parts.get("acl", "").strip()
        acl: Any = None
        if acl_text:
            try:
                acl = json.loads(acl_text)
            except ValueError:
                acl = ""
        cert = None
        if self.url.startswith("https://"):
            cert = certificate_fingerprint((await ssh.run(CERTIFICATE)).out)
        return DeviceState(
            manager=pm[0] if pm else "opkg",
            installed=set(pm[1:]),
            acl=acl,
            logins=parse_logins(parts["rpcd"]),
            certificate=cert,
            lldpd_running="running" in parts.get("lldpd", ""),
        )

    def steps(self, ssh: PinnedSsh, state: DeviceState) -> list[Step]:
        if self.request.remove:
            return self.removal(ssh, state)
        writes = self.request.allow_writes
        wanted_acl = WRITE_ACL if writes else READ_ACL
        missing = [p for p in PACKAGES.split() if p not in state.installed]
        if state.manager == "apk":
            install = f"apk update && apk add {' '.join(missing)}\n"
        else:
            install = f"opkg update && opkg install {' '.join(missing)}\n"
        acl_script = (
            f"mkdir -p {ACL_PATH.rsplit('/', 1)[0]}\n"
            f"cat > {ACL_PATH} <<'SIGNALBOX_ACL'\n{json.dumps(wanted_acl, indent=2)}\n"
            "SIGNALBOX_ACL\n"
        )
        mine = [x for x in state.logins if x.username == self.login]
        what = "with write access" if writes else "read-only"
        restart = RESTART + ("/etc/init.d/uhttpd restart\n" if missing else "")
        steps = [
            Step(
                "packages",
                f"Install the packages Signalbox reads through ({state.manager})",
                install if missing else PACKAGES,
                needed=bool(missing),
                action=self._run(ssh, install, timeout=max(300.0, self.request.timeout)),
                note="" if missing else "all installed",
            ),
            Step(
                "acl",
                f"Permissions {ACL_PATH} ({what}, as in the setup guide)",
                acl_script,
                needed=state.acl != wanted_acl,
                action=self._run(ssh, acl_script),
                note="" if state.acl != wanted_acl else "already as in the setup guide",
            ),
            Step(
                "login",
                f"{'Update' if mine else 'Create'} the rpcd login {self.login} ({what}) with a "
                "new generated password",
                self._login_script(mine),
                action=self._run(ssh, self._login_script(mine)),
                note="the password is stored encrypted in Signalbox and never shown",
            ),
            Step(
                "restart",
                "Restart rpcd so that it loads the permissions and the login",
                restart,
                action=self._run(ssh, restart),
            ),
        ]
        if state.certificate:
            steps.append(
                Step(
                    "certificate",
                    "Trust the router's web server certificate for reading (read over this "
                    "SSH connection)",
                    f"SHA-256 {state.certificate}",
                )
            )
        return steps

    def _login_script(self, mine: list[Login]) -> str:
        lines = ["set -e"]
        lines += [f"uci delete rpcd.{extra.section}" for extra in mine[1:]]
        lines.append(f"S={mine[0].section}" if mine else "S=$(uci add rpcd login)")
        lines += [
            f"uci set rpcd.$S.username={_q(self.login)}",
            f"uci set rpcd.$S.password={_q(self.hash)}",
            "uci -q delete rpcd.$S.read || true",
            "uci -q delete rpcd.$S.write || true",
            f"uci add_list rpcd.$S.read={_q(ACL_GROUP)}",
        ]
        if self.request.allow_writes:
            lines.append(f"uci add_list rpcd.$S.write={_q(ACL_GROUP)}")
        lines.append("uci commit rpcd")
        return "\n".join(lines) + "\n"

    def removal(self, ssh: PinnedSsh, state: DeviceState) -> list[Step]:
        mine = [x for x in state.logins if x.username == self.login]
        others = sorted(
            {
                x.username
                for x in state.logins
                if x.username != self.login and ACL_GROUP in (*x.read, *x.write)
            }
        )
        delete_login = (
            "set -e\n"
            + "".join(f"uci delete rpcd.{x.section}\n" for x in mine)
            + "uci commit rpcd\n"
        )
        drop_acl = state.acl is not None and not others
        changed = bool(mine) or drop_acl
        if state.acl is None:
            acl_note = "there is no such file"
        elif others:
            acl_note = f"kept: the login(s) {', '.join(others)} use it"
        else:
            acl_note = ""
        return [
            Step(
                "login",
                f"Delete the rpcd login {self.login}",
                delete_login if mine else "",
                needed=bool(mine),
                action=self._run(ssh, delete_login),
                note="" if mine else f"there is no login {self.login}",
            ),
            Step(
                "acl",
                f"Delete Signalbox's permissions {ACL_PATH}",
                f"rm -f {ACL_PATH}\n" if drop_acl else "",
                needed=drop_acl,
                action=self._run(ssh, f"rm -f {ACL_PATH}\n"),
                note=acl_note,
            ),
            Step(
                "restart",
                "Restart rpcd",
                RESTART,
                needed=changed,
                action=self._run(ssh, RESTART),
                note="" if changed else "nothing changed",
            ),
            Step(
                "packages",
                "Keep the packages (LuCI and other programs use them)",
                PACKAGES,
                needed=False,
                note="not removed",
            ),
        ]

    def _run(
        self, ssh: PinnedSsh, script: str, timeout: float | None = None
    ) -> Callable[[], Awaitable[str | None]]:
        async def run() -> str | None:
            res = await ssh.run(script, timeout=timeout)
            if res.code != 0:
                tail = (res.err or res.text).strip()[-400:]
                raise AdapterError(f"failed (exit status {res.code}): {self.redact(tail)}")
            return None

        return run

    # the two hooks ------------------------------------------------------------------------------

    async def plan(self) -> SetupPlan:
        try:
            async with self.ssh() as ssh:
                state = await self.inspect(ssh)
                steps = plan_steps(self.steps(ssh, state), self.redact)
                fingerprint = ssh.fingerprint or ""
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
                ok, steps = await run_steps(self.steps(ssh, state), self.redact)
        except UntrustedHostKey:
            raise
        except AdapterError as exc:
            raise type(exc)(self.redact(str(exc)), fix=exc.fix) from None
        if self.request.remove or not ok:
            return SetupResult(ok=ok, steps=steps)
        return SetupResult(
            ok=True,
            steps=steps,
            settings={"url": self.url, "username": self.login},
            secrets={"password": SecretStr(self.password)},
            certificate=state.certificate,
        )


# --- fix it (#215) ------------------------------------------------------------------------------


def install_script(manager: str, packages: list[str]) -> str:
    if manager == "apk":
        return f"apk update && apk add {' '.join(packages)}\n"
    return f"opkg update && opkg install {' '.join(packages)}\n"


def acl_script(acl: Any) -> str:
    return (
        f"mkdir -p {ACL_PATH.rsplit('/', 1)[0]}\n"
        f"cat > {ACL_PATH} <<'SIGNALBOX_ACL'\n{json.dumps(acl, indent=2)}\n"
        "SIGNALBOX_ACL\n"
    )


class OpenWrtFix(OpenWrtSetup):
    """*Fix it* on a stored router: the steps of one remedy, with the stored login kept."""

    def __init__(self, request: RemedyRequest) -> None:
        if request.remedy not in {r.id for r in REMEDIES}:
            raise AdapterError(f"OpenWrt has no remedy {request.remedy!r}")
        self.fix = request
        super().__init__(
            SetupRequest(
                config={"url": request.config.get("url"), "username": "signalbox-fix"},
                admin_user=request.admin_user,
                admin_secret=request.admin_secret,
                port=request.port,
                allow_writes=request.allow_writes,
                trust=request.trust,
                timeout=request.timeout,
            )
        )
        # the stored login may be root (it has every permission already)
        self.login = str(request.config.get("username") or "root").strip()
        for secret in request.secrets.values():
            self.redact.add(secret.get_secret_value())

    def steps(self, ssh: PinnedSsh, state: DeviceState) -> list[Step]:
        writes = self.fix.allow_writes
        wanted_acl = WRITE_ACL if writes else READ_ACL
        what = "with write access" if writes else "read-only"
        steps: list[Step] = []
        restart_web = False
        if self.fix.remedy == "lldp":
            missing = [p for p in LLDP_PACKAGES.split() if p not in state.installed]
            install = install_script(state.manager, missing)
            steps.append(
                Step(
                    "lldp-packages",
                    f"Install the LLDP packages ({state.manager})",
                    install if missing else LLDP_PACKAGES,
                    needed=bool(missing),
                    action=self._run(ssh, install, timeout=max(300.0, self.fix.timeout)),
                    note="" if missing else "all installed",
                )
            )
            start = "/etc/init.d/lldpd enable\n/etc/init.d/lldpd start\n"
            running = state.lldpd_running and not missing
            steps.append(
                Step(
                    "lldpd",
                    "Start lldpd (and at every boot)",
                    start,
                    needed=not running,
                    action=self._run(ssh, start),
                    note="already running" if running else "",
                )
            )
        else:
            missing = [p for p in PACKAGES.split() if p not in state.installed]
            install = install_script(state.manager, missing)
            restart_web = bool(missing)
            steps.append(
                Step(
                    "packages",
                    f"Install the packages Signalbox reads through ({state.manager})",
                    install if missing else PACKAGES,
                    needed=bool(missing),
                    action=self._run(ssh, install, timeout=max(300.0, self.fix.timeout)),
                    note="" if missing else "all installed",
                )
            )
        script = acl_script(wanted_acl)
        steps.append(
            Step(
                "acl",
                f"Permissions {ACL_PATH} ({what}, as in the setup guide)",
                script,
                needed=state.acl != wanted_acl,
                action=self._run(ssh, script),
                note="" if state.acl != wanted_acl else "already as in the setup guide",
            )
        )
        steps.append(self._login_step(ssh, state, writes))
        restart = RESTART + ("/etc/init.d/uhttpd restart\n" if restart_web else "")
        steps.append(
            Step(
                "restart",
                "Restart rpcd so that it loads the permissions",
                restart,
                action=self._run(ssh, restart),
            )
        )
        return steps

    def _login_step(self, ssh: PinnedSsh, state: DeviceState, writes: bool) -> Step:
        title = f"Permission {ACL_GROUP!r} for the stored login {self.login}"
        if self.login == "root":
            return Step("login", title, "", needed=False, note="root may use every permission")
        mine = [x for x in state.logins if x.username == self.login]
        if not mine:
            raise AdapterError(
                f"there is no rpcd login {self.login!r} on the router",
                fix="Set the device up again (device settings: Set up automatically, or the "
                "setup guide): Fix it only repairs the permissions of an existing login.",
            )
        login = mine[0]
        lines = []
        if ACL_GROUP not in login.read:
            lines.append(f"uci add_list rpcd.{login.section}.read={_q(ACL_GROUP)}")
        if writes and ACL_GROUP not in login.write:
            lines.append(f"uci add_list rpcd.{login.section}.write={_q(ACL_GROUP)}")
        script = "set -e\n" + "".join(x + "\n" for x in lines) + "uci commit rpcd\n"
        return Step(
            "login",
            title + " (the password stays)",
            script if lines else "",
            needed=bool(lines),
            action=self._run(ssh, script),
            note="" if lines else "already listed",
        )

    async def apply(self) -> SetupResult:
        result = await super().apply()
        return SetupResult(ok=result.ok, steps=result.steps)
