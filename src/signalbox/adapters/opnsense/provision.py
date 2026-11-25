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

Optionally (``SetupRequest.ssh_step``, off by default, #242) the setup also installs the helper
script that reads the ISC DHCP settings (:mod:`signalbox.adapters.opnsense.isc_script`) and an
SSH key that can run nothing else, over SSH as root with a pinned host key; "Remove" takes both
away again.
*Fix it* (#215, docs/adr/0012): the remedy ``privileges`` finds the user the stored API key
belongs to (``search_api_key``) and adds the documented privileges it lacks; its other
privileges, groups, password and keys stay as they are.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import asyncssh
from pydantic import SecretStr

from signalbox.adapters import (
    AdapterError,
    Label,
    PreviewStep,
    Remedy,
    RemedyRequest,
    SetupPlan,
    SetupRequest,
    SetupResult,
    UntrustedCertificate,
    UntrustedHostKey,
)
from signalbox.adapters.https import DeviceHttp, NotFound, device_url
from signalbox.adapters.provision import Redactor, Step, plan_steps, run_steps
from signalbox.adapters.ssh import PinnedSsh

#: Privileges of the read user (docs: "A least-privilege API user"; the integration test image
#: gives its users exactly these, tools/integration/opnsense/privileges.json).
READ_PRIVILEGES: tuple[str, ...] = (
    "page-system-firmware-manualupdate",
    "page-status-interfaces",
    "page-interfaces-vlan-edit",
    "page-dhcp-kea-v4",
    "page-services-dhcprelay",
    "page-services-unbound",
    "page-diagnostics-arptable",
    "page-diagnostics-ndptable",
    "page-system-login-logout",
    "page-status-ntp",
    "page-wireguard-diagnostics",
    "page-filter-api",
    "page-firewall-aliases",
    "page-interfaces-groups-edit",
    "page-firewall-nat-portforward-edit",
    "page-filter-snat-api",
    "page-firewall-nat-1-1-edit",
    "page-diagnostics-logs-settings-targets",
    "page-diagnostics-netflow",
    "page-system-certmanager",
    "page-system-camanager",
    "page-system-staticroutes",
    "page-system-gateways",
    "page-system-gatewaygroups",
    "page-services-dyndns",
    "page-services-captiveportal",
)
#: Privileges that exist only with an optional plugin (os-ddclient adds *Services: Dynamic DNS*):
#: the setup grants them when the firewall offers them, and leaves them out otherwise, since
#: the user manager refuses a privilege it does not know (#440).
PLUGIN_PRIVILEGES: frozenset[str] = frozenset({"page-services-dyndns"})
#: Privileges that only newer releases have: *System: Gateway Groups* came with the gateway group
#: API of 26.7 (#150). Left out where the firewall does not offer them, like plugin privileges.
#: *Services: Captive Portal* (#460) is in the core ACL of every release covered (26.7 image: seen),
#: but is treated the same way, so that a firewall without it cannot fail the setup.
NEWER_PRIVILEGES: frozenset[str] = frozenset(
    {"page-system-gatewaygroups", "page-services-captiveportal"}
)
#: Added while path traces are on (#253, docs: "Path traces").
TRACE_PRIVILEGES: tuple[str, ...] = ("page-diagnostics-traceroute",)
#: Optional extra "accounts" (#349): lets Signalbox list the local users. The user manager has no
#: read-only privilege: this one lets the user change every account too.
ACCOUNTS_PRIVILEGES: tuple[str, ...] = ("page-system-usermanager",)
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

# --- the optional ISC DHCP helper script (#242) -------------------------------------------------

SCRIPT_PATH = "/usr/local/sbin/signalbox-isc-dhcp"
KEY_COMMENT = "signalbox-isc-dhcp"
AUTH_KEYS = "/root/.ssh/authorized_keys"
#: The text installed: the module of the same name, verbatim (a test compares the two).
SCRIPT_TEXT = (Path(__file__).parent / "isc_script.py").read_text()
SSH_COMPARE = (
    "On the console or in a shell on the firewall: ssh-keygen -lf "
    "/etc/ssh/ssh_host_ed25519_key.pub (or the _ecdsa_ / _rsa_ key) prints the fingerprint."
)
INSPECT_SSH = f"""# signalbox-setup: inspect
echo @@python
test -x /usr/local/bin/python3 && echo yes
echo @@script
cat {SCRIPT_PATH} 2>/dev/null
echo @@keys
grep ' {KEY_COMMENT}$' {AUTH_KEYS} 2>/dev/null
echo @@end
"""
INSTALL_SCRIPT = f"""set -e
cat > {SCRIPT_PATH} <<'SIGNALBOX_SCRIPT'
{SCRIPT_TEXT}SIGNALBOX_SCRIPT
chown root:wheel {SCRIPT_PATH}
chmod 0755 {SCRIPT_PATH}
"""
DROP_KEY = f"""mkdir -p /root/.ssh
chmod 700 /root/.ssh
touch {AUTH_KEYS}
grep -v ' {KEY_COMMENT}$' {AUTH_KEYS} > {AUTH_KEYS}.signalbox || true
"""
FINISH_KEY = f"""chmod 600 {AUTH_KEYS}.signalbox
mv {AUTH_KEYS}.signalbox {AUTH_KEYS}
"""


async def _user_rows(http: DeviceHttp, path: str) -> list[dict[str, Any]]:
    """A grid of the user manager API. Releases before 25.1 have none (404): the setup and
    *Fix it* cannot work there, the manual setup of the guide does."""
    try:
        return _rows(await http.post_json(path, ALL))
    except NotFound as exc:
        raise AdapterError(
            f"{path}: not available (HTTP 404): this OPNsense has no user manager API "
            "(OPNsense 25.1 or newer has it)",
            fix="Create the user and its API key by hand (the setup guide, Setup); automatic "
            "setup and Fix it need OPNsense 25.1 or newer.",
            message_id="opnsense.noUserApi",
            fix_id="opnsense.noUserApi.fix",
            params={"path": path},
        ) from exc


def authorized_line(public_key: str) -> str:
    """The ``authorized_keys`` entry: the key may run the script and nothing else."""
    return f'command="{SCRIPT_PATH}",restrict {public_key} {KEY_COMMENT}'


def install_key_script(line: str) -> str:
    return (
        "set -e\n"
        + DROP_KEY
        + f"cat >> {AUTH_KEYS}.signalbox <<'SIGNALBOX_KEY'\n{line}\nSIGNALBOX_KEY\n"
        + FINISH_KEY
    )


REMOVE_SCRIPT = f"set -e\nrm -f {SCRIPT_PATH}\n"
REMOVE_KEY = "set -e\n" + DROP_KEY + FINISH_KEY


def _parts(text: str) -> dict[str, str]:
    parts: dict[str, str] = {}
    name = ""
    for line in text.splitlines():
        if line.startswith("@@"):
            name = line[2:].strip()
            parts[name] = ""
        elif name:
            parts[name] += line + "\n"
    return parts


REMEDIES = (
    Remedy(
        id="privileges",
        read_side=True,
        preview=[PreviewStep(id="privileges", title="Add the missing privileges to the user")],
        title="Add the missing privileges",
        description="Through the API with root's key: adds the privileges of the setup guide "
        "that the user of the stored API key lacks (with those for writing when changes are "
        "allowed). Its other privileges, groups, password and keys stay; nothing else changes.",
    ),
)


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
        raise AdapterError(
            f"{path}: refused: {problems}",
            message_id="opnsense.setupRefused",
            params={"path": path, "detail": problems},
        )
    result = answer.get("result") if isinstance(answer, dict) else None
    raise AdapterError(
        f"{path}: unexpected answer (result {result!r})",
        message_id="opnsense.setupUnexpected",
        params={"path": path, "result": repr(result)},
    )


class OpnsenseSetup:
    def __init__(self, request: SetupRequest) -> None:
        self.request = request
        self.redact = Redactor()
        self.redact.add(request.admin_user, request.admin_secret.get_secret_value())
        raw = str(request.config.get("url") or "").strip()
        if not raw:
            raise AdapterError(
                "give the firewall's address first", message_id="opnsense.setupNoUrl"
            )
        try:
            self.url = device_url(raw)
        except ValueError as exc:
            raise AdapterError(
                str(exc), message_id="opnsense.setupBadUrl", params={"detail": str(exc)}
            ) from None
        if not self.url.startswith("https://"):
            raise AdapterError(
                "the automatic setup sends root's API key only over https",
                message_id="opnsense.setupHttpsOnly",
            )
        self.privileges = sorted(
            {
                *(WRITE_PRIVILEGES if request.allow_writes else READ_PRIVILEGES),
                *(TRACE_PRIVILEGES if request.traces else ()),
                *(ACCOUNTS_PRIVILEGES if "accounts" in request.extras else ()),
            }
        )
        #: The privileges the firewall offers (None: not known), read in :meth:`inspect`.
        self.offered: set[str] | None = None
        self.key: dict[str, str] = {}
        self.ssh_step = request.ssh_step
        self.host = urlsplit(self.url).hostname or ""
        self.ssh_port = request.ssh_port or 22
        self.ssh_key: asyncssh.SSHKey | None = None
        self.ssh_private = ""
        if self.ssh_step and not request.identity_only:
            if request.ssh_secret is None or not request.ssh_secret.get_secret_value():
                raise AdapterError(
                    "enter the SSH password of root for the ISC DHCP script",
                    message_id="opnsense.setupSshPassword",
                )
            self.redact.add(request.ssh_secret.get_secret_value())
            if not request.remove:
                self.ssh_key = asyncssh.generate_private_key("ssh-ed25519")
                self.ssh_key.set_comment(KEY_COMMENT)
                self.ssh_private = self.ssh_key.export_private_key().decode()
                self.redact.add(self.ssh_private, *self.ssh_private.split("\n")[1:-2])

    def http(self) -> DeviceHttp:
        return DeviceHttp(
            self.url,
            pinned_fingerprint=self.request.trust,
            timeout=self.request.timeout,
            auth=(self.request.admin_user, self.request.admin_secret.get_secret_value()),
        )

    async def _offer(self, http: DeviceHttp, user: dict[str, Any] | None) -> None:
        """Remember which privileges the firewall offers and drop the plugin ones it lacks."""
        options = user.get("priv") if user else None
        if not isinstance(options, dict):
            try:
                answer = await http.get_json("/api/auth/user/get")
            except AdapterError:
                answer = None
            blank = answer.get("user") if isinstance(answer, dict) else None
            options = blank.get("priv") if isinstance(blank, dict) else None
        if isinstance(options, dict) and options:
            self.offered = {str(k) for k in options}
            gone = (PLUGIN_PRIVILEGES | NEWER_PRIVILEGES) - self.offered
            self.privileges = [p for p in self.privileges if p not in gone]

    async def inspect(self, http: DeviceHttp) -> tuple[str | None, dict[str, Any]]:
        """The uuid and settings of the user ``signalbox`` (None, {}: there is none)."""
        await http.get_json("/api/core/firmware/status")
        for row in await _user_rows(http, USERS):
            if row.get("name") == LOGIN:
                uuid = str(row.get("uuid", ""))
                answer = await http.get_json(f"/api/auth/user/get/{quote(uuid)}")
                user = answer.get("user") if isinstance(answer, dict) else None
                if not isinstance(user, dict):
                    raise AdapterError(
                        f"/api/auth/user/get/{uuid}: unexpected answer",
                        message_id="opnsense.userAnswer",
                        params={"path": f"/api/auth/user/get/{uuid}"},
                    )
                await self._offer(http, user)
                return uuid, user
        await self._offer(http, None)
        return None, {}

    def steps(self, http: DeviceHttp, uuid: str | None, user: dict[str, Any]) -> list[Step]:
        if user and str(user.get("scope", "user")) == "system":
            raise AdapterError(
                f"the user {LOGIN} is a system user; Signalbox leaves it alone",
                message_id="opnsense.systemUser",
                params={"user": LOGIN},
            )
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
                raise AdapterError(
                    f"{path}: no key in the answer (result {result!r})",
                    message_id="opnsense.noKeyAnswer",
                    params={"path": path, "result": repr(result)},
                )
            self.redact.add(key, secret)
            self.key = {"key": key, "secret": secret}
            old = [
                str(r.get("id") or r.get("key"))
                for r in await _user_rows(http, KEYS)
                if LOGIN in (r.get("username"), r.get("user"), r.get("name"))
                and key not in (r.get("key"), r.get("id"))
                and (r.get("id") or r.get("key"))
            ]
            for ident in old:
                gone = f"/api/auth/user/del_api_key/{quote(ident, safe='=+/')}"
                _saved(gone, await http.post_json(gone, {}))
            return f"older keys deleted: {len(old)}" if old else None

        return run

    def ssh(self) -> PinnedSsh:
        assert self.request.ssh_secret is not None
        return PinnedSsh(
            self.host,
            self.ssh_port,
            "root",
            self.request.ssh_secret.get_secret_value(),
            self.request.ssh_trust,
            self.request.timeout,
        )

    async def inspect_ssh(self, ssh: PinnedSsh) -> tuple[str, bool]:
        """The installed script's text ("" if none) and whether our key line is there."""
        res = await ssh.run(INSPECT_SSH)
        parts = _parts(res.text)
        if "end" not in parts:
            detail = self.redact((res.err or res.text).strip())[:300]
            raise AdapterError(
                "the device did not answer like OPNsense over SSH: " + detail,
                message_id="opnsense.sshNotOpnsense",
                params={"detail": detail},
            )
        if not self.request.remove and not parts.get("python", "").strip():
            raise AdapterError(
                "/usr/local/bin/python3 is missing on the firewall, which the script needs",
                message_id="opnsense.pythonMissing",
            )
        return parts.get("script", ""), bool(parts.get("keys", "").strip())

    def ssh_steps(self, ssh: PinnedSsh, script: str, has_key: bool) -> list[Step]:
        if self.request.remove:
            return [
                Step(
                    "isc-script",
                    f"Delete the script {SCRIPT_PATH}",
                    REMOVE_SCRIPT if script else "",
                    needed=bool(script),
                    action=self._ssh_run(ssh, REMOVE_SCRIPT),
                    note="" if script else "there is no such file",
                ),
                Step(
                    "isc-key",
                    f"Delete Signalbox's SSH key from {AUTH_KEYS}",
                    REMOVE_KEY if has_key else "",
                    needed=has_key,
                    action=self._ssh_run(ssh, REMOVE_KEY),
                    note="" if has_key else "there is no such key",
                ),
            ]
        assert self.ssh_key is not None
        line = authorized_line(self.ssh_key.export_public_key().decode().strip().rsplit(" ", 1)[0])
        return [
            Step(
                "isc-script",
                f"Install the read-only script {SCRIPT_PATH} (root, 0755): it prints only the "
                "DHCP sections of config.xml, without secrets",
                f"cat > {SCRIPT_PATH}  (the file signalbox/adapters/opnsense/isc_script.py)\n"
                f"chown root:wheel {SCRIPT_PATH}\nchmod 0755 {SCRIPT_PATH}",
                needed=script != SCRIPT_TEXT,
                action=self._ssh_run(ssh, INSTALL_SCRIPT),
                note="" if script != SCRIPT_TEXT else "already installed, unchanged",
            ),
            Step(
                "isc-key",
                f"Authorize a new SSH key in {AUTH_KEYS} that can run only that script; older "
                "keys of Signalbox are removed",
                line,
                action=self._ssh_run(ssh, install_key_script(line)),
                note="the private key is stored encrypted in Signalbox and never shown",
            ),
        ]

    def _ssh_run(self, ssh: PinnedSsh, script: str) -> Callable[[], Awaitable[str | None]]:
        async def run() -> str | None:
            res = await ssh.run(script)
            if res.code != 0:
                raise AdapterError(
                    f"SSH command failed ({res.code}): {res.err[:300]}",
                    message_id="opnsense.sshCommandFailed",
                    params={"code": res.code, "detail": res.err[:300]},
                )
            return None

        return run

    async def identities(self) -> SetupPlan:
        """Both identities to confirm, before any password (#290): the HTTPS certificate and,
        with the SSH step, the SSH host key. Nothing is trusted, so no credential is sent."""
        http = self.http()
        try:
            await self.inspect(http)
        except UntrustedCertificate as exc:
            certificate = exc.fingerprint
        except AdapterError as exc:
            raise exc.redacted(self.redact) from None
        else:  # pragma: no cover - without a pin the certificate is never trusted
            raise AdapterError(
                "the certificate was accepted without being confirmed",
                message_id="opnsense.certUnconfirmed",
            )
        finally:
            await http.close()
        ssh_fingerprint: str | None = None
        if self.ssh_step:
            probe = PinnedSsh(self.host, self.ssh_port, "root", "", None, self.request.timeout)
            try:
                async with probe:
                    pass  # pragma: no cover - without a pin the host key is never trusted
            except UntrustedHostKey as exc:
                ssh_fingerprint = exc.fingerprint
        return SetupPlan(
            fingerprint=certificate,
            fingerprint_kind="certificate",
            trusted=False,
            compare=COMPARE,
            ssh_fingerprint=ssh_fingerprint,
            ssh_trusted=False if self.ssh_step else None,
            ssh_compare=SSH_COMPARE if self.ssh_step else "",
        )

    async def plan(self) -> SetupPlan:
        if self.request.identity_only:
            return await self.identities()
        http = self.http()
        ssh_fingerprint: str | None = None
        ssh_trusted: bool | None = None
        try:
            uuid, user = await self.inspect(http)
            steps = plan_steps(self.steps(http, uuid, user), self.redact)
            if self.ssh_step:
                try:
                    async with self.ssh() as ssh:
                        ssh_fingerprint, ssh_trusted = ssh.fingerprint, True
                        script, has_key = await self.inspect_ssh(ssh)
                        steps += plan_steps(self.ssh_steps(ssh, script, has_key), self.redact)
                except UntrustedHostKey as exc:
                    return SetupPlan(
                        fingerprint=http.fingerprint or "",
                        fingerprint_kind="certificate",
                        trusted=True,
                        compare=COMPARE,
                        ssh_fingerprint=exc.fingerprint,
                        ssh_trusted=False,
                        ssh_compare=SSH_COMPARE,
                    )
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
            ssh_fingerprint=ssh_fingerprint,
            ssh_trusted=ssh_trusted,
            ssh_compare=SSH_COMPARE if self.ssh_step else "",
            steps=steps,
        )

    async def apply(self) -> SetupResult:
        http = self.http()
        try:
            uuid, user = await self.inspect(http)
            steps = self.steps(http, uuid, user)
            if self.ssh_step:
                # the host key is checked and the script's state read before anything changes
                async with self.ssh() as ssh:
                    script, has_key = await self.inspect_ssh(ssh)
                    steps += self.ssh_steps(ssh, script, has_key)
                    ok, reports = await run_steps(steps, self.redact)
            else:
                ok, reports = await run_steps(steps, self.redact)
        except (UntrustedCertificate, UntrustedHostKey):
            raise
        except AdapterError as exc:
            raise exc.redacted(self.redact) from None
        finally:
            await http.close()
        if self.request.remove or not ok:
            return SetupResult(ok=ok, steps=reports)
        settings: dict[str, Any] = {"url": self.url}
        secrets = {
            "api_key": SecretStr(self.key["key"]),
            "api_secret": SecretStr(self.key["secret"]),
        }
        if self.ssh_step:
            settings |= {
                "isc_ssh_host_key": self.request.ssh_trust,
                "isc_ssh_port": self.ssh_port,
                "isc_ssh_user": "root",
            }
            secrets["isc_ssh_key"] = SecretStr(self.ssh_private)
        return SetupResult(
            ok=True,
            steps=reports,
            settings=settings,
            secrets=secrets,
            certificate=http.fingerprint,
        )


class OpnsenseFix(OpnsenseSetup):
    """*Fix it* on a stored firewall: the documented privileges for the stored key's user."""

    def __init__(self, request: RemedyRequest) -> None:
        if request.remedy not in {r.id for r in REMEDIES}:
            raise AdapterError(
                f"OPNsense has no remedy {request.remedy!r}",
                message_id="opnsense.noRemedy",
                params={"remedy": repr(request.remedy)},
            )
        super().__init__(
            SetupRequest(
                config={"url": request.config.get("url")},
                admin_user=request.admin_user,
                admin_secret=request.admin_secret,
                allow_writes=request.allow_writes,
                trust=request.trust,
                timeout=request.timeout,
                traces=request.traces,
            )
        )
        stored = request.secrets.get("api_key")
        self.stored_key = stored.get_secret_value() if stored else ""
        for secret in request.secrets.values():
            self.redact.add(secret.get_secret_value())

    async def inspect(self, http: DeviceHttp) -> tuple[str | None, dict[str, Any]]:
        """The uuid and settings of the user the stored API key belongs to."""
        await http.get_json("/api/core/firmware/status")
        if not self.stored_key:
            raise AdapterError(
                "the device has no stored API key", message_id="opnsense.noStoredKey"
            )
        owner = next(
            (
                str(r.get("username") or r.get("user") or r.get("name") or "")
                for r in await _user_rows(http, KEYS)
                if self.stored_key in (r.get("key"), r.get("id"))
            ),
            "",
        )
        if not owner:
            raise AdapterError(
                "the firewall knows no user with the stored API key",
                fix="Set the device up again (device settings: Set up automatically, or the "
                "setup guide): Fix it only adds privileges to the user of the stored key.",
                message_id="opnsense.noKeyUser",
                fix_id="opnsense.noKeyUser.fix",
            )
        for row in await _user_rows(http, USERS):
            if row.get("name") == owner:
                uuid = str(row.get("uuid", ""))
                answer = await http.get_json(f"/api/auth/user/get/{quote(uuid)}")
                user = answer.get("user") if isinstance(answer, dict) else None
                if not isinstance(user, dict):
                    raise AdapterError(
                        f"/api/auth/user/get/{uuid}: unexpected answer",
                        message_id="opnsense.userAnswer",
                        params={"path": f"/api/auth/user/get/{uuid}"},
                    )
                await self._offer(http, user)
                return uuid, {**user, "name": user.get("name") or owner}
        raise AdapterError(
            f"the firewall lists no user {owner!r}",
            message_id="opnsense.noUser",
            params={"user": repr(owner)},
        )

    def steps(self, http: DeviceHttp, uuid: str | None, user: dict[str, Any]) -> list[Step]:
        name = str(user.get("name", ""))
        if name == "root" or str(user.get("scope", "user")) == "system":
            owner: str = name or Label("a system user", "systemUser")
            raise AdapterError(
                f"the stored API key belongs to {owner}; Signalbox changes only a user of its own",
                message_id="opnsense.foreignUser",
                params={"user": owner},
            )
        privs = _selected(user.get("priv"))
        missing = [p for p in self.privileges if p not in privs]
        groups = _selected(user.get("group_memberships"))
        body = {
            "user": {
                "name": name,
                "descr": str(user.get("descr") or ""),
                "priv": ",".join(sorted({*privs, *self.privileges})),
                "group_memberships": ",".join(groups),
            }
        }
        what = "with write access" if self.request.allow_writes else "read-only"
        return [
            Step(
                "privileges",
                f"Add the missing privileges of the setup guide to the user {name} ({what})",
                f"POST /api/auth/user/set/{uuid}\n" + "\n".join(f"+ {p}" for p in missing),
                needed=bool(missing),
                action=self._save(http, f"/api/auth/user/set/{quote(uuid or '')}", body),
                note="" if missing else "it has every documented privilege",
            )
        ]

    async def apply(self) -> SetupResult:
        http = self.http()
        try:
            uuid, user = await self.inspect(http)
            ok, steps = await run_steps(self.steps(http, uuid, user), self.redact)
        except UntrustedCertificate:
            raise
        except AdapterError as exc:
            raise exc.redacted(self.redact) from None
        finally:
            await http.close()
        return SetupResult(ok=ok, steps=steps)
