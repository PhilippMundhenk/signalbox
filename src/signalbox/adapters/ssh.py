"""SSH to a device with a pinned host key (automatic setup, #231).

Like :mod:`signalbox.adapters.https` for certificates: the host key the device presents is
compared with the fingerprint the user confirmed (``SHA256:<base64>``, as ``ssh-keygen -l``
shows it) inside the key exchange, before any credential is sent. Without a confirmed
fingerprint, or with a different one, the handshake is aborted and
:class:`~signalbox.adapters.UntrustedHostKey` carries the presented fingerprint so the user can
compare it. asyncssh checks that the server owns the private key of the accepted host key.

Nothing from the local machine is used: no ``~/.ssh/config``, no ``known_hosts``, no agent and
no client keys; only the password (or the private key) given for this one connection. Commands
are sent as a script on standard input of ``sh -s``, so nothing secret appears in a process list
on the device.

The read side of the Linux integration (#240) uses the same class with a key of its own and pins
the host key as hex SHA-256 (:func:`host_key_sha256`, the form certificate pins have), so the
device form's trust flow works unchanged; both forms of a pin are accepted.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import re
from dataclasses import dataclass
from types import TracebackType
from typing import Any

import asyncssh

from signalbox.adapters import AdapterError, AuthFailed, Unreachable, UntrustedHostKey
from signalbox.adapters.https import REACH_FIX
from signalbox.adapters.provision import same_fingerprint

#: Host key algorithms in order of preference.
HOST_KEY_ALGS = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
]


def host_key_fingerprint(key: asyncssh.SSHKey) -> str:
    """``SHA256:<base64>`` of a host key, as OpenSSH prints it."""
    return str(key.get_fingerprint("sha256"))


def host_key_sha256(key: asyncssh.SSHKey) -> str:
    """The same fingerprint as lower-case hex (64 digits), the form of a certificate pin."""
    return hashlib.sha256(key.public_data).hexdigest()


def sha256_hex(fingerprint: str) -> str | None:
    """``SHA256:<base64>`` as hex, or None when it is not one."""
    text = fingerprint.strip()
    if not text.upper().startswith("SHA256:"):
        return None
    body = text[7:].rstrip("=")
    try:
        raw = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except ValueError:
        return None
    return raw.hex() if len(raw) == 32 else None


_PEM = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.S)


def load_private_key(text: str) -> asyncssh.SSHKey:
    """A private key as pasted into a one-line field: the line breaks may be gone.

    Raises ValueError with a message that does not contain the key.
    """
    found = _PEM.search(text.strip())
    if found:
        body = "".join(found.group(2).split())
        lines = [body[i : i + 70] for i in range(0, len(body), 70)]
        text = "\n".join(
            [f"-----BEGIN {found.group(1)}-----", *lines, f"-----END {found.group(1)}-----", ""]
        )
    try:
        return asyncssh.import_private_key(text)
    except (asyncssh.KeyImportError, ValueError):
        raise ValueError(
            "the private key cannot be read: paste the whole OpenSSH private key without a "
            "passphrase (-----BEGIN OPENSSH PRIVATE KEY----- ... -----END OPENSSH PRIVATE KEY-----)"
        ) from None


_DEFAULT_LOGIN = "the admin login"
_DEFAULT_AUTH_FIX = (
    "Check the user name and password, and that the device allows a password login over SSH for it."
)


@dataclass
class ShellResult:
    code: int
    out: bytes
    err: str

    @property
    def text(self) -> str:
        return self.out.decode("utf-8", "replace")


class _Pinned(asyncssh.SSHClient):
    def __init__(self, pin: str | None) -> None:
        self.pin = pin
        self.presented: str | None = None
        self.presented_hex: str | None = None

    def validate_host_public_key(
        self, host: str, addr: str, port: int, key: asyncssh.SSHKey
    ) -> bool:
        self.presented = host_key_fingerprint(key)
        self.presented_hex = host_key_sha256(key)
        return same_fingerprint(self.presented, self.pin) or same_fingerprint(
            self.presented_hex, self.pin
        )


class PinnedSsh:
    """``async with PinnedSsh(host, port, user, password, pin) as ssh: await ssh.run(...)``.

    ``client_key``: log in with this private key (and the password, if any, as a fallback);
    ``private_key``: the same as OpenSSH PEM text (#242), imported when connecting;
    ``login``: how the refused login is named in the error ("the admin login").
    """

    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        password: str,
        pin: str | None,
        timeout: float,
        *,
        client_key: asyncssh.SSHKey | None = None,
        private_key: str | None = None,
        login: str = _DEFAULT_LOGIN,
        auth_fix: str = _DEFAULT_AUTH_FIX,
        auth_fix_id: str | None = None,
    ) -> None:
        self.host, self.port, self.user = host, port, user
        self._password = password
        self._key = client_key
        #: An OpenSSH private key (PEM text): log in with it instead of the password (#242).
        self._private_key = private_key
        self.pin = pin
        self.timeout = timeout
        self.login = login
        self.auth_fix = auth_fix
        self.auth_fix_id = auth_fix_id or (
            "transport.sshAuth.fix" if auth_fix == _DEFAULT_AUTH_FIX else None
        )
        self._conn: asyncssh.SSHClientConnection | None = None
        self.fingerprint: str | None = None
        #: The presented host key as hex SHA-256 (see :func:`host_key_sha256`).
        self.fingerprint_hex: str | None = None

    async def __aenter__(self) -> PinnedSsh:
        client = _Pinned(self.pin)
        where = f"{self.host}:{self.port}"
        try:
            if self._key is None and self._private_key:
                self._key = asyncssh.import_private_key(self._private_key)
            self._conn, _ = await asyncio.wait_for(
                asyncssh.create_connection(
                    lambda: client,
                    self.host,
                    self.port,
                    username=self.user,
                    password=self._password or None,
                    known_hosts=([], [], []),  # only validate_host_public_key decides
                    config=None,
                    agent_path=None,
                    client_keys=[self._key] if self._key is not None else None,
                    preferred_auth=(
                        "publickey,password,keyboard-interactive"
                        if self._key is not None
                        else "password,keyboard-interactive"
                    ),
                    connect_timeout=self.timeout,
                    login_timeout=self.timeout,
                    keepalive_interval=0,
                    gss_auth=False,  # no Kerberos credentials of this machine
                    gss_kex=False,  # a GSS key exchange would skip the host key
                    host_based_auth=False,
                    # ed25519 first: the key users compare (ssh_host_ed25519_key.pub)
                    server_host_key_algs=HOST_KEY_ALGS,
                ),
                timeout=self.timeout * 2,
            )
        except asyncssh.HostKeyNotVerifiable:
            self.fingerprint = client.presented
            self.fingerprint_hex = client.presented_hex
            if client.presented is None:  # pragma: no cover - a host key certificate
                raise AdapterError(
                    f"{where}: the SSH host key cannot be checked",
                    message_id="transport.sshHostKey",
                    params={"where": where},
                ) from None
            raise UntrustedHostKey(client.presented, self.pin) from None
        except asyncssh.PermissionDenied:
            default = self.login == _DEFAULT_LOGIN
            raise AuthFailed(
                f"{where}: the device refused {self.login} over SSH",
                fix=self.auth_fix,
                fix_id=self.auth_fix_id,
                message_id="transport.sshDeniedAdmin" if default else "transport.sshDenied",
                params={"where": where, "login": self.login},
            ) from None
        except (TimeoutError, OSError, asyncssh.Error, ValueError) as exc:
            raise Unreachable(
                f"cannot open an SSH connection to {where}: {_reason(exc)}",
                fix=REACH_FIX,
                fix_id="transport.reach.fix",
                message_id="transport.sshFailed",
                params={"where": where, "reason": _reason(exc)},
            ) from None
        self.fingerprint = client.presented
        self.fingerprint_hex = client.presented_hex
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._conn is not None:
            self._conn.close()
            with contextlib.suppress(TimeoutError, OSError, asyncssh.Error):
                await asyncio.wait_for(self._conn.wait_closed(), timeout=5)
            self._conn = None

    async def run(
        self, script: str, timeout: float | None = None, command: str = "sh -s", prefix: bytes = b""
    ) -> ShellResult:
        """Run a shell script (``sh -s``, script on standard input) and return its output.

        ``prefix`` is sent on standard input before the script (a sudo password for
        ``sudo -S``)."""
        return await self._exec(command, prefix + script.encode(), timeout)

    async def command(self, command: str, timeout: float | None = None) -> ShellResult:
        """Run one command without input (a key with a forced command runs its own, #242)."""
        return await self._exec(command, None, timeout)

    async def _exec(self, command: str, stdin: bytes | None, timeout: float | None) -> ShellResult:
        assert self._conn is not None, "use PinnedSsh as an async context manager"
        limit = timeout or self.timeout
        try:
            proc: Any = await asyncio.wait_for(
                # no input: close stdin at once (EOF), as a server may wait for it before answering
                self._conn.run(
                    command,
                    input=stdin,
                    stdin=asyncssh.DEVNULL if stdin is None else asyncssh.PIPE,
                    encoding=None,
                    check=False,
                ),
                timeout=limit,
            )
        except TimeoutError:
            raise Unreachable(
                f"{self.host}: no answer within {limit:g} s over SSH",
                message_id="transport.sshTimeout",
                params={"host": self.host, "seconds": f"{limit:g}"},
            ) from None
        except (OSError, asyncssh.Error) as exc:
            raise Unreachable(
                f"{self.host}: the SSH session failed: {_reason(exc)}",
                message_id="transport.sshSession",
                params={"host": self.host, "reason": _reason(exc)},
            ) from None
        out = proc.stdout or b""
        err = proc.stderr or b""
        code = proc.exit_status if proc.exit_status is not None else 255
        return ShellResult(
            code=code,
            out=out if isinstance(out, bytes) else str(out).encode(),
            err=(err.decode("utf-8", "replace") if isinstance(err, bytes) else str(err)).strip(),
        )


def _reason(exc: BaseException) -> str:
    return str(exc) or type(exc).__name__
