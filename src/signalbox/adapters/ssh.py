"""SSH to a device with a pinned host key (automatic setup, #231).

Like :mod:`signalbox.adapters.https` for certificates: the host key the device presents is
compared with the fingerprint the user confirmed (``SHA256:<base64>``, as ``ssh-keygen -l``
shows it) inside the key exchange, before any credential is sent. Without a confirmed
fingerprint, or with a different one, the handshake is aborted and
:class:`~signalbox.adapters.UntrustedHostKey` carries the presented fingerprint so the user can
compare it. asyncssh checks that the server owns the private key of the accepted host key.

Nothing from the local machine is used: no ``~/.ssh/config``, no ``known_hosts``, no agent and
no client keys; only the password given for this one connection. Commands are sent as a script
on standard input of ``sh -s``, so nothing secret appears in a process list on the device.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from types import TracebackType
from typing import Any

import asyncssh

from signalbox.adapters import AdapterError, AuthFailed, Unreachable, UntrustedHostKey
from signalbox.adapters.https import REACH_FIX
from signalbox.adapters.provision import same_fingerprint


def host_key_fingerprint(key: asyncssh.SSHKey) -> str:
    """``SHA256:<base64>`` of a host key, as OpenSSH prints it."""
    return str(key.get_fingerprint("sha256"))


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

    def validate_host_public_key(
        self, host: str, addr: str, port: int, key: asyncssh.SSHKey
    ) -> bool:
        self.presented = host_key_fingerprint(key)
        return same_fingerprint(self.presented, self.pin)


class PinnedSsh:
    """``async with PinnedSsh(host, port, user, password, pin) as ssh: await ssh.run(...)``."""

    def __init__(
        self, host: str, port: int, user: str, password: str, pin: str | None, timeout: float
    ) -> None:
        self.host, self.port, self.user = host, port, user
        self._password = password
        self.pin = pin
        self.timeout = timeout
        self._conn: asyncssh.SSHClientConnection | None = None
        self.fingerprint: str | None = None

    async def __aenter__(self) -> PinnedSsh:
        client = _Pinned(self.pin)
        where = f"{self.host}:{self.port}"
        try:
            self._conn, _ = await asyncio.wait_for(
                asyncssh.create_connection(
                    lambda: client,
                    self.host,
                    self.port,
                    username=self.user,
                    password=self._password,
                    known_hosts=([], [], []),  # only validate_host_public_key decides
                    config=None,
                    agent_path=None,
                    client_keys=None,
                    preferred_auth="password,keyboard-interactive",
                    connect_timeout=self.timeout,
                    login_timeout=self.timeout,
                    keepalive_interval=0,
                    gss_auth=False,  # no Kerberos credentials of this machine
                    gss_kex=False,  # a GSS key exchange would skip the host key
                    host_based_auth=False,
                ),
                timeout=self.timeout * 2,
            )
        except asyncssh.HostKeyNotVerifiable:
            self.fingerprint = client.presented
            if client.presented is None:  # pragma: no cover - a host key certificate
                raise AdapterError(f"{where}: the SSH host key cannot be checked") from None
            raise UntrustedHostKey(client.presented, self.pin) from None
        except asyncssh.PermissionDenied:
            raise AuthFailed(
                f"{where}: the device refused the admin login over SSH",
                fix="Check the user name and password, and that the device allows a password "
                "login over SSH for it.",
            ) from None
        except (TimeoutError, OSError, asyncssh.Error) as exc:
            raise Unreachable(
                f"cannot open an SSH connection to {where}: {_reason(exc)}", fix=REACH_FIX
            ) from None
        self.fingerprint = client.presented
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

    async def run(self, script: str, timeout: float | None = None) -> ShellResult:
        """Run a shell script (``sh -s``, script on standard input) and return its output."""
        assert self._conn is not None, "use PinnedSsh as an async context manager"
        limit = timeout or self.timeout
        try:
            proc: Any = await asyncio.wait_for(
                self._conn.run("sh -s", input=script.encode(), encoding=None, check=False),
                timeout=limit,
            )
        except TimeoutError:
            raise Unreachable(f"{self.host}: no answer within {limit:g} s over SSH") from None
        except (OSError, asyncssh.Error) as exc:
            raise Unreachable(f"{self.host}: the SSH session failed: {_reason(exc)}") from None
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
