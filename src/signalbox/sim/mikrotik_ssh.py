"""The SSH side of a simulated RouterOS router, for *Fix it* of the REST service (#267).

An asyncssh server with an admin password that answers the few CLI commands of
:class:`~signalbox.adapters.mikrotik.provision.MikrotikFix` (one command per exec channel, as
RouterOS runs them) against a small model of ``www-ssl`` and the certificate store. Anything
else is ``bad command name``, as RouterOS answers it.

    async with serve_ssh(MikrotikSsh()) as (port, fingerprint):
        ...
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import asyncssh

from signalbox.adapters.ssh import host_key_fingerprint

ADMIN = "admin"
ADMIN_PASSWORD = "example-admin-password"


@dataclass
class MikrotikSsh:
    admin_password: str = ADMIN_PASSWORD
    disabled: bool = True
    #: ``address=`` of www-ssl (empty: from everywhere)
    address: list[str] = field(default_factory=list)
    certificate: str = ""
    #: names of the certificates, and which of them are signed
    certs: dict[str, bool] = field(default_factory=dict)
    #: the address the admin session comes from, as ``/user active`` shows it
    source: str = "192.0.2.50"
    #: how many SSH sessions the router lists for admin (more than one: ambiguous)
    sessions: int = 1
    #: ``/ip service set`` is refused with this text
    refuse_set: str = ""
    #: a RouterOS without ``available-from`` (only ``address``)
    legacy: bool = False
    commands: list[str] = field(default_factory=list)

    def run(self, command: str) -> tuple[int, str]:
        self.commands.append(command)
        if m := re.fullmatch(r":put \[/ip service get www-ssl (\S+)\]", command):
            prop = m.group(1)
            if prop == "disabled":
                return 0, "true" if self.disabled else "false"
            if prop == "available-from" and self.legacy:
                return 0, "failure: no such property"
            if prop in ("address", "available-from"):
                return 0, ";".join(self.address)  # RouterOS prints a list with ;
            if prop == "certificate":
                return 0, self.certificate or "none"
            return 0, "failure: no such property"
        if m := re.fullmatch(r":put \[:len \[/certificate find where name=(\S+)\]\]", command):
            return 0, "1" if m.group(1) in self.certs else "0"
        if command == "/user active print terse where via=ssh":
            rows = []
            for i in range(self.sessions):
                addr = self.source if i == 0 else f"192.0.2.{60 + i}"
                rows.append(f" {i} when=nov/23/2026 name={ADMIN} address={addr} via=ssh group=full")
            return 0, "\n".join(rows)
        if m := re.fullmatch(r"/certificate add name=(\S+) (.*)", command):
            self.certs[m.group(1)] = False
            return 0, ""
        if m := re.fullmatch(r"/certificate sign (\S+)(?: ca=(\S+))?", command):
            name, ca = m.groups()
            if name not in self.certs:
                return 0, "failure: no such item"
            if ca and not self.certs.get(ca):
                return 0, "failure: CA not found"
            self.certs[name] = True
            return 0, ""
        if command.startswith("/ip service set www-ssl "):
            if self.refuse_set:
                return 0, self.refuse_set
            for word in command.split()[4:]:
                key, _, value = word.partition("=")
                if key == "certificate":
                    if value not in self.certs:
                        return 0, "failure: no such item"
                    self.certificate = value
                elif key == "disabled":
                    self.disabled = value == "yes"
                elif key == "address":
                    self.address = [a for a in value.split(",") if a]
            return 0, ""
        return 0, "bad command name"


class _Server(asyncssh.SSHServer):
    def __init__(self, device: MikrotikSsh) -> None:
        self.device = device

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == ADMIN and password == self.device.admin_password


@asynccontextmanager
async def serve_ssh(device: MikrotikSsh) -> AsyncIterator[tuple[int, str]]:
    """Serve ``device`` on 127.0.0.1; yields the port and the host key fingerprint."""
    key = asyncssh.generate_private_key("ssh-ed25519")

    async def handle(process: asyncssh.SSHServerProcess[bytes]) -> None:
        code, out = device.run(process.command or "")
        process.stdout.write(out.encode() + b"\r\n")
        process.exit(code)

    server = await asyncssh.create_server(
        lambda: _Server(device),
        "127.0.0.1",
        0,
        server_host_keys=[key],
        process_factory=handle,
        encoding=None,
    )
    port = server.sockets[0].getsockname()[1]
    try:
        yield port, host_key_fingerprint(key)
    finally:
        server.close()
        await server.wait_closed()
