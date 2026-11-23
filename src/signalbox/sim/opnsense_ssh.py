"""The SSH side of a simulated OPNsense firewall, for the ISC DHCP script (#242).

An asyncssh server with a root password and root's ``authorized_keys``. The setup's scripts
(:mod:`signalbox.adapters.opnsense.provision`) run against a small model of the filesystem: only
the commands they use are understood, anything else fails with status 127. A client that logs in
with a key whose ``authorized_keys`` entry has ``command="<path>"`` runs that command whatever it
asked for, as sshd does: here the installed script (its text is executed by importing it, so
what the file contains is what answers) reads :data:`SAMPLE_CONFIG`, which holds secrets on
purpose: the answer must contain none of them.

    async with serve_ssh(OpnsenseSsh()) as (port, fingerprint):
        ...
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import re
import shlex
import threading
import types
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field

import asyncssh

from signalbox.adapters.opnsense.provision import AUTH_KEYS, KEY_COMMENT, SCRIPT_PATH
from signalbox.adapters.ssh import host_key_fingerprint

ROOT_PASSWORD = "example-root-password"
#: Values that must never reach Signalbox (the tests look for them in everything it received).
SECRETS = ("S3CRET-root-hash", "S3CRET-api-secret", "S3CRET-ddns-key", "S3CRET-vpn-psk")

SAMPLE_CONFIG = f"""<?xml version="1.0"?>
<opnsense>
  <system>
    <user><name>root</name><password>{SECRETS[0]}</password></user>
  </system>
  <OPNsense><wireguard><key>{SECRETS[3]}</key></wireguard></OPNsense>
  <dhcpd>
    <lan>
      <enable>1</enable>
      <range><from>192.0.2.100</from><to>192.0.2.199</to></range>
      <gateway>192.0.2.1</gateway>
      <domain>home.example</domain>
      <dnsserver>192.0.2.53</dnsserver>
      <dnsserver>198.51.100.53</dnsserver>
      <ntpserver>192.0.2.123</ntpserver>
      <defaultleasetime>3600</defaultleasetime>
      <maxleasetime>7200</maxleasetime>
      <failover_peerip>192.0.2.2</failover_peerip>
      <ddnsdomainkey>{SECRETS[2]}</ddnsdomainkey>
      <ddnsdomainkeyname>ddns</ddnsdomainkeyname>
      <staticmap>
        <mac>02:00:00:00:00:41</mac><ipaddr>192.0.2.41</ipaddr><hostname>printer</hostname>
        <descr>the printer</descr><cid>ignored</cid>
      </staticmap>
      <staticmap>
        <mac>02-00-00-00-00-42</mac><ipaddr>192.0.2.42</ipaddr><hostname>nas</hostname>
      </staticmap>
      <staticmap><mac>not-a-mac</mac><ipaddr>192.0.2.43</ipaddr></staticmap>
    </lan>
    <opt2>
      <enable>1</enable>
      <range><from>203.0.113.100</from><to>203.0.113.150</to></range>
      <dnsserver>203.0.113.1</dnsserver>
      <staticmap>
        <mac>02:00:00:00:00:50</mac><ipaddr>203.0.113.50</ipaddr><hostname>kiosk</hostname>
      </staticmap>
    </opt2>
    <opt3><range><from>198.51.100.100</from><to>198.51.100.120</to></range></opt3>
  </dhcpd>
  <dhcpdv6>
    <lan>
      <enable>1</enable>
      <range><from>2001:db8::100</from><to>2001:db8::1ff</to></range>
      <dnsserver>2001:db8::53</dnsserver>
      <staticmap><duid>00:01:00:01:aa:bb:cc:dd</duid><ipaddrv6>2001:db8::41</ipaddrv6>
        <hostname>printer</hostname></staticmap>
    </lan>
  </dhcpdv6>
  <ipsec><psk>{SECRETS[3]}</psk></ipsec>
</opnsense>
"""


@dataclass
class OpnsenseSsh:
    """The firewall as the setup and the adapter see it over SSH; mutate between connections."""

    root_password: str = ROOT_PASSWORD
    #: /usr/local/bin/python3 exists
    python: bool = True
    config_xml: str = SAMPLE_CONFIG
    files: dict[str, str] = field(default_factory=dict)
    modes: dict[str, str] = field(default_factory=dict)
    #: every script received over a password login (to check that no secret is sent in clear)
    scripts: list[str] = field(default_factory=list)
    #: logins by key: the command each one actually ran
    ran: list[str] = field(default_factory=list)
    #: connections that logged in with a key (their command is forced)
    key_logins: set[int] = field(default_factory=set)

    def key_lines(self) -> list[str]:
        return [x for x in self.files.get(AUTH_KEYS, "").splitlines() if x.strip()]

    def key_ok(self, public_key: str) -> bool:
        blob = public_key.split()[1]
        return any(f" {blob} " in f" {line} " for line in self.key_lines())

    def forced(self) -> str | None:
        for line in self.key_lines():
            m = re.match(r'^command="([^"]*)",restrict ssh-', line)
            if m:
                return m.group(1)
        return None

    # the forced command --------------------------------------------------------------------

    def forced_command(self) -> tuple[int, bytes, str]:
        path = self.forced()
        self.ran.append(path or "")
        text = self.files.get(path or "")
        if path is None or text is None:
            return 127, b"", f"sh: {path}: not found"
        module = types.ModuleType("signalbox_isc_dhcp")
        exec(compile(text, path, "exec"), module.__dict__)

        try:
            return (
                0,
                (json.dumps(module.extract(self.config_xml), sort_keys=True) + "\n").encode(),
                "",
            )
        except Exception as exc:  # the script printed a traceback and exited with 1
            return 1, b"", type(exc).__name__

    # a tiny sh ----------------------------------------------------------------------------

    def run(self, script: str) -> tuple[int, bytes, str]:
        self.scripts.append(script)
        if script.startswith("# signalbox-setup: inspect"):
            return 0, self.inspect().encode(), ""
        lines = script.splitlines()
        out: list[str] = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            i += 1
            if not line or line.startswith("#") or line == "set -e":
                continue
            heredoc = re.match(r"^cat (>>?) (\S+) <<'(\w+)'$", line)
            if heredoc:
                body: list[str] = []
                while i < len(lines) and lines[i] != heredoc.group(3):
                    body.append(lines[i])
                    i += 1
                i += 1
                text = "\n".join(body) + "\n"
                path = heredoc.group(2)
                self.files[path] = (
                    self.files.get(path, "") if heredoc.group(1) == ">>" else ""
                ) + text
                continue
            try:
                code, text = self._command(line)
            except (ValueError, KeyError, IndexError) as exc:
                return 1, "\n".join(out).encode(), f"sh: {line}: {exc}"
            out.append(text)
            if code:
                return code, "\n".join(out).encode(), text or f"sh: {line}: failed"
        return 0, "\n".join(o for o in out if o).encode(), ""

    def inspect(self) -> str:
        keys = [x for x in self.key_lines() if x.endswith(f" {KEY_COMMENT}")]
        return (
            "@@python\n"
            + ("yes\n" if self.python else "")
            + "@@script\n"
            + self.files.get(SCRIPT_PATH, "")
            + "@@keys\n"
            + "".join(f"{x}\n" for x in keys)
            + "@@end\n"
        )

    def _command(self, line: str) -> tuple[int, str]:
        optional = line.endswith("|| true")
        line = line.removesuffix("|| true").strip()
        grep = re.match(r"^grep -v '(.*)' (\S+) > (\S+)$", line)
        if grep:
            pattern, source, target = grep.groups()
            keep = [x for x in self.files.get(source, "").splitlines() if not re.search(pattern, x)]
            self.files[target] = "".join(f"{x}\n" for x in keep)
            return (0, "") if keep or optional else (1, "")
        words = shlex.split(line)
        if words[:2] == ["mkdir", "-p"]:
            return 0, ""
        if words[0] == "touch":
            self.files.setdefault(words[1], "")
            return 0, ""
        if words[0] == "chmod":
            self.modes[words[2]] = words[1]
            return 0, ""
        if words[0] == "chown":
            return 0, ""
        if words[:2] == ["rm", "-f"]:
            self.files.pop(words[2], None)
            return 0, ""
        if words[0] == "mv":
            self.files[words[2]] = self.files.pop(words[1])
            if words[1] in self.modes:
                self.modes[words[2]] = self.modes.pop(words[1])
            return 0, ""
        return 127, f"sh: {words[0]}: not found"


class _Server(asyncssh.SSHServer):
    def __init__(self, device: OpnsenseSsh) -> None:
        self.device = device
        self.conn: asyncssh.SSHServerConnection | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.conn = conn

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == "root" and password == self.device.root_password

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        ok = username == "root" and self.device.key_ok(key.export_public_key().decode())
        if ok:
            self.device.key_logins.add(id(self.conn))
        return ok


@asynccontextmanager
async def serve_ssh(device: OpnsenseSsh) -> AsyncIterator[tuple[int, str]]:
    """Serve ``device`` on 127.0.0.1; yields the port and the host key fingerprint."""
    key = asyncssh.generate_private_key("ssh-ed25519")

    async def handle(process: asyncssh.SSHServerProcess[bytes]) -> None:
        if id(process.channel.get_connection()) in device.key_logins:
            # sshd runs the forced command, whatever the client asked for
            code, out, err = device.forced_command()
        elif process.command == "sh -s":
            code, out, err = device.run((await process.stdin.read()).decode())
        else:
            code, out, err = 127, b"", "only sh -s"
        process.stdout.write(out)
        if err:
            process.stderr.write(err.encode() + b"\n")
        process.exit(code)

    server = await asyncssh.create_server(
        lambda: _Server(device),
        "127.0.0.1",
        0,
        process_factory=handle,
        server_host_keys=[key],
        encoding=None,
    )
    port = server.sockets[0].getsockname()[1]
    try:
        yield port, host_key_fingerprint(key)
    finally:
        server.close()
        await server.wait_closed()


@contextmanager
def serve_ssh_in_thread(device: OpnsenseSsh) -> Iterator[tuple[int, str]]:
    """:func:`serve_ssh` on an event loop of its own (for synchronous tests)."""
    loop = asyncio.new_event_loop()
    ready: concurrent.futures.Future[tuple[int, str]] = concurrent.futures.Future()
    stop = asyncio.Event()

    async def main() -> None:
        async with serve_ssh(device) as served:
            ready.set_result(served)
            await stop.wait()

    thread = threading.Thread(target=loop.run_until_complete, args=(main(),), daemon=True)
    thread.start()
    try:
        yield ready.result(timeout=10)
    finally:
        loop.call_soon_threadsafe(stop.set)
        thread.join(timeout=10)
        loop.close()
