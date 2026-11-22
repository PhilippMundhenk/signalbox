"""The SSH side of a simulated OpenWrt router, for the automatic setup (#231).

An asyncssh server with a root password that runs the scripts of
:mod:`signalbox.adapters.openwrt.provision` against a small model of the router: installed
packages, files, the rpcd configuration (``uci``) and service restarts. Only the commands those
scripts use are understood; anything else fails with exit status 127, as a missing command
would. On ``/etc/init.d/rpcd restart`` the logins that list the ``signalbox`` ACL are handed to
an :class:`~signalbox.sim.openwrt.OpenWrtSim`, so the HTTP simulator accepts the new login
(its password is checked against the md5-crypt hash, as rpcd does).

    async with serve_ssh(OpenWrtSsh(http=sim)) as (port, fingerprint):
        ...
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import re
import shlex
import threading
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import Any

import asyncssh

from signalbox.adapters.openwrt.provision import ACL_PATH
from signalbox.adapters.ssh import host_key_fingerprint
from signalbox.sim.openwrt import OpenWrtSim

ROOT_PASSWORD = "example-root-password"
ALL_PACKAGES = {"uhttpd", "uhttpd-mod-ubus", "rpcd", "rpcd-mod-file", "rpcd-mod-luci"}


def _root_section() -> dict[str, Any]:
    return {
        "type": "login",
        "options": {"username": ["root"], "password": ["$p$root"], "read": ["*"], "write": ["*"]},
    }


@dataclass
class OpenWrtSsh:
    """The router as the setup sees it over SSH; mutate between connections."""

    root_password: str = ROOT_PASSWORD
    #: "apk" (25.12 and later) or "opkg"
    manager: str = "apk"
    installed: set[str] = field(default_factory=lambda: set(ALL_PACKAGES))
    #: the package feeds cannot be reached
    offline: bool = False
    files: dict[str, bytes] = field(default_factory=dict)
    #: rpcd sections in order: name -> {"type": ..., "options": {option: [values]}}
    rpcd: dict[str, dict[str, Any]] = field(default_factory=lambda: {"cfg01": _root_section()})
    restarts: list[str] = field(default_factory=list)
    #: every script received (to check that no secret is sent in clear)
    scripts: list[str] = field(default_factory=list)
    #: the HTTP side that gets the logins on an rpcd restart
    http: OpenWrtSim | None = None
    #: the web server certificate (DER), as px5g writes /etc/uhttpd.crt
    certificate: bytes | None = None
    _next: int = 0x10

    # what the scripts see ---------------------------------------------------------------

    def inspect(self) -> str:
        out = ["@@pm", self.manager]
        if self.manager == "apk":
            out += sorted(self.installed & ALL_PACKAGES)
        else:
            out += sorted(self.installed)
        out.append("@@acl")
        if ACL_PATH in self.files:
            out.append(self.files[ACL_PATH].decode())
        out.append("@@rpcd")
        for name, sec in self.rpcd.items():
            out.append(f"rpcd.{name}={sec['type']}")
            for opt, values in sec["options"].items():
                out.append(f"rpcd.{name}.{opt}=" + " ".join(shlex.quote(v) for v in values))
        out.append("@@end")
        return "\n".join(out) + "\n"

    def sync(self) -> None:
        """rpcd restarted: the HTTP side learns the logins of the Signalbox ACL."""
        if self.http is None:
            return
        self.http.login_hashes = {
            sec["options"]["username"][0]: sec["options"].get("password", [""])[0]
            for sec in self.rpcd.values()
            if sec["type"] == "login"
            and "signalbox" in sec["options"].get("read", [])
            and ACL_PATH in self.files
            and sec["options"].get("username")
        }

    # a tiny sh ----------------------------------------------------------------------------

    def run(self, script: str) -> tuple[int, bytes, str]:
        self.scripts.append(script)
        if script.startswith("# signalbox-setup: inspect"):
            return 0, self.inspect().encode(), ""
        if script.startswith("# signalbox-setup: certificate"):
            return 0, self.certificate or b"", ""
        env: dict[str, str] = {}
        lines = script.splitlines()
        out: list[str] = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            i += 1
            if not line or line.startswith("#") or line == "set -e":
                continue
            heredoc = re.match(r"^cat > (\S+) <<'(\w+)'$", line)
            if heredoc:
                body: list[str] = []
                while i < len(lines) and lines[i] != heredoc.group(2):
                    body.append(lines[i])
                    i += 1
                i += 1
                self.files[heredoc.group(1)] = ("\n".join(body) + "\n").encode()
                continue
            for name, value in env.items():
                line = line.replace(f"${name}", value)
            try:
                code, text = self._command(line, env)
            except (ValueError, KeyError, IndexError) as exc:
                return 1, "\n".join(out).encode(), f"sh: {line}: {exc}"
            out.append(text)
            if code:
                return code, "\n".join(out).encode(), text or f"sh: {line}: failed"
        return 0, "\n".join(o for o in out if o).encode(), ""

    def _command(self, line: str, env: dict[str, str]) -> tuple[int, str]:
        optional = line.endswith("|| true")
        line = line.removesuffix("|| true").strip()
        assign = re.match(r"^(\w+)=\$\(uci add rpcd (\w+)\)$", line)
        if assign:
            name = f"cfg{self._next:02x}"
            self._next += 1
            self.rpcd[name] = {"type": assign.group(2), "options": {}}
            env[assign.group(1)] = name
            return 0, ""
        plain = re.match(r"^(\w+)=(\w+)$", line)
        if plain:
            env[plain.group(1)] = plain.group(2)
            return 0, ""
        words = shlex.split(line)
        if words[:2] == ["mkdir", "-p"] or words[0] == "sleep":
            return 0, ""
        if words[:2] == ["rm", "-f"]:
            self.files.pop(words[2], None)
            return 0, ""
        if len(words) == 2 and words[0].startswith("/etc/init.d/") and words[1] == "restart":
            service = words[0].rsplit("/", 1)[1]
            self.restarts.append(service)
            if service == "rpcd":
                self.sync()
            return 0, ""
        if words[0] in ("apk", "opkg"):
            return self._packages(line)
        if words[0] == "uci":
            code, text = self._uci(words[1:])
            return (0, "") if optional else (code, text)
        return 127, f"sh: {words[0]}: not found"

    def _packages(self, line: str) -> tuple[int, str]:
        if self.offline:
            return 255, "ERROR: unable to fetch the package index"
        words = shlex.split(line.split("&&")[-1])
        self.installed |= set(words[2:])
        return 0, ""

    def _uci(self, words: list[str]) -> tuple[int, str]:
        if words and words[0] == "-q":
            words = words[1:]
        verb, args = words[0], words[1:]
        if verb == "commit":
            return 0, ""
        key, _, value = args[0].partition("=")
        parts = key.split(".")
        if parts[0] != "rpcd" or parts[1] not in self.rpcd:
            return 1, "uci: Entry not found"
        sec = self.rpcd[parts[1]]
        if verb == "delete" and len(parts) == 2:
            del self.rpcd[parts[1]]
        elif verb == "delete":
            if parts[2] not in sec["options"]:
                return 1, "uci: Entry not found"
            del sec["options"][parts[2]]
        elif verb == "set":
            sec["options"][parts[2]] = [value]
        elif verb == "add_list":
            sec["options"].setdefault(parts[2], []).append(value)
        else:
            return 1, f"uci: unknown command {verb}"
        return 0, ""


class _Server(asyncssh.SSHServer):
    def __init__(self, device: OpenWrtSsh) -> None:
        self.device = device

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == "root" and password == self.device.root_password


@asynccontextmanager
async def serve_ssh(device: OpenWrtSsh) -> AsyncIterator[tuple[int, str]]:
    """Serve ``device`` on 127.0.0.1; yields the port and the host key fingerprint."""
    key = asyncssh.generate_private_key("ssh-ed25519")

    async def handle(process: asyncssh.SSHServerProcess[bytes]) -> None:
        if process.command != "sh -s":
            process.stderr.write(b"only sh -s\n")
            process.exit(127)
            return
        script = (await process.stdin.read()).decode()
        code, out, err = device.run(script)
        process.stdout.write(out)
        if err:
            process.stderr.write(err.encode() + b"\n")
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


@contextmanager
def serve_ssh_in_thread(device: OpenWrtSsh) -> Iterator[tuple[int, str]]:
    """:func:`serve_ssh` on an event loop of its own (for synchronous tests and the demo)."""
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
