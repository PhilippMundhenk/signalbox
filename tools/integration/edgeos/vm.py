#!/usr/bin/env python3
"""Run the official VyOS rolling ISO in QEMU for the edgeos integration tests (#432).

Runs on a GitHub Actions runner (KVM, qemu-system-x86, openssh-client), never in the
development sandbox. Standard library only.

    vm.py fetch DIR    download the pinned rolling ISO from the public release page and verify
                       its SHA-256 (the page keeps about 30 builds: when the pinned one is gone,
                       the newest build is used with a warning that shows its hash)
    vm.py start DIR    boot the ISO (live system, nothing is installed), log in on the serial
                       console, create the read user and a small lab configuration, print the
                       IT_EDGEOS_* variables for $GITHUB_ENV
    vm.py stop  DIR    power the VM off

The live system answers on the serial console as vyos/vyos; that password never leaves the
VM (the SSH login of the router is the key-only user ``signalbox`` created here, level operator
where the version has levels). Network, in PCI order: eth0 is the management port and uplink
(QEMU user networking, DHCP client; the runner reaches SSH at 127.0.0.1:8022), eth1 the LAN
(192.0.2.1/24, DHCP server), eth2 carries VLAN 20 (203.0.113.1/24) and an LLDP daemon.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

TAG = "2026.11.25-0017-rolling"  # the newest rolling build on 2026-11-25
ISO = f"vyos-{TAG}-generic-amd64.iso"
#: SHA-256 of the ISO as downloaded on 2026-11-25 (VyOS publishes a minisign signature, no
#: checksum file next to it; empty: not pinned, the hash is reported as a warning).
PINNED_SHA256 = "bc3fd1b8a4ab64cfbadb697134b4e15595d6b7dc945b89581acaec29ef7eb4ed"
RELEASES = "https://github.com/vyos/vyos-nightly-build/releases/download/{tag}/vyos-{tag}-generic-amd64.iso"
LATEST_API = "https://api.github.com/repos/vyos/vyos-nightly-build/releases?per_page=1"

SERIAL_PORT = 4557
SSH_PORT = 8022
MACS = {
    "eth0": "02:00:00:00:0e:00",
    "eth1": "02:00:00:00:0e:01",
    "eth2": "02:00:00:00:0e:02",
}
LIVE_USER = "vyos"
LIVE_PASSWORD = "vyos"  # the documented login of the live system, the VM is thrown away
PROMPT = r"vyos@[\w.-]+:[^\r\n]*\$ ?$"
HOSTNAME = "sb-vyos"
#: what VyOS prints when a configuration command or the commit is refused
CONFIG_ERROR = re.compile(
    r"Commit failed|Set failed|Delete failed|Invalid command|is not valid|Configuration path.*not "
    r"valid|\[ .* \] failed|Traceback|ConfigError|Error:|Failed to commit",
    re.I,
)


def tail(path: Path, lines: int = 60) -> str:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return f"({path} not written)"
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text).replace("\r", "")
    return "\n".join(text.splitlines()[-lines:])


def gh_error(title: str, body: str, level: str = "error") -> None:
    body = body.replace("%", "%25").replace("\r", "").replace("\n", "%0A")
    print(f"::{level} title={title}::{body}", flush=True)


def fail(title: str, detail: str, d: Path | None = None) -> None:
    text = detail
    if d is not None:
        text += "\n--- serial console (last lines) ---\n" + tail(d / "serial.log")
    gh_error(title, text)
    raise SystemExit(f"{title}: {detail}")


def log(msg: str) -> None:
    print(f"[vm {time.strftime('%H:%M:%S')}] {msg}", flush=True)


# --- fetch ---------------------------------------------------------------------------------


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def download(url: str, dest: Path) -> None:
    log(f"GET {url}")
    with urllib.request.urlopen(url, timeout=120) as r, dest.open("wb") as f:
        shutil.copyfileobj(r, f, 1 << 20)


def newest_tag() -> str:
    with urllib.request.urlopen(LATEST_API, timeout=30) as r:
        return str(json.load(r)[0]["tag_name"])


def fetch(d: Path) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    done = d / "iso.json"
    if done.exists():
        return d / json.loads(done.read_text())["file"]
    tag, pinned = TAG, PINNED_SHA256
    iso = d / f"vyos-{tag}.iso"
    try:
        download(RELEASES.format(tag=tag), iso)
    except (OSError, urllib.error.URLError) as exc:
        tag = newest_tag()
        pinned = ""
        gh_error(
            "VyOS pinned build gone",
            f"{TAG} is no longer published ({exc}); using the newest rolling build {tag}. "
            "Pin it in tools/integration/edgeos/vm.py.",
            "warning",
        )
        iso = d / f"vyos-{tag}.iso"
        download(RELEASES.format(tag=tag), iso)
    got = sha256(iso)
    if pinned and got != pinned:
        iso.unlink()
        fail("VyOS ISO checksum", f"SHA-256 {got} != pinned {pinned}")
    level = "notice" if pinned else "warning"
    gh_error("VyOS ISO", f"{tag} SHA-256 {got} ({'pinned' if pinned else 'NOT pinned'})", level)
    done.write_text(json.dumps({"file": iso.name, "tag": tag, "sha256": got}))
    return iso


# --- QEMU and the serial console -----------------------------------------------------------


def qemu(d: Path, iso: Path) -> subprocess.Popen[bytes]:
    args = [
        "qemu-system-x86_64",
        "-machine", "pc,accel=kvm",
        "-cpu", "host",
        "-smp", "2",
        "-m", "2048",
        "-display", "none",
        "-monitor", "none",
        "-chardev",
        f"socket,id=ser0,host=127.0.0.1,port={SERIAL_PORT},server=on,wait=off,"
        f"logfile={d / 'serial.log'},logappend=on",
        "-serial", "chardev:ser0",
        "-cdrom", str(iso),
        "-boot", "d",
        "-netdev", f"user,id=eth0,ipv6=off,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22",
        "-device", f"virtio-net-pci,netdev=eth0,mac={MACS['eth0']}",
        "-netdev", "user,id=eth1,net=10.98.0.0/24,restrict=on,ipv6=off",
        "-device", f"virtio-net-pci,netdev=eth1,mac={MACS['eth1']}",
        "-netdev", "user,id=eth2,net=10.99.0.0/24,restrict=on,ipv6=off",
        "-device", f"virtio-net-pci,netdev=eth2,mac={MACS['eth2']}",
        "-pidfile", str(d / "qemu.pid"),
    ]  # fmt: skip
    log("starting QEMU: " + " ".join(args))
    out = (d / "qemu.log").open("ab")
    return subprocess.Popen(args, stdout=out, stderr=subprocess.STDOUT, start_new_session=True)


class Console:
    """The serial console over QEMU's TCP chardev: wait for text, type text."""

    def __init__(self, d: Path) -> None:
        self.d = d
        self.buf = ""
        self.pos = 0
        self.lock = threading.Lock()
        deadline = time.time() + 30
        while True:
            try:
                self.sock = socket.create_connection(("127.0.0.1", SERIAL_PORT), timeout=5)
                break
            except OSError:
                if time.time() > deadline:
                    fail("serial console", "cannot connect to the QEMU serial port", d)
                time.sleep(0.5)
        self.sock.settimeout(None)
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        while True:
            try:
                data = self.sock.recv(4096)
            except OSError:
                return
            if not data:
                return
            text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", data.decode("utf-8", "replace"))
            with self.lock:
                self.buf += text.replace("\r", "")

    def expect(self, patterns: list[str], timeout: float, what: str, soft: bool = False):  # type: ignore[no-untyped-def]
        deadline = time.time() + timeout
        compiled = [re.compile(p, re.M) for p in patterns]
        while time.time() < deadline:
            with self.lock:
                window = self.buf[self.pos :]
                found = [
                    (m.start(), i, m) for i, c in enumerate(compiled) if (m := c.search(window))
                ]
                if found:
                    _, i, m = min(found, key=lambda x: x[0])
                    self.pos += m.end()
                    return i, m
            time.sleep(0.2)
        if soft:
            return None
        fail(f"serial console: timeout waiting for {what}", f"patterns {patterns}", self.d)
        raise AssertionError  # unreachable

    def send(self, text: str) -> None:
        for i in range(0, len(text), 16):
            self.sock.sendall(text[i : i + 16].encode())
            time.sleep(0.03)

    def run(self, command: str, timeout: float = 120) -> str:
        """Type one shell command, return its output up to a marker (the typed marker is split
        by quotes, so only the printed one matches) and the exit code."""
        marker = secrets.token_hex(4)
        start = self.pos
        self.send(f'{command}; echo __D""ONE{marker}:$?\r')
        found = self.expect([rf"^__DONE{marker}:(\d+)$"], timeout, command)
        assert found is not None
        with self.lock:
            output = self.buf[start : self.pos]
        output = re.sub(rf"__DONE{marker}:\d+\s*$", "", output)
        log(f"console: {command[:100]} -> rc {found[1].group(1)}")
        self.last_rc = int(found[1].group(1))
        return output


def login(con: Console, timeout: float) -> None:
    steps = [r"[a-z]+ login: ?$", r"Password: ?$", PROMPT]
    deadline = time.time() + timeout
    while True:
        if time.time() > deadline:
            fail("serial console: no login", f"no login within {timeout} s", con.d)
        found = con.expect(steps, 30, "the login prompt", soft=True)
        if found is None:
            con.send("\r")
            continue
        if found[0] == 0:
            time.sleep(1)
            con.send(LIVE_USER + "\r")
        elif found[0] == 1:
            con.send(LIVE_PASSWORD + "\r")
        else:
            return


def configure(con: Console, name: str, commands: list[str], required: bool) -> bool:
    """Run configuration commands in one session (a script file, so the console needs no
    configuration prompt) and commit; True when nothing was refused."""
    body = "\n".join(
        [
            "source /opt/vyatta/etc/functions/script-template",
            "configure",
            *commands,
            "commit",
            "exit",
        ]
    )
    path = f"/tmp/sb-{name}.sh"
    con.run(f"cat > {path} <<'SB_EOF'\n{body}\nSB_EOF")
    out = con.run(f"vbash {path} 2>&1", 300)
    log(f"{name}:\n{out[-1500:]}")
    bad = CONFIG_ERROR.search(out) is not None
    if bad:
        gh_error(f"VyOS configuration {name}", out[-2500:], "error" if required else "warning")
        if required:
            fail("VyOS setup", f"configuration step {name} was refused", con.d)
    return not bad


def key_pair(d: Path) -> tuple[Path, str]:
    key = d / "signalbox-key"
    key.unlink(missing_ok=True)
    Path(f"{key}.pub").unlink(missing_ok=True)
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "it", "-f", str(key)], check=True
    )
    parts = Path(f"{key}.pub").read_text().split()
    return key, parts[1]


def host_key_pin() -> str:
    """The SHA-256 of the router's ed25519 host key as hex (what the adapter pins)."""
    for _ in range(30):
        out = subprocess.run(
            ["ssh-keyscan", "-t", "ed25519", "-p", str(SSH_PORT), "127.0.0.1"],
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "ssh-ed25519":
                return hashlib.sha256(base64.b64decode(parts[2])).hexdigest()
        time.sleep(2)
    raise SystemExit("ssh-keyscan: no ed25519 host key")


def start(d: Path) -> None:
    iso = fetch(d)
    tag = json.loads((d / "iso.json").read_text())["tag"]
    (d / "serial.log").unlink(missing_ok=True)
    vm = qemu(d, iso)
    con = Console(d)
    log("boot")
    login(con, 600)
    con.run("true")
    for _ in range(60):  # the configuration is loaded when the router service is up
        if "active" in con.run("systemctl is-active vyos-router || true", 30).split():
            break
        time.sleep(3)
    key, public = key_pair(d)
    configure(
        con,
        "user",
        [
            f"set system host-name {HOSTNAME}",
            "set service ssh port 22",
            "set system login user signalbox authentication public-keys it type ssh-ed25519",
            f"set system login user signalbox authentication public-keys it key {public}",
        ],
        required=True,
    )
    # the level of the setup guide; versions without levels refuse the line, then the user
    # has the rights VyOS gives a user of its own
    level = configure(con, "level", ["set system login user signalbox level operator"], False)
    configure(
        con,
        "lan",
        [
            "set interfaces ethernet eth1 address 192.0.2.1/24",
            "set interfaces ethernet eth1 description LAN",
            "set interfaces ethernet eth2 vif 20 address 203.0.113.1/24",
            "set interfaces ethernet eth2 vif 20 description IoT",
        ],
        required=True,
    )
    configure(
        con,
        "dhcp",
        [
            "set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 subnet-id 1",
            "set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 "
            "option default-router 192.0.2.1",
            "set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 "
            "option name-server 192.0.2.1",
            "set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 "
            "option domain-name lan.example",
            "set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 "
            "range 0 start 192.0.2.100",
            "set service dhcp-server shared-network-name LAN subnet 192.0.2.0/24 "
            "range 0 stop 192.0.2.150",
        ],
        required=False,
    )
    configure(
        con,
        "dns",
        [
            "set service dns forwarding listen-address 192.0.2.1",
            "set service dns forwarding allow-from 192.0.2.0/24",
            "set service dns forwarding name-server 203.0.113.53",
        ],
        required=False,
    )
    configure(
        con, "lldp", ["set service lldp interface eth1", "set service lldp interface eth2"], False
    )
    configure(
        con,
        "nat",
        [
            "set nat source rule 100 outbound-interface name eth0",
            "set nat source rule 100 source address 192.0.2.0/24",
            "set nat source rule 100 translation address masquerade",
        ],
        required=False,
    )
    log(
        con.run(
            "/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands 2>&1 | head -n 80",
            60,
        )
    )
    pin = host_key_pin()
    env = {
        "IT_EDGEOS_URL": f"ssh://127.0.0.1:{SSH_PORT}",
        "IT_EDGEOS_USER": "signalbox",
        "IT_EDGEOS_KEY_FILE": str(key),
        "IT_EDGEOS_HOST_KEY": pin,
        "IT_EDGEOS_HOSTNAME": HOSTNAME,
        "IT_EDGEOS_TAG": tag,
        "IT_EDGEOS_LEVEL": "operator" if level else "none",
    }
    target = os.environ.get("GITHUB_ENV")
    lines = "".join(f"{k}={v}\n" for k, v in env.items())
    if target:
        with open(target, "a") as f:
            f.write(lines)
    else:
        (d / "target.env").write_text(lines)
    log(f"VyOS {tag} is up on 127.0.0.1:{SSH_PORT} ({vm.pid})")


def stop(d: Path) -> None:
    pid_file = d / "qemu.pid"
    if not pid_file.exists():
        return
    with contextlib.suppress(OSError, ValueError):
        os.kill(int(pid_file.read_text().strip()), 9)


def main(argv: list[str]) -> None:
    if len(argv) != 3 or argv[1] not in ("fetch", "start", "stop"):
        raise SystemExit(__doc__)
    d = Path(argv[2]).resolve()
    d.mkdir(parents=True, exist_ok=True)
    {"fetch": fetch, "start": start, "stop": stop}[argv[1]](d)


if __name__ == "__main__":
    main(sys.argv)
