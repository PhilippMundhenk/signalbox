#!/usr/bin/env python3
"""Run the official MikroTik RouterOS CHR image in QEMU for the integration tests (#139).

Runs on a GitHub Actions runner (KVM, qemu-system-x86, qemu-utils), never in the development
sandbox. Standard library only.

    vm.py fetch   DIR    download the pinned CHR image, verify its SHA-256, unpack it
    vm.py prepare DIR    first boot: set the admin password and the www-ssl certificate on the
                         serial console, configure the rest through the REST API as admin
                         (bridge with VLAN filtering, VLAN 20, DHCP, DNS, the two user groups
                         of docs/adapters/mikrotik.md), shut down (DIR/base.qcow2 + keys.json)
    vm.py start   DIR    boot a throw-away overlay of base.qcow2, wait for the REST API, print
                         the IT_MIKROTIK_* variables for $GITHUB_ENV
    vm.py stop    DIR    power the VM off

Network, in PCI order: ether1 is the management port and uplink (QEMU user networking, DHCP
client 10.0.2.15, member of the interface list ``WAN``; the runner reaches www-ssl at
https://127.0.0.1:8443 through a host port forward), ether2 and ether3 are ports of the bridge
``bridge`` (vlan-filtering): ether2 an access port of the native LAN, ether3 a trunk with VLAN
20 "IoT" tagged. The serial console is logged to DIR/serial.log; every failure prints a GitHub
``::error::`` with its last lines.
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
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

VERSION = "7.25.1"  # the stable channel on 2026-11-22
IMAGE = f"chr-{VERSION}.img"
ARCHIVE = f"{IMAGE}.zip"
#: SHA-256 of the .zip, as downloaded in CI on 2026-11-22 (MikroTik publishes no checksum file
#: next to the image; empty: not pinned, the hash is reported as a warning).
PINNED_SHA256 = "c78e8e24ca78d7f13496140e600702df07fe5c57d1a5d6d025654c8476ed2ed2"
MIRRORS = [
    f"https://download.mikrotik.com/routeros/{VERSION}/",
    f"https://cdn.mikrotik.com/routeros/{VERSION}/",
]
NEWEST = "https://upgrade.mikrotik.com/routeros/NEWESTa7.{channel}"

SERIAL_PORT = 4556
HTTPS_PORT = 8443
SSH_PORT = 8022
URL = f"https://127.0.0.1:{HTTPS_PORT}"
MACS = {
    "ether1": "02:00:00:00:0f:11",
    "ether2": "02:00:00:00:01:02",
    "ether3": "02:00:00:00:01:03",
}
#: login options: no colours, no terminal detection, dumb terminal (no line redraws)
CONSOLE_LOGIN = "admin+cte"
PROMPT = r"\[admin@[^\]\r\n]*\] [^\r\n>]*> ?"
CONSOLE_ERROR = re.compile(
    r"syntax error|bad command name|expected end of command|failure:|invalid value|"
    r"no such item|input does not match|ambiguous value|missing value"
)

#: policies of the two groups, exactly as docs/adapters/mikrotik.md lists them
READ_POLICY = (
    "read,api,rest-api,!write,!policy,!password,!sensitive,!reboot,!test,!sniff,!romon,!local,"
    "!telnet,!ssh,!ftp,!winbox,!web"
)
WRITE_POLICY = (
    "read,write,api,rest-api,sensitive,!policy,!password,!reboot,!test,!sniff,!romon,!local,"
    "!telnet,!ssh,!ftp,!winbox,!web"
)


# --- reporting -----------------------------------------------------------------------------


def tail(path: Path, lines: int = 60) -> str:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return f"({path} not written)"
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text).replace("\r", "")
    return "\n".join(text.splitlines()[-lines:])


def gh_error(title: str, body: str) -> None:
    body = body.replace("%", "%25").replace("\r", "").replace("\n", "%0A")
    print(f"::error title={title}::{body}", flush=True)


def fail(title: str, detail: str, d: Path | None = None) -> None:
    text = detail
    if d is not None:
        text += "\n--- serial console (last lines) ---\n" + tail(d / "serial.log")
    gh_error(title, text)
    raise SystemExit(f"{title}: {detail}")


def log(msg: str) -> None:
    print(f"[vm {time.strftime('%H:%M:%S')}] {msg}", flush=True)


# --- fetch ---------------------------------------------------------------------------------


def _download(url: str, dest: Path) -> None:
    log(f"GET {url}")
    with urllib.request.urlopen(url, timeout=120) as r, dest.open("wb") as f:
        shutil.copyfileobj(r, f, 1 << 20)


def newest() -> str:
    out = []
    for channel in ("stable", "long-term"):
        try:
            with urllib.request.urlopen(NEWEST.format(channel=channel), timeout=30) as r:
                out.append(f"{channel}: {r.read(200).decode(errors='replace').strip()}")
        except (OSError, urllib.error.URLError) as exc:
            out.append(f"{channel}: {exc}")
    return "; ".join(out)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def fetch(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    img = d / IMAGE
    if img.exists():
        log(f"{img} already unpacked")
        return
    packed = d / ARCHIVE
    errors = []
    for mirror in MIRRORS:
        try:
            if not packed.exists():
                _download(mirror + ARCHIVE, packed)
            got = sha256(packed)
            if PINNED_SHA256 and got != PINNED_SHA256:
                packed.unlink()
                raise ValueError(f"SHA-256 {got} != pinned {PINNED_SHA256}")
            if PINNED_SHA256:
                print(f"::notice title=RouterOS CHR image::{ARCHIVE} SHA-256 {got} (pinned)")
            else:
                print(f"::warning title=RouterOS CHR image not pinned::{ARCHIVE} SHA-256 {got}")
            break
        except (OSError, ValueError, urllib.error.URLError) as exc:
            errors.append(f"{mirror}: {exc}")
            log(errors[-1])
    else:
        fail("RouterOS CHR download failed", "\n".join(errors) + "\nnewest: " + newest())
    log("unpacking")
    with zipfile.ZipFile(packed) as z:
        names = z.namelist()
        if IMAGE not in names:
            fail("RouterOS CHR archive", f"{IMAGE} not in {names}")
        with z.open(IMAGE) as src, img.open("wb") as dst:
            shutil.copyfileobj(src, dst, 1 << 20)
    packed.unlink()
    print(f"::notice title=RouterOS newest versions::{newest()}")


# --- QEMU and the serial console -----------------------------------------------------------


def qemu(d: Path, disk: Path) -> subprocess.Popen[bytes]:
    mgmt = (
        "user,id=ether1,ipv6=off,"
        f"hostfwd=tcp:127.0.0.1:{HTTPS_PORT}-:443,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22"
    )
    args = [
        "qemu-system-x86_64",
        "-machine", "pc,accel=kvm",
        "-cpu", "host",
        "-smp", "2",
        "-m", "1024",
        "-display", "none",
        "-monitor", "none",
        "-chardev",
        f"socket,id=ser0,host=127.0.0.1,port={SERIAL_PORT},server=on,wait=off,"
        f"logfile={d / 'serial.log'},logappend=on",
        "-serial", "chardev:ser0",
        "-drive", f"file={disk},if=ide,format=qcow2",
        "-netdev", mgmt,
        "-device", f"virtio-net-pci,netdev=ether1,mac={MACS['ether1']}",
        "-netdev", "user,id=ether2,net=10.98.0.0/24,restrict=on,ipv6=off",
        "-device", f"virtio-net-pci,netdev=ether2,mac={MACS['ether2']}",
        "-netdev", "user,id=ether3,net=10.99.0.0/24,restrict=on,ipv6=off",
        "-device", f"virtio-net-pci,netdev=ether3,mac={MACS['ether3']}",
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
        self.last = time.time()
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
            text = data.decode("utf-8", "replace")
            text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
            with self.lock:
                self.buf += text
                self.last = time.time()

    def expect(
        self, patterns: list[str], timeout: float, what: str, soft: bool = False
    ) -> tuple[int, re.Match[str]] | None:
        deadline = time.time() + timeout
        compiled = [re.compile(p) for p in patterns]
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

    def idle(self, timeout: float, what: str) -> None:
        """Wait until the console shows a prompt and has been quiet for two seconds (a
        command like ``/certificate sign`` shows progress and takes keys meanwhile)."""
        deadline = time.time() + timeout
        prompt = re.compile(PROMPT + r"\s*$")
        time.sleep(1)
        while time.time() < deadline:
            with self.lock:
                quiet = time.time() - self.last > 2
                ready = bool(prompt.search(self.buf[self.pos :]))
            if quiet and ready:
                return
            time.sleep(0.3)
        fail(f"serial console: no prompt after {what}", "timeout", self.d)

    def run(self, command: str, timeout: float = 120) -> str:
        """Type one RouterOS command, wait until it is done, fail on an error message.

        A second line prints a marker (``:put ("__DONE" . "<m>")`` echoes differently from
        what it prints), so the output of the command is everything up to the marker.
        """
        marker = secrets.token_hex(4)
        start = self.pos
        self.send(command + "\r")
        self.idle(timeout, command)
        self.send(f':put ("__DONE" . "{marker}")\r')
        self.expect([rf"__DONE{marker}"], timeout, command)
        with self.lock:
            output = self.buf[start : self.pos]
        if CONSOLE_ERROR.search(output):
            fail("RouterOS console command failed", command + "\n" + output[-2000:], self.d)
        log(f"console: {command}")
        return output


def login(con: Console, password: str, timeout: float) -> None:
    """Log in as admin on the serial console (the first login sets the password)."""
    steps = [
        r"[Ll]ogin: ?$",
        r"Password: ?$",
        r"software license\? \[Y/n\]",
        r"repeat new password> ?$",
        r"new password> ?$",
        PROMPT,
        r"Login failed",
    ]
    deadline = time.time() + timeout
    old = ""  # the first login: no password yet
    while True:
        if time.time() > deadline:
            fail("serial console: no login", f"no login within {timeout} s", con.d)
        found = con.expect(steps, 30, "the login prompt", soft=True)
        if found is None:
            con.send("\r")  # the console may wait for a key before it shows the login
            continue
        i = found[0]
        if i == 0:
            time.sleep(1)
            con.send(CONSOLE_LOGIN + "\r")
        elif i == 1:
            con.send(old + "\r")
            old = password  # a second round (the password was set before) uses it
        elif i == 2:
            con.send("n\r")
        elif i in (3, 4):
            log("first login: setting the admin password")
            con.send(password + "\r")
        elif i == 5:
            return
        else:
            log("login failed, retrying")
    raise AssertionError  # unreachable


# --- the REST API --------------------------------------------------------------------------


def rest(
    user: str, password: str, method: str, path: str, body: Any = None, timeout: float = 60
) -> Any:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(URL + path, data=data, method=method)
    req.add_header("Authorization", f"Basic {auth}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    handler = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.build_opener(handler, urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        text = r.read().decode()
    try:
        return json.loads(text) if text else None
    except ValueError:
        return text


def wait_rest(d: Path, password: str, timeout: float) -> dict[str, Any]:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            res = rest("admin", password, "GET", "/rest/system/resource", timeout=15)
            if isinstance(res, dict):
                return res
            last = f"not an object: {str(res)[:200]}"
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}: {exc.read()[:300]!r}"
        except (OSError, ssl.SSLError) as exc:
            last = repr(exc)
        time.sleep(5)
    fail("the RouterOS REST API does not answer", last, d)
    raise AssertionError


class Admin:
    """REST calls as admin during the preparation; a refused call fails the step."""

    def __init__(self, d: Path, password: str) -> None:
        self.d, self.password = d, password

    def __call__(self, method: str, path: str, body: Any = None) -> Any:
        try:
            answer = rest("admin", self.password, method, path, body)
        except urllib.error.HTTPError as exc:
            fail(
                "RouterOS REST setup call refused",
                f"{method} {path} {json.dumps(body)}\n-> HTTP {exc.code} {exc.read()[:800]!r}",
                self.d,
            )
        log(f"{method} {path} {json.dumps(body)} -> {json.dumps(answer)[:300]}")
        return answer

    def add(self, menu: str, body: dict[str, str]) -> dict[str, Any]:
        row = self("PUT", f"/rest/{menu}", body)
        if not isinstance(row, dict) or ".id" not in row:
            fail("RouterOS REST setup", f"PUT /rest/{menu} did not return the new entry: {row}")
        return row


def rest_setup(d: Path, keys: dict[str, str]) -> None:
    """What a user would type: the bridge, VLAN 20, DHCP, DNS, the Signalbox users."""
    admin = Admin(d, keys["admin"])
    admin.add("interface/list", {"name": "WAN"})
    admin.add("interface/list/member", {"list": "WAN", "interface": "ether1"})
    bridge = admin.add("interface/bridge", {"name": "bridge", "comment": "LAN"})
    admin.add("interface/bridge/port", {"bridge": "bridge", "interface": "ether2", "pvid": "1"})
    admin.add("interface/bridge/port", {"bridge": "bridge", "interface": "ether3"})
    admin.add(
        "interface/bridge/vlan",
        {"bridge": "bridge", "vlan-ids": "20", "tagged": "bridge,ether3", "comment": "IoT"},
    )
    admin.add("interface/vlan", {"name": "iot", "vlan-id": "20", "interface": "bridge"})
    # a tunnel interface (port role, #252) with one peer (#152): the peer's key is derived from
    # a name (a valid key nobody holds the private half of), the interface makes its own
    admin.add(
        "interface/wireguard", {"name": "wg0", "listen-port": "51820", "comment": "site link"}
    )
    peer_key = base64.b64encode(hashlib.sha256(b"signalbox-it-site-b").digest()).decode()
    admin.add(
        "interface/wireguard/peers",
        {
            "interface": "wg0",
            "public-key": peer_key,
            "comment": "site-b",
            "endpoint-address": "203.0.113.20",
            "endpoint-port": "51820",
            "allowed-address": "2001:db8:ff::2/128,203.0.113.0/24",
            "persistent-keepalive": "25s",
        },
    )
    admin.add(
        "ipv6/address", {"address": "2001:db8:ff::1/64", "interface": "wg0", "advertise": "no"}
    )
    # the packet filter (#135): a LAN list, an address list, a forward rule, masquerade and a
    # destination NAT (nothing that would cut the REST access over ether1)
    admin.add("interface/list", {"name": "LAN"})
    admin.add("interface/list/member", {"list": "LAN", "interface": "bridge"})
    admin.add("ip/firewall/address-list", {"list": "ci-trusted", "address": "198.51.100.0/28"})
    admin.add(
        "ip/firewall/filter",
        {
            "chain": "forward",
            "action": "accept",
            "protocol": "tcp",
            "dst-address": "192.0.2.10",
            "dst-port": "443",
            "src-address-list": "ci-trusted",
            "in-interface-list": "WAN",
            "comment": "Signalbox CI: NAS",
        },
    )
    admin.add(
        "ip/firewall/nat",
        {
            "chain": "srcnat",
            "action": "masquerade",
            "out-interface-list": "WAN",
            "comment": "Signalbox CI: masquerade",
        },
    )
    admin.add(
        "ip/firewall/nat",
        {
            "chain": "dstnat",
            "action": "dst-nat",
            "protocol": "tcp",
            "dst-port": "8443",
            "in-interface-list": "WAN",
            "to-addresses": "192.0.2.10",
            "to-ports": "443",
            "comment": "Signalbox CI: NAS web",
        },
    )
    admin.add("ip/address", {"address": "192.0.2.1/24", "interface": "bridge"})
    admin.add("ip/address", {"address": "198.51.100.1/24", "interface": "iot"})
    admin.add(
        "ipv6/address", {"address": "2001:db8:1::1/64", "interface": "bridge", "advertise": "no"}
    )
    admin.add("ip/pool", {"name": "dhcp-lan", "ranges": "192.0.2.100-192.0.2.199"})
    admin.add(
        "ip/dhcp-server",
        {
            "name": "lan",
            "interface": "bridge",
            "address-pool": "dhcp-lan",
            "lease-time": "30m",
            "disabled": "no",
        },
    )
    admin.add(
        "ip/dhcp-server/network",
        {
            "address": "192.0.2.0/24",
            "gateway": "192.0.2.1",
            "dns-server": "192.0.2.1",
            "domain": "home.example",
        },
    )
    admin.add(
        "ip/dhcp-server/lease",
        {
            "address": "192.0.2.10",
            "mac-address": "02:00:00:00:00:10",
            "server": "lan",
            "comment": "printer",
        },
    )
    admin("POST", "/rest/ip/dns/set", {"allow-remote-requests": "yes", "servers": "192.0.2.53"})
    admin.add("ip/dns/static", {"name": "nas.home.example", "address": "192.0.2.10"})
    admin.add(
        "ip/dns/static", {"name": "nas.home.example", "type": "AAAA", "address": "2001:db8:1::10"}
    )
    # VLAN filtering last, as RouterOS recommends (the ports and VLANs are in place)
    admin("PATCH", f"/rest/interface/bridge/{bridge['.id']}", {"vlan-filtering": "yes"})
    admin.add("user/group", {"name": "signalbox-read", "policy": READ_POLICY})
    admin.add("user/group", {"name": "signalbox-write", "policy": WRITE_POLICY})
    admin.add(
        "user", {"name": "signalbox", "group": "signalbox-read", "password": keys["signalbox"]}
    )
    admin.add(
        "user",
        {
            "name": "signalbox-write",
            "group": "signalbox-write",
            "password": keys["signalbox-write"],
        },
    )
    for path in ("/rest/user/group", "/rest/ip/service", "/rest/interface/bridge/vlan"):
        log(f"{path}: {json.dumps(admin('GET', path))[:2000]}")


# --- commands ------------------------------------------------------------------------------


def new_keys() -> dict[str, str]:
    return {u: secrets.token_urlsafe(18) for u in ("admin", "signalbox", "signalbox-write")}


#: the certificate and the service, typed exactly as docs/adapters/mikrotik.md shows them
CONSOLE_SETUP = [
    ":if ([:len [/ip dhcp-client find interface=ether1]] = 0) do={/ip dhcp-client add"
    " interface=ether1}",
    "/certificate add name=signalbox-ca common-name=signalbox-ca days-valid=3650"
    " key-usage=key-cert-sign,crl-sign",
    "/certificate sign signalbox-ca",
    "/certificate add name=signalbox-www common-name=router days-valid=3650"
    " key-usage=digital-signature,key-encipherment,tls-server",
    "/certificate sign signalbox-www ca=signalbox-ca",
    "/ip service set www-ssl certificate=signalbox-www disabled=no address=10.0.2.0/24",
]


def prepare(d: Path) -> None:
    img = d / IMAGE
    if not img.exists():
        fail("prepare", f"{img} missing; run fetch first")
    base = d / "base.qcow2"
    (d / "serial.log").unlink(missing_ok=True)
    subprocess.run(
        ["qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(img), str(base)],
        check=True,
        capture_output=True,
    )
    keys = new_keys()
    vm = qemu(d, base)
    try:
        con = Console(d)
        log("first boot")
        login(con, keys["admin"], 600)
        log(con.run("/system resource print", 60))
        log(con.run("/interface print", 60))
        for command in CONSOLE_SETUP:
            log(con.run(command, 300)[-500:])
        resource = wait_rest(d, keys["admin"], 300)
        log(f"resource: {json.dumps(resource)}")
        print(f"::notice title=RouterOS CHR::{resource.get('version')}")
        rest_setup(d, keys)
        log(con.run("/export terse", 120)[-4000:])
        log("shutting down")
        con.send("/system shutdown\r")
        con.expect([r"\[y/N\]"], 60, "the shutdown question")
        con.send("y\r")
        vm.wait(180)
    except BaseException:
        vm.kill()
        raise
    finally:
        if vm.poll() is None:
            vm.kill()
    (d / "keys.json").write_text(json.dumps(keys, indent=1))
    img.unlink()  # the cache keeps base.qcow2 only
    subprocess.run(["qemu-img", "info", str(base)], check=True)


def start(d: Path) -> None:
    base = d / "base.qcow2"
    keys = json.loads((d / "keys.json").read_text())
    run = d / "run.qcow2"
    run.unlink(missing_ok=True)
    (d / "serial.log").unlink(missing_ok=True)
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", "-b", str(base), "-F", "qcow2", str(run)],
        check=True,
        capture_output=True,
    )
    qemu(d, run)
    resource = wait_rest(d, keys["admin"], 600)
    log(f"resource: {json.dumps(resource)}")
    der = ssl.PEM_cert_to_DER_cert(ssl.get_server_certificate(("127.0.0.1", HTTPS_PORT)))
    env = {
        "IT_MIKROTIK_URL": URL,
        "IT_MIKROTIK_PIN": hashlib.sha256(der).hexdigest(),
        "IT_MIKROTIK_USER": "signalbox",
        "IT_MIKROTIK_PASSWORD": keys["signalbox"],
        "IT_MIKROTIK_WRITE_USER": "signalbox-write",
        "IT_MIKROTIK_WRITE_PASSWORD": keys["signalbox-write"],
        "IT_MIKROTIK_ADMIN_PASSWORD": keys["admin"],
        "IT_MIKROTIK_SSH_PORT": str(SSH_PORT),
        "IT_MIKROTIK_VERSION": str(resource.get("version", "")),
    }
    for name in (
        "IT_MIKROTIK_PASSWORD",
        "IT_MIKROTIK_WRITE_PASSWORD",
        "IT_MIKROTIK_ADMIN_PASSWORD",
    ):
        print(f"::add-mask::{env[name]}")
    target = os.environ.get("GITHUB_ENV")
    lines = "".join(f"{k}={v}\n" for k, v in env.items())
    if target:
        with open(target, "a") as f:
            f.write(lines)
    else:
        (d / "target.env").write_text(lines)
    log("RouterOS is up at " + URL)


def stop(d: Path) -> None:
    pid_file = d / "qemu.pid"
    if not pid_file.exists():
        return
    pid = int(pid_file.read_text().strip())
    try:
        keys = json.loads((d / "keys.json").read_text())
        rest("admin", keys["admin"], "POST", "/rest/system/shutdown", {}, timeout=10)
        for _ in range(60):
            os.kill(pid, 0)
            time.sleep(1)
    except (OSError, ValueError, urllib.error.URLError):
        pass
    with contextlib.suppress(OSError):
        os.kill(pid, 9)


def main(argv: list[str]) -> None:
    if len(argv) != 3 or argv[1] not in ("fetch", "prepare", "start", "stop"):
        raise SystemExit(__doc__)
    d = Path(argv[2]).resolve()
    d.mkdir(parents=True, exist_ok=True)
    {"fetch": fetch, "prepare": prepare, "start": start, "stop": stop}[argv[1]](d)


if __name__ == "__main__":
    main(sys.argv)
