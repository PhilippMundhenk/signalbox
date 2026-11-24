#!/usr/bin/env python3
"""Run the official OPNsense nano image in QEMU for the integration tests (#138).

Runs on a GitHub Actions runner (KVM, qemu-system-x86, qemu-utils, mtools, dosfstools,
openssl), never in the development sandbox. Standard library only.

    vm.py fetch   DIR    download the pinned image, verify its SHA-256, unpack it
    vm.py prepare DIR    first boot: update to the newest 26.7.x, preseed config.xml, set up
                         Kea, Unbound and a WireGuard instance through the API, power off
                         (DIR/base.qcow2, keys.json, wireguard.json with the public keys)
    vm.py start   DIR    boot a throw-away overlay of base.qcow2, wait for the API, print the
                         IT_OPNSENSE_* variables for $GITHUB_ENV
    vm.py stop    DIR    power the VM off

Network, in the order of the image's default assignment: vtnet0 is the LAN 192.0.2.1/24 (the
runner reaches the web interface at https://127.0.0.1:8443 through a host port forward), vtnet1
the WAN (QEMU user networking with DHCP and internet access), vtnet2 a trunk carrying VLAN 20
"IoT". The serial console is logged to
DIR/serial.log; every failure prints a GitHub ``::error::`` with its last lines.
"""

from __future__ import annotations

import base64
import bz2
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
from pathlib import Path
from typing import Any

VERSION = "26.7"
IMAGE = f"OPNsense-{VERSION}-nano-amd64.img"
CHECKSUMS = f"OPNsense-{VERSION}-checksums-amd64.sha256"
#: SHA-256 of the .bz2, as listed in the release's checksum file (seen in CI on 2026-11-22).
PINNED_SHA256 = "28d5e2f37e40d87468a924e3006ef10e2ddc6de485b85333d9e3958c84d0cb9d"
MIRRORS = [
    f"https://pkg.opnsense.org/releases/{VERSION}/",
    f"https://mirror.ams1.nl.leaseweb.net/opnsense/releases/{VERSION}/",
    f"https://mirror.dns-root.de/opnsense/releases/{VERSION}/",
]
#: the core version must have the full interface assignment API (addresses since 26.7.6)
MIN_CORE = (26, 7, 6)

SERIAL_PORT = 4555
HTTPS_PORT = 8443
URL = f"https://127.0.0.1:{HTTPS_PORT}"
LAN = "192.0.2.1"
MACS = {"wan": "02:00:00:00:0f:01", "lan": "02:00:00:00:01:00", "trunk": "02:00:00:00:02:00"}
ROOT_PASSWORD = "opnsense"  # the image's documented default; the VM is local to the runner


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


def published_sha256(text: str, name: str) -> str | None:
    """The hash of ``name`` in a checksum file (BSD ``SHA256 (x) = h`` or GNU ``h  x``)."""
    for line in text.splitlines():
        m = re.match(r"SHA256 \((.+)\) = ([0-9a-f]{64})", line.strip())
        if m and m.group(1) == name:
            return m.group(2)
        m = re.match(r"([0-9a-f]{64})\s+\*?(.+)$", line.strip())
        if m and m.group(2) == name:
            return m.group(1)
    return None


def fetch(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    img = d / IMAGE
    if img.exists():
        log(f"{img} already unpacked")
        return
    packed = d / f"{IMAGE}.bz2"
    errors = []
    for mirror in MIRRORS:
        try:
            _download(mirror + CHECKSUMS, d / CHECKSUMS)
            want = published_sha256((d / CHECKSUMS).read_text(), packed.name)
            if want is None:
                raise ValueError(f"{packed.name} is not listed in {CHECKSUMS}")
            if PINNED_SHA256 and want != PINNED_SHA256:
                raise ValueError(f"mirror lists {want}, pinned is {PINNED_SHA256}")
            if not packed.exists():
                _download(mirror + packed.name, packed)
            h = hashlib.sha256()
            with packed.open("rb") as f:
                for block in iter(lambda: f.read(1 << 20), b""):
                    h.update(block)
            if h.hexdigest() != want:
                packed.unlink()
                raise ValueError(f"SHA-256 {h.hexdigest()} != published {want}")
            print(f"::notice title=OPNsense image::{packed.name} SHA-256 {want} ({mirror})")
            break
        except (OSError, ValueError, urllib.error.URLError) as exc:
            errors.append(f"{mirror}: {exc}")
            log(errors[-1])
    else:
        fail("OPNsense image download failed", "\n".join(errors))
    log("unpacking")
    with bz2.open(packed, "rb") as src, img.open("wb") as dst:
        shutil.copyfileobj(src, dst, 1 << 20)
    packed.unlink()


# --- QEMU and the serial console -----------------------------------------------------------


def qemu(d: Path, disk: Path, seed: Path | None = None) -> subprocess.Popen[bytes]:
    lan = (
        "user,id=lan,net=192.0.2.0/24,host=192.0.2.2,dhcpstart=192.0.2.200,ipv6=off,"
        f"restrict=on,hostfwd=tcp:127.0.0.1:{HTTPS_PORT}-{LAN}:443"
    )
    args = [
        "qemu-system-x86_64",
        "-machine", "q35,accel=kvm",
        "-cpu", "host",
        "-smp", "2",
        "-m", "3072",
        "-display", "none",
        "-monitor", "none",
        "-chardev",
        f"socket,id=ser0,host=127.0.0.1,port={SERIAL_PORT},server=on,wait=off,"
        f"logfile={d / 'serial.log'},logappend=on",
        "-serial", "chardev:ser0",
        "-drive", f"file={disk},if=virtio,format=qcow2,cache=unsafe",
        "-netdev", lan,
        "-device", f"virtio-net-pci,netdev=lan,mac={MACS['lan']}",
        "-netdev", "user,id=wan",
        "-device", f"virtio-net-pci,netdev=wan,mac={MACS['wan']}",
        "-netdev", "user,id=trunk,net=10.99.0.0/24,restrict=on",
        "-device", f"virtio-net-pci,netdev=trunk,mac={MACS['trunk']}",
        "-pidfile", str(d / "qemu.pid"),
    ]  # fmt: skip
    if seed is not None:
        args += ["-drive", f"file={seed},if=virtio,format=raw"]
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
            text = data.decode("utf-8", "replace")
            text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
            with self.lock:
                self.buf += text

    def expect(self, patterns: list[str], timeout: float, what: str) -> tuple[int, re.Match[str]]:
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
        fail(f"serial console: timeout waiting for {what}", f"patterns {patterns}", self.d)
        raise AssertionError  # unreachable

    def send(self, text: str) -> None:
        for i in range(0, len(text), 16):
            self.sock.sendall(text[i : i + 16].encode())
            time.sleep(0.02)

    def sh(self, command: str, timeout: float = 120, check: bool = True) -> str:
        """Run a command in /bin/sh on the console; returns its output."""
        marker = secrets.token_hex(4)
        self.send(f"{command}; echo __END{marker}_$?__\r")
        start = self.pos
        _, m = self.expect([rf"__END{marker}_(\d+)__"], timeout, command)
        with self.lock:
            output = self.buf[start : self.pos]
        code = int(m.group(1))
        if check and code != 0:
            fail(f"console command failed ({code})", command + "\n" + output[-3000:], self.d)
        return output


#: answers to the questions of a first boot without a matching interface assignment
FIRST_BOOT = [
    (r"configure LAGGs now\? \[y/N\]", "n\r"),
    (r"configure VLANs now\? \[y/N\]", "n\r"),
    (r"Enter the WAN interface name", "vtnet1\r"),
    (r"Enter the LAN interface name", "vtnet0\r"),
    (r"Enter the Optional interface 1 name", "\r"),
    (r"Do you want to proceed\? \[y/N\]", "y\r"),
]


def login(con: Console, timeout: float) -> None:
    """Wait for the login prompt (answering first-boot questions), log in, open /bin/sh."""
    patterns = [p for p, _ in FIRST_BOOT] + [r"login: ?$", r"login:"]
    deadline = time.time() + timeout
    while True:
        i, _ = con.expect(patterns, max(5.0, deadline - time.time()), "the login prompt")
        if i < len(FIRST_BOOT):
            log(f"first boot question: {FIRST_BOOT[i][0]}")
            con.send(FIRST_BOOT[i][1])
            continue
        break
    time.sleep(2)
    con.send("root\r")
    con.expect([r"Password:"], 60, "the password prompt")
    con.send(ROOT_PASSWORD + "\r")
    con.expect([r"Enter an option:"], 120, "the console menu")
    con.send("8\r")
    con.expect([r"[#$] ?$", r"# "], 60, "a shell prompt")
    con.send("exec /bin/sh\r")
    time.sleep(1)
    con.sh("export PS1='sbx# ' TERM=dumb; stty -echo 2>/dev/null; true", 30)


# --- the preseed ---------------------------------------------------------------------------


def crypt_sha512(secret: str) -> str:
    out = subprocess.run(
        ["openssl", "passwd", "-6", "-stdin"],
        input=secret.encode(),
        capture_output=True,
        check=True,
    )
    return out.stdout.decode().strip()


def new_keys() -> dict[str, dict[str, str]]:
    """API key/secret pairs like OPNsense makes them (base64 of 60 random bytes)."""
    out = {}
    for user in ("root", "signalbox-read", "signalbox-write"):
        key = base64.b64encode(secrets.token_bytes(60)).decode()
        secret = base64.b64encode(secrets.token_bytes(60)).decode()
        out[user] = {"key": key, "secret": secret, "hash": crypt_sha512(secret)}
    return out


def seed_disk(d: Path, keys: dict[str, dict[str, str]]) -> Path:
    """A FAT disk with preseed.py and its input (users, keys as stored hashes)."""
    here = Path(__file__).resolve().parent
    seed = d / "seed.img"
    seed.unlink(missing_ok=True)
    subprocess.run(["truncate", "-s", "16M", str(seed)], check=True)
    subprocess.run(["mkfs.vfat", "-n", "SEED", str(seed)], check=True, capture_output=True)
    data = {
        "users": {u: {"key": k["key"], "hash": k["hash"]} for u, k in keys.items()},
        "privileges": json.loads((here / "privileges.json").read_text()),
    }
    (d / "seed.json").write_text(json.dumps(data, indent=1))
    for src, name in ((here / "preseed.py", "preseed.py"), (d / "seed.json", "seed.json")):
        subprocess.run(["mcopy", "-o", "-i", str(seed), str(src), f"::{name}"], check=True)
    return seed


# --- the API -------------------------------------------------------------------------------


def api(keys: dict[str, str], method: str, path: str, body: Any = None, timeout: float = 60) -> Any:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    auth = base64.b64encode(f"{keys['key']}:{keys['secret']}".encode()).decode()
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
        return json.loads(text)
    except ValueError:
        return text


def wait_api(d: Path, keys: dict[str, str], timeout: float) -> dict[str, Any]:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            status = api(keys, "GET", "/api/core/firmware/status", timeout=15)
            if isinstance(status, dict):
                return status
            last = f"not JSON: {str(status)[:200]}"
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}: {exc.read()[:300]!r}"
        except (OSError, ssl.SSLError) as exc:
            last = repr(exc)
        time.sleep(5)
    fail("the OPNsense API does not answer", last, d)
    raise AssertionError


def checked(keys: dict[str, str], path: str, body: Any, d: Path) -> dict[str, Any]:
    try:
        answer = api(keys, "POST", path, body)
    except urllib.error.HTTPError as exc:
        fail(
            "API setup call failed", f"POST {path} {body}: HTTP {exc.code} {exc.read()[:500]!r}", d
        )
    ok = isinstance(answer, dict) and (
        str(answer.get("result", answer.get("status", ""))).lower() in ("saved", "ok", "done")
    )
    if not ok:
        fail("API setup call refused", f"POST {path} {json.dumps(body)}\n-> {answer}", d)
    log(f"POST {path} -> {answer}")
    return answer  # type: ignore[no-any-return]


def api_setup(d: Path, root: dict[str, str]) -> None:
    """What a user would click: Kea on LAN with a subnet and a reservation, a host override."""
    checked(
        root,
        "/api/kea/dhcpv4/set",
        {"dhcpv4": {"general": {"enabled": "1", "interfaces": "lan", "valid_lifetime": "4000"}}},
        d,
    )
    subnet = checked(
        root,
        "/api/kea/dhcpv4/add_subnet",
        {
            "subnet4": {
                "subnet": "192.0.2.0/24",
                "pools": "192.0.2.100-192.0.2.199",
                "option_data_autocollect": "1",
                "description": "LAN",
            }
        },
        d,
    )
    checked(
        root,
        "/api/kea/dhcpv4/add_reservation",
        {
            "reservation": {
                "subnet": subnet["uuid"],
                "ip_address": "192.0.2.10",
                "hw_address": "02:00:00:00:00:10",
                "hostname": "printer",
                "description": "",
            }
        },
        d,
    )
    checked(root, "/api/kea/service/reconfigure", {}, d)
    override = checked(
        root,
        "/api/unbound/settings/add_host_override",
        {
            "host": {
                "enabled": "1",
                "hostname": "nas",
                "domain": "home.example",
                "rr": "A",
                "server": "192.0.2.10",
                "description": "",
            }
        },
        d,
    )
    # an alias of that override, and "Register DHCP static mappings / leases" on (#386)
    checked(
        root,
        "/api/unbound/settings/add_host_alias",
        {
            "alias": {
                "enabled": "1",
                "host": override["uuid"],
                "hostname": "storage",
                "domain": "home.example",
                "description": "",
            }
        },
        d,
    )
    checked(
        root,
        "/api/unbound/settings/set",
        {
            "unbound": {
                "general": {"regdhcp": "1", "regdhcpstatic": "1", "regdhcpdomain": "lan.example"}
            }
        },
        d,
    )
    checked(root, "/api/unbound/service/reconfigure", {}, d)
    wireguard_setup(d, root)
    firewall_setup(d, root)
    logging_setup(d, root)


def logging_setup(d: Path, root: dict[str, str]) -> None:
    """A remote syslog destination and NetFlow export of the LAN to one collector (#180)."""
    checked(
        root,
        "/api/syslog/settings/add_destination",
        {
            "destination": {
                "enabled": "1",
                "transport": "udp4",
                "hostname": "192.0.2.5",
                "port": "514",
                "level": "info,notice,warn,err,crit,alert,emerg",
                "facility": "",
                "program": "",
                "rfc5424": "0",
                "description": "collector",
            }
        },
        d,
    )
    checked(root, "/api/syslog/service/reconfigure", {}, d)
    checked(
        root,
        "/api/diagnostics/netflow/setconfig",
        {
            "netflow": {
                "capture": {"interfaces": "lan", "version": "v9", "targets": "192.0.2.5:2055"}
            }
        },
        d,
    )


def firewall_setup(d: Path, root: dict[str, str]) -> None:
    """What a user adds on the firewall pages (#135): a host alias, a filter rule of the "new"
    model that passes TCP 8443 to the NAS on LAN, and a port forward from WAN 8443 to it
    (443 on the NAS, no filter rule association)."""
    checked(
        root,
        "/api/firewall/alias/add_item",
        {
            "alias": {
                "enabled": "1",
                "name": "ci_nas",
                "type": "host",
                "content": "192.0.2.10",
                "description": "Signalbox CI NAS",
            }
        },
        d,
    )
    checked(
        root,
        "/api/firewall/filter/add_rule",
        {
            "rule": {
                "enabled": "1",
                "action": "pass",
                "quick": "1",
                "interface": "lan",
                "direction": "in",
                "ipprotocol": "inet",
                "protocol": "TCP",
                "source_net": "any",
                "destination_net": "ci_nas",
                "destination_port": "8443",
                "description": "Signalbox CI: NAS",
            }
        },
        d,
    )
    checked(
        root,
        "/api/firewall/d_nat/add_rule",
        {
            "rule": {
                "interface": "wan",
                "ipprotocol": "inet",
                "protocol": "tcp",
                "destination": {"network": "wanip", "port": "8443"},
                "target": "ci_nas",
                "local-port": "443",
                "descr": "Signalbox CI: NAS web",
            }
        },
        d,
    )
    # these answer {"status": "OK\n\n"}: apply them and look at the answer ourselves
    for path in ("/api/firewall/alias/reconfigure", "/api/firewall/filter/apply"):
        answer = api(root, "POST", path, {})
        log(f"POST {path} -> {answer}")
        if "ok" not in str(answer).lower():
            fail("API setup call refused", f"POST {path} -> {answer}", d)


def wireguard_setup(d: Path, root: dict[str, str]) -> None:
    """A WireGuard instance "s2s" (wg0, 2001:db8:ff::1/64, port 51820) with a site-to-site peer
    "site-b" routing 2001:db8:20::/64 at an endpoint that never answers (#239). Only the
    public keys are kept (wireguard.json); the instance's private key stays on the firewall."""
    own = api(root, "GET", "/api/wireguard/server/key_pair")
    other = api(root, "GET", "/api/wireguard/server/key_pair")
    if not (isinstance(own, dict) and own.get("pubkey") and isinstance(other, dict)):
        fail("WireGuard key pair", f"{str(own)[:200]}", d)
    peer = checked(
        root,
        "/api/wireguard/client/add_client",
        {
            "client": {
                "enabled": "1",
                "name": "site-b",
                "pubkey": other["pubkey"],
                "tunneladdress": "2001:db8:ff::2/128,2001:db8:20::/64",
                "serveraddress": "2001:db8:ffff:20::1",
                "serverport": "51820",
                "keepalive": "25",
            }
        },
        d,
    )
    checked(
        root,
        "/api/wireguard/server/add_server",
        {
            "server": {
                "enabled": "1",
                "name": "s2s",
                "pubkey": own["pubkey"],
                "privkey": own["privkey"],
                "port": "51820",
                "tunneladdress": "2001:db8:ff::1/64",
                "peers": peer["uuid"],
            }
        },
        d,
    )
    checked(root, "/api/wireguard/general/set", {"general": {"enabled": "1"}}, d)
    checked(root, "/api/wireguard/service/reconfigure", {}, d)
    keys = {"server": own["pubkey"], "peer": other["pubkey"]}
    (d / "wireguard.json").write_text(json.dumps(keys, indent=1))


def core_version(text: str) -> tuple[int, ...]:
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not m:
        return ()
    return tuple(int(x or 0) for x in m.groups())


# --- commands ------------------------------------------------------------------------------


def prepare(d: Path) -> None:
    img = d / IMAGE
    if not img.exists():
        fail("prepare", f"{img} missing; run fetch first")
    base = d / "base.qcow2"
    (d / "serial.log").unlink(missing_ok=True)
    subprocess.run(
        ["qemu-img", "convert", "-O", "qcow2", str(img), str(base)], check=True, capture_output=True
    )
    subprocess.run(["qemu-img", "resize", str(base), "8G"], check=True, capture_output=True)
    keys = new_keys()
    seed = seed_disk(d, keys)
    vm = qemu(d, base, seed)
    try:
        con = Console(d)
        log("first boot")
        login(con, 900)
        log(con.sh("opnsense-version; uname -a; ifconfig -l; ls /dev/vtbd*", 60))
        con.sh("mkdir -p /mnt/seed && mount_msdosfs /dev/vtbd1 /mnt/seed", 60)
        log("updating to the newest packages of the release")
        con.sh("pkg update -f", 600)
        out = con.sh("pkg upgrade -y 2>&1 | tail -n 40", 1500)
        log(out[-3000:])
        version = con.sh("opnsense-version", 60)
        log(f"core after the update: {version.strip()}")
        if core_version(version.split("OPNsense", 1)[-1]) < MIN_CORE:
            fail("OPNsense too old", f"core {version.strip()} < {MIN_CORE}", d)
        log(
            con.sh(
                "/usr/local/bin/python3 /mnt/seed/preseed.py /conf/config.xml /mnt/seed/seed.json",
                120,
            )
        )
        con.sh("umount /mnt/seed", 60)
        log("rebooting into the preseeded configuration")
        con.send("reboot\r")
        login(con, 900)
        status = wait_api(d, keys["root"], 600)
        log(f"firmware status: {json.dumps(status)[:500]}")
        api_setup(d, keys["root"])
        log("powering off")
        con.send("poweroff\r")
        vm.wait(300)
    except BaseException:
        vm.kill()
        raise
    finally:
        if vm.poll() is None:
            vm.kill()
    (d / "keys.json").write_text(json.dumps(keys, indent=1))
    seed.unlink(missing_ok=True)
    (d / "seed.json").unlink(missing_ok=True)
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
    status = wait_api(d, keys["root"], 900)
    log(f"firmware status: {json.dumps(status)[:500]}")
    der = ssl.PEM_cert_to_DER_cert(ssl.get_server_certificate(("127.0.0.1", HTTPS_PORT)))
    env = {
        "IT_OPNSENSE_URL": URL,
        "IT_OPNSENSE_PIN": hashlib.sha256(der).hexdigest(),
        "IT_OPNSENSE_USER": keys["signalbox-read"]["key"],
        "IT_OPNSENSE_PASSWORD": keys["signalbox-read"]["secret"],
        "IT_OPNSENSE_WRITE_USER": keys["signalbox-write"]["key"],
        "IT_OPNSENSE_WRITE_PASSWORD": keys["signalbox-write"]["secret"],
        "IT_OPNSENSE_ROOT_KEY": keys["root"]["key"],
        "IT_OPNSENSE_ROOT_SECRET": keys["root"]["secret"],
    }
    wg = json.loads((d / "wireguard.json").read_text())  # public keys only (#239)
    env["IT_OPNSENSE_WG_SERVER"], env["IT_OPNSENSE_WG_PEER"] = wg["server"], wg["peer"]
    for name, value in env.items():
        if not name.startswith("IT_OPNSENSE_WG_") and name not in (
            "IT_OPNSENSE_URL",
            "IT_OPNSENSE_PIN",
        ):
            print(f"::add-mask::{value}")
    target = os.environ.get("GITHUB_ENV")
    lines = "".join(f"{k}={v}\n" for k, v in env.items())
    if target:
        with open(target, "a") as f:
            f.write(lines)
    else:
        (d / "target.env").write_text(lines)
    log("OPNsense is up at " + URL)


def stop(d: Path) -> None:
    pid_file = d / "qemu.pid"
    if not pid_file.exists():
        return
    pid = int(pid_file.read_text().strip())
    try:
        keys = json.loads((d / "keys.json").read_text())
        api(keys["root"], "POST", "/api/core/system/halt", {}, timeout=10)
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
