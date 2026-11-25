#!/usr/bin/env python3
"""Run Ubiquiti's UniFi Network application in Docker for the integration tests (#432).

Runs on a GitHub Actions runner (Docker), never in the development sandbox. Standard library
only.

    controller.py start DIR MAJOR   MongoDB and the pinned image of that major version (8, 9 or
                                    10), wait for /status
    controller.py setup DIR MAJOR   the first-run setup through the controller's own API (the
                                    local super administrator, as the setup wizard does), a
                                    read-only local account, the test networks; prints the
                                    IT_UNIFI_* variables for $GITHUB_ENV
    controller.py dump  DIR         write what the classic API answers to the read-only account
                                    to DIR/api-read.json (and as notices)
    controller.py stop  DIR         stop both containers (logs go to DIR/*.log)

The image is linuxserver/unifi-network-application (Ubiquiti's own Debian package in a
maintained community image) with the MongoDB it needs; both pinned by tag and digest. There is
no adopted device: no gateway, switch or access point can run in CI. Passwords are generated
for each run and masked in the log.
"""

from __future__ import annotations

import hashlib
import http.cookiejar
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

#: major version -> image (tag and digest of the multi-architecture image, seen 2026-11-25)
IMAGES = {
    "8": "linuxserver/unifi-network-application:8.6.9"
    "@sha256:f8403a6813b9e0e68fcf622a7f00dbdbd772dfd6a11277fedcb54b816e0eb801",
    "9": "linuxserver/unifi-network-application:9.5.21"
    "@sha256:f45155f97d755373f5ad06abafa59fd2a5c2df690ae5d9e6d22e69548788c11b",
    "10": "linuxserver/unifi-network-application:10.6.109"
    "@sha256:31d2bc6f7df15fd737d7995e3907bf24e106e8b55deae22ad7bdea183c9b2e8b",
}
MONGO = "mongo:7.0.48@sha256:41e8195b2791692695e1dc9bd21cd51d0a3af05fff8ace9304a5c1acf94f1ae1"
NAME = "signalbox-unifi"
DB_NAME = "signalbox-unifi-db"
NET = "signalbox-unifi-net"
PORT = 8443
URL = f"https://127.0.0.1:{PORT}"
ADMIN = "sb-admin"
READER = "sb-reader"
SITE = "default"
#: the test networks: documentation prefixes only
NETWORKS = [
    {"name": "IoT", "vlan": 20, "subnet": "198.51.100.1/24", "start": "198.51.100.100"},
    {"name": "Guest", "vlan": 30, "subnet": "203.0.113.1/24", "start": "203.0.113.100"},
]


def log(msg: str) -> None:
    print(f"[unifi {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "").replace("\n", "%0A")


def notice(title: str, body: str) -> None:
    print(f"::notice title={title}::{escape(body[:4000])}", flush=True)


def container_log(name: str = NAME, lines: int = 60) -> str:
    r = subprocess.run(
        ["docker", "logs", "--tail", str(lines), name], capture_output=True, text=True, check=False
    )
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", r.stdout + r.stderr)
    return text[-12000:]


def fail(title: str, detail: str) -> None:
    body = detail + "\n--- application log (last lines) ---\n" + container_log()
    print(f"::error title={title}::{escape(body)}", flush=True)
    raise SystemExit(f"{title}: {detail}")


_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


class Session:
    """One login session (cookie jar, CSRF token header) against the controller."""

    def __init__(self) -> None:
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_ctx),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            urllib.request.ProxyHandler({}),
        )
        self.headers: dict[str, str] = {}

    def request(
        self, method: str, path: str, body: Any = None, timeout: float = 60
    ) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(URL + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        for k, v in self.headers.items():
            req.add_header(k, v)
        try:
            with self.opener.open(req, timeout=timeout) as r:
                status, text = r.status, r.read().decode(errors="replace")
                token = r.headers.get("X-CSRF-Token")
                if token:
                    self.headers["X-CSRF-Token"] = token
        except urllib.error.HTTPError as exc:
            status, text = exc.code, exc.read().decode(errors="replace")
        try:
            return status, json.loads(text)
        except ValueError:
            return status, text

    def login(self, user: str, password: str) -> tuple[int, Any]:
        return self.request("POST", "/api/login", {"username": user, "password": password})


def generated_password() -> str:
    out = "Sb-"
    while len(out) < 20:
        out += secrets.choice("abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")
    return out + "-9z"


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], check=check, capture_output=True, text=True)


def meta_of(body: Any) -> dict[str, Any]:
    meta = body.get("meta") if isinstance(body, dict) else None
    return meta if isinstance(meta, dict) else {}


def wait_status(timeout: float) -> dict[str, Any]:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            status, body = Session().request("GET", "/status", timeout=10)
            if status == 200 and meta_of(body).get("up"):
                return meta_of(body)
            last = f"HTTP {status}: {str(body)[:300]}"
        except (OSError, ssl.SSLError) as exc:
            last = repr(exc)
        time.sleep(5)
    fail("the UniFi Network application does not answer", last)
    raise AssertionError


# --- start ---------------------------------------------------------------------------------


def start(d: Path, major: str) -> None:
    image = IMAGES[major]
    docker("pull", "-q", MONGO)
    docker("pull", "-q", image)
    for name in (NAME, DB_NAME):
        docker("rm", "-f", name, check=False)
    docker("network", "rm", NET, check=False)
    docker("network", "create", NET)
    db_pass = generated_password()
    print(f"::add-mask::{db_pass}", flush=True)
    init = d / "mongo-init.js"
    init.write_text(
        "db.getSiblingDB('unifi').createUser({user: 'unifi', pwd: '" + db_pass + "', "
        "roles: [{role: 'dbOwner', db: 'unifi'}, {role: 'dbOwner', db: 'unifi_stat'}, "
        "{role: 'dbOwner', db: 'unifi_audit'}]});\n"
    )
    docker(
        "run", "-d", "--name", DB_NAME, "--network", NET,
        "-v", f"{init}:/docker-entrypoint-initdb.d/init-mongo.js:ro",
        MONGO,
    )  # fmt: skip
    time.sleep(15)
    docker(
        "run", "-d", "--name", NAME, "--network", NET, "--stop-timeout", "60",
        "-p", f"127.0.0.1:{PORT}:8443",
        "-e", "PUID=1000", "-e", "PGID=1000", "-e", "TZ=Etc/UTC",
        "-e", f"MONGO_HOST={DB_NAME}", "-e", "MONGO_PORT=27017",
        "-e", "MONGO_DBNAME=unifi", "-e", "MONGO_USER=unifi", "-e", f"MONGO_PASS={db_pass}",
        "-e", "MONGO_AUTHSOURCE=unifi",
        image,
    )  # fmt: skip
    t0 = time.time()
    meta = wait_status(900)
    log(f"application answers after {time.time() - t0:.0f} s: {json.dumps(meta)}")
    (d / "status.json").write_text(json.dumps(meta))
    notice("UniFi Network application", f"{image}\n{json.dumps(meta)}")


# --- setup ---------------------------------------------------------------------------------


def attempt(s: Session, label: str, path: str, bodies: list[dict[str, Any]]) -> None:
    """POST the bodies in turn; the first answer with ``meta.rc == ok`` wins. Else an error with
    every answer (the first run against a new version shows which spelling it wants)."""
    seen: list[str] = []
    for body in bodies:
        status, answer = s.request("POST", path, body)
        if status == 200 and meta_of(answer).get("rc") == "ok":
            log(f"{label}: ok with cmd {body.get('cmd')}")
            return
        seen.append(f"cmd {body.get('cmd')}: HTTP {status}: {str(answer)[:600]}")
    fail(f"UniFi setup: {label}", f"POST {path}\n" + "\n".join(seen))


def setup(d: Path, major: str) -> None:
    meta = wait_status(120)
    admin_password = generated_password()
    reader_password = generated_password()
    for secret in (admin_password, reader_password):
        print(f"::add-mask::{secret}", flush=True)
    s = Session()
    # The first-run wizard ends with this call: the local super administrator the wizard asks
    # for (name, e-mail, password).
    first = {"name": ADMIN, "x_password": admin_password, "email": "ci@example.com"}
    attempt(
        s, "first-run administrator", "/api/cmd/sitemgr", [{"cmd": "add-default-admin", **first}]
    )
    status, answer = s.login(ADMIN, admin_password)
    if status != 200 or meta_of(answer).get("rc") != "ok":
        fail("UniFi setup: login of the new administrator", f"HTTP {status}: {answer}")
    base = f"/api/s/{SITE}"
    account = {
        "name": READER,
        "x_password": reader_password,
        "email": "reader@example.com",
        "role": "readonly",
        "for_sso": False,
        "requires_new_password": False,
        "permissions": [],
    }
    attempt(
        s,
        "read-only account",
        f"{base}/cmd/sitemgr",
        [{"cmd": "create-admin", **account}, {"cmd": "invite-admin", **account}],
    )
    # the test networks (the default network stays as the controller made it)
    refused: dict[str, str] = {}
    for net in NETWORKS:
        row = {
            "name": net["name"], "purpose": "corporate", "vlan_enabled": True, "vlan": net["vlan"],
            "ip_subnet": net["subnet"], "networkgroup": "LAN", "enabled": True,
            "dhcpd_enabled": True, "dhcpd_start": net["start"],
            "dhcpd_stop": str(net["start"]).rsplit(".", 1)[0] + ".199",
            "dhcpd_leasetime": 86400, "domain_name": "lab.example",
        }  # fmt: skip
        status, answer = s.request("POST", f"{base}/rest/networkconf", row)
        if status != 200 or meta_of(answer).get("rc") != "ok":
            refused[str(net["name"])] = f"HTTP {status}: {str(answer)[:500]}"
    if refused:
        notice("UniFi setup: networks refused", json.dumps(refused))
    der = ssl.PEM_cert_to_DER_cert(ssl.get_server_certificate(("127.0.0.1", PORT)))
    env = {
        "IT_UNIFI_URL": URL,
        "IT_UNIFI_PIN": hashlib.sha256(der).hexdigest(),
        "IT_UNIFI_USER": READER,
        "IT_UNIFI_PASSWORD": reader_password,
        "IT_UNIFI_WRITE_USER": ADMIN,
        "IT_UNIFI_WRITE_PASSWORD": admin_password,
        "IT_UNIFI_VERSION": str(meta.get("server_version", "")),
        "IT_UNIFI_MAJOR": major,
        "IT_UNIFI_REFUSED": json.dumps(sorted(refused)),
    }
    lines = "".join(f"{k}={v}\n" for k, v in env.items())
    target = os.environ.get("GITHUB_ENV")
    if target:
        with open(target, "a") as f:
            f.write(lines)
    (d / "target.env").write_text(lines)
    log("UniFi Network application set up at " + URL)


# --- dump ----------------------------------------------------------------------------------

READ_PATHS = [
    "/status",
    "/api/self/sites",
    f"/api/s/{SITE}/stat/sysinfo",
    f"/api/s/{SITE}/stat/health",
    f"/api/s/{SITE}/stat/device",
    f"/api/s/{SITE}/rest/networkconf",
    f"/api/s/{SITE}/rest/wlanconf",
    f"/api/s/{SITE}/rest/portconf",
    f"/api/s/{SITE}/stat/sta",
    f"/api/s/{SITE}/rest/dynamicdns",
    "/integration/v1/info",
    "/integration/v1/sites",
]


def dump(d: Path) -> None:
    s = Session()
    status, answer = s.login(os.environ["IT_UNIFI_USER"], os.environ["IT_UNIFI_PASSWORD"])
    out: dict[str, Any] = {"login": status}
    for path in READ_PATHS:
        status, answer = s.request("GET", path)
        out[path] = {"status": status, "body": answer}
        notice(f"UniFi {path}", f"HTTP {status}: {json.dumps(answer)[:1500]}")
    status, answer = s.request(
        "POST", f"/api/s/{SITE}/rest/networkconf", {"name": "nope", "purpose": "corporate"}
    )
    out["write with the read-only role"] = {"status": status, "body": answer}
    notice("UniFi write with the read-only role", f"HTTP {status}: {json.dumps(answer)[:600]}")
    (d / "api-read.json").write_text(json.dumps(out, indent=1))


def stop(d: Path) -> None:
    (d / "controller.log").write_text(container_log(NAME, 100000))
    (d / "mongo.log").write_text(container_log(DB_NAME, 2000))
    for name in (NAME, DB_NAME):
        docker("stop", name, check=False)


def main(argv: list[str]) -> None:
    cmd = argv[1] if len(argv) > 1 else ""
    ok = (len(argv) == 4 and cmd in ("start", "setup") and argv[3] in IMAGES) or (
        len(argv) == 3 and cmd in ("dump", "stop")
    )
    if not ok:
        raise SystemExit(__doc__)
    d = Path(argv[2]).resolve()
    d.mkdir(parents=True, exist_ok=True)
    if cmd == "start":
        start(d, argv[3])
    elif cmd == "setup":
        setup(d, argv[3])
    elif cmd == "dump":
        dump(d)
    else:
        stop(d)


if __name__ == "__main__":
    main(sys.argv)
