#!/usr/bin/env python3
"""Run TP-Link's Omada Software Controller in Docker for the integration tests (#140).

Runs on a GitHub Actions runner (Docker), never in the development sandbox. Standard library
only.

    controller.py start DIR VER  pull the pinned image of the version (6.3, 5.15 or 5.14), start
                               the controller, wait for /api/info
    controller.py setup DIR    the first-start wizard, two Open API applications (viewer and
                               administrator) and the test site's networks, SSIDs and profile;
                               prints the IT_OMADA_* variables for $GITHUB_ENV
    controller.py stop  DIR    stop it (its log goes to DIR/controller.log)

The image is mbentley/omada-controller, a maintained community image that installs TP-Link's
official Linux package (the .deb) unchanged; it is pinned by version tag and digest. Versions:
6.3 (current), 5.15 and 5.14 (#501). 5.9.31 is not covered: its open-api/applications path answers
"Unsupported request path" (-1600).

The setup uses the calls of the controller's own web UI (read from its scripts): the
administrator (``/api/v2/anon/register``), the wizard (``/api/v2/anon/cmd/wizardConfig``),
the login (``/api/v2/login``, then a ``Csrf-Token`` header and the session cookie), the roles
(``/api/v2/roles-available``) and the Open API applications (``/api/v2/open-api/applications``).
Everything after that goes through the Open API with the administrator application, like
Signalbox. There is no managed hardware: no gateway, switch or access point.
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

#: version line -> image (tag and digest of the multi-architecture image, seen 2026-11-25)
IMAGES = {
    "6.3": "mbentley/omada-controller:6.3.0.111"
    "@sha256:d5d688dc39c8c6d17926d2a090d2ce806e221e00a037e3a43ff8cbc2d61f269b",
    "5.15": "mbentley/omada-controller:5.15.24.19"
    "@sha256:908a4e38ff273b0be77db5525237cf039f724c169f33d3be8b32f3acf34bbe2b",
    "5.14": "mbentley/omada-controller:5.14.32.4"
    "@sha256:879ec82534c76284ba8fabd3ccda5d27eda25b6cb69812466ac8b695d642c5f7",
}
NAME = "signalbox-omada"
PORT = 8043
URL = f"https://127.0.0.1:{PORT}"
ADMIN = "signalbox-admin"
SITE = "Default"
#: the test site: documentation prefixes only
NETWORKS = [
    {"name": "IoT", "vlan": 20},
    {"name": "Guest", "vlan": 30},
]
LAB = {"name": "Lab", "vlan": 40, "gatewaySubnet": "203.0.113.1/24"}


def gh_error(title: str, body: str) -> None:
    body = body.replace("%", "%25").replace("\r", "").replace("\n", "%0A")
    print(f"::error title={title}::{body}", flush=True)


def notice(title: str, body: str) -> None:
    body = body.replace("%", "%25").replace("\r", "").replace("\n", "%0A")
    print(f"::notice title={title}::{body[:4000]}", flush=True)


def log(msg: str) -> None:
    print(f"[omada {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def container_log(lines: int = 60) -> str:
    r = subprocess.run(
        ["docker", "logs", "--tail", str(lines), NAME], capture_output=True, text=True, check=False
    )
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", r.stdout + r.stderr)
    return text[-12000:]


def fail(title: str, detail: str) -> None:
    gh_error(title, detail + "\n--- controller log (last lines) ---\n" + container_log())
    raise SystemExit(f"{title}: {detail}")


_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
_jar = http.cookiejar.CookieJar()
_opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_ctx),
    urllib.request.HTTPCookieProcessor(_jar),
    urllib.request.ProxyHandler({}),
)


def request(
    method: str,
    path: str,
    body: Any = None,
    headers: dict[str, str] | None = None,
    timeout: float = 60,
) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(URL + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with _opener.open(req, timeout=timeout) as r:
            status, text = r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        status, text = exc.code, exc.read().decode(errors="replace")
    try:
        return status, json.loads(text)
    except ValueError:
        return status, text


def ok(method: str, path: str, body: Any = None, headers: dict[str, str] | None = None) -> Any:
    """The ``result`` of a call that must succeed; else an ``::error::`` with the answer."""
    status, answer = request(method, path, body, headers)
    if status != 200 or not isinstance(answer, dict) or answer.get("errorCode") != 0:
        shown = json.dumps(body)[:1500] if body is not None else ""
        fail(f"Omada setup: {method} {path}", f"HTTP {status}: {str(answer)[:2500]}\n{shown}")
    return answer.get("result")


def wait_info(timeout: float, configured: bool | None = None) -> dict[str, Any]:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            status, body = request("GET", "/api/info", timeout=10)
            if status == 200 and isinstance(body, dict) and body.get("errorCode") == 0:
                result: dict[str, Any] = body["result"]
                if configured is None or result.get("configured") == configured:
                    return result
            last = f"HTTP {status}: {str(body)[:300]}"
        except (OSError, ssl.SSLError) as exc:
            last = repr(exc)
        time.sleep(5)
    fail("the Omada controller does not answer", last)
    raise AssertionError


def start(d: Path, version: str) -> None:
    image = IMAGES[version]
    subprocess.run(["docker", "pull", "-q", image], check=True)
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True, check=False)
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            NAME,
            "--stop-timeout",
            "60",
            "-p",
            f"127.0.0.1:{PORT}:{PORT}",
            "-e",
            f"MANAGE_HTTPS_PORT={PORT}",
            "-e",
            "TZ=Etc/UTC",
            image,
        ],
        check=True,
    )
    t0 = time.time()
    info = wait_info(900)
    log(f"controller answers after {time.time() - t0:.0f} s: {json.dumps(info)}")
    (d / "info.json").write_text(json.dumps(info))
    notice("Omada controller", f"{image}\n{json.dumps(info)}")


# --- setup ---------------------------------------------------------------------------------


def password() -> str:
    """A password the controller's strength rules accept: 10 to 64 characters, letters, digits
    and a symbol, no character twice in a row (else "Invalid password.", -30105)."""
    out = "Sb-"
    while len(out) < 19:
        c = secrets.choice("abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        if c != out[-1]:
            out += c
    return out + "-Aa1"


def wizard(oid: str, admin_password: str) -> None:
    info = wait_info(60)
    if not info.get("registeredRoot"):
        ok(
            "POST",
            f"/{oid}/api/v2/anon/register",
            {
                "username": ADMIN,
                "password": admin_password,
                "email": "",
                "allowRemoteBinding": False,
                "language": 1,
            },
        )
        log("administrator created")
    current = ok("GET", f"/{oid}/api/v2/anon/controllerInfo") or {}
    log(f"controller info: {json.dumps(current)[:600]}")
    zone = current.get("timeZone") or "UTC"
    region = current.get("region") or "Germany"
    body = {
        "language": 1,
        "controllerName": "signalbox-ci",
        "timeZone": zone,
        "controllerNotification": False,
        "cloudFirmwareDetection": False,
        "type": 0,
        "region": region,
        "expImprove": False,
        "msp": False,
        "site": {
            "siteName": SITE,
            "scenario": "Home",
            "timeZone": zone,
            "region": region,
            "type": 0,
            "supportES": False,
            "supportL2": True,
        },
        "deviceAccountSetting": {"username": "signalbox-device", "password": password()},
    }
    ok("POST", f"/{oid}/api/v2/anon/cmd/wizardConfig", body)
    wait_info(300, configured=True)
    log("wizard done")


def login(oid: str, admin_password: str) -> dict[str, str]:
    result = ok("POST", f"/{oid}/api/v2/login", {"username": ADMIN, "password": admin_password})
    return {"Csrf-Token": result["token"]}


def application(oid: str, web: dict[str, str], name: str, role: str) -> dict[str, str]:
    roles = ok("GET", f"/{oid}/api/v2/roles-available", headers=web)
    found = roles.get("roles", roles) if isinstance(roles, dict) else roles
    names = [(r.get("name", ""), r.get("id")) for r in found]
    match = next((rid for n, rid in names if n.casefold() == role.casefold()), None) or next(
        (rid for n, rid in names if role.casefold() in n.casefold()), None
    )
    if match is None:
        fail("Omada setup: no such role", f"{role!r} not in {names}")
    body = {"name": name, "mode": 1, "permission": {"roleId": match, "sitePrivilege": 0}}
    base = f"/{oid}/api/v2/open-api/applications"
    ok("POST", base, body, headers=web)
    listed = ok("GET", f"{base}?currentPage=1&currentPageSize=100", headers=web)
    rows = listed.get("data", listed) if isinstance(listed, dict) else listed
    app = next((r for r in rows if r.get("name") == name), None)
    if not app or not app.get("clientId") or not app.get("clientSecret"):
        fail("Omada setup: application not listed", json.dumps(listed)[:2000])
    shown = {k: v for k, v in app.items() if k not in ("clientSecret",)}
    log(f"application {name}: {json.dumps(shown)[:800]}")
    return {"client_id": app["clientId"], "client_secret": app["clientSecret"], "role": role}


class OpenApi:
    """The administrator application, as Signalbox uses it."""

    def __init__(self, oid: str, app: dict[str, str]) -> None:
        self.oid = oid
        result = ok(
            "POST",
            "/openapi/authorize/token?grant_type=client_credentials",
            {"omadacId": oid, "client_id": app["client_id"], "client_secret": app["client_secret"]},
        )
        self.headers = {"Authorization": f"AccessToken={result['accessToken']}"}

    def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        return request(method, f"/openapi/v1/{self.oid}{path}", body, self.headers)

    def ok(self, method: str, path: str, body: Any = None) -> Any:
        return ok(method, f"/openapi/v1/{self.oid}{path}", body, self.headers)

    def rows(self, path: str) -> list[dict[str, Any]]:
        result = self.ok("GET", path + ("&" if "?" in path else "?") + "page=1&pageSize=1000")
        rows: list[dict[str, Any]] = result.get("data", []) if isinstance(result, dict) else result
        return rows


def site_data(api: OpenApi) -> dict[str, Any]:
    """The networks, SSIDs and port profile of the test site; what the controller refused."""
    sites = api.rows("/sites")
    site = next(s for s in sites if s.get("name") == SITE)
    sid = site["siteId"]
    s = f"/sites/{sid}"
    refused: dict[str, Any] = {}
    nets = {n.get("vlan"): n for n in api.rows(f"{s}/lan-networks")}
    for net in NETWORKS:
        if net["vlan"] not in nets:
            body = {**net, "purpose": 0, "igmpSnoopEnable": False}
            api.ok("POST", f"{s}/lan-networks", body)
    nets = {n.get("vlan"): n for n in api.rows(f"{s}/lan-networks")}
    # The native network (the controller's own "Default", 192.168.0.1/24) on a documentation
    # prefix; a PATCH takes the whole network, not just the keys that change.
    native = nets[1]
    if native.get("gatewaySubnet") != "192.0.2.1/24":
        body = {k: v for k, v in native.items() if k not in ("id", "primary", "site")}
        body["gatewaySubnet"] = "192.0.2.1/24"
        body["dhcpSettingsVO"] = {
            "enable": True,
            "ipaddrStart": "192.0.2.100",
            "ipaddrEnd": "192.0.2.199",
            "dhcpns": "auto",
            "leasetime": 120,
        }
        api.ok("PATCH", f"{s}/lan-networks/{native['id']}", body)
    # A network with a gateway address and DHCP. Without a gateway the controller needs the
    # LAN interfaces it gave the VLAN-only networks (else -33515 "LAN interfaces could not be
    # none").
    if LAB["vlan"] not in nets:
        lab = {
            **LAB,
            "purpose": 1,
            "vlanType": 0,
            "igmpSnoopEnable": False,
            "interfaceIds": nets[20].get("interfaceIds") or [],
            "dhcpSettingsVO": {
                "enable": True,
                "ipaddrStart": "203.0.113.100",
                "ipaddrEnd": "203.0.113.199",
                "dhcpns": "manual",
                "priDns": "203.0.113.1",
                "sndDns": "198.51.100.53",
                "leasetime": 1440,
            },
        }
        status, answer = api.call("POST", f"{s}/lan-networks", lab)
        if not (isinstance(answer, dict) and answer.get("errorCode") == 0):
            refused["interface network with DHCP"] = {"status": status, "answer": answer}
    nets = {n.get("vlan"): n for n in api.rows(f"{s}/lan-networks")}
    iot = nets[20]["id"]

    groups = api.ok("GET", f"{s}/wireless-network/wlans")
    group = next(g for g in groups if g.get("primary")) if groups else None
    if group is None:
        fail("Omada setup: no WLAN group", json.dumps(groups))
    gid = group.get("wlanId") or group.get("id")
    ssids = {x.get("name") for x in api.rows(f"{s}/wireless-network/wlans/{gid}/ssids")}
    common = {
        "deviceType": 1,
        "ssidEnable": True,
        "guestNetEnable": False,
        "mloEnable": False,
        "pmfMode": 3,
        "enable11r": False,
        "hidePwd": False,
        "vlanEnable": False,
    }
    psk = {"versionPsk": 2, "encryptionPsk": 3, "gikRekeyPskEnable": False}
    wanted = [
        {**common, "name": "Home", "band": 3, "security": 3, "broadcast": True, "pmfMode": 2,
         "pskSetting": {**psk, "securityKey": "example-home-passphrase"}},
        {**common, "name": "IoT", "band": 1, "security": 3, "broadcast": False,
         "vlanEnable": True, "vlanId": 20,
         "pskSetting": {**psk, "securityKey": "example-iot-passphrase"}},
        {**common, "name": "Guest", "band": 3, "security": 0, "broadcast": True,
         "vlanEnable": True, "vlanId": 30},
    ]  # fmt: skip
    for body in wanted:
        if body["name"] not in ssids:
            api.ok("POST", f"{s}/wireless-network/wlans/{gid}/ssids", body)
    profiles = {p.get("name") for p in api.rows(f"{s}/lan-profiles")}
    if "IoT access" not in profiles:
        body = {
            "name": "IoT access",
            "poe": 2,
            "nativeNetworkId": iot,
            "tagNetworkIds": [],
            "untagNetworkIds": [],
            "dot1x": 1,
            "portIsolationEnable": False,
            "lldpMedEnable": True,
            "bandWidthCtrlType": 0,
            "spanningTreeEnable": False,
            "loopbackDetectEnable": False,
        }
        status, answer = api.call("POST", f"{s}/lan-profiles", body)
        if not (isinstance(answer, dict) and answer.get("errorCode") == 0):
            refused["port profile"] = {"status": status, "answer": answer}
    return {"site_id": sid, "wlan_id": gid, "refused": refused}


def setup(d: Path) -> None:
    info = wait_info(60)
    oid = info["omadacId"]
    admin_password = password()
    print(f"::add-mask::{admin_password}", flush=True)
    wizard(oid, admin_password)
    web = login(oid, admin_password)
    apps = {
        "viewer": application(oid, web, "signalbox-viewer", "Viewer"),
        "admin": application(oid, web, "signalbox-admin", "Admin"),
    }
    for app in apps.values():
        print(f"::add-mask::{app['client_secret']}", flush=True)
    data = site_data(OpenApi(oid, apps["admin"]))
    if data["refused"]:
        notice("Omada setup: refused by the controller", json.dumps(data["refused"]))
    der = ssl.PEM_cert_to_DER_cert(ssl.get_server_certificate(("127.0.0.1", PORT)))
    env = {
        "IT_OMADA_URL": URL,
        "IT_OMADA_PIN": hashlib.sha256(der).hexdigest(),
        "IT_OMADA_USER": apps["viewer"]["client_id"],
        "IT_OMADA_PASSWORD": apps["viewer"]["client_secret"],
        "IT_OMADA_WRITE_USER": apps["admin"]["client_id"],
        "IT_OMADA_WRITE_PASSWORD": apps["admin"]["client_secret"],
        "IT_OMADA_OMADAC_ID": oid,
        "IT_OMADA_SITE_ID": data["site_id"],
        "IT_OMADA_WLAN_ID": data["wlan_id"],
        "IT_OMADA_VERSION": info["controllerVer"],
        "IT_OMADA_REFUSED": json.dumps(sorted(data["refused"])),
    }
    lines = "".join(f"{k}={v}\n" for k, v in env.items())
    target = os.environ.get("GITHUB_ENV")
    if target:
        with open(target, "a") as f:
            f.write(lines)
    (d / "target.env").write_text(lines)
    log("Omada controller set up at " + URL)


def stop(d: Path) -> None:
    (d / "controller.log").write_text(container_log(100000))
    subprocess.run(["docker", "stop", NAME], capture_output=True, check=False)


def main(argv: list[str]) -> None:
    if not (
        (len(argv) == 4 and argv[1] == "start" and argv[3] in IMAGES)
        or (len(argv) == 3 and argv[1] in ("setup", "stop"))
    ):
        raise SystemExit(__doc__)
    d = Path(argv[2]).resolve()
    d.mkdir(parents=True, exist_ok=True)
    if argv[1] == "start":
        start(d, argv[3])
    else:
        {"setup": setup, "stop": stop}[argv[1]](d)


if __name__ == "__main__":
    main(sys.argv)
