"""Discovery probe of OpenWrt (#203), without credentials.

1. ``POST https://<host>/ubus`` (then ``http://<host>/ubus``) with a JSON-RPC ``call`` of
   ``system board`` in the null session ``000…0``: rpcd answers it with JSON-RPC 2.0, normally
   ``-32002 Access denied`` (no session). That answer is what makes it OpenWrt; nothing is
   logged in. Should the ACL allow the null session to read the board, model and release
   are taken from it.
2. Without ubus over HTTP: ``GET /cgi-bin/luci/`` and look for LuCI's login page; the candidate
   then says which package is missing.
"""

from __future__ import annotations

import json
from typing import Any

from signalbox.discovery import Candidate, HostProbe, ProbeResponse
from signalbox.model import DeviceRole

NULL_SESSION = "0" * 32
BOARD = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "call",
        "params": [NULL_SESSION, "system", "board", {}],
    }
).encode()
ACCESS_DENIED = -32002


def _rpc(answer: ProbeResponse | None) -> dict[str, Any] | None:
    data = answer.json() if answer is not None else None
    if not isinstance(data, dict) or data.get("jsonrpc") != "2.0":
        return None
    if "result" not in data and not isinstance(data.get("error"), dict):
        return None
    return data


def _board(data: dict[str, Any]) -> tuple[str | None, str | None]:
    result = data.get("result")
    if not (isinstance(result, list) and len(result) > 1 and isinstance(result[1], dict)):
        return None, None
    board = result[1]
    release = board.get("release")
    release = release if isinstance(release, dict) else {}
    model = board.get("model") if isinstance(board.get("model"), str) else None
    version = release.get("version") if isinstance(release.get("version"), str) else None
    return model, version


async def discover(probe: HostProbe) -> Candidate | None:
    ports = {"https": probe.port("openwrt.https", 443), "http": probe.port("openwrt.http", 80)}
    for scheme in ("https", "http"):
        answer = await probe.post(
            scheme,
            ports[scheme],
            "/ubus",
            content=BOARD,
            headers={"Content-Type": "application/json"},
        )
        data = _rpc(answer)
        if data is None:
            continue
        model, version = _board(data)
        return Candidate(
            address=probe.host,
            role=DeviceRole.AP,
            config={"url": probe.origin("https", ports["https"])},
            vendor="OpenWrt",
            model=model,
            name=model or "OpenWrt",
            firmware=version,
            evidence=f"ubus JSON-RPC on {scheme} port {ports[scheme]}",
            note=None
            if scheme == "https"
            else "Answers on plain http only: install luci-ssl (HTTPS) on the device first.",
        )
    for scheme in ("https", "http"):
        page = await probe.get(scheme, ports[scheme], "/cgi-bin/luci/")
        if page is not None and page.status in (200, 403) and "luci" in page.text().lower():
            return Candidate(
                address=probe.host,
                role=DeviceRole.AP,
                config={"url": probe.origin("https", ports["https"])},
                vendor="OpenWrt",
                name="OpenWrt",
                evidence=f"LuCI login page on {scheme} port {ports[scheme]}",
                note="ubus does not answer over HTTP: install uhttpd-mod-ubus and rpcd "
                "(and luci-ssl for HTTPS) on the device first.",
            )
    return None
