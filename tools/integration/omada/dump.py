#!/usr/bin/env python3
"""Record what the real Omada controller answers on the endpoints the adapter uses (#140).

    dump.py DIR GROUP

Prints each answer (status and body, shortened) as a GitHub ``::notice::`` so the shapes can be
compared with docs/adapters/omada.md and the simulator without downloading logs; the full
answers go to DIR/api-<GROUP>.json. Only the throw-away controller's data is in there
(documentation prefixes, example passphrases). GROUP is ``read`` (the viewer application),
``detail`` (SSIDs and networks in full), ``auth`` (refusals: a wrong secret, a bogus token,
a write with the viewer role), ``services`` (the site's SSH and SNMP settings, #173) or
``spec`` (the fields of the managed-device answers and the services' own descriptions from the
controller's own Open API description), ``firewall`` (every path about ACLs, port forwarding
and NAT of that description, with its answer fields, and what the paths answer, #135).
Ten notices per call (the limit of one step).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import controller

OID = os.environ.get("IT_OMADA_OMADAC_ID", "")
SID = os.environ.get("IT_OMADA_SITE_ID", "")
WID = os.environ.get("IT_OMADA_WLAN_ID", "")
V1 = f"/openapi/v1/{OID}/sites/{SID}"
PAGE = "?page=1&pageSize=100"


def token(client_id: str, secret: str) -> tuple[int, Any]:
    return controller.request(
        "POST",
        "/openapi/authorize/token?grant_type=client_credentials",
        {"omadacId": OID, "client_id": client_id, "client_secret": secret},
    )


def bearer(write: bool = False) -> dict[str, str]:
    prefix = "IT_OMADA_WRITE_" if write else "IT_OMADA_"
    _, answer = token(os.environ[prefix + "USER"], os.environ[prefix + "PASSWORD"])
    return {"Authorization": f"AccessToken={answer['result']['accessToken']}"}


def spec() -> dict[str, Any]:
    """From the controller's own Open API description (``/v3/api-docs``): the fields of the
    answers the adapter reads from managed devices, which this test site does not have."""
    _, doc = controller.request("GET", "/v3/api-docs")
    schemas = doc.get("components", {}).get("schemas", {}) if isinstance(doc, dict) else {}

    def fields(node: Any, depth: int = 0) -> Any:
        if not isinstance(node, dict) or depth > 9:
            return None
        if "$ref" in node:
            return fields(schemas.get(node["$ref"].rsplit("/", 1)[-1], {}), depth + 1)
        if node.get("type") == "array":
            return [fields(node.get("items"), depth + 1)]
        props = node.get("properties")
        if not props:
            text = (node.get("description") or "")[:160]
            return f"{node.get('type')} {text}".strip()
        return {k: fields(v, depth + 1) for k, v in props.items()}

    wanted = (
        "/openapi/v1/{omadacId}/sites/{siteId}/switches/{switchMac}",
        "/openapi/v1/{omadacId}/sites/{siteId}/aps/{apMac}",
        # the device list: does it carry the wired uplink of an AP (#336)?
        "/openapi/v1/{omadacId}/sites/{siteId}/devices",
    )
    out: dict[str, Any] = {}
    paths = doc.get("paths", {}) if isinstance(doc, dict) else {}
    # the gateway's WAN ports (#148): the path parameter's name is the description's own
    wanted += tuple(p for p in paths if p.startswith("/openapi/v1/") and p.endswith("/wan-status"))
    # the site's SSH and SNMP settings (#173)
    wanted += tuple(
        p
        for p in paths
        if "/sites/{siteId}/" in p
        and p.rsplit("/", 1)[-1] in ("ssh", "snmp")
        and "{" not in p[p.index("{siteId}") + 8 :]
    )
    # the LAN networks' DHCP settings (#183): do they have options 60/66/138 and a relay mode?
    wanted += tuple(
        p
        for p in paths
        if p.startswith("/openapi/v")
        and "/sites/{siteId}/lan-networks" in p
        and p.rsplit("/", 1)[-1] in ("lan-networks", "{networkId}", "{lanNetworkId}")
    )
    # Omada Cloud access and the site's remote syslog (#327): the adapter's paths are guesses
    wanted += tuple(
        p
        for p in sorted(paths)
        if p.startswith("/openapi/v")
        and any(w in p.lower() for w in ("cloud", "syslog", "logging", "/log", "remote-log"))
    )
    for path in wanted:
        op = paths.get(path, {}).get("get", {})
        content = op.get("responses", {}).get("200", {}).get("content", {})
        body = [fields(c.get("schema")) for c in content.values()]
        result = body[0].get("result") if body and isinstance(body[0], dict) else body
        if isinstance(result, dict) and path.endswith("{switchMac}"):
            result = {"portList": result.get("portList")}
        out[path] = {"method": "GET", "path": path, "status": 200, "body": result}
    return out


def firewall_spec() -> dict[str, Any]:
    """The controller's own Open API description of everything about gateway ACLs, port
    forwarding, NAT and firewalls (#135): each path with its methods and, for GET, the fields
    of the answer, so the adapter's names can be confirmed without a gateway. The paths are
    also asked for real (the viewer role): the test site has no gateway, but a site-level list
    answers with an empty page and shows that the path exists."""
    _, doc = controller.request("GET", "/v3/api-docs")
    schemas = doc.get("components", {}).get("schemas", {}) if isinstance(doc, dict) else {}
    paths = doc.get("paths", {}) if isinstance(doc, dict) else {}

    def fields(node: Any, depth: int = 0) -> Any:
        if not isinstance(node, dict) or depth > 8:
            return None
        if "$ref" in node:
            return fields(schemas.get(node["$ref"].rsplit("/", 1)[-1], {}), depth + 1)
        if node.get("type") == "array":
            return [fields(node.get("items"), depth + 1)]
        props = node.get("properties")
        if not props:
            text = (node.get("description") or "")[:100]
            return f"{node.get('type')} {text}".strip()
        return {k: fields(v, depth + 1) for k, v in props.items()}

    words = ("acl", "port-forward", "portforward", "/nat", "firewall", "virtual-server")
    out: dict[str, Any] = {}
    for path in sorted(paths):
        if not path.startswith("/openapi/") or not any(w in path.lower() for w in words):
            continue
        methods = sorted(m.upper() for m in paths[path])
        entry: dict[str, Any] = {"methods": methods}
        op = paths[path].get("get", {})
        content = op.get("responses", {}).get("200", {}).get("content", {})
        body = [fields(c.get("schema")) for c in content.values()]
        entry["get"] = body[0].get("result") if body and isinstance(body[0], dict) else body
        out[path] = {"method": "SPEC", "path": path, "status": 200, "body": entry}
    h = bearer()
    for path in list(out):
        if "GET" not in out[path]["body"]["methods"]:
            continue
        real = path.replace("{omadacId}", OID).replace("{siteId}", SID)
        if "{" in real:
            continue  # a gateway or an object this site does not have
        try:
            status, answer = controller.request("GET", real + PAGE, None, h)
        except OSError as exc:
            status, answer = 0, repr(exc)
        out[f"answer {path}"] = {"method": "GET", "path": real, "status": status, "body": answer}
    return out


def calls(group: str) -> list[tuple[str, str, str, Any, dict[str, str]]]:
    """(label, method, path, body, headers)"""
    if group == "read":
        h = bearer()
        return [
            ("info", "GET", "/api/info", None, {}),
            ("sites", "GET", f"/openapi/v1/{OID}/sites{PAGE}", None, h),
            ("devices", "GET", f"{V1}/devices{PAGE}", None, h),
            ("lan-networks v1", "GET", f"{V1}/lan-networks{PAGE}", None, h),
            ("lan-profiles v1", "GET", f"{V1}/lan-profiles{PAGE}", None, h),
            ("wlans", "GET", f"{V1}/wireless-network/wlans", None, h),
            ("ssids", "GET", f"{V1}/wireless-network/wlans/{WID}/ssids{PAGE}", None, h),
            ("clients", "GET", f"{V1}/clients{PAGE}", None, h),
            ("lan-networks v3", "GET", f"/openapi/v3/{OID}/sites/{SID}/lan-networks{PAGE}",
             None, h),
            ("site ssids", "GET", f"{V1}/wireless-network/ssids{PAGE}", None, h),
        ]  # fmt: skip
    if group == "services":
        h = bearer()
        return [
            ("ssh", "GET", f"{V1}/ssh", None, h),
            ("snmp", "GET", f"{V1}/setting/service/snmp", None, h),
        ]
    if group == "detail":
        h = bearer()
        _, listed = controller.request("GET", f"{V1}/wireless-network/wlans/{WID}/ssids{PAGE}",
                                       None, h)  # fmt: skip
        out = []
        for row in (listed.get("result") or {}).get("data", [])[:3]:
            sid = row.get("ssidId") or row.get("id")
            path = f"{V1}/wireless-network/wlans/{WID}/ssids/{sid}"
            out.append((f"ssid {row.get('name')}", "GET", path, None, h))
        _, nets = controller.request("GET", f"{V1}/lan-networks{PAGE}", None, h)
        for row in (nets.get("result") or {}).get("data", [])[:3]:
            path = f"{V1}/lan-networks/{row.get('id')}"
            out.append((f"network {row.get('name')}", "GET", path, None, h))
        out.append(("eap radios (no such EAP)", "GET", f"{V1}/aps/02-00-00-00-0C-01/radios",
                    None, h))  # fmt: skip
        out.append(("switch ports (no such switch)", "GET",
                    f"{V1}/switches/02-00-00-00-0B-01/ports{PAGE}", None, h))  # fmt: skip
        return out
    viewer = bearer()
    return [
        ("token, wrong secret", "POST", "/openapi/authorize/token?grant_type=client_credentials",
         {"omadacId": OID, "client_id": os.environ["IT_OMADA_USER"], "client_secret": "wrong"},
         {}),
        ("token, unknown omadacId", "POST",
         "/openapi/authorize/token?grant_type=client_credentials",
         {"omadacId": "0" * 32, "client_id": os.environ["IT_OMADA_USER"],
          "client_secret": os.environ["IT_OMADA_PASSWORD"]}, {}),
        ("bogus token", "GET", f"{V1}/lan-networks{PAGE}", None,
         {"Authorization": "AccessToken=AT-bogus"}),
        ("no token", "GET", f"{V1}/lan-networks{PAGE}", None, {}),
        ("viewer write", "POST", f"{V1}/lan-networks",
         {"name": "Denied", "purpose": 0, "vlan": 99, "igmpSnoopEnable": False}, viewer),
        ("unknown site", "GET", f"/openapi/v1/{OID}/sites/{'0' * 24}/lan-networks{PAGE}", None,
         viewer),
        ("unknown network", "GET", f"{V1}/lan-networks/{'0' * 24}", None, viewer),
    ]  # fmt: skip


def main(d: Path, group: str, part: int) -> None:
    """Part ``part`` (ten notices of 4000 characters) of the answers of ``group``."""
    cached = d / f"api-{group}.json"
    if part and cached.exists():
        full = json.loads(cached.read_text())
    elif group in ("spec", "firewall"):
        full = spec() if group == "spec" else firewall_spec()
        cached.write_text(json.dumps(full, indent=1))
    else:
        full = {}
        for label, method, path, body, headers in calls(group):
            try:
                status, answer = controller.request(method, path, body, headers)
            except OSError as exc:
                status, answer = 0, repr(exc)
            full[label] = {"method": method, "path": path, "status": status, "body": answer}
        cached.write_text(json.dumps(full, indent=1))
    notes = []
    for label, r in full.items():
        answer = r["body"]
        text = answer if isinstance(answer, str) else json.dumps(answer, separators=(",", ":"))
        path = r["path"].replace(OID, "{oid}") if OID else r["path"]
        notes.append(f"## {label}: {r['method']} {path} -> {r['status']}\n{text}")
    text = "\n".join(notes)
    chunks = [text[i : i + 4000] for i in range(0, len(text), 4000)]
    print(f"{len(chunks)} chunks")
    for i in range(part * 10, min(part * 10 + 10, len(chunks))):
        body = chunks[i].replace("%", "%25").replace("\r", "").replace("\n", "%0A")
        print(f"::notice title=Omada API {group} {i:02d} of {len(chunks)}::{body}", flush=True)


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve(), sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 0)
