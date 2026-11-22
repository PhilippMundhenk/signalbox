#!/usr/bin/env python3
"""Record what the real RouterOS answers on the endpoints the adapter uses (#139).

    dump.py DIR GROUP

Prints each answer (status and a compact body) as a GitHub ``::notice::`` so the shapes can be
compared with docs/adapters/mikrotik.md and the simulator without downloading logs; the full
answers go to DIR/api-<GROUP>.json (uploaded as an artifact). Only the throw-away VM's data is
in there (documentation prefixes, the 02: MACs of the test setup). GROUP is ``read`` (the
read user, every menu the read side uses), ``more`` (the rest of them), ``write`` (the write
user: the export, refused changes, the menus of the backup) or ``refused`` (a wrong password,
the read user writing, unknown menus). At most ten notices per call (the limit of one step).
"""

from __future__ import annotations

import json
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vm

R, W = "signalbox", "signalbox-write"
GROUPS: dict[str, list[tuple[str, str, str, object]]] = {
    "read": [
        (R, "GET", "/rest/system/resource", None),
        (R, "GET", "/rest/system/routerboard", None),
        (R, "GET", "/rest/system/package/update", None),
        (R, "GET", "/rest/interface", None),
        (R, "GET", "/rest/interface/ethernet", None),
        (R, "GET", "/rest/interface/bridge", None),
        (R, "GET", "/rest/interface/bridge/port", None),
        (R, "GET", "/rest/interface/bridge/vlan", None),
        (R, "GET", "/rest/interface/vlan", None),
        (R, "GET", "/rest/interface/list/member", None),
    ],
    "more": [
        (R, "GET", "/rest/ip/address", None),
        (R, "GET", "/rest/ipv6/address", None),
        (R, "GET", "/rest/ip/dhcp-server", None),
        (R, "GET", "/rest/ip/dhcp-server/network", None),
        (R, "GET", "/rest/ip/pool", None),
        (R, "GET", "/rest/ip/dhcp-server/lease", None),
        (R, "GET", "/rest/ip/dns", None),
        (R, "GET", "/rest/ip/dns/static", None),
        (R, "GET", "/rest/ip/arp", None),
        (R, "GET", "/rest/ipv6/neighbor", None),
        (R, "GET", "/rest/interface/bridge/host", None),
        (R, "GET", "/rest/ip/neighbor", None),
    ],
    "write": [
        (W, "POST", "/rest/export", {}),
        (W, "PUT", "/rest/ip/address", {"address": "not-an-address", "interface": "bridge"}),
        (W, "PUT", "/rest/ip/address", {"address": "203.0.113.1/24", "interface": "nothere"}),
        (W, "PATCH", "/rest/ip/pool/*999", {"ranges": "192.0.2.100-192.0.2.110"}),
        (W, "DELETE", "/rest/ip/pool/*999", None),
        (W, "POST", "/rest/ip/dhcp-server/network/unset", {"numbers": "*999", "value-name": "x"}),
        (W, "GET", "/rest/interface/wifi", None),
        (W, "GET", "/rest/interface/wireless", None),
    ],
    "refused": [
        (R, "GET", "/rest/interface/wifi", None),
        (R, "GET", "/rest/interface/wireless", None),
        (R, "GET", "/rest/interface/wifi/registration-table", None),
        (R, "GET", "/rest/interface/wireless/registration-table", None),
        (R, "GET", "/rest/no/such/menu", None),
        (R, "PUT", "/rest/ip/dns/static", {"name": "x.home.example", "address": "192.0.2.99"}),
        (R, "POST", "/rest/export", {}),
        ("bad-password", "GET", "/rest/system/resource", None),
    ],
}


def main(d: Path, group: str) -> None:
    keys = json.loads((d / "keys.json").read_text())
    full = {}
    notes: list[str] = []
    for user, method, path, body in GROUPS[group]:
        password = keys.get(user, "not-the-password")
        login = R if user == "bad-password" else user
        try:
            answer = vm.rest(login, password, method, path, body, timeout=60)
            status = 200
        except urllib.error.HTTPError as exc:
            status, answer = exc.code, exc.read().decode(errors="replace")[:800]
        except OSError as exc:
            status, answer = 0, repr(exc)
        full[f"{user} {method} {path}"] = {"status": status, "body": answer}
        text = answer if isinstance(answer, str) else json.dumps(answer, separators=(",", ":"))
        notes.append(f"{user} {method} {path} {json.dumps(body)} -> {status}\n{text[:6000]}")
    (d / f"api-{group}.json").write_text(json.dumps(full, indent=1))
    size = -(-len(notes) // 10)
    for i in range(0, len(notes), size):
        text = "\n\n".join(notes[i : i + size]).replace("%", "%25").replace("\n", "%0A")
        print(f"::notice title=RouterOS REST {group} {i // size + 1}::{text}", flush=True)


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve(), sys.argv[2])
