#!/usr/bin/env python3
"""Record what the real OPNsense answers on the endpoints the adapter uses (#138).

    dump.py DIR GROUP

Prints each answer (status and a compact, shortened body) as a GitHub ``::notice::`` so the
shapes can be compared with docs/adapters/opnsense.md and the simulator without downloading
logs; the full answers go to DIR/api-<GROUP>.json (uploaded as an artifact). Only the
throw-away VM's data is in there (documentation prefixes, the 02: MACs of the test setup).
GROUP is ``read`` (the read user, camelCase and snake_case paths) or ``write`` (the write and
the root user). At most ten notices per call (the limit of one step).
"""

from __future__ import annotations

import json
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vm

GRID = "?current=1&rowCount=-1"
GROUPS = {
    "read": [
        ("signalbox-read", "/api/core/firmware/status"),
        ("signalbox-read", "/api/interfaces/overview/interfacesInfo" + GRID),
        ("signalbox-read", "/api/interfaces/overview/interfaces_info" + GRID),
        ("signalbox-read", "/api/interfaces/vlan_settings/searchItem" + GRID),
        ("signalbox-read", "/api/interfaces/vlan_settings/search_item" + GRID),
        ("signalbox-read", "/api/kea/dhcpv4/get"),
        ("signalbox-read", "/api/kea/leases4/search" + GRID),
        ("signalbox-read", "/api/dhcpv4/service/status"),
        ("signalbox-read", "/api/unbound/settings/get"),
        ("signalbox-read", "/api/unbound/settings/searchHostOverride" + GRID),
        ("signalbox-read", "/api/unbound/settings/search_host_override" + GRID),
        ("signalbox-read", "/api/diagnostics/interface/getArp"),
        ("signalbox-read", "/api/diagnostics/interface/get_arp"),
        ("signalbox-read", "/api/diagnostics/interface/getNdp"),
        ("signalbox-read", "/api/diagnostics/interface/get_ndp"),
    ],
    "kea": [
        ("signalbox-read", "/api/kea/dhcpv4/search_subnet" + GRID),
        ("signalbox-read", "/api/kea/dhcpv4/search_reservation" + GRID),
        ("signalbox-read", "/api/kea/dhcpv4/searchSubnet" + GRID),
        ("signalbox-read", "/api/kea/leases4/search" + GRID),
        ("signalbox-read", "/api/interfaces/overview/interfaces_info" + GRID),
        ("signalbox-write", "/api/interfaces/assignment/search_item" + GRID),
    ],
    "write": [
        ("signalbox-write", "/api/interfaces/assignment/searchItem" + GRID),
        ("signalbox-write", "/api/interfaces/assignment/search_item" + GRID),
        ("signalbox-write", "/api/interfaces/assignment/get_item/opt1"),
        ("signalbox-write", "/api/core/backup/backups/this"),
        ("signalbox-read", "/api/core/backup/backups/this"),
        ("root", "/api/dhcpv4/leases/searchLease" + GRID),
        ("root", "/api/interfaces/overview/interfaces_info" + GRID),
    ],
}


#: the fields worth showing of the long rows (interface overview, assignments)
SHORT = (
    "device", "identifier", "description", "descr", "status", "is_physical", "macaddr", "media",
    "vlan_tag", "ipv4", "ipv6", "if", "lock", "enable", "type4", "ipaddr", "type6", "ipaddrv6",
)  # fmt: skip


def short(body: object) -> object:
    rows = body.get("rows") if isinstance(body, dict) else None
    if (
        not isinstance(rows, list)
        or not rows
        or ("device" not in rows[0] and "type4" not in rows[0])
    ):
        return body
    return {"rows": [{k: r[k] for k in SHORT if k in r} for r in rows if isinstance(r, dict)]}


def main(d: Path, group: str) -> None:
    keys = json.loads((d / "keys.json").read_text())
    full = {}
    notes: list[str] = []
    for user, path in GROUPS[group]:
        try:
            body = vm.api(keys[user], "GET", path, timeout=60)
            status = 200
        except urllib.error.HTTPError as exc:
            status, body = exc.code, exc.read().decode(errors="replace")[:500]
        except OSError as exc:
            status, body = 0, repr(exc)
        full[f"{user} {path}"] = {"status": status, "body": body}
        text = body if isinstance(body, str) else json.dumps(short(body), separators=(",", ":"))
        notes.append(f"{user} GET {path} -> {status}\n{text[:6000]}")
    (d / f"api-{group}.json").write_text(json.dumps(full, indent=1))
    # ten notices at most: pack the answers into ten messages
    size = -(-len(notes) // 10)
    for i in range(0, len(notes), size):
        body = "\n\n".join(notes[i : i + size]).replace("%", "%25").replace("\n", "%0A")
        print(f"::notice title=OPNsense API {group} {i // size + 1}::{body}", flush=True)


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve(), sys.argv[2])
