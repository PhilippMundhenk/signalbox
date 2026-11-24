#!/usr/bin/env python3
"""Record what the real OPNsense answers on the endpoints the adapter uses (#138).

    dump.py DIR GROUP

Prints each answer (status and a compact, shortened body) as a GitHub ``::notice::`` so the
shapes can be compared with docs/adapters/opnsense.md and the simulator without downloading
logs; the full answers go to DIR/api-<GROUP>.json (uploaded as an artifact). Only the
throw-away VM's data is in there (documentation prefixes, the 02: MACs of the test setup).
GROUP is ``read`` (the read user, camelCase and snake_case paths), ``kea``, ``vpn`` (WireGuard,
#239, private keys redacted), ``logging`` (syslog and NetFlow targets, #180), ``health`` (the
dashboard and NTP endpoints of health and time, #178 and #179) or ``write`` (the write and
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
        ("signalbox-read", "/api/unbound/settings/searchHostAlias" + GRID),
        ("signalbox-read", "/api/unbound/settings/search_host_alias" + GRID),
        ("signalbox-read", "/api/unbound/settings/searchDomainOverride" + GRID),
        ("signalbox-read", "/api/unbound/settings/search_domain_override" + GRID),
        ("signalbox-read", "/api/diagnostics/interface/getArp"),
        ("signalbox-read", "/api/diagnostics/interface/get_arp"),
        ("signalbox-read", "/api/diagnostics/interface/getNdp"),
        ("signalbox-read", "/api/diagnostics/interface/get_ndp"),
        # the packet filter (#379, #390): before 26.7 only floating rules without show_all
        ("signalbox-read", "/api/firewall/filter/searchRule" + GRID),
        ("signalbox-read", "/api/firewall/filter/searchRule" + GRID + "&show_all=1"),
        ("signalbox-read", "/api/firewall/filter/search_rule" + GRID + "&show_all=1"),
    ],
    "kea": [
        ("signalbox-read", "/api/kea/dhcpv4/search_subnet" + GRID),
        ("signalbox-read", "/api/kea/dhcpv4/search_reservation" + GRID),
        ("signalbox-read", "/api/kea/dhcpv4/searchSubnet" + GRID),
        ("signalbox-read", "/api/kea/dhcpv4/search_peer" + GRID),
        ("signalbox-read", "/api/kea/leases6/search" + GRID),
        ("signalbox-read", "/api/dhcrelay/settings/search_relay" + GRID),
        ("signalbox-read", "/api/dhcrelay/settings/search_dest" + GRID),
        ("signalbox-read", "/api/kea/leases4/search" + GRID),
        ("signalbox-read", "/api/interfaces/overview/interfaces_info" + GRID),
        ("signalbox-write", "/api/interfaces/assignment/search_item" + GRID),
    ],
    "health": [
        ("signalbox-read", "/api/diagnostics/system/system_time"),
        ("signalbox-read", "/api/diagnostics/system/system_resources"),
        ("signalbox-read", "/api/diagnostics/system/system_disk"),
        ("signalbox-read", "/api/diagnostics/system/system_temperature"),
        ("signalbox-read", "/api/diagnostics/cpu_usage/get_cpu_type"),
        ("signalbox-read", "/api/ntpd/service/status"),
        ("signalbox-read", "/api/ntpd/service/status" + GRID),
        ("root", "/api/ntpd/service/status"),
        ("root", "/api/ntpd/service/gps"),
        ("root", "/api/diagnostics/system/system_time"),
    ],
    # WireGuard (#239): the status the adapter reads; the configuration grids the read user
    # must not get (they hold private keys: redacted below for the root user's answers)
    "vpn": [
        ("signalbox-read", "/api/wireguard/service/show"),
        ("signalbox-read", "/api/wireguard/server/search_server"),
        ("signalbox-read", "/api/wireguard/client/search_client"),
        ("root", "/api/wireguard/server/search_server"),
        ("root", "/api/wireguard/client/search_client"),
        ("root", "/api/wireguard/general/get"),
    ],
    # log and flow targets (#180): the destination and NetFlow export vm.py adds
    "logging": [
        ("signalbox-read", "/api/syslog/settings/search_destinations"),
        ("signalbox-read", "/api/syslog/settings/searchDestinations" + GRID),
        ("signalbox-read", "/api/diagnostics/netflow/getconfig"),
        ("signalbox-read", "/api/diagnostics/netflow/is_enabled"),
        ("root", "/api/syslog/settings/get"),
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
    # what the uplink is read from (#148)
    "link_type", "link_typev6", "gateways", "ifctl.nameserver", "ifctl.router", "ifctl.prefix",
)  # fmt: skip


#: fields never recorded, not even of the throw-away VM (private and pre-shared keys)
SECRET = ("privkey", "psk", "private-key", "preshared-key")


def redact(body: object) -> object:
    if isinstance(body, dict):
        return {k: "***" if k in SECRET else redact(v) for k, v in body.items()}
    if isinstance(body, list):
        return [redact(v) for v in body]
    return body


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
            body = redact(vm.api(keys[user], "GET", path, timeout=60))
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
