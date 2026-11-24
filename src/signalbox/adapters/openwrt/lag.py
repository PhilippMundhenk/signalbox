"""Link aggregation on OpenWrt (#157): bonding devices of netifd and of proto-bonding.

The configuration comes from UCI ``network``:

- netifd (OpenWrt 23.05 and later): a ``device`` section with ``type bonding``, ``name``,
  ``ports`` (the members) and ``policy`` (the kernel's mode names: ``balance-rr``,
  ``active-backup``, ``balance-xor``, ``broadcast``, ``802.3ad``, ``balance-tlb``,
  ``balance-alb``), ``xmit_hash_policy``, ``lacp_rate``, ``min_links``;
- the older package proto-bonding: an ``interface`` section with ``proto bonding``, ``slaves``,
  ``bonding_policy`` and the same options; its device is ``bonding-<interface>``.

The kernel's view (what is aggregated right now, the LACP partner) is in sysfs:
``/sys/class/net/<bond>/bonding/<attr>`` and ``/sys/class/net/<member>/bonding_slave/<attr>``
(:data:`signalbox.adapters.bonding.BOND_ATTRS`, ``MEMBER_ATTRS``), read with rpcd ``file read``
where the ACL allows it. Without it the configuration alone fills the LAG port. DSA switches
that offload a LAG (``bond`` over DSA user ports) look the same. The option names are taken
from netifd's ``bonding.c`` and the proto-bonding script, not from a real device (#21).
"""

from __future__ import annotations

from typing import Any

from signalbox.adapters.bonding import Bond, Member


def _words(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, str) and v]
    return value.split() if isinstance(value, str) else []


def _sections(uci: dict[str, Any] | None) -> list[dict[str, Any]]:
    values = (uci or {}).get("values")
    if not isinstance(values, dict):
        return []
    return [s for s in values.values() if isinstance(s, dict)]


def uci_bonds(uci: dict[str, Any] | None) -> dict[str, Bond]:
    """Bond device name -> its configuration (members, mode, hash, LACP rate, min links)."""
    out: dict[str, Bond] = {}
    for s in _sections(uci):
        if s.get(".type") == "device" and s.get("type") == "bonding" and s.get("name"):
            name, members, policy = str(s["name"]), _words(s.get("ports")), s.get("policy")
        elif s.get(".type") == "interface" and s.get("proto") == "bonding" and s.get(".name"):
            name = f"bonding-{s['.name']}"
            members, policy = _words(s.get("slaves")), s.get("bonding_policy")
        else:
            continue
        min_links = s.get("min_links")
        bond = Bond(
            name,
            mode=str(policy) if isinstance(policy, str) and policy else "balance-rr",
            hash_policy=str(s["xmit_hash_policy"]) if s.get("xmit_hash_policy") else None,
            lacp_rate=str(s["lacp_rate"]) if s.get("lacp_rate") else "slow",
            min_links=int(min_links)
            if isinstance(min_links, str) and min_links.isdigit()
            else None,
        )
        bond.members = {m: Member(m) for m in members}
        out[name] = bond
    return out
