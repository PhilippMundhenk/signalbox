"""The internal port structure of an OpenWrt device (#252, ADR 0008).

Sources, in the order they are trusted:

- netifd ``network.device status``: ``type`` ``bridge`` with ``bridge-members``, ``VLAN`` /
  ``8021q`` / ``8021ad`` devices (``parent`` for the latter, else the name before the last dot).
- ``luci-rpc getNetworkDevices`` (rpcd-mod-luci): ``devtype`` from the kernel (``DEVTYPE`` in
  the device's uevent: ``dsa`` for a DSA user port, ``vlan``, ``bridge``, ``wlan``; missing:
  ``ethernet``), ``parent`` (the device whose ifindex is this one's ``iflink``: a DSA user port's
  conduit, a VLAN device's parent), ``bridge`` with ``ports``, ``wireless``. A DSA conduit is the
  ``parent`` of a ``dsa`` device. Without this call only bridges, VLAN devices, Wi-Fi
  interfaces and swconfig CPU ports get a role.
- UCI ``switch`` / ``switch_vlan`` (swconfig, older devices): the device whose ``<dev>.<vid>``
  VLAN devices exist for a switch VLAN is the CPU port of that switch. Which switch port is
  the CPU port, and which ports are jacks, swconfig only tells through ``/etc/board.json``,
  which is not read: the switch ports themselves are not reported.
"""

from __future__ import annotations

from typing import Any

from signalbox.model import PortKind, PortRole

#: netifd ``type`` of VLAN devices (``eth0.2`` is ``VLAN``; ``device`` sections ``8021q``)
_VLAN_TYPES = frozenset({"VLAN", "8021q", "8021ad"})
#: kernel ``DEVTYPE`` values of tunnels and other software interfaces
_TUNNELS = frozenset({"wireguard", "ppp", "gre", "gretap", "ip6gre", "ipip", "sit", "vxlan"})
_VIRTUAL = frozenset({"veth", "dummy", "macvlan", "ifb", "vrf"})
#: ``type`` (ARP hardware type) in getNetworkDevices: 1 Ethernet; PPP, "none" (tun, WireGuard)
_ETHER = 1
_TUNNEL_HATYPES = frozenset({512, 65534})


def _names(value: Any) -> list[str]:
    return [str(v) for v in value if isinstance(v, str) and v] if isinstance(value, list) else []


def _switch_vids(uci: dict[str, Any] | None) -> set[int]:
    """VLAN ids of swconfig ``switch_vlan`` sections (``vid``, else ``vlan``)."""
    out: set[int] = set()
    values = (uci or {}).get("values")
    if not isinstance(values, dict):
        return out
    for s in values.values():
        if not isinstance(s, dict) or s.get(".type") != "switch_vlan":
            continue
        raw = s.get("vid", s.get("vlan"))
        if isinstance(raw, str) and raw.isdigit():
            out.add(int(raw))
    return out


def structure(
    names: list[str],
    status: dict[str, Any],
    devices: dict[str, Any] | None,
    uci: dict[str, Any] | None = None,
    wireless: frozenset[str] = frozenset(),
) -> dict[str, tuple[PortRole | None, list[str], PortKind | None]]:
    """name -> (role, names of the lower ports, kind if the role decides it) for ``names``.

    ``status`` is ``network.device status``, ``devices`` ``luci-rpc getNetworkDevices`` (None:
    not available), ``uci`` the ``network`` config, ``wireless`` the names already known to be
    Wi-Fi interfaces. Lower names are limited to ``names``.
    """
    known = set(names)
    luci = {k: v for k, v in (devices or {}).items() if isinstance(v, dict)}
    conduits = {
        str(v["parent"])
        for v in luci.values()
        if v.get("devtype") == "dsa" and isinstance(v.get("parent"), str)
    }
    vids = _switch_vids(uci)
    swconfig_cpu = {
        base
        for name in names
        if "." in name
        and (base := name.rsplit(".", 1)[0]) in known
        and name.rsplit(".", 1)[1].isdigit()
        and int(name.rsplit(".", 1)[1]) in vids
        and (status.get(base) or {}).get("type") != "bridge"
    }
    out: dict[str, tuple[PortRole | None, list[str], PortKind | None]] = {}
    for name in names:
        raw = status.get(name)
        st: dict[str, Any] = raw if isinstance(raw, dict) else {}
        ld = luci.get(name, {})
        devtype = ld.get("devtype")
        role: PortRole | None = None
        lower: list[str] = []
        kind: PortKind | None = None
        if st.get("type") == "bridge" or ld.get("bridge") or devtype == "bridge":
            role, kind = PortRole.BRIDGE, PortKind.BRIDGE
            lower = _names(st.get("bridge-members")) or _names(ld.get("ports"))
        elif st.get("type") in _VLAN_TYPES or devtype == "vlan":
            role, kind = PortRole.VLAN, PortKind.VIRTUAL
            parent = st.get("parent") or ld.get("parent")
            if not isinstance(parent, str) and "." in name:
                parent = name.rsplit(".", 1)[0]
            lower = [parent] if isinstance(parent, str) else []
        elif name in wireless or st.get("wireless") or ld.get("wireless") or devtype == "wlan":
            role, kind = PortRole.WIRELESS, PortKind.WIRELESS
        elif name in conduits or name in swconfig_cpu:
            role = PortRole.CPU
        elif devtype == "dsa":
            role = PortRole.JACK
            parent = ld.get("parent")
            lower = [parent] if isinstance(parent, str) else []
        elif devtype in _TUNNELS or ld.get("type") in _TUNNEL_HATYPES:
            role, kind = PortRole.TUNNEL, PortKind.VIRTUAL
        elif devtype in _VIRTUAL:
            role, kind = PortRole.VIRTUAL, PortKind.VIRTUAL
        elif devtype == "ethernet" and ld.get("type") == _ETHER:
            # a plain NIC that is neither a conduit nor a swconfig CPU port: wired to a jack.
            # A guess for software devices without a DEVTYPE (veth); routers rarely have them.
            role = PortRole.JACK
        out[name] = (role, [x for x in dict.fromkeys(lower) if x in known and x != name], kind)
    return out
