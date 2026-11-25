"""FRITZ!Mesh (#171): the mesh topology of ``Hosts:1 X_AVM-DE_GetMeshListPath``.

The action (in the service descriptions of FRITZ!OS 6.83, 7.29, 7.57 and 8.02) returns the path
of a JSON document: ``nodes`` (the boxes, repeaters and every host the box knows), each with
``node_interfaces`` and their ``node_links``. Written from AVM's description of the mesh
topology document (``schema_version`` 1.x), not from a real box: every field below is a
*guess* until a box confirms it (#21):

- a mesh node has ``is_meshed`` true and ``mesh_role`` ``master`` or ``slave``; the other
  nodes are clients and are ignored here (the host list reads them);
- a link has ``type`` ``WLAN`` or ``LAN``, ``state`` ``CONNECTED``, the two ``node_*_uid``,
  ``cur_data_rate_rx``/``_tx`` in kbit/s and ``rx_rcpi``/``tx_rcpi`` (802.11k RCPI: dBm =
  RCPI / 2 - 110, 255: not measured);
- an interface is named ``AP:2G:0``, ``UPLINK:5G:0``, ``LAN:0``: the band comes from the name,
  ``current_channel`` is the channel *(guess)*.

Which end of a link is upstream is not told: it is found by walking the links from the master.
Repeaters become devices the box manages (ADR 0004); their wireless uplink and the matching
port of the node in front are ports of their own, so the topology can draw the link.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from ipaddress import IPv4Address, ip_address
from typing import Any

from signalbox.model import (
    Band,
    Device,
    DeviceRole,
    Firmware,
    Link,
    LinkKind,
    LinkOrigin,
    MeshLinkKind,
    MeshMembership,
    MeshRole,
    MeshUplink,
    Port,
    PortKind,
    WirelessLinkInfo,
    normalise_mac,
    object_id,
    port_id,
)

_BAND = re.compile(r"(?<!\d)(2|5|6)G", re.IGNORECASE)
_BANDS = {"2": Band.GHZ_2_4, "5": Band.GHZ_5, "6": Band.GHZ_6}
_SLUG = re.compile(r"[^a-z0-9]+")


@dataclass
class MeshRead:
    """What the mesh list tells: repeaters as devices, their ports, the links and the roles."""

    devices: list[Device] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    mesh: dict[str, MeshMembership] = field(default_factory=dict)


def _mac(value: Any) -> str | None:
    try:
        return normalise_mac(str(value or ""))
    except ValueError:
        return None


def _num(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _v4(value: Any) -> str | None:
    try:
        address = ip_address(str(value or "").strip())
    except ValueError:
        return None
    ok = isinstance(address, IPv4Address) and not address.is_unspecified
    return str(address) if ok else None


def _slug(uid: str) -> str:
    return _SLUG.sub("-", uid.lower()).strip("-")[:40] or "node"


def dbm(rcpi: Any) -> int | None:
    """Signal in dBm from an 802.11k RCPI (0 to 220; 255 and anything else: not measured)."""
    value = _num(rcpi)
    if value is None or not 0 <= value <= 220:
        return None
    return round(value / 2 - 110)


def _band(name: str) -> Band | None:
    found = _BAND.search(name)
    return _BANDS[found.group(1)] if found else None


def _mbps(value: Any) -> float | None:
    kbit = _num(value)
    return round(kbit / 1000, 1) if kbit is not None and kbit > 0 else None


def parse(doc: Any, own_id: str, own_macs: set[str], role: DeviceRole = DeviceRole.AP) -> MeshRead:
    """The mesh of a topology document. ``own_id`` is the box Signalbox reads and ``own_macs``
    its MAC addresses (to find its node); ``None`` of the result means: no mesh to report."""
    out = MeshRead()
    nodes = doc.get("nodes") if isinstance(doc, dict) else None
    if not isinstance(nodes, list):
        return out
    meshed = {
        str(n["uid"]): n
        for n in nodes
        if isinstance(n, dict) and n.get("uid") and n.get("is_meshed") is True
    }
    if len(meshed) < 2:
        return out  # one box alone is no mesh: nothing to report
    master = next((u for u, n in meshed.items() if n.get("mesh_role") == "master"), None)
    own = next(
        (u for u, n in meshed.items() if _mac(n.get("device_mac_address")) in own_macs),
        master,
    )
    if master is None or own is None:
        return out
    ids = {u: own_id if u == own else object_id(own_id, "node", _slug(u)) for u in meshed}

    # links between meshed nodes, by uid pair, and the interface of each end
    edges: dict[str, list[dict[str, Any]]] = {u: [] for u in meshed}
    iface: dict[str, dict[str, Any]] = {}
    for node in meshed.values():
        for itf in node.get("node_interfaces") or []:
            if isinstance(itf, dict) and itf.get("uid"):
                iface[str(itf["uid"])] = itf
    for node in meshed.values():
        for itf in node.get("node_interfaces") or []:
            for lk in (itf.get("node_links") if isinstance(itf, dict) else None) or []:
                if not isinstance(lk, dict):
                    continue
                a, b = str(lk.get("node_1_uid")), str(lk.get("node_2_uid"))
                if a in meshed and b in meshed and a != b:
                    if str(lk.get("state", "CONNECTED")).upper() != "CONNECTED":
                        continue
                    if not any(x is lk or x.get("uid") == lk.get("uid") for x in edges[a]):
                        edges[a].append(lk)
                        edges[b].append(lk)

    # the tree from the master: parent of a node is the neighbour closer to the master
    parent: dict[str, tuple[str, dict[str, Any]]] = {}
    hops = {master: 0}
    queue = deque([master])
    while queue:
        cur = queue.popleft()
        for lk in edges[cur]:
            other = str(lk["node_2_uid"] if lk["node_1_uid"] == cur else lk["node_1_uid"])
            if other in hops:
                continue
            wireless = str(lk.get("type", "")).upper() == "WLAN"
            hops[other] = hops[cur] + (1 if wireless else 0)
            parent[other] = (cur, lk)
            queue.append(other)

    for uid, node in sorted(meshed.items()):
        did = ids[uid]
        link = parent.get(uid)
        is_master = uid == master
        wired = link is not None and str(link[1].get("type", "")).upper() != "WLAN"
        uplink = None if link is None else MeshUplink.WIRED if wired else MeshUplink.WIRELESS
        out.mesh[did] = MeshMembership(
            role=MeshRole.CONTROLLER if is_master else MeshRole.REPEATER,
            controller_id=None if is_master else ids[master],
            hop=hops.get(uid),
            uplink=uplink,
        )
        if uid != own:
            addresses = [x for i in node.get("node_interfaces") or [] if (x := _v4(i.get("ip")))]
            version = str(node.get("device_firmware_version") or "").strip()
            out.devices.append(
                Device(
                    id=did,
                    site_id="",
                    name=str(node.get("device_name") or uid),
                    role=role if not is_master else DeviceRole.GATEWAY,
                    vendor=str(node.get("device_manufacturer") or "AVM"),
                    model=str(node.get("device_model") or "") or None,
                    firmware=Firmware(current=version) if version else None,
                    management_address=addresses[0] if addresses else None,
                    mac=_mac(node.get("device_mac_address")),
                    adapter="",
                )
            )
        if link is None or wired:
            continue
        up_uid, lk = link
        up_id = ids[up_uid]
        a_if, b_if = (
            (iface.get(str(lk.get("node_interface_1_uid"))) or {}),
            (iface.get(str(lk.get("node_interface_2_uid"))) or {}),
        )
        if lk.get("node_1_uid") != up_uid:
            a_if, b_if = b_if, a_if  # a: the upstream node's interface, b: this node's
        slug = _slug(uid)
        pa, pb = port_id(up_id, f"mesh-{slug}"), port_id(did, "uplink")
        out.ports += [
            Port(
                id=pa,
                device_id=up_id,
                name=f"mesh-{slug}",
                kind=PortKind.WIRELESS,
                up=True,
                mac=_mac(a_if.get("mac_address")),
            ),
            Port(
                id=pb,
                device_id=did,
                name="uplink",
                kind=PortKind.WIRELESS,
                up=True,
                mac=_mac(b_if.get("mac_address")),
            ),
        ]
        names = " ".join(str(i.get("name", "")) for i in (b_if, a_if))
        rx, tx = _mbps(lk.get("cur_data_rate_rx")), _mbps(lk.get("cur_data_rate_tx"))
        rcpi = [dbm(lk.get("rx_rcpi")), dbm(lk.get("tx_rcpi"))]
        signals = [x for x in rcpi if x is not None]
        channel = b_if.get("current_channel") or a_if.get("current_channel")
        out.links.append(
            Link(
                id=f"mesh:{min(pa, pb)}~{max(pa, pb)}",
                a=pa,
                b=pb,
                kind=LinkKind.WIRELESS,
                origin=LinkOrigin.MESH,
                wireless=WirelessLinkInfo(
                    band=_band(names),
                    channel=int(channel) if isinstance(channel, int) and channel > 0 else None,
                    signal_dbm=min(signals) if signals else None,
                    tx_rate_mbps=tx,
                    rx_rate_mbps=rx,
                    kind=MeshLinkKind.MESH,
                ),
            )
        )
    return out
