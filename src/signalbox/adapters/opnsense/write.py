"""OPNsense write side: translate changes into REST calls (planning only, no I/O here).

Each change becomes a list of :class:`Call` computed from a :class:`WriteState`, a parsed read
of the firewall. ``plan_changes`` plans every change against one read and lets each planned
change update the state (a new interface, a new Kea subnet) so that later changes in the same
batch can refer to it through a placeholder; ``apply`` reads the firewall again before every
change, so the calls it sends always refer to real identifiers.

What each kind does, and why it is limited, is documented in ``docs/adapters/opnsense.md``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from ipaddress import IPv4Interface, ip_network
from typing import TYPE_CHECKING, Any

from signalbox.adapters import AdapterError, VendorCall
from signalbox.changes import (
    Change,
    ChangeKind,
    DhcpValue,
    PortValue,
    ReservationValue,
    RouterValue,
)
from signalbox.model import IPInterface, Membership, normalise_mac

if TYPE_CHECKING:  # pragma: no cover - import cycle at runtime
    from signalbox.adapters.opnsense import _Iface, _Layout

VLAN_ADD = "/api/interfaces/vlan_settings/add_item"
VLAN_DEL = "/api/interfaces/vlan_settings/del_item/"
VLAN_APPLY = "/api/interfaces/vlan_settings/reconfigure"
ASSIGN_SEARCH = "/api/interfaces/assignment/search_item"
ASSIGN_ADD = "/api/interfaces/assignment/add_item"
ASSIGN_SET = "/api/interfaces/assignment/set_item/"
ASSIGN_DEL = "/api/interfaces/assignment/del_item/"
ASSIGN_APPLY = "/api/interfaces/assignment/reconfigure"
KEA_SET = "/api/kea/dhcpv4/set"
KEA_ADD_SUBNET = "/api/kea/dhcpv4/add_subnet"
KEA_SET_SUBNET = "/api/kea/dhcpv4/set_subnet/"
KEA_DEL_SUBNET = "/api/kea/dhcpv4/del_subnet/"
KEA_ADD_RES = "/api/kea/dhcpv4/add_reservation"
KEA_SET_RES = "/api/kea/dhcpv4/set_reservation/"
KEA_DEL_RES = "/api/kea/dhcpv4/del_reservation/"
KEA_APPLY = "/api/kea/service/reconfigure"
BACKUPS = "/api/core/backup/backups/this"
DOWNLOAD = "/api/core/backup/download/this/"
REVERT = "/api/core/backup/revert_backup/"

#: OPNsense's mask for interface descriptions (``IfDescField``).
DESCR = re.compile(r"^[a-z_0-9]{1,255}$", re.IGNORECASE)


@dataclass(frozen=True)
class Call:
    description: str
    path: str
    payload: dict[str, Any] = field(default_factory=dict)
    method: str = "POST"

    def vendor(self) -> VendorCall:
        return VendorCall(
            description=self.description, method=self.method, target=self.path, payload=self.payload
        )

    @property
    def kea(self) -> bool:
        return self.path.startswith("/api/kea/")


@dataclass
class WriteState:
    """What the planner needs to know about the firewall (mutable while planning)."""

    site: str
    layout: _Layout
    #: VLAN devices: uuid, vlanif, if (parent), tag, descr
    vlans: list[dict[str, Any]]
    #: Kea DHCPv4 settings (``dhcpv4`` of ``/api/kea/dhcpv4/get``); None: Kea not available
    kea: dict[str, Any] | None
    #: segments served by ISC DHCP (not writable through the API)
    isc: set[str]
    #: Kea subnets and reservations by uuid
    subnets: dict[str, dict[str, Any]] = field(default_factory=dict)
    reservations: dict[str, dict[str, Any]] = field(default_factory=dict)
    listen: list[str] = field(default_factory=list)
    kea_enabled: bool = False
    lifetime: int | None = None

    def iface(self, sid: str) -> _Iface | None:
        return next((i for i in self.layout.ifaces if i.segment == sid), None)

    def vlan(self, tag: int) -> dict[str, Any] | None:
        """The VLAN device with this tag, preferably on the LAN's port."""
        rows = [v for v in self.vlans if _tag(v) == tag]
        preferred = [v for v in rows if v["if"] == self.lan_parent(required=False)]
        return next(iter(preferred or rows), None)

    def lan_parent(self, required: bool = True) -> str | None:
        lan = self.layout.by_identifier("lan")
        if lan is None or lan.port is None:
            if required:
                raise AdapterError("no LAN port found to carry a new VLAN; add the VLAN first")
            return None
        return lan.port.rsplit("/port/", 1)[-1]

    def subnet_of(self, iface: _Iface) -> tuple[str, dict[str, Any]] | None:
        """The Kea subnet the read side attaches to this interface."""
        for uuid, s in self.subnets.items():
            try:
                net = ip_network(str(s.get("subnet", "")).strip(), strict=False)
            except ValueError:
                continue
            if self.layout.containing(net[1] if net.num_addresses > 1 else net[0]) is iface:
                return uuid, s
        return None


def _tag(row: dict[str, Any]) -> int | None:
    try:
        return int(str(row.get("tag", "")).strip())
    except ValueError:
        return None


def _v4(iface: _Iface) -> IPInterface | None:
    return next((a for a in iface.addresses if isinstance(a, IPv4Interface)), None)


def _segment_vlan(sid: str) -> tuple[int | None, str]:
    """VLAN of a segment id (None for native or a named port network) and its last part."""
    last = sid.rsplit("/", 1)[-1]
    return (int(last), last) if last.isdigit() else (None, last)


def calls_for(change: Change, st: WriteState) -> list[Call]:
    if change.kind is ChangeKind.ROUTER:
        return _router(change, st)
    if change.kind is ChangeKind.DHCP:
        return _dhcp(change, st)
    if change.kind is ChangeKind.RESERVATION:
        return _reservation(change, st)
    if change.kind is ChangeKind.PORT:
        return _port(change, st)
    raise AdapterError(f"OPNsense cannot change {change.kind.value}")


# --- router interfaces ---------------------------------------------------------------------


def _router(c: Change, st: WriteState) -> list[Call]:
    from signalbox.adapters.opnsense import _Iface

    sid = c.key
    tag, last = _segment_vlan(sid)
    iface = st.iface(sid)
    new = c.new
    if new is None:
        if iface is None:
            return []  # already gone
        if tag is None:
            raise AdapterError(
                f"{sid}: Signalbox removes only VLAN networks; the LAN and networks on their "
                "own port stay assigned (unassign them in the web interface)"
            )
        calls = [
            Call(f"unassign interface {iface.identifier}", ASSIGN_DEL + iface.identifier),
            Call("apply the interface assignments", ASSIGN_APPLY),
        ]
        st.layout.ifaces.remove(iface)
        row = next((v for v in st.vlans if v.get("vlanif") == iface.device), None)
        if row is not None and st.layout.by_device(iface.device) is None:
            calls += [
                Call(f"delete VLAN device {iface.device}", VLAN_DEL + str(row["uuid"])),
                Call("apply the VLAN devices", VLAN_APPLY),
            ]
            st.vlans.remove(row)
        return calls
    assert isinstance(new, RouterValue)
    if new.vlan != tag:
        raise AdapterError(f"{sid}: VLAN {new.vlan} does not belong to this network")
    if not isinstance(new.address, IPv4Interface):
        raise AdapterError(f"{sid}: only IPv4 router addresses can be set")
    if new.name is not None and not DESCR.match(new.name):
        raise AdapterError(
            f"{sid}: OPNsense interface names may only contain letters, digits and _ ({new.name!r})"
        )
    item: dict[str, Any] = {"enable": "1", "type4": "staticv4", "ipaddr": str(new.address)}
    if new.name is not None:
        item["descr"] = new.name
    if iface is not None:
        calls = [
            Call(
                f"set address {new.address} on interface {iface.identifier}",
                ASSIGN_SET + iface.identifier,
                {"interface": item},
            ),
            Call("apply the interface assignments", ASSIGN_APPLY),
        ]
        iface.addresses = [
            new.address,
            *(a for a in iface.addresses if not isinstance(a, IPv4Interface)),
        ]
        iface.description = new.name or iface.description
        return calls
    if tag is None:
        raise AdapterError(
            f"{sid}: no interface is assigned to this network ({last}); assign its port in the "
            "web interface first"
        )
    if new.name is None:
        raise AdapterError(f"{sid}: give the network a name (OPNsense names every interface)")
    calls = []
    row = st.vlan(tag)
    if row is None:
        parent = st.lan_parent()
        assert parent is not None
        row = _new_vlan(st, parent, tag, new.name)
        calls += [
            Call(f"create VLAN {tag} on {parent}", VLAN_ADD, {"vlan": _vlan_item(row)}),
            Call("apply the VLAN devices", VLAN_APPLY),
        ]
    vlanif = str(row["vlanif"])
    calls += [
        Call(
            f"assign {vlanif} as {new.name} with {new.address}",
            ASSIGN_ADD,
            {"interface": {"if": vlanif, "lock": "0", **item}},
        ),
        Call("apply the interface assignments", ASSIGN_APPLY),
    ]
    parent_port = next(
        (p.id for p in st.layout.ports if p.name == row["if"]),
        None,
    )
    st.layout.ifaces.append(
        _Iface(
            identifier=f"{{new interface on {vlanif}}}",
            device=vlanif,
            description=new.name,
            port=parent_port,
            vlan=tag,
            segment=sid,
            addresses=[new.address],
        )
    )
    return calls


def _new_vlan(st: WriteState, parent: str, tag: int, descr: str) -> dict[str, Any]:
    names = {str(v.get("vlanif")) for v in st.vlans}
    vlanif = f"vlan0.{tag}" if f"vlan0.{tag}" not in names else f"{parent}_vlan{tag}"
    row = {"uuid": f"{{new VLAN {parent}.{tag}}}", "if": parent, "tag": str(tag)}
    row |= {"descr": descr, "vlanif": vlanif}
    st.vlans.append(row)
    return row


def _vlan_item(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "if": row["if"],
        "tag": row["tag"],
        "pcp": "0",
        "proto": "",
        "descr": row["descr"],
        "vlanif": row["vlanif"],
    }


# --- Kea DHCP --------------------------------------------------------------------------------


def _kea(st: WriteState, sid: str) -> None:
    if sid in st.isc:
        raise AdapterError(
            f"{sid} is served by ISC DHCP, which the OPNsense API cannot change; move the "
            "network to Kea DHCP (Services > Kea DHCP) to manage it with Signalbox"
        )
    if st.kea is None:
        raise AdapterError("Kea DHCP is not available on this firewall (API answered 404)")


def _dhcp(c: Change, st: WriteState) -> list[Call]:
    sid = c.key
    _kea(st, sid)
    iface = st.iface(sid)
    found = st.subnet_of(iface) if iface else None
    new = c.new
    calls: list[Call] = []
    listen = list(st.listen)
    enable = st.kea_enabled
    if new is None:
        if found is not None:
            calls.append(
                Call(f"delete Kea subnet {found[1].get('subnet')}", KEA_DEL_SUBNET + found[0])
            )
            del st.subnets[found[0]]
        if iface is not None and iface.identifier in listen:
            listen.remove(iface.identifier)
    else:
        assert isinstance(new, DhcpValue)
        if iface is None or (own := _v4(iface)) is None:
            raise AdapterError(
                f"{sid}: the firewall has no IPv4 interface on this network; set its router "
                "address first"
            )
        if new.lease_seconds is None and st.lifetime is not None:
            raise AdapterError(
                f"{sid}: give lease_seconds; Kea always hands out a lease time (the default "
                f"here is {st.lifetime} s)"
            )
        old = found[1] if found else {}
        options = old.get("option_data") if isinstance(old.get("option_data"), dict) else {}
        autocollect = str(old.get("option_data_autocollect", "0")) == "1"
        data: dict[str, Any] = {
            "subnet": str(old.get("subnet") or own.network),
            "pools": f"{new.pool[0]}-{new.pool[1]}" if new.pool else "",
            "valid_lifetime": str(new.lease_seconds) if new.lease_seconds else "",
        }
        option_data = {"domain_name_servers": ",".join(str(a) for a in new.dns or [])}
        if found is None or (new.dns is None and autocollect):
            # without autocollect an empty DNS option stays empty: the read shows no DNS
            data["option_data_autocollect"] = "0"
            option_data["routers"] = str((options or {}).get("routers") or "") or str(own.ip)
        data["option_data"] = option_data
        if found is None:
            data["description"] = iface.description
            calls.append(
                Call(f"create Kea subnet {data['subnet']}", KEA_ADD_SUBNET, {"subnet4": data})
            )
            st.subnets[f"{{new subnet {data['subnet']}}}"] = data
        else:
            calls.append(
                Call(
                    f"update Kea subnet {data['subnet']}",
                    KEA_SET_SUBNET + found[0],
                    {"subnet4": data},
                )
            )
            found[1].update(data)
        if new.enabled and iface.identifier not in listen:
            listen.append(iface.identifier)
        if not new.enabled and iface.identifier in listen:
            listen.remove(iface.identifier)
        enable = enable or new.enabled
    if listen != st.listen or enable != st.kea_enabled:
        general = {"enabled": "1" if enable else "0", "interfaces": ",".join(listen)}
        calls.append(
            Call(
                "set the interfaces Kea listens on: " + (", ".join(listen) or "none"),
                KEA_SET,
                {"dhcpv4": {"general": general}},
            )
        )
        st.listen, st.kea_enabled = listen, enable
    return calls


def _reservation(c: Change, st: WriteState) -> list[Call]:
    sid, mac = c.key.rsplit("/", 1)
    _kea(st, sid)
    iface = st.iface(sid)
    found = st.subnet_of(iface) if iface else None
    if found is None:
        if c.new is None:
            return []
        raise AdapterError(f"{sid}: no Kea subnet on this network; set up DHCP first")
    uuid = found[0]
    existing = next(
        (
            k
            for k, r in st.reservations.items()
            if _refers(r.get("subnet"), uuid) and _same_mac(r.get("hw_address"), mac)
        ),
        None,
    )
    new = c.new
    if new is None:
        if existing is None:
            return []
        del st.reservations[existing]
        return [Call(f"delete the reservation of {mac}", KEA_DEL_RES + existing)]
    assert isinstance(new, ReservationValue)
    item = {
        "subnet": uuid,
        "ip_address": str(new.address),
        "hw_address": new.mac,
        "hostname": new.hostname or "",
        "description": "",
    }
    if existing is None:
        st.reservations[f"{{new reservation {mac}}}"] = item
        return [
            Call(f"reserve {new.address} for {mac}", KEA_ADD_RES, {"reservation": item}),
        ]
    st.reservations[existing] = item
    return [
        Call(
            f"change the reservation of {mac} to {new.address}",
            KEA_SET_RES + existing,
            {"reservation": item},
        )
    ]


def _refers(value: Any, uuid: str) -> bool:
    if isinstance(value, dict):
        return uuid in value and (not isinstance(value[uuid], dict) or _sel(value[uuid]))
    return uuid in str(value or "").split(",")


def _sel(option: dict[str, Any]) -> bool:
    return option.get("selected") in (1, "1", True)


def _same_mac(value: Any, mac: str) -> bool:
    try:
        return normalise_mac(str(value or "")) == normalise_mac(mac)
    except ValueError:
        return False


# --- ports -----------------------------------------------------------------------------------


def _port(c: Change, st: WriteState) -> list[Call]:
    port = next((p for p in st.layout.ports if p.id == c.key), None)
    if port is None:
        raise AdapterError(f"{c.key}: no such port on the firewall")
    new = c.new if isinstance(c.new, PortValue) else PortValue()
    untagged = None
    for seg in st.layout.segments.values():
        if any(m.port_id == port.id and m.mode is Membership.UNTAGGED for m in seg.members):
            untagged = "native" if seg.vlan in (None, 1) else seg.vlan
    if new.untagged != untagged:
        raise AdapterError(
            f"{c.key}: the untagged network of a port is its interface assignment, which "
            "Signalbox does not change; change it in the web interface"
        )
    have = {t: v for v in st.vlans if v["if"] == port.name and (t := _tag(v)) is not None}
    calls: list[Call] = []
    for tag in sorted(set(new.tagged) - set(have)):
        row = _new_vlan(st, port.name, tag, "")
        calls.append(Call(f"create VLAN {tag} on {port.name}", VLAN_ADD, {"vlan": _vlan_item(row)}))
    for tag in sorted(set(have) - set(new.tagged)):
        row = have[tag]
        user = st.layout.by_device(str(row.get("vlanif")))
        if user is not None:
            raise AdapterError(
                f"{c.key}: VLAN {tag} carries the network {user.description} "
                f"({user.identifier}); remove its router interface first"
            )
        calls.append(Call(f"delete VLAN {tag} on {port.name}", VLAN_DEL + str(row["uuid"])))
        st.vlans.remove(row)
    if calls:
        calls.append(Call("apply the VLAN devices", VLAN_APPLY))
    return calls
