"""SNMP tables → the Signalbox model. Pure functions, no I/O.

``Mib`` holds what was read (columns as walked, keyed by the index below the column OID); the
functions here turn it into ports, VLANs, MAC table, spanning tree, link aggregation and LLDP
neighbours. What the switch does not offer stays ``None`` or empty (never invented).

Mapping rules (docs/adapters/snmp.md):

- Ports are the interfaces of IF-MIB with an Ethernet type (``ethernetCsmacd``, ``fastEther``,
  ``gigabitEthernet``, ...) plus link aggregations (``ieee8023adLag``). VLAN, loopback, CPU and
  tunnel interfaces are not ports. The port name is ``ifName`` (else ``ifDescr``).
- Bridge port numbers (Q-BRIDGE-MIB, BRIDGE-MIB, usually equal to ``ifIndex``) are translated
  with ``dot1dBasePortIfIndex``.
- A VLAN is one segment; members are the egress ports of the static VLAN table (the current
  table where a switch has no static one), untagged where the port is in the untagged set.
- Link aggregation comes from IEEE8023-LAG-MIB (LACP, with the partner) and from ``ifStackTable``
  (any aggregation, mode unknown).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from pydantic import JsonValue

from signalbox.adapters import SystemInfo
from signalbox.adapters.snmp import mib
from signalbox.adapters.snmp.client import Value, column
from signalbox.model import (
    DeviceHealth,
    FdbEntry,
    FdbKind,
    Firmware,
    FrameTypes,
    LacpRate,
    LagMemberState,
    LagMode,
    Membership,
    Neighbour,
    PoePriority,
    PoeStatus,
    PoeSupply,
    Port,
    PortCounters,
    PortKind,
    PortMembership,
    PortPoe,
    PortRole,
    Segment,
    StpBridge,
    StpPort,
    StpPortState,
    StpProtocol,
    fdb_id,
    normalise_capabilities,
    normalise_mac,
    object_id,
    parse_stp_bridge_id,
    port_id,
    segment_id,
    stp_bridge_id,
)

#: ifType values of Ethernet ports: ethernetCsmacd, fastEther, fastEtherFX, gigabitEthernet
ETHERNET_TYPES = frozenset({6, 62, 69, 117})
#: ifType ieee8023adLag
LAG_TYPE = 161
#: "no speed in ifSpeed": the 32 bit gauge's maximum means "4.29 Gbit/s or more"
_SPEED_CAP = 4_294_967_295


@dataclass
class Mib:
    """What was read: the walked rows per subtree (full OID → value) and the scalars."""

    scalars: dict[str, Value] = field(default_factory=dict)
    walks: dict[str, dict[str, Value]] = field(default_factory=dict)

    def col(self, table: str, number: int | None = None) -> dict[str, Value]:
        """A column of a table walked as ``table.number`` (index → value), or a whole walked
        subtree (``number`` None); empty when it was not read or the switch has none."""
        base = table if number is None else f"{table}.{number}"
        return column(self.walks.get(base, {}), base)

    def has(self, table: str, number: int | None = None) -> bool:
        return bool(self.col(table, number))


# -- value helpers ----------------------------------------------------------------------------


def as_int(value: Value | None) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def as_bytes(value: Value | None) -> bytes | None:
    return value if isinstance(value, bytes) else None


def as_text(value: Value | None) -> str | None:
    """An OCTET STRING as text (control characters dropped); None when empty."""
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        text = value
    else:
        return None
    text = "".join(ch for ch in text if ch.isprintable()).strip()
    return text or None


def as_mac(value: Value | None) -> str | None:
    """A 6 octet MAC address; None for anything else and for the all-zero address."""
    if not isinstance(value, bytes) or len(value) != 6 or not any(value):
        return None
    return normalise_mac(value.hex())


def portlist(value: Value | None) -> set[int]:
    """A PortList (bitmap, port 1 is the most significant bit of the first octet)."""
    out: set[int] = set()
    if isinstance(value, bytes):
        for byte_no, byte in enumerate(value):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    out.add(byte_no * 8 + bit + 1)
    return out


def _numeric(index: str) -> int | None:
    return int(index) if index.isdigit() else None


def _sorted_by_number(keys: list[str]) -> list[str]:
    return sorted(keys, key=lambda k: (_numeric(k) is None, _numeric(k) or 0, k))


# -- system -------------------------------------------------------------------------------------


def vendor_of(object_id_value: Value | None) -> str | None:
    """The vendor name from the enterprise number of sysObjectID."""
    if isinstance(object_id_value, str) and object_id_value.startswith("1.3.6.1.4.1."):
        number = object_id_value.split(".")[6:7]
        if number and number[0].isdigit():
            return mib.ENTERPRISES.get(int(number[0]))
    return None


def chassis_index(classes: dict[str, Value]) -> str | None:
    """The ENTITY-MIB entity of the (first) chassis."""
    chassis = [k for k, v in classes.items() if as_int(v) == mib.ENT_CLASS_CHASSIS]
    return _sorted_by_number(chassis)[0] if chassis else None


def system_info(
    scalars: dict[str, Value], entity: dict[int, Value], address: str, bridge_mac: str | None
) -> SystemInfo:
    """SNMPv2-MIB and the chassis entry of ENTITY-MIB (``entity``: column → value)."""
    descr = as_text(scalars.get(mib.SYS_DESCR))
    name = as_text(scalars.get(mib.SYS_NAME))
    model = as_text(entity.get(mib.ENT_MODEL)) or as_text(entity.get(mib.ENT_DESCR))
    software = as_text(entity.get(mib.ENT_SOFTWARE_REV))
    firmware = as_text(entity.get(mib.ENT_FIRMWARE_REV))
    version = software or firmware
    vendor = as_text(entity.get(mib.ENT_MFG)) or vendor_of(scalars.get(mib.SYS_OBJECT_ID))
    extra: dict[str, JsonValue] = {}
    for key, value in (
        ("sys_descr", descr),
        ("sys_name", name),
        ("sys_object_id", scalars.get(mib.SYS_OBJECT_ID)),
        ("firmware_revision", firmware),
    ):
        if isinstance(value, str) and value:
            extra[key] = value
    return SystemInfo(
        vendor=vendor,
        model=model,
        firmware=Firmware(current=version) if version else None,
        management_address=address,
        mac=bridge_mac,
        # Identity (#177): ENTITY-MIB chassis entry and SNMPv2-MIB system group
        serial=as_text(entity.get(mib.ENT_SERIAL)) or None,
        hardware_revision=as_text(entity.get(mib.ENT_HARDWARE_REV)) or None,
        hostname=name or None,
        location=as_text(scalars.get(mib.SYS_LOCATION)) or None,
        contact=as_text(scalars.get(mib.SYS_CONTACT)) or None,
        vendor_extra=extra,
    )


def health(scalars: dict[str, Value]) -> DeviceHealth | None:
    ticks = as_int(scalars.get(mib.SYS_UPTIME))
    return DeviceHealth(uptime_seconds=ticks // 100) if ticks is not None and ticks >= 0 else None


# -- ports --------------------------------------------------------------------------------------


@dataclass
class PortMap:
    """The ports of a switch and how the other tables point at them."""

    ports: list[Port] = field(default_factory=list)
    #: ifIndex → port id
    by_if: dict[int, str] = field(default_factory=dict)
    #: bridge port number → ifIndex
    bridge_if: dict[int, int] = field(default_factory=dict)
    #: port name → ifIndex (for LLDP, which names ports)
    names: dict[str, int] = field(default_factory=dict)
    macs: dict[str, int] = field(default_factory=dict)

    def of_bridge(self, bridge_port: int) -> str | None:
        return self.by_if.get(self.bridge_if.get(bridge_port, bridge_port))


@dataclass
class Lags:
    """Link aggregations: aggregator ifIndex → member ifIndexes, and LACP details."""

    members: dict[int, list[int]] = field(default_factory=dict)
    lacp: set[int] = field(default_factory=set)
    #: aggregator → members' LACP "activity" flag (True: active)
    active: dict[int, bool] = field(default_factory=dict)
    fast: dict[int, bool] = field(default_factory=dict)
    state: dict[int, LagMemberState] = field(default_factory=dict)


def lags(data: Mib) -> Lags:
    """IEEE8023-LAG-MIB (LACP aggregators and their members) and ``ifStackTable``."""
    out = Lags()
    ifaces = data.col(mib.IF_TABLE, mib.IF_TYPE)
    lag_ifs = {int(k) for k, v in ifaces.items() if as_int(v) == LAG_TYPE and k.isdigit()}
    aggregators = {int(k) for k in data.col(mib.LAG_AGG, 1) if k.isdigit()}
    attached = data.col(mib.LAG_PORT, mib.LAG_PORT_ATTACHED)
    selected = data.col(mib.LAG_PORT, mib.LAG_PORT_SELECTED)
    admin = data.col(mib.LAG_PORT, mib.LAG_PORT_ADMIN_STATE)
    oper = data.col(mib.LAG_PORT, mib.LAG_PORT_OPER_STATE)
    partner_system = data.col(mib.LAG_PORT, mib.LAG_PORT_PARTNER_SYSTEM)
    partner_key = data.col(mib.LAG_PORT, mib.LAG_PORT_PARTNER_KEY)
    partner_port = data.col(mib.LAG_PORT, mib.LAG_PORT_PARTNER_PORT)
    for key in _sorted_by_number(list({*attached, *selected})):
        if not key.isdigit():
            continue
        member = int(key)
        agg = as_int(attached.get(key)) or as_int(selected.get(key)) or 0
        if agg <= 0:
            continue
        out.members.setdefault(agg, []).append(member)
        out.lacp.add(agg)
        admin_bits = as_bytes(admin.get(key)) or b""
        oper_bits = as_bytes(oper.get(key)) or b""
        if admin_bits:
            out.active[agg] = out.active.get(agg, False) or bool(admin_bits[0] & 0x80)
            out.fast[agg] = out.fast.get(agg, False) or bool(admin_bits[0] & 0x40)
        pkey = as_int(partner_key.get(key))
        pport = as_int(partner_port.get(key))
        psys = as_bytes(partner_system.get(key))
        out.state[member] = LagMemberState(
            selected=as_int(attached.get(key)) is not None and bool(as_int(attached.get(key))),
            # state bits (802.1AX): collecting is bit 4, distributing bit 5 (MSB first)
            collecting_distributing=(
                bool(oper_bits[0] & 0x08) and bool(oper_bits[0] & 0x04) if oper_bits else None
            ),
            partner_system_id=as_mac(psys[-6:]) if psys and len(psys) >= 6 else None,
            partner_port=pport if pport is not None and 0 <= pport <= 65535 else None,
            partner_key=pkey if pkey is not None and 0 <= pkey <= 65535 else None,
        )
    for key, status in data.col(mib.IF_STACK_STATUS).items():
        higher, _, lower = key.partition(".")
        if not (higher.isdigit() and lower.isdigit()) or as_int(status) != 1:
            continue
        agg, member = int(higher), int(lower)
        known = any(member in m for m in out.members.values())
        if agg in lag_ifs and member not in lag_ifs and not known:
            out.members.setdefault(agg, []).append(member)
    # an aggregator the LACP table knows is LACP even without members
    out.lacp |= aggregators & lag_ifs
    return out


def _speed(up: bool | None, high: int | None, low: int | None) -> int | None:
    if not up:
        return None
    if high:
        return high
    if low and low < _SPEED_CAP:
        return max(1, low // 1_000_000)
    return None


#: The columns of ifTable and ifXTable read for the counters (#158).
IF_COUNTER_COLUMNS = (
    mib.IF_IN_OCTETS,
    mib.IF_IN_UCAST,
    mib.IF_IN_DISCARDS,
    mib.IF_IN_ERRORS,
    mib.IF_OUT_OCTETS,
    mib.IF_OUT_UCAST,
    mib.IF_OUT_DISCARDS,
    mib.IF_OUT_ERRORS,
)
IF_X_COUNTER_COLUMNS = (
    mib.IF_IN_MCAST,
    mib.IF_IN_BCAST,
    mib.IF_OUT_MCAST,
    mib.IF_OUT_BCAST,
    mib.IF_HC_IN_OCTETS,
    mib.IF_HC_IN_UCAST,
    mib.IF_HC_IN_MCAST,
    mib.IF_HC_IN_BCAST,
    mib.IF_HC_OUT_OCTETS,
    mib.IF_HC_OUT_UCAST,
    mib.IF_HC_OUT_MCAST,
    mib.IF_HC_OUT_BCAST,
)


def _counter(data: Mib, key: str, *columns: tuple[str, int]) -> int | None:
    """The first of the columns the switch has for the interface (the 64-bit HC counter before
    the 32-bit one, which wraps in about half a minute on a gigabit link)."""
    for table, number in columns:
        value = as_int(data.col(table, number).get(key))
        if value is not None and value >= 0:
            return value
    return None


def if_counters(data: Mib, key: str) -> PortCounters | None:
    """IF-MIB counters of an interface: the HC octet and packet counters (unicast, multicast and
    broadcast added), else the 32-bit ones, the error and discard counters, and EtherLike-MIB
    ``dot3StatsFCSErrors`` for the CRC errors. None when the switch reports none."""
    x, t = mib.IF_X_TABLE, mib.IF_TABLE

    def packets(*kinds: tuple[int, tuple[str, int]]) -> int | None:
        """Unicast, multicast and broadcast packets of one direction, each from its HC counter
        (``kinds``: the HC column, the 32-bit column with its table)."""
        parts = [_counter(data, key, (x, hc), plain) for hc, plain in kinds]
        known = [p for p in parts if p is not None]
        return sum(known) if known else None

    crc = as_int(data.col(mib.DOT3_FCS_ERRORS).get(key))
    values = {
        "rx_bytes": _counter(data, key, (x, mib.IF_HC_IN_OCTETS), (t, mib.IF_IN_OCTETS)),
        "tx_bytes": _counter(data, key, (x, mib.IF_HC_OUT_OCTETS), (t, mib.IF_OUT_OCTETS)),
        "rx_packets": packets(
            (mib.IF_HC_IN_UCAST, (t, mib.IF_IN_UCAST)),
            (mib.IF_HC_IN_MCAST, (x, mib.IF_IN_MCAST)),
            (mib.IF_HC_IN_BCAST, (x, mib.IF_IN_BCAST)),
        ),
        "tx_packets": packets(
            (mib.IF_HC_OUT_UCAST, (t, mib.IF_OUT_UCAST)),
            (mib.IF_HC_OUT_MCAST, (x, mib.IF_OUT_MCAST)),
            (mib.IF_HC_OUT_BCAST, (x, mib.IF_OUT_BCAST)),
        ),
        "rx_errors": _counter(data, key, (t, mib.IF_IN_ERRORS)),
        "tx_errors": _counter(data, key, (t, mib.IF_OUT_ERRORS)),
        "rx_drops": _counter(data, key, (t, mib.IF_IN_DISCARDS)),
        "tx_drops": _counter(data, key, (t, mib.IF_OUT_DISCARDS)),
        "rx_crc_errors": crc if crc is not None and crc >= 0 else None,
    }
    present = {k: v for k, v in values.items() if v is not None}
    return PortCounters(**present) if present else None


def ports(device_id: str, data: Mib) -> tuple[PortMap, Lags]:
    """Ports with their link, speed, MTU, MAC, VLAN settings, spanning tree and aggregation."""
    types = data.col(mib.IF_TABLE, mib.IF_TYPE)
    descr = data.col(mib.IF_TABLE, mib.IF_DESCR)
    mtu = data.col(mib.IF_TABLE, mib.IF_MTU)
    speed = data.col(mib.IF_TABLE, mib.IF_SPEED)
    phys = data.col(mib.IF_TABLE, mib.IF_PHYS)
    admin = data.col(mib.IF_TABLE, mib.IF_ADMIN)
    oper = data.col(mib.IF_TABLE, mib.IF_OPER)
    names = data.col(mib.IF_X_TABLE, mib.IF_NAME)
    high = data.col(mib.IF_X_TABLE, mib.IF_HIGH_SPEED)
    alias = data.col(mib.IF_X_TABLE, mib.IF_ALIAS)
    duplex = data.col(mib.DOT3_DUPLEX)
    pvids = data.col(mib.PORT_VLAN, mib.PVID)
    frames = data.col(mib.PORT_VLAN, mib.ACCEPTABLE_FRAMES)
    ingress = data.col(mib.PORT_VLAN, mib.INGRESS_FILTER)
    result = PortMap()
    for bridge_key, if_index in data.col(mib.BASE_PORT_IFINDEX).items():
        number, target = _numeric(bridge_key), as_int(if_index)
        if number is not None and target:
            result.bridge_if[number] = target
    link = lags(data)
    bridge_of = {v: k for k, v in result.bridge_if.items()}
    stp_ports = _stp_ports(data, result.bridge_if)

    wanted: list[int] = []
    for key in _sorted_by_number(list(types)):
        kind = as_int(types[key])
        if _numeric(key) is None or (kind not in ETHERNET_TYPES and kind != LAG_TYPE):
            continue
        if as_int(oper.get(key)) == 6:  # notPresent (an empty slot)
            continue
        wanted.append(int(key))
    used: set[str] = set()
    lag_name: dict[int, str] = {}
    pending: list[tuple[int, str]] = []
    for if_index in wanted:
        key = str(if_index)
        name = as_text(names.get(key)) or as_text(descr.get(key)) or key
        if name in used:
            name = f"{name}#{if_index}"
        used.add(name)
        pending.append((if_index, name))
        result.by_if[if_index] = port_id(device_id, name)
        result.names[name] = if_index
        text = as_text(descr.get(key))
        if text:
            result.names.setdefault(text, if_index)
        mac = as_mac(phys.get(key))
        if mac:
            result.macs.setdefault(mac, if_index)
        if as_int(types[key]) == LAG_TYPE:
            lag_name[if_index] = name
    member_of = {m: agg for agg, members in link.members.items() for m in members}

    for if_index, name in pending:
        key = str(if_index)
        is_lag = as_int(types[key]) == LAG_TYPE
        admin_state = as_int(admin.get(key))
        oper_state = as_int(oper.get(key))
        admin_up = {1: True, 2: False}.get(admin_state) if admin_state is not None else None
        up: bool | None
        if admin_up is False or oper_state in (2, 7):
            up = False
        elif oper_state == 1:
            up = True
        else:
            up = None
        high_speed, low_speed = as_int(high.get(key)), as_int(speed.get(key))
        mode = as_int(duplex.get(key))
        mtu_value = as_int(mtu.get(key))
        bridge_port = bridge_of.get(if_index, if_index if not bridge_of else None)
        pvid = as_int(pvids.get(str(bridge_port))) if bridge_port is not None else None
        frame = as_int(frames.get(str(bridge_port))) if bridge_port is not None else None
        filtering = as_int(ingress.get(str(bridge_port))) if bridge_port is not None else None
        extra: dict[str, JsonValue] = {"if_index": if_index}
        text = as_text(descr.get(key))
        if text and text != name:
            extra["if_descr"] = text
        members = sorted(link.members.get(if_index, [])) if is_lag else []
        agg = member_of.get(if_index)
        lag_member = lag_name.get(agg) if agg is not None and not is_lag else None
        lag_kwargs: dict[str, Any] = {}
        if is_lag:
            lacp = if_index in link.lacp
            lag_kwargs = {
                "role": PortRole.LAG,
                "lower": [result.by_if[m] for m in members if m in result.by_if],
                "lag_mode": (
                    (
                        LagMode.LACP_ACTIVE
                        if link.active.get(if_index, True)
                        else LagMode.LACP_PASSIVE
                    )
                    if lacp
                    else None
                ),
            }
            if lacp and if_index in link.fast:
                lag_kwargs["lacp_rate"] = LacpRate.FAST if link.fast[if_index] else LacpRate.SLOW
        else:
            lag_kwargs = {"role": PortRole.JACK, "lag": lag_member}
            if lag_member is not None and if_index in link.state:
                lag_kwargs["lag_member_state"] = link.state[if_index]
        result.ports.append(
            Port(
                id=result.by_if[if_index],
                device_id=device_id,
                name=name,
                kind=PortKind.LAG if is_lag else PortKind.ETHERNET,
                up=up,
                admin_up=admin_up,
                speed_mbps=_speed(up, high_speed, low_speed),
                full_duplex={2: False, 3: True}.get(mode) if up and mode is not None else None,
                mac=as_mac(phys.get(key)),
                description=_alias(alias.get(key), name),
                mtu=mtu_value if mtu_value is not None and 68 <= mtu_value <= 65535 else None,
                pvid=pvid if pvid is not None and 1 <= pvid <= 4094 else None,
                frame_types={
                    1: FrameTypes.ALL,
                    2: FrameTypes.TAGGED_ONLY,
                    3: FrameTypes.UNTAGGED_ONLY,
                }.get(frame)
                if frame is not None
                else None,
                ingress_filter={1: True, 2: False}.get(filtering)
                if filtering is not None
                else None,
                stp=stp_ports.get(if_index),
                counters=if_counters(data, key),
                vendor_extra=extra,
                **lag_kwargs,
            )
        )
    return result, link


def _alias(value: Value | None, name: str) -> str | None:
    text = as_text(value)
    return text if text and text != name else None


# -- VLANs --------------------------------------------------------------------------------------


def segments(site_id: str, pmap: PortMap, data: Mib) -> list[Segment] | None:
    """One segment per VLAN of Q-BRIDGE-MIB; ``None``: the switch has no VLAN table."""
    egress = data.col(mib.VLAN_STATIC, mib.VLAN_EGRESS)
    untagged = data.col(mib.VLAN_STATIC, mib.VLAN_UNTAGGED)
    names = data.col(mib.VLAN_STATIC, mib.VLAN_NAME)
    if not egress:  # a switch with only the current table (RFC 2674 allows it)
        egress, untagged, names = {}, {}, {}
        for key, value in data.col(mib.VLAN_CURRENT, mib.VLAN_CURRENT_EGRESS).items():
            egress[key.rpartition(".")[2]] = value
        for key, value in data.col(mib.VLAN_CURRENT, mib.VLAN_CURRENT_UNTAGGED).items():
            untagged[key.rpartition(".")[2]] = value
    if not egress:
        return None
    out: list[Segment] = []
    seen: set[str] = set()
    for key in _sorted_by_number(list(egress)):
        vid = _numeric(key)
        if vid is None or not 1 <= vid <= 4094:
            continue
        sid = segment_id(site_id, vid)
        if sid in seen:
            continue
        seen.add(sid)
        in_vlan = portlist(egress[key])
        plain = portlist(untagged.get(key))
        members: list[PortMembership] = []
        done: set[str] = set()
        for number in sorted(in_vlan | plain):
            pid = pmap.of_bridge(number)
            if pid is None or pid in done:
                continue
            done.add(pid)
            mode = Membership.UNTAGGED if number in plain else Membership.TAGGED
            members.append(PortMembership(port_id=pid, mode=mode))
        out.append(
            Segment(
                id=sid,
                site_id=site_id,
                vlan=vid,
                name=as_text(names.get(key)),
                members=members,
            )
        )
    return out


# -- MAC table ----------------------------------------------------------------------------------

_FDB_KINDS = {3: FdbKind.DYNAMIC, 4: FdbKind.SELF, 5: FdbKind.STATIC, 1: FdbKind.DYNAMIC}


def _mac_from_index(parts: list[str]) -> str | None:
    try:
        raw = bytes(int(p) for p in parts)
    except ValueError:
        return None
    return as_mac(raw) if len(raw) == 6 else None


def fdb(device_id: str, site_id: str, pmap: PortMap, data: Mib, vlans: set[int]) -> list[FdbEntry]:
    """The MAC address table: Q-BRIDGE-MIB per VLAN, else BRIDGE-MIB (one table)."""
    entries: dict[str, FdbEntry] = {}
    q_port = data.col(mib.Q_FDB_PORT)
    q_status = data.col(mib.Q_FDB_STATUS)
    legacy = not q_port
    rows = data.col(mib.TP_FDB_PORT) if legacy else q_port
    status = data.col(mib.TP_FDB_STATUS) if legacy else q_status
    for index, port_value in rows.items():
        parts = index.split(".")
        vlan: int | None = None
        if not legacy:
            if len(parts) != 7:
                continue
            fid = _numeric(parts[0])
            vlan = fid if fid in vlans else None
            parts = parts[1:]
        mac = _mac_from_index(parts)
        number = as_int(port_value)
        kind_code = as_int(status.get(index))
        if mac is None or not number or kind_code == 2:  # invalid, or on no port
            continue
        if int(mac[:2], 16) & 1:
            continue
        pid = pmap.of_bridge(number)
        if pid is None:
            continue
        port_name = pid.split("/port/", 1)[1]
        eid = fdb_id(device_id, port_name, mac, vlan)
        entries[eid] = FdbEntry(
            id=eid,
            device_id=device_id,
            port_id=pid,
            mac=mac,
            vlan=vlan,
            segment_id=segment_id(site_id, vlan) if vlan is not None else None,
            kind=_FDB_KINDS.get(kind_code or 3, FdbKind.DYNAMIC),
        )
    return list(entries.values())


# -- spanning tree ------------------------------------------------------------------------------

_STP_STATES = {
    1: StpPortState.DISABLED,
    2: StpPortState.BLOCKING,
    3: StpPortState.LISTENING,
    4: StpPortState.LEARNING,
    5: StpPortState.FORWARDING,
    6: StpPortState.DISABLED,
}


def _stp_ports(data: Mib, bridge_if: dict[int, int]) -> dict[int, StpPort]:
    states = data.col(mib.STP_PORT_TABLE, mib.STP_PORT_STATE)
    cost = data.col(mib.STP_PORT_TABLE, mib.STP_PORT_PATH_COST)
    edge = data.col(mib.RSTP_PORT_TABLE, mib.RSTP_PORT_OPER_EDGE)
    rstp = as_int(data.scalars.get(mib.STP_VERSION)) == 2
    out: dict[int, StpPort] = {}
    for key, raw in states.items():
        number = _numeric(key)
        state = _STP_STATES.get(as_int(raw) or 0)
        if number is None or state is None:
            continue
        if rstp and state is StpPortState.BLOCKING:
            state = StpPortState.DISCARDING
        path_cost = as_int(cost.get(key))
        oper_edge = as_int(edge.get(key))
        out[bridge_if.get(number, number)] = StpPort(
            state=state,
            edge={1: True, 2: False}.get(oper_edge) if oper_edge is not None else None,
            path_cost=path_cost if path_cost is not None and path_cost >= 0 else None,
        )
    return out


def stp_bridge(pmap: PortMap, data: Mib, bridge_mac: str | None) -> StpBridge | None:
    """The bridge's spanning tree (BRIDGE-MIB, RSTP-MIB): one for the whole switch."""
    s = data.scalars
    version = as_int(s.get(mib.STP_VERSION))
    spec = as_int(s.get(mib.STP_PROTOCOL))
    if version is None and spec in (None, 1):
        return None
    protocol = {2: StpProtocol.RSTP, 3: StpProtocol.MSTP}.get(version or 0, StpProtocol.STP)
    priority = as_int(s.get(mib.STP_PRIORITY))
    priority = priority if priority is not None and 0 <= priority <= 65535 else None
    bridge_id = stp_bridge_id(priority, bridge_mac) if priority is not None and bridge_mac else None
    root = as_bytes(s.get(mib.STP_DESIGNATED_ROOT))
    root_id = None
    if root and len(root) == 8:
        root_id = parse_stp_bridge_id(f"{int.from_bytes(root[:2], 'big'):x}.{root[2:].hex()}")
    root_port = as_int(s.get(mib.STP_ROOT_PORT))
    cost = as_int(s.get(mib.STP_ROOT_COST))
    changes = as_int(s.get(mib.STP_TOP_CHANGES))
    return StpBridge(
        name="switch",
        protocol=protocol,
        priority=priority,
        bridge_id=bridge_id,
        root_bridge_id=root_id,
        root_port_id=pmap.of_bridge(root_port) if root_port else None,
        root_path_cost=cost if cost is not None and cost >= 0 else None,
        topology_changes=changes if changes is not None and changes >= 0 else None,
    )


# -- LLDP ---------------------------------------------------------------------------------------

_CAPABILITIES = (
    "other",
    "repeater",
    "bridge",
    "wlan-access-point",
    "router",
    "telephone",
    "docsis-cable-device",
    "station",
)


def capabilities(bits: Value | None) -> list[str]:
    """The LLDP capability BITS (first octet, bit 0 most significant)."""
    raw = as_bytes(bits)
    if not raw:
        return []
    return normalise_capabilities(
        name for number, name in enumerate(_CAPABILITIES) if raw[0] & (0x80 >> number)
    )


def _lldp_id(value: Value | None, subtype: int | None, mac: int, address: int) -> str | None:
    """A chassis or port id as text: a MAC address for the MAC subtype, an IP address for the
    network address subtype, else its text (or hex)."""
    raw = as_bytes(value)
    if raw is None:
        return as_text(value)
    if subtype == mac and len(raw) == 6:
        return as_mac(raw)
    if subtype == address and len(raw) in (5, 17) and raw[0] in (1, 2):
        try:
            packed = raw[1:]
            return str(IPv4Address(packed) if raw[0] == 1 else IPv6Address(packed))
        except ValueError:
            return raw.hex()
    return as_text(raw) or (raw.hex() if raw else None)


def _local_port(number: int, pmap: PortMap, data: Mib) -> str | None:
    """The port a LLDP local port number stands for: by the name or MAC the local port table
    gives, else the number as ifIndex, else as bridge port."""
    key = str(number)
    ident = data.col(mib.LLDP_LOC_PORT, mib.LLDP_LOC_PORT_ID).get(key)
    sub = as_int(data.col(mib.LLDP_LOC_PORT, mib.LLDP_LOC_PORT_SUBTYPE).get(key))
    desc = as_text(data.col(mib.LLDP_LOC_PORT, mib.LLDP_LOC_PORT_DESC).get(key))
    if sub == 3 and (mac := as_mac(as_bytes(ident))) and mac in pmap.macs:
        return pmap.by_if.get(pmap.macs[mac])
    for candidate in (as_text(ident) if sub in (1, 5, 7) else None, desc):
        if candidate and candidate in pmap.names:
            return pmap.by_if.get(pmap.names[candidate])
    return pmap.by_if.get(number) or pmap.of_bridge(number)


def neighbours(device_id: str, pmap: PortMap, data: Mib) -> list[Neighbour]:
    """LLDP-MIB neighbours (lldpRemTable) with chassis and port ids, system name and
    description, capabilities and management address."""
    base = mib.LLDP_REM
    cols = {
        n: data.col(base, n)
        for n in (
            mib.REM_CHASSIS_SUBTYPE,
            mib.REM_CHASSIS_ID,
            mib.REM_PORT_SUBTYPE,
            mib.REM_PORT_ID,
            mib.REM_PORT_DESC,
            mib.REM_SYS_NAME,
            mib.REM_SYS_DESC,
            mib.REM_CAP_SUPPORTED,
            mib.REM_CAP_ENABLED,
        )
    }
    addresses: dict[str, str] = {}
    for key in data.col(mib.LLDP_REM_MAN_ADDR):
        parts = key.split(".")
        if len(parts) < 5:
            continue
        index, subtype, length, raw = ".".join(parts[:3]), parts[3], parts[4], parts[5:]
        if not (subtype.isdigit() and length.isdigit()) or len(raw) != int(length):
            continue
        try:
            packed = bytes(int(p) for p in raw)
            address = (
                str(IPv4Address(packed))
                if subtype == "1"
                else str(IPv6Address(packed))
                if subtype == "2"
                else None
            )
        except ValueError:
            continue
        if address is not None:
            addresses.setdefault(index, address)
    out: dict[str, Neighbour] = {}
    for key in cols[mib.REM_CHASSIS_ID]:
        parts = key.split(".")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            continue
        local = _local_port(int(parts[1]), pmap, data)
        chassis = _lldp_id(
            cols[mib.REM_CHASSIS_ID][key], as_int(cols[mib.REM_CHASSIS_SUBTYPE].get(key)), 4, 5
        )
        if local is None or chassis is None:
            continue
        remote = _lldp_id(
            cols[mib.REM_PORT_ID].get(key), as_int(cols[mib.REM_PORT_SUBTYPE].get(key)), 3, 4
        ) or as_text(cols[mib.REM_PORT_DESC].get(key))
        port_name = local.split("/port/", 1)[1]
        nid = object_id(device_id, "neighbour", f"{port_name}-{chassis}")
        caps = capabilities(cols[mib.REM_CAP_ENABLED].get(key)) or capabilities(
            cols[mib.REM_CAP_SUPPORTED].get(key)
        )
        out[nid] = Neighbour(
            id=nid,
            local_port_id=local,
            chassis_id=chassis,
            remote_port=remote,
            system_name=as_text(cols[mib.REM_SYS_NAME].get(key)),
            management_address=addresses.get(key),
            capabilities=caps,
            description=as_text(cols[mib.REM_SYS_DESC].get(key)),
        )
    return list(out.values())


#: pethPsePortDetectionStatus (RFC 3621): 1 disabled, 2 searching, 3 deliveringPower, 4 fault,
#: 5 test, 6 otherFault
_PETH_STATUS = {
    1: PoeStatus.DISABLED,
    2: PoeStatus.SEARCHING,
    3: PoeStatus.DELIVERING,
    4: PoeStatus.FAULT,
    6: PoeStatus.FAULT,
}
#: pethPsePortPowerPriority: 1 critical, 2 high, 3 low
_PETH_PRIORITY = {1: PoePriority.CRITICAL, 2: PoePriority.HIGH, 3: PoePriority.LOW}


def poe(pmap: PortMap, data: Mib) -> tuple[PoeSupply | None, dict[str, PortPoe]]:
    """PoE of POWER-ETHERNET-MIB: the budget (``pethMainPsePower`` and the consumption of
    group 1) and per port the admin state, detection status, class
    (``pethPsePortPowerClassifications`` 1..5 is class 0..4) and priority. RFC 3621 has no
    per-port power, so ``power_w`` stays empty.
    The port number of the table (``group.port``) is read as the bridge port or ifIndex of
    group 1 (a guess: the MIB does not say; stacked groups above 1 are skipped). Empty: no PoE."""
    ports: dict[str, PortPoe] = {}
    admin = data.col(mib.PETH_PORT, mib.PETH_PORT_ADMIN)
    detection = data.col(mib.PETH_PORT, mib.PETH_PORT_DETECTION)
    priority = data.col(mib.PETH_PORT, mib.PETH_PORT_PRIORITY)
    klass = data.col(mib.PETH_PORT, mib.PETH_PORT_CLASS)
    for index in sorted({*admin, *detection, *priority, *klass}):
        group, _, number = index.partition(".")
        if group != "1" or not number.isdigit():
            continue
        pid = pmap.of_bridge(int(number))
        if pid is None:
            continue
        flag = as_int(admin.get(index))
        cls = as_int(klass.get(index))
        ports[pid] = PortPoe(
            enabled={1: True, 2: False}.get(flag) if flag is not None else None,
            status=_PETH_STATUS.get(as_int(detection.get(index)) or 0),
            power_class=cls - 1 if cls is not None and 1 <= cls <= 5 else None,
            priority=_PETH_PRIORITY.get(as_int(priority.get(index)) or 0),
        )
    main = data.col(mib.PETH_MAIN, mib.PETH_MAIN_POWER).get("1")
    used = data.col(mib.PETH_MAIN, mib.PETH_MAIN_CONSUMPTION).get("1")
    budget, drawn = as_int(main), as_int(used)
    supply = (
        PoeSupply(budget_w=budget, used_w=drawn)
        if budget is not None or drawn is not None
        else None
    )
    return supply, ports
