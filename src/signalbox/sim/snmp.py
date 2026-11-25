"""An SNMP agent simulator for the ``snmp`` adapter, from ``.snmprec`` recordings.

A recording is the file format of `snmpsim <https://github.com/lextudio/snmpsim>`_: one line per
value, ``<OID>|<type tag>|<value>``, sorted by OID; a tag with an ``x`` suffix holds hex::

    1.3.6.1.2.1.1.1.0|4|Example Networks EX-8G-SW managed switch
    1.3.6.1.2.1.2.2.1.6.1|4x|020000000101
    1.3.6.1.2.1.1.3.0|67|8640000

:class:`SnmprecTransport` answers the adapter's two requests (GET, walk) from such a file
without any network, so the adapter is tested in-process; ``tests/test_snmp_snmpsim.py`` serves
the same file with the real snmpsim over UDP, so the pysnmp code is exercised too.

:func:`typical_switch` builds the committed recording ``tests/fixtures/snmp/managed-switch.snmprec``
(a made-up 8-port managed switch with VLANs, a LACP link aggregation, spanning tree and LLDP
neighbours; documentation addresses, locally administered MACs). ``tools/regen_recordings.py``
writes it and the snapshot the adapter must make of it.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from signalbox.adapters.snmp.client import Value, oid_tuple, suffix

if TYPE_CHECKING:
    from signalbox.adapters.snmp import SnmpAdapter

#: type tags of the snmprec format that carry a number
_NUMBER_TAGS = {"2", "65", "66", "67", "70"}


def parse(text: str) -> dict[str, Value]:
    """The values of a recording in OID order."""
    rows: dict[tuple[int, ...], tuple[str, Value]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        oid, tag, raw = line.split("|", 2)
        base, hexed = (tag[:-1], True) if tag.endswith("x") else (tag, False)
        value: Value
        if base in _NUMBER_TAGS:
            value = int(raw)
        elif base in {"4", "68"}:
            value = bytes.fromhex(raw) if hexed else raw.encode()
        elif base == "6":
            value = raw.strip(".")
        elif base == "64":
            value = raw
        else:  # 5 (Null) and anything unknown: not a value
            continue
        rows[oid_tuple(oid)] = (oid.strip("."), value)
    return {oid: value for _, (oid, value) in sorted(rows.items())}


class SnmprecTransport:
    """The :class:`~signalbox.adapters.snmp.client.SnmpTransport` of a recording."""

    def __init__(self, text: str) -> None:
        self.rows = parse(text)
        #: every OID asked for, for tests that want to see what was read
        self.asked: list[str] = []

    @classmethod
    def from_file(cls, path: Path) -> SnmprecTransport:
        return cls(path.read_text(encoding="utf-8"))

    async def get(self, *oids: str) -> dict[str, Value]:
        self.asked.extend(oids)
        return {oid: self.rows[oid] for oid in oids if oid in self.rows}

    async def walk(self, oid: str) -> dict[str, Value]:
        self.asked.append(oid)
        return {k: v for k, v in self.rows.items() if suffix(k, oid) is not None}

    async def close(self) -> None:
        return None


# -- the typical switch ---------------------------------------------------------------------------


def _bits(ports: set[int], octets: int = 2) -> str:
    """A PortList as hex."""
    value = bytearray(octets)
    for port in ports:
        value[(port - 1) // 8] |= 0x80 >> ((port - 1) % 8)
    return value.hex()


def _mac(last: int, a: int = 1) -> str:
    return f"02000000{a:02x}{last:02x}"


class _Writer:
    def __init__(self) -> None:
        self.lines: dict[tuple[int, ...], str] = {}

    def add(self, oid: str, tag: str, value: object) -> None:
        self.lines[oid_tuple(oid)] = f"{oid}|{tag}|{value}"

    def text(self, oid: str, value: str) -> None:
        self.add(oid, "4", value)

    def hexa(self, oid: str, value: str) -> None:
        self.add(oid, "4x", value)

    def integer(self, oid: str, value: int) -> None:
        self.add(oid, "2", value)

    def dump(self) -> str:
        return "\n".join(self.lines[k] for k in sorted(self.lines)) + "\n"


def typical_switch() -> str:
    """The recording of a made-up 8-port Gigabit managed switch, as snmprec text.

    Ports 1-8 (``Gi1``..``Gi8``) and the LACP link aggregation ``Po1`` (ports 7 and 8) over
    VLANs 1, 10 and 20: port 1 is the trunk to the router, 2 and 3 are office ports (3 at
    100 Mbit/s), 4 is an IoT port, 5 is down and 6 disabled. RSTP, LLDP neighbours on ports 1, 3
    and 7, a MAC table over the VLANs.
    """
    w = _Writer()
    # SNMPv2-MIB
    w.text("1.3.6.1.2.1.1.1.0", "Example Networks EX-8G-SW managed switch, firmware 1.2.3")
    w.add("1.3.6.1.2.1.1.2.0", "6", "1.3.6.1.4.1.99999.1.8")
    w.add("1.3.6.1.2.1.1.3.0", "67", 8_640_000)
    w.text("1.3.6.1.2.1.1.4.0", "noc@example.net")
    w.text("1.3.6.1.2.1.1.5.0", "switch-example")
    w.text("1.3.6.1.2.1.1.6.0", "Rack 1, server room")
    # ENTITY-MIB: a chassis and its first port
    ent = "1.3.6.1.2.1.47.1.1.1.1"
    w.integer(f"{ent}.5.1", 3)
    w.integer(f"{ent}.5.2", 10)
    w.text(f"{ent}.2.1", "Example 8-port Gigabit managed switch")
    w.text(f"{ent}.8.1", "A1")
    w.text(f"{ent}.9.1", "0.9.1")
    w.text(f"{ent}.10.1", "1.2.3")
    w.text(f"{ent}.11.1", "EXAMPLE-0001")
    w.text(f"{ent}.12.1", "Example Networks")
    w.text(f"{ent}.13.1", "EX-8G-SW")
    # IF-MIB: ports 1-8, the aggregation 9, a VLAN interface 100 and a loopback 101
    up = {1, 2, 3, 4, 7, 8, 9}
    speeds = {3: 100}
    for n in range(1, 10):
        t = 6 if n <= 8 else 161
        name = f"Gi{n}" if n <= 8 else "Po1"
        w.integer(f"1.3.6.1.2.1.2.2.1.1.{n}", n)
        w.text(f"1.3.6.1.2.1.2.2.1.2.{n}", f"Example {name}")
        w.integer(f"1.3.6.1.2.1.2.2.1.3.{n}", t)
        w.integer(f"1.3.6.1.2.1.2.2.1.4.{n}", 1500)
        mbit = speeds.get(n, 1000) if n in up else 0
        w.add(f"1.3.6.1.2.1.2.2.1.5.{n}", "66", mbit * 1_000_000)
        w.hexa(f"1.3.6.1.2.1.2.2.1.6.{n}", _mac(n))
        w.integer(f"1.3.6.1.2.1.2.2.1.7.{n}", 2 if n == 6 else 1)
        w.integer(f"1.3.6.1.2.1.2.2.1.8.{n}", 1 if n in up else 2)
        w.add(f"1.3.6.1.2.1.2.2.1.10.{n}", "65", 1000 * n)
        w.text(f"1.3.6.1.2.1.31.1.1.1.1.{n}", name)
        w.add(f"1.3.6.1.2.1.31.1.1.1.15.{n}", "66", mbit)
        if n in up and n <= 8:  # counters: fixed values, the HC ones past 32 bits on port 1
            big = 5_000_000_000 if n == 1 else 0
            w.add(f"1.3.6.1.2.1.31.1.1.1.6.{n}", "70", big + 91_220_000 * n)  # ifHCInOctets
            w.add(f"1.3.6.1.2.1.31.1.1.1.10.{n}", "70", big + 17_330_000 * n)  # ifHCOutOctets
            w.add(f"1.3.6.1.2.1.31.1.1.1.7.{n}", "70", 70_000 * n)  # ifHCInUcastPkts
            w.add(f"1.3.6.1.2.1.31.1.1.1.11.{n}", "70", 41_000 * n)  # ifHCOutUcastPkts
            w.add(f"1.3.6.1.2.1.31.1.1.1.8.{n}", "70", 300)  # ifHCInMulticastPkts
            w.add(f"1.3.6.1.2.1.2.2.1.13.{n}", "65", 1)  # ifInDiscards
            w.add(f"1.3.6.1.2.1.2.2.1.14.{n}", "65", 2 if n == 2 else 0)  # ifInErrors
            w.add(f"1.3.6.1.2.1.2.2.1.20.{n}", "65", 0)  # ifOutErrors
            w.add(f"1.3.6.1.2.1.10.7.2.1.3.{n}", "65", 2 if n == 2 else 0)  # dot3StatsFCSErrors
        if n == 1:
            w.text("1.3.6.1.2.1.31.1.1.1.18.1", "uplink to the router")
        if n <= 8 and n in up:
            w.integer(f"1.3.6.1.2.1.10.7.2.1.19.{n}", 3)
    for n, t, name in ((100, 53, "Vlan10"), (101, 24, "lo")):
        w.integer(f"1.3.6.1.2.1.2.2.1.1.{n}", n)
        w.text(f"1.3.6.1.2.1.2.2.1.2.{n}", name)
        w.integer(f"1.3.6.1.2.1.2.2.1.3.{n}", t)
        w.integer(f"1.3.6.1.2.1.2.2.1.7.{n}", 1)
        w.integer(f"1.3.6.1.2.1.2.2.1.8.{n}", 1)
        w.text(f"1.3.6.1.2.1.31.1.1.1.1.{n}", name)
    for member in (7, 8):  # ifStackTable: the aggregation over its members
        w.integer(f"1.3.6.1.2.1.31.1.2.1.3.9.{member}", 1)
    # BRIDGE-MIB
    w.hexa("1.3.6.1.2.1.17.1.1.0", _mac(0))
    for n in range(1, 10):
        w.integer(f"1.3.6.1.2.1.17.1.4.1.2.{n}", n)
    # Q-BRIDGE-MIB: VLANs 1 (default), 10 (office), 20 (IoT)
    vlans = {
        1: ("default", {1, 5, 6, 7, 8, 9}, {1, 5, 6, 7, 8, 9}),
        10: ("office", {1, 2, 3, 9}, {2, 3}),
        20: ("iot", {1, 4, 9}, {4}),
    }
    for vid, (name, egress, untagged) in vlans.items():
        w.text(f"1.3.6.1.2.1.17.7.1.4.3.1.1.{vid}", name)
        w.hexa(f"1.3.6.1.2.1.17.7.1.4.3.1.2.{vid}", _bits(egress))
        w.hexa(f"1.3.6.1.2.1.17.7.1.4.3.1.3.{vid}", _bits(set()))
        w.hexa(f"1.3.6.1.2.1.17.7.1.4.3.1.4.{vid}", _bits(untagged))
    pvid = {2: 10, 3: 10, 4: 20}
    for n in range(1, 10):
        w.integer(f"1.3.6.1.2.1.17.7.1.4.5.1.1.{n}", pvid.get(n, 1))
        w.integer(f"1.3.6.1.2.1.17.7.1.4.5.1.2.{n}", 1)
        w.integer(f"1.3.6.1.2.1.17.7.1.4.5.1.3.{n}", 2 if n == 1 else 1)
    # Q-BRIDGE-MIB MAC table: vlan.mac -> port, status 3 learned, 4 self
    fdb = (
        (1, "02:00:00:00:00:01", 1, 3),
        (10, "02:00:00:00:10:01", 2, 3),
        (10, "02:00:00:00:10:02", 3, 3),
        (10, "02:00:00:00:10:99", 9, 3),
        (20, "02:00:00:00:20:01", 4, 3),
        (1, "02:00:00:00:01:00", 0, 4),
    )
    for vid, mac, port, status in fdb:
        index = f"{vid}." + ".".join(str(int(b, 16)) for b in mac.split(":"))
        w.integer(f"1.3.6.1.2.1.17.7.1.2.2.1.2.{index}", port)
        w.integer(f"1.3.6.1.2.1.17.7.1.2.2.1.3.{index}", status)
    # BRIDGE-MIB / RSTP-MIB: this switch (priority 32768) follows a root (priority 4096)
    w.integer("1.3.6.1.2.1.17.2.1.0", 3)
    w.integer("1.3.6.1.2.1.17.2.2.0", 32768)
    w.add("1.3.6.1.2.1.17.2.4.0", "65", 3)
    w.hexa("1.3.6.1.2.1.17.2.5.0", "1000" + "020000000001")
    w.integer("1.3.6.1.2.1.17.2.6.0", 4)
    w.integer("1.3.6.1.2.1.17.2.7.0", 1)
    w.integer("1.3.6.1.2.1.17.2.16.0", 2)
    for n in range(1, 10):
        w.integer(f"1.3.6.1.2.1.17.2.15.1.3.{n}", 1 if n in (5, 6) else 5)
        w.integer(f"1.3.6.1.2.1.17.2.15.1.5.{n}", 20_000 if n != 1 else 4)
        w.integer(f"1.3.6.1.2.1.17.2.19.1.3.{n}", 1 if n == 4 else 2)
    # LLDP-MIB: local ports and three neighbours (time mark 0)
    w.hexa("1.0.8802.1.1.2.1.3.2.0", _mac(0))
    for n in range(1, 9):
        w.integer(f"1.0.8802.1.1.2.1.3.7.1.2.{n}", 5)
        w.text(f"1.0.8802.1.1.2.1.3.7.1.3.{n}", f"Gi{n}")
        w.text(f"1.0.8802.1.1.2.1.3.7.1.4.{n}", f"Example Gi{n}")
    rem = "1.0.8802.1.1.2.1.4.1.1"
    neighbours = (
        # local port, chassis mac, port subtype, port id (hex), name, description, caps, address
        (1, "020000000001", 7, "33", "router-example", "Example router OS 1.0", 0x28, "192.0.2.1"),
        (
            3,
            "0200000000a1",
            3,
            "0200000000a1",
            "ap-office",
            "Example access point",
            0x30,
            "192.0.2.30",
        ),
        (
            7,
            "020000000002",
            5,
            "4769332f35",
            "switch-peer",
            "Example peer switch",
            0x20,
            "192.0.2.2",
        ),
    )
    for local, chassis, sub, port_hex, name, descr, caps, address in neighbours:
        i = f"0.{local}.1"
        w.integer(f"{rem}.4.{i}", 4)
        w.hexa(f"{rem}.5.{i}", chassis)
        w.integer(f"{rem}.6.{i}", sub)
        w.hexa(f"{rem}.7.{i}", port_hex)
        w.text(f"{rem}.9.{i}", name)
        w.text(f"{rem}.10.{i}", descr)
        w.hexa(f"{rem}.11.{i}", f"{caps:02x}")
        w.hexa(f"{rem}.12.{i}", f"{caps:02x}")
        octets = ".".join(address.split("."))
        w.integer(f"1.0.8802.1.1.2.1.4.2.1.3.{i}.1.4.{octets}", 2)
    # IEEE8023-LAG-MIB: the aggregation 9 (LACP, active, fast) with ports 7 and 8
    w.integer("1.2.840.10006.300.43.1.1.1.1.1.9", 9)
    for n in (7, 8):
        p = "1.2.840.10006.300.43.1.2.1.1"
        w.integer(f"{p}.12.{n}", 9)
        w.integer(f"{p}.13.{n}", 9)
        w.hexa(f"{p}.21.{n}", "c0")
        w.hexa(f"{p}.22.{n}", "bc")
        w.hexa(f"{p}.9.{n}", "8000" + "0200000000b1")
        w.integer(f"{p}.11.{n}", 100)
        w.integer(f"{p}.17.{n}", n)
    return w.dump()


# -- observing a recording ------------------------------------------------------------------------


def adapter_for(transport: SnmprecTransport, *, version: str = "v2c") -> SnmpAdapter:
    """The ``snmp`` adapter reading ``transport``, with secrets made up at runtime."""
    import secrets

    from pydantic import SecretStr

    from signalbox.adapters import AdapterContext
    from signalbox.adapters.snmp import SnmpAdapter, SnmpConfig
    from signalbox.model import DeviceRole

    def secret() -> SecretStr:
        return SecretStr(secrets.token_hex(8))

    if version == "v2c":
        config = SnmpConfig(address="192.0.2.10", version="v2c", community=secret())
    else:
        config = SnmpConfig(
            address="192.0.2.10",
            version="v3",
            username="signalbox",
            auth_password=secret(),
            priv_password=secret(),
        )
    return SnmpAdapter(
        AdapterContext(
            site_id="home",
            device_id="switch",
            device_name="Switch",
            role=DeviceRole.SWITCH,
            config=config,
            extra={"snmp_transport": transport},
        )
    )
