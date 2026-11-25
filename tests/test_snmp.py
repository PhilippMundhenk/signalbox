"""The generic SNMP switch adapter: contract, recording replay, mapping details, errors.

No network and no pysnmp are needed here: the adapter reads ``.snmprec`` recordings through
``signalbox.sim.snmp.SnmprecTransport`` (the real UDP/pysnmp path is tested against snmpsim in
``test_snmp_snmpsim.py``). Every secret is made up at runtime.
"""

from __future__ import annotations

import importlib
import json
import secrets
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from signalbox.adapters import (
    AdapterContext,
    AdapterError,
    AuthFailed,
    Unreachable,
    load_adapters,
)
from signalbox.adapters.snmp import SnmpAdapter, SnmpConfig, mapping, mib
from signalbox.adapters.snmp.client import SnmpError, Value, column, convert, oid_tuple, suffix
from signalbox.model import (
    DeviceRole,
    DeviceStatus,
    FdbKind,
    FrameTypes,
    LagMode,
    Membership,
    Snapshot,
    StpPortState,
    StpProtocol,
)
from signalbox.recording import stable
from signalbox.sim.snmp import SnmprecTransport, adapter_for, parse, typical_switch
from signalbox.testing import assert_contract

FIXTURES = Path(__file__).parent / "fixtures" / "snmp"
RECORDING = FIXTURES / "managed-switch.snmprec"


def without(text: str, *prefixes: str) -> str:
    """The recording minus every row below one of the OIDs."""
    return "\n".join(
        line
        for line in text.splitlines()
        if not any(line.startswith(p + ".") or line.startswith(p + "|") for p in prefixes)
    )


def adapter(text: str | None = None, version: str = "v2c") -> SnmpAdapter:
    return adapter_for(
        SnmprecTransport(text if text is not None else typical_switch()), version=version
    )


async def observe(text: str | None = None, version: str = "v2c") -> Snapshot:
    a = adapter(text, version)
    snap = await a.observe()
    await a.close()
    return snap


def by_name(snap: Snapshot, kind: str) -> dict[str, Any]:
    return {getattr(o, "name", None) or o.id: o for o in getattr(snap, kind)}


# --- manifest and configuration -------------------------------------------------------------------


def test_the_adapter_is_registered_and_cannot_write() -> None:
    cls = load_adapters()["snmp"]
    assert cls is SnmpAdapter
    manifest = cls.manifest
    assert manifest.writes == frozenset()
    assert manifest.roles == {DeviceRole.SWITCH}
    assert manifest.setup_steps and manifest.setup_url.endswith("snmp.md#setup")
    for name in ("apply", "backup", "restore", "plan_changes", "confirm"):
        assert not hasattr(cls, name), name


def test_the_committed_recording_is_what_the_generator_makes() -> None:
    assert RECORDING.read_text(encoding="utf-8") == typical_switch()


def test_config_v2c_needs_a_community() -> None:
    community = SecretStr(secrets.token_hex(6))
    assert SnmpConfig(address="192.0.2.10", version="v2c", community=community).port == 161
    with pytest.raises(ValidationError, match="community"):
        SnmpConfig(address="192.0.2.10", version="v2c")
    with pytest.raises(ValidationError, match="community"):
        SnmpConfig(address="192.0.2.10", version="v2c", community=SecretStr(""))


def test_config_v3_needs_user_and_both_passwords() -> None:
    def pw(n: int = 12) -> SecretStr:
        return SecretStr(secrets.token_hex(n))

    ok = SnmpConfig(
        address="2001:db8::10", username="reader", auth_password=pw(), priv_password=pw()
    )
    assert ok.version == "v3" and ok.auth_protocol == "sha256" and ok.address == "2001:db8::10"
    with pytest.raises(ValidationError, match="user name"):
        SnmpConfig(address="192.0.2.10", auth_password=pw(), priv_password=pw())
    with pytest.raises(ValidationError, match="8 characters"):
        SnmpConfig(address="192.0.2.10", username="reader", auth_password=pw())
    with pytest.raises(ValidationError, match="8 characters"):
        SnmpConfig(address="192.0.2.10", username="reader", auth_password=pw(2), priv_password=pw())


@pytest.mark.parametrize("address", ["", "  ", "-x", "host/path", "user@host", "a b"])
def test_config_rejects_a_bad_address(address: str) -> None:
    with pytest.raises(ValidationError):
        SnmpConfig(address=address, version="v2c", community=SecretStr("x"))


def test_secrets_are_secret_fields_in_the_form() -> None:
    from signalbox.web.app import adapter_info

    info = adapter_info(SnmpAdapter)
    assert set(info["secret_fields"]) == {"community", "auth_password", "priv_password"}


# --- the contract and the recording ---------------------------------------------------------------


@pytest.mark.parametrize("version", ["v2c", "v3"])
async def test_contract(version: str) -> None:
    a = adapter(version=version)
    snap = await assert_contract(a)
    assert snap.status is DeviceStatus.OK
    assert snap.device.transport_encrypted is (version == "v3")
    (service,) = snap.services
    assert service.snmp is not None and service.encrypted is (version == "v3")
    assert service.snmp.v3_privacy is (True if version == "v3" else None)
    assert snap.device.default_credentials is (None if version == "v3" else False)
    await a.close()


async def test_the_recording_gives_the_stored_snapshot() -> None:
    a = adapter_for(SnmprecTransport.from_file(RECORDING))
    expected = json.loads(RECORDING.with_suffix(".snapshot.json").read_text(encoding="utf-8"))
    assert stable(await a.observe()) == expected, "run python tools/regen_recordings.py"


async def test_nothing_is_ever_written() -> None:
    t = SnmprecTransport(typical_switch())
    a = adapter_for(t)
    await a.observe()
    assert t.asked and all(o.startswith(("1.3.6.1.2.1", "1.0.8802", "1.2.840")) for o in t.asked)
    assert not hasattr(t, "set")


# --- what the typical switch gives ----------------------------------------------------------------


async def test_system_and_health() -> None:
    snap = await observe()
    d = snap.device
    assert (d.vendor, d.model, d.mac) == ("Example Networks", "EX-8G-SW", "02:00:00:00:01:00")
    assert d.firmware is not None and d.firmware.current == "1.2.3"
    assert d.health is not None and d.health.uptime_seconds == 86400
    assert (d.serial, d.hardware_revision) == ("EXAMPLE-0001", "A1")
    assert (d.hostname, d.location, d.contact) == (
        "switch-example",
        "Rack 1, server room",
        "noc@example.net",
    )


async def test_ports_vlans_and_lag() -> None:
    snap = await observe()
    ports = by_name(snap, "ports")
    assert list(ports) == [f"Gi{n}" for n in range(1, 9)] + ["Po1"]  # no VLAN or loopback
    assert ports["Gi1"].description == "uplink to the router"
    assert (ports["Gi3"].speed_mbps, ports["Gi5"].up, ports["Gi6"].admin_up) == (100, False, False)
    assert ports["Gi2"].pvid == 10 and ports["Gi1"].ingress_filter is False
    assert ports["Gi1"].frame_types is FrameTypes.ALL
    po = ports["Po1"]
    assert po.lower == ["switch/port/Gi7", "switch/port/Gi8"]
    assert po.lag_mode is LagMode.LACP_ACTIVE and po.lacp_rate is not None
    assert ports["Gi7"].lag == "Po1" and ports["Gi7"].lag_member_state is not None
    assert ports["Gi7"].lag_member_state.partner_key == 100
    segs = {s.vlan: s for s in snap.segments}
    assert set(segs) == {1, 10, 20} and segs[10].name == "office"
    members = {m.port_id.rsplit("/", 1)[1]: m.mode for m in segs[10].members}
    assert members == {
        "Gi1": Membership.TAGGED,
        "Gi2": Membership.UNTAGGED,
        "Gi3": Membership.UNTAGGED,
        "Po1": Membership.TAGGED,
    }


async def test_mac_table_per_vlan() -> None:
    snap = await observe()
    table = {(e.vlan, e.mac): e for e in snap.fdb}
    assert len(table) == 5  # the switch's own address (port 0) is not on a port
    entry = table[(10, "02:00:00:00:10:99")]
    assert entry.port_id == "switch/port/Po1" and entry.kind is FdbKind.DYNAMIC
    assert entry.segment_id == "home/segment/10"
    assert table[(1, "02:00:00:00:00:01")].segment_id == "home/segment/native"


async def test_spanning_tree() -> None:
    snap = await observe()
    (bridge,) = snap.device.stp_bridges or []
    assert bridge.protocol is StpProtocol.RSTP and bridge.is_root is False
    assert bridge.bridge_id == "8000.02:00:00:00:01:00"
    assert bridge.root_bridge_id == "1000.02:00:00:00:00:01"
    assert bridge.root_port_id == "switch/port/Gi1" and bridge.topology_changes == 3
    ports = by_name(snap, "ports")
    assert ports["Gi1"].stp is not None and ports["Gi1"].stp.state is StpPortState.FORWARDING
    assert ports["Gi5"].stp is not None and ports["Gi5"].stp.state is StpPortState.DISABLED
    assert ports["Gi4"].stp is not None and ports["Gi4"].stp.edge is True


async def test_lldp_neighbours() -> None:
    snap = await observe()
    by_id = {n.local_port_id.rsplit("/", 1)[1]: n for n in snap.neighbours}
    assert set(by_id) == {"Gi1", "Gi3", "Gi7"}
    router = by_id["Gi1"]
    assert router.chassis_id == "02:00:00:00:00:01" and router.remote_port == "3"
    assert router.system_name == "router-example" and router.management_address == "192.0.2.1"
    assert router.capabilities == ["bridge", "router"]
    ap = by_id["Gi3"]
    assert ap.capabilities == ["bridge", "wlan-access-point"]
    assert ap.remote_port == "02:00:00:00:00:a1"  # a MAC port id
    assert by_id["Gi7"].remote_port == "Gi3/5" and by_id["Gi7"].description


# --- switches that offer less ---------------------------------------------------------------------


GAPS = {
    "q-bridge": ("1.3.6.1.2.1.17.7", "Q-BRIDGE"),
    "stp": ("1.3.6.1.2.1.17.2", "spanning tree"),
    "entity": ("1.3.6.1.2.1.47", "ENTITY-MIB"),
    "lldp": ("1.0.8802", "LLDP"),
}


@pytest.mark.parametrize("name", GAPS)
async def test_a_missing_mib_is_an_optional_gap(name: str) -> None:
    prefix, word = GAPS[name]
    text = "\n".join(
        line for line in typical_switch().splitlines() if not line.startswith(prefix + ".")
    )
    a = adapter(text)
    snap = await assert_contract(a)
    gaps = [e for e in snap.errors if word in e.message]
    assert gaps and all(e.optional and e.message_id == "snmp.gapMib" for e in gaps)
    assert snap.status is DeviceStatus.OK
    if name == "q-bridge":
        assert not snap.segments and not snap.fdb  # the MAC table needs Q-BRIDGE or BRIDGE
        assert snap.ports


async def test_current_vlan_table_when_there_is_no_static_one() -> None:
    lines = []
    for line in typical_switch().splitlines():
        oid, tag, value = line.split("|", 2)
        if oid.startswith("1.3.6.1.2.1.17.7.1.4.3.1."):
            column_no, vid = oid.split(".")[-2:]
            new = {"2": "4", "4": "5"}.get(column_no)
            if new:
                lines.append(f"1.3.6.1.2.1.17.7.1.4.2.1.{new}.0.{vid}|{tag}|{value}")
            continue
        lines.append(line)
    snap = await observe("\n".join(lines))
    assert {s.vlan for s in snap.segments} == {1, 10, 20}


async def test_old_bridge_mib_mac_table() -> None:
    lines = []
    for line in typical_switch().splitlines():
        oid, tag, value = line.split("|", 2)
        if oid.startswith("1.3.6.1.2.1.17.7.1.2.2.1."):
            parts = oid.split(".")
            if parts[-8] in ("2", "3") and parts[-7] == "10":  # vlan 10 only, no VLAN id
                lines.append(
                    f"1.3.6.1.2.1.17.4.3.1.{parts[-8]}.{'.'.join(parts[-6:])}|{tag}|{value}"
                )
            continue
        lines.append(line)
    snap = await observe("\n".join(lines))
    assert len(snap.fdb) == 3 and {e.vlan for e in snap.fdb} == {None}


async def test_a_switch_without_ifx_names_ports_by_description_and_lists_each_once() -> None:
    text = without(typical_switch(), "1.3.6.1.2.1.31.1.1.1.1", "1.3.6.1.2.1.31.1.1.1.15")
    text = text.replace("|4|Example Gi2\n", "|4|Example Gi1\n")  # a description twice
    snap = await observe(text)
    names = [p.name for p in snap.ports]
    assert len(names) == len(set(names)) == 9
    assert "Example Gi1" in names and "Example Gi1#2" in names
    assert {p.speed_mbps for p in snap.ports if p.up} == {
        100,
        1000,
    }  # ifSpeed instead of ifHighSpeed


async def test_a_static_lag_is_known_from_the_interface_stack_only() -> None:
    text = without(typical_switch(), "1.2.840.10006.300.43")
    snap = await observe(text)
    ports = by_name(snap, "ports")
    assert ports["Po1"].lower == ["switch/port/Gi7", "switch/port/Gi8"]
    assert ports["Po1"].lag_mode is None and ports["Gi8"].lag == "Po1"
    assert ports["Gi8"].lag_member_state is None


def test_bridge_ports_are_translated_to_interfaces() -> None:
    pmap = mapping.PortMap(by_if={5: "sw/port/a", 6: "sw/port/b"}, bridge_if={1: 5})
    assert pmap.of_bridge(1) == "sw/port/a"  # through dot1dBasePortIfIndex
    assert pmap.of_bridge(6) == "sw/port/b"  # no entry: the bridge port is the ifIndex
    assert pmap.of_bridge(2) is None


async def test_a_read_only_view_may_hide_things_in_the_middle() -> None:
    class Flaky(SnmprecTransport):
        async def walk(self, oid: str) -> dict[str, Value]:
            if oid.startswith("1.3.6.1.2.1.17.7"):
                raise SnmpError("timeout", "requestTimedOut")
            return await super().walk(oid)

    a = adapter_for(Flaky(typical_switch()))
    snap = await a.observe()
    assert snap.ports and not snap.segments
    assert any("Q-BRIDGE" in e.message for e in snap.errors)


# --- errors ---------------------------------------------------------------------------------------


class Failing:
    def __init__(self, error: Exception) -> None:
        self.error = error

    async def get(self, *oids: str) -> dict[str, Value]:
        raise self.error

    async def walk(self, oid: str) -> dict[str, Value]:
        raise self.error

    async def close(self) -> None:
        return None


@pytest.mark.parametrize(
    ("kind", "exc", "status", "message_id"),
    [
        ("timeout", Unreachable, DeviceStatus.UNREACHABLE, "snmp.noAnswer"),
        ("auth", AuthFailed, DeviceStatus.AUTH_FAILED, "snmp.authFailed"),
        ("other", AdapterError, DeviceStatus.UNREACHABLE, "snmp.error"),
    ],
)
async def test_errors_are_translated(
    kind: str, exc: type[AdapterError], status: DeviceStatus, message_id: str
) -> None:
    a = adapter_for(Failing(SnmpError(kind, "requestTimedOut")))
    with pytest.raises(exc) as info:
        await a.read_system()
    assert info.value.message_id == message_id
    snap = await a.observe()
    assert snap.status is status and snap.errors[0].message_id == message_id


async def test_an_agent_without_sysdescr_is_not_a_switch() -> None:
    a = adapter("1.3.6.1.2.1.1.5.0|4|x\n")
    with pytest.raises(AdapterError, match="no sysDescr"):
        await a.read_system()


async def test_no_interfaces_is_an_error_of_the_interface_read() -> None:
    text = without(typical_switch(), "1.3.6.1.2.1.2")
    snap = await observe(text)
    assert snap.status is DeviceStatus.PARTIAL
    assert any(e.capability == "interfaces" for e in snap.errors)


async def test_an_auth_error_in_a_walk_is_not_hidden() -> None:
    class Hidden(SnmprecTransport):
        async def walk(self, oid: str) -> dict[str, Value]:
            raise SnmpError("auth", "notInView")

    snap = await adapter_for(Hidden(typical_switch())).observe()
    assert snap.status is DeviceStatus.AUTH_FAILED


async def test_a_community_that_is_a_factory_default_is_flagged() -> None:
    cfg = SnmpConfig(address="192.0.2.10", version="v2c", community=SecretStr("pub" + "lic"))
    ctx = AdapterContext(
        site_id="home",
        device_id="switch",
        device_name="Switch",
        role=DeviceRole.SWITCH,
        config=cfg,
        extra={"snmp_transport": SnmprecTransport(typical_switch())},
    )
    snap = await SnmpAdapter(ctx).observe()
    assert snap.device.default_credentials is True
    assert snap.services[0].snmp is not None and snap.services[0].snmp.default_community is True


# --- mapping helpers ------------------------------------------------------------------------------


def test_portlist_bits() -> None:
    assert mapping.portlist(bytes([0b10100000, 0b00000001])) == {1, 3, 16}
    assert mapping.portlist(None) == set() and mapping.portlist(5) == set()


def test_text_and_mac_helpers() -> None:
    assert mapping.as_text(b"  a\x00b\n ") == "ab"
    assert mapping.as_text(b"   ") is None and mapping.as_text(7) is None
    assert mapping.as_text("x") == "x"
    assert mapping.as_mac(bytes(6)) is None and mapping.as_mac(b"abc") is None
    assert mapping.as_mac(bytes([2, 0, 0, 0, 0, 1])) == "02:00:00:00:00:01"


def test_vendor_from_the_enterprise_number() -> None:
    assert mapping.vendor_of("1.3.6.1.4.1.11863.1.1") == "TP-Link"
    assert mapping.vendor_of("1.3.6.1.4.1.1.2") is None
    assert mapping.vendor_of(b"x") is None and mapping.vendor_of("1.3.6.1.2") is None


def test_lldp_capabilities_bits() -> None:
    assert mapping.capabilities(bytes([0x28])) == ["bridge", "router"]
    assert mapping.capabilities(bytes([0x01])) == ["station"]
    assert mapping.capabilities(None) == [] and mapping.capabilities(b"") == []


def test_lldp_ids() -> None:
    f = mapping._lldp_id
    assert f(bytes([1, 192, 0, 2, 7]), 5, 4, 5) == "192.0.2.7"
    assert f(bytes([2]) + bytes(15) + bytes([1]), 5, 4, 5) == "::1"
    assert f(bytes([3, 1, 2, 3, 4]), 5, 4, 5) == "03010203" + "04"
    assert f(bytes([1, 2]), 7, 4, 5) == "0102"
    assert f(None, 7, 4, 5) is None and f("text", 7, 4, 5) == "text"


def test_health_and_scalars() -> None:
    assert mapping.health({}) is None
    h = mapping.health({mib.SYS_UPTIME: 12345})
    assert h is not None and h.uptime_seconds == 123


def test_bad_rows_are_skipped() -> None:
    data = mapping.Mib()
    base = mib.LLDP_REM
    data.walks[f"{base}.{mib.REM_CHASSIS_ID}"] = {
        f"{base}.{mib.REM_CHASSIS_ID}.0.1": b"x",  # not three index parts
        f"{base}.{mib.REM_CHASSIS_ID}.0.1.1": b"x",  # no local port 1 known
    }
    data.walks[mib.LLDP_REM_MAN_ADDR] = {f"{mib.LLDP_REM_MAN_ADDR}.0.1.1.9": 2}
    assert mapping.neighbours("sw", mapping.PortMap(), data) == []
    assert mapping.fdb("sw", "home", mapping.PortMap(), data, set()) == []
    assert mapping.segments("home", mapping.PortMap(), data) is None
    assert mapping.stp_bridge(mapping.PortMap(), data, None) is None


# --- client helpers -------------------------------------------------------------------------------


def test_oid_helpers() -> None:
    assert oid_tuple(".1.3.6") == (1, 3, 6)
    assert suffix("1.3.6.1", "1.3.6") == "1" and suffix("1.3.60", "1.3.6") is None
    rows: dict[str, Value] = {"1.3.6.1": 1, "1.3.6.2.5": 2, "1.4": 3}
    assert column(rows, "1.3.6") == {"1": 1, "2.5": 2}


def test_parse_reads_every_tag_in_oid_order() -> None:
    text = "\n".join(
        [
            "# a comment",
            "1.3.6.1.2.1.1.5.0|4|name",
            "1.3.6.1.2.1.1.2.0|6|1.3.6.1.4.1.9.1",
            "1.3.6.1.2.1.1.3.0|67|42",
            "1.3.6.1.2.1.1.4.0|4x|0a0b",
            "1.3.6.1.2.1.4.20.1.1.1|64|192.0.2.1",
            "1.3.6.1.2.1.1.9.0|5|",
            "1.3.6.1.2.1.1.8.0|68x|ff",
        ]
    )
    rows = parse(text)
    assert list(rows)[:2] == ["1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.3.0"]
    assert rows["1.3.6.1.2.1.1.4.0"] == b"\x0a\x0b" and rows["1.3.6.1.2.1.1.5.0"] == b"name"
    assert rows["1.3.6.1.2.1.1.2.0"] == "1.3.6.1.4.1.9.1" and rows["1.3.6.1.2.1.1.8.0"] == b"\xff"
    assert rows["1.3.6.1.2.1.4.20.1.1.1"] == "192.0.2.1" and "1.3.6.1.2.1.1.9.0" not in rows


def test_convert_pysnmp_values() -> None:
    hlapi = pytest.importorskip("pysnmp.hlapi.v3arch.asyncio")
    assert convert(hlapi.Integer32(5), hlapi) == 5
    assert convert(hlapi.TimeTicks(7), hlapi) == 7
    assert convert(hlapi.OctetString(b"ab"), hlapi) == b"ab"
    assert convert(hlapi.IpAddress("192.0.2.1"), hlapi) == "192.0.2.1"
    assert convert(hlapi.ObjectIdentifier("1.3.6.1"), hlapi) == "1.3.6.1"
    assert convert(hlapi.NoSuchObject(), hlapi) is None
    assert convert(hlapi.EndOfMibView(), hlapi) is None
    assert convert(hlapi.Null(""), hlapi) is None


async def test_without_pysnmp_the_read_says_how_to_install_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = importlib.import_module

    def refuse(name: str, package: str | None = None) -> ModuleType:
        if name.startswith("pysnmp"):
            raise ImportError(name)
        return real(name, package)

    monkeypatch.setattr(importlib, "import_module", refuse)
    cfg = SnmpConfig(address="192.0.2.10", version="v2c", community=SecretStr(secrets.token_hex(6)))
    a = SnmpAdapter(
        AdapterContext(
            site_id="home",
            device_id="switch",
            device_name="Switch",
            role=DeviceRole.SWITCH,
            config=cfg,
        )
    )
    with pytest.raises(AdapterError) as info:
        await a.read_system()
    assert info.value.message_id == "snmp.install"
