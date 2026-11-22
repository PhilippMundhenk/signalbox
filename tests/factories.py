"""Small builders for model objects used across the tests (documentation addresses only)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any

from signalbox.model import (
    SERVICE_PORTS,
    Acknowledgement,
    Annotation,
    Device,
    DeviceHealth,
    DeviceRole,
    DeviceTime,
    Fan,
    ManagementService,
    Network,
    NtpClient,
    NtpServer,
    Port,
    PortMedia,
    PowerSupply,
    ServiceKind,
    Site,
    Snapshot,
    SnmpSettings,
    SnmpVersion,
    Source,
    StorageKind,
    StorageUsage,
    TemperatureSensor,
    Uplink,
    UplinkKind,
    UpsStatus,
    object_id,
    port_id,
)

T0 = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
SITE = Site(id="home", name="Home")


def device(
    device_id: str, role: DeviceRole = DeviceRole.GATEWAY, adapter: str = "test", **kw: Any
) -> Device:
    return Device(
        id=device_id,
        site_id=kw.pop("site_id", SITE.id),
        name=kw.pop("name", device_id),
        role=role,
        adapter=adapter,
        source=Source(adapter=adapter, device_id=device_id),
        **kw,
    )


def port(device_id: str, name: str, **kw: Any) -> Port:
    return Port(id=port_id(device_id, name), device_id=device_id, name=name, **kw)


def configured_port(device_id: str, name: str, **kw: Any) -> Port:
    """A gigabit copper port, link up, with every configuration detail reported (#156).

    Enabled, PVID 1, MTU 1500, auto-negotiation 10/100/1000; override any field, for example
    ``configured_port("sw", "5", pvid=20, description="office desk")`` or ``mtu=9000``.
    """
    values: dict[str, Any] = {
        "up": True,
        "speed_mbps": 1000,
        "full_duplex": True,
        "admin_up": True,
        "pvid": 1,
        "mtu": 1500,
        "max_speed_mbps": 1000,
        "advertised_speeds_mbps": [10, 100, 1000],
        "autoneg": True,
        "media": PortMedia.COPPER,
        "flow_control": False,
        "eee": False,
    }
    return port(device_id, name, **(values | kw))


def snapshot(dev: Device, **kw: Any) -> Snapshot:
    return Snapshot(device=dev, observed_at=kw.pop("observed_at", T0), **kw)


MiB = 1024 * 1024


def health(**kw: Any) -> DeviceHealth:
    """A healthy small router; override any field (``health(memory_used_bytes=250 * MiB)``)."""
    values: dict[str, Any] = {
        "uptime_seconds": 3 * 86400,
        "boot_time": T0 - timedelta(days=3),
        "cpu_load_pct": 12.0,
        "load_average": (0.2, 0.15, 0.1),
        "cpu_count": 4,
        "memory_total_bytes": 256 * MiB,
        "memory_used_bytes": 96 * MiB,
        "storage": [storage("/overlay", total_bytes=64 * MiB, used_bytes=8 * MiB)],
        "temperatures": [TemperatureSensor(name="cpu", value_c=52.0, limit_c=95.0)],
    }
    values.update(kw)
    return DeviceHealth(**values)


def storage(name: str, kind: StorageKind = StorageKind.SYSTEM, **kw: Any) -> StorageUsage:
    return StorageUsage(name=name, kind=kind, **kw)


def fan(name: str = "fan1", rpm: int | None = 3000, ok: bool | None = True) -> Fan:
    return Fan(name=name, rpm=rpm, ok=ok)


def psu(name: str = "psu1", ok: bool | None = True, **kw: Any) -> PowerSupply:
    return PowerSupply(name=name, ok=ok, **kw)


def ups(name: str = "ups", **kw: Any) -> UpsStatus:
    values: dict[str, Any] = {
        "on_battery": False,
        "charge_pct": 100.0,
        "runtime_seconds": 1800,
        "load_pct": 20.0,
        "last_test": T0 - timedelta(days=30),
    }
    values.update(kw)
    return UpsStatus(name=name, **values)


def device_time(offset_seconds: float = 0.0, **kw: Any) -> DeviceTime:
    """A clock read at ``T0``, ``offset_seconds`` ahead, synchronised to the gateway."""
    values: dict[str, Any] = {
        "clock": T0 + timedelta(seconds=offset_seconds),
        "read_at": T0,
        "uncertainty_seconds": 0.05,
        "timezone": "Europe/Berlin",
        "utc_offset_minutes": 60,
        "ntp_client": NtpClient(enabled=True, servers=["192.0.2.1"], synchronised=True),
    }
    values.update(kw)
    return DeviceTime(**values)


def ntp_server(*segments: str, enabled: bool = True) -> NtpServer:
    return NtpServer(enabled=enabled, segments=list(segments))


def uplink(device_id: str, name: str = "wan", **kw: Any) -> Uplink:
    """A DHCP uplink with a public IPv4, IPv6 and a delegated /56, up since a day (#148).

    Override any field: ``uplink("gw", addresses=[iface("100.64.0.23/10")])`` is behind CGNAT,
    ``addresses=[iface("192.0.2.20/24")]`` behind the router whose LAN that is (see
    ``Network.upstream_router``), ``kind=UplinkKind.DSLITE`` without IPv4, ``up=False,
    since=None`` down. ``port`` names the device's port.
    """
    port_name = kw.pop("port", None)
    values: dict[str, Any] = {
        "name": name,
        "kind": UplinkKind.DHCP,
        "up": True,
        "since": T0 - timedelta(days=1),
        "addresses": [iface("198.51.100.23/24"), iface("2001:db8:ffff::2/64")],
        "delegated_prefixes": [ip_network("2001:db8:100::/56")],
        "upstream_gateway": ip("198.51.100.1"),
        "dns_servers": [ip("198.51.100.53"), ip("2001:db8:ffff::53")],
    }
    if port_name is not None:
        values["port_id"] = port_id(device_id, port_name)
    return Uplink(
        id=object_id(device_id, "uplink", name),
        device_id=device_id,
        **(values | kw),
    )


def service(
    device_id: str, kind: ServiceKind | str, name: str | None = None, **kw: Any
) -> ManagementService:
    """An enabled management service on its usual port, listening everywhere (#173).

    Id ``<device>/service/<name or kind>``. Override any field:
    ``service("gw", "ssh", password_login=True, root_login=True)`` (root with a password),
    ``service("gw", "http", redirects_to_https=False)``,
    ``service("gw", "https", "remote-access", from_wan=True, port=8443)`` (Fritz!Box internet
    access), ``service("gw", "winbox", allowed_from=[net("192.0.2.0/24")])``,
    ``service("gw", "ssh", segments=[segment_id("home", 99)])`` (only in the management
    VLAN), ``service("gw", "mac-telnet", interfaces=[port_id("gw", "ether1")])``,
    ``service("gw", "snmp", snmp=snmp(default_community=True))``, ``enabled=False``.
    ``ports`` names the device's ports to bind to.
    """
    kind = ServiceKind(kind)
    ports = kw.pop("ports", None)
    values: dict[str, Any] = {"enabled": True, "port": SERVICE_PORTS.get(kind)}
    if ports is not None:
        values["interfaces"] = [port_id(device_id, p) for p in ports]
    if kind is ServiceKind.SNMP:
        values["snmp"] = snmp()
    return ManagementService(
        id=object_id(device_id, "service", name or kind.value),
        device_id=device_id,
        kind=kind,
        name=name,
        **(values | kw),
    )


def snmp(*versions: str, **kw: Any) -> SnmpSettings:
    """SNMP settings: v2c with a community of its own unless given (``snmp("3",
    v3_privacy=True)`` is encrypted)."""
    values: dict[str, Any] = {"versions": [SnmpVersion(v) for v in versions or ("2c",)]}
    values.setdefault("default_community", False)
    return SnmpSettings(**(values | kw))


def mikrotik_default_services(device_id: str) -> list[ManagementService]:
    """RouterOS's factory services: telnet, ftp, www, ssh, api and winbox on, www-ssl and
    api-ssl off, MAC telnet/Winbox on every interface (as ``/ip/service`` and
    ``/tool/mac-server`` report them on a fresh device; RoMON off)."""
    on = [("telnet", None), ("ftp", None), ("http", "www"), ("ssh", None), ("api", None)]
    out = [service(device_id, k, n) for k, n in on]
    out += [
        service(device_id, "https", "www-ssl", enabled=False),
        service(device_id, "winbox"),
        service(device_id, "api-ssl", enabled=False),
        service(device_id, "mac-telnet", port=None),
        service(device_id, "mac-winbox", port=None),
        service(device_id, "romon", port=None, enabled=False),
    ]
    return out


def net(text: str) -> Any:
    return ip_network(text)


def ip(text: str) -> Any:
    return ip_address(text)


def iface(text: str) -> Any:
    return ip_interface(text)


def annotation(target: str, **kw: Any) -> Annotation:
    """A user annotation (#186); expectations go into ``expected``, for example
    ``annotation("client/02:00:00:00:00:44", label="printer", expected={"static_address": True})``.
    """
    return Annotation(target=target, **kw)


def acknowledgement(rule_id: str, target: str | None = None, **kw: Any) -> Acknowledgement:
    """An acknowledgement of every finding of ``rule_id`` that names ``target`` (or of one
    finding: ``finding_id=...``), made at ``T0`` unless ``at`` is given."""
    kw.setdefault("id", f"ack-{rule_id}-{target or kw.get('finding_id')}")
    kw.setdefault("at", T0)
    return Acknowledgement(rule_id=rule_id, target=target, **kw)


def annotated(net: Network, *items: Annotation | Acknowledgement) -> Network:
    """The network with these annotations and acknowledgements added (as the runner does)."""
    notes = [i for i in items if isinstance(i, Annotation)]
    acks = [i for i in items if isinstance(i, Acknowledgement)]
    return net.model_copy(
        update={
            "annotations": [*net.annotations, *notes],
            "acknowledgements": [*net.acknowledgements, *acks],
        }
    )
