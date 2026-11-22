"""Fake adapters and a rule for the browser tests (documentation addresses, local MACs only)."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_interface, ip_network
from typing import Literal

from pydantic import Field, SecretStr

from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterError,
    Capability,
    Manifest,
    Observation,
    SystemInfo,
    Unreachable,
    UntrustedCertificate,
)
from signalbox.model import (
    Band,
    Client,
    DeviceHealth,
    DeviceRole,
    DeviceTime,
    DhcpPool,
    DhcpServer,
    DnsService,
    Firmware,
    HostRecord,
    Membership,
    Network,
    NtpClient,
    Pmf,
    Port,
    PortMembership,
    PurposeSource,
    Radio,
    Reservation,
    Security,
    Segment,
    SegmentPurpose,
    StorageKind,
    StorageUsage,
    Subnet,
    TemperatureSensor,
    Uplink,
    UplinkKind,
    Wlan,
    object_id,
    port_id,
    segment_id,
)
from signalbox.rules import Result, Severity, found, rule

#: The certificate the "untrusted" lab device presents.
FINGERPRINT = hashlib.sha256(b"signalbox-e2e-certificate").hexdigest()


def mac(device_id: str, n: int) -> str:
    d = hashlib.sha256(device_id.encode()).digest()
    return f"02:{d[0]:02x}:{d[1]:02x}:{d[2]:02x}:00:{n:02x}"


class LabConfig(AdapterConfig):
    host: str = Field(description="Address or name of the device, e.g. 192.0.2.1.")
    port: int = Field(443, ge=1, le=65535, description="HTTPS port of the device API.")
    verify_tls: bool = Field(True, description="Check the device certificate.")
    mode: Literal["full", "basic"] = Field("full", description="How much to read.")
    username: str = Field("admin", description="API user.")
    password: SecretStr = Field(description="API password.")
    api_token: SecretStr | None = Field(None, description="Optional API token.")


class Lab(Adapter):
    """A router with Wi-Fi. The host name decides the behaviour: "untrusted…" presents an
    untrusted certificate, "down…" does not answer, everything else answers."""

    manifest = Manifest(
        id="lab",
        name="Lab router",
        version="1",
        api_version="1.2",
        vendor="Example",
        roles=frozenset({DeviceRole.GATEWAY, DeviceRole.AP}),
        capabilities=frozenset(
            {Capability.INTERFACES, Capability.DHCP, Capability.DNS, Capability.WIRELESS}
            | {Capability.CLIENTS, Capability.HEALTH, Capability.TIME}
        ),
        config=LabConfig,
        description="Simulated router with Wi-Fi for the browser tests.",
        setup_url="https://github.com/PhilippMundhenk/signalbox/blob/main/docs/ADAPTERS.md",
        setup_steps=("Switch on the API of the router.", "Paste the commands below."),
        setup_commands="echo prepared\n",
    )

    @property
    def cfg(self) -> LabConfig:
        assert isinstance(self.context.config, LabConfig)
        return self.context.config

    async def read_system(self) -> SystemInfo:
        host = self.cfg.host
        if host.startswith("untrusted") and self.context.pinned_fingerprint != FINGERPRINT:
            raise UntrustedCertificate(FINGERPRINT, self.context.pinned_fingerprint)
        if host.startswith("down"):
            raise Unreachable(f"no answer from {host}")
        return SystemInfo(
            vendor="Example",
            model="LR-1",
            firmware=Firmware(current="1.2.3", available="1.3.0"),
            management_address=host,
        )

    def _seg(self, vlan: int) -> str:
        return segment_id(self.context.site_id, vlan)

    async def read_interfaces(self) -> Observation:
        d = self.context.device_id
        ports = [
            Port(
                id=port_id(d, "lan1"),
                device_id=d,
                name="lan1",
                up=True,
                speed_mbps=1000,
                mac=mac(d, 1),
                vendor_extra={"led": "green", "hw_queue": 4},
                description="Desk",
                admin_up=True,
                pvid=20,  # differs from its untagged VLAN 10 (#156)
                mtu=1500,
                max_speed_mbps=2500,
            ),
            Port(id=port_id(d, "lan2"), device_id=d, name="lan2", up=True, mac=mac(d, 2)),
            Port(
                id=port_id(d, "lan3"),
                device_id=d,
                name="lan3",
                up=False,
                admin_up=False,
                mac=mac(d, 3),
            ),
        ]
        segments = [
            Segment(
                id=self._seg(10),
                site_id=self.context.site_id,
                vlan=10,
                name="Office",
                purpose=SegmentPurpose.MAIN,
                purpose_source=PurposeSource.REPORTED,
                members=[
                    PortMembership(port_id=port_id(d, "lan1"), mode=Membership.UNTAGGED),
                    PortMembership(port_id=port_id(d, "lan2"), mode=Membership.TAGGED),
                ],
            ),
            Segment(
                id=self._seg(20),
                site_id=self.context.site_id,
                vlan=20,
                name="Guests",
                members=[PortMembership(port_id=port_id(d, "lan2"), mode=Membership.TAGGED)],
            ),
        ]
        subnets = [
            Subnet(
                id=f"{d}/subnet/office",
                segment_id=self._seg(10),
                interface=ip_interface("192.0.2.1/24"),
                device_id=d,
                gateway=True,
            ),
            Subnet(
                id=f"{d}/subnet/guests",
                segment_id=self._seg(20),
                interface=ip_interface("198.51.100.1/24"),
                device_id=d,
                gateway=True,
            ),
        ]
        uplink = Uplink(
            id=f"{d}/uplink/wan",
            device_id=d,
            name="wan",
            kind=UplinkKind.PPPOE,
            up=True,
            since=datetime.now(UTC) - timedelta(hours=3),
            addresses=[ip_interface("203.0.113.23/32"), ip_interface("2001:db8:ff::2/64")],
            delegated_prefixes=[ip_network("2001:db8:100::/56")],
            upstream_gateway=ip_address("203.0.113.1"),
            dns_servers=[ip_address("203.0.113.53")],
            downstream_kbps=100_000,
            upstream_kbps=40_000,
        )
        return Observation(ports=ports, segments=segments, subnets=subnets, uplinks=[uplink])

    async def read_dhcp(self) -> Observation:
        d = self.context.device_id
        return Observation(
            dhcp_servers=[
                DhcpServer(
                    id=f"{d}/dhcp/office",
                    device_id=d,
                    segment_id=self._seg(10),
                    enabled=True,
                    pools=[
                        DhcpPool(start=ip_address("192.0.2.100"), end=ip_address("192.0.2.199"))
                    ],
                    lease_seconds=86400,
                    router=ip_address("192.0.2.1"),
                    dns_servers=[ip_address("192.0.2.1")],
                    domain="lan",
                    reservations=[
                        Reservation(
                            mac="02:00:00:00:aa:01",
                            address=ip_address("192.0.2.10"),
                            hostname="printer",
                        )
                    ],
                ),
                DhcpServer(
                    id=f"{d}/dhcp/guests",
                    device_id=d,
                    segment_id=self._seg(20),
                    enabled=True,
                    pools=[
                        DhcpPool(
                            start=ip_address("198.51.100.100"), end=ip_address("198.51.100.199")
                        )
                    ],
                    router=ip_address("198.51.100.1"),
                    dns_servers=[ip_address("198.51.100.1")],
                ),
            ]
        )

    async def read_dns(self) -> Observation:
        d = self.context.device_id
        if self.cfg.host.startswith("nodns"):
            raise AdapterError(
                "access denied for dns",
                fix="Allow DNS reading, see https://github.com/PhilippMundhenk/signalbox/blob/main/docs/ADAPTERS.md",
            )
        return Observation(
            dns_services=[
                DnsService(
                    id=f"{d}/dns",
                    device_id=d,
                    listen=[ip_address("192.0.2.1"), ip_address("198.51.100.1")],
                    forwarders=[ip_address("203.0.113.53")],
                    host_records=[HostRecord(name="printer.lan", address=ip_address("192.0.2.10"))],
                )
            ]
        )

    async def read_wireless(self) -> Observation:
        d = self.context.device_id
        r24, r5 = object_id(d, "radio", "radio0"), object_id(d, "radio", "radio1")
        return Observation(
            radios=[
                Radio(
                    id=r24,
                    device_id=d,
                    name="radio0",
                    band=Band.GHZ_2_4,
                    channel=6,
                    width_mhz=20,
                    country="DE",
                    tx_power_dbm=20,
                ),
                Radio(
                    id=r5,
                    device_id=d,
                    name="radio1",
                    band=Band.GHZ_5,
                    channel=36,
                    width_mhz=80,
                    country="DE",
                ),
            ],
            wlans=[
                Wlan(
                    id=object_id(d, "wlan", "home-2g"),
                    device_id=d,
                    ssid="Home",
                    radio_id=r24,
                    security=Security.WPA3,
                    pmf=Pmf.REQUIRED,
                    segment_id=self._seg(10),
                    roaming_80211r=True,
                    roaming_80211k=True,
                    roaming_80211v=False,
                ),
                Wlan(
                    id=object_id(d, "wlan", "home-5g"),
                    device_id=d,
                    ssid="Home",
                    radio_id=r5,
                    security=Security.WPA3,
                    pmf=Pmf.REQUIRED,
                    segment_id=self._seg(10),
                    roaming_80211r=True,
                    roaming_80211k=True,
                    roaming_80211v=False,
                ),
                Wlan(
                    id=object_id(d, "wlan", "guest"),
                    device_id=d,
                    ssid="Guest",
                    radio_id=r24,
                    security=Security.OPEN,
                    segment_id=self._seg(20),
                    client_isolation=True,
                ),
            ],
        )

    async def read_clients(self) -> Observation:
        d = self.context.device_id
        now = datetime.now(UTC)
        return Observation(
            clients=[
                Client(
                    id=object_id(d, "client", "printer"),
                    mac="02:00:00:00:aa:01",
                    addresses=[ip_address("192.0.2.10")],
                    hostname="printer",
                    segment_id=self._seg(10),
                    seen_on=port_id(d, "lan1"),
                    last_seen=now,
                ),
                Client(
                    id=object_id(d, "client", "laptop"),
                    mac="02:00:00:00:aa:02",
                    addresses=[ip_address("192.0.2.123")],
                    hostname="laptop",
                    segment_id=self._seg(10),
                    seen_on=object_id(d, "wlan", "home-5g"),
                    last_seen=now,
                ),
            ]
        )

    async def read_health(self) -> Observation:
        mib = 1024 * 1024
        value = DeviceHealth(
            uptime_seconds=3 * 86400 + 4 * 3600,
            cpu_load_pct=12,
            cpu_count=2,
            memory_total_bytes=256 * mib,
            memory_used_bytes=96 * mib,
            storage=[
                StorageUsage(
                    name="/overlay",
                    kind=StorageKind.SYSTEM,
                    total_bytes=64 * mib,
                    used_bytes=8 * mib,
                )
            ],
            temperatures=[TemperatureSensor(name="cpu", value_c=52, limit_c=95)],
        )
        return Observation(health={self.context.device_id: value})

    async def read_time(self) -> Observation:
        value = DeviceTime(
            clock=datetime.now(UTC) - timedelta(minutes=7),
            timezone="Etc/UTC",
            ntp_client=NtpClient(enabled=False),
        )
        return Observation(time={self.context.device_id: value})


class SwitchConfig(AdapterConfig):
    address: str = Field(description="Address of the switch.")
    community: SecretStr | None = Field(None, description="Read community (optional).")


class Switch(Adapter):
    """A small managed switch: port p1 carries VLAN 10 tagged but not VLAN 20."""

    manifest = Manifest(
        id="labswitch",
        name="Lab switch",
        version="1",
        api_version="1.0",
        vendor="Example",
        roles=frozenset({DeviceRole.SWITCH}),
        capabilities=frozenset({Capability.INTERFACES}),
        config=SwitchConfig,
    )

    async def read_system(self) -> SystemInfo:
        return SystemInfo(vendor="Example", model="LS-8")

    async def read_interfaces(self) -> Observation:
        d = self.context.device_id
        seg = segment_id(self.context.site_id, 10)
        ports = [
            Port(id=port_id(d, f"p{i}"), device_id=d, name=f"p{i}", up=i < 3, mac=mac(d, i))
            for i in range(1, 5)
        ]
        members = [
            PortMembership(port_id=port_id(d, "p1"), mode=Membership.TAGGED),
            PortMembership(port_id=port_id(d, "p2"), mode=Membership.UNTAGGED),
        ]
        return Observation(
            ports=ports,
            segments=[Segment(id=seg, site_id=self.context.site_id, vlan=10, members=members)],
        )


@rule(
    "lab.open-wifi",
    "Open Wi-Fi network",
    Severity.WARNING,
    "An SSID without encryption lets everyone nearby read the traffic.",
)
def open_wifi(net: Network) -> Iterator[Result]:
    for w in net.wlans:
        if w.security is Security.OPEN:
            yield found(
                f"SSID {w.ssid} on {w.device_id} is open",
                [w.id],
                fix="Use WPA3 Personal, or Enhanced Open (OWE) for a guest network.",
            )
