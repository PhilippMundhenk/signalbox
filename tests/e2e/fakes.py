"""Fake adapters and a rule for the browser tests (documentation addresses, local MACs only)."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any, Literal

from pydantic import Field, SecretStr

from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterError,
    Capability,
    Manifest,
    Observation,
    SystemInfo,
    TraceAnswer,
    TraceSupport,
    Unreachable,
    UntrustedCertificate,
)
from signalbox.discovery import Candidate, HostProbe
from signalbox.model import (
    AddressSource,
    Band,
    Cipher,
    Client,
    DeviceHealth,
    DeviceRole,
    DeviceTime,
    DhcpLease,
    DhcpPool,
    DhcpServer,
    DnsForwarder,
    DnsService,
    FdbEntry,
    FdbKind,
    Firewall,
    FirewallAction,
    FirewallProtocol,
    FirewallZone,
    Firmware,
    HostRecord,
    LeaseState,
    ManagementService,
    Membership,
    Network,
    NtpClient,
    Pmf,
    Port,
    PortForward,
    PortKind,
    PortMembership,
    PortRange,
    PortRole,
    PurposeSource,
    Radio,
    Reservation,
    SaePwe,
    SaeSettings,
    Security,
    Segment,
    SegmentPurpose,
    ServiceKind,
    SnmpSettings,
    SnmpVersion,
    StorageKind,
    StorageUsage,
    Subnet,
    TemperatureSensor,
    TraceHop,
    Tunnel,
    TunnelPeer,
    Uplink,
    UplinkKind,
    Wlan,
    Wps,
    WpsMethod,
    ZonePolicy,
    fdb_id,
    firewall_id,
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

    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        """Lab routers answer at 192.0.2.1 (added in the tests) and 192.0.2.7; the model name
        carries markup that must stay text."""
        if probe.host not in ("192.0.2.1", "192.0.2.7", "203.0.113.5"):
            return None
        return Candidate(
            address=probe.host,
            role=DeviceRole.AP,
            config={"host": probe.host, "port": 8443},
            vendor="Example",
            model="LR-2 <img src=x onerror=alert(1)>",
            firmware="2.0",
            identities=[f"serial:LR-{'1' if probe.host == '192.0.2.1' else '2'}"],
            evidence="lab answer",
            note="Switch on the API first.",
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
            transport_encrypted=True,
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
                role=PortRole.JACK,
                lower=[port_id(d, "eth0")],
            ),
            Port(
                id=port_id(d, "lan2"),
                device_id=d,
                name="lan2",
                up=True,
                mac=mac(d, 2),
                role=PortRole.JACK,
                lower=[port_id(d, "eth0")],
            ),
            Port(
                id=port_id(d, "lan3"),
                device_id=d,
                name="lan3",
                up=False,
                admin_up=False,
                mac=mac(d, 3),
                role=PortRole.JACK,
                lower=[port_id(d, "eth0")],
            ),
            # the internal structure (#252): CPU port, bridge, VLAN and Wi-Fi interface
            Port(id=port_id(d, "eth0"), device_id=d, name="eth0", up=True, role=PortRole.CPU),
            Port(
                id=port_id(d, "br-lan"),
                device_id=d,
                name="br-lan",
                kind=PortKind.BRIDGE,
                role=PortRole.BRIDGE,
                lower=[port_id(d, "lan1"), port_id(d, "lan2"), port_id(d, "phy0-ap0")],
            ),
            Port(
                id=port_id(d, "br-lan.10"),
                device_id=d,
                name="br-lan.10",
                kind=PortKind.VIRTUAL,
                role=PortRole.VLAN,
                lower=[port_id(d, "br-lan")],
            ),
            Port(
                id=port_id(d, "phy0-ap0"),
                device_id=d,
                name="phy0-ap0",
                kind=PortKind.WIRELESS,
                role=PortRole.WIRELESS,
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

        def svc(kind: ServiceKind, **kw: object) -> ManagementService:
            name = str(kw.get("name") or kind.value)
            return ManagementService.model_validate(
                {"id": f"{d}/service/{name}", "device_id": d, "kind": kind, **kw}
            )

        services = [
            svc(ServiceKind.HTTPS, enabled=True, port=443, segments=[self._seg(10)]),
            svc(ServiceKind.HTTP, enabled=True, port=80, redirects_to_https=True),
            svc(
                ServiceKind.SSH,
                enabled=True,
                port=22,
                allowed_from=[ip_network("192.0.2.0/24")],
                password_login=True,
                root_login=True,
            ),
            svc(ServiceKind.TELNET, enabled=False, port=23),
            svc(
                ServiceKind.SNMP,
                enabled=True,
                port=161,
                snmp=SnmpSettings(versions=[SnmpVersion.V2C], default_community=True),
            ),
            svc(ServiceKind.HTTPS, name="remote", enabled=True, port=8443, from_wan=True),
        ]
        return Observation(
            ports=ports, segments=segments, subnets=subnets, uplinks=[uplink], services=services
        )

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
                    leases=[
                        DhcpLease(
                            address=ip_address("192.0.2.123"),
                            mac="02:00:00:00:aa:02",
                            hostname="laptop",
                            expires=datetime.now(UTC) + timedelta(hours=12),
                            vendor_class="MSFT 5.0",
                        ),
                        DhcpLease(
                            address=ip_address("192.0.2.150"),
                            mac="02:00:00:00:aa:09",
                            state=LeaseState.EXPIRED,
                        ),
                    ],
                    search_domains=["lan"],
                    authoritative=True,
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
                    forwarders=[
                        DnsForwarder(address=ip_address("203.0.113.53")),
                        DnsForwarder(address=ip_address("2001:db8::53"), port=5353),
                    ],
                    host_records=[HostRecord(name="printer.lan", address=ip_address("192.0.2.10"))],
                ),
                # AdGuard Home next to it (#241): known to answer, not read
                DnsService(id=f"{d}/dns/port-5353", device_id=d, port=5353, config_read=False),
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
                    supported_security=[Security.WPA2, Security.WPA3, Security.WPA2_WPA3],
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
                    port_id=port_id(d, "phy0-ap0"),
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
                    ciphers=[Cipher.CCMP],
                    group_cipher=Cipher.CCMP,
                    sae=SaeSettings(pwe=SaePwe.HASH_TO_ELEMENT),
                    wps=Wps(enabled=True, methods=[WpsMethod.PUSH_BUTTON]),
                    beacon_protection=True,
                    key_rotation_seconds=3600,
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
                    address_sources={ip_address("192.0.2.10"): AddressSource.DHCP_RESERVED},
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
            ],
            fdb=[  # the bridge's MAC address table (#160)
                FdbEntry(
                    id=fdb_id(d, "lan1", "02:00:00:00:aa:01", 10),
                    device_id=d,
                    port_id=port_id(d, "lan1"),
                    mac="02:00:00:00:aa:01",
                    vlan=10,
                    age_seconds=30,
                ),
                FdbEntry(
                    id=fdb_id(d, "lan1", "02:00:00:00:aa:09"),
                    device_id=d,
                    port_id=port_id(d, "lan1"),
                    mac="02:00:00:00:aa:09",
                    kind=FdbKind.STATIC,
                ),
            ],
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

    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        if probe.host != "198.51.100.20":
            return None
        return Candidate(
            address=probe.host, role=DeviceRole.SWITCH, config={"address": probe.host}, model="LS-8"
        )

    async def read_system(self) -> SystemInfo:
        return SystemInfo(vendor="Example", model="LS-8", transport_encrypted=False)

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


def wg_key(name: str) -> str:
    """A valid WireGuard key from a name (nobody's real key)."""
    return base64.b64encode(hashlib.sha256(f"e2e-{name}".encode()).digest()).decode()


class GateConfig(AdapterConfig):
    end: Literal["a", "b"] = Field(description="Which end of the lab tunnel this gateway is.")


class Gate(Adapter):
    """A gateway with one WireGuard tunnel (#239): end "a" and end "b" name each other's keys;
    "a" also has a peer "office" routing 203.0.113.0/24, whose end is never read."""

    manifest = Manifest(
        id="labvpn",
        name="Lab VPN gateway",
        version="1",
        api_version="1.4",
        vendor="Example",
        roles=frozenset({DeviceRole.GATEWAY}),
        capabilities=frozenset({Capability.VPN, Capability.FIREWALL}),
        config=GateConfig,
    )

    async def read_system(self) -> SystemInfo:
        return SystemInfo(vendor="Example", model="VPN-1")

    async def read_vpn(self) -> Observation:
        assert isinstance(self.context.config, GateConfig)
        end = self.context.config.end
        other = "b" if end == "a" else "a"
        lan = {"a": "192.0.2.0/24", "b": "198.51.100.0/24"}
        host = {"a": "1", "b": "2"}
        peers = [
            TunnelPeer(
                public_key=wg_key(other),
                name=f"site-{other}",
                endpoint_host="203.0.113.9" if end == "a" else None,
                endpoint_port=51820 if end == "a" else None,
                allowed_ips=[ip_network(f"2001:db8:ff::{host[other]}/128"), ip_network(lan[other])],
                latest_handshake=datetime.now(UTC) - timedelta(seconds=50),
                rx_bytes=2048,
                tx_bytes=4096,
                keepalive_seconds=25,
            )
        ]
        if end == "a":
            peers.append(
                TunnelPeer(
                    public_key=wg_key("office"),
                    name="office",
                    allowed_ips=[ip_network("2001:db8:ff::9/128"), ip_network("203.0.113.0/24")],
                )
            )
        d = self.context.device_id
        tunnel = Tunnel(
            id=f"{d}/tunnel/wg0",
            device_id=d,
            name="wg0",
            description="s2s",
            up=True,
            listen_port=51820,
            public_key=wg_key(end),
            addresses=[ip_interface(f"2001:db8:ff::{host[end]}/64")],
            peers=peers,
        )
        return Observation(tunnels=[tunnel])

    async def read_firewall(self) -> Observation:
        """Zones ``vpn`` (the tunnel) and ``wan``; the tunnel may reach the gateway, the
        internet may not; HTTPS is forwarded to a server (#135)."""
        d = self.context.device_id
        accept, drop = FirewallAction.ACCEPT, FirewallAction.DROP
        fw = Firewall(
            id=firewall_id(d),
            device_id=d,
            zones=[FirewallZone(name="vpn", tunnels=[f"{d}/tunnel/wg0"]), FirewallZone(name="wan")],
            policies=[
                ZonePolicy(source="vpn", destination=None, action=accept),
                ZonePolicy(source="wan", destination=None, action=drop),
            ],
            forward_policy=drop,
            port_forwards=[
                PortForward(
                    name="web",
                    protocols=[FirewallProtocol.TCP],
                    external_ports=[PortRange(start=443)],
                    target_address=ip_address("192.0.2.10"),
                )
            ],
        )
        return Observation(firewalls=[fw])


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


class TracingConfig(AdapterConfig):
    lan: str = Field(description="The router's LAN address with prefix, e.g. 10.1.0.1/24.")


class Tracing(Adapter):
    """A router that runs traceroutes (#253): every target is reached through the provider's
    router 192.168.100.1 (a router Signalbox does not know, private address) and 203.0.113.1."""

    manifest = Manifest(
        id="labtrace",
        name="Lab tracing router",
        version="1",
        api_version="1.3",
        vendor="Example",
        roles=frozenset({DeviceRole.GATEWAY}),
        capabilities=frozenset({Capability.INTERFACES}),
        config=TracingConfig,
        traces=TraceSupport(permission="nothing (a lab router)", method="lab"),
    )

    @property
    def cfg(self) -> TracingConfig:
        assert isinstance(self.context.config, TracingConfig)
        return self.context.config

    async def read_system(self) -> SystemInfo:
        return SystemInfo(vendor="Example", model="TR-1")

    async def read_interfaces(self) -> Observation:
        d = self.context.device_id
        return Observation(
            subnets=[
                Subnet(
                    id=object_id(d, "subnet", "lan"),
                    segment_id=segment_id(self.context.site_id, None),
                    interface=ip_interface(self.cfg.lan),
                    device_id=d,
                    gateway=True,
                )
            ],
            uplinks=[
                Uplink(
                    id=object_id(d, "uplink", "wan"),
                    device_id=d,
                    name="wan",
                    kind=UplinkKind.DHCP,
                    up=True,
                    addresses=[ip_interface("203.0.113.30/24")],
                )
            ],
        )

    async def trace(self, target: Any, max_hops: int, wait: float) -> TraceAnswer:
        hops = [
            TraceHop(ttl=1, address=ip_address("192.168.100.1"), rtt_ms=0.8),
            TraceHop(ttl=2, address=ip_address("203.0.113.1"), rtt_ms=4.0),
            TraceHop(ttl=3, address=target, rtt_ms=9.5),
        ]
        return TraceAnswer(hops=hops, reached=True)
