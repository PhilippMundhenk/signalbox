"""Ubiquiti EdgeRouter (EdgeOS) and VyOS over SSH, read-only (#403).

Signalbox logs in with a user of its own (operator level: it may run ``show`` commands and
nothing else), a key and a pinned host key, sends one read script per observation
(:mod:`signalbox.adapters.edgeos.collect`) and maps the answer: ``show configuration commands``
(the whole configuration as ``set`` lines, a tree in :mod:`~signalbox.adapters.edgeos.tree`) to
ports, VLANs (``vif``), bridges and switches, bonds, addresses, the DHCP server, DNS forwarding,
WireGuard, SSH/GUI/Telnet services, NTP and the firewall rule-sets, NAT and port forwards
(:mod:`~signalbox.adapters.edgeos.firewall`); ``ip`` for link state, MAC addresses, installed
addresses and routes; ``show dhcp leases``, ``show lldp neighbors detail`` and ``show version``.

EdgeOS 2.0.x, 1.10.x and 1.9.x, and VyOS 1.3 are read alike; VyOS 1.4 too, except the firewall
rules (renamed to ``firewall ipv4``), which a gap names. Nothing is written, nothing needs root.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from ipaddress import IPv4Address, ip_address, ip_network
from typing import Any

import asyncssh
from pydantic import Field

from signalbox.adapters import (
    Adapter,
    AdapterError,
    Capability,
    Gap,
    Manifest,
    Observation,
    SystemInfo,
    UntrustedHostKey,
    known_interfaces,
)
from signalbox.adapters.edgeos import collect, firewall, parse, tree
from signalbox.adapters.edgeos.collect import Answer

# the config class is shared with the Linux integration (host, port, user, key or password)
from signalbox.adapters.linux import LinuxConfig as _SshConfig
from signalbox.adapters.linux import UntrustedSshHostKey
from signalbox.adapters.linux import parse as linux_parse
from signalbox.adapters.linux.collect import split
from signalbox.adapters.ssh import PinnedSsh, load_private_key
from signalbox.lldp import med_class, protocol_of
from signalbox.model import (
    DeviceHealth,
    DeviceRole,
    DeviceTime,
    DhcpLease,
    DhcpPool,
    DhcpRelay,
    DhcpServer,
    DnsForwarder,
    DnsService,
    Firewall,
    FirewallZone,
    Firmware,
    HostRecord,
    IPAddress,
    IPInterface,
    ManagementService,
    Membership,
    Neighbour,
    NtpClient,
    Port,
    PortKind,
    PortMembership,
    PortRole,
    Reservation,
    Route,
    RouteKind,
    RouteOrigin,
    Segment,
    ServiceKind,
    Subnet,
    Tunnel,
    TunnelPeer,
    Uplink,
    UplinkKind,
    firewall_id,
    object_id,
    port_id,
    route_id,
    segment_id,
)

__all__ = ["EdgeosAdapter", "EdgeosConfig"]

AUTH_FIX = (
    "Check the user name and the private key (or password) in the settings, and that the user "
    "exists on the router with the level operator and its public key (see the setup guide)."
)


class EdgeosConfig(_SshConfig):
    host: str = Field(
        description="The router's address or name, for example 192.0.2.1 or er.lan",
        examples=["192.0.2.1"],
    )
    username: str = Field(
        "signalbox",
        description="A user of its own with the level operator (read only), see the setup guide",
    )


EDGEOS_STEPS = (
    "On the router, in configuration mode, create a user signalbox with the level operator "
    "and your public key (commands below).",
    "Commit and save the configuration. The user can run show commands and nothing else.",
    "Below: the address, user signalbox and the private key. Then Test connection and trust "
    "the SSH host key (compare it with ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub).",
)

SETUP_COMMANDS = """configure
set system login user signalbox level operator
set system login user signalbox authentication public-keys signalbox type ssh-ed25519
set system login user signalbox authentication public-keys signalbox key <the key, middle part>
commit
save
exit"""

#: Port types of the ``interfaces`` configuration and what they are.
_TUNNELS = {
    "wireguard",
    "tunnel",
    "vti",
    "openvpn",
    "l2tp",
    "l2tpv3",
    "pppoe",
    "pptp",
    "sstpc",
    "vxlan",
}
_SKIPPED = {"loopback", "input"}


class EdgeosAdapter(Adapter):
    manifest = Manifest(
        id="edgeos",
        name="Ubiquiti EdgeRouter (EdgeOS) and VyOS",
        version="0.1.0",
        api_version="1.4",
        vendor="Ubiquiti",
        roles=frozenset({DeviceRole.GATEWAY, DeviceRole.OTHER}),
        capabilities=frozenset(
            {
                Capability.INTERFACES,
                Capability.DHCP,
                Capability.DNS,
                Capability.NEIGHBOURS,
                Capability.HEALTH,
                Capability.TIME,
                Capability.VPN,
                Capability.FIREWALL,
            }
        ),
        config=EdgeosConfig,
        description=(
            "Reads an EdgeRouter (EdgeOS 2.0, 1.10, 1.9) or a VyOS router (1.3, 1.4) over SSH "
            "with an operator-level user of its own: the configuration (show configuration "
            "commands), ip, DHCP leases, LLDP neighbours, WireGuard, firewall rule-sets and NAT."
        ),
        setup_steps=EDGEOS_STEPS,
        setup_commands=SETUP_COMMANDS,
        setup_url="https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/edgeos.md#setup",
    )

    _ssh: PinnedSsh | None = None
    _answer: Answer | None = None

    @property
    def config(self) -> EdgeosConfig:
        assert isinstance(self.context.config, EdgeosConfig)
        return self.context.config

    async def close(self) -> None:
        if self._ssh is not None:
            await self._ssh.__aexit__(None, None, None)
            self._ssh = None

    async def _connect(self) -> PinnedSsh:
        cfg = self.config
        key: asyncssh.SSHKey | None = None
        if cfg.private_key is not None and cfg.private_key.get_secret_value().strip():
            try:
                key = load_private_key(cfg.private_key.get_secret_value())
            except ValueError as exc:
                raise AdapterError(
                    f"private key: {exc}",
                    fix=AUTH_FIX,
                    message_id="edgeos.privateKey",
                    fix_id="edgeos.auth.fix",
                    params={"detail": str(exc)},
                ) from None
        ssh = PinnedSsh(
            cfg.host,
            cfg.port,
            cfg.username,
            cfg.password.get_secret_value() if cfg.password is not None else "",
            self.context.pinned_fingerprint,
            self.context.timeout,
            client_key=key,
            login=f"the login {cfg.username}",
            auth_fix=AUTH_FIX,
            auth_fix_id="edgeos.auth.fix",
        )
        try:
            await ssh.__aenter__()
        except UntrustedHostKey:
            raise UntrustedSshHostKey(
                ssh.fingerprint_hex or "", self.context.pinned_fingerprint, ssh.fingerprint
            ) from None
        return ssh

    async def _run(self, script: str) -> Answer:
        if self._ssh is None:
            self._ssh = await self._connect()
        res = await self._ssh.run(script)
        answer = split(res.text)
        if not answer.complete():
            tail = (res.err or res.text).strip()[-300:]
            raise AdapterError(
                f"the router did not answer the read commands completely: {tail}",
                fix="Signalbox runs its commands with sh -s. Check that the user's login shell "
                "is the default (vbash) and that the user has the level operator.",
                message_id="edgeos.incompleteAnswer",
                fix_id="edgeos.incompleteAnswer.fix",
                params={"tail": tail},
            )
        return answer

    @property
    def answer(self) -> Answer:
        assert self._answer is not None, "read_system first"
        return self._answer

    @property
    def root(self) -> tree.Node:
        return tree.parse(self.answer.text("config"))

    @property
    def version(self) -> parse.Version:
        return parse.version(self.answer)

    # system -----------------------------------------------------------------------------

    async def read_system(self) -> SystemInfo:
        await self.close()  # a new observation: check the host key again
        self._answer = await self._run(collect.READ)
        a = self._answer
        v = self.version
        f = v.fields
        kernel = a.text("kernel").split()
        extra: dict[str, Any] = {"software": v.flavor}
        for key, label in (("Build ID", "build_id"), ("Release train", "release_train")):
            if f.get(key):
                extra[label] = f[key]
        if len(kernel) >= 2:
            extra["kernel"] = kernel[1]
        hardware = f.get("HW model") or f.get("Hardware model")
        serial = f.get("HW S/N") or f.get("Hardware S/N")
        return SystemInfo(
            vendor="VyOS" if v.vyos else "Ubiquiti",
            model=hardware or None,
            firmware=Firmware(current=v.text) if v.text else None,
            management_address=self.config.host,
            transport_encrypted=True,
            serial=serial or None,
            hostname=self.root.first("system", "host-name"),
            architecture=kernel[-1] if len(kernel) >= 3 else None,
            os=v.name,
            os_version=v.text,
            vendor_extra=extra,
        )

    # interfaces -------------------------------------------------------------------------

    @property
    def router(self) -> bool:
        return self.context.role is DeviceRole.GATEWAY

    def _layout(self) -> _Layout:
        return _Layout.build(
            self.context.device_id, self.context.site_id, self.answer, self.root, self.router
        )

    async def read_interfaces(self) -> Observation:
        lay = self._layout()
        v = self.version
        gaps: list[Gap] = []
        if v.text is None:
            gaps.append(
                Gap(
                    message="version: show version printed no Version line, so the software "
                    "version is not known; the configuration is read as EdgeOS 2.0",
                    optional=True,
                    message_id="edgeos.versionUnknown",
                )
            )
        if not lay.links:
            gaps.append(
                Gap(
                    message="interfaces: ip -o link printed no interfaces, so the link state, "
                    "MAC addresses and installed addresses are not read",
                    optional=True,
                    message_id="edgeos.noLinks",
                )
            )
        if not self.answer.text("config").strip():
            gaps.append(
                Gap(
                    message="configuration: show configuration commands printed nothing, so "
                    "nothing of the configuration was read",
                    fix="Check that the user has the level operator and that "
                    "/opt/vyatta/bin/vyatta-op-cmd-wrapper exists.",
                    message_id="edgeos.configEmpty",
                    fix_id="edgeos.configEmpty.fix",
                )
            )
        return Observation(
            incomplete=gaps,
            ports=list(lay.ports.values()),
            segments=lay.segments(),
            subnets=lay.subnets,
            uplinks=lay.uplinks,
            services=self._services(lay),
            routes=known_interfaces(self._routes(lay), [p.id for p in lay.ports.values()]),
        )

    def _routes(self, lay: _Layout) -> list[Route]:
        d = self.context.device_id
        configured: dict[tuple[Any, Any], int | None] = {}
        for dest, node in self.root.items("protocols", "static", "route"):
            with contextlib.suppress(ValueError):
                net = ip_network(dest, strict=False)
                for hop, hop_node in node.items("next-hop"):
                    if not hop_node.has("disable"):
                        configured[(net, ip_address(hop))] = _int(hop_node.first("distance"))
                if node.has("blackhole"):
                    configured[(net, None)] = _int(node.first("blackhole", "distance"))
        for dest, node in self.root.items("protocols", "static", "route6"):
            with contextlib.suppress(ValueError):
                net = ip_network(dest, strict=False)
                for hop, hop_node in node.items("next-hop"):
                    configured[(net, ip_address(hop))] = _int(hop_node.first("distance"))
        out: dict[str, Route] = {}
        for r in parse.routes(self.answer):
            if r.protocol == "kernel" and r.gateway is None:
                continue  # connected: derived from the subnets
            ours = (r.destination, r.gateway) in configured
            origin = RouteOrigin.OTHER
            if r.protocol == "dhcp":
                origin = RouteOrigin.DHCP
            elif r.protocol == "ra":
                origin = RouteOrigin.RA
            elif ours or r.protocol in ("static", "boot"):
                origin = RouteOrigin.STATIC
            elif r.protocol in ("zebra", "bird", "ospf", "bgp", "rip", "isis"):
                origin = RouteOrigin.DYNAMIC
            kind = {
                "blackhole": RouteKind.BLACKHOLE,
                "unreachable": RouteKind.UNREACHABLE,
                "prohibit": RouteKind.PROHIBIT,
            }.get(r.kind, RouteKind.UNICAST)
            iface = port_id(d, r.dev) if r.dev else None
            rid = route_id(d, "main", r.destination, r.gateway, iface, kind)
            out[rid] = Route(
                id=rid,
                device_id=d,
                destination=r.destination,
                gateway=r.gateway,
                interface=iface,
                metric=r.metric
                if r.metric is not None
                else configured.get((r.destination, r.gateway)),
                origin=origin,
                kind=kind,
                active=True,
            )
        installed = {(x.destination, x.gateway) for x in out.values()}
        for (net, gateway), distance in configured.items():
            if (net, gateway) in installed:
                continue
            kind = RouteKind.BLACKHOLE if gateway is None else RouteKind.UNICAST
            rid = route_id(d, "main", net, gateway, None, kind)
            out[rid] = Route(
                id=rid,
                device_id=d,
                destination=net,
                gateway=gateway,
                metric=distance,
                origin=RouteOrigin.STATIC,
                kind=kind,
                active=False,
            )
        return list(out.values())

    def _services(self, lay: _Layout) -> list[ManagementService]:
        d = self.context.device_id
        root = self.root
        out: list[ManagementService] = []

        def listen(*path: str) -> list[IPAddress]:
            found: list[IPAddress] = []
            for text in root.keys(*path, "listen-address"):
                with contextlib.suppress(ValueError):
                    found.append(ip_address(text))
            return found

        if root.has("service", "ssh"):
            ports = [int(p) for p in root.keys("service", "ssh", "port") if p.isdigit()] or [22]
            for n, number in enumerate(dict.fromkeys(ports)):
                out.append(
                    ManagementService(
                        id=object_id(d, "service", "ssh" if n == 0 else f"ssh-{number}"),
                        device_id=d,
                        kind=ServiceKind.SSH,
                        name="sshd",
                        enabled=True,
                        port=number,
                        listen=listen("service", "ssh"),
                        password_login=not root.has(
                            "service", "ssh", "disable-password-authentication"
                        ),
                    )
                )
        if root.has("service", "gui"):
            https = _int(root.first("service", "gui", "https-port")) or 443
            out.append(
                ManagementService(
                    id=object_id(d, "service", "gui-https"),
                    device_id=d,
                    kind=ServiceKind.HTTPS,
                    name="gui",
                    enabled=True,
                    port=https,
                    listen=listen("service", "gui"),
                )
            )
            if root.has("service", "gui", "http-port"):
                out.append(
                    ManagementService(
                        id=object_id(d, "service", "gui-http"),
                        device_id=d,
                        kind=ServiceKind.HTTP,
                        name="gui",
                        enabled=True,
                        port=_int(root.first("service", "gui", "http-port")) or 80,
                        listen=listen("service", "gui"),
                    )
                )
        if root.has("service", "telnet"):
            out.append(
                ManagementService(
                    id=object_id(d, "service", "telnet"),
                    device_id=d,
                    kind=ServiceKind.TELNET,
                    name="telnet",
                    enabled=True,
                    port=_int(root.first("service", "telnet", "port")) or 23,
                    listen=listen("service", "telnet"),
                )
            )
        if root.has("service", "snmp"):
            out.append(
                ManagementService(
                    id=object_id(d, "service", "snmp"),
                    device_id=d,
                    kind=ServiceKind.SNMP,
                    name="snmpd",
                    enabled=True,
                    port=161,
                    listen=listen("service", "snmp"),
                )
            )
        return out

    # DHCP and DNS -------------------------------------------------------------------------

    async def read_dhcp(self) -> Observation:
        d = self.context.device_id
        root = self.root
        lay = self._layout()
        gaps: list[Gap] = []
        leases = parse.dhcp_leases(self.answer)
        servers: list[DhcpServer] = []
        relays: dict[str, DhcpRelay] = {}
        off = (root.first("service", "dhcp-server", "disabled") or "false") == "true"
        for shared, shared_node in root.items("service", "dhcp-server", "shared-network-name"):
            enabled = not off and not shared_node.has("disable")
            for net_text, sub in shared_node.items("subnet"):
                try:
                    net = ip_network(net_text, strict=False)
                except ValueError:
                    continue
                found = lay.locate(net)
                if found is None:
                    gaps.append(
                        Gap(
                            message=f"{shared}: the DHCP subnet {net_text} is on no network of "
                            "the router",
                            message_id="edgeos.rangeNoNetwork",
                            params={"server": shared, "range": net_text},
                        )
                    )
                    continue
                seg, iface = found
                pools = _pools(sub)
                reservations = []
                for name, mapping in sub.items("static-mapping"):
                    mac = mapping.first("mac-address") or mapping.first("mac")
                    address = _address(mapping.first("ip-address"))
                    if mac and address is not None and address in net:
                        with contextlib.suppress(ValueError):
                            reservations.append(
                                Reservation(mac=mac.lower(), address=address, hostname=name)
                            )
                reserved = {(r.mac, r.address) for r in reservations}
                mine: list[DhcpLease] | None = None
                if leases is not None:
                    mine = [
                        x.lease.model_copy(
                            update={"reserved": (x.lease.mac, x.lease.address) in reserved}
                        )
                        for x in leases
                        if x.lease.address in net
                    ]
                dns = [
                    a
                    for a in (
                        _address(x)
                        for x in sub.keys("dns-server") + sub.keys("option", "name-server")
                    )
                    if a is not None
                ]
                ntp = [
                    a
                    for a in (
                        _address(x)
                        for x in sub.keys("ntp-server") + sub.keys("option", "ntp-server")
                    )
                    if a is not None
                ]
                servers.append(
                    DhcpServer(
                        id=object_id(d, "dhcp", f"{shared}-{net_text.replace('/', '-')}"),
                        device_id=d,
                        segment_id=seg,
                        enabled=enabled,
                        pools=pools,
                        lease_seconds=_int(sub.first("lease")),
                        router=_address(
                            sub.first("default-router") or sub.first("option", "default-router")
                        ),
                        dns_servers=dns,
                        domain=sub.first("domain-name") or sub.first("option", "domain-name"),
                        reservations=reservations,
                        ntp_servers=ntp,
                        leases=mine,
                        authoritative=(
                            shared_node.first("authoritative") in ("enable", "true")
                            if shared_node.has("authoritative")
                            else None
                        ),
                        vendor_extra={"shared_network": shared, "interface_address": str(iface)},
                    )
                )
        for name in root.keys("service", "dhcp-relay", "interface"):
            found_net = lay.networks.get(name)
            if found_net is None:
                continue
            seg = found_net[0]
            relays[seg] = DhcpRelay(
                id=object_id(d, "dhcp-relay", seg.rsplit("/", 1)[-1]),
                device_id=d,
                segment_id=seg,
                servers=[
                    a
                    for a in (_address(x) for x in root.keys("service", "dhcp-relay", "server"))
                    if a
                ],
            )
        return Observation(dhcp_servers=servers, dhcp_relays=list(relays.values()), incomplete=gaps)

    async def read_dns(self) -> Observation:
        d = self.context.device_id
        root = self.root
        if not root.has("service", "dns", "forwarding"):
            return Observation()
        lay = self._layout()
        listen: list[IPAddress] = []
        for name in root.keys("service", "dns", "forwarding", "listen-on"):
            for addr in lay.networks.get(name, ("", []))[1]:
                if addr.ip not in listen:
                    listen.append(addr.ip)
        for text in root.keys("service", "dns", "forwarding", "listen-address"):
            with contextlib.suppress(ValueError):
                listen.append(ip_address(text))
        forwarders: list[DnsForwarder] = []
        for text in root.keys("service", "dns", "forwarding", "name-server"):
            with contextlib.suppress(ValueError):
                fwd = DnsForwarder.model_validate(text)
                if fwd not in forwarders:
                    forwarders.append(fwd)
        records: list[HostRecord] = []
        for host, node in root.items("system", "static-host-mapping", "host-name"):
            address = _address(node.first("inet"))
            if address is not None:
                records.append(HostRecord(name=host, address=address, source="host-override"))
        cache = self.root.first("service", "dns", "forwarding", "cache-size")
        # ``dhcp <interface>``: dnsmasq answers the names of that DHCP server's leases (#456)
        names = self.root.has("service", "dns", "forwarding", "dhcp")
        return Observation(
            dns_services=[
                DnsService(
                    id=object_id(d, "dns", "forwarding"),
                    device_id=d,
                    name="dnsmasq",
                    enabled=True,
                    listen=listen,
                    forwarders=forwarders,
                    host_records=records,
                    recursive=False,  # dnsmasq asks its name servers
                    cache_size=int(cache) if cache and cache.isdigit() else None,
                    register_dhcp=names,
                    dynamic_records=names or None,
                )
            ]
        )

    # neighbours -----------------------------------------------------------------------------

    async def read_neighbours(self) -> Observation:
        d = self.context.device_id
        lay = self._layout()
        gaps: list[Gap] = []
        if not self.root.has("service", "lldp"):
            gaps.append(
                Gap(
                    message="LLDP is off on the router, so no neighbours are read",
                    fix="Optional: enable it (configure, set service lldp interface all, "
                    "commit, save).",
                    optional=True,
                    message_id="edgeos.lldpOff",
                    fix_id="edgeos.lldpOff.fix",
                )
            )
        out: dict[str, Neighbour] = {}
        for n in parse.lldp(self.answer):
            if n.interface not in lay.ports:
                continue
            nid = object_id(d, "neighbour", f"{n.interface}-{n.chassis}")
            out[nid] = Neighbour(
                id=nid,
                local_port_id=port_id(d, n.interface),
                chassis_id=n.chassis,
                remote_port=n.port,
                system_name=n.system_name,
                management_address=n.management,
                capabilities=n.capabilities,
                description=n.description,
                protocol=protocol_of(n.via),
                chassis_id_kind=n.chassis_kind,
                port_description=n.port_description,
                ttl_seconds=n.ttl,
                age_seconds=n.age,
                max_frame_size=n.max_frame_size,
                port_vlan=n.port_vlan,
                vlans=n.vlans,
                med_device_class=med_class(n.med_device_type),
            )
        return Observation(neighbours=list(out.values()), incomplete=gaps)

    # VPN ------------------------------------------------------------------------------------

    async def read_vpn(self) -> Observation:
        d = self.context.device_id
        root = self.root
        lay = self._layout()
        keys = parse.wireguard_keys(self.answer)
        tunnels: list[Tunnel] = []
        for name, node in root.items("interfaces", "wireguard"):
            peers: list[TunnelPeer] = []
            for label, peer in node.items("peer"):
                # EdgeOS names the peer by its key; VyOS by a name with pubkey (1.3) or
                # public-key (1.4)
                key = peer.first("pubkey") or peer.first("public-key") or label
                if key == keys.get(name):
                    continue
                endpoint = peer.first("endpoint")
                if endpoint is None and peer.first("address"):
                    endpoint = f"{peer.first('address')}:{peer.first('port') or ''}"
                host, port = _endpoint(endpoint)
                allowed = []
                for text in peer.keys("allowed-ips"):
                    with contextlib.suppress(ValueError):
                        allowed.append(ip_network(text, strict=False))
                try:
                    peers.append(
                        TunnelPeer(
                            public_key=key,
                            name=peer.first("description") or (label if label != key else None),
                            endpoint_host=host,
                            endpoint_port=port if host else None,
                            allowed_ips=allowed,
                            keepalive_seconds=_int(peer.first("persistent-keepalive")),
                            enabled=not peer.has("disable"),
                        )
                    )
                except ValueError:
                    continue
            link = lay.links.get(name)
            mtu = _int(node.first("mtu"))
            addresses: list[IPInterface] = list(lay.all_addresses.get(name, []))
            public = keys.get(name)
            tunnels.append(
                Tunnel(
                    id=object_id(d, "tunnel", name),
                    device_id=d,
                    name=name,
                    description=node.first("description"),
                    port_id=port_id(d, name) if name in lay.ports else None,
                    up=link.up if link is not None else None,
                    enabled=not node.has("disable"),
                    listen_port=_int(node.first("listen-port") or node.first("port")),
                    public_key=public if public and _valid_key(public) else None,
                    addresses=addresses,
                    mtu=mtu if mtu is not None and 68 <= mtu <= 65535 else None,
                    peers=peers,
                )
            )
        return Observation(tunnels=tunnels)

    # firewall -------------------------------------------------------------------------------

    async def read_firewall(self) -> Observation:
        d = self.context.device_id
        root = self.root
        v = self.version
        lay = self._layout()
        gaps: list[Gap] = []
        vyos_14 = v.vyos and v.at_least(1, 4)
        rules = firewall.filter_rules(root, vyos_14)
        nat = firewall.nat(root)
        complete = rules.complete
        if vyos_14:
            gaps.append(
                Gap(
                    message=f"firewall: {v.text} names its rule-sets firewall ipv4 and firewall "
                    "ipv6 (VyOS 1.4 and newer); only the NAT and port forwards are read",
                    message_id="edgeos.firewallVyos14",
                    params={"version": v.text or "VyOS 1.4"},
                )
            )
        else:
            other = firewall.unsupported_firewall(root)
            if other:
                complete = False
                gaps.append(
                    Gap(
                        message=f"firewall: {', '.join(other)} is not read, so the rules of the "
                        "zone policy are missing",
                        message_id="edgeos.firewallUnsupported",
                        params={"what": ", ".join(other)},
                    )
                )
        for message, mid, params in rules.gaps:
            gaps.append(Gap(message=message, message_id=mid, params=params))
        if not nat.complete:
            gaps.append(
                Gap(
                    message="NAT: a rule without a usable translation address was left out",
                    optional=True,
                    message_id="edgeos.natSkipped",
                )
            )
        names = sorted(rules.zone_names | nat.zone_names)
        return Observation(
            firewalls=[
                Firewall(
                    id=firewall_id(d),
                    device_id=d,
                    enabled=rules.applied or not complete,
                    zones=[self._zone(lay, n) for n in names],
                    rules=rules.rules,
                    rules_complete=complete,
                    nat=nat.nat,
                    port_forwards=nat.forwards,
                    port_forwards_complete=nat.complete,
                    vendor_extra={"source": "show configuration commands"},
                )
            ],
            incomplete=gaps,
        )

    def _zone(self, lay: _Layout, name: str) -> FirewallZone:
        d = self.context.device_id
        if name in lay.networks:
            return FirewallZone(name=name, segments=[lay.networks[name][0]])
        if any(u.name == name for u in lay.uplinks):
            return FirewallZone(name=name, uplinks=[object_id(d, "uplink", name)])
        port = lay.ports.get(name)
        if port is not None and port.role is PortRole.TUNNEL:
            if name in self.root.keys("interfaces", "wireguard"):
                return FirewallZone(name=name, tunnels=[object_id(d, "tunnel", name)])
            return FirewallZone(name=name, ports=[port_id(d, name)])
        if port is not None:
            return FirewallZone(name=name, ports=[port_id(d, name)])
        return FirewallZone(name=name, complete=False)

    # health and time ----------------------------------------------------------------------

    async def read_health(self) -> Observation:
        a = self.answer
        total, used = linux_parse.memory(a)
        cpus = linux_parse._int(a.text("cpus"))
        health = DeviceHealth(
            uptime_seconds=linux_parse.uptime(a),
            load_average=linux_parse.load_average(a),
            cpu_count=cpus if cpus and cpus > 0 else None,
            memory_total_bytes=total,
            memory_used_bytes=used,
            storage=linux_parse.storage(a),
            temperatures=linux_parse.temperatures(a),
        )
        return Observation(health={self.context.device_id: health})

    async def read_time(self) -> Observation:
        answer = await self._run(collect.TIME)
        root = self.root
        clock: datetime | None = None
        with contextlib.suppress(ValueError, OverflowError, OSError):
            clock = datetime.fromtimestamp(float(answer.text("clock").strip()), UTC)
        servers = root.keys("system", "ntp", "server") or root.keys("service", "ntp", "server")
        zone = root.first("system", "time-zone")
        value = DeviceTime(
            clock=clock,
            timezone=zone,
            ntp_client=NtpClient(enabled=bool(servers), servers=servers),
        )
        return Observation(time={self.context.device_id: value})


def _int(text: str | None) -> int | None:
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return None


def _address(text: str | None) -> IPAddress | None:
    if text is None:
        return None
    with contextlib.suppress(ValueError):
        return ip_address(text)
    return None


def _valid_key(text: str) -> bool:
    return len(text) == 44 and text.endswith("=")


def _endpoint(text: str | None) -> tuple[str | None, int | None]:
    """``203.0.113.1:51820``, ``[2001:db8::1]:51820``, ``vpn.example:51820``."""
    if not text:
        return None, None
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        return host or None, _int(rest.lstrip(":"))
    host, sep, port = text.rpartition(":")
    if not sep or ":" in host:
        return text, None
    return host or None, _int(port)


def _pools(sub: tree.Node) -> list[DhcpPool]:
    """Address ranges: EdgeOS ``start A stop B``, VyOS ``range N start A`` / ``stop B``."""
    pairs: list[tuple[str, str | None]] = []
    for start, node in sub.items("start"):
        pairs.append((start, node.first("stop")))
    for _, rng in sub.items("range"):
        pairs.append((rng.first("start") or "", rng.first("stop")))
    out = []
    for start_text, stop_text in pairs:
        first, last = _address(start_text), _address(stop_text)
        if first is not None and last is not None and first.version == last.version:
            out.append(DhcpPool(start=first, end=last))
    return out


# --- the router's layout ---------------------------------------------------------------------


class _Layout:
    """Ports, networks (segments and subnets) and uplinks of one answer."""

    def __init__(self, device: str, site: str) -> None:
        self.device, self.site = device, site
        self.links: dict[str, parse.Link] = {}
        self.ports: dict[str, Port] = {}
        self.members: dict[str, dict[str, Membership]] = {}
        self.names: dict[str, str] = {}
        self.subnets: list[Subnet] = []
        self.uplinks: list[Uplink] = []
        self.networks: dict[str, tuple[str, list[IPInterface]]] = {}
        self.all_addresses: dict[str, list[IPInterface]] = {}

    def seg(self, vlan: int | None) -> str:
        return segment_id(self.site, vlan)

    def add_member(self, seg: str, name: str, mode: Membership) -> None:
        pid = port_id(self.device, name)
        current = self.members.setdefault(seg, {})
        if current.get(pid) is not Membership.UNTAGGED:
            current[pid] = mode

    def segments(self) -> list[Segment]:
        ids = set(self.members) | {seg for seg, _ in self.networks.values()}
        out = []
        for seg in sorted(ids):
            key = seg.rsplit("/", 1)[-1]
            out.append(
                Segment(
                    id=seg,
                    site_id=self.site,
                    vlan=int(key) if key.isdigit() else None,
                    name=self.names.get(seg),
                    members=[
                        PortMembership(port_id=p, mode=m)
                        for p, m in sorted(self.members.get(seg, {}).items())
                    ],
                )
            )
        return out

    def locate(self, net: Any) -> tuple[str, IPInterface] | None:
        for _name, (seg, addrs) in sorted(self.networks.items()):
            for addr in addrs:
                if isinstance(addr.ip, IPv4Address) and net.version == 4 and addr.ip in net:
                    return seg, addr
        return None

    @classmethod
    def build(cls, device: str, site: str, a: Answer, root: tree.Node, router: bool) -> _Layout:
        lay = cls(device, site)
        lay.links = {n: x for n, x in parse.links(a).items() if x.kind != "loopback"}
        sys = parse.sysnet(a)
        installed = parse.addresses(a)
        entries = _interfaces(root)
        # physical interfaces the configuration does not mention are still ports
        for name, known in sorted(lay.links.items()):
            if (
                name not in entries
                and known.kind == "ether"
                and sys.get(name, parse.SysNet()).device
            ):
                entries[name] = _Entry(name, "ethernet", None)
        members: dict[str, list[str]] = {}
        for name, e in entries.items():
            for group in e.groups:
                members.setdefault(group, []).append(name)
        for name, e in entries.items():
            link = lay.links.get(name)
            role, kind = e.role()
            info = sys.get(name)
            node = e.node
            disabled = node is not None and node.has("disable")
            lag = next(
                (g for g in e.groups if entries.get(g) and entries[g].type == "bonding"), None
            )
            lower = sorted(members.get(name, [])) if role in (PortRole.BRIDGE, PortRole.LAG) else []
            if role is PortRole.VLAN and e.parent in entries:
                lower = [e.parent]
            lay.ports[name] = Port(
                id=port_id(device, name),
                device_id=device,
                name=name,
                kind=kind,
                up=(link.up and not disabled) if link is not None else None,
                admin_up=(link.admin_up if link is not None else True) and not disabled,
                speed_mbps=info.speed if info and link is not None and link.up else None,
                full_duplex=(info.duplex == "full")
                if info and info.duplex and link is not None and link.up
                else None,
                mac=link.mac if link is not None and link.kind == "ether" else None,
                mtu=link.mtu if link is not None else _int(node.first("mtu") if node else None),
                description=node.first("description") if node is not None else None,
                role=role,
                lag=lag,
                lower=[port_id(device, x) for x in lower if x in entries],
                vendor_extra={"type": e.type} | ({"vlan": e.vlan} if e.vlan is not None else {}),
            )
            configured = [
                ipi
                for text in (node.keys("address") if node is not None else [])
                if (ipi := _interface(text)) is not None
            ]
            lay.all_addresses[name] = installed.get(name) or (configured if link is None else [])

        # uplinks: interfaces with a default route (a router only)
        wan: dict[str, list[parse.Route]] = {}
        if router:
            for r in parse.routes(a):
                if r.destination.prefixlen == 0 and r.dev in lay.ports and r.kind == "unicast":
                    if lay.ports[r.dev].role is PortRole.TUNNEL and r.dev in root.keys(
                        "interfaces", "wireguard"
                    ):
                        continue
                    wan.setdefault(r.dev, []).append(r)
        for name, found in wan.items():
            port = lay.ports[name]
            node = entries[name].node if name in entries else None
            if name.startswith("pppoe") or (name in entries and entries[name].type == "pppoe"):
                ukind = UplinkKind.PPPOE
            elif (node is not None and "dhcp" in node.keys("address")) or any(
                r.protocol == "dhcp" for r in found
            ):
                ukind = UplinkKind.DHCP
            else:
                ukind = UplinkKind.STATIC
            lay.uplinks.append(
                Uplink(
                    id=object_id(device, "uplink", name),
                    device_id=device,
                    port_id=port.id,
                    name=name,
                    kind=ukind,
                    up=port.up,
                    addresses=lay.all_addresses.get(name, []),
                    upstream_gateway=next(
                        (r.gateway for r in found if r.gateway is not None), None
                    ),
                    vendor_extra={"protocol": [r.protocol for r in found if r.protocol]},
                )
            )
        wan_names = set(wan)
        lay._networks(entries, members, wan_names, router)
        if not lay.networks and wan_names:
            lay._networks(entries, members, set(), router)
        return lay

    def _networks(
        self,
        entries: dict[str, _Entry],
        members: dict[str, list[str]],
        wan: set[str],
        router: bool,
    ) -> None:
        for name, e in sorted(entries.items()):
            role = self.ports[name].role
            if name in wan or role is PortRole.TUNNEL:
                continue
            addresses = [x for x in self.all_addresses.get(name, []) if not x.ip.is_link_local]
            if role is PortRole.VLAN:
                seg = self.seg(e.vlan)
                if addresses:
                    parent = entries.get(e.parent or "")
                    if parent is not None and parent.type in ("bridge", "switch"):
                        for member in sorted(members.get(parent.name, [])):
                            self.add_member(seg, member, Membership.TAGGED)
                    elif e.parent:
                        self.add_member(seg, e.parent, Membership.TAGGED)
            else:
                seg = self.seg(None)
                if not addresses:
                    continue
                if role is PortRole.BRIDGE:
                    for member in sorted(members.get(name, [])):
                        self.add_member(seg, member, Membership.UNTAGGED)
                elif not e.groups:
                    self.add_member(seg, name, Membership.UNTAGGED)
            if not addresses:
                continue
            self.names.setdefault(seg, name)
            self.networks[name] = (seg, addresses)
            for n, addr in enumerate(addresses):
                self.subnets.append(
                    Subnet(
                        id=object_id(self.device, "subnet", f"{name}-{n}"),
                        segment_id=seg,
                        interface=addr,
                        device_id=self.device,
                        gateway=router,
                    )
                )


class _Entry:
    """One interface of the configuration."""

    def __init__(
        self,
        name: str,
        type_: str,
        node: tree.Node | None,
        parent: str | None = None,
        vlan: int | None = None,
    ) -> None:
        self.name, self.type, self.node = name, type_, node
        self.parent, self.vlan = parent, vlan
        self.groups: list[str] = []

    def role(self) -> tuple[PortRole, PortKind]:
        if self.vlan is not None:
            return PortRole.VLAN, PortKind.VIRTUAL
        if self.type in ("bridge", "switch"):
            return PortRole.BRIDGE, PortKind.BRIDGE
        if self.type == "bonding":
            return PortRole.LAG, PortKind.LAG
        if self.type == "ethernet":
            return PortRole.JACK, PortKind.ETHERNET
        if self.type in _TUNNELS:
            return PortRole.TUNNEL, PortKind.VIRTUAL
        return PortRole.VIRTUAL, PortKind.VIRTUAL


def _interfaces(root: tree.Node) -> dict[str, _Entry]:
    """The interfaces of ``interfaces``: ports, their ``vif`` VLANs, ``pppoe`` sessions and the
    bridge, bond and switch groups their members belong to."""
    out: dict[str, _Entry] = {}
    for kind, kind_node in root.items("interfaces"):
        if kind in _SKIPPED:
            continue
        for name, node in kind_node.items():
            entry = _Entry(name, kind, node)
            out[name] = entry
            # EdgeOS: bridge-group bridge br0 / bond-group bond0 on the member
            for word in ("bridge-group", "bond-group"):
                group = node.first(word, "bridge") if word == "bridge-group" else node.first(word)
                if group:
                    entry.groups.append(group)
            for vid, vif in node.items("vif"):
                if vid.isdigit():
                    vname = f"{name}.{vid}"
                    out[vname] = _Entry(vname, "vif", vif, parent=name, vlan=int(vid))
            for number, _ in node.items("pppoe"):
                out[f"pppoe{number}"] = _Entry(f"pppoe{number}", "pppoe", node.get("pppoe", number))
    # members named by the group (VyOS: member interface; EdgeOS switch: switch-port interface)
    for name, entry in list(out.items()):
        if entry.node is None:
            continue
        node = entry.node
        for member in node.keys("member", "interface") + node.keys("switch-port", "interface"):
            if member in out and name not in out[member].groups:
                out[member].groups.append(name)
    return out


def _interface(text: str) -> IPInterface | None:
    with contextlib.suppress(ValueError):
        from ipaddress import ip_interface

        return ip_interface(text)
    return None
