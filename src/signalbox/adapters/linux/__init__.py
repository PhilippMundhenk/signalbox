"""Generic Linux gateway (Debian, Raspberry Pi OS, Arch Linux ARM, ...) over SSH, read-only (#240).

Signalbox logs in over SSH with a user of its own (a key, or a password) and a pinned host key,
sends one read script per observation (:mod:`signalbox.adapters.linux.collect`) and maps the
answer: ``ip -j`` links, addresses and routes to ports (with their roles, ADR 0008), segments,
subnets and the uplink (default route); sshd's configuration to the SSH service; dnsmasq, Kea,
ISC dhcpd and systemd-networkd configuration and lease files to DHCP servers; dnsmasq, AdGuard
Home, Pi-hole and Unbound to DNS services; ``/proc`` and ``df`` to health; ``timedatectl`` and
chrony to time; ``wg show all <field>`` and ``nft -j list ruleset`` (root, or the sudoers rule
of the setup guide) to the WireGuard tunnels and the firewall (#135). Nothing needs root except
``wg`` and ``nft``; nothing that prints a private key is run.
"""

from __future__ import annotations

import contextlib
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any

import asyncssh
from pydantic import Field, SecretStr, field_validator, model_validator

from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterError,
    AdminLogin,
    Capability,
    Gap,
    Manifest,
    Observation,
    PreviewStep,
    RemedyRequest,
    SetupExtra,
    SetupPlan,
    SetupRequest,
    SetupResult,
    SystemInfo,
    TraceAnswer,
    TraceSupport,
    UntrustedCertificate,
    UntrustedHostKey,
    bonding,
    dnsmap,
    known_interfaces,
)
from signalbox.adapters.linux import (
    clock,
    collect,
    ddns,
    dhcp,
    distro,
    ipv6,
    nftables,
    parse,
    provision,
    setup,
    syslog,
    updates,
    wireguard,
)
from signalbox.adapters.linux import (
    iptables as iptables_reader,
)
from signalbox.adapters.linux import (
    routes as route_reader,
)
from signalbox.adapters.linux import trace as _trace
from signalbox.adapters.linux.collect import Answer
from signalbox.adapters.ssh import PinnedSsh, load_private_key
from signalbox.discovery import Candidate, HostProbe
from signalbox.model import (
    DeviceHealth,
    DeviceRole,
    Dhcp6Mode,
    Dhcp6Server,
    DhcpLease,
    DhcpPool,
    DhcpServer,
    DnsForwarder,
    DnsService,
    DnsTransport,
    FdbEntry,
    FdbKind,
    Firewall,
    FirewallZone,
    Firmware,
    IPAddress,
    IPInterface,
    LogTarget,
    ManagementService,
    Membership,
    Port,
    PortMembership,
    PortRole,
    RaPrefix,
    RouterAdvert,
    Segment,
    ServiceKind,
    Subnet,
    Tunnel,
    TunnelPeer,
    Uplink,
    UplinkKind,
    fdb_id,
    firewall_id,
    object_id,
    port_id,
    segment_id,
)

__all__ = ["LinuxAdapter", "LinuxConfig"]

AUTH_FIX = (
    "Check the user name and the private key (or password) in the settings, and that the "
    "user's public key is in ~/.ssh/authorized_keys on the device (see the setup guide)."
)
#: Tunnel kinds that are never an uplink, even with a default route (a full tunnel).
NOT_UPLINK = parse.TUNNEL_KINDS - {"ppp"}


class LinuxConfig(AdapterConfig):
    host: str = Field(
        description="The device's address or name, for example 192.0.2.1 or raspberrypi.lan",
        examples=["192.0.2.1"],
    )
    port: int = Field(22, ge=1, le=65535, description="SSH port")
    username: str = Field(
        "signalbox",
        description="A user of its own for Signalbox, without sudo (see the setup guide)",
    )
    private_key: SecretStr | None = Field(
        None,
        description="The user's private key (OpenSSH format, without passphrase); recommended",
    )
    password: SecretStr | None = Field(None, description="Or the user's password")

    @field_validator("host")
    @classmethod
    def _host(cls, value: str) -> str:
        text = value.strip()
        for prefix in ("ssh://", "https://", "http://"):
            text = text.removeprefix(prefix)
        text = text.split("/", 1)[0].strip()
        if not text or " " in text:
            raise ValueError("give the device's address or host name")
        return text

    @model_validator(mode="after")
    def _login(self) -> LinuxConfig:
        if self.private_key is None and self.password is None:
            raise ValueError("give a private key or a password")
        return self


class UntrustedSshHostKey(UntrustedCertificate):
    """The host key is not the pinned one: hex SHA-256 for the trust flow, plus the form
    ``ssh-keygen -l`` prints to compare."""

    def __init__(self, fingerprint: str, pinned: str | None, openssh: str | None) -> None:
        super().__init__(fingerprint, pinned)
        what = "a different SSH host key" if pinned else "an SSH host key not yet trusted"
        shown = f"; ssh-keygen -lf shows it as {openssh}" if openssh else ""
        self.args = (f"device presented {what} (SHA-256 {fingerprint}{shown})",)


LINUX_STEPS = (
    "Create a user signalbox without sudo and give it a login key (commands below). Or let "
    "Signalbox do it: Set up automatically, with root or a sudo user.",
    "Only with WireGuard, nftables, iptables, ddclient or inadyn: add the sudoers rule of the "
    "commands; it allows exactly the read-only commands listed in it.",
    "Below: the address, user signalbox and the private key. Then Test connection and trust "
    "the SSH host key (compare it with ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub).",
)


class LinuxAdapter(Adapter):
    manifest = Manifest(
        id="linux",
        name="Linux (Debian, Raspberry Pi OS, Arch Linux ARM)",
        version="0.1.0",
        api_version="1.4",
        vendor="Linux",
        roles=frozenset({DeviceRole.GATEWAY, DeviceRole.OTHER}),
        capabilities=frozenset(
            {
                Capability.INTERFACES,
                Capability.DHCP,
                Capability.DNS,
                Capability.HEALTH,
                Capability.TIME,
                Capability.VPN,
                Capability.FIREWALL,
            }
        ),
        config=LinuxConfig,
        description=(
            "Reads a Linux gateway (Debian, Raspberry Pi OS, Ubuntu, Arch Linux ARM; Fedora and "
            "Alpine less tested) over SSH with a user "
            "of its own: ip, /proc, sshd, dnsmasq/Kea/ISC/networkd DHCP, chrony/timesyncd, "
            "WireGuard, nftables, iptables and DDNS configuration files through a sudoers rule "
            "of read-only commands."
        ),
        setup_steps=LINUX_STEPS,
        setup_commands=setup.commands(),
        setup_url="https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/linux.md#manual-setup",
        admin_login=AdminLogin(
            transport="SSH as root or a user with sudo",
            user_default="root",
            secret_label="Password",
            port_default=22,
            note="A login that may use sudo (Raspberry Pi OS: the first user) or root, with "
            "a password over SSH. Signalbox creates the user signalbox with a key of its own, "
            "and the sudoers rule of read-only commands if wg, nft, iptables-save, ddclient or "
            "inadyn is installed.",
            preview=[
                PreviewStep(
                    id="user",
                    title="Create the user signalbox (no password, no sudo)",
                    title_id="setup.linux.previewUser",
                ),
                PreviewStep(
                    id="key",
                    title="Authorize a new SSH key for it (public key only)",
                    title_id="setup.linux.previewKey",
                ),
                PreviewStep(
                    id="sudoers",
                    title=(
                        "Allow it the read-only commands of the sudoers rule (listed in the plan)"
                    ),
                    title_id="setup.linux.previewSudoers",
                ),
                PreviewStep(
                    id="install-nftables",
                    title="Install nftables with the device's package manager",
                    extra="nftables",
                    title_id="setup.linux.previewInstall",
                ),
                PreviewStep(
                    id="install-iproute2",
                    title="Install iproute2 (ip -j, bridge) with the device's package manager",
                    extra="iproute2",
                    title_id="setup.linux.previewInstallIproute2",
                ),
                PreviewStep(
                    id="install-wireguard",
                    title="Install wireguard-tools with the device's package manager",
                    extra="wireguard",
                    title_id="setup.linux.previewInstallWireguard",
                ),
                PreviewStep(
                    id="install-tracepath",
                    title="Install tracepath with the device's package manager",
                    extra="tracepath",
                    title_id="setup.linux.previewInstallTracepath",
                ),
                PreviewStep(
                    id="host-key",
                    title="Trust the SSH host key you confirmed, for reading",
                    title_id="setup.linux.previewHostKey",
                ),
                PreviewStep(
                    id="sudoers",
                    title="Delete the sudoers rule",
                    remove=True,
                    title_id="setup.linux.previewDeleteSudoers",
                ),
                PreviewStep(
                    id="user",
                    title="Delete the user signalbox",
                    remove=True,
                    title_id="setup.linux.previewDeleteUser",
                ),
            ],
            extras=[
                SetupExtra(
                    id=tool,
                    label=f"Also install {what} (optional)",
                    note="Installed with the device's package manager (apt, pacman, dnf or "
                    "apk, shown in the plan). Only what is missing; nothing is removed again.",
                )
                for tool, (what, _) in distro.TOOLS.items()
            ],
        ),
        remedies=provision.REMEDIES,
        traces=TraceSupport(
            permission="none: tracepath (or traceroute) as the read user, no root",
            method="tracepath -n over SSH (iputils-tracepath)",
        ),
    )

    _ssh: PinnedSsh | None = None
    _answer: Answer | None = None

    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        """The SSH banner of a Debian-based system (no login)."""
        from signalbox.adapters.linux.discovery import discover

        return await discover(probe)

    @classmethod
    async def plan_setup(cls, request: SetupRequest) -> SetupPlan:
        from signalbox.adapters.linux.provision import LinuxSetup

        return await LinuxSetup(request).plan()

    @classmethod
    async def apply_setup(cls, request: SetupRequest) -> SetupResult:
        from signalbox.adapters.linux.provision import LinuxSetup

        return await LinuxSetup(request).apply()

    @classmethod
    async def plan_remedy(cls, request: RemedyRequest) -> SetupPlan:
        """*Fix it*: install nftables and add the read-only sudoers rule (#302)."""
        return await provision.LinuxFix(request).plan()

    @classmethod
    async def apply_remedy(cls, request: RemedyRequest) -> SetupResult:
        return await provision.LinuxFix(request).apply()

    @property
    def config(self) -> LinuxConfig:
        assert isinstance(self.context.config, LinuxConfig)
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
                    message_id="linux.privateKey",
                    fix_id="linux.auth.fix",
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
            auth_fix_id="linux.auth.fix",
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
        answer = collect.split(res.text)
        if not answer.complete():
            tail = (res.err or res.text).strip()[-300:]
            raise AdapterError(
                f"the device did not answer the read commands completely: {tail}",
                fix="Signalbox reads Debian-based systems with a POSIX sh, iproute2 and "
                "coreutils. Check that the user's login shell is /bin/sh or bash.",
                message_id="linux.incompleteAnswer",
                fix_id="linux.incompleteAnswer.fix",
                params={"tail": tail},
            )
        return answer

    @property
    def answer(self) -> Answer:
        assert self._answer is not None, "read_system first"
        return self._answer

    async def trace(self, target: Any, max_hops: int, wait: float) -> TraceAnswer:
        """``tracepath -n`` (else ``traceroute -n``) as the read user (#253)."""
        if self._ssh is None:
            self._ssh = await self._connect()
        res = await self._ssh.run(
            _trace.script(target, max_hops, wait), timeout=self.context.timeout
        )
        return _trace.parse(res.text, target, max_hops)

    # system -----------------------------------------------------------------------------

    async def read_system(self) -> SystemInfo:
        await self.close()  # a new observation: check the host key again
        self._answer = await self._run(collect.READ)
        a = self._answer
        release = parse.os_release(a)
        vendor, model = parse.hardware(a)
        pretty = release.get("PRETTY_NAME") or release.get("NAME")
        extra: dict[str, Any] = {}
        if a.text("kernel").strip():
            extra["kernel"] = a.text("kernel").strip()
        if release.get("ID"):
            extra["os_id"] = release["ID"]
        found = distro.detect(release, parse.release_markers(a))
        if found.manager:
            extra["os_family"] = found.family
            extra["package_manager"] = found.manager
        state = updates.read(a, found.manager)
        forwarding = parse.forwarding(a)
        if forwarding is not None:
            extra["ip_forwarding"] = forwarding
        return SystemInfo(
            vendor=vendor,
            model=model,
            firmware=Firmware(current=pretty, **state) if pretty or state else None,
            management_address=self.config.host,
            transport_encrypted=True,
            vendor_extra=extra,
            **parse.identity(a, release),
        )

    # interfaces -------------------------------------------------------------------------

    def _layout(self) -> _Layout:
        return _Layout.build(self.context.device_id, self.context.site_id, self.answer, self.router)

    @property
    def router(self) -> bool:
        return self.context.role is DeviceRole.GATEWAY

    @property
    def distro(self) -> distro.Distro:
        return distro.detect(parse.os_release(self.answer), parse.release_markers(self.answer))

    async def read_interfaces(self) -> Observation:
        lay = self._layout()
        gaps: list[Gap] = []
        if not lay.links and not isinstance(parse._json(self.answer.text("link")), list):
            gaps.append(
                Gap(
                    message="interfaces: ip -j printed no JSON (iproute2 is too old, or busybox "
                    "ip is used), so no port, segment or subnet was read",
                    fix=f"Install iproute2 ({self.distro.hint('iproute2')}).",
                    message_id="linux.noIpJson",
                    fix_id="linux.noIpJson.fix",
                    params={"hint": self.distro.hint("iproute2")},
                )
            )
        bridges, port_stp = parse.stp(lay.links, {n: p.id for n, p in lay.ports.items()})
        ports = [
            p.model_copy(update={"stp": port_stp[n]}) if n in port_stp else p
            for n, p in lay.ports.items()
        ]
        ddns_clients, ddns_gaps = ddns.read(self.context.device_id, self.answer, lay.uplinks)
        gaps += ddns_gaps
        return Observation(
            incomplete=gaps,
            ports=ports,
            ddns=ddns_clients,
            stp_bridges={self.context.device_id: bridges} if lay.links else {},
            segments=lay.segments(),
            subnets=lay.subnets,
            uplinks=lay.uplinks,
            services=self._services(lay),
            fdb=self._fdb(lay),
            routes=known_interfaces(
                route_reader.read_routes(
                    self.context.device_id,
                    self.answer,
                    frozenset(n for n, p in lay.ports.items() if p.role is PortRole.TUNNEL),
                ),
                [p.id for p in lay.ports.values()],
            ),
            routing_rules=route_reader.read_rules(
                self.context.device_id,
                self.answer,
                lambda n: lay.networks[n][0] if n in lay.networks else None,
            ),
            log_targets=self._log_targets(gaps),
        )

    def _log_targets(self, gaps: list[Gap]) -> dict[str, list[LogTarget]]:
        """rsyslog and syslog-ng forward targets (#180): none read from an older script, an
        optional gap for a configuration file the user may not read."""
        a = self.answer
        if not a.has("syslog"):
            return {}
        unreadable = a.unreadable("syslog")
        if unreadable:
            gaps.append(
                Gap(
                    message=f"log targets: {', '.join(unreadable)} not readable for "
                    f"{self.config.username}",
                    fix="Give the user read access to these files, or accept that the remote "
                    "syslog targets are not read.",
                    optional=True,
                    message_id="linux.logUnreadable",
                    fix_id="linux.logUnreadable.fix",
                    params={"files": ", ".join(unreadable), "user": self.config.username},
                )
            )
            return {}
        return {self.context.device_id: syslog.targets(a.files("syslog"))}

    def _fdb(self, lay: _Layout) -> list[FdbEntry]:
        """The bridges' MAC address tables (``bridge -j -s fdb show``, as the read user, #160)."""
        d = self.context.device_id
        segments = {s.id for s in lay.segments()}
        out: dict[str, FdbEntry] = {}
        for row in parse.bridge_fdb(self.answer):
            if row.port not in lay.ports:
                continue
            seg = lay.seg(row.vlan) if row.vlan is not None else None
            fid = fdb_id(d, row.port, row.mac, row.vlan)
            out[fid] = FdbEntry(
                id=fid,
                device_id=d,
                port_id=lay.ports[row.port].id,
                mac=row.mac,
                vlan=row.vlan,
                segment_id=seg if seg in segments else None,
                kind={"permanent": FdbKind.SELF, "static": FdbKind.STATIC}.get(
                    row.state, FdbKind.DYNAMIC
                ),
                age_seconds=row.age,
            )
        return [out[k] for k in sorted(out)]

    # WireGuard ----------------------------------------------------------------------------

    async def read_vpn(self) -> Observation:
        """Every WireGuard interface of ``ip -d link`` with what ``wg show all <field>`` says;
        without the permission for ``wg`` the interfaces without keys and peers, and a gap."""
        d = self.context.device_id
        links = {n: x for n, x in parse.links(self.answer).items() if x.kind == "wireguard"}
        wg, denied = wireguard.read(self.answer)
        gaps: list[Gap] = []
        if denied and links:
            gaps.append(
                Gap(
                    message="WireGuard: wg show is not allowed for this user, so the public "
                    "keys and peers are not read",
                    fix="Add the sudoers rule of the setup guide "
                    f"({setup.sudoers_path(self.config.username)}), or run Set up "
                    "automatically again.",
                    message_id="linux.wgDenied",
                    fix_id="linux.sudoers.fix",
                    params={"path": setup.sudoers_path(self.config.username)},
                )
            )
        tunnels: list[Tunnel] = []
        for name in sorted(set(links) | set(wg)):
            link = links.get(name)
            iface = wg.get(name, wireguard.WgInterface(name))
            mtu = link.raw.get("mtu") if link is not None else None
            tunnels.append(
                Tunnel(
                    id=object_id(d, "tunnel", name),
                    device_id=d,
                    name=name,
                    port_id=port_id(d, name) if link is not None else None,
                    up=link.up if link is not None else None,
                    listen_port=iface.listen_port,
                    public_key=iface.public_key,
                    addresses=parse.global_addresses(link) if link is not None else [],
                    mtu=mtu if isinstance(mtu, int) and 68 <= mtu <= 65535 else None,
                    peers=[
                        TunnelPeer(
                            public_key=p.public_key,
                            endpoint_host=p.endpoint_host,
                            endpoint_port=p.endpoint_port if p.endpoint_host else None,
                            allowed_ips=p.allowed_ips,
                            latest_handshake=p.latest_handshake,
                            rx_bytes=p.rx_bytes,
                            tx_bytes=p.tx_bytes,
                            keepalive_seconds=p.keepalive_seconds,
                        )
                        for p in iface.peers.values()
                        if p.public_key != iface.public_key
                    ],
                )
            )
        return Observation(tunnels=tunnels, incomplete=gaps)

    # firewall ----------------------------------------------------------------------------

    async def read_firewall(self) -> Observation:
        """``nft -j list ruleset`` (iptables-nft shows up there too), else the legacy iptables
        rules (``iptables-save``, #394). Without the permission nothing is reported (not read)
        and a gap says what to add. Source: ``vendor_extra["source"]`` of the firewall."""
        a = self.answer
        d = self.context.device_id
        lay = self._layout()
        fix = (
            "Add the sudoers rule of the setup guide "
            f"({setup.sudoers_path(self.config.username)}), or run Set up automatically again."
        )
        tool = a.text("nft-tool").strip()
        iptables = a.text("iptables").strip()
        legacy, legacy_gaps = self._legacy_iptables(fix)
        if tool in ("", "none"):
            if legacy is not None:
                return self._firewall(lay, legacy, "iptables-save", legacy_gaps)
            if legacy_gaps:
                return Observation(incomplete=legacy_gaps)
            if not iptables:
                return Observation(
                    firewalls=[Firewall(id=firewall_id(d), device_id=d, enabled=False)]
                )
            kind = "legacy" if "legacy" in iptables else "iptables"
            return Observation(
                firewalls=[
                    Firewall(
                        id=firewall_id(d),
                        device_id=d,
                        rules_complete=False,
                        port_forwards_complete=False,
                    )
                ],
                incomplete=[
                    Gap(
                        message=f"firewall: only {kind} iptables is installed, there is no nft "
                        "command to read its rules",
                        fix="Install nftables (the iptables-nft backend shows its rules "
                        f"there; {self.distro.hint('nftables')}), or use Fix it.",
                        remedy="nftables",
                        message_id="linux.onlyIptables",
                        fix_id="linux.onlyIptables.fix",
                        params={"kind": kind, "hint": self.distro.hint("nftables")},
                    )
                ],
            )
        if a.has("nft-denied"):
            return Observation(
                incomplete=[
                    Gap(
                        message="firewall: nft list ruleset is not allowed for this user",
                        fix=fix,
                        message_id="linux.nftDenied",
                        fix_id="linux.sudoers.fix",
                        params={"path": setup.sudoers_path(self.config.username)},
                    )
                ]
            )
        try:
            parsed = nftables.parse(a.text("nft"))
        except ValueError as exc:
            return Observation(
                incomplete=[
                    Gap(
                        message=f"firewall: {exc}",
                        message_id="linux.firewallError",
                        params={"cause": str(exc)},
                    )
                ]
            )
        if (
            not iptables_reader.has_rules(parsed)
            and legacy is not None
            and iptables_reader.has_rules(legacy)
        ):  # nft is empty: the rules are the legacy ones
            return self._firewall(lay, legacy, "iptables-save", legacy_gaps)
        extra: list[Gap] = []
        complete = parsed.complete
        if "legacy" in iptables and (legacy is None or iptables_reader.has_rules(legacy)):
            complete = False
            extra += legacy_gaps
            switch = (
                "pacman -S iptables-nft"
                if self.distro.manager == "pacman"
                else "update-alternatives --set iptables /usr/sbin/iptables-nft"
            )
            extra.append(
                Gap(
                    message="firewall: iptables-legacy is in use; its rules are not visible to "
                    "nft and are not read",
                    fix=f"Switch to the nf_tables backend ({switch}).",
                    message_id="linux.iptablesLegacy",
                    fix_id="linux.iptablesLegacy.fix",
                    params={"command": switch},
                )
            )
        return self._firewall(lay, parsed, "nft", extra, complete)

    def _legacy_iptables(self, fix: str) -> tuple[nftables.Parsed | None, list[Gap]]:
        """The rules of ``iptables-save`` / ``ip6tables-save`` (``None``: not available or not
        readable, then a gap says what to add), mapped like the nft ruleset (#394)."""
        a = self.answer
        if a.text("ipt4-tool").strip() in ("", "none"):
            return None, []
        denied = Gap(
            message="firewall: iptables-save is not allowed for this user",
            fix=fix,
            message_id="linux.iptablesDenied",
            fix_id="linux.sudoers.fix",
            params={"path": setup.sudoers_path(self.config.username)},
        )
        if a.has("ipt4-denied"):
            return None, [denied]
        gaps: list[Gap] = []
        if a.has("ipt6-denied"):  # IPv6 rules exist but cannot be read: the result is partial
            gaps.append(
                denied.model_copy(
                    update={
                        "message": "firewall: ip6tables-save is not allowed for this user, "
                        "the IPv6 rules are not read",
                        "message_id": "linux.ip6tablesDenied",
                    }
                )
            )
        parsed = iptables_reader.parse(a.text("ipt4-save"), a.text("ipt6-save"))
        if gaps:
            parsed.complete = False
        return parsed, gaps

    def _firewall(
        self,
        lay: _Layout,
        parsed: nftables.Parsed,
        source: str,
        extra: list[Gap],
        complete: bool | None = None,
    ) -> Observation:
        d = self.context.device_id
        done = parsed.complete if complete is None else complete
        gaps = [Gap(message=m, message_id=m.message_id, params=m.params) for m in parsed.gaps]
        zones = [self._zone(lay, name) for name in sorted(parsed.zone_names)]
        return Observation(
            firewalls=[
                Firewall(
                    id=firewall_id(d),
                    device_id=d,
                    enabled=parsed.enabled or not done,
                    zones=zones,
                    input_policy=parsed.input_policy,
                    forward_policy=parsed.forward_policy,
                    rules=parsed.rules,
                    rules_complete=done,
                    nat=parsed.nat,
                    port_forwards=parsed.port_forwards,
                    port_forwards_complete=parsed.port_forwards_complete and done,
                    vendor_extra={"source": source},
                )
            ],
            incomplete=[*gaps, *extra],
        )

    def _zone(self, lay: _Layout, name: str) -> FirewallZone:
        """The zone of one interface: a segment, the uplink, the tunnel or a bare port."""
        d = self.context.device_id
        if name in lay.networks:
            return FirewallZone(name=name, segments=[lay.networks[name][0]])
        if any(u.name == name for u in lay.uplinks):
            return FirewallZone(name=name, uplinks=[object_id(d, "uplink", name)])
        link = lay.links.get(name)
        if link is not None and link.kind == "wireguard":
            return FirewallZone(name=name, tunnels=[object_id(d, "tunnel", name)])
        if name in lay.ports:
            return FirewallZone(name=name, ports=[port_id(d, name)])
        # the loopback maps to nothing by design; a wildcard or a vanished interface does not
        return FirewallZone(name=name, complete=name == "lo")

    def _services(self, lay: _Layout) -> list[ManagementService]:
        a = self.answer
        d = self.context.device_id
        settings = parse.sshd_settings(a)
        active = parse.services_running(a)
        listening = {(x.proto, x.port) for x in parse.listeners(a)}
        if not settings and "ssh" not in active and ("tcp", self.config.port) not in listening:
            return []
        ports = [int(p) for p in settings.get("port", []) if p.isdigit()] or [22]
        listen: list[IPAddress] = []
        for text in settings.get("listenaddress", []):
            host = text.rsplit(":", 1)[0] if text.count(":") == 1 or text.startswith("[") else text
            with contextlib.suppress(ValueError):
                listen.append(ip_address(host.strip("[]")))
        password = (settings.get("passwordauthentication") or ["yes"])[0].lower() == "yes"
        root = (settings.get("permitrootlogin") or ["prohibit-password"])[0].lower()
        out: list[ManagementService] = []
        for n, number in enumerate(dict.fromkeys(ports)):
            enabled = "ssh" in active or ("tcp", number) in listening
            out.append(
                ManagementService(
                    id=object_id(d, "service", "ssh" if n == 0 else f"ssh-{number}"),
                    device_id=d,
                    kind=ServiceKind.SSH,
                    name="sshd",
                    enabled=enabled,
                    port=number,
                    listen=listen,
                    password_login=password,
                    root_login=root != "no",
                    root_password_login=root == "yes" and password,
                )
            )
        return out

    # DHCP and DNS -------------------------------------------------------------------------

    async def read_dhcp(self) -> Observation:
        a = self.answer
        lay = self._layout()
        active = parse.services_running(a)
        gaps: list[Gap] = []
        servers: list[DhcpServer] = []

        def unreadable(section: str, what: str) -> None:
            for path in a.unreadable(section):
                gaps.append(
                    Gap(
                        message=f"{what}: {path} is not readable for {self.config.username}",
                        fix=f"Give the user read access to {path} (for example by adding it to "
                        "the group that owns the file), or accept that it is not read.",
                        message_id="linux.unreadable",
                        fix_id="linux.unreadable.fix",
                        params={"what": what, "path": path, "user": self.config.username},
                    )
                )

        for section, what in (
            ("dnsmasq", "dnsmasq"),
            ("dnsmasq-leases", "dnsmasq leases"),
            ("kea", "Kea"),
            ("kea-leases", "Kea leases"),
            ("isc", "ISC dhcpd"),
            ("isc-leases", "ISC dhcpd leases"),
        ):
            unreadable(section, what)

        pihole = "pihole-FTL" in active
        masq = dhcp.parse_dnsmasq(a.files("dnsmasq"))
        if masq.configured and not (pihole and "dnsmasq" not in active):
            lease_text = a.files("dnsmasq-leases").get("/var/lib/misc/dnsmasq.leases")
            leases = dhcp.dnsmasq_leases(lease_text) if lease_text is not None else None
            if leases is None and "dnsmasq" in active and not a.unreadable("dnsmasq-leases"):
                leases = []
            servers += self._servers(lay, masq.scopes, "dnsmasq" in active, leases, gaps, True)
        kea_text = a.files("kea").get("/etc/kea/kea-dhcp4.conf")
        if kea_text is not None:
            kea = dhcp.parse_kea(kea_text)
            if kea.error:
                gaps.append(
                    Gap(
                        message=f"Kea: {kea.error}",
                        message_id="linux.keaError",
                        params={"cause": kea.error},
                    )
                )
            rows = a.files("kea-leases").get("/var/lib/kea/kea-leases4.csv")
            by_id = dhcp.kea_leases(rows) if rows is not None else None
            for scope in kea.scopes:
                if scope.interface is None and len(kea.interfaces) == 1:
                    scope.interface = kea.interfaces[0]
                lease = (
                    [x for sid, x in by_id if sid is None or sid == scope.kea_id]
                    if by_id is not None
                    else None
                )
                servers += self._servers(
                    lay, [scope], "kea-dhcp4-server" in active, lease, gaps, False
                )
        isc_text = a.files("isc").get("/etc/dhcp/dhcpd.conf")
        if isc_text is not None:
            rows_text = a.files("isc-leases").get("/var/lib/dhcp/dhcpd.leases")
            isc_lease = dhcp.isc_leases(rows_text) if rows_text is not None else None
            servers += self._servers(
                lay, dhcp.parse_isc(isc_text), "isc-dhcp-server" in active, isc_lease, gaps, False
            )
        networkd = dhcp.parse_networkd(a.files("networkd"), sorted(lay.links))
        servers += self._servers(
            lay,
            networkd,
            "systemd-networkd" in active or not a.lines("units"),
            None,
            gaps,
            False,
        )
        adverts, servers6 = self._ipv6(lay, active, masq_files=a.files("dnsmasq"))
        return Observation(
            dhcp_servers=servers, router_adverts=adverts, dhcp6_servers=servers6, incomplete=gaps
        )

    def _ipv6(
        self, lay: _Layout, active: set[str], masq_files: dict[str, str]
    ) -> tuple[list[RouterAdvert], list[Dhcp6Server]]:
        """Router advertisements and DHCPv6 from ``/etc/radvd.conf`` and dnsmasq (#151);
        see :mod:`~signalbox.adapters.linux.ipv6`."""
        d = self.context.device_id
        adverts: list[RouterAdvert] = []
        servers: list[Dhcp6Server] = []

        def place(block: ipv6.RaInterface) -> str | None:
            if block.name is not None:
                return lay.networks[block.name][0] if block.name in lay.networks else None
            for _, (seg, addrs) in sorted(lay.networks.items()):
                if block.network is not None and any(
                    isinstance(x.ip, IPv6Address) and x.ip in block.network for x in addrs
                ):
                    return seg
            return None

        text = self.answer.files("radvd").get("/etc/radvd.conf")
        blocks = [(b, "radvd" in active) for b in ipv6.parse_radvd(text)] if text else []
        if masq_files and "dnsmasq" in active:
            blocks += [(b, True) for b in ipv6.parse_dnsmasq6(masq_files)]
        for block, running in blocks:
            seg = place(block)
            if seg is None:
                continue
            key = seg.rsplit("/", 1)[-1]
            key = "lan" if key == "native" else key
            if running and not any(x.id.endswith(f"/ra/{key}") for x in adverts):
                adverts.append(
                    RouterAdvert(
                        id=object_id(d, "ra", key),
                        device_id=d,
                        segment_id=seg,
                        mode=ipv6.mode_of(block),
                        managed=block.managed if block.send else None,
                        other=block.other if block.send else None,
                        prefixes=[
                            RaPrefix(prefix=p, on_link=on_link, autonomous=auto)
                            for p, on_link, auto in block.prefixes
                        ],
                        rdnss=block.rdnss,
                        dnssl=block.dnssl,
                        router_lifetime=block.lifetime,
                    )
                )
            if block.dhcpv6:
                servers.append(
                    Dhcp6Server(
                        id=object_id(d, "dhcp6", f"dnsmasq-{key}"),
                        device_id=d,
                        segment_id=seg,
                        enabled=running,
                        mode=Dhcp6Mode.STATEFUL if block.dhcpv6_stateful else Dhcp6Mode.STATELESS,
                        pools=[DhcpPool(start=block.pool[0], end=block.pool[1])]
                        if block.pool
                        else [],
                        lease_seconds=block.lease_seconds,
                        dns_servers=block.rdnss,
                        search_domains=block.dnssl,
                    )
                )
        return adverts, servers

    def _servers(
        self,
        lay: _Layout,
        scopes: list[dhcp.Scope],
        enabled: bool,
        leases: list[DhcpLease] | None,
        gaps: list[Gap],
        own_defaults: bool,
    ) -> list[DhcpServer]:
        d = self.context.device_id
        out: list[DhcpServer] = []
        for scope in scopes:
            found = lay.locate(scope)
            if found is None:
                gaps.append(
                    Gap(
                        message=f"{scope.server}: the DHCP range {scope.key} is on no network "
                        "of the device",
                        message_id="linux.rangeNoNetwork",
                        params={"server": scope.server, "range": scope.key},
                    )
                )
                continue
            seg, iface = found
            net = iface.network
            reservations = [r for r in scope.reservations if r.address in net]
            reserved = {(r.mac, r.address) for r in reservations}
            mine = (
                [
                    x.model_copy(update={"reserved": (x.mac, x.address) in reserved})
                    for x in leases
                    if x.address in net
                ]
                if leases is not None
                else None
            )
            router = scope.router
            dns = scope.dns
            if own_defaults:  # dnsmasq hands out itself unless told otherwise
                router = router or iface.ip
                dns = dns or [iface.ip]
            out.append(
                DhcpServer(
                    id=object_id(d, "dhcp", scope.key),
                    device_id=d,
                    segment_id=seg,
                    enabled=enabled,
                    pools=[DhcpPool(start=s, end=e) for s, e in scope.pools],
                    lease_seconds=scope.lease_seconds,
                    router=router,
                    dns_servers=dns,
                    domain=scope.domain,
                    reservations=reservations,
                    ntp_servers=scope.ntp,
                    leases=mine,
                    search_domains=scope.search,
                    static_routes=scope.routes,
                    options=scope.options,
                    authoritative=scope.authoritative,
                    failover_peer=scope.failover_peer,
                    vendor_extra={"server": scope.server}
                    | ({"interface": scope.interface} if scope.interface else {}),
                )
            )
        return out

    async def read_dns(self) -> Observation:
        a = self.answer
        d = self.context.device_id
        active = parse.services_running(a)
        present = set(a.lines("present"))
        out: list[DnsService] = []
        masq = dhcp.parse_dnsmasq(a.files("dnsmasq"))
        if (
            masq.configured
            and masq.port != 0
            and not ("pihole-FTL" in active and "dnsmasq" not in active)
        ):
            forwarders: list[DnsForwarder] = []
            for text in masq.servers:
                with contextlib.suppress(ValueError):
                    fwd = DnsForwarder.model_validate(text)
                    if fwd not in forwarders:
                        forwarders.append(fwd)
            for domain, server in masq.domain_servers:
                with contextlib.suppress(ValueError):
                    fwd = DnsForwarder.model_validate(server).model_copy(update={"domain": domain})
                    if fwd not in forwarders:
                        forwarders.append(fwd)
            if not masq.no_resolv:
                forwarders += [
                    DnsForwarder(address=x)
                    for x in parse.resolvers(a)
                    if DnsForwarder(address=x) not in forwarders
                ]
            lay = self._layout()
            # dnsmasq answers the names of the leases it hands out (and its ``dhcp-host`` names)
            # whenever it serves DHCP; no ``dhcp-range``: no DHCP names
            serves_dhcp = bool(masq.scopes)
            segments = {lay.networks[i][0] for i in masq.interfaces if i in lay.networks}
            for addr in masq.listen:
                segments |= {
                    seg
                    for seg, nets in lay.networks.values()
                    if any(addr in n.network for n in nets)
                }
            out.append(
                DnsService(
                    id=object_id(d, "dns", "dnsmasq"),
                    device_id=d,
                    name="dnsmasq",
                    enabled="dnsmasq" in active,
                    listen=masq.listen,
                    port=masq.port,
                    forwarders=forwarders,
                    host_records=masq.hosts,
                    recursive=False,
                    rebind_protection=masq.stop_rebind,
                    rebind_allowed_domains=masq.rebind_ok,
                    cache_size=masq.cache_size,
                    local_domain=masq.domain,
                    register_dhcp=serves_dhcp,
                    dynamic_records=True if serves_dhcp else None,
                    listen_segments=sorted(segments),
                )
            )
        out += self._resolved(a, active)
        for name, unit, path in (
            ("adguardhome", "AdGuardHome", "/opt/AdGuardHome"),
            ("pihole", "pihole-FTL", "/etc/pihole"),
            ("unbound", "unbound", "/etc/unbound/unbound.conf"),
        ):
            if unit in active or path in present:
                out.append(
                    DnsService(
                        id=object_id(d, "dns", name),
                        device_id=d,
                        name=name,
                        enabled=unit in active,
                        config_read=False,
                    )
                )
        return Observation(dns_services=out)

    def _resolved(self, a: Answer, active: set[str]) -> list[DnsService]:
        """systemd-resolved (#182): ``[Resolve]`` of ``resolved.conf`` and its drop-ins.

        ``DNS=`` lists the global upstreams (``192.0.2.1``, ``192.0.2.1#dns.example`` with a
        server name, ``192.0.2.1:853#name`` with a port; v246/v247 and later), ``DNSOverTLS=yes``
        sends them over TLS (v239 and later; ``opportunistic`` tries and falls back to plain
        text, so the upstream stays plain), ``DNSSEC=yes`` or ``allow-downgrade`` validates.
        Upstreams that come from the links (DHCP, networkd) are not read: without ``DNS=`` the
        service counts as not read. Quiet when resolved does not run.
        """
        if "systemd-resolved" not in active:
            return []
        conf = parse.resolved_conf(a.files("resolved"))
        forwarders: list[DnsForwarder] = []
        tls = conf.get("dnsovertls", "").lower() in ("yes", "true", "1", "on")
        for item in conf.get("dns", "").split():
            host, _, name = item.partition("#")
            host, port = dnsmap.host_port(host)
            try:
                fwd = DnsForwarder(
                    address=ip_address(host),
                    port=port or (853 if tls else 53),
                    transport=DnsTransport.TLS if tls else DnsTransport.UDP,
                    tls_name=(name or None) if tls else None,
                )
            except ValueError:
                continue
            if fwd not in forwarders:
                forwarders.append(fwd)
        dnssec = conf.get("dnssec", "").lower()
        extra: dict[str, Any] = {}
        if conf.get("dnsovertls", "").lower() == "opportunistic":
            extra["dns_over_tls"] = "opportunistic"
        if dnssec == "allow-downgrade":
            extra["dnssec"] = "allow-downgrade"
        return [
            DnsService(
                id=object_id(self.context.device_id, "dns", "systemd-resolved"),
                device_id=self.context.device_id,
                name="systemd-resolved",
                listen=[ip_address("127.0.0.53")],
                forwarders=forwarders,
                dnssec=True
                if dnssec in ("yes", "true", "allow-downgrade")
                else False
                if dnssec in ("no", "false")
                else None,
                supports_encrypted_dns=True,
                recursive=False,
                local_domain=conf.get("domains", "").split()[0].lstrip("~").lower()
                if conf.get("domains", "").split() and not conf["domains"].startswith("~")
                else None,
                config_read=bool(forwarders),
                vendor_extra=extra,
            )
        ]

    # health and time ----------------------------------------------------------------------

    async def read_health(self) -> Observation:
        a = self.answer
        total, used = parse.memory(a)
        cpus = parse._int(a.text("cpus"))
        health = DeviceHealth(
            uptime_seconds=parse.uptime(a),
            load_average=parse.load_average(a),
            cpu_count=cpus if cpus and cpus > 0 else None,
            memory_total_bytes=total,
            memory_used_bytes=used,
            storage=parse.storage(a),
            temperatures=parse.temperatures(a),
        )
        return Observation(health={self.context.device_id: health})

    async def read_time(self) -> Observation:
        answer = await self._run(collect.TIME)
        value = clock.device_time(answer, parse.services_running(self.answer))
        return Observation(time={self.context.device_id: value})


# --- the device's layout ---------------------------------------------------------------------


class _Layout:
    """Ports, the networks (segments and subnets) and the uplinks of one answer."""

    def __init__(self, device: str, site: str) -> None:
        self.device, self.site = device, site
        self.links: dict[str, parse.Link] = {}
        self.ports: dict[str, Port] = {}
        self.members: dict[str, dict[str, Membership]] = {}
        self.names: dict[str, str] = {}
        self.subnets: list[Subnet] = []
        self.uplinks: list[Uplink] = []
        #: L3 interface name -> (segment id, addresses)
        self.networks: dict[str, tuple[str, list[IPInterface]]] = {}

    def seg(self, vlan: int | None) -> str:
        return segment_id(self.site, vlan)

    @classmethod
    def build(cls, device: str, site: str, a: Answer, router: bool) -> _Layout:
        lay = cls(device, site)
        links = parse.links(a)
        sys = parse.sysnet(a)
        lay.links = {n: x for n, x in links.items() if x.raw.get("link_type") != "loopback"}
        conduits = {x.parent for x in links.values() if x.kind == "dsa" and x.parent}
        roles: dict[str, PortRole | None] = {}
        for name, link in sorted(lay.links.items()):
            role, kind = parse.role_of(link, sys.get(name), conduits)
            roles[name] = role
            lower: list[str] = []
            if link.kind in ("bridge", "bond", "team"):
                lower = sorted(n for n, x in lay.links.items() if x.master == name)
            elif link.kind in ("vlan", "dsa") and link.parent in lay.links:
                lower = [link.parent]
            mac = link.raw.get("address")
            info = sys.get(name)
            mtu = link.raw.get("mtu")
            extra: dict[str, Any] = {"kind": link.kind} if link.kind else {}
            if link.vlan is not None:
                extra["vlan"] = link.vlan
            lay.ports[name] = Port(
                id=port_id(device, name),
                device_id=device,
                name=name,
                kind=kind,
                up=link.up,
                admin_up=link.admin_up,
                speed_mbps=info.speed if info and link.up else None,
                full_duplex=(info.duplex == "full") if info and info.duplex and link.up else None,
                mac=mac
                if link.raw.get("link_type") == "ether" and isinstance(mac, str) and len(mac) == 17
                else None,
                mtu=mtu if isinstance(mtu, int) and 68 <= mtu <= 65535 else None,
                role=role,
                lower=[port_id(device, x) for x in lower],
                counters=parse.link_counters(link.raw),
                vendor_extra=extra,
            )

        lay._bonds(a)

        # uplinks: interfaces with a default route (a gateway only)
        uplink_devs: dict[str, list[parse.Route]] = {}
        if router:
            for route in parse.default_routes(a):
                found = lay.links.get(route.dev or "")
                if found is None or found.kind in NOT_UPLINK:
                    continue
                uplink_devs.setdefault(found.name, []).append(route)
        for name, routes in uplink_devs.items():
            link = lay.links[name]
            if link.kind == "ppp" or link.raw.get("link_type") == "ppp":
                ukind = UplinkKind.PPPOE
            elif link.dynamic or any(r.protocol == "dhcp" for r in routes):
                ukind = UplinkKind.DHCP
            else:
                ukind = UplinkKind.STATIC
            gateway = next((r.gateway for r in routes if r.gateway is not None), None)
            lay.uplinks.append(
                Uplink(
                    id=object_id(device, "uplink", name),
                    device_id=device,
                    port_id=port_id(device, name),
                    name=name,
                    kind=ukind,
                    up=link.up,
                    addresses=parse.global_addresses(link),
                    upstream_gateway=gateway,
                    vendor_extra={"protocol": [r.protocol for r in routes if r.protocol]},
                )
            )

        # networks: interfaces with addresses, except tunnels and, on a router, the uplinks
        # (the WAN side). A host that does not forward (IP forwarding is off: a single-NIC
        # Raspberry Pi, #302) has no WAN side: its uplink interface is its network, and so is
        # the uplink of a router on which nothing else has an address.
        forwarding = parse.forwarding(a)
        vlans = parse.bridge_vlans(a)
        wan = set(uplink_devs) if forwarding is not False else set()
        lay._networks(roles, vlans, wan, router, forwarding)
        if not lay.networks and wan:
            lay._networks(roles, vlans, set(), router, forwarding)
        return lay

    def _bonds(self, a: Answer) -> None:
        """LAG details (#157): ``lag`` on the members of every bond or team, and from
        ``/proc/net/bonding/<bond>`` mode, hash, LACP rate and minimum links on the bond and
        the LACP state of its members."""
        files = {bonding.bond_name(p): t for p, t in a.files("bonding").items()}
        for name, link in sorted(self.links.items()):
            if link.kind not in ("bond", "team") or name not in self.ports:
                continue
            bond = bonding.parse_proc(name, files[name]) if name in files else None
            if bond is not None:
                self.ports[name] = self.ports[name].model_copy(update=bond.details())
            members = {n for n, x in self.links.items() if x.master == name}
            members |= set(bond.members) if bond is not None else set()
            for member in sorted(members & set(self.ports)):
                update: dict[str, Any] = {"lag": name}
                if bond is not None:
                    update["lag_member_state"] = bond.member_state(member)
                self.ports[member] = self.ports[member].model_copy(update=update)

    def _networks(
        self,
        roles: dict[str, PortRole | None],
        vlans: dict[str, list[tuple[int, bool, bool]]],
        wan: set[str],
        router: bool,
        forwarding: bool | None,
    ) -> None:
        for name, link in sorted(self.links.items()):
            role = roles[name]
            if name in wan or role is PortRole.TUNNEL:
                continue
            addresses = parse.global_addresses(link)
            filtering = link.kind == "bridge" and link.vlan_filtering
            if filtering:  # the bridge's own VLAN table: one segment per VLAN
                for member in sorted(n for n, x in self.links.items() if x.master == name):
                    for vid, _pvid, untagged in vlans.get(member, []):
                        mode = Membership.UNTAGGED if untagged else Membership.TAGGED
                        self.add_member(self.seg(vid), member, mode)
            if not addresses and link.kind != "bridge":
                continue
            seg = self.seg(link.vlan if role is PortRole.VLAN else None)
            if role is PortRole.VLAN and link.parent in self.links:
                parent = self.links[link.parent]
                if parent.kind == "bridge" and parent.vlan_filtering:
                    pass  # members come from the bridge's VLAN table
                else:
                    self.add_member(seg, link.parent, Membership.TAGGED)
            elif link.kind == "bridge" and not filtering:
                for member in sorted(n for n, x in self.links.items() if x.master == name):
                    self.add_member(seg, member, Membership.UNTAGGED)
            elif link.kind != "bridge" and link.master is None:
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
                        interface_name=name,
                        device_id=self.device,
                        gateway=router and forwarding is not False,
                    )
                )

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

    def locate(self, scope: dhcp.Scope) -> tuple[str, IPInterface] | None:
        """The segment and the device's address of a DHCP scope."""
        v4 = {
            name: [x for x in addrs if isinstance(x.ip, IPv4Address)]
            for name, (_, addrs) in self.networks.items()
        }
        if scope.interface in self.networks:
            for addr in v4[scope.interface]:
                if scope.network is None or addr.ip in scope.network:
                    return self.networks[scope.interface][0], addr
        probe = scope.network[1] if scope.network is not None else scope.start
        if probe is None and scope.pools:
            probe = scope.pools[0][0]
        for name, addrs in sorted(v4.items()):
            if probe is not None and (found := parse.network_of(list(addrs), probe)) is not None:
                return self.networks[name][0], found
        return None
