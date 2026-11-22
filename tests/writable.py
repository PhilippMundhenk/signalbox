"""A fake integration that can be written to, with failure switches, for deployment tests."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from pydantic import SecretStr

from factories import iface, ip
from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterError,
    ApplyResult,
    Backup,
    Capability,
    Manifest,
    Observation,
    SystemInfo,
    Unreachable,
    VendorCall,
)
from signalbox.changes import Change, ChangeKind, apply_change
from signalbox.model import (
    Band,
    Device,
    DeviceRole,
    DhcpPool,
    DhcpServer,
    Membership,
    Network,
    PortMembership,
    Radio,
    Security,
    Segment,
    Subnet,
    Wlan,
    passphrase_fingerprint,
    port_id,
    segment_id,
)
from signalbox.model import Port as PortModel


class WConfig(AdapterConfig):
    host: str
    password: SecretStr


def initial(device_id: str, role: DeviceRole, site: str = "home") -> Network:
    native = segment_id(site, None)
    lan = port_id(device_id, "lan")
    dev = Device(id=device_id, site_id=site, name=device_id, role=role, adapter="w")
    net = Network(
        devices=[dev],
        ports=[PortModel(id=lan, device_id=device_id, name="lan", speed_mbps=1000)],
        segments=[
            Segment(
                id=native,
                site_id=site,
                members=[PortMembership(port_id=lan, mode=Membership.UNTAGGED)],
            )
        ],
    )
    if role is DeviceRole.GATEWAY:
        net = net.model_copy(
            update={
                "subnets": [
                    Subnet(
                        id=f"{device_id}/subnet/lan",
                        segment_id=native,
                        interface=iface("192.0.2.1/24"),
                        device_id=device_id,
                        gateway=True,
                    )
                ],
                "dhcp_servers": [
                    DhcpServer(
                        id=f"{device_id}/dhcp/lan",
                        device_id=device_id,
                        segment_id=native,
                        enabled=True,
                        pools=[DhcpPool(start=ip("192.0.2.100"), end=ip("192.0.2.199"))],
                        dns_servers=[ip("192.0.2.1")],
                    )
                ],
            }
        )
    else:
        radio = Radio(
            id=f"{device_id}/radio/0", device_id=device_id, name="radio0", band=Band.GHZ_5
        )
        net = net.model_copy(
            update={
                "radios": [radio],
                "wlans": [
                    Wlan(
                        id=f"{device_id}/wlan/0",
                        device_id=device_id,
                        ssid="Example",
                        radio_id=radio.id,
                        security=Security.WPA2,
                        segment_id=native,
                        passphrase_fingerprint=passphrase_fingerprint("Example", "old passphrase"),
                    )
                ],
            }
        )
    return net


class Writable(Adapter):
    manifest = Manifest(
        id="w",
        name="Writable",
        version="1",
        api_version="1.0",
        vendor="Example",
        roles=frozenset({DeviceRole.GATEWAY, DeviceRole.AP}),
        capabilities=frozenset({Capability.INTERFACES, Capability.DHCP, Capability.WIRELESS}),
        config=WConfig,
        writes=frozenset(ChangeKind),
    )
    #: device id -> current configuration
    state: ClassVar[dict[str, Network]] = {}
    #: device id -> set of failure switches
    fail: ClassVar[dict[str, set[str]]] = {}
    #: device id -> list of operations seen
    log: ClassVar[dict[str, list[str]]] = {}
    secrets_seen: ClassVar[list[str]] = []

    @classmethod
    def reset(cls) -> None:
        cls.state = {
            "gw": initial("gw", DeviceRole.GATEWAY),
            "ap": initial("ap", DeviceRole.AP),
        }
        cls.fail = {}
        cls.log = {}
        cls.secrets_seen = []

    @property
    def dev(self) -> str:
        return self.context.device_id

    def _switch(self, name: str) -> bool:
        return name in self.fail.get(self.dev, set())

    def _note(self, what: str) -> None:
        self.log.setdefault(self.dev, []).append(what)

    async def read_system(self) -> SystemInfo:
        if self._switch("down"):
            raise Unreachable("no answer")
        return SystemInfo(vendor="Example", model="W1")

    def _net(self) -> Network:
        return self.state[self.dev]

    async def read_interfaces(self) -> Observation:
        n = self._net()
        return Observation(ports=n.ports, segments=n.segments, subnets=n.subnets)

    async def read_dhcp(self) -> Observation:
        return Observation(dhcp_servers=self._net().dhcp_servers)

    async def read_wireless(self) -> Observation:
        n = self._net()
        return Observation(radios=n.radios, wlans=n.wlans)

    # WritesConfig ---------------------------------------------------------------------------

    async def plan_changes(
        self, changes: list[Change], secrets: Mapping[str, str]
    ) -> list[VendorCall]:
        if self._switch("plan"):
            raise AdapterError("cannot translate the change")
        return [
            VendorCall(description=c.describe(), method="SET", target=c.key, payload={"x": "***"})
            for c in changes
        ]

    async def backup(self) -> Backup:
        if self._switch("backup"):
            raise AdapterError("export refused")
        self._note("backup")
        return Backup(
            device_id=self.dev,
            taken_at=datetime.now(UTC),
            format="fake-json",
            content=self._net().model_dump_json(),
        )

    async def apply(
        self, changes: list[Change], secrets: Mapping[str, str], rollback_seconds: int
    ) -> ApplyResult:
        second = self.log.get(self.dev, []).count("apply") >= 1  # the rollback's inverse
        if self._switch("apply") or (second and self._switch("inverse")):
            raise AdapterError("device refused the change")
        self._note("apply")
        if not self._switch("noop"):
            net = self._net()
            for c in changes:
                had = {w.ssid: w.passphrase_fingerprint for w in net.wlans}
                net = apply_change(net, c)
                if c.kind is ChangeKind.WLAN and c.new is not None:
                    name = c.new.passphrase_secret  # type: ignore[union-attr]
                    # like a device: without a passphrase in the change the old one stays
                    fp = had.get(c.key)
                    if name:
                        self.secrets_seen.append(secrets[name])
                        fp = passphrase_fingerprint(c.key, secrets[name])
                    if fp:
                        net = net.model_copy(
                            update={
                                "wlans": [
                                    w.model_copy(update={"passphrase_fingerprint": fp})
                                    if w.ssid == c.key
                                    else w
                                    for w in net.wlans
                                ]
                            }
                        )
            self.state[self.dev] = Network.model_validate(net.model_dump())
        if self._switch("down-after"):
            self.fail[self.dev].add("down")
        deadline = (
            datetime.now(UTC) + timedelta(seconds=rollback_seconds)
            if self._switch("timer")
            else None
        )
        return ApplyResult(
            confirm_deadline=deadline, calls=await self.plan_changes(changes, secrets)
        )

    async def confirm(self) -> None:
        if self._switch("confirm"):
            raise AdapterError("confirm refused")
        self._note("confirm")

    async def restore(self, backup: Backup) -> None:
        if self._switch("restore"):
            raise AdapterError("restore refused")
        self._note("restore")
        self.state[self.dev] = Network.model_validate(json.loads(backup.content))
        self.fail.get(self.dev, set()).discard("down")


def snapshot_json(device_id: str) -> Any:
    return Writable.state[device_id].model_dump(mode="json")
