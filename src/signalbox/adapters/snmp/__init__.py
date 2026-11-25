"""Generic SNMP switch reader (read only): any managed switch that offers the standard MIBs.

SNMP v2c (a read-only community) or v3 (authPriv: SHA or SHA-256 authentication, AES-128
privacy), through pysnmp 7 (``pip install signalbox-net[snmp]``, imported only when a switch is
read). Only GET, GETNEXT and GETBULK are sent: **Signalbox never writes over SNMP**, there is no
change deployment for this adapter.

What is read, and from which MIB (numeric OIDs, :mod:`signalbox.adapters.snmp.mib`):

- SNMPv2-MIB: description, name, uptime (capability ``health``)
- ENTITY-MIB: model, serial, firmware of the chassis
- IF-MIB (+ EtherLike-MIB): ports, link, speed, duplex, MTU, MAC, alias
- Q-BRIDGE-MIB: VLANs (tagged/untagged members), PVID, frame types, ingress filter, the MAC
  address table per VLAN (``fdb``); BRIDGE-MIB's table where a switch has no Q-BRIDGE one
- BRIDGE-MIB / RSTP-MIB: spanning tree of the switch and of every port
- LLDP-MIB: neighbours (capability ``neighbours``)
- IEEE8023-LAG-MIB and the IF-MIB stack table: link aggregation

Everything a switch does not offer becomes an optional gap (the rest is kept). The MAC tables
and LLDP neighbours feed the topology inference like those of any other adapter.

One observation is one session: a few scalars, then walks of the columns needed. Walks are
cached for the observation, so ports are read once for the interface and the neighbour read.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from signalbox.adapters import (
    Adapter,
    AdapterContext,
    AdapterError,
    AuthFailed,
    Capability,
    Gap,
    Manifest,
    Observation,
    SystemInfo,
    Unreachable,
)
from signalbox.adapters.snmp import mapping, mib
from signalbox.adapters.snmp.client import (
    INSTALL_HINT,
    PysnmpTransport,
    SnmpError,
    SnmpTransport,
    SnmpUnavailable,
)
from signalbox.adapters.snmp.config import SnmpConfig
from signalbox.factory_defaults import is_factory_default
from signalbox.model import (
    AccountPrivilege,
    ManagementService,
    ServiceKind,
    SnmpSettings,
    SnmpVersion,
    object_id,
)
from signalbox.model import DeviceRole as Role

__all__ = ["SnmpAdapter", "SnmpConfig"]

log = logging.getLogger(__name__)

SETUP_URL = "https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/snmp.md#setup"

SETUP_STEPS = (
    "On the switch enable SNMP with a read-only user. SNMP v3 with authentication and "
    "encryption (authPriv) is recommended: create a user in a read-only group with SHA-256 (or "
    "SHA) authentication and AES-128 privacy, and give it a view of the whole MIB tree or at "
    "least of the standard MIBs (see the guide).",
    "SNMP v2c sends its community in clear text, and anyone who sees one packet can read the "
    "switch (and write it, if the community allows): use it only where v3 is not available, "
    "with a read-only community and an access list that allows only this host.",
    "Enable LLDP on the switch to get its neighbours, and spanning tree if you use it.",
    "Below: the switch's address and the version with its credentials, then Test connection.",
)

#: what the capability reads: the walks (``group``) and what is read with them
_IF_COLUMNS = (
    *(
        f"{mib.IF_TABLE}.{n}"
        for n in (
            mib.IF_TYPE,
            mib.IF_DESCR,
            mib.IF_MTU,
            mib.IF_SPEED,
            mib.IF_PHYS,
            mib.IF_ADMIN,
            mib.IF_OPER,
        )
    ),
    *(f"{mib.IF_X_TABLE}.{n}" for n in (mib.IF_NAME, mib.IF_HIGH_SPEED, mib.IF_ALIAS)),
    mib.DOT3_DUPLEX,
    mib.DOT3_FCS_ERRORS,
    *(f"{mib.IF_TABLE}.{n}" for n in mapping.IF_COUNTER_COLUMNS),
    *(f"{mib.IF_X_TABLE}.{n}" for n in mapping.IF_X_COUNTER_COLUMNS),
    mib.BASE_PORT_IFINDEX,
    *(f"{mib.PORT_VLAN}.{n}" for n in (mib.PVID, mib.ACCEPTABLE_FRAMES, mib.INGRESS_FILTER)),
    *(f"{mib.STP_PORT_TABLE}.{n}" for n in (mib.STP_PORT_STATE, mib.STP_PORT_PATH_COST)),
    f"{mib.RSTP_PORT_TABLE}.{mib.RSTP_PORT_OPER_EDGE}",
    mib.IF_STACK_STATUS,
    f"{mib.LAG_AGG}.1",
    *(
        f"{mib.LAG_PORT}.{n}"
        for n in (
            mib.LAG_PORT_SELECTED,
            mib.LAG_PORT_ATTACHED,
            mib.LAG_PORT_ADMIN_STATE,
            mib.LAG_PORT_OPER_STATE,
            mib.LAG_PORT_PARTNER_SYSTEM,
            mib.LAG_PORT_PARTNER_KEY,
            mib.LAG_PORT_PARTNER_PORT,
        )
    ),
)
_VLAN_COLUMNS = (
    *(f"{mib.VLAN_STATIC}.{n}" for n in (mib.VLAN_NAME, mib.VLAN_EGRESS, mib.VLAN_UNTAGGED)),
)
_VLAN_CURRENT_COLUMNS = (
    f"{mib.VLAN_CURRENT}.{mib.VLAN_CURRENT_EGRESS}",
    f"{mib.VLAN_CURRENT}.{mib.VLAN_CURRENT_UNTAGGED}",
)
_FDB_COLUMNS = (mib.Q_FDB_PORT, mib.Q_FDB_STATUS)
_FDB_LEGACY_COLUMNS = (mib.TP_FDB_PORT, mib.TP_FDB_STATUS)
_POE_COLUMNS = (
    *(
        f"{mib.PETH_PORT}.{n}"
        for n in (
            mib.PETH_PORT_ADMIN,
            mib.PETH_PORT_DETECTION,
            mib.PETH_PORT_PRIORITY,
            mib.PETH_PORT_CLASS,
        )
    ),
    *(f"{mib.PETH_MAIN}.{n}" for n in (mib.PETH_MAIN_POWER, mib.PETH_MAIN_CONSUMPTION)),
)
_STP_SCALARS = (
    mib.STP_PROTOCOL,
    mib.STP_PRIORITY,
    mib.STP_TOP_CHANGES,
    mib.STP_DESIGNATED_ROOT,
    mib.STP_ROOT_COST,
    mib.STP_ROOT_PORT,
    mib.STP_VERSION,
)
_LLDP_COLUMNS = (
    *(
        f"{mib.LLDP_LOC_PORT}.{n}"
        for n in (mib.LLDP_LOC_PORT_SUBTYPE, mib.LLDP_LOC_PORT_ID, mib.LLDP_LOC_PORT_DESC)
    ),
    *(
        f"{mib.LLDP_REM}.{n}"
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
    ),
    mib.LLDP_REM_MAN_ADDR,
)


class SnmpAdapter(Adapter):
    manifest: ClassVar[Manifest] = Manifest(
        id="snmp",
        name="SNMP switch (generic, read only)",
        version="0.1.0",
        api_version="1.2",
        vendor="Generic",
        roles=frozenset({Role.SWITCH}),
        capabilities=frozenset({Capability.INTERFACES, Capability.NEIGHBOURS, Capability.HEALTH}),
        config=SnmpConfig,
        description="Managed switches that offer the standard MIBs over SNMP v2c or v3: "
        "ports, VLANs, MAC table, spanning tree, LLDP neighbours and link aggregation. "
        "Read only.",
        setup_url=SETUP_URL,
        setup_steps=SETUP_STEPS,
        least_privilege=AccountPrivilege.READ,
    )

    def __init__(self, context: AdapterContext) -> None:
        super().__init__(context)
        self._transport: SnmpTransport | None = None
        self._mib = mapping.Mib()
        self._entity_missing = False
        self._done: set[str] = set()
        self._pmap: mapping.PortMap | None = None
        self._bridge_mac: str | None = None

    @property
    def _cfg(self) -> SnmpConfig:
        cfg = self.context.config
        assert isinstance(cfg, SnmpConfig)
        return cfg

    # -- transport and errors -----------------------------------------------------------------

    def _open(self) -> SnmpTransport:
        if self._transport is None:
            injected = self.context.extra.get("snmp_transport")
            if injected is not None:
                self._transport = injected
            else:
                try:
                    self._transport = PysnmpTransport(self._cfg, self.context.timeout)
                except SnmpUnavailable:
                    raise AdapterError(INSTALL_HINT, message_id="snmp.install") from None
        return self._transport

    def _translate(self, exc: SnmpError) -> AdapterError:
        host = self._cfg.address
        if exc.kind == "auth":
            return AuthFailed(
                f"{host}: the switch refused the SNMP login ({exc.detail})",
                fix="Check the SNMPv3 user name, the authentication algorithm (SHA or SHA-256) "
                "and both passwords in the device settings, and that the user has a view of "
                "the MIBs. With v2c check the community string.",
                message_id="snmp.authFailed",
                fix_id="snmp.authFailed.fix",
                params={"host": host, "detail": exc.detail},
            )
        if exc.kind == "timeout":
            return Unreachable(
                f"{host}: no SNMP answer",
                fix="Check the address and the port, that SNMP is enabled on the switch and "
                "allows this host, and the credentials: with a wrong v2c community or a wrong "
                "v3 user name the switch does not answer at all.",
                message_id="snmp.noAnswer",
                fix_id="snmp.noAnswer.fix",
                params={"host": host},
            )
        return AdapterError(
            f"{host}: SNMP request failed ({exc.detail})",
            message_id="snmp.error",
            params={"host": host, "detail": exc.detail},
        )

    async def _get(self, *oids: str) -> dict[str, Any]:
        try:
            return dict(await self._open().get(*oids))
        except SnmpError as exc:
            raise self._translate(exc) from exc

    async def _walk(self, base: str) -> bool:
        """Walk one subtree into the cache. A failure after the switch answered is not fatal:
        the part is simply missing (``False``)."""
        try:
            rows = await self._open().walk(base)
        except SnmpError as exc:
            if exc.kind == "auth":
                raise self._translate(exc) from exc
            log.info("%s: %s not read: %s", self._cfg.address, base, exc.detail)
            return False
        self._mib.walks[base] = rows
        return True

    async def _walks(self, group: str, bases: tuple[str, ...]) -> None:
        if group in self._done:
            return
        self._done.add(group)
        for base in bases:
            await self._walk(base)

    async def close(self) -> None:
        transport, self._transport = self._transport, None
        if transport is not None:
            await transport.close()

    # -- system -------------------------------------------------------------------------------

    async def read_system(self) -> SystemInfo:
        self._mib = mapping.Mib()
        self._done = set()
        self._pmap = None
        self._entity_missing = False
        scalars = await self._get(
            mib.SYS_DESCR,
            mib.SYS_OBJECT_ID,
            mib.SYS_UPTIME,
            mib.SYS_CONTACT,
            mib.SYS_NAME,
            mib.SYS_LOCATION,
        )
        if mib.SYS_DESCR not in scalars:
            raise AdapterError(
                f"{self._cfg.address}: SNMP request failed (no sysDescr)",
                message_id="snmp.error",
                params={"host": self._cfg.address, "detail": "no sysDescr"},
            )
        self._mib.scalars.update(scalars)
        bridge = await self._get(mib.BRIDGE_ADDRESS)
        self._bridge_mac = mapping.as_mac(bridge.get(mib.BRIDGE_ADDRESS))
        entity = await self._entity()
        self._entity_missing = not entity
        return mapping.system_info(
            self._mib.scalars,
            entity,
            self._cfg.address,
            self._bridge_mac,
        ).model_copy(update={"transport_encrypted": self._cfg.version == "v3"})

    async def _entity(self) -> dict[int, Any]:
        """The chassis row of ENTITY-MIB (column → value); empty: not offered."""
        try:
            classes = await self._open().walk(f"{mib.ENT_PHYSICAL}.{mib.ENT_CLASS}")
        except SnmpError as exc:
            if exc.kind == "auth":
                raise self._translate(exc) from exc
            return {}
        index = mapping.chassis_index({k.rsplit(".", 1)[1]: v for k, v in classes.items()}) or next(
            (k.rsplit(".", 1)[1] for k in classes), None
        )
        if index is None:
            return {}
        columns = (
            mib.ENT_DESCR,
            mib.ENT_HARDWARE_REV,
            mib.ENT_FIRMWARE_REV,
            mib.ENT_SOFTWARE_REV,
            mib.ENT_SERIAL,
            mib.ENT_MFG,
            mib.ENT_MODEL,
        )
        wanted = {f"{mib.ENT_PHYSICAL}.{c}.{index}": c for c in columns}
        got = await self._get(*wanted)
        return {wanted[oid]: value for oid, value in got.items() if oid in wanted}

    async def read_health(self) -> Observation:
        health = mapping.health(self._mib.scalars)
        return Observation(health={self.context.device_id: health} if health else {})

    # -- interfaces ---------------------------------------------------------------------------

    async def _ports(self) -> mapping.PortMap:
        if self._pmap is None:
            await self._walks("if", _IF_COLUMNS)
            if "stp" not in self._done:
                self._done.add("stp")
                self._mib.scalars.update(await self._get(*_STP_SCALARS))
            self._pmap, _ = mapping.ports(self.context.device_id, self._mib)
        return self._pmap

    def _gap(self, what: str) -> Gap:
        host = self._cfg.address
        return Gap(
            message=f"{host}: the switch does not offer {what} over SNMP; what depends on it "
            "is not read",
            fix="Nothing is wrong with Signalbox: the switch has no such data, or the feature "
            "is off (enable LLDP or spanning tree on the switch), or the SNMP user's view "
            "does not include it (SNMPv3: add the MIB to the view). The checks that need it "
            'report "incomplete" until it is there.',
            optional=True,
            message_id="snmp.gapMib",
            fix_id="snmp.gapMib.fix",
            params={"host": host, "mib": what},
        )

    def _services(self) -> list[ManagementService]:
        cfg, d = self._cfg, self.context.device_id
        v3 = cfg.version == "v3"
        secret = cfg.community.get_secret_value() if cfg.community else ""
        return [
            ManagementService(
                id=object_id(d, "service", "snmp"),
                device_id=d,
                kind=ServiceKind.SNMP,
                name="snmp",
                enabled=True,
                port=cfg.port,
                encrypted=v3,
                snmp=SnmpSettings(
                    versions=[SnmpVersion.V3 if v3 else SnmpVersion.V2C],
                    default_community=None if v3 else is_factory_default("snmp", secret),
                    v3_privacy=True if v3 else None,
                ),
            )
        ]

    async def read_interfaces(self) -> Observation:
        d, site = self.context.device_id, self.context.site_id
        pmap = await self._ports()
        if not pmap.ports:
            raise AdapterError(
                f"{self._cfg.address}: SNMP request failed (no interfaces)",
                message_id="snmp.error",
                params={"host": self._cfg.address, "detail": "no interfaces"},
            )
        gaps: list[Gap] = []
        await self._walks("vlan", _VLAN_COLUMNS)
        if not self._mib.has(mib.VLAN_STATIC, mib.VLAN_EGRESS):
            await self._walks("vlan-current", _VLAN_CURRENT_COLUMNS)
        segments = mapping.segments(site, pmap, self._mib)
        if segments is None:
            gaps.append(self._gap("Q-BRIDGE-MIB (VLANs)"))
        await self._walks("fdb", _FDB_COLUMNS)
        if not self._mib.has(mib.Q_FDB_PORT):
            await self._walks("fdb-legacy", _FDB_LEGACY_COLUMNS)
        vlans = {s.vlan for s in segments or [] if s.vlan is not None}
        table = mapping.fdb(d, site, pmap, self._mib, vlans)
        if not table:
            gaps.append(self._gap("a MAC address table (Q-BRIDGE-MIB, BRIDGE-MIB)"))
        await self._walks("poe", _POE_COLUMNS)
        supply, port_poe = mapping.poe(pmap, self._mib)
        ports = [
            p.model_copy(update={"poe": port_poe[p.id]}) if p.id in port_poe else p
            for p in pmap.ports
        ]
        bridge = mapping.stp_bridge(pmap, self._mib, self._bridge_mac)
        if bridge is None:
            gaps.append(self._gap("spanning tree (BRIDGE-MIB)"))
        if self._entity_missing:
            gaps.append(self._gap("ENTITY-MIB (model, serial, firmware)"))
        return Observation(
            ports=ports,
            poe={d: supply} if supply else {},
            segments=segments or [],
            fdb=table,
            services=self._services(),
            stp_bridges={d: [bridge] if bridge else []},
            incomplete=gaps,
            **self._login_facts(),
        )

    def _login_facts(self) -> dict[str, Any]:
        """A v2c community that is a factory default (``public``, ``private``), compared in
        memory; nothing for v3 (there is no default user)."""
        cfg = self._cfg
        if cfg.version != "v2c" or cfg.community is None:
            return {}
        d = self.context.device_id
        return {
            "default_credentials": {d: is_factory_default("snmp", cfg.community.get_secret_value())}
        }

    # -- neighbours ---------------------------------------------------------------------------

    async def read_neighbours(self) -> Observation:
        pmap = await self._ports()
        await self._walks("lldp", _LLDP_COLUMNS)
        found = mapping.neighbours(self.context.device_id, pmap, self._mib)
        gaps: list[Gap] = []
        if not found:
            local = await self._get(mib.LLDP_LOC_CHASSIS)
            if mib.LLDP_LOC_CHASSIS not in local:
                gaps.append(self._gap("LLDP-MIB (neighbours)"))
        return Observation(neighbours=found, incomplete=gaps)
