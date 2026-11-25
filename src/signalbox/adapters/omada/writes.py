"""TP-Link Omada (write): changes through the controller's Open API (issue #44).

Changes name the devices the controller manages (``<controller>/<type>-<mac>``, ADR 0004); the
deployment hands them to the controller's adapter, which turns them into Open API calls:

- ``router`` and ``dhcp`` of the gateway (of the controller itself on a site without one) →
  create, change or remove a LAN network (name, VLAN, gateway address and subnet) and its DHCP
  settings; one call per network
- ``port`` of a switch → the port's native (untagged) network and tagged networks: the port
  profile with exactly these networks if there is one, else a port-level override
- ``wlan`` of an EAP → create, change or remove the SSID in the EAP's WLAN group (security,
  passphrase, PMF, VLAN, hidden, enabled). An SSID belongs to the WLAN group, so the change
  reaches every EAP of the group; the review says which.

The controller provisions the devices by itself, later; Signalbox verifies what the controller
reports, which is also what the read side reads. The calls and bodies of networks and SSIDs
are those the real Omada Software Controller 6.3 takes (tests/integration/test_omada_real.py):
a network ``PATCH`` carries the whole network, an SSID is changed with ``update-basic-config``
(its whole basic configuration) and switched on or off with ``…/ssids/{id}/enable``. The
switch port call follows the controller's own API description (no switch to test it with).

A backup is the JSON of every controller object a change may touch (LAN networks, the SSIDs of
every WLAN group with their settings, the ports of every switch); restoring compares it with
the controller and creates, changes and deletes objects until they match.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_interface
from typing import TYPE_CHECKING, Any

from pydantic import JsonValue

from signalbox.adapters import (
    AdapterError,
    ApplyResult,
    Backup,
    Described,
    Label,
    VendorCall,
    message_fields,
)
from signalbox.adapters.omada import (
    OmadaError,
    TokenRefused,
    _check,
    _dhcp_settings,
    _dict,
    _flag,
    _int,
    _Managed,
    _Net,
    _text,
    wifi_extras,
)
from signalbox.changes import (
    Change,
    ChangeKind,
    DhcpValue,
    PortValue,
    RouterValue,
    WlanValue,
)
from signalbox.model import IPAddress, Pmf, Security, segment_id

if TYPE_CHECKING:
    from signalbox.adapters.omada import OmadaAdapter

BACKUP_FORMAT = "omada-openapi-json"
#: Security → Omada ``security`` and ``pskSetting.versionPsk`` (3 WPA-Personal: 2 WPA2-PSK,
#: 4 WPA2-PSK/WPA3-SAE).
SECURITY: dict[Security, tuple[int, int | None]] = {
    Security.OPEN: (0, None),
    Security.WPA2: (3, 2),
    Security.WPA2_WPA3: (3, 4),
}
PMF = {Pmf.REQUIRED: 1, Pmf.OPTIONAL: 2, Pmf.DISABLED: 3}
#: ``band`` of a new SSID: 2.4 and 5 GHz (6 GHz needs WPA3 or OWE).
NEW_SSID_BAND = 3
#: The basic configuration of an SSID: ``update-basic-config`` takes all of it.
SSID_BASIC = (
    "name", "band", "guestNetEnable", "security", "broadcast", "vlanEnable", "vlanId",
    "pskSetting", "mloEnable", "pmfMode", "enable11r", "hidePwd",
)  # fmt: skip
#: Defaults of a new SSID for what the desired state does not say.
SSID_DEFAULTS: dict[str, Any] = {
    "band": NEW_SSID_BAND,
    "guestNetEnable": False,
    "mloEnable": False,
    "enable11r": False,
}
#: Keys of a switch port that a port change writes (and a restore puts back).
PORT_KEYS = ("profileId", "profileOverrideEnable", "nativeNetworkId", "tagNetworkIds")
#: Keys of a network that are the controller's own (not sent back).
NETWORK_OWN = ("id", "primary", "site")
#: What a network restore compares.
NETWORK_COMPARED = ("name", "purpose", "vlan", "gatewaySubnet", "domain")
#: Error codes of a refused permission (-1007 on 6.3); the message then names the role.
PERMISSION_CODES = frozenset({-1005, -1007})
MASK = "***"


@dataclass
class Op:
    """One Open API call."""

    description: str
    method: str
    path: str
    body: dict[str, Any] | None = None
    #: The body as shown in the review (passphrases replaced by ``***``).
    shown: dict[str, JsonValue] = field(default_factory=dict)

    def call(self) -> VendorCall:
        return VendorCall(
            description=self.description,
            **message_fields(self.description),
            method=self.method,
            target=self.path,
            payload=self.shown,
        )


def _shown(body: dict[str, Any] | None) -> dict[str, JsonValue]:
    if body is None:
        return {}
    out = json.loads(json.dumps(body))
    psk = out.get("pskSetting")
    if isinstance(psk, dict) and "securityKey" in psk:
        psk["securityKey"] = MASK
    result: dict[str, JsonValue] = out
    return result


def _vlan_of_key(site: str, change: Change) -> int | None:
    """The VLAN of a segment key (None: the native network); other sites are refused."""
    prefix = f"{site}/segment/"
    rest = change.key.removeprefix(prefix)
    if rest == change.key or not (rest == "native" or rest.isdigit()):
        raise AdapterError(
            f"{change.id}: {change.key} is not a segment of site {site}",
            message_id="omada.notSegment",
            params={"subject": change.id, "key": change.key, "site": site},
        )
    return None if rest == "native" else int(rest)


def _config(row: Mapping[str, Any]) -> dict[str, Any]:
    """A network as a ``PATCH`` or ``POST`` takes it: everything but the controller's own keys,
    the DHCP settings as ``dhcpSettingsVO`` (the newer lists call them ``dhcpSettings``)."""
    out = {k: v for k, v in row.items() if k not in NETWORK_OWN and k != "dhcpSettings"}
    dhcp = _dhcp_settings(dict(row))
    if dhcp:
        out["dhcpSettingsVO"] = dhcp
    return out


def _basic(row: Mapping[str, Any]) -> dict[str, Any]:
    """The basic configuration of an SSID (``update-basic-config``)."""
    out = {k: row[k] for k in SSID_BASIC if k in row}
    if not out.get("vlanEnable"):
        out.pop("vlanId", None)
    if out.get("security") != 3:
        out.pop("pskSetting", None)
    return out


class Writer:
    """The write side of one :class:`~signalbox.adapters.omada.OmadaAdapter`."""

    def __init__(self, adapter: OmadaAdapter) -> None:
        self.a = adapter

    @property
    def site(self) -> str:
        return self.a._site_path

    async def connect(self) -> None:
        """Resolve the site and authorise; forget everything read before."""
        await self.a.read_system()

    async def send(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        """One write; a refused token is renewed once. Never puts the body into an error."""
        try:
            for attempt in range(2):
                data = await self.a.http.request_json(
                    method,
                    path,
                    json=body,
                    headers={"Authorization": f"AccessToken={self.a._token}"},
                )
                try:
                    return _check(data, path)
                except TokenRefused:
                    if attempt:
                        raise
                    await self.a._authorise()
        except OmadaError as exc:
            hint = (
                " (changes need an Open API application with the Admin role)"
                if exc.code in PERMISSION_CODES or "ermission" in str(exc)
                else ""
            )
            raise AdapterError(
                f"{method} {path}: the controller refused: {exc}{hint}",
                message_id="omada.refusedPermission" if hint else "omada.refused",
                params={"request": f"{method} {path}", "detail": str(exc)},
            ) from exc
        finally:
            self.a._cache.clear()
            self.a._wireless_cache = None
        raise AssertionError("unreachable")  # pragma: no cover

    # --- what the controller has ------------------------------------------------------------

    async def _managed(self) -> dict[str, _Managed]:
        return {self.a._prefix(d): d for d in await self.a._devices()}

    async def _device(self, change: Change, kind: str) -> _Managed | None:
        """The managed device a change is for; None for the controller itself (no gateway)."""
        managed = await self._managed()
        dev = managed.get(change.device_id)
        if dev is not None and dev.kind == kind:
            return dev
        no_gateway = not any(d.kind == "gateway" for d in managed.values())
        if kind == "gateway" and change.device_id == self.a.context.device_id and no_gateway:
            return None
        raise AdapterError(
            f"{change.id}: {change.device_id} is not a {kind} managed by this controller",
            message_id="omada.notManaged",
            params={"subject": change.id, "device": change.device_id, "kind": kind},
        )

    async def _uses(self, net_id: str, vlan: int | None) -> bool:
        """Whether a port, port profile or SSID still uses a network. Two profiles do not
        count: the one the controller made for the network itself (``flag`` 1), which goes
        with it, and the built-in "All" (``type`` 0), which has every network."""
        rows = [
            p
            for p in await self.a._optional_rows(f"{self.site}/lan-profiles")
            if not (p.get("flag") == 1 and p.get("nativeNetworkId") == net_id)
            and p.get("type") != 0
        ]
        for sw in (d for d in await self.a._devices() if d.kind == "switch"):
            rows += await self.a._ports(sw.raw_mac)
        if any(
            r.get("nativeNetworkId") == net_id or net_id in (r.get("tagNetworkIds") or [])
            for r in rows
        ):
            return True
        groups, _ = await self.a._wlan_groups()
        for gid in groups:
            for s in await self.a._rows(f"{self.site}/wireless-network/wlans/{gid}/ssids"):
                if s.get("vlanEnable") and s.get("vlanId") == vlan:
                    return True
        return False

    async def _interfaces(self) -> list[str]:
        """The LAN interfaces of a new network: those of the native network, else those the
        controller gave another network (without a gateway: its virtual LAN ports)."""
        nets = sorted((await self.a._networks()).values(), key=lambda n: (n.vlan or 1) != 1)
        for n in nets:
            ids = n.raw.get("interfaceIds")
            if isinstance(ids, list) and ids:
                return [str(i) for i in ids]
        return []

    # --- changes → calls --------------------------------------------------------------------

    async def ops(
        self, changes: list[Change], secrets: Mapping[str, str], strict: bool
    ) -> list[Op]:
        """The calls for ``changes``. ``strict``: refuse what only exists after earlier steps
        of the deployment (a network a port needs); for the review it is named instead."""
        out: list[Op] = []
        networks: dict[str, dict[ChangeKind, Change]] = {}
        for c in changes:
            if c.kind in (ChangeKind.ROUTER, ChangeKind.DHCP):
                networks.setdefault(c.key, {})[c.kind] = c
            elif c.kind is ChangeKind.PORT:
                out.append(await self._port(c, strict))
            elif c.kind is ChangeKind.WLAN:
                out += await self._wlan(c, secrets, strict)
            else:
                raise AdapterError(
                    f"{c.id}: the Omada integration cannot change {c.kind.value}",
                    message_id="omada.cannotChange",
                    params={"subject": c.id, "kind": c.kind.value},
                )
        nets = [await self._network(key, by_kind) for key, by_kind in networks.items()]
        return [op for group in nets for op in group] + out

    async def _network(self, key: str, by_kind: dict[ChangeKind, Change]) -> list[Op]:
        router = by_kind.get(ChangeKind.ROUTER)
        dhcp = by_kind.get(ChangeKind.DHCP)
        first = router or dhcp
        assert first is not None
        for c in by_kind.values():
            await self._device(c, "gateway")
        vlan = _vlan_of_key(self.a.context.site_id, first)
        r_new = router.new if router and isinstance(router.new, RouterValue) else None
        d_new = dhcp.new if dhcp and isinstance(dhcp.new, DhcpValue) else None
        if r_new is not None and segment_id(self.a.context.site_id, r_new.vlan) != key:
            raise AdapterError(
                f"{first.id}: VLAN {r_new.vlan} does not match {key}",
                message_id="omada.vlanMismatch",
                params={"subject": first.id, "vlan": r_new.vlan, "key": key},
            )
        nets = await self.a._networks()
        net = next((n for n in nets.values() if n.segment == key), None)
        label = (
            Label(f"VLAN {vlan}", "vlan", vlan)
            if vlan
            else Label("the native network", "nativeNetwork")
        )
        lan = f"{self.site}/lan-networks"

        if router is not None and r_new is None:  # remove the router interface
            if d_new is not None:
                raise AdapterError(
                    f"{first.id}: DHCP needs the network's gateway address",
                    message_id="omada.dhcpNeedsGateway",
                    params={"subject": first.id},
                )
            if net is None:
                return []
            if vlan is None:
                raise AdapterError(
                    f"{first.id}: the native network cannot be removed",
                    message_id="omada.nativeNotRemovable",
                    params={"subject": first.id},
                )
            if await self._uses(net.id, net.vlan):
                body = _config(net.raw)
                body["purpose"] = 0
                for gone in ("gatewaySubnet", "dhcpSettingsVO"):
                    body.pop(gone, None)
                desc = Described(
                    f"network {net.name} ({label}): VLAN only, no gateway address or DHCP",
                    "plan.omada.networkVlanOnly",
                    name=net.name,
                    label=label,
                )
                shown: dict[str, Any] = {"purpose": 0, "gatewaySubnet": None}
                return [Op(desc, "PATCH", f"{lan}/{net.id}", body, _shown(shown))]
            desc = Described(
                f"delete network {net.name} ({label})",
                "plan.omada.networkDelete",
                name=net.name,
                label=label,
            )
            return [Op(desc, "DELETE", f"{lan}/{net.id}")]

        own = self._own(r_new, net)
        if net is None:
            if r_new is None:
                raise AdapterError(
                    f"{first.id}: there is no LAN network for {label}",
                    message_id="omada.noLanNetwork",
                    params={"subject": first.id, "label": label},
                )
            if not r_new.name:
                raise AdapterError(
                    f"{first.id}: an Omada network needs a name (set name: in the desired state)",
                    message_id="omada.networkNeedsName",
                    params={"subject": first.id},
                )
            body = {
                "name": r_new.name,
                "purpose": 1,
                "vlanType": 0,
                "vlan": vlan or 1,
                "gatewaySubnet": str(r_new.address),
                "igmpSnoopEnable": False,
                "interfaceIds": await self._interfaces(),
            }
            if d_new is not None:
                body["dhcpSettingsVO"] = self._dhcp(first, d_new, {}, own)
            desc = Described(
                f"create network {r_new.name} ({label}, {r_new.address})",
                "plan.omada.networkCreate",
                name=r_new.name,
                label=label,
                address=str(r_new.address),
            )
            shown = {k: v for k, v in body.items() if k != "interfaceIds"}
            return [Op(desc, "POST", lan, body, _shown(shown))]

        body = _config(net.raw)
        changed: dict[str, Any] = {}
        parts: list[str] = []
        dhcp_label: Label | None = None
        if r_new is not None:
            changed.update(
                name=r_new.name or net.name,
                purpose=1,
                vlanType=_int(net.raw.get("vlanType")) or 0,
                vlan=vlan or 1,
                gatewaySubnet=str(r_new.address),
            )
            if not body.get("interfaceIds"):
                changed["interfaceIds"] = await self._interfaces()
            parts.append(f"gateway {r_new.address}")
        old_dhcp = _dhcp_settings(net.raw)
        if dhcp is not None:
            if d_new is None:
                changed["dhcpSettingsVO"] = None
                parts.append("no DHCP")
                dhcp_label = Label("no DHCP", "omadaNoDhcp")
            else:
                if own is None:
                    raise AdapterError(
                        f"{first.id}: DHCP needs the network's gateway address",
                        message_id="omada.dhcpNeedsGateway",
                        params={"subject": first.id},
                    )
                changed["dhcpSettingsVO"] = self._dhcp(first, d_new, old_dhcp, own)
                parts.append("DHCP " + ("on" if d_new.enabled else "off"))
                dhcp_label = (
                    Label("DHCP on", "omadaDhcpOn")
                    if d_new.enabled
                    else Label("DHCP off", "omadaDhcpOff")
                )
        elif r_new is not None and old_dhcp:
            old_own = self._own(None, net)
            settings = dict(old_dhcp)
            if old_own and settings.get("gateway") == str(old_own) and own is not None:
                settings["gateway"] = str(own)  # the DHCP router follows the new address
                changed["dhcpSettingsVO"] = settings
        body.update(changed)
        text = f"network {body.get('name', net.name)} ({label}): " + ", ".join(parts)
        fields: dict[str, str] = {"name": str(body.get("name", net.name)), "label": label}
        if r_new is not None and dhcp_label is not None:
            fields |= {"gateway": str(r_new.address), "dhcp": dhcp_label}
            desc = Described(text, "plan.omada.networkGatewayDhcp", **fields)
        elif r_new is not None:
            fields["gateway"] = str(r_new.address)
            desc = Described(text, "plan.omada.networkGateway", **fields)
        else:
            assert dhcp_label is not None
            fields["dhcp"] = dhcp_label
            desc = Described(text, "plan.omada.networkDhcp", **fields)
        shown = {k: v for k, v in changed.items() if k != "interfaceIds"}
        return [Op(desc, "PATCH", f"{lan}/{net.id}", body, _shown(shown))]

    @staticmethod
    def _own(r_new: RouterValue | None, net: _Net | None) -> IPAddress | None:
        """The gateway's own address on the network after the change."""
        if r_new is not None:
            return r_new.address.ip
        try:
            return ip_interface(_text(net.raw.get("gatewaySubnet"))).ip if net else None
        except ValueError:
            return None

    @staticmethod
    def _dhcp(
        c: Change, v: DhcpValue, old: Mapping[str, Any], own: IPAddress | None
    ) -> dict[str, Any]:
        """DHCP settings that read back as ``v`` (unknown keys of ``old`` are kept)."""
        keys = (
            "enable", "ipaddrStart", "ipaddrEnd", "dhcpns", "priDns", "sndDns", "leasetime",
            "ipRangePool", "ipRangeStart", "ipRangeEnd",
        )  # fmt: skip
        out = {k: x for k, x in old.items() if k not in keys}
        ranges = old.get("ipRangePool")
        first = ranges[0] if isinstance(ranges, list) and ranges else old
        for k in ("ipaddrStart", "ipaddrEnd"):
            if isinstance(first, dict) and k in first:
                out[k] = first[k]
        if "leasetime" in old:
            out["leasetime"] = old["leasetime"]
        out["enable"] = v.enabled
        if v.pool is not None:
            out["ipaddrStart"], out["ipaddrEnd"] = str(v.pool[0]), str(v.pool[1])
        dns = list(v.dns or [])
        if own is not None and dns == [own]:
            out["dhcpns"] = "auto"  # the controller hands out the gateway
        else:
            if len(dns) > 2:
                raise AdapterError(
                    f"{c.id}: Omada hands out at most two DNS servers",
                    message_id="omada.dnsMax",
                    params={"subject": c.id},
                )
            out["dhcpns"] = "manual"
            for key, addr in zip(("priDns", "sndDns"), dns, strict=False):
                out[key] = str(addr)
        if v.lease_seconds is not None:
            if v.lease_seconds <= 0 or v.lease_seconds % 60:
                raise AdapterError(
                    f"{c.id}: Omada lease times are whole minutes",
                    message_id="omada.leaseMinutes",
                    params={"subject": c.id},
                )
            out["leasetime"] = v.lease_seconds // 60
        out.setdefault("leasetime", 120)  # the controller's default, 2 hours
        return out

    async def _network_ids(
        self, c: Change, vlans: list[int], strict: bool
    ) -> tuple[list[str], dict[str, str]]:
        """Network ids for VLANs (1: the native network) and the networks' names by id."""
        by_vlan = {n.vlan or 1: n for n in (await self.a._networks()).values()}
        ids = []
        names: dict[str, str] = {}
        for vlan in vlans:
            net = by_vlan.get(vlan)
            if net is None:
                if strict:
                    raise AdapterError(
                        f"{c.id}: the controller has no LAN network for VLAN {vlan} (create it "
                        "first: a segment with a gateway in the desired state)",
                        message_id="omada.noLanNetworkFor",
                        params={"subject": c.id, "vlan": vlan},
                    )
                ids.append(f"<network of VLAN {vlan}>")
                names[ids[-1]] = Label(
                    f"VLAN {vlan} (created earlier in this change)", "omadaVlanPending", vlan
                )
                continue
            ids.append(net.id)
            names[net.id] = net.name
        return ids, names

    async def _port(self, c: Change, strict: bool) -> Op:
        sw = await self._device(c, "switch")
        assert sw is not None
        number = c.key.removeprefix(f"{c.device_id}/port/")
        rows = await self.a._ports(sw.raw_mac)
        row = next((r for r in rows if str(r.get("port")) == number), None)
        if row is None or number == c.key:
            raise AdapterError(
                f"{c.id}: {sw.name} has no port {number}",
                message_id="omada.noPort",
                params={"subject": c.id, "switch": sw.name, "number": number},
            )
        new = c.new if isinstance(c.new, PortValue) else PortValue()
        if new.untagged is None:
            raise AdapterError(
                f"{c.id}: an Omada switch port always has a native (untagged) network",
                message_id="omada.portNeedsNative",
                params={"subject": c.id},
            )
        native = 1 if new.untagged == "native" else new.untagged
        if 1 in new.tagged:
            raise AdapterError(
                f"{c.id}: the native network (VLAN 1) cannot be sent tagged",
                message_id="omada.nativeNotTagged",
                params={"subject": c.id},
            )
        if native in new.tagged:
            raise AdapterError(
                f"{c.id}: VLAN {native} cannot be both untagged and tagged",
                message_id="write.vlanTaggedUntagged",
                params={"subject": c.id, "vlan": native},
            )
        tagged = sorted(set(new.tagged))
        ids, names = await self._network_ids(c, [native, *tagged], strict)
        nid, tids = ids[0], ids[1:]
        profiles = await self.a._optional_rows(f"{self.site}/lan-profiles")
        match = next(
            (
                p
                for p in profiles
                if p.get("nativeNetworkId") == nid
                and sorted(p.get("tagNetworkIds") or []) == sorted(tids)
            ),
            None,
        )
        body: dict[str, Any] = {
            "profileId": _text(match.get("id")) if match else row.get("profileId"),
            "profileOverrideEnable": match is None,
            "nativeNetworkId": nid,
            "tagNetworkIds": tids,
        }
        how = (
            Label(f"profile {match.get('name')}", "omadaProfile", match.get("name"))
            if match
            else Label("override of the profile", "omadaOverride")
        )
        tagged_names = [names[t] for t in tids]
        shown_tagged: str = (
            ", ".join(tagged_names)
            if len(tagged_names) > 1
            else (tagged_names[0] if tagged_names else Label("nothing", "omadaNothing"))
        )
        desc = Described(
            f"{sw.name} port {number}: native {names[nid]}, tagged {shown_tagged} ({how})",
            "plan.omada.port",
            switch=sw.name,
            number=number,
            native=names[nid],
            tagged=shown_tagged,
            how=how,
        )
        path = f"{self.site}/switches/{sw.raw_mac}/ports/{number}"
        return Op(desc, "PATCH", path, body, _shown(body))

    async def _wlan(self, c: Change, secrets: Mapping[str, str], strict: bool) -> list[Op]:
        ap = await self._device(c, "eap")
        assert ap is not None
        groups, primary = await self.a._wlan_groups()
        gid = ap.wlan_id if ap.wlan_id in groups else primary
        if gid is None:
            raise AdapterError(
                f"{c.id}: the site has no WLAN group",
                message_id="omada.noWlanGroup",
                params={"subject": c.id},
            )
        path = f"{self.site}/wireless-network/wlans/{gid}/ssids"
        ssids = await self.a._ssids(gid)
        row = next((s for s in ssids if _text(s.get("name")) == c.key), None)
        sharing = sorted(
            d.name
            for d in await self.a._devices()
            if d.kind == "eap" and (d.wlan_id if d.wlan_id in groups else primary) == gid
        )
        where = Label(
            f"in WLAN group {groups[gid]} (EAPs {', '.join(sharing)})",
            "omadaWlanWhere",
            groups[gid],
            ", ".join(sharing),
        )
        new = c.new if isinstance(c.new, WlanValue) else None
        if new is None:
            if row is None:
                return []
            sid = _text(row.get("ssidId") or row.get("id"))
            desc = Described(
                f"delete SSID {c.key} {where}", "plan.omada.ssidDelete", ssid=c.key, where=where
            )
            return [Op(desc, "DELETE", f"{path}/{sid}")]
        if new.security is Security.WPA3:
            raise AdapterError(
                f"{c.id}: Omada sets WPA3 only together with WPA2 (security wpa2-wpa3)",
                message_id="omada.wpa3Alone",
                params={"subject": c.id},
            )
        if new.security is Security.OWE:
            raise AdapterError(
                f"{c.id}: the controller does not report OWE back, so Signalbox cannot verify "
                "it and does not set it",
                message_id="omada.oweUnverifiable",
                params={"subject": c.id},
            )
        if new.security not in SECURITY:
            raise AdapterError(
                f"{c.id}: Signalbox cannot set {new.security.value} security on Omada",
                message_id="omada.securityUnsupported",
                params={"subject": c.id, "security": new.security.value},
            )
        # 802.11r is read since #447 (``enable11r``), so a value that is the SSID's own is no change
        current_r = _flag(row.get("enable11r")) if row is not None else False
        # 802.11k/v are site settings read since #469: the value they have is no change either
        site = wifi_extras.site_fields(
            await self.a._object(f"{self.site}/setting/roaming"), None, None
        )
        if (
            new.roaming_80211r not in (None, current_r)
            or new.roaming_80211k not in (None, site.get("roaming_80211k"))
            or new.roaming_80211v not in (None, site.get("roaming_80211v"))
        ):
            raise AdapterError(
                f"{c.id}: fast roaming (802.11r/k/v) is not changed on Omada",
                message_id="omada.roamingNotChanged",
                params={"subject": c.id},
            )
        if new.client_isolation is not None:
            raise AdapterError(
                f"{c.id}: client isolation is not read or changed on Omada",
                message_id="omada.isolationNotChanged",
                params={"subject": c.id},
            )
        mode, version = SECURITY[new.security]
        vlan = None if new.segment == "native" else new.segment
        if vlan is not None and vlan != 1:
            await self._network_ids(c, [vlan], strict)
        else:
            vlan = None
        old = _basic(row) if row else dict(SSID_DEFAULTS)
        body: dict[str, Any] = {**SSID_DEFAULTS, **old}
        body.update(
            name=new.ssid,
            security=mode,
            broadcast=not new.hidden,
            vlanEnable=vlan is not None,
        )
        if vlan is not None:
            body["vlanId"] = vlan
        else:
            body.pop("vlanId", None)
        if version is not None:
            kept = old.get("pskSetting")
            psk = dict(kept) if isinstance(kept, dict) else {}
            psk.update(versionPsk=version)
            psk.setdefault("encryptionPsk", 3)
            psk.setdefault("gikRekeyPskEnable", False)
            name = new.passphrase_secret
            if name:
                if name not in secrets:
                    raise AdapterError(
                        f"{c.id}: the secret {name!r} was not provided",
                        message_id="omada.secretMissing",
                        params={"subject": c.id, "name": repr(name)},
                    )
                key = secrets[name]
                if not 8 <= len(key) <= 63:
                    raise AdapterError(
                        f"{c.id}: a WPA passphrase has 8 to 63 characters",
                        message_id="omada.passphraseLength",
                        params={"subject": c.id},
                    )
                psk["securityKey"] = key
            elif not psk.get("securityKey"):  # the controller takes no WPA SSID without a key
                raise AdapterError(
                    f"{c.id}: a WPA SSID needs a passphrase (passphrase_secret in the desired "
                    "state)",
                    message_id="omada.passphraseNeeded",
                    params={"subject": c.id},
                )
            body["pskSetting"] = psk
        else:
            body.pop("pskSetting", None)
        pmf = PMF.get(new.pmf) if new.pmf else None
        body["pmfMode"] = pmf or old.get("pmfMode") or (2 if version else 3)
        if row is None:
            create = {**body, "deviceType": 1, "hidePwd": False, "ssidEnable": new.enabled}
            desc = Described(
                f"create SSID {c.key} {where}", "plan.omada.ssidCreate", ssid=c.key, where=where
            )
            return [Op(desc, "POST", path, create, _shown(create))]
        sid = _text(row.get("ssidId") or row.get("id"))
        out = []
        if body != _basic(row):
            update = f"{path}/{sid}/update-basic-config"
            desc = Described(
                f"SSID {c.key} {where}", "plan.omada.ssidUpdate", ssid=c.key, where=where
            )
            out.append(Op(desc, "PATCH", update, body, _shown(body)))
        if new.enabled != (row.get("ssidEnable") is not False):
            on = {"ssidEnable": new.enabled}
            desc = Described(
                f"SSID {c.key} {where}: " + ("on" if new.enabled else "off"),
                "plan.omada.ssidOn" if new.enabled else "plan.omada.ssidOff",
                ssid=c.key,
                where=where,
            )
            enable = f"{self.site}/wireless-network/ssids/{sid}/enable"
            out.append(Op(desc, "PATCH", enable, on, _shown(on)))
        return out

    # --- WritesConfig -----------------------------------------------------------------------

    async def plan_changes(
        self, changes: list[Change], secrets: Mapping[str, str]
    ) -> list[VendorCall]:
        await self.connect()
        return [op.call() for op in await self.ops(changes, secrets, strict=False)]

    async def apply(self, changes: list[Change], secrets: Mapping[str, str]) -> ApplyResult:
        await self.connect()
        ops = await self.ops(changes, secrets, strict=True)
        for op in ops:
            await self.send(op.method, op.path, op.body)
        return ApplyResult(calls=[op.call() for op in ops])

    async def _state(self) -> dict[str, Any]:
        groups, _ = await self.a._wlan_groups()
        return {
            "site": self.site,
            "lan_networks": await self.a._rows(f"{self.site}/lan-networks"),
            "ssids": {gid: await self.a._ssids(gid) for gid in groups},
            "ports": {
                sw.raw_mac: await self.a._ports(sw.raw_mac)
                for sw in await self.a._devices()
                if sw.kind == "switch"
            },
        }

    async def backup(self) -> Backup:
        """The objects a change may touch; the SSIDs with their passphrases (the backup is
        stored encrypted), so that a restore can put them back."""
        await self.connect()
        return Backup(
            device_id=self.a.context.device_id,
            taken_at=datetime.now(UTC),
            format=BACKUP_FORMAT,
            content=json.dumps(await self._state(), sort_keys=True),
        )

    async def restore(self, backup: Backup) -> None:
        if backup.format != BACKUP_FORMAT:
            raise AdapterError(
                f"cannot restore a backup in the format {backup.format!r}",
                message_id="omada.restoreFormat",
                params={"format": repr(backup.format)},
            )
        try:
            saved = _dict(json.loads(backup.content), "backup", "the backup")
            nets_saved = [_dict(r, "backup", "a network") for r in saved["lan_networks"]]
            ssids_saved = {
                str(g): [_dict(r, "backup", "an SSID") for r in rows]
                for g, rows in _dict(saved["ssids"], "backup", "ssids").items()
            }
            ports_saved = {
                str(m): [_dict(r, "backup", "a port") for r in rows]
                for m, rows in _dict(saved["ports"], "backup", "ports").items()
            }
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise AdapterError(
                f"the backup is not an Omada backup: {exc}",
                message_id="omada.restoreInvalid",
                params={"detail": str(exc)},
            ) from exc
        await self.connect()
        if saved.get("site") != self.site:
            raise AdapterError(
                "the backup is of another controller or site", message_id="omada.restoreOther"
            )
        ids = await self._restore_networks(nets_saved)
        for mac, rows in ports_saved.items():
            await self._restore_ports(mac, rows, ids)
        for gid, rows in ssids_saved.items():
            await self._restore_ssids(gid, rows)
        keep = set(ids.values()) | {_text(r.get("id")) for r in nets_saved}
        for row in await self.a._rows(f"{self.site}/lan-networks"):
            if _text(row.get("id")) not in keep:
                await self.send("DELETE", f"{self.site}/lan-networks/{_text(row.get('id'))}")

    @staticmethod
    def _same_network(have: Mapping[str, Any], want: Mapping[str, Any]) -> bool:
        def dhcp(row: Mapping[str, Any]) -> dict[str, Any]:
            d = _dhcp_settings(dict(row))
            skip = ("ipRangeStart", "ipRangeEnd", "options")
            return {k: v for k, v in d.items() if k not in skip}

        return all(have.get(k) == want.get(k) for k in NETWORK_COMPARED) and dhcp(have) == dhcp(
            want
        )

    async def _restore_networks(self, saved: list[dict[str, Any]]) -> dict[str, str]:
        """Networks of the backup back (changed ones patched, missing ones created); returns
        backup id → id on the controller. A network created since that has the VLAN of a
        missing one takes its place (a VLAN is only used once)."""
        path = f"{self.site}/lan-networks"
        current = {_text(r.get("id")): r for r in await self.a._rows(path)}
        saved_ids = {_text(r.get("id")) for r in saved}
        spare = {r.get("vlan"): i for i, r in current.items() if i not in saved_ids}
        ids: dict[str, str] = {}
        for row in saved:
            bid = _text(row.get("id"))
            cid = bid if bid in current else spare.pop(row.get("vlan"), None)
            if cid is None:
                result = await self.send("POST", path, _config(row))
                cid = self._new_id(result, path)
            elif not self._same_network(current[cid], row):
                body = _config(row)
                for gone in ("gatewaySubnet", "dhcpSettingsVO"):
                    if gone not in body and _config(current[cid]).get(gone) is not None:
                        body[gone] = None
                await self.send("PATCH", f"{path}/{cid}", body)
            ids[bid] = cid
        return ids

    @staticmethod
    def _new_id(result: Any, path: str) -> str:
        if isinstance(result, dict):
            new = _text(result.get("id") or result.get("networkId") or result.get("ssidId"))
        else:
            new = _text(result)
        if not new:
            raise AdapterError(
                f"{path}: the controller did not say which id it created",
                message_id="omada.noCreatedId",
                params={"path": path},
            )
        return new

    async def _restore_ports(
        self, mac: str, saved: list[dict[str, Any]], ids: Mapping[str, str]
    ) -> None:
        path = f"{self.site}/switches/{mac}/ports"
        current = {str(r.get("port")): r for r in await self.a._ports(mac)}
        for row in saved:
            have = current.get(str(row.get("port")))
            if have is None:
                continue  # the switch is gone or smaller: nothing to put back
            want: dict[str, Any] = {}
            for key in PORT_KEYS:
                if key not in row:
                    continue
                value = row[key]
                if key == "nativeNetworkId":
                    value = ids.get(value, value)
                elif key == "tagNetworkIds" and isinstance(value, list):
                    value = [ids.get(v, v) for v in value]
                want[key] = value
            body = {k: v for k, v in want.items() if have.get(k) != v}
            body.update({k: None for k in PORT_KEYS if k in have and k not in want})
            if body:
                await self.send("PATCH", f"{path}/{row.get('port')}", body)

    async def _restore_ssids(self, gid: str, saved: list[dict[str, Any]]) -> None:
        path = f"{self.site}/wireless-network/wlans/{gid}/ssids"
        current = {_text(r.get("ssidId") or r.get("id")): r for r in await self.a._ssids(gid)}
        saved_ids = {_text(r.get("ssidId") or r.get("id")) for r in saved}
        for sid in current:
            if sid not in saved_ids:
                await self.send("DELETE", f"{path}/{sid}")
        for row in saved:
            sid = _text(row.get("ssidId") or row.get("id"))
            basic = _basic(row)
            enabled = row.get("ssidEnable") is not False
            have = current.get(sid)
            if have is None:
                create = {**SSID_DEFAULTS, "hidePwd": False, **basic, "deviceType": 1}
                create["ssidEnable"] = enabled
                create.setdefault("pmfMode", 2 if basic.get("security") == 3 else 3)
                await self.send("POST", path, create)
                continue
            if _basic(have) != basic:
                body = {**SSID_DEFAULTS, **basic}
                body.setdefault("pmfMode", _basic(have).get("pmfMode") or 3)
                await self.send("PATCH", f"{path}/{sid}/update-basic-config", body)
            if (have.get("ssidEnable") is not False) != enabled:
                enable = f"{self.site}/wireless-network/ssids/{sid}/enable"
                await self.send("PATCH", enable, {"ssidEnable": enabled})
