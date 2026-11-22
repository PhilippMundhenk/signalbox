"""TP-Link Omada (write): changes through the controller's Open API (issue #44).

Changes name the devices the controller manages (``<controller>/<type>-<mac>``, ADR 0004); the
deployment hands them to the controller's adapter, which turns them into Open API calls:

- ``router`` and ``dhcp`` of the gateway → create, change or remove a LAN network (name, VLAN,
  gateway address and subnet) and its DHCP settings; one call per network
- ``port`` of a switch → the port's native (untagged) network and tagged networks: the port
  profile with exactly these networks if there is one, else a port-level override
- ``wlan`` of an EAP → create, change or remove the SSID in the EAP's WLAN group (security,
  passphrase, PMF, VLAN, hidden, enabled). An SSID belongs to the WLAN group, so the change
  reaches every EAP of the group; the review says which.

The controller provisions the devices by itself, later; Signalbox verifies what the controller
reports, which is also what the read side reads. Endpoint paths and bodies are guesses from the
Open API documentation (docs/adapters/omada.md), like the read side's.

A backup is the JSON of every controller object a change may touch (LAN networks, the SSIDs of
every WLAN group, the ports of every switch); restoring compares it with the controller and
creates, changes and deletes objects until they match.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_interface
from typing import TYPE_CHECKING, Any

from pydantic import JsonValue

from signalbox.adapters import AdapterError, ApplyResult, Backup, VendorCall
from signalbox.adapters.omada import (
    OmadaError,
    TokenRefused,
    _check,
    _dict,
    _Managed,
    _Net,
    _text,
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
#: Security → Omada ``security`` and ``pskSetting.versionPsk`` (guesses but 0 and 3).
SECURITY: dict[Security, tuple[int, int | None]] = {
    Security.OPEN: (0, None),
    Security.OWE: (1, None),
    Security.WPA2: (3, 2),
    Security.WPA3: (3, 4),
    Security.WPA2_WPA3: (3, 5),
}
PMF = {Pmf.REQUIRED: 1, Pmf.OPTIONAL: 2, Pmf.DISABLED: 3}
#: ``band`` of a new SSID: 2.4 and 5 GHz (guess; 6 GHz needs WPA3 or OWE).
NEW_SSID_BAND = 3
#: Keys of a switch port that a port change writes (and a restore puts back).
PORT_KEYS = ("profileId", "profileOverrideEnable", "nativeNetworkId", "tagNetworkIds")
#: Error codes of a refused permission (guess); the message then names the role.
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
            description=self.description, method=self.method, target=self.path, payload=self.shown
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
        raise AdapterError(f"{change.id}: {change.key} is not a segment of site {site}")
    return None if rest == "native" else int(rest)


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
                " (changes need an Open API client with an administrator role)"
                if exc.code in PERMISSION_CODES or "ermission" in str(exc)
                else ""
            )
            raise AdapterError(f"{method} {path}: the controller refused: {exc}{hint}") from exc
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
            f"{change.id}: {change.device_id} is not a {kind} managed by this controller"
        )

    async def _uses(self, net_id: str, vlan: int | None) -> bool:
        """Whether a port, port profile or SSID still uses a network."""
        rows = list(await self.a._optional_rows(f"{self.site}/lan-profiles"))
        for sw in (d for d in await self.a._devices() if d.kind == "switch"):
            rows += await self.a._rows(f"{self.site}/switches/{sw.raw_mac}/ports")
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
                raise AdapterError(f"{c.id}: the Omada integration cannot change {c.kind.value}")
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
            raise AdapterError(f"{first.id}: VLAN {r_new.vlan} does not match {key}")
        nets = await self.a._networks()
        net = next((n for n in nets.values() if n.segment == key), None)
        label = f"VLAN {vlan}" if vlan else "the native network"
        lan = f"{self.site}/lan-networks"

        if router is not None and r_new is None:  # remove the router interface
            if d_new is not None:
                raise AdapterError(f"{first.id}: DHCP needs the network's gateway address")
            if net is None:
                return []
            if vlan is None:
                raise AdapterError(f"{first.id}: the native network cannot be removed")
            if await self._uses(net.id, net.vlan):
                body: dict[str, Any] = {"purpose": "vlan", "gatewaySubnet": None}
                body["dhcpSettings"] = None
                desc = f"network {net.name} ({label}): VLAN only, no gateway address or DHCP"
                return [Op(desc, "PATCH", f"{lan}/{net.id}", body, _shown(body))]
            desc = f"delete network {net.name} ({label})"
            return [Op(desc, "DELETE", f"{lan}/{net.id}")]

        own = self._own(r_new, net)
        if net is None:
            if r_new is None:
                raise AdapterError(f"{first.id}: there is no LAN network for {label}")
            if not r_new.name:
                raise AdapterError(
                    f"{first.id}: an Omada network needs a name (set name: in the desired state)"
                )
            body = {
                "name": r_new.name,
                "purpose": "interface",
                "vlan": vlan or 1,
                "gatewaySubnet": str(r_new.address),
            }
            if d_new is not None:
                body["dhcpSettings"] = self._dhcp(first, d_new, {}, own)
            desc = f"create network {r_new.name} ({label}, {r_new.address})"
            return [Op(desc, "POST", lan, body, _shown(body))]

        body = {}
        parts = []
        if r_new is not None:
            body.update(
                name=r_new.name or net.name,
                purpose="interface",
                vlan=vlan or 1,
                gatewaySubnet=str(r_new.address),
            )
            parts.append(f"gateway {r_new.address}")
        if dhcp is not None:
            if d_new is None:
                body["dhcpSettings"] = None
                parts.append("no DHCP")
            else:
                if own is None:
                    raise AdapterError(f"{first.id}: DHCP needs the network's gateway address")
                old = net.raw.get("dhcpSettings")
                body["dhcpSettings"] = self._dhcp(first, d_new, old or {}, own)
                parts.append("DHCP " + ("on" if d_new.enabled else "off"))
        elif r_new is not None and isinstance(net.raw.get("dhcpSettings"), dict):
            old_own = self._own(None, net)
            settings = dict(net.raw["dhcpSettings"])
            if old_own and settings.get("gateway") == str(old_own) and own is not None:
                settings["gateway"] = str(own)  # the DHCP router follows the new address
                body["dhcpSettings"] = settings
        desc = f"network {body.get('name', net.name)} ({label}): " + ", ".join(parts)
        return [Op(desc, "PATCH", f"{lan}/{net.id}", body, _shown(body))]

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
        keys = ("enable", "ipaddrStart", "ipaddrEnd", "dhcpns", "priDns", "sndDns", "leasetime")
        out = {k: x for k, x in old.items() if k not in keys}
        out["enable"] = v.enabled
        if v.pool is not None:
            out["ipaddrStart"], out["ipaddrEnd"] = str(v.pool[0]), str(v.pool[1])
        dns = list(v.dns or [])
        if own is not None and dns == [own]:
            out["dhcpns"] = "auto"  # the controller hands out the gateway
        else:
            if len(dns) > 2:
                raise AdapterError(f"{c.id}: Omada hands out at most two DNS servers")
            out["dhcpns"] = "manual"
            for key, addr in zip(("priDns", "sndDns"), dns, strict=False):
                out[key] = str(addr)
        if v.lease_seconds is not None:
            if v.lease_seconds <= 0 or v.lease_seconds % 60:
                raise AdapterError(f"{c.id}: Omada lease times are whole minutes")
            out["leasetime"] = v.lease_seconds // 60
        return out

    async def _network_ids(
        self, c: Change, vlans: list[int], strict: bool
    ) -> tuple[list[str], dict[str, str]]:
        """Network ids for VLANs (1: the native network) and the networks' names by id."""
        by_vlan = {n.vlan or 1: n for n in (await self.a._networks()).values()}
        ids = []
        names = {}
        for vlan in vlans:
            net = by_vlan.get(vlan)
            if net is None:
                if strict:
                    raise AdapterError(
                        f"{c.id}: the controller has no LAN network for VLAN {vlan} (create it "
                        "first: a segment with a gateway in the desired state)"
                    )
                ids.append(f"<network of VLAN {vlan}>")
                names[ids[-1]] = f"VLAN {vlan} (created earlier in this change)"
                continue
            ids.append(net.id)
            names[net.id] = net.name
        return ids, names

    async def _port(self, c: Change, strict: bool) -> Op:
        sw = await self._device(c, "switch")
        assert sw is not None
        number = c.key.removeprefix(f"{c.device_id}/port/")
        rows = await self.a._rows(f"{self.site}/switches/{sw.raw_mac}/ports")
        row = next((r for r in rows if str(r.get("port")) == number), None)
        if row is None or number == c.key:
            raise AdapterError(f"{c.id}: {sw.name} has no port {number}")
        new = c.new if isinstance(c.new, PortValue) else PortValue()
        if new.untagged is None:
            raise AdapterError(
                f"{c.id}: an Omada switch port always has a native (untagged) network"
            )
        native = 1 if new.untagged == "native" else new.untagged
        if 1 in new.tagged:
            raise AdapterError(f"{c.id}: the native network (VLAN 1) cannot be sent tagged")
        if native in new.tagged:
            raise AdapterError(f"{c.id}: VLAN {native} cannot be both untagged and tagged")
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
        how = f"profile {match.get('name')}" if match else "override of the profile"
        desc = (
            f"{sw.name} port {number}: native {names[nid]}, tagged "
            + (", ".join(names[t] for t in tids) or "nothing")
            + f" ({how})"
        )
        path = f"{self.site}/switches/{sw.raw_mac}/ports/{number}"
        return Op(desc, "PATCH", path, body, _shown(body))

    async def _wlan(self, c: Change, secrets: Mapping[str, str], strict: bool) -> list[Op]:
        ap = await self._device(c, "eap")
        assert ap is not None
        groups, primary = await self.a._wlan_groups()
        gid = ap.wlan_id if ap.wlan_id in groups else primary
        if gid is None:
            raise AdapterError(f"{c.id}: the site has no WLAN group")
        path = f"{self.site}/wireless-network/wlans/{gid}/ssids"
        ssids = await self.a._rows(path)
        row = next((s for s in ssids if _text(s.get("name")) == c.key), None)
        sharing = sorted(
            d.name
            for d in await self.a._devices()
            if d.kind == "eap" and (d.wlan_id if d.wlan_id in groups else primary) == gid
        )
        where = f"in WLAN group {groups[gid]} (EAPs {', '.join(sharing)})"
        new = c.new if isinstance(c.new, WlanValue) else None
        if new is None:
            if row is None:
                return []
            sid = _text(row.get("ssidId") or row.get("id"))
            return [Op(f"delete SSID {c.key} {where}", "DELETE", f"{path}/{sid}")]
        if new.security not in SECURITY:
            raise AdapterError(
                f"{c.id}: Signalbox cannot set {new.security.value} security on Omada"
            )
        if any(x is not None for x in (new.roaming_80211r, new.roaming_80211k, new.roaming_80211v)):
            raise AdapterError(f"{c.id}: fast roaming (802.11r/k/v) is not changed on Omada")
        mode, version = SECURITY[new.security]
        vlan = None if new.segment == "native" else new.segment
        if vlan is not None and vlan != 1:
            await self._network_ids(c, [vlan], strict)
        else:
            vlan = None
        body: dict[str, Any] = {
            "name": new.ssid,
            "security": mode,
            "broadcast": not new.hidden,
            "enable": new.enabled,
            "vlanEnable": vlan is not None,
            "vlanId": vlan,
            "pmfMode": PMF.get(new.pmf) if new.pmf else None,
        }
        if version is not None:  # (open and OWE leave the WPA settings, and the key, alone)
            kept = row.get("pskSetting") if row else None
            psk = dict(kept) if isinstance(kept, dict) else {}
            psk["versionPsk"] = version
            name = new.passphrase_secret
            if name:
                if name not in secrets:
                    raise AdapterError(f"{c.id}: the secret {name!r} was not provided")
                key = secrets[name]
                if not 8 <= len(key) <= 63:
                    raise AdapterError(f"{c.id}: a WPA passphrase has 8 to 63 characters")
                psk["securityKey"] = key
            elif not psk.keys() - {"versionPsk"}:  # nothing kept: there is no key to keep
                raise AdapterError(
                    f"{c.id}: a WPA SSID needs a passphrase (passphrase_secret in the desired "
                    "state)"
                )
            body["pskSetting"] = psk
        if row is None:
            body = {k: v for k, v in body.items() if v is not None}
            body["band"] = NEW_SSID_BAND
            return [Op(f"create SSID {c.key} {where}", "POST", path, body, _shown(body))]
        sid = _text(row.get("ssidId") or row.get("id"))
        return [Op(f"SSID {c.key} {where}", "PATCH", f"{path}/{sid}", body, _shown(body))]

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
            "ssids": {
                gid: await self.a._rows(f"{self.site}/wireless-network/wlans/{gid}/ssids")
                for gid in groups
            },
            "ports": {
                sw.raw_mac: await self.a._rows(f"{self.site}/switches/{sw.raw_mac}/ports")
                for sw in await self.a._devices()
                if sw.kind == "switch"
            },
        }

    async def backup(self) -> Backup:
        await self.connect()
        return Backup(
            device_id=self.a.context.device_id,
            taken_at=datetime.now(UTC),
            format=BACKUP_FORMAT,
            content=json.dumps(await self._state(), sort_keys=True),
        )

    async def restore(self, backup: Backup) -> None:
        if backup.format != BACKUP_FORMAT:
            raise AdapterError(f"cannot restore a backup in the format {backup.format!r}")
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
            raise AdapterError(f"the backup is not an Omada backup: {exc}") from exc
        await self.connect()
        if saved.get("site") != self.site:
            raise AdapterError("the backup is of another controller or site")
        ids = await self._restore_networks(nets_saved)
        for mac, rows in ports_saved.items():
            await self._restore_ports(mac, rows, ids)
        for gid, rows in ssids_saved.items():
            await self._restore_rows(
                f"{self.site}/wireless-network/wlans/{gid}/ssids", rows, "ssidId"
            )
        keep = set(ids.values()) | {_text(r.get("id")) for r in nets_saved}
        for row in await self.a._rows(f"{self.site}/lan-networks"):
            if _text(row.get("id")) not in keep:
                await self.send("DELETE", f"{self.site}/lan-networks/{_text(row.get('id'))}")

    @staticmethod
    def _diff(have: Mapping[str, Any], want: Mapping[str, Any], skip: str) -> dict[str, Any]:
        out = {k: v for k, v in want.items() if k != skip and have.get(k) != v}
        out.update({k: None for k in have if k not in want and k != skip})
        return out

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
                result = await self.send("POST", path, {k: v for k, v in row.items() if k != "id"})
                cid = self._new_id(result, path)
            else:
                body = self._diff(current[cid], row, "id")
                if body:
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
            raise AdapterError(f"{path}: the controller did not say which id it created")
        return new

    async def _restore_ports(
        self, mac: str, saved: list[dict[str, Any]], ids: Mapping[str, str]
    ) -> None:
        path = f"{self.site}/switches/{mac}/ports"
        current = {str(r.get("port")): r for r in await self.a._rows(path)}
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

    async def _restore_rows(self, path: str, saved: list[dict[str, Any]], key: str) -> None:
        current = {_text(r.get(key)): r for r in await self.a._rows(path)}
        saved_ids = {_text(r.get(key)) for r in saved}
        for rid in current:
            if rid not in saved_ids:
                await self.send("DELETE", f"{path}/{rid}")
        for row in saved:
            rid = _text(row.get(key))
            if rid in current:
                body = self._diff(current[rid], row, key)
                if body:
                    await self.send("PATCH", f"{path}/{rid}", body)
            else:
                await self.send("POST", path, {k: v for k, v in row.items() if k != key})
