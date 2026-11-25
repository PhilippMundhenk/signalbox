"""Contract checks every adapter must pass against its simulator.

Use from an adapter's tests::

    from signalbox.testing import assert_contract

    async def test_contract(simulator):
        adapter = MyAdapter(context_for(simulator))
        snapshot = await assert_contract(adapter)
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from pydantic import SecretStr

from signalbox.adapters import Adapter, Capability, check_manifest
from signalbox.factory_defaults import FACTORY_DEFAULTS
from signalbox.model import (
    FDB_LIMIT,
    ROUTE_LIMIT,
    SCAN_LIMIT,
    TYPED_OPTION_CODES,
    Band,
    Cipher,
    Client,
    Device,
    DeviceAccount,
    DeviceHealth,
    DeviceMulticast,
    DeviceStatus,
    DeviceTime,
    DhcpRelay,
    DhcpServer,
    FdbEntry,
    Firewall,
    FirewallChain,
    FirewallProtocol,
    LeaseState,
    LinkKind,
    LinkOrigin,
    LogKind,
    LogTarget,
    LogTransport,
    ManagementService,
    Membership,
    NatClass,
    Port,
    PortKind,
    PortRole,
    Radio,
    Security,
    ServiceKind,
    ServiceTransport,
    Snapshot,
    StpBridge,
    Tunnel,
    Uplink,
    UplinkKind,
    WifiScanResult,
    Wlan,
    address_nat_class,
    firewall_id,
    parse_stp_bridge_id,
    scan_id,
    set_passphrase_digest_key,
    source_fits,
)

#: Key of :func:`passphrase_digest_key` unless a test passes its own.
TEST_DIGEST_KEY = b"signalbox-test-passphrase-digest"


@contextmanager
def passphrase_digest_key(key: bytes = TEST_DIGEST_KEY) -> Iterator[bytes]:
    """Within the block :func:`signalbox.model.passphrase_digest` uses ``key`` (as the service
    does with its vault-derived key); outside it the previous key (normally none) is back."""
    old = set_passphrase_digest_key(key)
    try:
        yield key
    finally:
        set_passphrase_digest_key(old)


#: Modes with a pre-shared passphrase (``other`` may be one the model has no name for).
PERSONAL_SECURITY = {
    Security.WPA,
    Security.WPA_WPA2,
    Security.WPA2,
    Security.WPA3,
    Security.WPA2_WPA3,
    Security.OTHER,
}
#: Modes that can use SAE.
SAE_SECURITY = {Security.WPA3, Security.WPA2_WPA3, Security.OTHER}


def _aware(value: object) -> bool:
    return getattr(value, "tzinfo", None) is not None


def health_problems(device_id: str, health: DeviceHealth) -> list[str]:
    """Inconsistent health values (used above total, naive times, empty names)."""
    out: list[str] = []
    total, used = health.memory_total_bytes, health.memory_used_bytes
    if total is not None and used is not None and used > total:
        out.append(f"{device_id}: memory used {used} > total {total}")
    for st in health.storage:
        if (
            st.total_bytes is not None
            and st.used_bytes is not None
            and st.used_bytes > st.total_bytes
        ):
            out.append(
                f"{device_id}: storage {st.name} used {st.used_bytes} > total {st.total_bytes}"
            )
    names = [
        *(x.name for x in health.storage),
        *(x.name for x in health.temperatures),
        *(x.name for x in health.fans),
        *(x.name for x in health.power_supplies),
        *(x.name for x in health.ups),
    ]
    if any(not n.strip() for n in names):
        out.append(f"{device_id}: a storage, sensor, fan, power supply or UPS has no name")
    for when in (health.boot_time, *(u.last_test for u in health.ups)):
        if when is not None and not _aware(when):
            out.append(f"{device_id}: health time {when} has no time zone")
    return out


def port_problems(port: Port) -> list[str]:
    """Inconsistent port details (#156): speed above the maximum, a disabled port with link."""
    out: list[str] = []
    top = port.max_speed_mbps
    if top is not None and port.speed_mbps is not None and port.speed_mbps > top:
        out.append(f"port {port.id}: speed {port.speed_mbps} > max speed {top}")
    if top is not None and any(s > top for s in port.advertised_speeds_mbps):
        out.append(f"port {port.id}: advertises a speed above its max speed {top}")
    if port.admin_up is False and port.up:
        out.append(f"port {port.id}: link up on a disabled port")
    if port.kind is PortKind.WIRELESS and port.media is not None:
        out.append(f"port {port.id}: wireless port with a wired medium")
    return out


#: Port kind a role implies (#252): a bridge is a bridge, a Wi-Fi interface is wireless.
_ROLE_KINDS = {
    PortRole.BRIDGE: PortKind.BRIDGE,
    PortRole.WIRELESS: PortKind.WIRELESS,
    PortRole.LAG: PortKind.LAG,
}


def _in_lag(port: Port, ports: Sequence[Port]) -> bool:
    return bool(port.lag) or any(
        p.role is PortRole.LAG and port.id in p.lower for p in ports if p.id != port.id
    )


def structure_problems(ports: Sequence[Port], wlans: Sequence[Wlan] = ()) -> list[str]:
    """The internal port structure (#252, ADR 0008): ``lower`` names ports of the same device
    that were reported, no port runs on itself (also not through others), roles fit kinds,
    an SSID's interface is a Wi-Fi port of its device."""
    out: list[str] = []
    by_id = {p.id: p for p in ports}
    for p in ports:
        if len(set(p.lower)) != len(p.lower):
            out.append(f"port {p.id}: lower lists a port twice")
        for low in p.lower:
            other = by_id.get(low)
            if other is None:
                out.append(f"port {p.id}: lower port {low} is not reported")
            elif other.device_id != p.device_id:
                out.append(f"port {p.id}: lower port {low} belongs to another device")
        want = _ROLE_KINDS.get(p.role) if p.role is not None else None
        if want is not None and p.kind is not want:
            out.append(f"port {p.id}: role {p.role} with kind {p.kind.value}")
        if p.role is PortRole.VLAN and len(p.lower) > 1:
            out.append(f"port {p.id}: a VLAN interface runs on one port, not {len(p.lower)}")
        # link aggregation (#157): LAG settings on a LAG, a member state on a member
        is_lag = p.kind is PortKind.LAG or p.role is PortRole.LAG
        lag_fields = (p.lag_mode, p.hash_policy, p.min_links, p.lacp_rate)
        if not is_lag and any(v is not None for v in lag_fields):
            out.append(f"port {p.id}: LAG settings on a port that is not a LAG")
        if p.lacp_rate is not None and p.lag_mode is not None and not p.lag_mode.lacp:
            out.append(f"port {p.id}: LACP rate on a LAG without LACP")
        if p.lag_member_state is not None and (is_lag or not _in_lag(p, ports)):
            out.append(f"port {p.id}: LAG member state on a port that is not a LAG member")
    # cycles: follow lower from every port
    state: dict[str, int] = {}  # 1: on the path, 2: done

    def visit(pid: str) -> bool:
        if state.get(pid) == 1:
            return True
        if state.get(pid) == 2 or pid not in by_id:
            return False
        state[pid] = 1
        cyclic = any(visit(x) for x in by_id[pid].lower)
        state[pid] = 2
        return cyclic

    for pid in sorted(by_id):
        if pid not in state and visit(pid):
            out.append(f"port {pid}: lower ports form a cycle")
    for w in wlans:
        if w.port_id is None:
            continue
        # the interface may be missing from the ports (netifd lists Wi-Fi interfaces it
        # bridges), but it is one of the device's
        port = by_id.get(w.port_id)
        if not w.port_id.startswith(f"{w.device_id}/port/"):
            out.append(f"wlan {w.id}: port {w.port_id} is not a port of its device")
        elif port is not None and port.kind is not PortKind.WIRELESS:
            out.append(f"wlan {w.id}: port {w.port_id} is not a Wi-Fi interface")
    return out


def radio_problems(radio: Radio) -> list[str]:
    """Inconsistent radio capabilities (#167)."""
    out: list[str] = []
    sup = radio.supported_security
    if sup is not None and not sup:
        out.append(f"radio {radio.id}: empty supported_security (None: not reported)")
    if sup is not None and len(set(sup)) != len(sup):
        out.append(f"radio {radio.id}: supported_security lists a mode twice")
    # capabilities and state (#172): lists are None or non-empty, the state fits them
    for name in ("standards", "supported_channels", "supported_widths_mhz"):
        values = getattr(radio, name)
        if values is not None and (not values or len(set(values)) != len(values)):
            out.append(f"radio {radio.id}: {name} empty or with duplicates (None: not reported)")
    if radio.standard is not None and radio.standards and radio.standard not in radio.standards:
        out.append(f"radio {radio.id}: standard {radio.standard.value} is not in its standards")
    widths = radio.supported_widths_mhz
    if radio.width_mhz is not None and widths and radio.width_mhz not in widths:
        out.append(f"radio {radio.id}: width {radio.width_mhz} MHz is not a supported width")
    busy, other = radio.channel_utilisation_pct, radio.interference_pct
    if busy is not None and other is not None and other > busy:
        out.append(f"radio {radio.id}: interference_pct above channel_utilisation_pct")
    if radio.dfs_state is not None and radio.band is not Band.GHZ_5:
        out.append(f"radio {radio.id}: dfs_state outside 5 GHz")
    return out


def wlan_problems(wlan: Wlan, radio: Radio | None = None) -> list[str]:
    """Inconsistent Wi-Fi security details (#167): a digest without a passphrase, WEP ciphers
    on a WPA network, WPS methods while WPS is off, a mode the radio says it cannot offer."""
    out: list[str] = []
    sec = wlan.security
    if wlan.passphrase_digest is not None and sec not in PERSONAL_SECURITY:
        out.append(f"wlan {wlan.id}: passphrase digest with security {sec.value}")
    if wlan.passphrase_fingerprint is not None and sec not in PERSONAL_SECURITY:
        out.append(f"wlan {wlan.id}: passphrase fingerprint with security {sec.value}")
    ciphers = wlan.ciphers
    if ciphers is not None:
        if not ciphers and sec is not Security.OPEN:
            out.append(f"wlan {wlan.id}: empty ciphers (None: not reported)")
        if len(set(ciphers)) != len(ciphers):
            out.append(f"wlan {wlan.id}: ciphers list a cipher twice")
        if ciphers and sec is Security.OPEN:
            out.append(f"wlan {wlan.id}: an open network has no ciphers")
        if sec is Security.WEP and set(ciphers) - {Cipher.WEP}:
            out.append(f"wlan {wlan.id}: a WEP network with other ciphers than wep")
        if sec is not Security.WEP and sec is not Security.OTHER and Cipher.WEP in ciphers:
            out.append(f"wlan {wlan.id}: cipher wep with security {sec.value}")
    if sec is Security.OPEN and wlan.group_cipher is not None:
        out.append(f"wlan {wlan.id}: an open network has no group cipher")
    if wlan.sae is not None and sec not in SAE_SECURITY:
        out.append(f"wlan {wlan.id}: SAE settings with security {sec.value}")
    if wlan.wps is not None and not wlan.wps.enabled and wlan.wps.methods:
        out.append(f"wlan {wlan.id}: WPS methods while WPS is off")
    sup = radio.supported_security if radio is not None else None
    if sup and sec is not Security.OTHER and sec not in sup:
        out.append(f"wlan {wlan.id}: {sec.value} is not in its radio's supported_security")
    return out


def uplink_problems(uplink: Uplink, port_ids: set[str]) -> list[str]:
    """Inconsistent uplink values (#148): ids, naive times, a bridge with addresses."""
    out: list[str] = []
    prefix = f"{uplink.device_id}/uplink/"
    if not uplink.id.startswith(prefix) or uplink.id == prefix:
        out.append(f"uplink id {uplink.id} is not {prefix}<name>")
    if uplink.port_id is not None and uplink.port_id not in port_ids:
        out.append(f"uplink {uplink.id} on unknown port {uplink.port_id}")
    if uplink.since is not None and not _aware(uplink.since):
        out.append(f"uplink {uplink.id}: since {uplink.since} has no time zone")
    if uplink.up is False and uplink.since is not None:
        out.append(f"uplink {uplink.id}: down but connected since {uplink.since}")
    if uplink.kind is UplinkKind.BRIDGE and (uplink.addresses or uplink.upstream_gateway):
        out.append(f"uplink {uplink.id}: a bridge has no addresses or gateway of its own")
    public = uplink.public_ipv4
    if public is not None and address_nat_class(public) is not NatClass.PUBLIC:
        out.append(f"uplink {uplink.id}: public_ipv4 {public} is not a public address")
    return out


def portal_problems(snapshot: Snapshot) -> list[str]:
    """Captive portals (#460): ids, and the networks and SSIDs they name were reported."""
    out: list[str] = []
    segment_ids = {s.id for s in snapshot.segments}
    wlan_ids = {w.id for w in snapshot.wlans}
    for portal in snapshot.portals:
        prefix = f"{portal.device_id}/portal/"
        if not portal.id.startswith(prefix) or portal.id == prefix:
            out.append(f"portal id {portal.id} is not {prefix}<name>")
        for sid in portal.segments:
            if sid not in segment_ids:
                out.append(f"{portal.id} references unknown segment {sid}")
        for wid in portal.wlans:
            if wid not in wlan_ids:
                out.append(f"{portal.id} references unknown wlan {wid}")
    return out


def multiwan_problems(snapshot: Snapshot) -> list[str]:
    """Gateway groups (#150) and dynamic DNS clients (#154): ids, members once, tiers, a known
    active member, uplinks that were reported, naive times."""
    out: list[str] = []
    uplink_ids = {u.id for u in snapshot.uplinks}
    seen: set[str] = set()
    for u in snapshot.uplinks:
        if u.health is not None and u.health.last_change and not _aware(u.health.last_change):
            out.append(f"uplink {u.id}: last_change has no time zone")
    for g in snapshot.gateway_groups:
        prefix = f"{g.device_id}/gateway-group/"
        if not g.id.startswith(prefix) or g.id == prefix:
            out.append(f"gateway group id {g.id} is not {prefix}<name>")
        if g.id in seen:
            out.append(f"gateway group {g.id} reported twice")
        seen.add(g.id)
        names = [m.name for m in g.members]
        if len(set(names)) != len(names):
            out.append(f"gateway group {g.id} lists a member twice")
        if g.active is not None and g.active not in names:
            out.append(f"gateway group {g.id}: active member {g.active} is not a member")
        for m in g.members:
            if m.uplink_id is not None and m.uplink_id not in uplink_ids:
                out.append(f"gateway group {g.id}: member {m.name} has unknown uplink")
    for d in snapshot.ddns:
        prefix = f"{d.device_id}/ddns/"
        if not d.id.startswith(prefix) or d.id == prefix:
            out.append(f"ddns id {d.id} is not {prefix}<name>")
        if d.id in seen:
            out.append(f"ddns {d.id} reported twice")
        seen.add(d.id)
        if d.uplink_id is not None and d.uplink_id not in uplink_ids:
            out.append(f"ddns {d.id} publishes the address of unknown uplink {d.uplink_id}")
        if d.last_update is not None and not _aware(d.last_update):
            out.append(f"ddns {d.id}: last_update has no time zone")
        if d.hostname != d.hostname.strip() or not d.hostname:
            out.append(f"ddns {d.id}: hostname is empty or has spaces around it")
    return out


def service_problems(
    service: ManagementService, port_ids: set[str], segment_ids: set[str]
) -> list[str]:
    """Inconsistent management services (#173): ids, unknown ports and segments, options of
    another kind of service, a disabled service reachable from the internet."""
    out: list[str] = []
    sid = service.id
    prefix = f"{service.device_id}/service/"
    if not sid.startswith(prefix) or sid == prefix:
        out.append(f"service id {sid} is not {prefix}<name>")
    for p in service.interfaces:
        if p not in port_ids:
            out.append(f"service {sid} bound to unknown port {p}")
    for seg in service.segments:
        if seg not in segment_ids:
            out.append(f"service {sid} references unknown segment {seg}")
    if service.transport is ServiceTransport.LAYER2 and (service.port or service.listen):
        out.append(f"service {sid}: a layer-2 service has no port or listen address")
    if service.enabled is False and service.from_wan:
        out.append(f"service {sid}: disabled but reachable from the internet")
    if service.kind is not ServiceKind.SSH and (
        service.root_login is not None or service.root_password_login is not None
    ):
        out.append(f"service {sid}: root login options on a {service.kind.value} service")
    if service.kind is not ServiceKind.HTTP and service.redirects_to_https is not None:
        out.append(f"service {sid}: redirects_to_https on a {service.kind.value} service")
    if service.kind is not ServiceKind.SNMP and service.snmp is not None:
        out.append(f"service {sid}: SNMP settings on a {service.kind.value} service")
    return out


def log_target_problems(device_id: str, targets: list[LogTarget]) -> list[str]:
    """Log targets (#180): a target listed twice, a port on a kind without one, TLS for flows."""
    out: list[str] = []
    seen: set[tuple[str, str, int | None, str | None]] = set()
    for t in targets:
        key = (t.kind.value, t.address, t.port, t.name)
        if key in seen:
            out.append(f"{device_id}: log target {t.kind.value} {t.endpoint()} listed twice")
        seen.add(key)
        if t.transport is LogTransport.TLS and t.kind is not LogKind.SYSLOG:
            out.append(f"{device_id}: log target {t.endpoint()}: TLS on a {t.kind.value} target")
        if "\n" in t.address or " " in t.address:
            out.append(f"{device_id}: log target address {t.address!r} is not an address")
    return out


#: Password hashes: crypt (``$1$``, ``$5$``, ``$6$``, ``$y$``, bcrypt), rpcd's ``$p$`` reference.
#: Factory passwords are words that may appear in any text ("password").
_KNOWN_DEFAULTS = {p for pairs in FACTORY_DEFAULTS.values() for _, p in pairs}
_HASH = re.compile(r"\$(?:1|2[aby]?|5|6|y|p)\$[./A-Za-z0-9]")


def account_problems(device_id: str, accounts: list[DeviceAccount]) -> list[str]:
    """Accounts (#175): a name listed twice, more than one login of Signalbox."""
    out: list[str] = []
    names = [a.name for a in accounts]
    for name in sorted({n for n in names if names.count(n) > 1}):
        out.append(f"{device_id}: account {name!r} listed twice")
    if sum(a.is_signalbox for a in accounts) > 1:
        out.append(f"{device_id}: more than one account is Signalbox's login")
    return out


def stp_problems(device_id: str, bridges: list[StpBridge], ports: dict[str, Port]) -> list[str]:
    """Spanning tree (#155): a bridge named twice, bridge and root ports of the device, bridge
    ids in the canonical form, a bridge port with the bridge role."""
    out: list[str] = []
    names = [b.name for b in bridges]
    for name in sorted({n for n in names if names.count(n) > 1}):
        out.append(f"{device_id}: spanning tree bridge {name!r} listed twice")
    for b in bridges:
        for attr in ("port_id", "root_port_id"):
            pid = getattr(b, attr)
            if pid is not None and (pid not in ports or ports[pid].device_id != device_id):
                out.append(f"{device_id}: bridge {b.name} {attr} {pid} is not a port of it")
        bport = ports.get(b.port_id or "")
        if bport is not None and bport.role not in (None, PortRole.BRIDGE):
            out.append(f"{device_id}: bridge {b.name} names {bport.name}, not a bridge port")
        for attr in ("bridge_id", "root_bridge_id"):
            value = getattr(b, attr)
            if value is not None and parse_stp_bridge_id(value) != value:
                out.append(f"{device_id}: bridge {b.name} {attr} {value!r} is not canonical")
    return out


def multicast_problems(device_id: str, multicast: DeviceMulticast, segments: set[str]) -> list[str]:
    """Multicast (#161): networks named by a bridge or reflector exist, one reflector per kind."""
    out: list[str] = []
    for m in multicast.settings:
        if m.segment_id is not None and m.segment_id not in segments:
            out.append(f"{device_id}: multicast of {m.name} names unknown segment {m.segment_id}")
    kinds = [r.kind for r in multicast.reflectors]
    for kind in sorted({k for k in kinds if kinds.count(k) > 1}, key=str):
        out.append(f"{device_id}: reflector {kind.value} listed twice")
    for r in multicast.reflectors:
        for sid in [*r.segments, *([r.upstream_segment_id] if r.upstream_segment_id else [])]:
            if sid not in segments:
                out.append(f"{device_id}: reflector {r.kind.value} names unknown segment {sid}")
    return out


def credential_problems(adapter: Adapter, snapshot: Snapshot) -> list[str]:
    """No configured secret and no password hash anywhere in the snapshot (#175): only the
    booleans derived from them may leave the integration."""
    text = snapshot.model_dump_json()
    out: list[str] = []
    cfg = adapter.context.config
    for name in type(cfg).model_fields:
        value = getattr(cfg, name)
        secret = value.get_secret_value() if isinstance(value, SecretStr) else ""
        if len(secret) >= 6 and secret not in _KNOWN_DEFAULTS and secret in text:
            out.append(f"the secret setting {name} appears in the snapshot")
    if _HASH.search(text):
        out.append("a password hash appears in the snapshot")
    return out


def dhcp_problems(server: DhcpServer) -> list[str]:
    """Inconsistent DHCP server data (#183): leases without an owner or with impossible times,
    one address leased to two clients, options that repeat a typed field."""
    out: list[str] = []
    sid = server.id
    active: dict[str, str] = {}
    for lease in server.leases or []:
        what = f"{sid} lease {lease.address}"
        if lease.mac is None and not lease.client_id:
            out.append(f"{what} has neither a MAC address nor a client id")
        if lease.starts and lease.expires and lease.expires < lease.starts:
            out.append(f"{what} expires before it starts")
        if lease.state is LeaseState.RESERVED and lease.reserved is False:
            out.append(f"{what}: state reserved but not a reservation")
        owner = lease.mac or lease.client_id or ""
        if lease.state is LeaseState.ACTIVE:
            other = active.setdefault(str(lease.address), owner)
            if other != owner:
                out.append(f"{what} is active for both {other} and {owner}")
    codes = [o.code for o in server.options]
    for code in sorted(set(codes)):
        if code in TYPED_OPTION_CODES:
            out.append(f"{sid}: option {code} belongs in its typed field")
        if codes.count(code) > 1:
            out.append(f"{sid}: option {code} listed twice")
    return out


def relay_problems(relay: DhcpRelay) -> list[str]:
    prefix = f"{relay.device_id}/dhcp-relay/"
    if not relay.id.startswith(prefix) or relay.id == prefix:
        return [f"dhcp relay id {relay.id} is not {prefix}<segment key>"]
    return []


def client_problems(client: Client) -> list[str]:
    """Address sources (#183) only for listed addresses, and of the right family."""
    out: list[str] = []
    for addr, src in client.address_sources.items():
        if addr not in client.addresses:
            out.append(f"client {client.id}: source for {addr}, which it does not list")
        elif not source_fits(addr, src):
            out.append(f"client {client.id}: {src.value} cannot apply to {addr}")
    return out


def time_problems(device_id: str, value: DeviceTime, segment_prefix: str) -> list[str]:
    """Inconsistent clock and NTP values."""
    out: list[str] = []
    stamps = [value.clock, value.read_at, value.ntp_client.last_sync if value.ntp_client else None]
    for when in stamps:
        if when is not None and not _aware(when):
            out.append(f"{device_id}: time {when} has no time zone")
    if value.clock is not None and value.read_at is None:
        out.append(f"{device_id}: clock without read_at")
    if value.timezone is not None and not value.timezone.strip():
        out.append(f"{device_id}: empty time zone")
    if value.ntp_client is not None and any(not s.strip() for s in value.ntp_client.servers):
        out.append(f"{device_id}: empty NTP server name")
    for seg in value.ntp_server.segments if value.ntp_server else []:
        if not seg.startswith(segment_prefix):
            out.append(
                f"{device_id}: NTP server segment {seg} does not start with {segment_prefix}"
            )
    return out


def tunnel_problems(tunnel: Tunnel, port_ids: set[str]) -> list[str]:
    """A tunnel (#239): its port, its peers' keys, its handshake times."""
    out: list[str] = []
    own = f"{tunnel.device_id}/"
    if tunnel.id != f"{tunnel.device_id}/tunnel/{tunnel.name}":
        out.append(f"tunnel {tunnel.id} is not {tunnel.device_id}/tunnel/{tunnel.name}")
    port = tunnel.port_id
    if port is not None and port.startswith(own) and port not in port_ids:
        out.append(f"tunnel {tunnel.id} on unknown port {tunnel.port_id}")
    keys = [p.public_key for p in tunnel.peers]
    if len(set(keys)) != len(keys):
        out.append(f"tunnel {tunnel.id} lists a peer twice")
    if tunnel.public_key is not None and tunnel.public_key in keys:
        out.append(f"tunnel {tunnel.id} has itself as a peer")
    for peer in tunnel.peers:
        if peer.endpoint_port is not None and not peer.endpoint_host:
            out.append(f"tunnel {tunnel.id} peer {peer.public_key}: endpoint port without host")
    return out


def firewall_problems(
    fw: Firewall,
    port_ids: set[str],
    segment_ids: set[str],
    uplink_ids: set[str],
    tunnel_ids: set[str],
) -> list[str]:
    """A firewall (#135): its id, unique zone names, zone members that exist in the snapshot,
    rules, policies and NAT that name known zones."""
    out: list[str] = []
    if fw.id != firewall_id(fw.device_id):
        out.append(f"firewall {fw.id} is not {firewall_id(fw.device_id)}")
    names = [z.name for z in fw.zones]
    if len(set(names)) != len(names):
        out.append(f"firewall {fw.id} lists a zone twice")
    known = set(names)
    own = f"{fw.device_id}/"
    for z in fw.zones:
        for kind, ids, refs in (
            ("segment", segment_ids, z.segments),
            ("uplink", uplink_ids, z.uplinks),
            ("tunnel", tunnel_ids, z.tunnels),
            ("port", port_ids, z.ports),
        ):
            for ref in refs:
                if ref not in ids and (kind == "segment" or ref.startswith(own)):
                    out.append(f"firewall {fw.id} zone {z.name} has unknown {kind} {ref}")
    pairs = [(p.source, p.destination) for p in fw.policies]
    if len(set(pairs)) != len(pairs):
        out.append(f"firewall {fw.id} has two policies for the same zone pair")
    for p in fw.policies:
        for zone in (p.source, p.destination):
            if zone is not None and zone not in known:
                out.append(f"firewall {fw.id} policy names unknown zone {zone}")
    for i, rule in enumerate(fw.rules):
        where = f"firewall {fw.id} rule {rule.name or i}"
        for zone in (*rule.source.zones, *rule.destination.zones):
            if zone not in known:
                out.append(f"{where} names unknown zone {zone}")
        if (
            rule.destination.ports
            and rule.protocols
            and not set(rule.protocols)
            & {
                FirewallProtocol.TCP,
                FirewallProtocol.UDP,
            }
        ):
            out.append(f"{where} has ports without TCP or UDP")
        if rule.chain is FirewallChain.INPUT and rule.destination.zones:
            out.append(f"{where} is an input rule with a destination zone")
    for pf in fw.port_forwards:
        for zone in pf.zones:
            if zone not in known:
                out.append(f"firewall {fw.id} port forward {pf.name} names unknown zone {zone}")
    for n in fw.nat:
        for zone in n.zones:
            if zone not in known:
                out.append(f"firewall {fw.id} NAT rule {n.name} names unknown zone {zone}")
        if not n.masquerade and n.to_address is None:
            out.append(f"firewall {fw.id} NAT rule {n.name} has neither masquerade nor address")
    return out


#: Names of fields that hold tunnel keys: never in ``vendor_extra`` (#239).
SECRET_KEYS = re.compile(
    r"priv(ate)?[-_ ]?key|pre[-_ ]?shared[-_ ]?key|^psk$",
    re.IGNORECASE,
)
_WG_KEY = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=(?![A-Za-z0-9+/=])")


def _extra_secrets(where: str, value: Any, public: set[str]) -> Iterator[str]:
    if isinstance(value, dict):
        for k, v in value.items():
            if SECRET_KEYS.search(str(k)):
                yield f"{where}: vendor_extra field {k!r} looks like a secret"
            yield from _extra_secrets(where, v, public)
    elif isinstance(value, list):
        for v in value:
            yield from _extra_secrets(where, v, public)
    elif isinstance(value, str):
        for key in _WG_KEY.findall(value):
            if key not in public:
                yield f"{where}: vendor_extra holds a key that is no public key of the snapshot"


def certificate_problems(snapshot: Snapshot) -> list[str]:
    """Stored certificates (#330): ids, each once, ``used_by`` naming reported services, and no
    key material anywhere in them (the model has no field for it; a PEM private key or
    certificate request in ``vendor_extra`` or a name is refused)."""
    out: list[str] = []
    services = {s.id for s in snapshot.services}
    seen: set[str] = set()
    for cert in snapshot.certificates:
        prefix = f"{cert.device_id}/cert/"
        if not cert.id.startswith(prefix) or cert.id == prefix:
            out.append(f"certificate id {cert.id} is not {prefix}<name>")
        if cert.id in seen:
            out.append(f"certificate {cert.id} reported twice")
        seen.add(cert.id)
        out += [
            f"certificate {cert.id} used by unknown service {s}"
            for s in cert.used_by
            if s not in services
        ]
        dump = cert.model_dump_json()
        if "PRIVATE KEY" in dump or "CERTIFICATE REQUEST" in dump:
            out.append(f"certificate {cert.id} holds key material")
    return out


def secret_problems(snapshot: Snapshot) -> list[str]:
    """No private or pre-shared key anywhere (#239): the model has no field for them, so the
    only place an adapter could put one is ``vendor_extra``. A field named like a secret, or a
    WireGuard-shaped key that is not one of the snapshot's public keys, is refused."""
    public = {t.public_key for t in snapshot.tunnels if t.public_key}
    public |= {p.public_key for t in snapshot.tunnels for p in t.peers}
    out: list[str] = []
    objects: list[Any] = [snapshot.device, *snapshot.extra_devices]
    for kind in Snapshot.model_fields:
        value = getattr(snapshot, kind)
        if isinstance(value, list) and kind != "errors":
            objects += value
    for obj in objects:
        extra = getattr(obj, "vendor_extra", None)
        if extra:
            out += _extra_secrets(getattr(obj, "id", "?"), extra, public)
    return out


def _capability_problems(snapshot: Snapshot, site: str) -> list[str]:
    caps = set(snapshot.device.capabilities)
    devices: list[Device] = [snapshot.device, *snapshot.extra_devices]
    out: list[str] = []
    for cap, attr in ((Capability.HEALTH, "health"), (Capability.TIME, "time")):
        found = [d for d in devices if getattr(d, attr) is not None]
        if cap.value in caps and not found:
            out.append(f"declares {cap.value} but no device has {attr}")
        if cap.value not in caps and found:
            out.append(f"{attr} reported without declaring {cap.value}")
    for kind in ("uplinks", "gateway_groups", "ddns", "portals", "services", "certificates"):
        if getattr(snapshot, kind) and Capability.INTERFACES.value not in caps:
            out.append(f"{kind} reported without declaring {Capability.INTERFACES.value}")
    if snapshot.dhcp_relays and Capability.DHCP.value not in caps:
        out.append(f"dhcp_relays reported without declaring {Capability.DHCP.value}")
    if (snapshot.dhcp6_servers or snapshot.router_adverts) and Capability.DHCP.value not in caps:
        out.append(
            f"dhcp6_servers or router_adverts reported without declaring {Capability.DHCP.value}"
        )
    if snapshot.server_sightings and Capability.DHCP.value not in caps:
        out.append(f"server_sightings reported without declaring {Capability.DHCP.value}")
    if snapshot.tunnels and Capability.VPN.value not in caps:
        out.append(f"tunnels reported without declaring {Capability.VPN.value}")
    if (snapshot.routes or snapshot.routing_rules) and Capability.INTERFACES.value not in caps:
        out.append(f"routes reported without declaring {Capability.INTERFACES.value}")
    if snapshot.firewalls and Capability.FIREWALL.value not in caps:
        out.append(f"firewalls reported without declaring {Capability.FIREWALL.value}")
    for d in devices:
        if d.log_targets is not None:
            if Capability.INTERFACES.value not in caps:
                out.append(f"log targets reported without declaring {Capability.INTERFACES.value}")
            out += log_target_problems(d.id, d.log_targets)
        if d.accounts is not None:
            if Capability.INTERFACES.value not in caps:
                out.append(f"accounts reported without declaring {Capability.INTERFACES.value}")
            out += account_problems(d.id, d.accounts)
        if d.stp_bridges is not None:
            if Capability.INTERFACES.value not in caps:
                out.append(f"stp_bridges reported without declaring {Capability.INTERFACES.value}")
            out += stp_problems(d.id, d.stp_bridges, {p.id: p for p in snapshot.ports})
        if d.multicast is not None:
            if Capability.INTERFACES.value not in caps:
                out.append(f"multicast reported without declaring {Capability.INTERFACES.value}")
            out += multicast_problems(d.id, d.multicast, {s.id for s in snapshot.segments})
        if d.health is not None:
            out += health_problems(d.id, d.health)
        if d.time is not None:
            out += time_problems(d.id, d.time, site)
    return out


def problems(adapter: Adapter, snapshot: Snapshot) -> list[str]:
    """Everything wrong with a snapshot, as readable sentences (empty list: all good)."""
    m = adapter.manifest
    ctx = adapter.context
    out: list[str] = []
    dev = snapshot.device
    if dev.id != ctx.device_id or dev.site_id != ctx.site_id:
        out.append(f"device id/site {dev.id}/{dev.site_id} != context {ctx.device_id}")
    if snapshot.status is not DeviceStatus.OK:
        out.append(f"status {snapshot.status.value}, expected ok")
    # optional gaps (#278, #349) leave the device ok: a missing optional privilege or feature
    out += [f"read error {e.capability}: {e.message}" for e in snapshot.errors if not e.optional]
    out += credential_problems(adapter, snapshot)

    own = f"{ctx.device_id}/"
    site = f"{ctx.site_id}/segment/"
    owners = {ctx.device_id, *(d.id for d in snapshot.extra_devices)}
    for d in snapshot.extra_devices:
        if not d.id.startswith(own):
            out.append(f"extra device id {d.id} does not start with {own}")
        if d.managed_by != ctx.device_id or d.site_id != ctx.site_id:
            out.append(f"extra device {d.id} has managed_by {d.managed_by}, site {d.site_id}")
    for key in snapshot.extra_status:
        if key not in owners:
            out.append(f"status for unknown device {key}")
    port_ids = {p.id for p in snapshot.ports}
    radio_ids = {r.id for r in snapshot.radios}
    segment_ids = {s.id for s in snapshot.segments}

    owned = (
        "ports",
        "subnets",
        "uplinks",
        "gateway_groups",
        "ddns",
        "portals",
        "services",
        "certificates",
        "dhcp_servers",
        "dhcp_relays",
        "dhcp6_servers",
        "router_adverts",
        "dns_services",
        "tunnels",
        "firewalls",
        "server_sightings",
        "routes",
        "routing_rules",
    )
    for kind in (*owned, "radios", "wlans"):
        for obj in getattr(snapshot, kind):
            if not obj.id.startswith(own):
                out.append(f"{kind} id {obj.id} does not start with {own}")
            owner = getattr(obj, "device_id", ctx.device_id)
            if owner not in owners:
                out.append(f"{kind} {obj.id} has device_id {obj.device_id}")
            elif not obj.id.startswith(f"{owner}/"):
                out.append(f"{kind} id {obj.id} does not start with {owner}/")
    for kind in ("clients", "neighbours", "mesh_peers"):
        for obj in getattr(snapshot, kind):
            if not obj.id.startswith(own):
                out.append(f"{kind} id {obj.id} does not start with {own}")
    for kind in Snapshot.model_fields:
        value = getattr(snapshot, kind)
        if not isinstance(value, list) or kind in ("errors", "wireless_links"):
            continue  # a Link carries no source: it is not an observed object
        for obj in value:
            src = getattr(obj, "source", None)
            if src is None or src.adapter != m.id or src.device_id != ctx.device_id:
                out.append(f"{kind} {obj.id} has source {src}")

    for seg in snapshot.segments:
        if not seg.id.startswith(site):
            out.append(f"segment id {seg.id} does not start with {site}")
        for mem in seg.members:
            if mem.port_id.startswith(own) and mem.port_id not in port_ids:
                out.append(f"segment {seg.id} references unknown port {mem.port_id}")
        untagged = [x for x in seg.members if x.mode is Membership.UNTAGGED]
        if len({x.port_id for x in untagged}) != len(untagged):
            out.append(f"segment {seg.id} lists a port twice")
    for refs in (
        snapshot.subnets,
        snapshot.dhcp_servers,
        snapshot.dhcp_relays,
        snapshot.dhcp6_servers,
        snapshot.router_adverts,
    ):
        for obj in refs:
            if obj.segment_id not in segment_ids:
                out.append(f"{obj.id} references unknown segment {obj.segment_id}")
    out += portal_problems(snapshot)
    sightings: set[str] = set()
    for sighting in snapshot.server_sightings:
        if sighting.id in sightings:
            out.append(f"server sighting {sighting.id} reported twice")
        sightings.add(sighting.id)
        if sighting.segment_id is not None and sighting.segment_id not in segment_ids:
            out.append(f"{sighting.id} references unknown segment {sighting.segment_id}")
        if sighting.server_address is None and sighting.server_mac is None:
            out.append(f"{sighting.id} names neither the server's address nor its MAC")
    radios = {r.id: r for r in snapshot.radios}
    for radio in snapshot.radios:
        out += radio_problems(radio)
    for wlan in snapshot.wlans:
        out += wlan_problems(wlan, radios.get(wlan.radio_id))
        if wlan.radio_id not in radio_ids:
            out.append(f"wlan {wlan.id} references unknown radio {wlan.radio_id}")
        if wlan.segment_id is not None and wlan.segment_id not in segment_ids:
            out.append(f"wlan {wlan.id} references unknown segment {wlan.segment_id}")
    for port in snapshot.ports:
        out += port_problems(port)
    out += structure_problems(snapshot.ports, snapshot.wlans)
    for uplink in snapshot.uplinks:
        out += uplink_problems(uplink, port_ids)
    out += multiwan_problems(snapshot)
    seen: set[str] = set()
    for service in snapshot.services:
        if service.id in seen:
            out.append(f"service {service.id} reported twice")
        seen.add(service.id)
        out += service_problems(service, port_ids, segment_ids)
    for server in snapshot.dhcp_servers:
        out += dhcp_problems(server)
    relays: set[str] = set()
    for relay in snapshot.dhcp_relays:
        if relay.id in relays:
            out.append(f"dhcp relay {relay.id} reported twice")
        relays.add(relay.id)
        out += relay_problems(relay)
    for client in snapshot.clients:
        out += client_problems(client)
    tunnels: set[str] = set()
    for tunnel in snapshot.tunnels:
        if tunnel.id in tunnels:
            out.append(f"tunnel {tunnel.id} reported twice")
        tunnels.add(tunnel.id)
        out += tunnel_problems(tunnel, port_ids)
    firewalls: set[str] = set()
    uplink_ids = {u.id for u in snapshot.uplinks}
    for fw in snapshot.firewalls:
        if fw.device_id in firewalls:
            out.append(f"firewall of {fw.device_id} reported twice")
        firewalls.add(fw.device_id)
        out += firewall_problems(fw, port_ids, segment_ids, uplink_ids, tunnels)
    out += secret_problems(snapshot)
    out += certificate_problems(snapshot)
    for nb in snapshot.neighbours:
        if nb.local_port_id not in port_ids:
            out.append(f"neighbour {nb.id} on unknown port {nb.local_port_id}")

    out += fdb_problems(snapshot.fdb, owners, port_ids, segment_ids)
    out += route_problems(snapshot, port_ids, segment_ids)
    out += mesh_problems(snapshot, port_ids, owners)
    if snapshot.wifi_scan and Capability.WIRELESS.value not in snapshot.device.capabilities:
        out.append(f"wifi_scan reported without declaring {Capability.WIRELESS.value}")
    out += scan_problems(snapshot.wifi_scan, owners, {r.id: r for r in snapshot.radios})

    out += _capability_problems(snapshot, site)

    if Snapshot.model_validate_json(snapshot.model_dump_json()) != snapshot:
        out.append("snapshot does not survive a JSON round trip")
    return out


def mesh_problems(snapshot: Snapshot, port_ids: set[str], owners: Iterable[str]) -> list[str]:
    """Wireless backhaul links (#171) join two reported ports of two devices of this snapshot,
    are of origin ``mesh`` and say what kind of link they are; mesh membership names devices."""
    out: list[str] = []
    caps = set(snapshot.device.capabilities)
    ids = set(owners)
    if (snapshot.wireless_links or snapshot.mesh_peers) and not caps & {
        Capability.INTERFACES.value,
        "wireless",
    }:
        out.append("wireless_links reported without declaring interfaces or wireless")
    ports = {p.id: p.device_id for p in snapshot.ports}
    for peer in snapshot.mesh_peers:
        if peer.port_id not in port_ids:
            out.append(f"mesh peer {peer.id} on unknown port {peer.port_id}")
        if peer.device_id not in ids:
            out.append(f"mesh peer {peer.id} has device_id {peer.device_id}")
    for link in snapshot.wireless_links:
        if link.origin is not LinkOrigin.MESH or link.kind is not LinkKind.WIRELESS:
            out.append(f"wireless link {link.id} is not a wireless link of origin mesh")
        if link.wireless is None:
            out.append(f"wireless link {link.id} has no radio details")
        for end in (link.a, link.b):
            if end not in port_ids:
                out.append(f"wireless link {link.id} ends on unknown port {end}")
        if ports.get(link.a) is not None and ports.get(link.a) == ports.get(link.b):
            out.append(f"wireless link {link.id} joins two ports of one device")
    for dev in (snapshot.device, *snapshot.extra_devices):
        if dev.mesh is not None and dev.mesh.controller_id not in (None, *ids):
            out.append(f"{dev.id} names mesh controller {dev.mesh.controller_id} (unknown)")
    return out


def route_problems(snapshot: Snapshot, port_ids: set[str], segment_ids: set[str]) -> list[str]:
    """Routes and routing rules (#149): each once, an interface that is a reported port of the
    same device, a rule's segment reported, and a table name that is not empty."""
    out: list[str] = []
    seen: set[str] = set()
    for r in snapshot.routes:
        if r.id in seen:
            out.append(f"route {r.id} reported twice")
        seen.add(r.id)
        if r.interface is not None and r.interface not in port_ids:
            out.append(f"route {r.id} leaves through unknown port {r.interface}")
        elif r.interface is not None and not r.interface.startswith(f"{r.device_id}/"):
            out.append(f"route {r.id} leaves through port {r.interface} of another device")
        if not r.table:
            out.append(f"route {r.id} has no table")
    if len(snapshot.routes) > ROUTE_LIMIT:
        out.append(f"{len(snapshot.routes)} routes reported (over {ROUTE_LIMIT})")
    for rule in snapshot.routing_rules:
        if rule.id in seen:
            out.append(f"routing rule {rule.id} reported twice")
        seen.add(rule.id)
        if rule.segment_id is not None and rule.segment_id not in segment_ids:
            out.append(f"routing rule {rule.id} references unknown segment {rule.segment_id}")
    return out


def fdb_problems(
    entries: list[FdbEntry], owners: Iterable[str], port_ids: set[str], segment_ids: set[str]
) -> list[str]:
    """Forwarding-database entries (#160): of a reported device, on a reported port of that
    device, a unicast MAC, a known segment, each once, at most ``FDB_LIMIT`` per device."""
    out: list[str] = []
    devices = set(owners)
    seen: set[str] = set()
    count: dict[str, int] = {}
    for e in entries:
        if e.id in seen:
            out.append(f"fdb entry {e.id} reported twice")
        seen.add(e.id)
        count[e.device_id] = count.get(e.device_id, 0) + 1
        if e.device_id not in devices:
            out.append(f"fdb entry {e.id} has device_id {e.device_id}")
        elif not e.id.startswith(f"{e.device_id}/fdb/"):
            out.append(f"fdb entry id {e.id} does not start with {e.device_id}/fdb/")
        if e.port_id not in port_ids:
            out.append(f"fdb entry {e.id} on unknown port {e.port_id}")
        elif not e.port_id.startswith(f"{e.device_id}/"):
            out.append(f"fdb entry {e.id} on port {e.port_id} of another device")
        if int(e.mac[:2], 16) & 1:
            out.append(f"fdb entry {e.id} is a multicast address")
        if e.segment_id is not None and e.segment_id not in segment_ids:
            out.append(f"fdb entry {e.id} references unknown segment {e.segment_id}")
    out += [
        f"{d} reports {n} fdb entries (over {FDB_LIMIT})" for d, n in count.items() if n > FDB_LIMIT
    ]
    return out


def scan_problems(
    results: list[WifiScanResult], owners: Iterable[str], radios: dict[str, Radio]
) -> list[str]:
    """Scan results (#169): of a reported device, heard by a radio of that device (or none),
    id ``<radio or device>/scan/<bssid>``, a unicast BSSID, each once, the radio's band, at
    most ``SCAN_LIMIT`` per device."""
    out: list[str] = []
    devices = set(owners)
    seen: set[str] = set()
    count: dict[str, int] = {}
    for r in results:
        if r.id in seen:
            out.append(f"scan result {r.id} reported twice")
        seen.add(r.id)
        count[r.device_id] = count.get(r.device_id, 0) + 1
        if r.device_id not in devices:
            out.append(f"scan result {r.id} has device_id {r.device_id}")
        if r.id != scan_id(r.radio_id or r.device_id, r.bssid):
            out.append(
                f"scan result id {r.id} is not {scan_id(r.radio_id or r.device_id, r.bssid)}"
            )
        if r.radio_id is not None:
            radio = radios.get(r.radio_id)
            if radio is None:
                out.append(f"scan result {r.id} heard by unknown radio {r.radio_id}")
            elif radio.device_id != r.device_id:
                out.append(f"scan result {r.id} heard by a radio of another device")
            elif r.band is not None and r.band is not radio.band:
                out.append(f"scan result {r.id} on {r.band} GHz heard by a {radio.band} GHz radio")
        if int(r.bssid[:2], 16) & 1:
            out.append(f"scan result {r.id} has a multicast BSSID")
    out += [
        f"{d} reports {n} scan results (over {SCAN_LIMIT})"
        for d, n in count.items()
        if n > SCAN_LIMIT
    ]
    return out


async def assert_contract(adapter: Adapter) -> Snapshot:
    """Observe once and fail with every contract problem found."""
    check_manifest(adapter.manifest)
    adapter.manifest.config.model_json_schema()  # the UI must be able to render the form
    snapshot = await adapter.observe()
    found = problems(adapter, snapshot)
    assert not found, f"{adapter.manifest.id} breaks the adapter contract:\n  " + "\n  ".join(found)
    return snapshot
