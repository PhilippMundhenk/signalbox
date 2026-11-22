"""Contract checks every adapter must pass against its simulator.

Use from an adapter's tests::

    from signalbox.testing import assert_contract

    async def test_contract(simulator):
        adapter = MyAdapter(context_for(simulator))
        snapshot = await assert_contract(adapter)
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from signalbox.adapters import Adapter, Capability, check_manifest
from signalbox.model import (
    Cipher,
    Device,
    DeviceHealth,
    DeviceStatus,
    DeviceTime,
    ManagementService,
    Membership,
    NatClass,
    Port,
    PortKind,
    Radio,
    Security,
    ServiceKind,
    ServiceTransport,
    Snapshot,
    Uplink,
    UplinkKind,
    Wlan,
    address_nat_class,
    set_passphrase_digest_key,
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


def radio_problems(radio: Radio) -> list[str]:
    """Inconsistent radio capabilities (#167)."""
    out: list[str] = []
    sup = radio.supported_security
    if sup is not None and not sup:
        out.append(f"radio {radio.id}: empty supported_security (None: not reported)")
    if sup is not None and len(set(sup)) != len(sup):
        out.append(f"radio {radio.id}: supported_security lists a mode twice")
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
    for kind in ("uplinks", "services"):
        if getattr(snapshot, kind) and Capability.INTERFACES.value not in caps:
            out.append(f"{kind} reported without declaring {Capability.INTERFACES.value}")
    for d in devices:
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
    out += [f"read error {e.capability}: {e.message}" for e in snapshot.errors]

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

    owned = ("ports", "subnets", "uplinks", "services", "dhcp_servers", "dns_services")
    for kind in (*owned, "radios", "wlans"):
        for obj in getattr(snapshot, kind):
            if not obj.id.startswith(own):
                out.append(f"{kind} id {obj.id} does not start with {own}")
            owner = getattr(obj, "device_id", ctx.device_id)
            if owner not in owners:
                out.append(f"{kind} {obj.id} has device_id {obj.device_id}")
            elif not obj.id.startswith(f"{owner}/"):
                out.append(f"{kind} id {obj.id} does not start with {owner}/")
    for kind in ("clients", "neighbours"):
        for obj in getattr(snapshot, kind):
            if not obj.id.startswith(own):
                out.append(f"{kind} id {obj.id} does not start with {own}")
    for kind in Snapshot.model_fields:
        value = getattr(snapshot, kind)
        if not isinstance(value, list) or kind == "errors":
            continue
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
    for refs in (snapshot.subnets, snapshot.dhcp_servers):
        for obj in refs:
            if obj.segment_id not in segment_ids:
                out.append(f"{obj.id} references unknown segment {obj.segment_id}")
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
    for uplink in snapshot.uplinks:
        out += uplink_problems(uplink, port_ids)
    seen: set[str] = set()
    for service in snapshot.services:
        if service.id in seen:
            out.append(f"service {service.id} reported twice")
        seen.add(service.id)
        out += service_problems(service, port_ids, segment_ids)
    for nb in snapshot.neighbours:
        if nb.local_port_id not in port_ids:
            out.append(f"neighbour {nb.id} on unknown port {nb.local_port_id}")

    out += _capability_problems(snapshot, site)

    if Snapshot.model_validate_json(snapshot.model_dump_json()) != snapshot:
        out.append("snapshot does not survive a JSON round trip")
    return out


async def assert_contract(adapter: Adapter) -> Snapshot:
    """Observe once and fail with every contract problem found."""
    check_manifest(adapter.manifest)
    adapter.manifest.config.model_json_schema()  # the UI must be able to render the form
    snapshot = await adapter.observe()
    found = problems(adapter, snapshot)
    assert not found, f"{adapter.manifest.id} breaks the adapter contract:\n  " + "\n  ".join(found)
    return snapshot
