"""Contract checks every adapter must pass against its simulator.

Use from an adapter's tests::

    from signalbox.testing import assert_contract

    async def test_contract(simulator):
        adapter = MyAdapter(context_for(simulator))
        snapshot = await assert_contract(adapter)
"""

from __future__ import annotations

from signalbox.adapters import Adapter, Capability, check_manifest
from signalbox.model import Device, DeviceHealth, DeviceStatus, DeviceTime, Membership, Snapshot


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

    for kind in ("ports", "subnets", "dhcp_servers", "dns_services", "radios", "wlans"):
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
    for wlan in snapshot.wlans:
        if wlan.radio_id not in radio_ids:
            out.append(f"wlan {wlan.id} references unknown radio {wlan.radio_id}")
        if wlan.segment_id is not None and wlan.segment_id not in segment_ids:
            out.append(f"wlan {wlan.id} references unknown segment {wlan.segment_id}")
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
