"""Contract checks every adapter must pass against its simulator.

Use from an adapter's tests::

    from signalbox.testing import assert_contract

    async def test_contract(simulator):
        adapter = MyAdapter(context_for(simulator))
        snapshot = await assert_contract(adapter)
"""

from __future__ import annotations

from signalbox.adapters import Adapter, check_manifest
from signalbox.model import DeviceStatus, Membership, Snapshot


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
    port_ids = {p.id for p in snapshot.ports}
    radio_ids = {r.id for r in snapshot.radios}
    segment_ids = {s.id for s in snapshot.segments}

    for kind in ("ports", "subnets", "dhcp_servers", "dns_services", "radios", "wlans"):
        for obj in getattr(snapshot, kind):
            if not obj.id.startswith(own):
                out.append(f"{kind} id {obj.id} does not start with {own}")
            if getattr(obj, "device_id", ctx.device_id) != ctx.device_id:
                out.append(f"{kind} {obj.id} has device_id {obj.device_id}")
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
