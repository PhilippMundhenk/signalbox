"""UniFi Smart Queues (#166): fields of the WAN network in ``rest/networkconf``.

``wan_smartq_enabled`` (bool), ``wan_smartq_up_rate`` and ``wan_smartq_down_rate`` (kbit/s). The
queue is fq_codel based (the console calls it Smart Queues); the field names are *guess* from
community documentation of Network 7 and 8 (UniFi OS 3 and 4), not seen on a device (#21). A WAN
without the fields reports nothing. The integration API has no such setting.
"""

from __future__ import annotations

from typing import Any

from signalbox.adapters.shaping import kbps
from signalbox.model import Shaper, ShaperKind, Uplink, object_id


def _flag(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.lower() in ("1", "true", "yes"))


def smart_queues(
    device_id: str, uplinks: list[Uplink], confs: dict[str, dict[str, Any]]
) -> list[Shaper]:
    """One shaper per WAN network that has the Smart Queues fields. ``confs``: ``wan1`` ... ->
    the ``rest/networkconf`` row; the uplink id ends in the same key."""
    out: list[Shaper] = []
    for key, conf in sorted(confs.items()):
        if "wan_smartq_enabled" not in conf:
            continue
        up = next((u for u in uplinks if u.id.endswith(f"/uplink/{key}")), None)
        out.append(
            Shaper(
                id=object_id(device_id, "shaper", f"smartq-{key}"),
                device_id=device_id,
                name=f"Smart Queues {key.upper()}",
                kind=ShaperKind.FQ_CODEL,
                interface=key,
                uplink_id=up.id if up else None,
                download_kbps=kbps(conf.get("wan_smartq_down_rate"), "kbit"),
                upload_kbps=kbps(conf.get("wan_smartq_up_rate"), "kbit"),
                enabled=_flag(conf.get("wan_smartq_enabled")),
            )
        )
    return out
