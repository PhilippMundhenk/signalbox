"""Network purpose (issue #164): what a segment or SSID is for, and where that is known from.

Three sources, strongest first:

1. **declared**: ``purpose`` of a segment or SSID in the desired state
   (:func:`signalbox.desired.apply_declared`, applied by the runner to every network it builds)
2. **reported**: the device knows it (Fritz!Box guest network, Omada guest SSID); set by adapters
3. **heuristic**: guessed from the name by :func:`guess` during the merge; a guess is only a
   fallback and is shown as one

Rules read the result through :func:`wlan_purpose` and :func:`segment_purpose`.
"""

from __future__ import annotations

import re

from signalbox.model import (
    UNTRUSTED_PURPOSES,
    DeviceRole,
    Network,
    PurposeSource,
    Segment,
    SegmentPurpose,
    Wlan,
)

#: Name parts that mark a network. Cautious on purpose: a wrong guess produces wrong findings.
_GUESSES: tuple[tuple[re.Pattern[str], SegmentPurpose], ...] = (
    (re.compile(r"^(guest|gast|visitor)"), SegmentPurpose.GUEST),
    (re.compile(r"^iot(\d|$)"), SegmentPurpose.IOT),
)


def _words(name: str) -> list[str]:
    """``MyGuest-WiFi_5G`` -> ``my``, ``guest``, ``wi``, ``fi``, ``5g`` (lower case)."""
    spaced = re.sub(r"(?<=[a-z])(?=[A-Z][a-z])", " ", name)
    return [w for w in re.split(r"[^a-z0-9]+", spaced.lower()) if w]


def guess(name: str | None) -> SegmentPurpose | None:
    """The purpose a name suggests (``Guest``, ``Gastzugang``, ``IoT``), or None."""
    found = {p for w in _words(name or "") for rx, p in _GUESSES if rx.search(w)}
    return next(iter(found)) if len(found) == 1 else None


def with_heuristics(net: Network) -> Network:
    """Fill unknown purposes of segments (by name) and SSIDs (by SSID) with guesses."""

    def seg(s: Segment) -> Segment:
        p = guess(s.name) if s.purpose is None else None
        return (
            s.model_copy(update={"purpose": p, "purpose_source": PurposeSource.HEURISTIC})
            if p
            else s
        )

    def wlan(w: Wlan) -> Wlan:
        p = guess(w.ssid) if w.purpose is None else None
        return (
            w.model_copy(update={"purpose": p, "purpose_source": PurposeSource.HEURISTIC})
            if p
            else w
        )

    return net.model_copy(
        update={"segments": [seg(s) for s in net.segments], "wlans": [wlan(w) for w in net.wlans]}
    )


def segment_purpose(net: Network, segment_id: str | None) -> SegmentPurpose | None:
    seg = net.segment(segment_id) if segment_id else None
    return seg.purpose if seg else None


def wlan_purpose(net: Network, wlan: Wlan) -> SegmentPurpose | None:
    """The SSID's own purpose, else the purpose of its segment."""
    return wlan.purpose or segment_purpose(net, wlan.segment_id)


def wlan_source(net: Network, wlan: Wlan) -> PurposeSource | None:
    if wlan.purpose is not None:
        return wlan.purpose_source
    seg = net.segment(wlan.segment_id) if wlan.segment_id else None
    return seg.purpose_source if seg else None


def untrusted(purpose: SegmentPurpose | None) -> bool:
    return purpose in UNTRUSTED_PURPOSES


def device_internal(net: Network, segment_id: str) -> bool:
    """A network a router keeps to itself: isolated, without a modelled subnet, and every SSID in
    it is on a router (the Fritz!Box guest network). The router serves it; rules that look for a
    router subnet must not report it.
    """
    seg = net.segment(segment_id)
    if seg is None or not seg.isolated or any(s.segment_id == segment_id for s in net.subnets):
        return False
    wlans = [w for w in net.wlans if w.segment_id == segment_id]
    devices = [net.device(w.device_id) for w in wlans]
    return bool(wlans) and all(d is not None and d.role is DeviceRole.GATEWAY for d in devices)
