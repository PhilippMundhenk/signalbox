"""Wi-Fi radio state rules: busy channels, radar hits and old standards (issue #172).

They use what the radio reports about itself (capabilities and the state at the last read)
and stay quiet where a device does not report it.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

from signalbox.model import STANDARD_RANK, Band, DfsState, Network, Radio, WifiStandard
from signalbox.rules import (
    Result,
    Rule,
    RuleParams,
    Severity,
    ctx,
    found,
    history_rule,
    param,
    rule,
)
from signalbox.rules._names import device_name
from signalbox.rules.wifi_hygiene import dfs_fix
from signalbox.sightings import History

#: Channel utilisation (percent) from which a radio counts as busy, and as very busy.
BUSY_PCT = 60.0
VERY_BUSY_PCT = 80.0
#: How long a radar hit counts as recent.
RADAR_RECENT = timedelta(hours=24)


def _label(net: Network, radio: Radio) -> str:
    return f"{device_name(net, radio.device_id)} ({radio.band.value} GHz)"


class BusyParams(RuleParams):
    info_pct: float = param(
        BUSY_PCT, unit="%", ge=1, le=100, description="Utilisation reported as information."
    )
    warning_pct: float = param(
        VERY_BUSY_PCT, unit="%", ge=1, le=100, description="Utilisation reported as a warning."
    )


def _enabled(net: Network) -> list[Radio]:
    return sorted((r for r in net.radios if r.enabled), key=lambda r: r.id)


@rule(
    "wifi.channel-busy",
    "Wi-Fi channel busy",
    Severity.INFO,
    "The radio reported that its channel was busy most of the time at the last read: its own "
    "clients, neighbouring networks and other radio sources share the air time, so every "
    f"client waits longer to send. From {BUSY_PCT:.0f} % this is reported for information, "
    f"from {VERY_BUSY_PCT:.0f} % as a warning. One read is a snapshot: a short peak (a large "
    "download) can trigger it, a channel that is busy at every read needs action. Radios "
    "that do not report their utilisation are skipped. The limits are the parameters "
    "info_pct and warning_pct.",
    params=BusyParams,
)
def channel_busy(net: Network) -> Iterator[Result]:
    for r in _enabled(net):
        busy = r.channel_utilisation_pct
        p = ctx.params(BusyParams, r)
        if busy is None or busy < p.info_pct:
            continue
        params: dict[str, str | int | None] = {
            "radio": _label(net, r),
            "busy": round(busy),
            "channel": r.channel,
        }
        if r.interference_pct is not None:
            params["interference"] = round(r.interference_pct)
            text = (
                f"The channel of {_label(net, r)} was busy {busy:.0f} % of the time "
                f"({r.interference_pct:.0f} % neighbours and interference)"
            )
            mid = "wifiRadio.busyInterference"
        else:
            text = f"The channel of {_label(net, r)} was busy {busy:.0f} % of the time"
            mid = "wifiRadio.busy"
        mostly_others = r.interference_pct is not None and r.interference_pct >= busy / 2
        if mostly_others and r.channel_auto:
            fix = (
                "Most of the air time is used by others although automatic channel selection "
                "picked this channel, so the band is crowded: use a narrower channel, or move "
                "clients to another band."
            )
            fix_id = "wifiRadio.busy.fixAuto"
        elif mostly_others:
            fix = (
                "Most of the air time is used by others: move the radio to a less busy channel "
                "or turn on automatic channel selection."
            )
            fix_id = "wifiRadio.busy.fixOthers"
        else:
            fix = (
                "Spread the clients over more access points or bands, or move the radio to a "
                "less busy channel."
            )
            fix_id = "wifiRadio.busy.fix"
        yield found(
            text,
            [r.id],
            fix=fix,
            severity=Severity.WARNING if busy >= p.warning_pct else Severity.INFO,
            mid=mid,
            fix_id=fix_id,
            params=params,
        )


@history_rule(
    "wifi.radar-hit",
    "Radar detected on a Wi-Fi channel",
    Severity.INFO,
    "On the 5 GHz radar (DFS) channels an access point must leave the channel when it detects "
    "radar, and may not come back for half an hour; its clients lose the network for a moment "
    "and the radio moves to another channel. Reported when the radio says radar was detected "
    "within the last 24 hours, or that it left its channel because of radar. Real radar near "
    "airports and weather stations, but also false detections by some hardware, cause this: "
    "if it repeats, a channel outside 52-144 avoids it.",
)
def radar_hit(net: Network, history: History) -> Iterator[Result]:
    for r in _enabled(net):
        if r.band is not Band.GHZ_5:
            continue
        recent = (
            r.last_radar is not None
            and history.now is not None
            and history.now - r.last_radar <= RADAR_RECENT
        )
        if not recent and r.dfs_state is not DfsState.RADAR_DETECTED:
            continue
        fix, fix_id, channels = dfs_fix(r)
        params: dict[str, str | int | None] = {"radio": _label(net, r), "channel": r.channel}
        if channels:
            params["channels"] = channels
        if recent and r.last_radar is not None:
            when = r.last_radar.strftime("%Y-%m-%d %H:%M")
            params["when"] = when
            text, mid = f"{_label(net, r)} detected radar at {when} UTC", "wifiRadio.radarAt"
        else:
            text, mid = (
                f"{_label(net, r)} left channel {r.channel} because radar was detected",
                "wifiRadio.radar",
            )
        yield found(text, [r.id], fix=fix, mid=mid, fix_id=fix_id, params=params)


#: Standards a radio is fairly limited to: Wi-Fi 7 is not expected yet (many clients cannot
#: use it), so a radio set to ``ax`` that supports ``be`` is not reported.
_EXPECTED = STANDARD_RANK[WifiStandard.AX]


@rule(
    "wifi.legacy-standard",
    "Radio set to an old Wi-Fi standard",
    Severity.INFO,
    "The radio supports a newer Wi-Fi standard than the one it is set to, so every client, "
    "also a new one, is limited to the old standard's speed and efficiency. Newer standards "
    "stay compatible with older clients, so the newest mode the radio supports (up to Wi-Fi 6, "
    "802.11ax) is usually the right choice. A warning for 802.11a, b and g (no MIMO, no wider "
    "channels), information otherwise. Radios that do not report what they support are "
    "skipped.",
)
def legacy_standard(net: Network) -> Iterator[Result]:
    for r in _enabled(net):
        if r.standard is None or not r.standards:
            continue
        best = max(r.standards, key=lambda s: STANDARD_RANK[s])
        target = min(STANDARD_RANK[best], _EXPECTED)
        if STANDARD_RANK[r.standard] >= target:
            continue
        newest = max(
            (s for s in r.standards if STANDARD_RANK[s] <= target), key=lambda s: STANDARD_RANK[s]
        )
        yield found(
            f"{_label(net, r)} is set to 802.11{r.standard.value} although it supports "
            f"802.11{newest.value}",
            [r.id],
            fix=f"Set the radio's mode to 802.11{newest.value} (older clients keep working).",
            severity=Severity.WARNING if STANDARD_RANK[r.standard] <= 1 else Severity.INFO,
            mid="wifiRadio.legacy",
            fix_id="wifiRadio.legacy.fix",
            params={
                "radio": _label(net, r),
                "standard": f"802.11{r.standard.value}",
                "newest": f"802.11{newest.value}",
            },
        )


RULES: list[Rule] = [channel_busy, radar_hit, legacy_standard]
