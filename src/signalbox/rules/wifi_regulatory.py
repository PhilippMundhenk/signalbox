"""Wi-Fi channels and transmit power against the radio's country (issue #96).

Uses the small table in :mod:`signalbox.regdomains` (a guide, not legal advice). A channel list
the device reports itself (#172) wins over the table.
"""

from __future__ import annotations

from collections.abc import Iterator

from signalbox.model import Band, Network, Radio
from signalbox.regdomains import Domain, domain_of
from signalbox.rules import Result, Rule, Severity, found, rule
from signalbox.rules._names import device_name
from signalbox.rules.wireless import _occupied, channel_ranges


def _label(net: Network, radio: Radio) -> str:
    return f"{device_name(net, radio.device_id)} {radio.name} ({radio.band.value} GHz)"


def _occupied_channels(radio: Radio) -> list[int]:
    """The 20 MHz channels the radio occupies (the secondary one on 2.4 GHz)."""
    assert radio.channel is not None
    if radio.band is Band.GHZ_2_4:
        return sorted(
            {radio.channel, *([radio.secondary_channel] if radio.secondary_channel else [])}
        )
    return sorted(_occupied(radio))


@rule(
    "wifi.regulatory",
    "Wi-Fi channel or power not allowed in the radio's country",
    Severity.ERROR,
    "Each country allows only some channels and a maximum transmit power; the radio's country "
    "code selects them. A channel (or a part of a wide channel) that is not allowed there is "
    "either not used (the radio does not start) or makes the network invisible to clients set "
    "to the right country; 6 GHz is not available in every country; power above the limit is "
    "illegal and disturbs radar and others. The usual cause is a country code copied with a "
    "configuration. A channel list the device reports itself wins over Signalbox's small "
    "regulatory table, which is a guide and not legal advice. An error for a channel that is "
    "not allowed, a warning for power above the limit, information for a missing country code.",
)
def regulatory(net: Network) -> Iterator[Result]:
    for r in sorted(net.radios, key=lambda r: r.id):
        if not r.enabled:
            continue
        label = _label(net, r)
        if not r.country:
            yield found(
                f"{label} has no country code, so it uses the most restrictive world domain "
                "and its channels and power cannot be checked",
                [r.id],
                fix="Set the country code of this radio to the country it is used in.",
                severity=Severity.INFO,
                key="nocountry",
                mid="wifiRegulatory.noCountry",
                fix_id="wifiRegulatory.noCountry.fix",
                params={"radio": label},
            )
            continue
        country = r.country.upper()
        domain = domain_of(country)
        if r.channel is None:
            continue
        occupied = _occupied_channels(r)
        params: dict[str, str | int | None] = {
            "radio": label,
            "country": country,
            "channel": r.channel,
            "width": r.width_mhz or 20,
        }
        if r.supported_channels is not None:
            allowed = sorted(r.supported_channels)
            bad = [c for c in occupied if c not in allowed]
        elif domain is not None:
            allowed = domain.channels(r.band)
            bad = [c for c in occupied if not domain.allows(r.band, c)]
        else:
            continue  # a country the table does not know: quiet
        if bad and not allowed:
            yield found(
                f"{label} is on {r.band.value} GHz, which is not available in country {country}",
                [r.id],
                fix="Turn this radio off, or set the correct country code.",
                key="band",
                mid="wifiRegulatory.noBand",
                fix_id="wifiRegulatory.noBand.fix",
                params=params,
            )
            continue
        if bad:
            channels = channel_ranges(allowed, r.band)
            if r.channel in bad:
                yield found(
                    f"{label} uses channel {r.channel} with country {country}, where it is "
                    "not allowed",
                    [r.id],
                    fix="Set the correct country code, or use one of the allowed channels: "
                    f"{channels}.",
                    key="channel",
                    mid="wifiRegulatory.channel",
                    fix_id="wifiRegulatory.channel.fix",
                    params={**params, "channels": channels},
                )
            else:
                yield found(
                    f"{label} uses {params['width']} MHz around channel {r.channel} with "
                    f"country {country}, but channel {', '.join(str(c) for c in bad)} of that "
                    "span is not allowed there",
                    [r.id],
                    fix="Set the correct country code, or use a narrower channel.",
                    key="width",
                    mid="wifiRegulatory.width",
                    fix_id="wifiRegulatory.width.fix",
                    params={**params, "blocked": ", ".join(str(c) for c in bad)},
                )
            continue
        yield from _power(r, label, domain, occupied, params)


def _power(
    r: Radio,
    label: str,
    domain: Domain | None,
    occupied: list[int],
    params: dict[str, str | int | None],
) -> Iterator[Result]:
    if domain is None or r.tx_power_dbm is None:
        return
    limit = domain.limit_dbm(r.band, occupied)
    if limit is None or r.tx_power_dbm <= limit:
        return
    yield found(
        f"{label} sends at {r.tx_power_dbm} dBm, above the {limit} dBm limit for its channel "
        f"in country {params['country']}",
        [r.id],
        fix=f"Lower the transmit power to {limit} dBm or less (the limit is EIRP, including "
        "the antenna gain).",
        severity=Severity.WARNING,
        key="power",
        mid="wifiRegulatory.power",
        fix_id="wifiRegulatory.power.fix",
        params={**params, "power": r.tx_power_dbm, "limit": limit},
    )


RULES: list[Rule] = [regulatory]
