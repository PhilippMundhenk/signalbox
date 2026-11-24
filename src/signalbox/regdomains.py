"""A small regulatory table for Wi-Fi: which channels and how much power are allowed where (#96).

A GUIDE, NOT LEGAL ADVICE. The table covers the common regulatory domains in a few lines each,
for ``wifi.regulatory`` to catch a wrong country code or an impossible channel. Rules change,
many countries add conditions (indoor use, outdoor licensing, per-device approval) and the radio's
firmware is what really counts. Check the national regulator before relying on a value.

Source: the public Linux wireless regulatory database (``db.txt`` of
https://git.kernel.org/pub/scm/linux/kernel/git/wens/wireless-regdb.git, ISC licence), read in
November 2026. Each row is a frequency range in MHz, the maximum EIRP in dBm (regdb gives mW for
some countries; 100 mW = 20 dBm, 200 mW = 23, 250 mW = 24, 500 mW = 27, 4000 mW = 36) and the
conditions. Deviations from regdb are marked with ``NOTE`` below. A channel is allowed when its
whole 20 MHz span lies inside one range. Ranges that regdb marks NO-IR (the radio may not start
transmitting there on its own, for example 5850-5895 MHz in the US) are left out.

The EU/ETSI group uses the German entry for all EU and EEA countries: the harmonised rules are
the same; a few countries restrict single ranges further (outdoor use of 5 GHz for example).
GB and CH have their own entries, as their rules differ slightly.
"""

from __future__ import annotations

from dataclasses import dataclass

from signalbox.model import Band


@dataclass(frozen=True)
class Range:
    """One allowed frequency range."""

    start_mhz: float
    end_mhz: float
    #: Maximum EIRP in dBm; None where the table does not know a safe value.
    eirp_dbm: int | None
    #: Radar detection and avoidance (DFS) is required.
    dfs: bool = False
    #: Indoor use only.
    indoor: bool = False


@dataclass(frozen=True)
class Domain:
    """The Wi-Fi rules of one regulatory domain (a country or a group of countries)."""

    id: str
    name: str
    countries: tuple[str, ...]
    #: Ranges by band; a band without ranges is not available (6 GHz in many countries).
    ranges: dict[Band, tuple[Range, ...]]
    #: The 6 GHz rules are low-power indoor (LPI) only.
    note: str = ""

    def range_of(self, band: Band, channel: int) -> Range | None:
        """The range that contains the whole 20 MHz channel, or None: not allowed."""
        centre = channel_mhz(band, channel)
        for r in self.ranges.get(band, ()):
            if r.start_mhz <= centre - 10 and centre + 10 <= r.end_mhz:
                return r
        return None

    def allows(self, band: Band, channel: int) -> bool:
        return self.range_of(band, channel) is not None

    def channels(self, band: Band) -> list[int]:
        """The 20 MHz channels of the band that are allowed here."""
        return [c for c in PLAN[band] if self.allows(band, c)]

    def limit_dbm(self, band: Band, channels: list[int]) -> int | None:
        """The lowest known EIRP limit over the 20 MHz channels, None where none is known."""
        limits = [
            r.eirp_dbm
            for c in channels
            if (r := self.range_of(band, c)) is not None and r.eirp_dbm is not None
        ]
        return min(limits) if limits else None


#: The 20 MHz channel numbers of each band.
PLAN: dict[Band, list[int]] = {
    Band.GHZ_2_4: list(range(1, 15)),
    Band.GHZ_5: [*range(36, 65, 4), *range(100, 145, 4), *range(149, 178, 4)],
    Band.GHZ_6: list(range(1, 234, 4)),
}


def channel_mhz(band: Band, channel: int) -> float:
    """The centre frequency of a 20 MHz channel in MHz."""
    if band is Band.GHZ_2_4:
        return 2484.0 if channel == 14 else 2407.0 + 5 * channel
    if band is Band.GHZ_5:
        return 5000.0 + 5 * channel
    return 5950.0 + 5 * channel


G24, G5, G6 = Band.GHZ_2_4, Band.GHZ_5, Band.GHZ_6

_EU = Domain(
    "EU",
    "EU/ETSI (EU and EEA countries)",
    (
        *("AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE"),
        *("IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE"),
        *("IS", "LI", "NO"),
    ),
    {
        G24: (Range(2400, 2483.5, 20),),
        G5: (
            Range(5150, 5250, 23, indoor=True),
            Range(5250, 5350, 20, dfs=True, indoor=True),
            Range(5470, 5725, 27, dfs=True),
            Range(5725, 5875, 14),  # short-range devices (25 mW)
        ),
        G6: (Range(5945, 6425, 23, indoor=True),),
    },
)
_GB = Domain(
    "GB",
    "United Kingdom",
    ("GB",),
    {
        G24: (Range(2400, 2483.5, 20),),
        G5: (
            Range(5150, 5250, 23, indoor=True),
            Range(5250, 5350, 20, dfs=True, indoor=True),
            Range(5470, 5730, 27, dfs=True),
            Range(5725, 5850, 23, indoor=True),
        ),
        G6: (Range(5925, 6425, 24, indoor=True),),
    },
)
_CH = Domain(
    "CH",
    "Switzerland",
    ("CH",),
    {
        G24: (Range(2400, 2483.5, 20),),
        G5: (
            Range(5150, 5250, 23, indoor=True),
            Range(5250, 5350, 20, dfs=True, indoor=True),
            Range(5470, 5725, 27, dfs=True),
            Range(5725, 5875, 14),
        ),
        G6: (Range(5945, 6425, 23, indoor=True),),
    },
)
_US = Domain(
    "US",
    "United States (FCC)",
    ("US",),
    {
        G24: (Range(2400, 2472, 30),),
        G5: (
            Range(5150, 5250, 23),
            Range(5250, 5350, 24, dfs=True),
            Range(5470, 5730, 24, dfs=True),
            Range(5730, 5850, 30),
        ),
        # NOTE: regdb marks 6 GHz NO-IR (client of a controlling AP) because it cannot express
        # the power classes; low-power indoor (LPI) access points may use 5925-7125 MHz at up
        # to 30 dBm EIRP under FCC rules.
        G6: (Range(5925, 7125, 30, indoor=True),),
    },
    "6 GHz: low-power indoor (LPI) only; standard power needs an AFC system",
)
_CA = Domain(
    "CA",
    "Canada (ISED)",
    ("CA",),
    {
        G24: (Range(2400, 2483.5, 36),),
        G5: (
            Range(5150, 5250, 23, indoor=True),
            Range(5250, 5350, 27, dfs=True),
            Range(5470, 5730, 27, dfs=True),
            Range(5730, 5850, 36),
        ),
        # NOTE: LPI limit of ISED RSS-248 (30 dBm EIRP), regdb lists 12 dBm NO-OUTDOOR.
        G6: (Range(5925, 7125, 30, indoor=True),),
    },
    "6 GHz: low-power indoor (LPI) only",
)
_JP = Domain(
    "JP",
    "Japan",
    ("JP",),
    {
        # channel 14 (2474-2494 MHz) is allowed for 802.11b only (regdb NO-OFDM); it is accepted
        G24: (Range(2402, 2482, 20), Range(2474, 2494, 20)),
        G5: (
            Range(5170, 5250, 20, indoor=True),
            Range(5250, 5330, 20, dfs=True, indoor=True),
            Range(5490, 5730, 23, dfs=True),
        ),
        G6: (Range(5925, 6425, 23, indoor=True),),
    },
)
_AU = Domain(
    "AU",
    "Australia",
    ("AU",),
    {
        G24: (Range(2400, 2483.5, 36),),
        G5: (
            Range(5150, 5250, 23, indoor=True),
            Range(5250, 5350, 20, dfs=True, indoor=True),
            Range(5470, 5600, 27, dfs=True),
            Range(5650, 5730, 27, dfs=True),
            Range(5730, 5850, 36),
        ),
        G6: (Range(5925, 6585, 24, indoor=True),),
    },
)
_NZ = Domain(
    "NZ",
    "New Zealand",
    ("NZ",),
    {
        G24: (Range(2400, 2483.5, 36),),
        G5: (
            Range(5150, 5250, 30),
            Range(5250, 5350, 27, dfs=True),
            Range(5470, 5730, 27, dfs=True),
            Range(5725, 5875, 36),
        ),
        G6: (Range(5925, 6425, 24, indoor=True),),
    },
)
_CN = Domain(
    "CN",
    "China",
    ("CN",),
    {
        G24: (Range(2400, 2483.5, 20),),
        G5: (
            Range(5150, 5250, 23, indoor=True),
            Range(5250, 5350, 20, dfs=True, indoor=True),
            Range(5725, 5850, 33),
        ),
        # no 6 GHz Wi-Fi allocation (the band is reserved for mobile networks)
    },
    "no 6 GHz Wi-Fi allocation; 5470-5725 MHz (channels 100-144) is not open",
)
_KR = Domain(
    "KR",
    "South Korea",
    ("KR",),
    {
        G24: (Range(2400, 2483.5, 23),),
        G5: (
            Range(5150, 5230, 23),
            Range(5230, 5250, 17),
            Range(5250, 5350, 20, dfs=True),
            Range(5470, 5725, 20, dfs=True),
            Range(5725, 5850, 23),
        ),
        G6: (Range(5925, 6425, 18, indoor=True), Range(6425, 7125, 15, indoor=True)),
    },
)
_IN = Domain(
    "IN",
    "India",
    ("IN",),
    {
        G24: (Range(2402, 2482, 30),),
        G5: (
            Range(5150, 5250, 30),
            Range(5250, 5350, 24, dfs=True),
            Range(5470, 5725, 24, dfs=True),
            Range(5725, 5875, 30),
        ),
        G6: (Range(5925, 6425, 24, indoor=True),),
    },
)
_BR = Domain(
    "BR",
    "Brazil",
    ("BR",),
    {
        G24: (Range(2400, 2483.5, 30),),
        G5: (
            Range(5150, 5250, 27, indoor=True),
            Range(5250, 5350, 27, dfs=True, indoor=True),
            Range(5470, 5725, 27, dfs=True),
            Range(5725, 5850, 30),
        ),
        # NOTE: regdb lists 12 dBm NO-OUTDOOR for 6 GHz; the LPI limit is not taken over
        G6: (Range(5925, 7125, None, indoor=True),),
    },
    "6 GHz: low-power indoor (LPI) only",
)

#: Every domain of the table.
DOMAINS: tuple[Domain, ...] = (_EU, _GB, _CH, _US, _CA, _JP, _AU, _NZ, _CN, _KR, _IN, _BR)

_BY_COUNTRY = {code: d for d in DOMAINS for code in d.countries}


def domain_of(country: str | None) -> Domain | None:
    """The domain of an ISO 3166 country code, None for a missing or unknown code."""
    if not country:
        return None
    return _BY_COUNTRY.get(country.strip().upper())
