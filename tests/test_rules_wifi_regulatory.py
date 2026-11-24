"""wifi.regulatory and the regulatory table (#96)."""

import pytest

from factories import SITE
from signalbox.merge import merge
from signalbox.model import Band, Radio, Site, Snapshot
from signalbox.regdomains import DOMAINS, channel_mhz, domain_of
from signalbox.rules import Finding, Severity, evaluate
from signalbox.rules.wifi_regulatory import regulatory
from test_rules_wireless import ap, radio


def run(*snaps: Snapshot) -> list[Finding]:
    net = merge([SITE, Site(id="cabin", name="Cabin")], snaps, [])
    return [f for f in evaluate(net, [regulatory]) if f.rule_id == regulatory.id]


def one(r: Radio) -> list[Finding]:
    return run(ap("ap1", radios=[r]))


# the table ------------------------------------------------------------------------------------


def test_table_lookup() -> None:
    assert domain_of("de") is domain_of("FR") is DOMAINS[0]
    assert domain_of("ZZ") is None and domain_of(None) is None and domain_of("") is None
    us = domain_of("US")
    assert us is not None
    assert us.channels(Band.GHZ_2_4) == list(range(1, 12))
    assert us.limit_dbm(Band.GHZ_5, [36, 52]) == 23
    assert us.limit_dbm(Band.GHZ_5, [177]) is None
    assert channel_mhz(Band.GHZ_2_4, 14) == 2484 and channel_mhz(Band.GHZ_6, 1) == 5955
    assert 144 not in DOMAINS[0].channels(Band.GHZ_5)
    assert 144 in us.channels(Band.GHZ_5)
    cn = domain_of("CN")
    assert cn is not None and cn.channels(Band.GHZ_6) == []


def test_every_domain_has_24_ghz_and_unique_countries() -> None:
    codes = [c for d in DOMAINS for c in d.countries]
    assert len(codes) == len(set(codes))
    for d in DOMAINS:
        assert d.channels(Band.GHZ_2_4)


# channels -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("band", "channel", "country"),
    [
        (Band.GHZ_2_4, 13, "DE"),
        (Band.GHZ_2_4, 11, "US"),
        (Band.GHZ_5, 149, "DE"),
        (Band.GHZ_5, 100, "GB"),
        (Band.GHZ_5, 144, "US"),
        (Band.GHZ_6, 5, "FR"),
        (Band.GHZ_6, 1, "US"),
    ],
)
def test_allowed_channels_are_quiet(band: Band, channel: int, country: str) -> None:
    assert one(radio("ap1", band=band, channel=channel, country=country)) == []


def test_channel_not_allowed() -> None:
    (f,) = one(radio("ap1", band=Band.GHZ_2_4, channel=13, country="US"))
    assert f.severity is Severity.ERROR
    assert f.message_id == "wifiRegulatory.channel" and f.fix_id == "wifiRegulatory.channel.fix"
    assert f.params["channels"] == "1-11" and f.params["country"] == "US"
    assert "channel 13" in f.message and "1-11" in (f.fix or "")


def test_lower_case_country_and_5ghz_channel() -> None:
    (f,) = one(radio("ap1", channel=177, country="de"))
    assert f.message_id == "wifiRegulatory.channel"
    assert f.params["country"] == "DE"


def test_wide_channel_span() -> None:
    # 40 MHz at 140 + 144: channel 144 ends above 5725 MHz, not allowed in the EU
    (f,) = one(radio("ap1", channel=140, width_mhz=40, country="DE"))
    assert f.message_id == "wifiRegulatory.width" and f.severity is Severity.ERROR
    assert f.params["blocked"] == "144" and f.fix_id == "wifiRegulatory.width.fix"
    assert one(radio("ap1", channel=140, width_mhz=40, country="US")) == []
    assert one(radio("ap1", channel=116, width_mhz=160, country="DE")) == []


def test_24_secondary_channel_counts() -> None:
    kw = {"band": Band.GHZ_2_4, "channel": 9, "width_mhz": 40, "secondary_channel": 13}
    (f,) = one(radio("ap1", country="US", **kw))
    assert f.message_id == "wifiRegulatory.width" and f.params["blocked"] == "13"
    assert one(radio("ap1", country="DE", **kw)) == []


def test_six_ghz_without_allocation() -> None:
    (f,) = one(radio("ap1", band=Band.GHZ_6, channel=5, country="CN"))
    assert f.message_id == "wifiRegulatory.noBand" and f.severity is Severity.ERROR
    assert f.fix_id == "wifiRegulatory.noBand.fix"


def test_device_channel_list_wins() -> None:
    allowed = list(range(1, 14))
    r = radio("ap1", band=Band.GHZ_2_4, channel=13, country="US", supported_channels=allowed)
    assert one(r) == []
    r = radio("ap1", band=Band.GHZ_2_4, channel=13, country="DE", supported_channels=allowed[:11])
    (f,) = one(r)
    assert f.params["channels"] == "1-11"
    (g,) = one(radio("ap1", band=Band.GHZ_6, channel=5, country="DE", supported_channels=[]))
    assert g.message_id == "wifiRegulatory.noBand"
    # a country the table does not know, but the device lists its channels
    assert one(radio("ap1", channel=36, country="ZZ", supported_channels=[36, 40])) == []
    (h,) = one(radio("ap1", channel=44, country="ZZ", supported_channels=[36, 40]))
    assert h.message_id == "wifiRegulatory.channel"


# power ----------------------------------------------------------------------------------------


def test_power_above_limit() -> None:
    (f,) = one(radio("ap1", band=Band.GHZ_2_4, channel=1, tx_power_dbm=23))
    assert f.severity is Severity.WARNING
    assert f.message_id == "wifiRegulatory.power" and f.fix_id == "wifiRegulatory.power.fix"
    assert f.params["limit"] == 20 and f.params["power"] == 23
    assert one(radio("ap1", band=Band.GHZ_2_4, channel=1, tx_power_dbm=20)) == []
    (g,) = one(radio("ap1", channel=36, country="US", tx_power_dbm=24))
    assert g.params["limit"] == 23
    assert one(radio("ap1", channel=149, country="US", tx_power_dbm=24)) == []


def test_power_stays_quiet_without_data() -> None:
    assert one(radio("ap1", channel=36, tx_power_dbm=None)) == []
    assert one(radio("ap1", channel=36, country="ZZ", tx_power_dbm=40)) == []
    # no known limit (Brazil 6 GHz)
    assert one(radio("ap1", band=Band.GHZ_6, channel=5, country="BR", tx_power_dbm=40)) == []


def test_no_power_finding_for_a_blocked_channel() -> None:
    fs = one(radio("ap1", band=Band.GHZ_2_4, channel=13, country="US", tx_power_dbm=40))
    assert [f.message_id for f in fs] == ["wifiRegulatory.channel"]


# country and quiet cases -----------------------------------------------------------------------


def test_missing_country_is_left_to_wifi_country() -> None:
    assert one(radio("ap1", country=None, channel=36)) == []


def test_quiet_cases() -> None:
    assert one(radio("ap1", enabled=False, country=None)) == []
    assert one(radio("ap1", channel=None)) == []
    assert one(radio("ap1", channel=13, band=Band.GHZ_2_4, country="ZZ")) == []
