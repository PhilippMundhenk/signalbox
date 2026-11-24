"""Neighbouring Wi-Fi networks: evil twins, crowded channels, security on the air (#169)."""

from typing import Any

from factories import SITE
from signalbox.merge import merge
from signalbox.model import (
    Band,
    Port,
    ScanSource,
    Security,
    Site,
    Snapshot,
    WifiScanResult,
    scan_id,
)
from signalbox.neighbours import radio_neighbours, scan_rows, shares_channel
from signalbox.rules import Finding, Rule, Severity, evaluate
from signalbox.rules.wifi_neighbours import channel_crowded, rogue_ssid
from signalbox.rules.wireless import ssid_consistent
from signalbox.sightings import History
from test_rules_wireless import ap, radio, wlan

OWN = "02:00:00:00:0a:01"
TWIN = "02:5e:00:00:00:99"


def heard(dev: str, bssid: str, radio_name: str | None = "radio0", **kw: Any) -> WifiScanResult:
    rid = f"{dev}/radio/{radio_name}" if radio_name else None
    kw.setdefault("band", Band.GHZ_5)
    kw.setdefault("channel", 36)
    kw.setdefault("signal_dbm", -60)
    return WifiScanResult(
        id=scan_id(rid or dev, bssid), device_id=dev, radio_id=rid, bssid=bssid, **kw
    )


def run(r: Rule, *snaps: Snapshot) -> list[Finding]:
    net = merge([SITE, Site(id="cabin", name="Cabin")], snaps, [])
    return [f for f in evaluate(net, [r], history=History()) if f.rule_id == r.id]


def own_ap(*results: WifiScanResult, **kw: Any) -> Snapshot:
    kw.setdefault("wlans", [wlan("ap1", bssid=OWN)])
    return ap("ap1", radios=[radio("ap1", channel=36)], wifi_scan=list(results), **kw)


# wifi.rogue-ssid ------------------------------------------------------------------------------


def test_a_foreign_bssid_with_our_ssid_is_a_possible_evil_twin() -> None:
    (f,) = run(rogue_ssid, own_ap(heard("ap1", TWIN, ssid="Example", security=Security.WPA2)))
    assert f.severity is Severity.WARNING
    assert f.message == (
        "An access point that is not yours broadcasts your Wi-Fi name 'Example' "
        "(heard by ap1 (5 GHz))"
    )
    assert f.message_id == "wifiNeighbours.rogue" and f.fix_id == "wifiNeighbours.rogue.fix"
    assert TWIN not in f.message and TWIN not in (f.fix or "") and TWIN not in f.id
    assert all(TWIN not in o for o in f.objects)
    assert "ap1/radio/radio0" in f.objects and "ap1/wlan/Example/radio0" in f.objects


def test_an_open_twin_is_named_and_a_rogue_list_needs_no_own_bssids() -> None:
    result = heard(
        "ap1", TWIN, None, ssid="Example", security=Security.OPEN, kind=ScanSource.ROGUE_DETECTION
    )
    (f,) = run(rogue_ssid, own_ap(result, wlans=[wlan("ap1")]))  # our BSSID not reported
    assert f.message_id == "wifiNeighbours.rogueOpen" and "as an open network" in f.message
    assert f.params["heard"] == "ap1" and f.objects[0] == "ap1"


def test_rogue_ssid_stays_quiet() -> None:
    quiet = [
        heard("ap1", OWN, ssid="Example"),  # our own BSSID
        heard("ap1", "02:5e:00:00:00:01", ssid="Neighbour"),  # another name
        heard("ap1", "02:5e:00:00:00:02"),  # hidden
        heard("ap1", "02:00:00:00:0a:03", ssid="Example"),  # next to our MAC: a second BSSID
    ]
    assert run(rogue_ssid, own_ap(*quiet)) == []
    # a scan cannot tell ours from theirs while one of our WLANs has no BSSID
    unknown = own_ap(heard("ap1", TWIN, ssid="Example"), wlans=[wlan("ap1")])
    assert run(rogue_ssid, unknown) == []
    # a port MAC counts as ours; disabled WLANs and other sites do not count
    port = Port(id="ap1/port/phy0-ap0", device_id="ap1", name="phy0-ap0", mac=TWIN)
    assert run(rogue_ssid, own_ap(heard("ap1", TWIN, ssid="Example"), ports=[port])) == []
    off = own_ap(heard("ap1", TWIN, ssid="Example"), wlans=[wlan("ap1", bssid=OWN, enabled=False)])
    assert run(rogue_ssid, off) == []
    other_site = ap(
        "ap2",
        radios=[radio("ap2", channel=36)],
        wlans=[],
        site_id="cabin",
        wifi_scan=[heard("ap2", TWIN, ssid="Example")],
    )
    assert run(rogue_ssid, own_ap(), other_site) == []


# wifi.channel-crowded -------------------------------------------------------------------------


def _crowd(n: int, channel: int = 36, **kw: Any) -> list[WifiScanResult]:
    return [heard("ap1", f"02:5e:00:00:01:{i:02x}", channel=channel, **kw) for i in range(n)]


def test_a_crowded_channel_names_a_quieter_one() -> None:
    results = [*_crowd(3), heard("ap1", "02:5e:00:00:02:01", channel=44)]
    r = radio("ap1", channel=36, supported_channels=[36, 40, 44, 48, 52])
    (f,) = run(channel_crowded, ap("ap1", radios=[r], wifi_scan=results))
    assert f.severity is Severity.INFO
    assert f.message == "ap1 (5 GHz) shares channel 36 with 3 foreign access points"
    assert f.fix_id == "wifiNeighbours.crowded.fixChannel"
    assert f.params["better"] == 40 and f.params["better_count"] == 0
    assert f.fix == (
        "Channel 40 has 0 of them: move the radio there, or turn on automatic channel selection."
    )


def test_a_crowded_busy_24_channel_without_a_better_one() -> None:
    results = [
        heard("ap1", f"02:5e:00:00:{c:02x}:{i:02x}", channel=c, band=Band.GHZ_2_4)
        for c in (1, 6, 11)
        for i in range(3)
    ]
    r = radio("ap1", band=Band.GHZ_2_4, channel=6, channel_utilisation_pct=71.6)
    (f,) = run(channel_crowded, ap("ap1", radios=[r], wifi_scan=results))
    assert f.message.endswith("(busy 72 % of the time)")
    assert f.message_id == "wifiNeighbours.crowdedBusy"
    assert f.fix_id == "wifiNeighbours.crowded.fix24" and "5 or 6 GHz" in (f.fix or "")


def test_a_5ghz_radio_without_a_better_channel() -> None:
    r = radio("ap1", channel=36, width_mhz=20, supported_channels=[36])
    (f,) = run(channel_crowded, ap("ap1", radios=[r], wifi_scan=_crowd(4)))
    assert f.fix_id == "wifiNeighbours.crowded.fix"


def test_channel_crowded_stays_quiet() -> None:
    assert run(channel_crowded, ap("ap1", radios=[radio("ap1", channel=36)])) == []  # no scan
    assert run(channel_crowded, own_ap(*_crowd(2))) == []  # two only
    assert run(channel_crowded, own_ap(*_crowd(3, signal_dbm=-85))) == []  # too weak
    assert run(channel_crowded, own_ap(*_crowd(3, channel=149))) == []  # elsewhere
    off = ap("ap1", radios=[radio("ap1", channel=36, enabled=False)], wifi_scan=_crowd(5))
    assert run(channel_crowded, off) == []
    # own access points are wifi.channel-overlap's business
    ours = [heard("ap1", f"02:00:00:00:0b:0{i}") for i in range(3)]
    ports = [
        Port(id=f"ap1/port/p{i}", device_id="ap1", name=f"p{i}", mac=f"02:00:00:00:0b:0{i}")
        for i in range(3)
    ]
    assert run(channel_crowded, own_ap(*ours, ports=ports)) == []


# wifi.ssid-consistent: security on the air ----------------------------------------------------


def test_security_on_the_air_differs_from_the_settings() -> None:
    snap = own_ap(heard("ap1", OWN, ssid="Example", security=Security.WPA2))
    (f,) = [f for f in run(ssid_consistent, snap) if f.message_id == "wireless.airSecurity"]
    assert f.severity is Severity.WARNING
    assert f.message == (
        "SSID 'Example' at site home: ap1 announces wpa2-psk on the air although it is set to "
        "wpa2-wpa3"
    )
    assert list(f.objects) == ["ap1/wlan/Example/radio0"]


def test_security_on_the_air_stays_quiet() -> None:
    same = own_ap(heard("ap1", OWN, ssid="Example", security=Security.WPA2_WPA3))
    unknown = own_ap(heard("ap1", OWN, ssid="Example"))
    other = own_ap(heard("ap1", OWN, ssid="Example", security=Security.OTHER))
    for snap in (same, unknown, other):
        assert not [f for f in run(ssid_consistent, snap) if f.message_id == "wireless.airSecurity"]


# signalbox.neighbours -------------------------------------------------------------------------


def test_radio_neighbours_and_scan_rows() -> None:
    results = [
        heard("ap1", OWN, ssid="Example"),
        heard("ap1", TWIN, ssid="Example", signal_dbm=-50),
        heard("ap1", "02:5e:00:00:00:01", channel=40, width_mhz=80, signal_dbm=-70),
        heard("ap1", "02:5e:00:00:00:02", channel=149, signal_dbm=-40),
        heard("ap1", "02:5e:00:00:00:03", None, signal_dbm=None),  # the device's 5 GHz radio
    ]
    net = merge([SITE], [own_ap(*results)], [])
    r = net.radios[0]
    assert radio_neighbours(net, r) == {"neighbour_count": 3, "strongest_foreign_dbm": -50}
    idle = radio("ap9", channel=36)
    assert radio_neighbours(net, idle)["neighbour_count"] is None
    rows = {x["bssid"]: x for x in scan_rows(net)}
    assert rows[OWN]["own"] and not rows[OWN]["own_ssid"]
    assert rows[TWIN]["own_ssid"] and not rows["02:5e:00:00:00:01"]["own_ssid"]
    assert next(x["bssid"] for x in scan_rows(net)) == "02:5e:00:00:00:02"  # strongest first
    assert net.without_neighbour_networks().wifi_scan == []
    bare = net.without_neighbour_networks()
    assert bare.without_neighbour_networks() is bare


def test_shares_channel() -> None:
    r24 = radio("a", band=Band.GHZ_2_4, channel=6)
    assert shares_channel(r24, heard("a", TWIN, band=Band.GHZ_2_4, channel=3))
    assert not shares_channel(r24, heard("a", TWIN, band=Band.GHZ_2_4, channel=11))
    assert not shares_channel(r24, heard("a", TWIN, channel=None))
    r6 = radio("a", band=Band.GHZ_6, channel=37, width_mhz=80)
    assert shares_channel(r6, heard("a", TWIN, band=Band.GHZ_6, channel=45))
    assert not shares_channel(r6, heard("a", TWIN, band=Band.GHZ_6, channel=53))
    r5 = radio("a", channel=149, width_mhz=40)
    assert shares_channel(r5, heard("a", TWIN, channel=153))
