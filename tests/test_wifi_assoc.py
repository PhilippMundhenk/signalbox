"""Association and roaming readers (#168, #170): the vendor-neutral parsers."""

import hashlib

from signalbox.adapters.mikrotik import wifi_assoc as mikrotik
from signalbox.adapters.openwrt import wifi_assoc as openwrt
from signalbox.model import Band, BandSteering, FtKeyHolder, WifiStandard


def test_openwrt_default_mobility_domain_is_md5_of_ssid_with_newline() -> None:
    want = hashlib.md5(b"Example\n", usedforsecurity=False).hexdigest()[:4]  # echo | md5sum
    assert openwrt.default_mobility_domain("Example") == want


def test_openwrt_roaming_fields() -> None:
    iface = {
        "ieee80211r": "1",
        "mobility_domain": "A1B2",
        "ft_over_ds": "1",
        "ft_psk_generate_local": "1",
        "reassociation_deadline": "20000",
        "rssi_reject_assoc_rssi": "-75",
        "multicast_to_unicast": "1",
        "dtim_period": "3",
        "max_inactivity": "300",
        "maxassoc": "40",
    }
    fields = openwrt.roaming_fields(iface, {"airtime_mode": "2", "beacon_int": "100"}, "Example")
    assert fields["ft"].mobility_domain == "a1b2"
    assert fields["ft"].over_ds is True
    assert fields["ft"].key_holder is FtKeyHolder.LOCAL
    assert fields["ft"].reassociation_deadline_ms == 20000
    assert fields["assoc_rssi_dbm"] == -75
    assert fields["airtime_fairness"] is True
    assert fields["multicast_to_unicast"] is True
    assert fields["dtim_period"] == 3
    assert fields["beacon_interval_ms"] == 100
    assert fields["bss_max_idle_seconds"] == 300
    assert fields["max_clients"] == 40


def test_openwrt_roaming_fields_without_80211r_or_options() -> None:
    assert openwrt.roaming_fields({}, {}, "Example") == {}
    derived = openwrt.roaming_fields({"ieee80211r": "1"}, {}, "Example")
    assert derived["ft"].mobility_domain == openwrt.default_mobility_domain("Example")
    assert derived["ft"].over_ds is None
    assert derived["ft"].key_holder is None
    pushed = openwrt.roaming_fields({"ieee80211r": "1", "ft_psk_generate_local": "0"}, {}, "x")
    assert pushed["ft"].key_holder is FtKeyHolder.PMK_R1_PUSH


def test_openwrt_association_from_hostapd_and_iwinfo() -> None:
    entry = {
        "signal": -61,
        "ht": True,
        "vht": True,
        "he": False,
        "mfp": True,
        "rate": {"rx": 866700, "tx": 780000},
        "rrm": [113, 0, 0, 0, 0],
        "extended_capabilities": [0, 0, 8, 0],
    }
    info = {
        "noise": -95,
        "inactive": 1500,
        "connected_time": 600,
        "rx": {"vht": True, "80mhz": True, "packets": 100},
        "tx": {"packets": 200, "retries": 20, "failed": 2},
    }
    a = openwrt.association(
        entry, radio_id="r", wlan_id="w", band=Band.GHZ_5, bssid=None, iwinfo=info, noise_dbm=None
    )
    assert (a.signal_dbm, a.noise_dbm, a.snr_db) == (-61, -95, 34)
    assert (a.tx_rate_mbps, a.rx_rate_mbps) == (780.0, 866.7)
    assert a.standard is WifiStandard.AC
    assert a.width_mhz == 80
    assert (a.connected_seconds, a.inactive_seconds) == (600, 1)
    assert a.capabilities == ["11k", "11v", "pmf"]
    assert (a.retries_pct, a.tx_failed) == (10.0, 2)


def test_openwrt_association_old_release_falls_back_to_iwinfo_and_band() -> None:
    entry = {"signal": 0}  # hostapd without rate; no usable signal
    info = {"signal": -70, "rx": {"rate": 54000}, "tx": {"rate": 48000}}
    a = openwrt.association(
        entry, radio_id="r", wlan_id="w", band=Band.GHZ_2_4, bssid=None, iwinfo=info, noise_dbm=None
    )
    assert a.signal_dbm == -70
    assert (a.tx_rate_mbps, a.rx_rate_mbps) == (48.0, 54.0)
    assert a.standard is WifiStandard.G
    assert a.snr_db is None
    assert a.width_mhz is None


def test_mikrotik_rate_signal_and_uptime() -> None:
    assert mikrotik.rate("866.7Mbps-80MHz-2S-short-GI") == (866.7, 80, 2)
    assert mikrotik.rate("144.4Mbps-20MHz/2S/SGI") == (144.4, 20, 2)
    assert mikrotik.rate("1.2Gbps-160MHz") == (1200.0, 160, None)
    assert mikrotik.rate("") == (None, None, None)
    assert mikrotik.signal("-55dBm") == -55
    assert mikrotik.signal("-61") == -61
    assert mikrotik.signal("-70@6Mbps") == -70
    assert mikrotik.signal("") is None
    assert mikrotik.uptime("1h2m3s") == 3723
    assert mikrotik.uptime("3d2h") == 3 * 86400 + 2 * 3600
    assert mikrotik.uptime("00:10:00") == 600
    assert mikrotik.uptime("junk") is None


def test_mikrotik_mobility_domain_and_min_signal() -> None:
    assert mikrotik.mobility_domain("44481") == "adc1"
    assert mikrotik.mobility_domain("0xADC1") == "adc1"
    assert mikrotik.mobility_domain("") is None
    assert mikrotik.mobility_domain("70000") is None
    rows = [
        {"signal-range": "-80..120", "action": "accept"},
        {"signal-range": "-70..120", "interface": "wifi2"},
        {"signal-range": "-60..120", "mac-address": "02:00:00:00:00:01"},
        {"signal-range": "-50..120", "disabled": "true"},
        {"signal-range": "-40..120", "action": "reject"},
    ]
    assert mikrotik.min_signal(rows, "wifi1") == -80
    assert mikrotik.min_signal(rows, "wifi2") == -70
    assert mikrotik.min_signal([], "wifi1") is None


def test_mikrotik_association() -> None:
    row = {
        "signal": "-61",
        "tx-rate": "286.7Mbps-20MHz-2S",
        "rx-rate": "172Mbps-20MHz-2S",
        "uptime": "1h",
        "auth-type": "wpa3-psk-pmf",
    }
    a = mikrotik.association(
        row, radio_id=None, wlan_id="w", band=Band.GHZ_2_4, standard=WifiStandard.AX
    )
    assert (a.signal_dbm, a.tx_rate_mbps, a.rx_rate_mbps) == (-61, 286.7, 172.0)
    assert (a.width_mhz, a.spatial_streams, a.connected_seconds) == (20, 2, 3600)
    assert a.capabilities == ["pmf"]


def test_openwrt_band_steering_of_usteer_and_dawn() -> None:
    def usteer(**options: str) -> dict[str, object]:
        return {"values": {"usteer": {".type": "usteer", **options}}}

    def dawn(**options: str) -> dict[str, object]:
        return {"values": {"global": {".type": "metric", **options}}}

    none: dict[str, object] = {"values": {}}
    assert openwrt.band_steering(none, none) is None
    assert openwrt.band_steering({}, {}) is None
    assert openwrt.band_steering(usteer(), none) is BandSteering.PREFER_5GHZ  # the default
    assert openwrt.band_steering(usteer(band_steering_interval="0"), none) is BandSteering.OFF
    off = usteer(band_steering_interval="0", load_balancing_threshold="5")
    assert openwrt.band_steering(off, none) is BandSteering.BALANCE
    assert openwrt.band_steering(none, dawn()) is BandSteering.PREFER_5GHZ
    assert openwrt.band_steering(none, dawn(freq_5="0")) is BandSteering.OFF
    assert openwrt.band_steering(none, {"values": {"x": {".type": "other"}}}) is None
    both = openwrt.band_steering(usteer(band_steering_interval="0"), dawn())
    assert both is BandSteering.OFF  # usteer wins


def test_mikrotik_auth_type_capabilities() -> None:
    from signalbox.adapters.mikrotik import wifi_assoc as mt

    assert mt.capabilities({"auth-type": "wpa2-psk ft"}) == ["11r"]
    assert mt.capabilities({"auth-type": "wpa3-psk,ft"}) == ["wpa3", "11r"]
    assert mt.capabilities({"auth-type": "wpa2-psk"}) == []
    assert mt.capabilities({}) == []
    assert mt.key_holder("") is None and mt.key_holder(None) is None
