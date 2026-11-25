"""Roaming settings across access points (#168) and client association rules (#170)."""

from typing import Any

from factories import SITE, snapshot
from signalbox.merge import merge
from signalbox.model import (
    Client,
    FastTransition,
    Snapshot,
    WifiStandard,
    WirelessAssociation,
)
from signalbox.rules import Finding, Rule, Severity, evaluate
from signalbox.rules.wifi_roaming import (
    MIN_RSSI_HIGH_DBM,
    RULES,
    WEAK_CLIENT_SIGNAL_DBM,
    client_weak_signal,
    ft_mobility_domain_mismatch,
    legacy_client,
    min_rssi_inconsistent,
    min_rssi_too_high,
)
from test_rules_wireless import ap, wlan

WLAN_ID = "ap1/wlan/Example/radio0"
MAC = "02:00:00:00:00:51"


def run(r: Rule, *snaps: Snapshot) -> list[Finding]:
    net = merge([SITE], snaps)
    return [f for f in evaluate(net, [r]) if f.rule_id == r.id]


def with_clients(*clients: Client) -> Snapshot:
    base = ap("ap1")
    return snapshot(base.device, radios=base.radios, wlans=base.wlans, clients=list(clients))


def station(**kw: Any) -> Client:
    association = WirelessAssociation(wlan_id=WLAN_ID, **kw)
    return Client(
        id=f"ap1/client/{MAC}",
        mac=MAC,
        hostname="laptop",
        seen_on=WLAN_ID,
        wireless=association,
    )


def test_rules_are_exported() -> None:
    assert [r.id for r in RULES] == [
        "wifi.ft-mobility-domain-mismatch",
        "wifi.min-rssi-too-high",
        "wifi.min-rssi-inconsistent",
        "wifi.client-weak-signal",
        "wifi.legacy-client",
    ]


# wifi.ft-mobility-domain-mismatch -------------------------------------------------------------


def ft_ap(dev: str, domain: str | None, **kw: Any) -> Snapshot:
    ft = FastTransition(mobility_domain=domain) if domain else None
    return ap(dev, wlans=[wlan(dev, ft=ft, **kw)])


def test_mobility_domain_mismatch_is_found() -> None:
    (f,) = run(ft_mobility_domain_mismatch, ft_ap("ap1", "a1b2"), ft_ap("ap2", "c3d4"))
    assert f.severity is Severity.WARNING
    assert f.message_id == "wifi.ftDomainMismatch"
    assert f.params == {"ssid": "'Example'", "domains": "ap1: a1b2, ap2: c3d4"}
    assert len(f.entities) == 2


def test_mobility_domain_quiet_when_equal_unknown_or_off() -> None:
    assert run(ft_mobility_domain_mismatch, ft_ap("ap1", "a1b2"), ft_ap("ap2", "a1b2")) == []
    assert run(ft_mobility_domain_mismatch, ft_ap("ap1", "a1b2"), ft_ap("ap2", None)) == []
    off = ft_ap("ap2", "c3d4", roaming_80211r=False)
    assert run(ft_mobility_domain_mismatch, ft_ap("ap1", "a1b2"), off) == []
    assert run(ft_mobility_domain_mismatch, ft_ap("ap1", "a1b2")) == []


# wifi.min-rssi-too-high -----------------------------------------------------------------------


def test_min_rssi_too_high_is_found() -> None:
    (f,) = run(min_rssi_too_high, ap("ap1", wlans=[wlan("ap1", min_rssi_dbm=-65)]))
    assert f.message_id == "wifi.minRssiHigh"
    assert f.params == {"ssid": "'Example'", "ap": "ap1", "dbm": -65, "suggested": -75}
    (g,) = run(min_rssi_too_high, ap("ap1", wlans=[wlan("ap1", assoc_rssi_dbm=-60)]))
    assert g.params["dbm"] == -60


def test_min_rssi_too_high_quiet() -> None:
    assert MIN_RSSI_HIGH_DBM == -70
    for kw in (
        {"min_rssi_dbm": -70},
        {"min_rssi_dbm": -80},
        {},
        {"min_rssi_dbm": -50, "enabled": False},
    ):
        assert run(min_rssi_too_high, ap("ap1", wlans=[wlan("ap1", **kw)])) == []


# wifi.min-rssi-inconsistent -------------------------------------------------------------------


def limit_ap(dev: str, dbm: int | None) -> Snapshot:
    return ap(dev, wlans=[wlan(dev, min_rssi_dbm=dbm)])


def test_min_rssi_inconsistent_is_found() -> None:
    (f,) = run(min_rssi_inconsistent, limit_ap("ap1", -75), limit_ap("ap2", -85))
    assert f.severity is Severity.INFO
    assert f.params == {"ssid": "'Example'", "limits": "ap1: -75 dBm, ap2: -85 dBm"}


def test_min_rssi_inconsistent_quiet() -> None:
    assert run(min_rssi_inconsistent, limit_ap("ap1", -75), limit_ap("ap2", -75)) == []
    assert run(min_rssi_inconsistent, limit_ap("ap1", -75), limit_ap("ap2", None)) == []
    assert run(min_rssi_inconsistent, limit_ap("ap1", -75)) == []


# wifi.client-weak-signal ----------------------------------------------------------------------


def test_weak_client_signal_is_found() -> None:
    (f,) = run(client_weak_signal, with_clients(station(signal_dbm=-82)))
    assert f.severity is Severity.INFO
    assert f.message_id == "wifi.clientWeakSignal"
    assert f.params == {"client": f"laptop ({MAC})", "dbm": -82, "ap": "ap1"}
    assert set(f.entities) == {f"client/{MAC}", WLAN_ID}


def test_weak_client_signal_quiet() -> None:
    assert WEAK_CLIENT_SIGNAL_DBM == -75
    assert run(client_weak_signal, with_clients(station(signal_dbm=-75))) == []
    assert run(client_weak_signal, with_clients(station(signal_dbm=-50))) == []
    assert run(client_weak_signal, with_clients(station())) == []  # no reading
    wired = Client(id=f"ap1/client/{MAC}", mac=MAC)
    assert run(client_weak_signal, with_clients(wired)) == []
    unknown_wlan = station(signal_dbm=-90).model_copy(
        update={"wireless": WirelessAssociation(wlan_id="gone/wlan/x", signal_dbm=-90)}
    )
    assert run(client_weak_signal, with_clients(unknown_wlan)) == []


# wifi.legacy-client ---------------------------------------------------------------------------


def test_legacy_client_is_found() -> None:
    for standard in (WifiStandard.B, WifiStandard.G):
        (f,) = run(legacy_client, with_clients(station(standard=standard)))
        assert f.message_id == "wifi.legacyClient"
        assert f.params == {"client": f"laptop ({MAC})", "ap": "ap1", "standard": standard.value}


def test_legacy_client_quiet() -> None:
    for standard in (WifiStandard.N, WifiStandard.AC, WifiStandard.AX, WifiStandard.A, None):
        assert run(legacy_client, with_clients(station(standard=standard))) == []
