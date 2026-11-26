"""Wi-Fi roaming in the desired state (#489, ADR 0033): the 802.11r mobility domain and
over-DS, the minimum signal, one mobility domain per SSID, drift, import and the predicted
network."""

from __future__ import annotations

from typing import Any

import pytest

from factories import SITE, device, wlan
from signalbox.changes import (
    ChangeKind,
    PlanError,
    WlanValue,
    changes_for,
    observed_wlan,
    predict,
)
from signalbox.desired import DesiredError, drift_rules, dump, from_network, parse
from signalbox.model import DeviceRole, FastTransition, Network
from signalbox.rules import evaluate


def network(*wlans: Any) -> Network:
    if not wlans:
        wlans = (
            wlan("ap-1", security="wpa2-psk", roaming_80211r=False),
            wlan("ap-2", security="wpa2-psk", roaming_80211r=False),
        )
    return Network(
        sites=[SITE],
        devices=[device("ap-1", DeviceRole.AP), device("ap-2", DeviceRole.AP)],
        wlans=list(wlans),
    )


def ft_wlan(dev: str, domain: str | None, **kw: Any) -> Any:
    return wlan(
        dev,
        security="wpa2-psk",
        roaming_80211r=True,
        ft=FastTransition(mobility_domain=domain, over_ds=kw.pop("over_ds", None)),
        **kw,
    )


def text(extra: str) -> str:
    return (
        "sites:\n  home:\n    wlans:\n      - ssid: Example\n        security: wpa2-psk\n" + extra
    )


ROAMING = ("mobility domain", "over DS", "minimum signal", "802.11r")


def drift_messages(net: Network, state: Any) -> list[str]:
    """The roaming findings of ``drift.wlan`` (the factories' WLANs have no segment)."""
    return [
        f.message
        for f in evaluate(net, drift_rules(state))
        if f.rule_id == "drift.wlan" and any(word in f.message for word in ROAMING)
    ]


# --- syntax -------------------------------------------------------------------------------------


def test_roaming_fields_parse_and_round_trip() -> None:
    state = parse(
        text(
            "        roaming: {r: true, mobility_domain: A1B2, over_ds: false}\n"
            "        min_rssi_dbm: -75\n"
        )
    )
    w = state.sites["home"].wlans[0]
    assert w.roaming.mobility_domain == "a1b2"
    assert w.roaming.over_ds is False
    assert w.min_rssi_dbm == -75
    assert parse(dump(state)) == state


def test_unquoted_off_is_no_limit() -> None:
    w = parse(text("        min_rssi_dbm: off\n")).sites["home"].wlans[0]
    assert w.min_rssi_dbm == "off"


@pytest.mark.parametrize(
    "extra",
    [
        "        roaming: {mobility_domain: a1b2}\n",
        "        roaming: {r: false, over_ds: true}\n",
        "        roaming: {r: true, mobility_domain: a1b}\n",
        "        roaming: {r: true, mobility_domain: zzzz}\n",
        "        min_rssi_dbm: -121\n",
        "        min_rssi_dbm: 0\n",
        "        min_rssi_dbm: weak\n",
    ],
)
def test_invalid_roaming_fields_are_refused(extra: str) -> None:
    with pytest.raises(DesiredError):
        parse(text(extra))


# --- planner ------------------------------------------------------------------------------------


def test_declared_domain_is_planned_for_every_access_point() -> None:
    state = parse(text("        roaming: {r: true, mobility_domain: a1b2, over_ds: false}\n"))
    changes = changes_for(state, network())
    assert {c.device_id for c in changes} == {"ap-1", "ap-2"}
    for c in changes:
        assert c.kind is ChangeKind.WLAN
        assert isinstance(c.new, WlanValue)
        assert c.new.roaming_80211r is True
        assert c.new.mobility_domain == "a1b2"
        assert c.new.ft_over_ds is False


def test_turning_on_ft_without_a_domain_on_several_aps_is_refused() -> None:
    with pytest.raises(PlanError) as err:
        changes_for(parse(text("        roaming: {r: true}\n")), network())
    assert err.value.message_id == "plan.mobilityDomainSplit"
    assert "ap-1 (?)" in str(err.value)


def test_split_domains_are_refused_when_the_ssid_changes() -> None:
    net = network(ft_wlan("ap-1", "a1b2"), ft_wlan("ap-2", "c3d4"))
    with pytest.raises(PlanError) as err:
        changes_for(parse(text("        roaming: {r: true}\n        hidden: true\n")), net)
    assert "ap-1 (a1b2), ap-2 (c3d4)" in str(err.value)


def test_split_domains_without_a_change_plan_nothing() -> None:
    net = network(ft_wlan("ap-1", "a1b2"), ft_wlan("ap-2", "c3d4"))
    assert changes_for(parse(text("        roaming: {r: true}\n")), net) == []


def test_one_reported_domain_is_kept_without_a_declaration() -> None:
    net = network(ft_wlan("ap-1", "a1b2"), ft_wlan("ap-2", "a1b2"))
    changes = changes_for(parse(text("        roaming: {r: true}\n        hidden: true\n")), net)
    assert len(changes) == 2
    assert all(isinstance(c.new, WlanValue) and c.new.mobility_domain == "a1b2" for c in changes)


def test_single_access_point_needs_no_domain() -> None:
    state = parse(text("        devices: [ap-1]\n        roaming: {r: true}\n"))
    changes = changes_for(state, network())
    assert [c.device_id for c in changes] == ["ap-1"]


def test_minimum_signal_is_planned_against_both_reported_fields() -> None:
    net = network(
        wlan("ap-1", security="wpa2-psk", assoc_rssi_dbm=-80),
        wlan("ap-2", security="wpa2-psk", min_rssi_dbm=-75),
    )
    changes = changes_for(parse(text("        min_rssi_dbm: -75\n")), net)
    assert [(c.device_id, c.new.min_rssi_dbm) for c in changes] == [("ap-1", -75)]  # type: ignore[union-attr]


def test_off_only_changes_a_device_that_reports_a_limit() -> None:
    net = network(
        wlan("ap-1", security="wpa2-psk", assoc_rssi_dbm=-80), wlan("ap-2", security="wpa2-psk")
    )
    changes = changes_for(parse(text("        min_rssi_dbm: off\n")), net)
    assert [(c.device_id, c.new.min_rssi_dbm) for c in changes] == [("ap-1", "off")]  # type: ignore[union-attr]


def test_undeclared_fields_keep_what_the_device_has() -> None:
    net = network(
        ft_wlan("ap-1", "a1b2", over_ds=True, min_rssi_dbm=-70),
        ft_wlan("ap-2", "a1b2", over_ds=True, min_rssi_dbm=-70),
    )
    old = observed_wlan(net, "ap-1", "Example")
    assert old is not None
    assert (old.mobility_domain, old.ft_over_ds, old.min_rssi_dbm) == ("a1b2", True, -70)
    changes = changes_for(parse(text("        hidden: true\n")), net)
    assert all(
        isinstance(c.new, WlanValue)
        and (c.new.mobility_domain, c.new.ft_over_ds, c.new.min_rssi_dbm) == ("a1b2", True, -70)
        for c in changes
    )


def test_prediction_holds_the_new_fields() -> None:
    state = parse(
        text(
            "        roaming: {r: true, mobility_domain: a1b2, over_ds: true}\n"
            "        min_rssi_dbm: -72\n"
        )
    )
    net = network()
    after = predict(net, changes_for(state, net))
    for w in after.wlans:
        assert w.ft is not None
        assert (w.ft.mobility_domain, w.ft.over_ds, w.min_rssi_dbm) == ("a1b2", True, -72)
    assert drift_messages(after, state) == []


# --- drift and import ---------------------------------------------------------------------------


def test_drift_reports_domain_over_ds_and_signal() -> None:
    net = network(
        ft_wlan("ap-1", "c3d4", over_ds=True, assoc_rssi_dbm=-85),
        ft_wlan("ap-2", "a1b2", over_ds=False),
    )
    state = parse(
        text(
            "        roaming: {r: true, mobility_domain: a1b2, over_ds: false}\n"
            "        min_rssi_dbm: -75\n"
        )
    )
    found = drift_messages(net, state)
    assert any("ap-1 mobility domain" in m for m in found)
    assert any("ap-1 802.11r over DS" in m for m in found)
    assert any("ap-1 minimum signal" in m for m in found)
    assert any("ap-2 minimum signal" in m and "none reported" in m for m in found)
    assert not any("ap-2 mobility domain" in m for m in found)


def test_drift_reports_a_split_domain_without_a_declaration() -> None:
    net = network(ft_wlan("ap-1", "a1b2"), ft_wlan("ap-2", "c3d4"))
    found = drift_messages(net, parse(text("        roaming: {r: true}\n")))
    assert any("more than one mobility domain" in m for m in found)
    one = network(ft_wlan("ap-1", "a1b2"), ft_wlan("ap-2", "a1b2"))
    assert drift_messages(one, parse(text("        roaming: {r: true}\n"))) == []


def test_off_is_no_drift_where_no_limit_is_reported() -> None:
    assert drift_messages(network(), parse(text("        min_rssi_dbm: off\n"))) == []


def test_import_exports_shared_values_only() -> None:
    same = network(
        ft_wlan("ap-1", "a1b2", over_ds=False, min_rssi_dbm=-75),
        ft_wlan("ap-2", "a1b2", over_ds=False, min_rssi_dbm=-75),
    )
    w = from_network(same, "home").sites["home"].wlans[0]
    assert (w.roaming.mobility_domain, w.roaming.over_ds, w.min_rssi_dbm) == ("a1b2", False, -75)
    split = network(
        ft_wlan("ap-1", "a1b2", min_rssi_dbm=-75), ft_wlan("ap-2", "c3d4", min_rssi_dbm=-70)
    )
    w = from_network(split, "home").sites["home"].wlans[0]
    assert (w.roaming.mobility_domain, w.min_rssi_dbm) == (None, None)
