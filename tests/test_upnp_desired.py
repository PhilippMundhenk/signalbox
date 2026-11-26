"""UPnP, NAT-PMP and PCP in the desired state (#513, ADR 0035): syntax, planner, drift, import
and the predicted network. Only declared fields change, a widening change is marked, devices
without an entry are never touched, and a device without UPnP satisfies ``enabled: false``."""

from __future__ import annotations

from typing import Any

import pytest

from factories import SITE, device, net, service
from signalbox.changes import (
    UPNP_DENY_ALL,
    ChangeKind,
    PlanError,
    UpnpValue,
    apply_change,
    changes_for,
    observed_upnp,
    plan,
    upnp_widens,
)
from signalbox.deploy import current_value
from signalbox.desired import DesiredError, drift_rules, dump, from_network, parse
from signalbox.model import (
    DeviceStatus,
    DeviceUpnp,
    Network,
    ServiceKind,
    UpnpAclRule,
    UpnpProtocol,
    object_id,
    segment_id,
)
from signalbox.rules import evaluate
from signalbox.rules.builtin import RULES

NATIVE = segment_id("home", None)
IOT = segment_id("home", 20)
HIGH = UpnpAclRule(
    allow=True, external_first=1024, internal_network=net("192.0.2.0/24"), internal_first=1024
)


def upnp_service(device_id: str, **kw: Any) -> Any:
    return service(device_id, ServiceKind.UPNP, "upnp", port=None, **kw)


def network(**kw: Any) -> Network:
    """Two gateways with UPnP on: gw (secure mode, the LAN, one rule) and other (no settings)."""
    upnp = DeviceUpnp(
        protocols=[UpnpProtocol.IGD, UpnpProtocol.NAT_PMP],
        secure_mode=True,
        allow_rules=[HIGH, UPNP_DENY_ALL],
    )
    values: dict[str, Any] = {
        "sites": [SITE],
        "devices": [device("gw", upnp=upnp), device("other", upnp=DeviceUpnp())],
        "services": [upnp_service("gw", segments=[NATIVE]), upnp_service("other")],
    }
    return Network(**(values | kw))


def text(body: str, device_id: str = "gw") -> str:
    return f"sites:\n  home:\n    upnp:\n      - device: {device_id}\n{body}"


# --- syntax -------------------------------------------------------------------------------------


def test_syntax_round_trips() -> None:
    state = parse(
        text(
            "        enabled: true\n        secure_mode: false\n        networks: [native, 20]\n"
            "        allow:\n          - {network: 192.0.2.0/25}\n"
            "          - {network: 198.51.100.0/24, ports: 5000-5100}\n"
        )
    )
    [u] = state.sites["home"].upnp
    assert (u.device, u.enabled, u.secure_mode, u.networks) == ("gw", True, False, ["native", 20])
    assert u.allow is not None and [str(a.ports) for a in u.allow] == ["1024-65535", "5000-5100"]
    assert parse(dump(state)) == state


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("        networks: []\n", "networks"),
        ("        allow:\n          - {network: not-a-network}\n", "network"),
        ("        allow:\n          - {network: 192.0.2.0/24, ports: [1, 2]}\n", "one port"),
        ("        mappings: []\n", "mappings"),
    ],
)
def test_wrong_entries_are_refused(body: str, message: str) -> None:
    with pytest.raises(DesiredError, match=message):
        parse(text(body))


def test_a_device_may_be_declared_once_across_files() -> None:
    merged = parse(text("        enabled: false\n")).merged(
        parse(text("        secure_mode: true\n"))
    )
    with pytest.raises(DesiredError, match="UPnP of gw declared twice"):
        parse(dump(merged))


# --- planner ------------------------------------------------------------------------------------


def test_off_changes_only_the_switch_and_is_not_a_widening() -> None:
    [c] = changes_for(parse(text("        enabled: false\n")), network())
    assert (c.kind, c.key, c.device_id, c.risk) == (ChangeKind.UPNP, "upnp", "gw", None)
    assert isinstance(c.old, UpnpValue) and isinstance(c.new, UpnpValue)
    assert c.old == observed_upnp(network(), "gw")
    assert c.new == c.old.model_copy(update={"enabled": False})  # the rest as the device has it
    assert current_value(network(), c) == c.old


def test_devices_without_an_entry_are_never_touched() -> None:
    changes = changes_for(parse(text("        enabled: false\n")), network())
    assert {c.device_id for c in changes} == {"gw"}
    assert changes_for(parse("sites:\n  home: {}\n"), network()) == []


def test_a_matching_declaration_needs_no_change() -> None:
    same = text(
        "        enabled: true\n        secure_mode: true\n        networks: [native]\n"
        "        allow:\n          - {network: 192.0.2.0/24}\n"
    )
    assert changes_for(parse(same), network()) == []


def test_allow_is_the_whole_list_ending_in_deny() -> None:
    [c] = changes_for(
        parse(text("        allow:\n          - {network: 192.0.2.0/25, ports: 8000-8100}\n")),
        network(),
    )
    assert isinstance(c.new, UpnpValue)
    assert c.new.rules == [
        UpnpAclRule(
            allow=True,
            external_first=8000,
            external_last=8100,
            internal_network=net("192.0.2.0/25"),
            internal_first=8000,
            internal_last=8100,
        ),
        UPNP_DENY_ALL,
    ]
    assert c.risk is None  # fewer clients and ports: narrower


@pytest.mark.parametrize(
    ("body", "what"),
    [
        ("        secure_mode: false\n", "turns secure mode off"),
        ("        networks: [native, 20]\n", "adds networks"),
        ("        allow:\n          - {network: 198.51.100.0/24}\n", "lets more clients"),
    ],
)
def test_a_widening_change_is_marked(body: str, what: str) -> None:
    [c] = changes_for(parse(text(body)), network())
    assert c.risk is not None and c.risk.startswith("widens UPnP: ") and what in c.risk


def test_turning_it_on_is_marked_and_only_when_declared() -> None:
    off = network(services=[upnp_service("gw", enabled=False, segments=[NATIVE])])
    # narrowing a service that is off keeps it off
    narrow = "        allow:\n          - {network: 192.0.2.0/25}\n"
    [c] = changes_for(parse(text(narrow)), off)
    assert isinstance(c.new, UpnpValue) and c.new.enabled is False and c.risk is None
    [c] = changes_for(parse(text("        enabled: true\n")), off)
    assert c.risk == "widens UPnP: turns it on"


def test_widening_rules() -> None:
    old = UpnpValue(enabled=True, secure_mode=True, networks=[NATIVE], rules=[HIGH, UPNP_DENY_ALL])
    assert upnp_widens(old, old) == []
    assert upnp_widens(old, old.model_copy(update={"networks": []})) == ["adds networks"]
    assert upnp_widens(None, old) == ["turns it on"]
    assert upnp_widens(None, old.model_copy(update={"enabled": False})) == []
    no_rules = old.model_copy(update={"rules": []})  # none configured: nothing to compare
    assert upnp_widens(no_rules, old) == []


def test_a_device_without_upnp_satisfies_off_only() -> None:
    bare = network(services=[upnp_service("other")])
    assert changes_for(parse(text("        enabled: false\n")), bare) == []
    with pytest.raises(PlanError) as err:
        changes_for(parse(text("        secure_mode: true\n")), bare)
    assert err.value.message_id == "plan.upnpMissing"
    with pytest.raises(PlanError) as err:
        changes_for(parse(text("        enabled: false\n", device_id="nowhere")), bare)
    assert err.value.message_id == "plan.deviceUnknown"


def test_the_predicted_network_has_the_new_state() -> None:
    [c] = changes_for(
        parse(text("        enabled: false\n        secure_mode: false\n        networks: [20]\n")),
        network(),
    )
    after = apply_change(network(), c)
    assert observed_upnp(after, "gw") == c.new
    assert observed_upnp(after, "other") == observed_upnp(network(), "other")


def test_a_plan_marks_the_risk_and_checks_run() -> None:
    p = plan(parse(text("        secure_mode: false\n")), network(), RULES)
    [c] = p.changes
    assert c.risk == "widens UPnP: turns secure mode off"


# --- drift and import ---------------------------------------------------------------------------


def test_drift_compares_the_declared_fields() -> None:
    state = parse(text("        enabled: false\n        networks: [native]\n"))
    [f] = [f for f in evaluate(network(), drift_rules(state)) if f.rule_id == "drift.upnp"]
    assert f.problem and f.objects == [object_id("gw", "service", "upnp")]
    assert f.message == "UPnP of gw: enabled: should be off, is on"
    after = apply_change(network(), changes_for(state, network())[0])
    assert not [f for f in evaluate(after, drift_rules(state)) if f.rule_id == "drift.upnp"]


def test_drift_of_a_device_without_upnp_and_one_not_read() -> None:
    bare = network(services=[upnp_service("other")])
    [f] = [
        f
        for f in evaluate(bare, drift_rules(parse(text("        secure_mode: true\n"))))
        if f.rule_id == "drift.upnp"
    ]
    assert f.problem and "does not install" in f.message
    down = network(statuses={"gw": DeviceStatus.UNREACHABLE})
    [f] = [
        f
        for f in evaluate(down, drift_rules(parse(text("        enabled: false\n"))))
        if f.rule_id == "drift.upnp"
    ]
    assert not f.problem and "not read" in f.message


def test_import_writes_the_switch_and_secure_mode_only() -> None:
    state = from_network(network(), "home")
    got = {
        (u.device, u.enabled, u.secure_mode, u.networks, u.allow) for u in state.sites["home"].upnp
    }
    assert got == {("gw", True, True, None, None), ("other", True, None, None, None)}
    again = parse(dump(state))
    assert changes_for(again, network()) == []
