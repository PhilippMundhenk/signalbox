"""Gateway groups in the desired state (#463, ADR 0032): syntax, planner, drift, import and the
predicted network. Signalbox only changes tiers, weights and monitors of a group the user
adopted; it never creates or removes groups or members."""

from __future__ import annotations

from typing import Any

import pytest

from factories import SITE, device, ip
from signalbox.changes import (
    ChangeKind,
    GatewayGroupValue,
    PlanError,
    apply_change,
    changes_for,
    observed_group,
    plan,
    predict,
)
from signalbox.deploy import current_value
from signalbox.desired import DesiredError, drift_rules, dump, from_network, parse
from signalbox.model import (
    DeviceStatus,
    GatewayGroup,
    GatewayGroupMember,
    GroupMode,
    Network,
    UplinkState,
    object_id,
)
from signalbox.rules import evaluate
from signalbox.rules.builtin import RULES

GID = object_id("gw", "gateway-group", "failover")


def member(name: str, tier: int, **kw: Any) -> GatewayGroupMember:
    return GatewayGroupMember(name=name, tier=tier, state=UplinkState.ONLINE, **kw)


def network(*groups: GatewayGroup, **kw: Any) -> Network:
    if not groups:
        groups = (
            GatewayGroup(
                id=GID,
                device_id="gw",
                name="failover",
                mode=GroupMode.FAILOVER,
                members=[
                    member("wan", 1, weight=3, monitor_targets=[ip("198.51.100.53")]),
                    member("wanb", 2, weight=1, monitor_targets=[ip("203.0.113.53")]),
                    member("lte", 3),
                ],
                active="wan",
            ),
        )
    values: dict[str, Any] = {
        "sites": [SITE],
        "devices": [device("gw", name="Router")],
        "gateway_groups": list(groups),
    }
    return Network(**(values | kw))


def text(members: str, adopt: bool = True, name: str = "failover", device: str = "gw") -> str:
    return (
        "sites:\n  home:\n    gateway_groups:\n"
        f"      - device: {device}\n        name: {name}\n        adopt: {str(adopt).lower()}\n"
        f"        members:\n{members}"
    )


SWAP = text("          - {name: wan, tier: 2}\n          - {name: wanb, tier: 1}\n")


# --- syntax -------------------------------------------------------------------------------------


def test_syntax_round_trips() -> None:
    state = parse(
        text(
            "          - {name: wan, tier: 1, weight: 3, monitor: [192.0.2.53, 2001:db8::53]}\n"
            "          - {name: wanb, monitor: []}\n"
        )
    )
    [g] = state.sites["home"].gateway_groups
    assert (g.device, g.name, g.adopt) == ("gw", "failover", True)
    assert g.members[0].monitor == [ip("192.0.2.53"), ip("2001:db8::53")]
    assert g.members[1].monitor == [] and g.members[1].tier is None
    assert parse(dump(state)) == state


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("          - {name: wan, tier: 0}\n", "tier"),
        ("          - {name: wan, weight: -1}\n", "weight"),
        ("          - {name: wan, monitor: [not-an-address]}\n", "monitor"),
        ("          - {name: wan}\n          - {name: wan}\n", "member declared twice"),
        ("          - {name: wan, mode: balance}\n", "mode"),
    ],
)
def test_wrong_groups_are_refused(body: str, message: str) -> None:
    with pytest.raises(DesiredError, match=message):
        parse(text(body))


def test_a_group_may_be_declared_once_across_files() -> None:
    a = parse(text("          - {name: wan, tier: 1}\n"))
    b = parse(text("          - {name: wanb, tier: 1}\n"))
    merged = a.merged(b)
    assert len(merged.sites["home"].gateway_groups) == 2
    with pytest.raises(DesiredError, match="gateway group declared twice: gw/failover"):
        parse(dump(merged))


# --- planner ------------------------------------------------------------------------------------


def test_tiers_are_swapped_and_undeclared_members_kept() -> None:
    [c] = changes_for(parse(SWAP), network())
    assert (c.kind, c.key, c.adopt, c.device_id) == (
        ChangeKind.GATEWAY_GROUP,
        "group/failover",
        "failover",
        "gw",
    )
    assert isinstance(c.old, GatewayGroupValue) and isinstance(c.new, GatewayGroupValue)
    tiers = {m.name: m.tier for m in c.new.members}
    # wan 2, wanb 1, lte keeps the highest tier: renumbered 2, 1, 3
    assert tiers == {"wan": 2, "wanb": 1, "lte": 3}
    weights = {m.name: m.weight for m in c.new.members}
    assert weights == {"wan": 3, "wanb": 1, "lte": None}  # not declared: as the device has them
    assert c.old == observed_group(network(), "gw", c.key)


def test_tiers_are_ranks_and_monitors_sets() -> None:
    same = text(
        "          - {name: wan, tier: 10, monitor: [198.51.100.53, 198.51.100.53]}\n"
        "          - {name: wanb, tier: 20}\n"
        "          - {name: lte, tier: 30}\n"
    )
    assert changes_for(parse(same), network()) == []
    [c] = changes_for(
        parse(text("          - {name: wan, monitor: [203.0.113.9, 192.0.2.53]}\n")), network()
    )
    assert isinstance(c.new, GatewayGroupValue)
    assert c.new.members[0].monitor == [ip("192.0.2.53"), ip("203.0.113.9")]  # sorted
    [c] = changes_for(parse(text("          - {name: wan, monitor: []}\n")), network())
    assert isinstance(c.new, GatewayGroupValue) and c.new.members[0].monitor == []


def test_a_plan_needs_adopt_but_drift_does_not() -> None:
    state = parse(SWAP.replace("adopt: true", "adopt: false"))
    with pytest.raises(PlanError, match="add adopt: true") as err:
        changes_for(state, network())
    assert err.value.message_id == "plan.groupAdopt"
    found = [
        f for f in evaluate(network(), drift_rules(state)) if f.rule_id == "drift.gateway-group"
    ]
    assert all(f.problem and f.objects == [GID] for f in found)
    assert sorted(f.message for f in found) == [
        "Gateway group failover of gw: member wan: tier: should be 2, is 1",
        "Gateway group failover of gw: member wanb: tier: should be 1, is 2",
    ]


def test_tiers_without_gaps_move_the_others() -> None:
    # wan joins wanb on tier 2; tier 1 is empty, so the tiers move up: wan and wanb 1, lte 2
    [c] = changes_for(parse(text("          - {name: wan, tier: 2}\n")), network())
    assert isinstance(c.new, GatewayGroupValue)
    assert {m.name: m.tier for m in c.new.members} == {"wan": 1, "wanb": 1, "lte": 2}
    # a declaration that matches the device needs no adopt
    assert (
        changes_for(parse(text("          - {name: wan, tier: 1}\n", adopt=False)), network()) == []
    )


@pytest.mark.parametrize(
    ("state", "message_id"),
    [
        (text("          - {name: wan, tier: 2}\n", name="other"), "plan.groupMissing"),
        (text("          - {name: dsl, tier: 2}\n"), "plan.groupMemberMissing"),
        (text("          - {name: wan, tier: 2}\n", device="nowhere"), "plan.deviceUnknown"),
    ],
)
def test_groups_and_members_are_never_created(state: str, message_id: str) -> None:
    with pytest.raises(PlanError) as err:
        changes_for(parse(state), network())
    assert err.value.message_id == message_id
    if message_id != "plan.deviceUnknown":
        findings = evaluate(network(), drift_rules(parse(state)))
        [f] = [f for f in findings if f.rule_id == "drift.gateway-group"]
        assert f.problem and "does not" in f.message


def test_one_line_in_two_groups_has_one_monitor() -> None:
    second = GatewayGroup(
        id=object_id("gw", "gateway-group", "balanced"),
        device_id="gw",
        name="balanced",
        mode=GroupMode.BALANCE,
        members=[
            member("wan", 1, monitor_targets=[ip("198.51.100.53")]),
            member("wanb", 1, monitor_targets=[ip("203.0.113.53")]),
        ],
    )
    first = network().gateway_groups[0]
    both = network(first, second)
    conflict = (
        "sites:\n  home:\n    gateway_groups:\n"
        "      - {device: gw, name: failover, adopt: true,\n"
        "         members: [{name: wan, monitor: [192.0.2.1]}]}\n"
        "      - {device: gw, name: balanced, adopt: true,\n"
        "         members: [{name: wan, monitor: [192.0.2.2]}]}\n"
    )
    with pytest.raises(PlanError) as err:
        changes_for(parse(conflict), both)
    assert err.value.message_id == "plan.groupMonitorConflict"
    agree = conflict.replace("192.0.2.2", "192.0.2.1")
    assert len(changes_for(parse(agree), both)) == 2


def test_the_predicted_network_has_the_new_tiers_and_mode() -> None:
    p = plan(parse(SWAP), network(), RULES)
    [g] = predict(network(), p.changes).gateway_groups
    assert {m.name: m.tier for m in g.members} == {"wan": 2, "wanb": 1, "lte": 3}
    assert g.mode is GroupMode.FAILOVER
    balance = text(
        "          - {name: wan, tier: 1}\n          - {name: wanb, tier: 1}\n"
        "          - {name: lte, tier: 1, monitor: [192.0.2.53]}\n"
    )
    [c] = changes_for(parse(balance), network())
    [g] = apply_change(network(), c).gateway_groups
    assert g.mode is GroupMode.BALANCE and g.active is None
    assert g.members[2].monitor_targets == [ip("192.0.2.53")]
    # the deployer's verification reads the same value back from a network that has it
    assert current_value(apply_change(network(), c), c) == c.new


# --- drift and import ---------------------------------------------------------------------------


def test_drift_names_every_differing_member_field() -> None:
    state = parse(
        text(
            "          - {name: wan, tier: 2, weight: 5}\n"
            "          - {name: wanb, tier: 1, monitor: []}\n"
        )
    )
    found = sorted(
        f.message
        for f in evaluate(network(), drift_rules(state))
        if f.rule_id == "drift.gateway-group"
    )
    assert found == [
        "Gateway group failover of gw: member wan: tier: should be 2, is 1; weight: should be "
        "5, is 3",
        "Gateway group failover of gw: member wanb: tier: should be 1, is 2; monitor: should be "
        "none, is 203.0.113.53",
    ]


def test_unread_devices_are_incomplete() -> None:
    down = network(statuses={"gw": DeviceStatus.UNREACHABLE})
    [f] = [
        f for f in evaluate(down, drift_rules(parse(SWAP))) if f.rule_id == "drift.gateway-group"
    ]
    assert f.incomplete and not f.problem


def test_import_exports_the_groups_without_adopt() -> None:
    state = from_network(network(), "home")
    [g] = state.sites["home"].gateway_groups
    assert not g.adopt and [m.name for m in g.members] == ["wan", "wanb", "lte"]
    assert g.members[0].weight == 3 and g.members[0].monitor == [ip("198.51.100.53")]
    again = parse(dump(state))
    assert changes_for(again, network()) == []
    assert not [f for f in evaluate(network(), drift_rules(again)) if f.problem]
