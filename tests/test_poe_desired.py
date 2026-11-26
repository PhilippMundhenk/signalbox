"""PoE in the desired state (#484, ADR 0036): syntax, planner, outage and budget protection,
drift and the predicted network. Only declared ports change; switching off is refused where the
port powers a managed device or a bridge, router or access point unless the entry allows the
outage; switching on must stay within the budget the switch reports."""

from __future__ import annotations

from typing import Any

import pytest

from factories import SITE, device, port
from signalbox.changes import (
    POE_DEFAULT_W,
    Change,
    ChangeKind,
    PlanError,
    PoeValue,
    apply_change,
    changes_for,
    observed_poe,
    plan,
    poe_load,
)
from signalbox.deploy import current_value
from signalbox.desired import DesiredError, drift_rules, from_network, parse
from signalbox.model import (
    DeviceRole,
    DeviceStatus,
    Link,
    LinkOrigin,
    Neighbour,
    Network,
    PoeStatus,
    PoeSupply,
    PortPoe,
    port_id,
)
from signalbox.rules import evaluate
from signalbox.rules.builtin import RULES

DELIVERING = PortPoe(enabled=True, status=PoeStatus.DELIVERING, power_w=5.8)


def network(budget: float | None = 60.0, **kw: Any) -> Network:
    """A PoE switch ``sw``: p1 powers the managed access point ap-1, p2 an LLDP neighbour that
    is a camera, p3 is off, p4 on and searching, p5 has no PoE; ap-1 is linked to p1."""
    values: dict[str, Any] = {
        "sites": [SITE],
        "devices": [
            device(
                "sw",
                DeviceRole.SWITCH,
                poe=PoeSupply(budget_w=budget, used_w=20.0) if budget else None,
            ),
            device("ap-1", DeviceRole.AP, name="Office AP"),
        ],
        "ports": [
            port("sw", "p1", poe=PortPoe(enabled=True, status=PoeStatus.DELIVERING, power_w=9.0)),
            port("sw", "p2", poe=DELIVERING),
            port("sw", "p3", poe=PortPoe(enabled=False, status=PoeStatus.DISABLED, max_w=30.0)),
            port("sw", "p4", poe=PortPoe(enabled=True, status=PoeStatus.SEARCHING)),
            port("sw", "p5"),
            port("sw", "p6", poe=PortPoe(enabled=False, status=PoeStatus.DISABLED)),
            port("ap-1", "lan"),
        ],
        "links": [
            Link(id="l1", a=port_id("sw", "p1"), b=port_id("ap-1", "lan"), origin=LinkOrigin.LLDP)
        ],
        "neighbours": [
            Neighbour(
                id="sw/neighbour/cam",
                local_port_id=port_id("sw", "p2"),
                chassis_id="02:00:00:00:00:21",
                system_name="cam-door",
                capabilities=["other"],
            )
        ],
    }
    return Network(**(values | kw))


def text(*entries: str) -> str:
    return "sites:\n  home:\n    poe:\n" + "".join(f"      - {e}\n" for e in entries)


# --- syntax -------------------------------------------------------------------------------------


def test_syntax_and_defaults() -> None:
    [e] = parse(text("{device: sw, port: p2, enabled: false}")).sites["home"].poe
    assert (e.device, e.port, e.enabled, e.allow_outage) == ("sw", "p2", False, False)


def test_a_port_may_be_declared_once() -> None:
    with pytest.raises(DesiredError, match="PoE of sw/p2 declared twice"):
        parse(
            text("{device: sw, port: p2, enabled: false}", "{device: sw, port: p2, enabled: true}")
        )


def test_enabled_is_required() -> None:
    with pytest.raises(DesiredError):
        parse(text("{device: sw, port: p2}"))


# --- planner ------------------------------------------------------------------------------------


def test_nothing_changes_without_a_declaration() -> None:
    assert changes_for(parse("sites:\n  home: {}\n"), network()) == []


def test_a_matching_declaration_needs_no_change() -> None:
    assert changes_for(parse(text("{device: sw, port: p4, enabled: true}")), network()) == []


def test_off_names_what_loses_power() -> None:
    [c] = changes_for(parse(text("{device: sw, port: p2, enabled: false}")), network())
    assert (c.kind, c.key, c.old, c.new) == (
        ChangeKind.POE,
        port_id("sw", "p2"),
        PoeValue(enabled=True),
        PoeValue(enabled=False),
    )
    assert c.risk == "cuts power to cam-door"


def test_off_of_an_unknown_load_and_of_an_empty_port() -> None:
    bare = network(neighbours=[])
    [c] = changes_for(parse(text("{device: sw, port: p2, enabled: false}")), bare)
    assert c.risk == "cuts power to an unknown device that draws 5.8 W"
    [c] = changes_for(parse(text("{device: sw, port: p4, enabled: false}")), bare)
    assert c.risk == "no powered device detected"


def test_off_is_refused_where_a_managed_device_is_powered() -> None:
    with pytest.raises(PlanError) as err:
        changes_for(parse(text("{device: sw, port: p1, enabled: false}")), network())
    assert err.value.message_id == "plan.poeOutage"
    assert err.value.params["load"] == "Office AP (ap, managed by Signalbox)"
    assert "allow_outage: true" in str(err.value)


@pytest.mark.parametrize("cap", ["bridge", "router", "wlan-access-point"])
def test_off_is_refused_for_a_neighbour_that_is_part_of_the_network(cap: str) -> None:
    nb = Neighbour(
        id="sw/neighbour/x",
        local_port_id=port_id("sw", "p2"),
        chassis_id="02:00:00:00:00:31",
        capabilities=[cap, "station"],
    )
    with pytest.raises(PlanError, match=f"announces itself as {cap}"):
        changes_for(parse(text("{device: sw, port: p2, enabled: false}")), network(neighbours=[nb]))


def test_allow_outage_accepts_it_and_keeps_the_risk() -> None:
    state = parse(text("{device: sw, port: p1, enabled: false, allow_outage: true}"))
    [c] = changes_for(state, network())
    assert c.risk == "cuts power to Office AP (ap, managed by Signalbox)"


def test_inferred_and_tunnel_links_count_for_nothing() -> None:
    links = [
        Link(
            id="l1",
            a=port_id("sw", "p1"),
            b=port_id("ap-1", "lan"),
            origin=LinkOrigin.MAC,
            inferred=True,
        )
    ]
    assert poe_load(network(links=links), port_id("sw", "p1")) == (
        "an unknown device that draws 9 W",
        None,
    )


@pytest.mark.parametrize(
    ("entry", "message_id"),
    [
        ("{device: sw, port: p5, enabled: true}", "plan.poeMissing"),
        ("{device: sw, port: p9, enabled: true}", "plan.noPort"),
        ("{device: nope, port: p1, enabled: true}", "plan.deviceUnknown"),
    ],
)
def test_ports_without_poe_are_refused(entry: str, message_id: str) -> None:
    with pytest.raises(PlanError) as err:
        changes_for(parse(text(entry)), network())
    assert err.value.message_id == message_id


def test_on_within_the_budget() -> None:
    # 20 W in use + 30 W (p3's limit) = 50 W of 60 W
    [c] = changes_for(parse(text("{device: sw, port: p3, enabled: true}")), network())
    assert c.new == PoeValue(enabled=True) and c.risk is None


def test_on_over_the_budget_is_refused_with_the_numbers() -> None:
    # 20 W in use + 30 W (p3's limit) + 15.4 W (p6, no limit reported) = 65.4 W of 60 W
    state = parse(
        text("{device: sw, port: p3, enabled: true}", "{device: sw, port: p6, enabled: true}")
    )
    with pytest.raises(PlanError) as err:
        changes_for(state, network())
    assert err.value.message_id == "plan.poeBudget"
    assert err.value.params == {
        "device": "sw",
        "ports": "sw/port/p3, sw/port/p6",
        "total": "65.4",
        "used": "20",
        "budget": "60",
    }
    assert POE_DEFAULT_W == 15.4


def test_the_reserved_power_counts_where_it_is_larger() -> None:
    sw = device("sw", DeviceRole.SWITCH, poe=PoeSupply(budget_w=60, used_w=10, reserved_w=35))
    devices = [sw, device("ap-1", DeviceRole.AP)]
    with pytest.raises(PlanError, match="65 W"):
        changes_for(parse(text("{device: sw, port: p3, enabled: true}")), network(devices=devices))


def test_the_sum_of_the_ports_counts_without_a_reported_draw() -> None:
    sw = device("sw", DeviceRole.SWITCH, poe=PoeSupply(budget_w=40))
    devices = [sw, device("ap-1", DeviceRole.AP)]
    # p1 9 W + p2 5.8 W + p3 30 W = 44.8 W of 40 W
    with pytest.raises(PlanError, match=r"44\.8 W"):
        changes_for(parse(text("{device: sw, port: p3, enabled: true}")), network(devices=devices))


def test_a_switch_without_a_budget_is_not_checked_and_says_so() -> None:
    state = parse(
        text("{device: sw, port: p3, enabled: true}", "{device: sw, port: p6, enabled: true}")
    )
    changes = changes_for(state, network(budget=None))
    assert [c.risk for c in changes] == ["the switch reports no PoE budget; not checked"] * 2


def test_switching_off_frees_nothing_for_the_budget_check() -> None:
    # switching p2 off does not make room in the estimate: the check stays on the safe side
    state = parse(
        text(
            "{device: sw, port: p2, enabled: false}",
            "{device: sw, port: p3, enabled: true}",
            "{device: sw, port: p6, enabled: true}",
        )
    )
    with pytest.raises(PlanError, match="budget"):
        changes_for(state, network())


# --- predicted network, deploy helpers, plan ------------------------------------------------------


def test_the_predicted_network_has_the_new_state() -> None:
    [off] = changes_for(parse(text("{device: sw, port: p2, enabled: false}")), network())
    after = apply_change(network(), off)
    p2 = after.port(port_id("sw", "p2"))
    assert p2 is not None and p2.poe is not None
    assert (p2.poe.enabled, p2.poe.status, p2.poe.power_w) == (False, PoeStatus.DISABLED, None)
    assert observed_poe(after, port_id("sw", "p2")) == PoeValue(enabled=False)
    assert current_value(after, off) == PoeValue(enabled=False)
    [on] = changes_for(parse(text("{device: sw, port: p3, enabled: true}")), network())
    p3 = apply_change(network(), on).port(port_id("sw", "p3"))
    assert p3 is not None and p3.poe is not None
    assert (p3.poe.enabled, p3.poe.status) == (True, PoeStatus.SEARCHING)
    undone = apply_change(apply_change(network(), on), on.inverse())
    assert observed_poe(undone, port_id("sw", "p3")) == PoeValue(enabled=False)


def test_a_plan_carries_the_risk() -> None:
    p = plan(parse(text("{device: sw, port: p2, enabled: false}")), network(), RULES)
    [c] = p.changes
    assert c.kind is ChangeKind.POE and c.risk == "cuts power to cam-door"
    assert c.describe() == "sw: poe sw/port/p2: enabled True → False"


# --- drift and import ---------------------------------------------------------------------------


def _drift(state_text: str, n: Network) -> list[Any]:
    return [f for f in evaluate(n, drift_rules(parse(state_text))) if f.rule_id == "drift.poe"]


def test_drift_compares_declared_ports_only() -> None:
    [f] = _drift(text("{device: sw, port: p2, enabled: false}"), network())
    assert f.problem and f.objects == [port_id("sw", "p2")]
    assert f.message == "PoE of sw p2: should be off, is on"
    assert not _drift(text("{device: sw, port: p4, enabled: true}"), network())
    assert not _drift("sites:\n  home: {}\n", network())


def test_drift_of_a_port_without_poe_and_a_switch_not_read() -> None:
    [f] = _drift(text("{device: sw, port: p5, enabled: true}"), network())
    assert f.problem and "no PoE" in f.message and f.objects == [port_id("sw", "p5")]
    [f] = _drift(text("{device: sw, port: p9, enabled: true}"), network())
    assert f.problem and f.objects == ["sw"]
    down = network(statuses={"sw": DeviceStatus.UNREACHABLE})
    [f] = _drift(text("{device: sw, port: p2, enabled: false}"), down)
    assert not f.problem and "not read" in f.message


def test_import_writes_no_poe_entries() -> None:
    assert from_network(network(), "home").sites["home"].poe == []


def test_a_stored_change_is_read_back_as_a_poe_change() -> None:
    [c] = changes_for(parse(text("{device: sw, port: p2, enabled: false}")), network())
    again = Change.model_validate_json(c.model_dump_json())
    assert again == c and isinstance(again.new, PoeValue)
