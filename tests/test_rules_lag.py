"""Link aggregation rules (#157): lag.mode-mismatch, lag.member-not-selected,
lag.partner-mismatch, and the LACP part of lag.consistent."""

from __future__ import annotations

from typing import Any

from factories import SITE, device, port
from signalbox.model import (
    DeviceRole,
    LagMemberState,
    LagMode,
    Link,
    LinkOrigin,
    Network,
    Port,
    PortKind,
    PortRole,
    port_id,
)
from signalbox.rules import Finding, evaluate
from signalbox.rules.builtin import RULES
from signalbox.rules.lag_checks import member_not_selected, mode_mismatch, partner_mismatch
from signalbox.rules.topology_checks import lag_consistent

UP = {"up": True, "speed_mbps": 1000, "full_duplex": True}
OK = LagMemberState(
    selected=True,
    collecting_distributing=True,
    partner_system_id="02:00:00:00:00:b2",
    partner_port=1,
    partner_key=7,
)


def run(net: Network, *rules: Any) -> list[Finding]:
    return evaluate(net, rules, {})


def link(a: str, b: str) -> Link:
    return Link(id=f"{a}~{b}", a=a, b=b, origin=LinkOrigin.LLDP)


def lag(dev: str, name: str, members: list[str], mode: LagMode | None) -> Port:
    """A LAG port that lists its members (``lower``) without ``Port.lag`` on them."""
    return port(
        dev,
        name,
        kind=PortKind.LAG,
        role=PortRole.LAG,
        lower=[port_id(dev, m) for m in members],
        lag_mode=mode,
    )


def lag_net(
    a: LagMode | None = LagMode.LACP_ACTIVE,
    b: LagMode | None = LagMode.LACP_ACTIVE,
    states: list[LagMemberState | None] | None = None,
    ups: tuple[bool | None, bool | None] = (True, True),
    far_lag: bool = True,
) -> Network:
    states = states if states is not None else [OK, OK]
    return Network(
        sites=[SITE],
        devices=[device("nas", DeviceRole.OTHER), device("sw", DeviceRole.SWITCH)],
        ports=[
            *(
                port("nas", f"eth{i}", lag_member_state=s, **(UP | {"up": u}))
                for i, (s, u) in enumerate(zip(states, ups, strict=True), start=1)
            ),
            lag("nas", "bond0", ["eth1", "eth2"], a),
            port("sw", "1", **UP),
            port("sw", "2", **UP),
            *([lag("sw", "lag1", ["1", "2"], b)] if far_lag else []),
        ],
        links=[
            link(port_id("nas", "eth1"), port_id("sw", "1")),
            link(port_id("nas", "eth2"), port_id("sw", "2")),
        ],
    )


def test_rules_are_registered() -> None:
    ids = {r.id for r in RULES}
    assert {"lag.mode-mismatch", "lag.member-not-selected", "lag.partner-mismatch"} <= ids


def test_members_from_lower_only_are_one_lag() -> None:
    net = lag_net()
    groups = net.lag_groups()
    assert list(groups) == [("nas", "bond0"), ("sw", "lag1")]
    g = groups[("nas", "bond0")]
    assert g.member_ids == ["nas/port/eth1", "nas/port/eth2"] and g.mode is LagMode.LACP_ACTIVE
    assert g.port is not None and g.port.id == "nas/port/bond0"
    found = net.lag_of("nas/port/eth1")
    assert found is not None and found.name == "bond0"
    assert net.lag_of("nas/port/bond0") is None and net.lag_of("nope") is None
    assert run(net, lag_consistent, mode_mismatch, member_not_selected, partner_mismatch) == []


def test_lag_groups_by_name_and_foreign_lower_ignored() -> None:
    net = Network(
        sites=[SITE],
        devices=[device("sw", DeviceRole.SWITCH), device("x", DeviceRole.SWITCH)],
        ports=[
            port("sw", "1", lag="lag1"),
            port("sw", "lag1", kind=PortKind.LAG, lag_mode=LagMode.STATIC),
            port("sw", "2"),
            # an adapter error: a LAG that names another device's port
            port("x", "ae0", kind=PortKind.LAG, role=PortRole.LAG, lower=["sw/port/2"]),
        ],
    )
    groups = net.lag_groups()
    assert list(groups) == [("sw", "lag1")]
    assert groups[("sw", "lag1")].mode is LagMode.STATIC


# --- lag.mode-mismatch ----------------------------------------------------------------------


def test_lacp_against_static_is_reported_once() -> None:
    (f,) = run(lag_net(LagMode.LACP_ACTIVE, LagMode.STATIC), mode_mismatch)
    assert f.rule_id == "lag.mode-mismatch" and f.severity == "error"
    assert f.message == "nas bond0 is LACP (active), but the other end sw lag1 is static."
    assert f.objects == ["nas", "sw", "nas/port/bond0", "sw/port/lag1"]
    assert f.message_id == "lag.modeMismatch" and f.fix_id == "lag.modeMismatch.fix"


def test_two_passive_ends_and_active_backup_against_a_lag() -> None:
    (f,) = run(lag_net(LagMode.LACP_PASSIVE, LagMode.LACP_PASSIVE), mode_mismatch)
    assert "LACP (passive)" in f.message
    (g,) = run(lag_net(LagMode.ACTIVE_BACKUP, LagMode.STATIC), mode_mismatch)
    assert "active-backup" in g.message


def test_mode_mismatch_stays_quiet() -> None:
    assert run(lag_net(LagMode.LACP_ACTIVE, LagMode.LACP_PASSIVE), mode_mismatch) == []
    assert run(lag_net(LagMode.BALANCE_XOR, LagMode.STATIC), mode_mismatch) == []
    assert run(lag_net(LagMode.OTHER, LagMode.STATIC), mode_mismatch) == []
    assert run(lag_net(None, LagMode.STATIC), mode_mismatch) == []
    # the far end is no LAG: lag.consistent reports it
    assert run(lag_net(far_lag=False), mode_mismatch) == []
    net = lag_net(LagMode.LACP_ACTIVE, LagMode.STATIC)
    assert run(net.model_copy(update={"links": []}), mode_mismatch) == []


def test_mode_helpers() -> None:
    assert LagMode.LACP_PASSIVE.lacp and not LagMode.STATIC.lacp
    assert LagMode.OTHER.needs_far_lag is None and LagMode.BALANCE_ALB.needs_far_lag is False
    assert LagMode.BALANCE_RR.needs_far_lag is True


# --- lag.member-not-selected ----------------------------------------------------------------


def test_member_up_but_not_aggregated() -> None:
    waiting = LagMemberState(selected=False, collecting_distributing=False)
    (f,) = run(lag_net(states=[OK, waiting]), member_not_selected)
    assert f.severity == "warning" and f.objects == ["nas", "nas/port/eth2", "nas/port/bond0"]
    assert f.message == "nas bond0: member eth2 is up but LACP does not aggregate it."
    assert f.message_id == "lag.memberNotSelected"
    # unknown mode, but the member says it is not collecting: still reported
    (g,) = run(lag_net(a=None, states=[OK, waiting]), member_not_selected)
    assert g.objects[1] == "nas/port/eth2"


def test_member_not_selected_stays_quiet() -> None:
    waiting = LagMemberState(selected=False, collecting_distributing=False)
    assert run(lag_net(states=[OK, waiting], ups=(True, False)), member_not_selected) == []
    assert run(lag_net(states=[OK, None]), member_not_selected) == []
    backup = LagMemberState(selected=False)
    standby = lag_net(a=LagMode.ACTIVE_BACKUP, states=[OK, backup])
    assert run(standby, member_not_selected) == []
    assert run(lag_net(a=None, states=[OK, backup]), member_not_selected) == []


def test_single_carrying_member_is_info_of_lag_consistent() -> None:
    waiting = LagMemberState(selected=False, collecting_distributing=False)
    out = run(lag_net(states=[OK, waiting]), lag_consistent)
    single = [f for f in out if f.message_id == "topology.lagSingleActive"]
    assert len(single) == 1 and single[0].severity == "info"
    assert single[0].message == "nas bond0 [eth1, eth2]: only one member carries traffic."
    # not reported without LACP data, or in a static LAG
    assert not [
        f
        for f in run(lag_net(states=[OK, None]), lag_consistent)
        if f.message_id == "topology.lagSingleActive"
    ]
    static = lag_net(a=LagMode.STATIC, b=LagMode.STATIC, states=[OK, waiting])
    assert not [f for f in run(static, lag_consistent) if "carries" in f.message]


# --- lag.partner-mismatch -------------------------------------------------------------------


def test_members_with_different_partners() -> None:
    other = OK.model_copy(update={"partner_system_id": "02:00:00:00:00:c3", "partner_key": 9})
    (f,) = run(lag_net(states=[OK, other]), partner_mismatch)
    assert f.severity == "warning" and f.objects == ["nas", "nas/port/eth1", "nas/port/eth2"]
    assert f.message == (
        "nas bond0: the members reach different LACP partners "
        "(eth1: 02:00:00:00:00:b2 key 7; eth2: 02:00:00:00:00:c3 key 9)."
    )
    # same system, other key: two LAGs on the far device
    two = OK.model_copy(update={"partner_key": 8})
    assert len(run(lag_net(states=[OK, two]), partner_mismatch)) == 1


def test_partner_mismatch_stays_quiet() -> None:
    unknown = LagMemberState(selected=False, collecting_distributing=False)
    assert run(lag_net(states=[OK, unknown]), partner_mismatch) == []
    no_key = OK.model_copy(update={"partner_key": None})
    assert run(lag_net(states=[no_key, no_key]), partner_mismatch) == []
