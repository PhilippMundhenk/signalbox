"""Checks of a neighbour's announced port details against the local port (#163)."""

from __future__ import annotations

from typing import Any

from factories import SITE, device, port
from signalbox.model import DeviceRole, Neighbour, Network, PortPoe, port_id
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.neighbour_checks import mtu_mismatch, poe_request_unmet, pvid_mismatch


def lab(local: dict[str, Any], **nb: Any) -> Network:
    return Network(
        sites=[SITE],
        devices=[device("sw", DeviceRole.SWITCH, name="Switch")],
        ports=[port("sw", "p1", **local)],
        neighbours=[
            Neighbour(
                id="sw/neighbour/p1-x",
                local_port_id=port_id("sw", "p1"),
                chassis_id="02:00:00:00:00:09",
                system_name="peer",
                **nb,
            )
        ],
    )


def run(rule: Rule, net: Network) -> list[Finding]:
    return [f for f in evaluate(net, [rule]) if f.rule_id == rule.id]


def test_pvid_mismatch_found_and_quiet() -> None:
    assert len(run(pvid_mismatch, lab({"pvid": 1}, port_vlan=10))) == 1
    assert not run(pvid_mismatch, lab({"pvid": 10}, port_vlan=10))
    assert not run(pvid_mismatch, lab({}, port_vlan=10))  # local PVID unknown
    assert not run(pvid_mismatch, lab({"pvid": 1}))  # neighbour does not say
    assert not run(pvid_mismatch, lab({"pvid": 1}, port_vlan=10, wireless=True))


def test_mtu_mismatch_found_and_quiet() -> None:
    assert len(run(mtu_mismatch, lab({"mtu": 9000}, max_frame_size=1522))) == 1
    assert not run(mtu_mismatch, lab({"mtu": 1500}, max_frame_size=1522))
    assert not run(mtu_mismatch, lab({"mtu": 1500}, max_frame_size=9216))  # far end is bigger
    assert not run(mtu_mismatch, lab({"mtu": 9000}))
    assert not run(mtu_mismatch, lab({}, max_frame_size=1522))


def test_poe_request_unmet_found_and_quiet() -> None:
    off = lab({"poe": PortPoe(enabled=False)}, poe_requested_w=15.4)
    assert [f.message_id for f in run(poe_request_unmet, off)] == ["poe.requestOff"]
    low = lab({"poe": PortPoe(enabled=True, max_w=7.5)}, poe_requested_w=15.4)
    assert [f.message_id for f in run(poe_request_unmet, low)] == ["poe.requestLimit"]
    ok = lab({"poe": PortPoe(enabled=True, max_w=30)}, poe_requested_w=15.4)
    assert not run(poe_request_unmet, ok)
    assert not run(poe_request_unmet, lab({"poe": PortPoe(enabled=True, max_w=7.5)}))
    assert not run(poe_request_unmet, lab({}, poe_requested_w=15.4))  # not a PoE port
