"""radius.single, port.dot1x-no-fallback and the FreeRADIUS plugin reader (#519, ADR 0030)."""

from __future__ import annotations

from typing import Any

import pytest

from factories import SITE, annotation, client, device, port, wlan
from signalbox.adapters.opnsense import freeradius as fr
from signalbox.model import (
    AccessControlMode,
    DeviceRole,
    Network,
    PortAccessControl,
    RadiusEndpoint,
    RadiusPurpose,
    RadiusRef,
    RadiusServer,
    Security,
)
from signalbox.rules import Finding, Rule, RuleSettings, Severity, evaluate
from signalbox.rules.access_control import dot1x_no_fallback, radius_single
from signalbox.sim.opnsense import FREERADIUS_SECRET
from signalbox.testing import SIM_SECRET_MARKER

MAC = "02:00:00:00:51:01"


def run(r: Rule, n: Network, **params: Any) -> list[Finding]:
    settings = {r.id: RuleSettings(params=params)} if params else None
    return [f for f in evaluate(n, [r], settings) if f.rule_id == r.id]


def enterprise(dev: str, ssid: str, *servers: str) -> Any:
    ref = RadiusRef(auth=[RadiusEndpoint(address=a, port=1812) for a in servers], secret_set=True)
    return wlan(dev, ssid, security=Security.WPA2_ENTERPRISE, radius=ref)


def test_the_freeradius_secret_carries_the_marker() -> None:
    assert SIM_SECRET_MARKER in FREERADIUS_SECRET


def test_single_server_for_an_enterprise_network_is_info() -> None:
    ap1, ap2 = device("ap1", DeviceRole.AP), device("ap2", DeviceRole.AP)
    one = [enterprise("ap1", "Corp", "192.0.2.53"), enterprise("ap2", "Corp", "192.0.2.53")]
    (f,) = run(radius_single, Network(sites=[SITE], devices=[ap1, ap2], wlans=one))
    assert f.message_id == "radius.singleWifi" and f.params["address"] == "192.0.2.53"
    assert f.severity is Severity.INFO and len(f.objects) == 2


def test_two_servers_psk_or_unreported_servers_stay_quiet() -> None:
    ap1, ap2 = device("ap1", DeviceRole.AP), device("ap2", DeviceRole.AP)
    two = enterprise("ap1", "Corp", "192.0.2.53", "192.0.2.54")
    psk = wlan("ap2", "Home", security=Security.WPA2)
    bare = wlan("ap2", "Bare", security=Security.WPA2_ENTERPRISE)
    n = Network(sites=[SITE], devices=[ap1, ap2], wlans=[two, psk, bare])
    assert run(radius_single, n) == []


def test_the_minimum_is_a_parameter() -> None:
    ap = device("ap", DeviceRole.AP)
    servers = ("192.0.2.53", "192.0.2.54")
    two = Network(sites=[SITE], devices=[ap], wlans=[enterprise("ap", "C", *servers)])
    assert run(radius_single, two) == []
    assert len(run(radius_single, two, min_servers=3)) == 1
    one = Network(sites=[SITE], devices=[ap], wlans=[enterprise("ap", "C", servers[0])])
    assert run(radius_single, one, min_servers=1) == []


def test_single_dot1x_server_of_a_switch() -> None:
    def sw(servers: list[RadiusServer] | None) -> Network:
        d = device("sw", DeviceRole.SWITCH, radius_servers=servers)
        p = port("sw", "1", access_control=PortAccessControl(mode=AccessControlMode.DOT1X))
        return Network(sites=[SITE], devices=[d], ports=[p])

    one = RadiusServer(name="a", address="192.0.2.53", purposes=[RadiusPurpose.DOT1X])
    two = RadiusServer(name="b", address="192.0.2.54", purposes=[RadiusPurpose.DOT1X])
    (f,) = run(radius_single, sw([one]))
    assert f.message_id == "radius.singleDot1x"
    assert run(radius_single, sw([one, two])) == []
    assert run(radius_single, sw(None)) == []
    assert run(radius_single, sw([])) == []


def _port_net(ac: PortAccessControl | None, category: str | None = "printer") -> Network:
    sw = device("sw", DeviceRole.SWITCH)
    p = port("sw", "1", access_control=ac)
    c = client(MAC, "192.0.2.150", seen_on=p.id)
    notes = [annotation(f"client/{MAC}", expected={"category": category})] if category else []
    return Network(sites=[SITE], devices=[sw], ports=[p], clients=[c], annotations=notes)


def test_dot1x_port_without_fallback_where_a_printer_is_seen() -> None:
    (f,) = run(dot1x_no_fallback, _port_net(PortAccessControl(mode=AccessControlMode.DOT1X)))
    assert f.message_id == "port.dot1xNoFallback" and MAC in f.params["clients"]


@pytest.mark.parametrize(
    "ac",
    [
        None,
        PortAccessControl(mode=AccessControlMode.OPEN),
        PortAccessControl(mode=AccessControlMode.DOT1X_OR_MAC),
        PortAccessControl(mode=AccessControlMode.MAC_AUTH),
        PortAccessControl(mode=AccessControlMode.DOT1X, guest_vlan=30),
        PortAccessControl(mode=AccessControlMode.DOT1X, auth_fail_vlan=31),
    ],
)
def test_dot1x_port_with_a_fallback_or_other_mode_stays_quiet(ac: PortAccessControl | None) -> None:
    assert run(dot1x_no_fallback, _port_net(ac)) == []


def test_dot1x_no_fallback_needs_a_declared_device_and_honours_min_clients() -> None:
    dot1x = PortAccessControl(mode=AccessControlMode.DOT1X)
    assert run(dot1x_no_fallback, _port_net(dot1x, None)) == []
    assert run(dot1x_no_fallback, _port_net(dot1x, "computer")) == []
    assert run(dot1x_no_fallback, _port_net(dot1x), min_clients=2) == []


# --- FreeRADIUS reader: no secrets ---------------------------------------------------------------

ON = {"freeradius": {"general": {"enabled": "1"}}}
ROWS = [
    {"enabled": "1", "name": "ap", "ip": "192.0.2.20", "secret": FREERADIUS_SECRET},
    {"enabled": "1", "name": "sw", "ip": "192.0.2.21", "secret": FREERADIUS_SECRET},
]


def test_freeradius_server_is_local_and_keeps_no_secret() -> None:
    s = fr.server(ON, {"status": "running"}, ROWS, "192.0.2.1")
    assert s is not None and s.local and s.address == "192.0.2.1"
    assert s.purposes == [RadiusPurpose.WLAN, RadiusPurpose.DOT1X] and s.secret_set is True
    dump = s.model_dump_json()
    assert FREERADIUS_SECRET not in dump and SIM_SECRET_MARKER not in dump


def test_freeradius_secret_missing_unknown_and_no_clients() -> None:
    blank = [{**ROWS[0], "secret": ""}, ROWS[1]]
    s = fr.server(ON, None, blank, "192.0.2.1")
    assert s is not None and s.secret_set is False
    unknown = fr.server(ON, None, [{"enabled": "1", "name": "x"}], "192.0.2.1")
    assert unknown is not None and unknown.secret_set is None
    for rows in ([], None, [{**ROWS[0], "enabled": "0"}]):
        s = fr.server(ON, None, rows, "192.0.2.1")
        assert s is not None and s.purposes == [] and s.secret_set is None


def test_freeradius_off_stopped_or_unreadable_is_not_reported() -> None:
    off = {"freeradius": {"general": {"enabled": "0"}}}
    assert fr.server(off, None, ROWS, "192.0.2.1") is None
    assert fr.server({}, None, ROWS, "192.0.2.1") is None
    assert fr.server(ON, {"status": "stopped"}, ROWS, "192.0.2.1") is None
    assert fr.server(ON, {"status": "weird"}, ROWS, "192.0.2.1") is not None
    assert fr.server(ON, None, ROWS, "") is None
    assert fr.enabled(None) is None and fr.running("x") is None
