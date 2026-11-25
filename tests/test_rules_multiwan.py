"""Multi-WAN groups (#150) and dynamic DNS (#154): passing, failing and silent cases."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from factories import SITE, device, iface, ip, peer, tunnel, uplink
from signalbox.adapters import Observation
from signalbox.model import (
    DdnsResult,
    DynamicDns,
    GatewayGroup,
    GatewayGroupMember,
    GroupMode,
    Monitor,
    Network,
    Snapshot,
    UplinkHealth,
    UplinkState,
    object_id,
)
from signalbox.rules import Finding, Rule, RuleSettings, Severity, evaluate
from signalbox.rules.builtin import RULES as BUILTIN
from signalbox.rules.multiwan import (
    RULES,
    last_member,
    member_down,
    mismatch,
    monitor_local,
    plain_http,
    private_address,
    stale,
    update_failed,
    vpn_endpoint,
)
from signalbox.sightings import History
from signalbox.testing import multiwan_problems


def member(name: str, state: UplinkState | None = UplinkState.ONLINE, **kw: Any) -> Any:
    return GatewayGroupMember(name=name, state=state, **kw)


def group(*members: GatewayGroupMember, name: str = "failover") -> GatewayGroup:
    return GatewayGroup(
        id=object_id("gw", "gateway-group", name),
        device_id="gw",
        name=name,
        mode=GroupMode.FAILOVER,
        members=list(members),
    )


def network(**kw: Any) -> Network:
    return Network(**({"sites": [SITE], "devices": [device("gw", name="Router")]} | kw))


def run(r: Rule, net: Network) -> list[Finding]:
    return evaluate(net, [r])


def ddns(**kw: Any) -> DynamicDns:
    values: dict[str, Any] = {
        "id": object_id("gw", "ddns", "home"),
        "device_id": "gw",
        "provider": "dyndns2",
        "hostname": "home.example.dyndns.invalid",
        "published_address": ip("198.51.100.23"),
        "last_result": DdnsResult.OK,
    }
    return DynamicDns(**(values | kw))


def test_registered_with_the_builtin_rules() -> None:
    assert {r.id for r in RULES} <= {r.id for r in BUILTIN}
    assert len(RULES) == 9


def test_member_down_with_two_left() -> None:
    g = group(member("a"), member("b"), member("c", UplinkState.DOWN))
    [f] = run(member_down, network(gateway_groups=[g]))
    assert f.severity is Severity.WARNING
    assert "c of the gateway group failover on Router is down" in f.message
    assert f.message_id == "wan.groupMemberDown"


@pytest.mark.parametrize(
    "members",
    [
        [member("a"), member("b")],  # nothing down
        [member("a"), member("b", UplinkState.DOWN)],  # last-member instead
        [member("a", None), member("b", UplinkState.DOWN), member("c")],  # unknown state
        [member("a", UplinkState.DOWN), member("b", UplinkState.DOWN)],  # all down: wan.down
    ],
)
def test_member_down_quiet(members: list[GatewayGroupMember]) -> None:
    assert run(member_down, network(gateway_groups=[group(*members)])) == []


def test_last_member_left() -> None:
    g = group(member("lte"), member("fibre", UplinkState.DOWN))
    [f] = run(last_member, network(gateway_groups=[g]))
    assert f.severity is Severity.WARNING and "Only lte is left" in f.message
    assert run(last_member, network(gateway_groups=[group(member("a"), member("b"))])) == []
    all_down = group(member("a", UplinkState.DOWN), member("b", UplinkState.DOWN))
    assert run(last_member, network(gateway_groups=[all_down])) == []


def test_state_comes_from_the_uplink_when_the_member_has_none() -> None:
    wan = uplink("gw", "wan", up=False)
    wan2 = uplink("gw", "wan2", health=UplinkHealth(state=UplinkState.ONLINE))
    g = group(
        member("wan", None, uplink_id=wan.id),
        member("wan2", None, uplink_id=wan2.id),
    )
    [f] = run(last_member, network(uplinks=[wan, wan2], gateway_groups=[g]))
    assert "Only wan2 is left" in f.message


def test_monitor_pinging_the_own_gateway() -> None:
    hop = ip("198.51.100.1")
    local = member("wan", gateway=hop, monitor_targets=[hop])
    far = member("wan2", gateway=hop, monitor_targets=[ip("203.0.113.53")])
    [f] = run(monitor_local, network(gateway_groups=[group(local, far)]))
    assert f.severity is Severity.INFO and f.message_id == "wan.monitorLocal"
    assert "wan of the gateway group" in f.message


def test_monitor_local_from_the_uplink_and_quiet_cases() -> None:
    wan = uplink("gw", "wan", monitor=Monitor(targets=[ip("198.51.100.1")]))
    g = group(member("wan", uplink_id=wan.id), member("wan2"))
    assert len(run(monitor_local, network(uplinks=[wan], gateway_groups=[g]))) == 1
    assert run(monitor_local, network(gateway_groups=[g])) == []  # nothing known
    single = group(member("wan", uplink_id=wan.id))
    assert run(monitor_local, network(uplinks=[wan], gateway_groups=[single])) == []


def test_ddns_mismatch() -> None:
    wan = uplink("gw", "wan")
    entry = ddns(published_address=ip("203.0.113.9"), uplink_id=wan.id)
    [f] = run(mismatch, network(uplinks=[wan], ddns=[entry]))
    assert f.severity is Severity.WARNING and f.message_id == "ddns.mismatch"
    assert "203.0.113.9" in f.message and "198.51.100.23" in f.message
    # the only uplink of the device is used when none is named
    assert (
        len(run(mismatch, network(uplinks=[wan], ddns=[ddns(published_address=ip("203.0.113.9"))])))
        == 1
    )


def test_ddns_mismatch_uses_the_public_address_the_device_knows() -> None:
    wan = uplink("gw", "wan", addresses=[iface("100.64.0.23/10")], public_ipv4=ip("198.51.100.77"))
    entry = ddns(uplink_id=wan.id)
    [f] = run(mismatch, network(uplinks=[wan], ddns=[entry]))
    assert "198.51.100.77" in f.message


def test_ddns_mismatch_quiet() -> None:
    wan = uplink("gw", "wan")
    cases = [
        ddns(uplink_id=wan.id),  # same address
        ddns(published_address=None),
        ddns(published_address=ip("2001:db8::1")),
        ddns(published_address=ip("203.0.113.9"), enabled=False),
    ]
    for entry in cases:
        assert run(mismatch, network(uplinks=[wan], ddns=[entry])) == []
    other = ddns(published_address=ip("203.0.113.9"))
    down = uplink("gw", "wan", up=False)
    assert run(mismatch, network(uplinks=[down], ddns=[other])) == []
    cgnat = uplink("gw", "wan", addresses=[iface("100.64.0.23/10")])
    assert run(mismatch, network(uplinks=[cgnat], ddns=[other])) == []
    two = [uplink("gw", "wan"), uplink("gw", "wan2")]
    assert run(mismatch, network(uplinks=two, ddns=[other])) == []  # which uplink: not known
    assert run(mismatch, network(ddns=[other])) == []


def test_ddns_update_failed() -> None:
    [f] = run(update_failed, network(ddns=[ddns(last_result=DdnsResult.ERROR)]))
    assert f.severity is Severity.WARNING and f.message_id == "ddns.updateFailed"
    assert "home.example.dyndns.invalid" in f.message
    for entry in (
        ddns(),
        ddns(last_result=DdnsResult.UNKNOWN),
        ddns(last_result=DdnsResult.ERROR, enabled=False),
    ):
        assert run(update_failed, network(ddns=[entry])) == []


def test_contract_checks() -> None:
    wan = uplink("gw", "wan")
    good = Snapshot(
        device=device("gw"),
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        uplinks=[wan],
        gateway_groups=[group(member("wan", uplink_id=wan.id), member("b"))],
        ddns=[ddns(uplink_id=wan.id, last_update=datetime(2026, 1, 1, tzinfo=UTC))],
    )
    assert multiwan_problems(good) == []
    bad = good.model_copy(
        update={
            "gateway_groups": [
                group(member("a", uplink_id="gw/uplink/none"), member("a")).model_copy(
                    update={"active": "zzz", "id": "gw/x/y"}
                )
            ],
            "ddns": [
                ddns(
                    id="gw/other/1",
                    uplink_id="gw/uplink/none",
                    hostname=" ",
                    last_update=datetime(2026, 1, 1),
                )
            ],
        }
    )
    assert len(multiwan_problems(bad)) >= 7


def test_observation_carries_the_new_objects() -> None:
    obs = Observation(gateway_groups=[group(member("a"))], ddns=[ddns()])
    assert len(obs.gateway_groups) == 1 and len(obs.ddns) == 1


# --- #440: private address, plain http, VPN endpoint, stale ------------------------------------


def test_private_address_announced() -> None:
    for address in ("192.168.1.5", "100.64.3.4", "127.0.0.1", "fe80::1", "fd00::5"):
        [f] = run(private_address, network(ddns=[ddns(published_address=ip(address))]))
        assert f.message_id == "ddns.privateAddress" and f.params["address"] == address


def test_private_address_of_a_shared_line() -> None:
    wan = uplink("gw", "wan", addresses=[iface("100.64.2.9/10")])
    entry = ddns(published_address=None, uplink_id=wan.id)
    [f] = run(private_address, network(uplinks=[wan], ddns=[entry]))
    assert f.params["address"] == "100.64.2.9"


def test_private_address_quiet() -> None:
    cases = [
        ddns(),  # public address
        ddns(published_address=None),  # nothing known
        ddns(published_address=ip("192.168.1.5"), enabled=False),
        ddns(published_address=ip("2001:db8::1")),
    ]
    for entry in cases:
        assert run(private_address, network(ddns=[entry])) == []
    off = uplink("gw", "wan", addresses=[iface("100.64.2.9/10")], up=False)
    entry = ddns(published_address=None, uplink_id=off.id)
    assert run(private_address, network(uplinks=[off], ddns=[entry])) == []


def test_plain_http() -> None:
    [f] = run(plain_http, network(ddns=[ddns(tls=False)]))
    assert f.message_id == "ddns.plainHttp" and f.severity is Severity.WARNING
    for entry in (ddns(tls=True), ddns(tls=None), ddns(tls=False, enabled=False)):
        assert run(plain_http, network(ddns=[entry])) == []


def test_vpn_endpoint_name_not_kept_up_to_date() -> None:
    host = "home.example.dyndns.invalid"
    tun = tunnel("gw", peer("far", "198.51.100.0/24", endpoint_host=host.upper()))
    for bad in (ddns(enabled=False), ddns(last_result=DdnsResult.ERROR)):
        [f] = run(vpn_endpoint, network(ddns=[bad], tunnels=[tun]))
        assert f.message_id == "ddns.vpnEndpoint" and f.params["hostname"] == host
    assert run(vpn_endpoint, network(ddns=[ddns()], tunnels=[tun])) == []
    assert run(vpn_endpoint, network(tunnels=[tun])) == []  # no client known
    off = tunnel("gw", peer("far", endpoint_host=host, enabled=False))
    assert run(vpn_endpoint, network(ddns=[ddns(enabled=False)], tunnels=[off])) == []
    other = tunnel("gw", peer("far", endpoint_host="203.0.113.7"))
    assert run(vpn_endpoint, network(ddns=[ddns(enabled=False)], tunnels=[other])) == []


NOW = datetime(2026, 11, 25, tzinfo=UTC)


def run_stale(net: Network, settings: dict[str, RuleSettings] | None = None) -> list[Finding]:
    return evaluate(net, [stale], settings, History(now=NOW))


def test_stale_update() -> None:
    old = ddns(last_update=NOW - timedelta(days=45))
    [f] = run_stale(network(ddns=[old]))
    assert f.severity is Severity.INFO and f.params["age"] == 45 and f.params["days"] == 30
    for entry in (
        ddns(last_update=NOW - timedelta(days=5)),
        ddns(last_update=None),
        ddns(last_update=NOW - timedelta(days=45), enabled=False),
    ):
        assert run_stale(network(ddns=[entry])) == []
    assert evaluate(network(ddns=[old]), [stale], None, History()) == []


def test_stale_days_are_a_parameter() -> None:
    entry = ddns(last_update=NOW - timedelta(days=45))
    settings = {"ddns.stale": RuleSettings(params={"days": 60})}
    assert run_stale(network(ddns=[entry]), settings) == []
