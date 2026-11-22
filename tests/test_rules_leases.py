"""Lease, option 121 and relay rules (#67, #183) and the lease-aware pool-usage / one-server."""

from datetime import timedelta
from typing import Any

from factories import (
    SITE,
    T0,
    annotated,
    annotation,
    client,
    device,
    dhcp_server,
    iface,
    ip,
    lease,
    relay,
)
from signalbox.adapters import Capability
from signalbox.model import (
    DeviceRole,
    DhcpRoute,
    DhcpServer,
    Network,
    ReadError,
    Subnet,
    segment_id,
)
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.addressing import pool_usage
from signalbox.rules.dhcp import one_server
from signalbox.rules.leases import (
    declined,
    option_121_without_router,
    relay_target_missing,
    static_in_pool,
)

LAN = segment_id(SITE.id, None)
MAC = "02:00:00:00:00:44"


def gw_subnet(dev: str = "gw", address: str = "192.0.2.1/24", seg: str = LAN) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{address}",
        segment_id=seg,
        interface=iface(address),
        device_id=dev,
        gateway=True,
    )


def network(**kw: Any) -> Network:
    kw.setdefault("sites", [SITE])
    kw.setdefault("devices", [device("gw"), device("srv", DeviceRole.OTHER)])
    kw.setdefault("subnets", [gw_subnet()])
    kw.setdefault("dhcp_servers", [dhcp_server("gw", leases=[])])
    return Network(**kw)


def run(r: Rule, net: Network) -> list[Finding]:
    return [f for f in evaluate(net, [r]) if f.rule_id == r.id]


# --- dhcp.static-in-pool ---------------------------------------------------------------------


def test_static_in_pool_flags_static_and_unleased() -> None:
    printer = client(MAC, "192.0.2.150", hostname="printer", sources={"192.0.2.150": "static"})
    (f,) = run(static_in_pool, network(clients=[printer]))
    assert f.message.startswith("printer (02:00:00:00:00:44) uses 192.0.2.150 inside the DHCP pool")
    assert f.message.endswith("without a lease")
    (f,) = run(static_in_pool, network(clients=[client(MAC, "192.0.2.150")]))
    assert "uses 192.0.2.150" in f.message


def test_static_in_pool_passes_with_lease_or_outside_pool() -> None:
    srv = dhcp_server("gw", leases=[lease("192.0.2.150", MAC)])
    assert (
        run(static_in_pool, network(dhcp_servers=[srv], clients=[client(MAC, "192.0.2.150")])) == []
    )
    assert run(static_in_pool, network(clients=[client(MAC, "192.0.2.10")])) == []
    leased = client(MAC, "192.0.2.150", sources={"192.0.2.150": "dhcp"})
    assert run(static_in_pool, network(clients=[leased])) == []
    assert run(static_in_pool, network(clients=[client(MAC, "169.254.1.1")])) == []


def test_static_in_pool_quiet_without_lease_table_or_segment() -> None:
    nolist = network(dhcp_servers=[dhcp_server("gw")], clients=[client(MAC, "192.0.2.150")])
    assert run(static_in_pool, nolist) == []
    assert run(static_in_pool, network(clients=[client(MAC, "192.0.2.150", segment_id=None)])) == []
    assert run(static_in_pool, network(dhcp_servers=[], clients=[client(MAC, "192.0.2.150")])) == []


def test_static_in_pool_grace_for_expired_leases() -> None:
    recent = lease("192.0.2.150", MAC, "expired", expires=T0 - timedelta(hours=5))
    old = lease("192.0.2.150", MAC, "expired", expires=T0 - timedelta(days=3))
    c = client(MAC, "192.0.2.150")
    srv = dhcp_server("gw", leases=[recent], observed_at=T0)
    assert run(static_in_pool, network(dhcp_servers=[srv], clients=[c])) == []
    srv = dhcp_server("gw", leases=[old], observed_at=T0)
    assert len(run(static_in_pool, network(dhcp_servers=[srv], clients=[c]))) == 1
    srv = dhcp_server("gw", leases=[old], lease_seconds=None)
    assert run(static_in_pool, network(dhcp_servers=[srv], clients=[c])) == []  # time unknown


def test_static_in_pool_quiet_for_reservation_offer_and_expectation() -> None:
    c = client(MAC, "192.0.2.150")
    offered = dhcp_server("gw", leases=[lease("192.0.2.150", MAC, "offered")])
    assert run(static_in_pool, network(dhcp_servers=[offered], clients=[c])) == []
    from signalbox.model import Reservation

    res = dhcp_server(
        "gw", leases=[], reservations=[Reservation(mac=MAC, address=ip("192.0.2.150"))]
    )
    assert run(static_in_pool, network(dhcp_servers=[res], clients=[c])) == []
    expected = annotated(network(clients=[c]), annotation(c.id, expected={"static_address": True}))
    assert run(static_in_pool, expected) == []


# --- dhcp.declined ---------------------------------------------------------------------------


def test_declined() -> None:
    srv = dhcp_server(
        "gw", leases=[lease("192.0.2.151", MAC, "declined"), lease("192.0.2.150", MAC)]
    )
    (f,) = run(declined, network(dhcp_servers=[srv]))
    assert "192.0.2.151" in f.message and "192.0.2.150" not in f.message
    assert (
        run(declined, network(dhcp_servers=[dhcp_server("gw", leases=[lease("192.0.2.150", MAC)])]))
        == []
    )
    assert run(declined, network(dhcp_servers=[dhcp_server("gw")])) == []
    off = dhcp_server("gw", enabled=False, leases=[lease("192.0.2.151", MAC, "declined")])
    assert run(declined, network(dhcp_servers=[off])) == []


# --- dhcp.option-121-without-router ----------------------------------------------------------


def route(dest: str) -> DhcpRoute:
    return DhcpRoute(destination=dest, gateway="192.0.2.1")


def test_option_121() -> None:
    bad = dhcp_server("gw", static_routes=[route("198.51.100.0/24")])
    (f,) = run(option_121_without_router, network(dhcp_servers=[bad]))
    assert f.fix is not None and "0.0.0.0/0 via 192.0.2.1" in f.fix
    ok = dhcp_server("gw", static_routes=[route("198.51.100.0/24"), route("0.0.0.0/0")])
    assert run(option_121_without_router, network(dhcp_servers=[ok])) == []
    assert run(option_121_without_router, network(dhcp_servers=[dhcp_server("gw")])) == []
    off = dhcp_server("gw", enabled=False, static_routes=[route("198.51.100.0/24")])
    assert run(option_121_without_router, network(dhcp_servers=[off])) == []
    (f,) = run(
        option_121_without_router,
        network(
            dhcp_servers=[dhcp_server("gw", router=None, static_routes=[route("198.51.100.0/24")])]
        ),
    )
    assert "0.0.0.0/0 to" in (f.fix or "")


# --- dhcp.relay-target-missing ---------------------------------------------------------------


def relay_net(**kw: Any) -> Network:
    subs = [gw_subnet(), gw_subnet("srv", "192.0.2.5/24", seg=segment_id(SITE.id, 20))]
    kw.setdefault("subnets", subs)
    kw.setdefault("dhcp_servers", [])
    return network(**kw)


def test_relay_target_found_and_missing() -> None:
    server = dhcp_server("srv")
    ok = relay_net(dhcp_relays=[relay("gw", 20, "192.0.2.5")], dhcp_servers=[server])
    assert run(relay_target_missing, ok) == []
    (f,) = run(relay_target_missing, relay_net(dhcp_relays=[relay("gw", 20, "192.0.2.5")]))
    assert not f.incomplete and "no DHCP server is enabled on srv" in f.message
    off = dhcp_server("srv", enabled=False)
    (f,) = run(
        relay_target_missing,
        relay_net(dhcp_relays=[relay("gw", 20, "192.0.2.5")], dhcp_servers=[off]),
    )
    assert not f.incomplete


def test_relay_target_empty_unknown_unreadable_disabled() -> None:
    (f,) = run(relay_target_missing, relay_net(dhcp_relays=[relay("gw", 20)]))
    assert "no server to forward to" in f.message
    (f,) = run(relay_target_missing, relay_net(dhcp_relays=[relay("gw", 20, "203.0.113.9")]))
    assert f.incomplete
    err = ReadError(device_id="srv", capability=Capability.DHCP, message="timeout")
    (f,) = run(
        relay_target_missing,
        relay_net(dhcp_relays=[relay("gw", 20, "192.0.2.5")], errors=[err]),
    )
    assert f.incomplete and "could not be read" in f.message
    assert run(relay_target_missing, relay_net(dhcp_relays=[relay("gw", 20, enabled=False)])) == []


# --- dhcp.one-server and dhcp.pool-usage -----------------------------------------------------


def test_one_server_quiet_with_relay() -> None:
    bare = network(dhcp_servers=[])
    assert [f.message for f in run(one_server, bare)] == ["No DHCP server on home"] or run(
        one_server, bare
    )
    relayed = network(dhcp_servers=[], dhcp_relays=[relay("gw", None, "192.0.2.5")])
    assert run(one_server, relayed) == []
    off = network(dhcp_servers=[], dhcp_relays=[relay("gw", None, "192.0.2.5", enabled=False)])
    assert run(one_server, off)


def test_pool_usage_counts_active_leases() -> None:
    from signalbox.model import DhcpPool

    pool = [DhcpPool(start=ip("192.0.2.100"), end=ip("192.0.2.109"))]
    full = [lease(f"192.0.2.{100 + i}", f"02:00:00:00:01:{i:02x}") for i in range(10)]
    srv: DhcpServer = dhcp_server("gw", pools=pool, leases=full)
    (f,) = run(pool_usage, network(dhcp_servers=[srv]))
    assert "is full" in f.message
    dead = [lease(x.address.compressed, x.mac or "", "expired") for x in full]
    quiet = dhcp_server("gw", pools=pool, leases=dead)
    assert run(pool_usage, network(dhcp_servers=[quiet])) == []
