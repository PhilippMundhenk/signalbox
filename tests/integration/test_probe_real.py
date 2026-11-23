"""Signalbox's probe against a real second DHCP server and router (#184, #61).

tools/integration/probe/netns.sh starts dnsmasq in a network namespace behind a veth pair and
sets:

    IT_PROBE_URL=veth://<host side of the pair>
    IT_PROBE_USER, IT_PROBE_PASSWORD   unused (the target fixture wants them)
    IT_PROBE_SERVER                    dnsmasq's address (198.51.100.1)
    IT_PROBE_LEASES                    dnsmasq's lease file: must stay empty
    IT_PROBE_RA=1                      when the tests run as root (CAP_NET_RAW): expect the RA

The DHCP test runs as the normal CI user with net.ipv4.ip_unprivileged_port_start=67; the RA
test as root (a raw ICMPv6 socket).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from ipaddress import IPv6Network, ip_address
from pathlib import Path

import pytest

from signalbox.model import ServerKind
from signalbox.probehost import HostInterface, HostSockets, probe_sync

from .conftest import Target


def _iface(t: Target) -> HostInterface:
    name = t.host
    found = [i for i in HostSockets().interfaces() if i.name == name]
    assert found, f"interface {name} not found"
    return found[0]


def test_dhcp_offer_from_the_second_server(target: Callable[[str], Target]) -> None:
    t = target("probe")
    iface = _iface(t)
    legs = probe_sync(HostSockets(), [iface], 4.0, ra=False)
    leg = legs[t.host]
    assert leg.errors == [] and leg.probed == {ServerKind.DHCPV4}
    [answer] = [a for a in leg.answers if a.kind is ServerKind.DHCPV4]
    server = ip_address(t.extra["SERVER"])
    assert answer.server_address == server
    assert answer.offered.routers == [server]
    assert str(answer.offered.address).startswith("198.51.100.")
    assert [str(p) for p in answer.offered.prefixes] == ["198.51.100.0/24"]
    # DISCOVER only: dnsmasq wrote no lease
    leases = Path(t.extra["LEASES"])
    assert not leases.exists() or leases.read_text().strip() == ""


def test_router_advertisement(target: Callable[[str], Target]) -> None:
    t = target("probe")
    if t.extra.get("RA") != "1" or os.geteuid() != 0:
        pytest.skip("router solicitations need CAP_NET_RAW: run as root (IT_PROBE_RA=1)")
    iface = _iface(t)
    legs = probe_sync(HostSockets(), [iface], 5.0, dhcp=False)
    leg = legs[t.host]
    assert leg.errors == [] and leg.probed == {ServerKind.RA}
    [answer] = leg.answers
    assert answer.server_address is not None and answer.server_address.is_link_local
    assert answer.server_mac is not None
    assert IPv6Network("2001:db8:5::/64") in answer.offered.prefixes


def test_router_solicitation_without_cap_net_raw(target: Callable[[str], Target]) -> None:
    t = target("probe")
    if os.geteuid() == 0:
        pytest.skip("runs as root: has CAP_NET_RAW")
    iface = _iface(t)
    leg = probe_sync(HostSockets(), [iface], 1.0, dhcp=False)[t.host]
    assert leg.answers == [] and any("CAP_NET_RAW" in e for e in leg.errors)
