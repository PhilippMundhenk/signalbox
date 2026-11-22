"""DHCP leases, address sources, options and relays (#183): model, helpers, merge, contract,
UI JSON."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError

from factories import (
    SITE,
    T0,
    client,
    device,
    dhcp_server,
    ip,
    lease,
    net,
    relay,
    snapshot,
)
from signalbox.adapters import Capability, Observation, check_manifest
from signalbox.merge import merge
from signalbox.model import (
    LEASED_SOURCES,
    AddressSource,
    Client,
    DeviceRole,
    DhcpBoot,
    DhcpLease,
    DhcpOption,
    DhcpPool,
    DhcpRoute,
    LeaseState,
    Network,
    json_schema,
    segment_id,
    source_fits,
)
from signalbox.testing import assert_contract, client_problems, dhcp_problems, problems
from test_adapters import Fake, ctx

LAN, IOT = segment_id(SITE.id, None), segment_id(SITE.id, 20)
PRINTER, LAPTOP, PHONE = "02:00:00:00:00:10", "02:00:00:00:00:21", "02:00:00:00:00:22"


def test_pool_contains_its_ends_and_only_its_family() -> None:
    pool = DhcpPool(start=ip("192.0.2.100"), end=ip("192.0.2.199"))
    assert pool.contains(ip("192.0.2.100")) and pool.contains(ip("192.0.2.199"))
    assert not pool.contains(ip("192.0.2.99")) and not pool.contains(ip("192.0.2.200"))
    assert not pool.contains(ip("2001:db8::100"))
    srv = dhcp_server("gw")
    assert srv.in_pool(ip("192.0.2.150")) and not srv.in_pool(ip("192.0.2.10"))


def test_new_fields_default_to_not_reported() -> None:
    srv = dhcp_server("gw")
    assert srv.leases is None  # not read, unlike []
    assert srv.search_domains == srv.static_routes == srv.options == []
    assert srv.boot is srv.authoritative is srv.failover_peer is None
    assert srv.lease_for(ip("192.0.2.150")) is None and srv.leases_of(LAPTOP) == []
    assert client(LAPTOP, "192.0.2.150").address_sources == {}


def test_lease_state_activity_and_source() -> None:
    now = lease("192.0.2.150", LAPTOP)
    assert now.active() and now.active(T0) and not now.active(T0 + timedelta(days=2))
    assert not lease("192.0.2.150", LAPTOP, "expired").active()
    assert lease("192.0.2.150", LAPTOP, expires=None).active(T0 + timedelta(days=400))
    assert now.source() is AddressSource.DHCP
    assert lease("192.0.2.10", PRINTER, reserved=True).source() is AddressSource.DHCP_RESERVED
    assert lease("2001:db8::10", PRINTER).source() is AddressSource.DHCPV6
    naive = DhcpLease(address=ip("192.0.2.5"), mac=PRINTER, expires=datetime(2026, 1, 1))
    assert naive.expires is not None and naive.expires.tzinfo is not None
    v6 = DhcpLease(address=ip("2001:db8::5"), client_id="00:01:00:01:aa:bb")
    assert v6.mac is None and v6.state is LeaseState.ACTIVE


def test_option_codes_and_routes_are_validated() -> None:
    with pytest.raises(ValidationError):
        DhcpOption(code=255, value="x")
    with pytest.raises(ValidationError):
        DhcpRoute(destination=net("2001:db8::/32"), gateway=ip("192.0.2.1"))
    srv = dhcp_server(
        "gw",
        search_domains=["home.example"],
        static_routes=[DhcpRoute(destination=net("198.51.100.0/24"), gateway=ip("192.0.2.254"))],
        boot=DhcpBoot(next_server=ip("192.0.2.5"), filename="pxelinux.0"),
        options=[DhcpOption(code=252, name="wpad", value="http://192.0.2.5/wpad.dat")],
        authoritative=True,
        failover_peer="192.0.2.3",
    )
    assert dhcp_problems(srv) == []


def test_source_fits_the_family() -> None:
    v4, v6 = ip("192.0.2.5"), ip("2001:db8::5")
    assert source_fits(v4, AddressSource.DHCP) and not source_fits(v4, AddressSource.SLAAC)
    assert source_fits(v6, AddressSource.DHCPV6) and not source_fits(v6, AddressSource.DHCP)
    assert all(source_fits(a, s) for a in (v4, v6) for s in (AddressSource.STATIC,))
    assert {
        AddressSource.DHCP,
        AddressSource.DHCP_RESERVED,
        AddressSource.DHCPV6,
    } == LEASED_SOURCES


def _network(*clients_: object, leases: list[DhcpLease] | None = None, **kw: object) -> Network:
    return Network(
        sites=[SITE],
        devices=[device("gw")],
        dhcp_servers=[dhcp_server("gw", leases=leases)],
        clients=list(clients_),  # type: ignore[arg-type]
        **kw,  # type: ignore[arg-type]
    )


def test_address_source_prefers_the_client_then_the_lease() -> None:
    laptop = client(LAPTOP, "192.0.2.150", "fe80::21", "2001:db8::21")
    printer = client(PRINTER, "192.0.2.10", sources={"192.0.2.10": "static"})
    odd = client(PHONE, "192.0.2.160", sources={"192.0.2.160": "unknown"})
    leases = [
        lease("192.0.2.150", LAPTOP),
        lease("192.0.2.10", PRINTER),  # the printer itself says static: it wins
        lease("192.0.2.160", PRINTER),  # another MAC's lease is not the phone's
    ]
    nw = _network(laptop, printer, odd, leases=leases)
    assert nw.address_source(laptop, ip("192.0.2.150")) is AddressSource.DHCP
    assert nw.address_source(laptop, ip("fe80::21")) is AddressSource.LINK_LOCAL
    assert nw.address_source(laptop, ip("2001:db8::21")) is None
    assert nw.address_source(printer, ip("192.0.2.10")) is AddressSource.STATIC
    assert nw.address_source(odd, ip("192.0.2.160")) is AddressSource.UNKNOWN
    # an expired lease (by state or by time) gives nothing
    assert nw.address_source(laptop, ip("192.0.2.150"), T0 + timedelta(days=2)) is None
    found = nw.lease_of(LAPTOP, ip("192.0.2.150"))
    assert found is not None and found[0].id == "gw/dhcp/lan"


def test_leases_read_and_relays_per_segment() -> None:
    assert not _network().leases_read(LAN)  # table not read
    assert _network(leases=[]).leases_read(LAN)  # read, empty: "no lease" means something
    assert not _network(leases=[]).leases_read(IOT)  # no server at all
    off = dhcp_server("gw", 20, enabled=False, leases=[])
    nw = _network(
        leases=[],
        dhcp_relays=[relay("sw", 20, "192.0.2.1"), relay("sw", 30, enabled=False)],
    ).model_copy(update={"dhcp_servers": [dhcp_server("gw", leases=[]), off]})
    assert not nw.leases_read(IOT)  # only a disabled server
    assert [s.id for s in nw.dhcp_servers_on(IOT)] == [off.id]
    assert [r.id for r in nw.dhcp_relays_on(IOT)] == ["sw/dhcp-relay/20"]
    assert nw.dhcp_relays_on(segment_id(SITE.id, 30)) == []  # disabled
    assert nw.knows("sw/dhcp-relay/20")


def test_dhcp_server_lease_helpers() -> None:
    srv = dhcp_server(
        "gw",
        leases=[
            lease("192.0.2.150", LAPTOP),
            lease("192.0.2.151", LAPTOP, "expired"),
            lease("192.0.2.152", PHONE, "declined"),
        ],
    )
    assert [str(x.address) for x in srv.leases_of(LAPTOP)] == ["192.0.2.150", "192.0.2.151"]
    assert [str(x.address) for x in srv.active_leases()] == ["192.0.2.150"]
    assert srv.lease_for(ip("192.0.2.151")) is None


def test_merge_keeps_relays_leases_and_joins_sources() -> None:
    ap, gw = device("ap", DeviceRole.AP), device("gw")

    def c(dev: str, **sources: str) -> Client:
        addrs = ["192.0.2.150", "2001:db8::21"]
        return client(LAPTOP, *addrs, sources=sources).model_copy(
            update={"id": f"{dev}/client/{LAPTOP}"}
        )

    net_ = merge(
        [SITE],
        [
            snapshot(
                gw,
                dhcp_servers=[dhcp_server("gw", leases=[lease("192.0.2.150", LAPTOP)])],
                dhcp_relays=[relay("gw", 20, "192.0.2.1")],
                clients=[c("gw", **{"192.0.2.150": "dhcp", "2001:db8::21": "slaac"})],
            ),
            # the AP is more specific about where; it does not know the IPv4 source
            snapshot(ap, clients=[c("ap", **{"192.0.2.150": "unknown"})]),
        ],
    )
    (merged,) = net_.clients
    assert {str(a): s.value for a, s in merged.address_sources.items()} == {
        "192.0.2.150": "dhcp",
        "2001:db8::21": "slaac",
    }
    assert [r.id for r in net_.dhcp_relays] == ["gw/dhcp-relay/20"]
    assert net_.dhcp_servers[0].leases == [lease("192.0.2.150", LAPTOP)]


def test_client_sources_survive_json() -> None:
    c = client(LAPTOP, "192.0.2.150", "2001:db8::21", sources={"2001:db8::21": "slaac-privacy"})
    assert type(c).model_validate_json(c.model_dump_json()) == c


def test_contract_finds_inconsistent_dhcp_data() -> None:
    good = dhcp_server("gw", leases=[lease("192.0.2.150", LAPTOP), lease("192.0.2.150", LAPTOP)])
    assert dhcp_problems(good) == []  # the same client twice is not a conflict
    bad = dhcp_server(
        "gw",
        leases=[
            DhcpLease(address=ip("192.0.2.5")),
            lease("192.0.2.6", LAPTOP, starts=T0, expires=T0 - timedelta(hours=1)),
            lease("192.0.2.7", LAPTOP, "reserved", reserved=False),
            lease("192.0.2.8", LAPTOP),
            lease("192.0.2.8", PHONE),
        ],
        options=[
            DhcpOption(code=42, value="192.0.2.1"),
            DhcpOption(code=252, value="a"),
            DhcpOption(code=252, value="b"),
        ],
    )
    found = "\n".join(dhcp_problems(bad))
    for needle in [
        "192.0.2.5 has neither a MAC address nor a client id",
        "192.0.2.6 expires before it starts",
        "192.0.2.7: state reserved but not a reservation",
        f"192.0.2.8 is active for both {LAPTOP} and {PHONE}",
        "option 42 belongs in its typed field",
        "option 252 listed twice",
    ]:
        assert needle in found, needle
    wrong = client(LAPTOP, "192.0.2.150", "2001:db8::21")
    wrong = wrong.model_copy(
        update={
            "address_sources": {
                ip("192.0.2.150"): AddressSource.SLAAC,
                ip("2001:db8::21"): AddressSource.DHCP,
                ip("192.0.2.99"): AddressSource.DHCP,
            }
        }
    )
    text = "\n".join(client_problems(wrong))
    assert "slaac cannot apply to 192.0.2.150" in text
    assert "dhcp cannot apply to 2001:db8::21" in text
    assert "source for 192.0.2.99, which it does not list" in text


class WithDhcp(Fake):
    """An adapter on API 1.0 that reads a DHCP server with leases and a relay."""

    manifest = Fake.manifest.model_copy(
        update={"capabilities": frozenset({*Fake.manifest.capabilities, Capability.DHCP})}
    )

    async def read_dhcp(self) -> Observation:
        d = self.context.device_id
        seg = segment_id(self.context.site_id, None)
        return Observation(
            dhcp_servers=[
                dhcp_server(d, leases=[lease("192.0.2.150", LAPTOP)]).model_copy(
                    update={"segment_id": seg}
                )
            ],
            dhcp_relays=[relay(d, None, "192.0.2.1")],
        )


async def test_observe_stamps_relays_and_passes_the_contract() -> None:
    check_manifest(WithDhcp.manifest)
    snap = await assert_contract(WithDhcp(ctx()))
    (r,) = snap.dhcp_relays
    assert r.source is not None and r.source.adapter == "fake"
    assert snap.dhcp_servers[0].leases == [lease("192.0.2.150", LAPTOP)]


def test_contract_needs_dhcp_own_ids_and_unique_relays() -> None:
    adapter = WithDhcp(ctx())
    good = asyncio.run(adapter.observe())
    first = good.dhcp_relays[0]
    misnamed = first.model_copy(update={"id": "ap1/relay/x", "segment_id": IOT})
    twice = good.model_copy(update={"dhcp_relays": [first, first, misnamed]})
    text = "\n".join(problems(adapter, twice))
    assert f"dhcp relay {first.id} reported twice" in text
    assert "dhcp relay id ap1/relay/x is not ap1/dhcp-relay/<segment key>" in text
    assert f"ap1/relay/x references unknown segment {IOT}" in text
    no_caps = good.device.model_copy(update={"capabilities": ["interfaces"]})
    text = "\n".join(problems(adapter, good.model_copy(update={"device": no_caps})))
    assert "dhcp_relays reported without declaring dhcp" in text


def test_ui_network_carries_sources_and_lease_end() -> None:
    from signalbox.web.app import public_network

    laptop = client(LAPTOP, "192.0.2.150", "2001:db8::21")
    printer = client(PRINTER, "192.0.2.10", sources={"192.0.2.10": "dhcp-reserved"})
    leases = [
        lease("192.0.2.150", LAPTOP),
        lease("192.0.2.149", LAPTOP, expires=T0 + timedelta(days=3)),
        lease("192.0.2.148", LAPTOP, "expired", expires=T0 + timedelta(days=9)),
    ]
    data = public_network(_network(laptop, printer, leases=leases))
    by_mac = {c["mac"]: c for c in data["clients"]}
    assert by_mac[LAPTOP]["sources"] == {"192.0.2.150": "dhcp"}
    assert by_mac[LAPTOP]["lease_expires"] == (T0 + timedelta(days=3)).isoformat()
    assert by_mac[PRINTER]["sources"] == {"192.0.2.10": "dhcp-reserved"}
    assert by_mac[PRINTER]["lease_expires"] is None


def test_schema_has_leases_and_relays() -> None:
    defs = json_schema()["$defs"]
    assert {"DhcpLease", "DhcpRelay", "DhcpOption", "AddressSource", "LeaseState"} <= set(defs)
    assert "address_sources" in defs["Client"]["properties"]
    assert "dhcp_relays" in defs["Snapshot"]["properties"]
    assert defs["AddressSource"]["enum"][:2] == ["dhcp", "dhcp-reserved"]
