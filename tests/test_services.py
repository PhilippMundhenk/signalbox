"""Management services (#173): model, derived reach, merge, contract, UI JSON."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import pytest
from pydantic import ValidationError

from factories import (
    SITE,
    device,
    iface,
    ip,
    mikrotik_default_services,
    net,
    port,
    service,
    snapshot,
    snmp,
    uplink,
)
from signalbox.adapters import Observation, SystemInfo, check_manifest
from signalbox.merge import merge
from signalbox.model import (
    SERVICE_ENCRYPTED,
    SERVICE_LABELS,
    DeviceRole,
    ManagementService,
    Membership,
    Network,
    PortMembership,
    Segment,
    ServiceKind,
    ServiceTransport,
    Snapshot,
    Subnet,
    internet_reachable_network,
    json_schema,
    port_id,
    segment_id,
)
from signalbox.testing import assert_contract, problems, service_problems
from test_adapters import Fake, ctx

LAN, MGMT, GUEST = (segment_id(SITE.id, v) for v in (None, 99, 30))


def test_defaults_come_from_the_kind_and_can_be_overridden() -> None:
    ssh = ManagementService(id="gw/service/ssh", device_id="gw", kind=ServiceKind.SSH, enabled=True)
    assert (ssh.transport, ssh.encrypted, ssh.port) == (ServiceTransport.TCP, True, None)
    assert ssh.listen == ssh.interfaces == ssh.segments == ssh.allowed_from == []
    assert ssh.from_wan is ssh.password_login is ssh.snmp is None
    telnet = service("gw", "telnet")
    assert (telnet.encrypted, telnet.port) == (False, 23)
    assert service("gw", "mac-telnet").transport is ServiceTransport.LAYER2
    assert service("gw", "snmp").transport is ServiceTransport.UDP
    # not fixed by the kind: left unknown
    other = service("gw", "other", "bandwidth-server")
    assert (other.transport, other.encrypted) == (None, None)
    assert service("gw", "tr-064").encrypted is None
    assert service("gw", "tr-064", port=49443, encrypted=True).encrypted is True
    # the device's own answer wins
    assert service("gw", "http", encrypted=True).encrypted is True
    assert service("gw", "ssh", transport=ServiceTransport.UDP).transport is ServiceTransport.UDP
    # SNMP: only v3 with privacy is encrypted
    assert service("gw", "snmp").encrypted is False
    assert service("gw", "snmp", snmp=snmp("3", v3_privacy=True)).encrypted is True
    assert service("gw", "snmp", snmp=snmp("2c", "3", v3_privacy=True)).encrypted is False
    assert service("gw", "snmp", snmp=snmp("3", v3_privacy=False)).encrypted is False
    assert set(SERVICE_ENCRYPTED) == set(ServiceKind) == set(SERVICE_LABELS)
    # JSON round trip keeps the filled values; validation of dicts works the same way
    v3 = service("gw", "snmp", snmp=snmp("3", "1", v3_privacy=True))
    assert v3.snmp is not None and [v.value for v in v3.snmp.versions] == ["1", "3"]
    assert ManagementService.model_validate_json(v3.model_dump_json()) == v3
    assert ManagementService.model_validate(v3) is v3
    raw = {"id": "gw/service/snmp", "device_id": "gw", "kind": "snmp", "enabled": True}
    as_dict = ManagementService.model_validate(raw | {"snmp": {"versions": ["3"], "v3_privacy": 1}})
    assert as_dict.encrypted is True
    with pytest.raises(ValidationError):
        ManagementService.model_validate(raw | {"kind": "gopher"})
    with pytest.raises(ValidationError):
        service("gw", "ssh", port=0)
    assert Snapshot(device=device("gw"), observed_at=datetime.now()).services == []


def test_labels_and_helpers() -> None:
    assert service("gw", "https", "www-ssl").label() == "HTTPS (www-ssl)"
    assert service("gw", "ssh", "SSH").label() == "SSH"
    assert service("gw", "tr-064", "TR-064").label() == "TR-064"
    assert service("gw", "vendor", "nsdp").label() == "configuration protocol (nsdp)"
    assert service("gw", "http").plaintext()
    assert not service("gw", "http", redirects_to_https=True).plaintext()
    assert not service("gw", "telnet", enabled=False).plaintext()
    assert not service("gw", "ssh").plaintext() and not service("gw", "tr-064").plaintext()
    everywhere = service("gw", "ssh", listen=[ip("0.0.0.0"), ip("::")])
    assert everywhere.unrestricted() and not everywhere.listen_restricted()
    assert not service("gw", "ssh", listen=[ip("192.0.2.1")]).unrestricted()
    assert not service("gw", "ssh", allowed_from=[net("192.0.2.0/24")]).unrestricted()
    only = service("gw", "ssh", allowed_from=[net("192.0.2.0/24"), net("2001:db8::/32")])
    assert only.accepts_from(ip("192.0.2.9")) and only.accepts_from(ip("2001:db8::9"))
    assert not only.accepts_from(ip("198.51.100.9"))
    assert service("gw", "ssh").accepts_from(ip("203.0.113.9"))


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ({}, None),
        ({"password_login": True, "root_login": True}, True),
        ({"password_login": True, "root_login": True, "root_password_login": False}, False),
        ({"root_password_login": True}, True),  # OpenWrt RootPasswordAuth on
        ({"root_password_login": True, "password_login": False}, False),
        ({"root_password_login": True, "root_login": False}, False),
        ({"password_login": True}, None),
    ],
)
def test_root_password_login(values: dict[str, Any], expected: bool | None) -> None:
    assert service("gw", "ssh", **values).allows_root_password() is expected


@pytest.mark.parametrize(
    ("cidr", "expected"),
    [
        ("192.168.0.0/16", False),
        ("10.1.0.0/16", False),
        ("100.64.0.0/10", False),
        ("fd00::/8", False),
        ("fe80::/64", False),
        ("127.0.0.0/8", False),
        ("0.0.0.0/0", True),
        ("192.0.2.0/24", True),  # documentation prefixes stand in for public ones
        ("2001:db8::/32", True),
        ("10.0.0.0/7", True),  # larger than the private block
    ],
)
def test_internet_reachable_network(cidr: str, expected: bool) -> None:
    assert internet_reachable_network(net(cidr)) is expected


def _subnet(dev: str, seg: str, cidr: str, gateway: bool = True) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{seg.rsplit('/', 1)[-1]}",
        segment_id=seg,
        interface=iface(cidr),
        device_id=dev,
        gateway=gateway,
    )


def _segment(seg: str, vlan: int | None, *members: tuple[str, Membership]) -> Segment:
    return Segment(
        id=seg,
        site_id=SITE.id,
        vlan=vlan,
        members=[PortMembership(port_id=p, mode=m) for p, m in members],
    )


def _router(*services: ManagementService, uplinks: bool = True) -> Network:
    """Router ``gw``: LAN 192.168.1.0/24 untagged on ether2, management VLAN 99
    (192.0.2.0/24), guest VLAN 30 (198.51.100.0/24) tagged on ether2, WAN on ether1;
    a switch ``sw`` managed in the guest network (wrongly) at 198.51.100.5."""
    gw = "gw"
    e2 = port_id(gw, "ether2")
    U, T = Membership.UNTAGGED, Membership.TAGGED
    return merge(
        [SITE],
        [
            snapshot(
                device(gw),
                ports=[port(gw, "ether1"), port(gw, "ether2")],
                segments=[
                    _segment(LAN, None, (e2, U)),
                    _segment(MGMT, 99, (e2, T)),
                    _segment(GUEST, 30, (e2, T)),
                ],
                subnets=[
                    _subnet(gw, LAN, "192.168.1.1/24"),
                    _subnet(gw, MGMT, "192.0.2.1/24"),
                    _subnet(gw, GUEST, "198.51.100.1/24"),
                ],
                uplinks=[uplink(gw, addresses=[iface("203.0.113.7/24")], port="ether1")]
                if uplinks
                else [],
                services=list(services),
            ),
            snapshot(
                device("sw", DeviceRole.SWITCH, management_address="198.51.100.5"),
                services=[s for s in services if s.device_id == "sw"],
            ),
        ],
    )


def test_service_segments_from_the_devices_own_restrictions() -> None:
    def reach(svc: ManagementService) -> list[str]:
        return _router(svc).service_segments(svc)

    all_three = sorted([LAN, MGMT, GUEST])
    assert reach(service("gw", "ssh")) == all_three
    assert reach(service("gw", "ssh", enabled=False)) == []
    assert reach(service("gw", "ssh", segments=[MGMT])) == [MGMT]
    assert reach(service("gw", "ssh", listen=[ip("192.0.2.1")])) == [MGMT]
    assert reach(service("gw", "ssh", listen=[ip("0.0.0.0")])) == all_three
    assert reach(service("gw", "ssh", listen=[ip("127.0.0.1")])) == []
    assert reach(service("gw", "ssh", allowed_from=[net("192.0.2.0/25")])) == [MGMT]
    assert reach(service("gw", "ssh", allowed_from=[net("0.0.0.0/0")])) == all_three
    # bound to the WAN port only: none of the site's networks
    assert reach(service("gw", "ssh", ports=["ether1"])) == []
    assert reach(service("gw", "ssh", ports=["ether2"])) == all_three
    # layer 2: every network on a port of the device, address filters do not apply
    mac = service("gw", "mac-winbox", allowed_from=[net("192.0.2.0/24")])
    assert reach(mac) == all_three
    # a switch without subnets of its own: the network of its management address
    assert reach(service("sw", "http")) == [GUEST]
    # a segment without a known subnet is kept by allowed_from (it cannot be ruled out)
    lonely = segment_id(SITE.id, 40)
    assert reach(service("gw", "ssh", segments=[lonely], allowed_from=[net("192.0.2.0/24")])) == [
        lonely
    ]


def test_service_segments_with_a_bad_management_address() -> None:
    n = _router()
    odd = n.model_copy(
        update={
            "devices": [
                d.model_copy(update={"management_address": "switch.example"}) if d.id == "sw" else d
                for d in n.devices
            ]
        }
    )
    assert odd.service_segments(service("sw", "http")) == []
    assert odd.service_segments(service("unknown", "http")) == []


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ({}, None),  # listens on the uplink: the firewall decides (#135)
        ({"enabled": False, "from_wan": None}, False),
        ({"from_wan": True}, True),
        ({"from_wan": False}, False),
        ({"segments": [LAN]}, False),
        ({"listen": [ip("192.168.1.1")]}, False),
        ({"listen": [ip("203.0.113.7")]}, None),
        ({"listen": [ip("::")]}, None),
        ({"ports": ["ether2"]}, False),
        ({"ports": ["ether1"]}, None),
        ({"allowed_from": [net("192.168.0.0/16"), net("fd00::/8")]}, False),
        ({"allowed_from": [net("192.168.0.0/16"), net("203.0.113.0/24")]}, None),
    ],
)
def test_service_from_wan(values: dict[str, Any], expected: bool | None) -> None:
    svc = service("gw", "winbox", **values)
    assert _router(svc).service_from_wan(svc) is expected


def test_service_from_wan_layer2_and_without_uplinks() -> None:
    every = service("gw", "mac-telnet")
    assert _router(every).service_from_wan(every) is None  # also on the WAN port
    wan = service("gw", "mac-telnet", ports=["ether1"])
    assert _router(wan).service_from_wan(wan) is None
    lan = service("gw", "mac-telnet", ports=["ether2"])
    assert _router(lan).service_from_wan(lan) is False
    seg = service("gw", "mac-telnet", segments=[LAN])
    assert _router(seg).service_from_wan(seg) is False
    # no uplink reported: not on the internet side itself (port forwards are #135)
    ssh = service("gw", "ssh")
    assert _router(ssh, uplinks=False).service_from_wan(ssh) is False
    assert _router(ssh, uplinks=False).service_from_wan(ssh.model_copy(update={"from_wan": True}))
    # the uplink's port is not known: a port binding cannot rule the uplink out
    n = _router(ssh)
    blind = n.model_copy(
        update={"uplinks": [u.model_copy(update={"port_id": None}) for u in n.uplinks]}
    )
    assert blind.service_from_wan(service("gw", "ssh", ports=["ether2"])) is None


def test_merge_keeps_services_and_moves_native_segments() -> None:
    from test_double_nat import ISP_LAN, MAIN, firewall, isp, site

    fw_ssh = service("fw", "ssh", segments=[MAIN])
    isp_ui = service("isp", "http", segments=[MAIN])
    n = site(isp(services=[isp_ui]), firewall(services=[fw_ssh]))
    assert [s.id for s in n.services] == ["fw/service/ssh", "isp/service/http"]
    assert n.services_of("isp")[0].segments == [ISP_LAN]
    assert n.services_of("fw")[0].segments == [MAIN]
    assert n.service_segments(n.services_of("isp")[0]) == [ISP_LAN]


def test_contract_finds_inconsistent_services() -> None:
    ports, segs = {port_id("gw", "ether1")}, {LAN}
    good = [
        *mikrotik_default_services("gw"),
        service("gw", "ssh", "ssh2", ports=["ether1"], segments=[LAN], root_login=False),
        service("gw", "http", "web", redirects_to_https=True),
        service("gw", "snmp"),
    ]
    assert [p for s in good for p in service_problems(s, ports, segs)] == []
    bad = [
        service("gw", "ssh").model_copy(update={"id": "gw/ssh"}),
        service("gw", "ssh", ports=["ether9"]),
        service("gw", "ssh", segments=[GUEST]),
        service("gw", "mac-telnet", port=20561),
        service("gw", "mac-winbox", listen=[ip("192.0.2.1")]),
        service("gw", "https", enabled=False, from_wan=True),
        service("gw", "telnet", root_login=True),
        service("gw", "https", redirects_to_https=True),
        service("gw", "ssh", snmp=snmp()),
    ]
    found = "\n".join(p for s in bad for p in service_problems(s, ports, segs))
    for needle in [
        "service id gw/ssh is not gw/service/<name>",
        "bound to unknown port gw/port/ether9",
        f"references unknown segment {GUEST}",
        "a layer-2 service has no port or listen address",
        "disabled but reachable from the internet",
        "root login options on a telnet service",
        "redirects_to_https on a https service",
        "SNMP settings on a ssh service",
    ]:
        assert needle in found, needle
    assert found.count("layer-2") == 2


class WithServices(Fake):
    """An adapter on API 1.0 that reports services with ``interfaces`` and says it reads the
    device in clear text: no new capability, no API version."""

    async def read_system(self) -> SystemInfo:
        base = await super().read_system()
        return base.model_copy(update={"transport_encrypted": False})

    async def read_interfaces(self) -> Observation:
        base = await super().read_interfaces()
        d = self.context.device_id
        services = [service(d, "http"), service(d, "vendor", "nsdp", port=63322)]
        return base.model_copy(update={"services": services})


async def test_observe_stamps_services_and_passes_the_contract() -> None:
    check_manifest(WithServices.manifest)
    assert WithServices.manifest.api_version == "1.0"
    snap = await assert_contract(WithServices(ctx()))
    assert snap.device.transport_encrypted is False
    http, nsdp = snap.services
    assert http.source is not None and http.source.adapter == "fake"
    assert nsdp.observed_at == snap.observed_at
    assert (nsdp.transport, nsdp.encrypted) == (ServiceTransport.UDP, False)
    plain = await Fake(ctx()).observe()
    assert plain.device.transport_encrypted is None and plain.services == []


def test_contract_needs_interfaces_own_ids_and_unique_services() -> None:
    adapter = WithServices(ctx())
    good = asyncio.run(adapter.observe())
    first = good.services[0]
    stranger = first.model_copy(update={"id": "other/service/ssh", "device_id": "other"})
    twice = good.model_copy(update={"services": [*good.services, first, stranger]})
    text = "\n".join(problems(adapter, twice))
    assert "services id other/service/ssh does not start with" in text
    assert f"service {first.id} reported twice" in text
    no_caps = good.device.model_copy(update={"capabilities": ["wireless"]})
    text = "\n".join(problems(adapter, good.model_copy(update={"device": no_caps})))
    assert "services reported without declaring interfaces" in text


def test_ui_network_carries_the_derived_values() -> None:
    from signalbox.web.app import public_network

    ssh = service("gw", "ssh", allowed_from=[net("192.0.2.0/24")])
    remote = service("gw", "https", "remote-access", from_wan=True)
    data = public_network(_router(ssh, remote))
    by_id = {s["id"]: s for s in data["services"]}
    assert by_id["gw/service/ssh"]["reach_segments"] == [MGMT]
    assert by_id["gw/service/ssh"]["internet"] is None
    assert by_id["gw/service/remote-access"]["internet"] is True


def test_schema_has_services() -> None:
    defs = json_schema()["$defs"]
    assert {"ManagementService", "ServiceKind", "SnmpSettings"} <= set(defs)
    assert "transport_encrypted" in defs["Device"]["properties"]
    assert defs["ServiceTransport"]["enum"] == ["tcp", "udp", "layer2"]
