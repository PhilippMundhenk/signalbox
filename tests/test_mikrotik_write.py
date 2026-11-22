"""MikroTik write side against the simulator: every kind applied, verified and undone."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from factories import SITE, iface, ip
from signalbox.adapters import AdapterContext, AdapterError, Backup, WritesConfig
from signalbox.adapters.mikrotik import (
    BRIDGE_PORT,
    BRIDGE_VLAN,
    DHCP_LEASE,
    IP_ADDRESS,
    WIFI,
    MikrotikAdapter,
    MikrotikConfig,
)
from signalbox.adapters.mikrotik.write import BACKUP_FORMAT, _export_text, ros_duration
from signalbox.changes import (
    AnyValue,
    Change,
    ChangeKind,
    DhcpValue,
    PortValue,
    ReservationValue,
    RouterValue,
    WlanValue,
    order,
    plan,
)
from signalbox.deploy import Deployer, current_value, matches
from signalbox.desired import parse
from signalbox.history import ChangeStatus
from signalbox.merge import merge
from signalbox.model import DeviceRole, Network, Pmf, Security, passphrase_fingerprint
from signalbox.rules.builtin import RULES
from signalbox.service import build
from signalbox.sim.mikrotik import PASSPHRASE, PASSWORD, MikrotikSimulator
from signalbox.sim.server import serve
from signalbox.store import DeviceRecord

SIM = MikrotikSimulator()
DEV = "rt"
NATIVE = "home/segment/native"
IOT = "home/segment/20"
SECRETS = {"psk": "a brand new passphrase"}


@pytest.fixture(scope="module")
def url() -> Iterator[str]:
    with serve(SIM.app()) as u:
        yield u


@pytest.fixture(autouse=True)
def sim() -> MikrotikSimulator:
    SIM.__dict__.update(MikrotikSimulator().__dict__)
    return SIM


def adapter(url: str) -> MikrotikAdapter:
    config = MikrotikConfig(url=url, password=SecretStr(PASSWORD), allow_insecure_http=True)
    return MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id=DEV,
            device_name="Router",
            role=DeviceRole.GATEWAY,
            config=config,
        )
    )


async def network(url: str) -> Network:
    a = adapter(url)
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert not snap.errors, snap.errors
    return merge([SITE], [snap])


def view(net: Network) -> dict[str, Any]:
    """What the writes may change (clients and neighbours are not configuration)."""
    data = net.model_dump(mode="json", exclude={"observed_at", "source"})

    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items() if k not in ("observed_at", "source")}
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value

    return {k: clean(data[k]) for k in ("ports", "segments", "subnets", "dhcp_servers", "wlans")}


def differences(a: Any, b: Any, path: str = "") -> list[str]:
    """Where two views differ (readable assertion messages)."""
    if isinstance(a, dict) and isinstance(b, dict):
        return [
            d
            for k in sorted(set(a) | set(b))
            for d in differences(a.get(k), b.get(k), f"{path}.{k}")
        ]
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [
            d
            for i, (x, y) in enumerate(zip(a, b, strict=True))
            for d in differences(x, y, f"{path}[{i}]")
        ]
    return [] if a == b else [f"{path}: {a!r} != {b!r}"]


def unkeyed(view: dict[str, Any]) -> dict[str, Any]:
    """A view without passphrase fingerprints (a revert cannot know the old passphrase)."""
    wlans = [{k: v for k, v in w.items() if k != "passphrase_fingerprint"} for w in view["wlans"]]
    return {**view, "wlans": wlans}


def change(net: Network, kind: ChangeKind, key: str, new: AnyValue | None) -> Change:
    probe = Change(kind=kind, device_id=DEV, site_id="home", key=key, new=new or _any(kind))
    old = current_value(net, probe)
    return Change(kind=kind, device_id=DEV, site_id="home", key=key, old=old, new=new)


def _any(kind: ChangeKind) -> AnyValue:
    if kind is ChangeKind.RESERVATION:
        return ReservationValue(mac="02:00:00:00:00:99", address=ip("192.0.2.99"))
    return PortValue()


async def apply(url: str, changes: list[Change], secrets: dict[str, str] | None = None) -> Any:
    a = adapter(url)
    try:
        return await a.apply(order(changes), secrets or SECRETS, 120)
    finally:
        await a.close()


async def roundtrip(url: str, changes: list[Change], secrets: dict[str, str] | None = None) -> Any:
    """Apply, check the new values; apply the inverses, check the old values and the rest."""
    secrets = secrets if secrets is not None else SECRETS
    before = await network(url)
    result = await apply(url, changes, secrets)
    assert result.confirm_deadline is None and result.calls
    after = await network(url)
    for c in changes:
        assert matches(after, c, c.new, secrets), (c.describe(), current_value(after, c))
    await apply(url, [c.inverse() for c in changes], secrets)
    back = await network(url)
    for c in changes:
        assert matches(back, c, c.old, secrets), (c.describe(), current_value(back, c))
    assert not differences(view(back), view(before)), differences(view(back), view(before))
    return after


def test_manifest_declares_every_kind() -> None:
    assert MikrotikAdapter.manifest.writes == frozenset(ChangeKind)
    assert issubclass(MikrotikAdapter, WritesConfig)
    assert ros_duration(0) == "0s" and ros_duration(90061) == "1d1h1m1s"


# --- ROUTER ------------------------------------------------------------------------------------


async def test_router_new_vlan_with_dhcp_and_reservation(url: str, sim: MikrotikSimulator) -> None:
    net = await network(url)
    key = "home/segment/30"
    router = change(
        net,
        ChangeKind.ROUTER,
        key,
        RouterValue(vlan=30, name="Guests", address=iface("198.51.100.129/25")),
    )
    dhcp = Change(
        kind=ChangeKind.DHCP,
        device_id=DEV,
        site_id="home",
        key=key,
        new=DhcpValue(
            enabled=True,
            pool=(ip("198.51.100.150"), ip("198.51.100.199")),
            dns=[ip("198.51.100.129")],
            lease_seconds=3600,
        ),
    )
    res = Change(
        kind=ChangeKind.RESERVATION,
        device_id=DEV,
        site_id="home",
        key=f"{key}/02:00:00:00:00:31",
        new=ReservationValue(
            mac="02:00:00:00:00:31", address=ip("198.51.100.131"), hostname="tablet"
        ),
    )
    after = await roundtrip(url, [router, dhcp, res])
    seg = after.segment(key)
    assert seg is not None and seg.vlan == 30 and seg.name == "Guests"
    # the inverse removed what it created
    assert all(r["vlan-ids"] != "30" for r in sim.data[BRIDGE_VLAN])
    assert all(r["name"] != "vlan30" for r in sim.data["/rest/interface"])


async def test_router_vlan_without_name(url: str) -> None:
    net = await network(url)
    c = change(
        net,
        ChangeKind.ROUTER,
        "home/segment/40",
        RouterValue(vlan=40, address=iface("198.51.100.193/26")),
    )
    after = await roundtrip(url, [c])
    seg = after.segment("home/segment/40")
    assert seg is not None and seg.name is None


async def test_router_update_address_and_name(url: str, sim: MikrotikSimulator) -> None:
    net = await network(url)
    iot = change(
        net,
        ChangeKind.ROUTER,
        IOT,
        RouterValue(vlan=20, name="Things", address=iface("198.51.100.254/24")),
    )
    lan = change(
        net, ChangeKind.ROUTER, NATIVE, RouterValue(name="Home", address=iface("192.0.2.254/24"))
    )
    assert iot.old == RouterValue(vlan=20, name="IoT devices", address=iface("198.51.100.1/24"))
    await roundtrip(url, [iot, lan])
    assert sim.data["/rest/interface/bridge"][0]["comment"] == "LAN"


async def test_router_add_address_to_a_tagged_vlan(url: str, sim: MikrotikSimulator) -> None:
    # VLAN 20 without the router's interface: only the bridge VLAN entry is left
    sim.data["/rest/interface/vlan"] = []
    sim.data[IP_ADDRESS] = [r for r in sim.data[IP_ADDRESS] if r["interface"] != "iot"]
    sim.data[BRIDGE_VLAN][1]["tagged"] = "ether2"
    sim.data[BRIDGE_VLAN][1]["comment"] = ""
    net = await network(url)
    c = change(net, ChangeKind.ROUTER, IOT, RouterValue(vlan=20, address=iface("198.51.100.1/24")))
    assert c.old is None
    await roundtrip(url, [c])


async def test_router_refusals(url: str, sim: MikrotikSimulator) -> None:
    net = await network(url)
    # a network without an interface, that is not a VLAN
    dmz = Change(
        kind=ChangeKind.ROUTER,
        device_id=DEV,
        site_id="home",
        key="home/segment/dmz",
        new=RouterValue(address=iface("203.0.113.65/26")),
    )
    with pytest.raises(AdapterError, match="only VLAN interfaces are created"):
        await apply(url, [dmz])
    # a VLAN id that shares a bridge VLAN entry
    sim.data[BRIDGE_VLAN][1]["vlan-ids"] = "20,30"
    net = await network(url)
    c = change(
        net,
        ChangeKind.ROUTER,
        "home/segment/30",
        RouterValue(vlan=30, address=iface("198.51.100.129/25")),
    )
    with pytest.raises(AdapterError, match="split it on the device first"):
        await apply(url, [c])
    sim.data[BRIDGE_VLAN][1]["vlan-ids"] = "20"
    # an interface name in use
    sim.data["/rest/interface"].append({".id": "*99", "name": "vlan30", "type": "ether"})
    with pytest.raises(AdapterError, match="named vlan30 exists already"):
        await apply(url, [c])
    # an address the router refuses
    bad = change(
        net, ChangeKind.ROUTER, IOT, RouterValue(vlan=20, address=iface("198.51.100.1/24"))
    )
    sim.fail_write[IP_ADDRESS] = 400
    bad = bad.model_copy(
        update={"new": RouterValue(vlan=20, name="IoT", address=iface("198.51.100.2/24"))}
    )
    with pytest.raises(AdapterError, match="refused the change: simulated failure"):
        await apply(url, [bad])
    assert net is not None
    # a dynamic (DHCP client) address
    wan = "home/segment/ether1"
    sim.data["/rest/interface/list/member"] = []
    net = await network(url)
    up = change(net, ChangeKind.ROUTER, wan, RouterValue(address=iface("203.0.113.3/24")))
    with pytest.raises(AdapterError, match="dynamic"):
        await apply(url, [up])
    with pytest.raises(AdapterError, match="dynamic"):
        await apply(url, [up.inverse().model_copy(update={"new": None})])


async def test_router_name_from_a_shared_entry_cannot_be_set(
    url: str, sim: MikrotikSimulator
) -> None:
    sim.data[BRIDGE_VLAN][1]["vlan-ids"] = "20,21"
    net = await network(url)
    c = change(
        net,
        ChangeKind.ROUTER,
        IOT,
        RouterValue(vlan=20, name="Other", address=iface("198.51.100.1/24")),
    )
    with pytest.raises(AdapterError, match="name cannot be set"):
        await apply(url, [c])


# --- DHCP and reservations ----------------------------------------------------------------------


async def test_dhcp_update(url: str) -> None:
    net = await network(url)
    c = change(
        net,
        ChangeKind.DHCP,
        IOT,
        DhcpValue(
            enabled=False,
            pool=(ip("198.51.100.50"), ip("198.51.100.99")),
            dns=[ip("192.0.2.53")],
            lease_seconds=7200,
        ),
    )
    assert c.old is not None and c.old.lease_seconds == 86400  # type: ignore[union-attr]
    await roundtrip(url, [c])


async def test_dhcp_without_pool_and_dns(url: str, sim: MikrotikSimulator) -> None:
    net = await network(url)
    c = change(net, ChangeKind.DHCP, NATIVE, DhcpValue(enabled=True, lease_seconds=1800))
    await roundtrip(url, [c])
    # a server without a pool gets one
    sim.data["/rest/ip/dhcp-server"][0]["address-pool"] = "static-only"
    sim.data["/rest/ip/dhcp-server/network"] = []
    net = await network(url)
    c = change(
        net,
        ChangeKind.DHCP,
        NATIVE,
        DhcpValue(enabled=True, pool=(ip("192.0.2.20"), ip("192.0.2.30")), lease_seconds=1800),
    )
    await apply(url, [c])
    assert matches(await network(url), c, c.new, {})
    assert sim.data["/rest/ip/dhcp-server/network"][0]["address"] == "192.0.2.0/24"


async def test_dhcp_needs_an_address(url: str) -> None:
    c = Change(
        kind=ChangeKind.DHCP,
        device_id=DEV,
        site_id="home",
        key="home/segment/77",
        new=DhcpValue(enabled=True),
    )
    with pytest.raises(AdapterError, match="no IPv4 address in this network"):
        await apply(url, [c])


async def test_reservations(url: str, sim: MikrotikSimulator) -> None:
    net = await network(url)
    mac = "02:00:00:00:00:10"
    update = change(
        net,
        ChangeKind.RESERVATION,
        f"{NATIVE}/{mac}",
        ReservationValue(mac=mac, address=ip("192.0.2.11"), hostname="office printer"),
    )
    assert update.old == ReservationValue(mac=mac, address=ip("192.0.2.10"), hostname="printer")
    await roundtrip(url, [update])
    sensor = "02:00:00:00:00:20"
    rename = change(
        net,
        ChangeKind.RESERVATION,
        f"{IOT}/{sensor}",
        ReservationValue(mac=sensor, address=ip("198.51.100.20"), hostname="weather"),
    )
    await apply(url, [rename])
    assert matches(await network(url), rename, rename.new, {})
    remove = Change(
        kind=ChangeKind.RESERVATION,
        device_id=DEV,
        site_id="home",
        key=f"{NATIVE}/{mac}",
        old=update.old,
    )
    await roundtrip(url, [remove])
    # a lease for every server ("all") in the network
    sim.data[DHCP_LEASE][0]["server"] = "all"
    net = await network(url)
    assert current_value(net, update) == update.old
    await roundtrip(url, [update])
    orphan = update.model_copy(update={"key": f"home/segment/77/{mac}"})
    with pytest.raises(AdapterError, match="no DHCP server"):
        await apply(url, [orphan])


# --- PORT --------------------------------------------------------------------------------------


async def test_ports(url: str, sim: MikrotikSimulator) -> None:
    net = await network(url)
    changes = [
        change(net, ChangeKind.PORT, f"{DEV}/port/ether3", PortValue(untagged=20, tagged=[30, 40])),
        change(net, ChangeKind.PORT, f"{DEV}/port/ether2", PortValue(untagged="native")),
        change(net, ChangeKind.PORT, f"{DEV}/port/ether4", PortValue(untagged=None, tagged=[20])),
    ]
    assert changes[1].old == PortValue(untagged="native", tagged=[20])
    await roundtrip(url, changes)
    # a port without any VLAN (the inverse of a port's membership being created)
    gone = Change(
        kind=ChangeKind.PORT,
        device_id=DEV,
        site_id="home",
        key=f"{DEV}/port/ether2",
        old=changes[1].old,
    )
    await apply(url, [gone])
    after = await network(url)
    assert matches(after, gone, None, {})
    assert sim.data[BRIDGE_PORT][0]["frame-types"] == "admit-only-vlan-tagged"


async def test_port_refusals(url: str, sim: MikrotikSimulator) -> None:
    net = await network(url)

    async def refused(port: str, new: PortValue, match: str) -> None:
        c = Change(
            kind=ChangeKind.PORT,
            device_id=DEV,
            site_id="home",
            key=f"{DEV}/port/{port}",
            old=PortValue(),
            new=new,
        )
        with pytest.raises(AdapterError, match=match):
            await apply(url, [c])

    await refused("ether1", PortValue(untagged="native"), "not a bridge port")
    await refused("nope", PortValue(untagged="native"), "no such port")
    await refused("ether2", PortValue(untagged=20, tagged=[20]), "cannot be untagged and tagged")
    sim.data[BRIDGE_VLAN][1]["vlan-ids"] = "20,30"
    await refused("ether3", PortValue(untagged="native", tagged=[20]), "split it")
    sim.data["/rest/interface/bridge"][0]["vlan-filtering"] = "false"
    await refused("ether2", PortValue(untagged="native"), "in bridge")
    assert net.port(f"{DEV}/port/ether2") is not None


# --- WLAN --------------------------------------------------------------------------------------


async def test_wlan_update_on_inline_and_profile_interfaces(
    url: str, sim: MikrotikSimulator
) -> None:
    net = await network(url)
    c = change(
        net,
        ChangeKind.WLAN,
        "Example",
        WlanValue(
            ssid="Example",
            security=Security.WPA3,
            pmf=Pmf.REQUIRED,
            segment=20,
            hidden=True,
            roaming_80211r=False,
            roaming_80211k=False,
            roaming_80211v=True,
            passphrase_secret="psk",
        ),
    )
    after = await apply(url, [c])
    assert all(call.payload.get("security.passphrase") in (None, "***") for call in after.calls)
    net2 = await network(url)
    assert matches(net2, c, c.new, SECRETS)
    fps = {w.passphrase_fingerprint for w in net2.wlans if w.ssid == "Example"}
    assert fps == {passphrase_fingerprint("Example", SECRETS["psk"])}
    sent = json.dumps(sim.writes)
    assert SECRETS["psk"] in sent  # it went to the device, not to the calls
    assert SECRETS["psk"] not in json.dumps([x.model_dump() for x in after.calls])
    # the inverse sets everything back, except the passphrase (not known to Signalbox)
    await apply(url, [c.inverse()])
    back = await network(url)
    assert matches(back, c, c.old, {})


async def test_wlan_roundtrip_without_passphrase(url: str) -> None:
    net = await network(url)
    iot = change(
        net,
        ChangeKind.WLAN,
        "Example-IoT",
        WlanValue(
            ssid="Example-IoT",
            security=Security.WPA2_WPA3,
            pmf=Pmf.OPTIONAL,
            segment="native",
            hidden=False,
            enabled=False,
            roaming_80211r=True,
            roaming_80211k=True,
            roaming_80211v=True,
        ),
    )
    await roundtrip(url, [iot], {})


async def test_wlan_open_and_owe(url: str, sim: MikrotikSimulator) -> None:
    # both radios alike (a change sets every interface of the SSID to the same values)
    sim.data[WIFI][1].update({"steering.rrm": "yes", "steering.wnm": "yes"})
    net = await network(url)
    base = net.wlans[0]
    assert base.ssid == "Example"

    def to(security: Security) -> Change:
        return change(
            net,
            ChangeKind.WLAN,
            "Example",
            WlanValue(
                ssid="Example",
                security=security,
                pmf=base.pmf,
                roaming_80211r=True,
                roaming_80211k=True,
                roaming_80211v=True,
            ),
        )

    await roundtrip(url, [to(Security.OWE)], {})
    # open drops the security profile, passphrase included: only the backup brings it back
    a = adapter(url)
    try:
        backup = await a.backup()
    finally:
        await a.close()
    c = to(Security.OPEN)
    await apply(url, [c], {})
    assert matches(await network(url), c, c.new, {})
    with pytest.raises(AdapterError, match="wpa2-wpa3 needs a passphrase"):
        await apply(url, [c.inverse()], {})
    a = adapter(url)
    try:
        await a.restore(backup)
    finally:
        await a.close()
    now = view(await network(url))
    assert not differences(now, view(net)), differences(now, view(net))


async def test_wlan_create_and_remove(url: str, sim: MikrotikSimulator) -> None:
    net = await network(url)
    new = WlanValue(
        ssid="Example Guest",
        security=Security.WPA2,
        pmf=Pmf.OPTIONAL,
        segment=20,
        hidden=True,
        roaming_80211r=True,
        roaming_80211k=False,
        roaming_80211v=True,
        passphrase_secret="psk",
    )
    c = change(net, ChangeKind.WLAN, "Example Guest", new)
    assert c.old is None
    after = await roundtrip(url, [c])
    created = [w for w in after.wlans if w.ssid == "Example Guest"]
    assert len(created) == 2  # one per radio
    assert {w.segment_id for w in created} == {IOT}
    assert all(w["name"] != "wifi1-Example-Guest" for w in sim.data[WIFI])
    # native and open, enabled
    plain = WlanValue(ssid="Open", security=Security.OPEN)
    await roundtrip(url, [change(net, ChangeKind.WLAN, "Open", plain)])


async def test_wlan_refusals(url: str, sim: MikrotikSimulator) -> None:
    net = await network(url)

    def wlan(ssid: str, **kw: Any) -> Change:
        new = WlanValue(ssid=ssid, **{"security": Security.WPA2, **kw})
        return change(net, ChangeKind.WLAN, ssid, new)

    with pytest.raises(AdapterError, match="cannot be set through Signalbox"):
        await apply(url, [wlan("Example", security=Security.WPA2_ENTERPRISE)])
    with pytest.raises(AdapterError, match="client isolation is not read or changed on RouterOS"):
        await apply(url, [wlan("Example", client_isolation=True)])
    with pytest.raises(AdapterError, match="needs a passphrase secret"):
        await apply(url, [wlan("New")])
    with pytest.raises(AdapterError, match="secret 'missing' was not given"):
        await apply(url, [wlan("New", passphrase_secret="missing")])
    remove = Change(
        kind=ChangeKind.WLAN,
        device_id=DEV,
        site_id="home",
        key="Example",
        old=WlanValue(ssid="Example", security=Security.WPA2),
    )
    with pytest.raises(AdapterError, match="only disabled"):
        await apply(url, [remove])
    # an open SSID that becomes personal needs a passphrase
    sim.data[WIFI][2]["security.authentication-types"] = ""
    sim.data[WIFI][2]["security.passphrase"] = ""
    with pytest.raises(AdapterError, match="needs a passphrase"):
        await apply(url, [wlan("Example-IoT", segment=20, hidden=True)])
    # no radio
    sim.data[WIFI] = [r for r in sim.data[WIFI] if r.get("master-interface")]
    with pytest.raises(AdapterError, match="has no radio"):
        await apply(url, [wlan("New", passphrase_secret="psk")])
    # a VLAN without a filtering bridge
    sim.data[WIFI] = MikrotikSimulator().data[WIFI]
    sim.data["/rest/interface/bridge"][0]["vlan-filtering"] = "false"
    net = await network(url)
    with pytest.raises(AdapterError, match="needs a bridge with vlan-filtering"):
        await apply(url, [wlan("New", passphrase_secret="psk", segment=30)])
    # the legacy wireless package is read only
    sim.wireless = "legacy"
    with pytest.raises(AdapterError, match="legacy wireless package is read only"):
        await apply(url, [wlan("Example", passphrase_secret="psk")])


# --- plan, backup, restore, failures ---------------------------------------------------------


async def test_plan_changes_needs_no_secrets_and_sends_nothing(
    url: str, sim: MikrotikSimulator
) -> None:
    net = await network(url)
    c = change(
        net,
        ChangeKind.WLAN,
        "Example",
        WlanValue(ssid="Example", security=Security.WPA2, passphrase_secret="psk"),
    )
    other = c.model_copy(update={"device_id": "elsewhere"})
    a = adapter(url)
    try:
        calls = await a.plan_changes([c], {})
        with pytest.raises(AdapterError, match="not a change of rt"):
            await a.plan_changes([other], {})
    finally:
        await a.close()
    assert calls and all(x.target.startswith(WIFI) for x in calls)
    assert {x.payload.get("security.passphrase") for x in calls if x.method == "PATCH"} == {"***"}
    assert sim.writes == []
    assert "Example" in calls[0].description


async def test_backup_and_restore_round_trip(url: str, sim: MikrotikSimulator) -> None:
    before = await network(url)
    a = adapter(url)
    try:
        backup = await a.backup()
    finally:
        await a.close()
    assert backup.format == BACKUP_FORMAT and backup.device_id == DEV
    content = json.loads(backup.content)
    assert content["export"].startswith("# simulated RouterOS export")
    assert PASSPHRASE not in content["export"]
    assert set(content["menus"]) >= {IP_ADDRESS, WIFI, BRIDGE_VLAN, DHCP_LEASE}
    net = before
    changes = [
        change(
            net,
            ChangeKind.ROUTER,
            "home/segment/30",
            RouterValue(vlan=30, name="Guests", address=iface("198.51.100.129/25")),
        ),
        change(
            net,
            ChangeKind.DHCP,
            IOT,
            DhcpValue(enabled=False, pool=(ip("198.51.100.60"), ip("198.51.100.70"))),
        ),
        Change(
            kind=ChangeKind.RESERVATION,
            device_id=DEV,
            site_id="home",
            key=f"{NATIVE}/02:00:00:00:00:10",
            old=ReservationValue(mac="02:00:00:00:00:10", address=ip("192.0.2.10")),
        ),
        change(net, ChangeKind.PORT, f"{DEV}/port/ether3", PortValue(untagged=20, tagged=[30])),
        change(
            net,
            ChangeKind.WLAN,
            "Example",
            WlanValue(ssid="Example", security=Security.WPA3, segment=30, passphrase_secret="psk"),
        ),
    ]
    await apply(url, changes)
    assert view(await network(url)) != view(before)
    a = adapter(url)
    try:
        await a.restore(backup)
    finally:
        await a.close()
    after = await network(url)
    assert view(after) == view(before)
    # a second restore has nothing left to do
    sim.writes.clear()
    a = adapter(url)
    try:
        await a.restore(backup)
    finally:
        await a.close()
    assert sim.writes == []


async def test_backup_without_export_and_menus(url: str, sim: MikrotikSimulator) -> None:
    sim.fail_write["/rest/execute"] = 400
    sim.wireless = "legacy"
    a = adapter(url)
    try:
        backup = await a.backup()
        content = json.loads(backup.content)
        assert content["export"] is None and content["menus"][WIFI] is None
        await a.restore(backup)  # menus that do not exist are left alone
    finally:
        await a.close()


async def test_restore_refusals(url: str) -> None:
    from datetime import UTC, datetime

    def backup(fmt: str, content: str) -> Backup:
        return Backup(device_id=DEV, taken_at=datetime.now(UTC), format=fmt, content=content)

    a = adapter(url)
    try:
        with pytest.raises(AdapterError, match="cannot restore a 'fake' backup"):
            await a.restore(backup("fake", "{}"))
        for content in ("not json", "[]", '{"menus": []}'):
            with pytest.raises(AdapterError, match="no menu snapshot"):
                await a.restore(backup(BACKUP_FORMAT, content))
        await a.confirm()
    finally:
        await a.close()


async def test_write_refused_by_the_router(url: str, sim: MikrotikSimulator) -> None:
    net = await network(url)
    c = change(net, ChangeKind.WLAN, "Example", WlanValue(ssid="Example", security=Security.WPA3))
    sim.read_only = True
    with pytest.raises(
        AdapterError,
        match=r"access denied \(not enough permissions \(9\)\); the user's group needs write",
    ):
        await apply(url, [c])
    sim.read_only = False
    sim.fail_write[WIFI] = 500
    with pytest.raises(AdapterError, match="refused the change: simulated failure"):
        await apply(url, [c])


async def test_errors_never_show_secrets(
    url: str, sim: MikrotikSimulator, monkeypatch: pytest.MonkeyPatch
) -> None:
    net = await network(url)
    secret = "s3cret-passphrase"
    c = change(
        net,
        ChangeKind.WLAN,
        "Example",
        WlanValue(ssid="Example", security=Security.WPA2, passphrase_secret="psk"),
    )
    real = sim.write

    def echo(method: str, path: str, body: dict[str, Any]) -> Any:
        from fastapi.responses import JSONResponse

        if method == "PATCH":
            detail = f"bad passphrase {body.get('security.passphrase')}"
            return JSONResponse({"error": 400, "detail": detail}, status_code=400)
        return real(method, path, body)

    monkeypatch.setattr(sim, "write", echo)
    with pytest.raises(AdapterError) as info:
        await apply(url, [c], {"psk": secret})
    assert secret not in str(info.value) and "bad passphrase ***" in str(info.value)


async def test_odd_answers_to_writes(
    url: str, sim: MikrotikSimulator, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fastapi.responses import Response

    net = await network(url)
    c = change(
        net,
        ChangeKind.ROUTER,
        "home/segment/30",
        RouterValue(vlan=30, address=iface("198.51.100.129/25")),
    )
    real = sim.write
    answer = {"body": "not json", "status": 200}

    def odd(method: str, path: str, body: dict[str, Any]) -> Any:
        if method == "PUT":
            return Response(answer["body"], status_code=int(answer["status"]))
        return real(method, path, body)

    monkeypatch.setattr(sim, "write", odd)
    with pytest.raises(AdapterError, match=r"did not return the new \.id"):
        await apply(url, [c])
    answer.update(body="also not json", status=400)
    with pytest.raises(AdapterError, match="refused the change: HTTP 400"):
        await apply(url, [c])
    answer.update(body='[{".id": "*AA"}]', status=200)
    await apply(url, [c])  # a list with the new entry is accepted


def test_export_text_shapes() -> None:
    class R:
        def __init__(self, body: str) -> None:
            self.text = body

        def json(self) -> Any:
            return json.loads(self.text)

    assert _export_text(R('"plain"')) == "plain"
    assert _export_text(R('[{"ret": "x"}]')) == "x"
    assert _export_text(R('{"a": 1}')) == '{"a": 1}'
    assert _export_text(R("/ip address\nadd")) == "/ip address\nadd"


async def test_simulator_refuses_like_routeros(url: str, sim: MikrotikSimulator) -> None:
    import httpx

    auth = ("signalbox", PASSWORD)
    async with httpx.AsyncClient(base_url=url, auth=auth, trust_env=False) as client:

        async def put(menu: str, body: dict[str, Any]) -> str:
            r = await client.put(menu, json=body)
            assert r.status_code == 400, r.text
            return str(r.json()["detail"])

        assert "missing value for address" in await put(IP_ADDRESS, {"interface": "bridge"})
        assert "interface" in await put(IP_ADDRESS, {"address": "192.0.2.5/24", "interface": "x"})
        assert "address" in await put(IP_ADDRESS, {"address": "nope", "interface": "bridge"})
        assert "already exists" in await put(
            "/rest/interface/vlan", {"name": "iot", "vlan-id": "5", "interface": "bridge"}
        )
        assert "already exists" in await put(
            "/rest/interface/vlan", {"name": "ether2", "vlan-id": "5", "interface": "bridge"}
        )
        assert "vlan-id" in await put(
            "/rest/interface/vlan", {"name": "v", "vlan-id": "x", "interface": "bridge"}
        )
        assert "address-pool" in await put(
            "/rest/ip/dhcp-server", {"name": "d", "interface": "bridge", "address-pool": "x"}
        )
        assert "server" in await put(
            DHCP_LEASE, {"address": "192.0.2.5", "mac-address": "02:00:00:00:00:05", "server": "x"}
        )
        assert "master-interface" in await put(WIFI, {"name": "w", "master-interface": "x"})
        assert "address" in await put("/rest/ip/pool", {"name": "p", "ranges": "a-b"})
        assert "tagged" in await put(
            BRIDGE_VLAN, {"bridge": "bridge", "vlan-ids": "5", "tagged": "x"}
        )
        r = await client.put("/rest/ip/dns", json={})
        assert r.status_code == 400 and r.json()["detail"] == "no such command or directory (dns)"
        r = await client.post("/rest/execute", json={"script": "/system reboot"})
        assert r.status_code == 400
        assert (await client.post("/rest/export", json={})).json() == []
        assert (await client.patch(f"{IP_ADDRESS}/*77", json={})).status_code == 404
        dynamic = sim.data[IP_ADDRESS][2][".id"]
        assert (await client.delete(f"{IP_ADDRESS}/{dynamic}")).status_code == 400
        first = sim.data[IP_ADDRESS][0][".id"]
        r = await client.patch(f"{IP_ADDRESS}/{first}", json={"address": "bad"})
        assert r.status_code == 400
        r = await client.request("PATCH", f"{IP_ADDRESS}/{first}", content=b"{")
        assert r.json()["detail"] == "invalid JSON"
        r = await client.request("PATCH", f"{IP_ADDRESS}/{first}", content=b"[]")
        assert r.json()["detail"] == "expected an object"
        sim.ignore_writes = True
        assert (await client.put(IP_ADDRESS, json={})).json() == {".id": "*FFFF"}
        assert (await client.delete(f"{IP_ADDRESS}/{first}")).json() == []
        sim.ignore_writes = False
        r = await client.put(IP_ADDRESS, json={}, auth=("signalbox", "wrong"))
        assert r.status_code == 401
        sim.rest_enabled = False
        assert (await client.put(IP_ADDRESS, json={})).status_code == 404


# --- a full deployment -----------------------------------------------------------------------

WANT = """
sites:
  home:
    segments:
      - vlan: 20
        name: IoT
        gateway: {device: rt, address: 198.51.100.1/24}
        dhcp: {enabled: true, pool: [198.51.100.50, 198.51.100.99], lease_seconds: 43200}
        reservations:
          - {mac: "02:00:00:00:00:20", address: 198.51.100.21, hostname: sensor}
    ports:
      - {device: rt, port: ether3, untagged: native, tagged: [20]}
    wlans:
      - ssid: Example-IoT
        security: wpa2-wpa3
        segment: 20
        hidden: false
        passphrase_secret: iot-psk
        devices: [rt]
"""


async def test_deployment_and_revert(
    url: str, sim: MikrotikSimulator, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = {"SIGNALBOX_AUTH_PASSWORD": "x" * 12, "SIGNALBOX_DEPLOY_ENABLED": "true"}
    svc = build(
        tmp_path, env=env, adapters={"mikrotik": MikrotikAdapter}, rules=RULES, link_sources=[]
    )
    try:
        svc.store.put_site(SITE)
        rec = DeviceRecord(
            id=DEV,
            site_id="home",
            name="Router",
            role=DeviceRole.GATEWAY,
            adapter="mikrotik",
            allow_writes=True,
        )
        svc.store.put_device(
            rec,
            {"url": url, "password": PASSWORD, "allow_insecure_http": True},
            MikrotikConfig,
        )
        svc.store.set_secret("iot-psk", "the IoT passphrase")
        await svc.runner.observe_all()
        before = view(svc.runner.network())
        desired = parse(WANT)
        p = plan(desired, svc.runner.network(), RULES, secret=svc.store.get_secret)
        kinds = {c.kind for c in p.changes}
        assert kinds == set(ChangeKind), [c.describe() for c in p.changes]
        d = Deployer(svc.runner)
        cid = (await d.prepare(p, "tidy up the IoT network", "tester")).id
        d.approve(cid, "tester", override="test")
        done = await d.deploy(cid)
        assert done.status is ChangeStatus.APPLIED, [(r.status, r.error) for r in done.devices]
        assert all(r.backup_id for r in done.devices)
        assert "the IoT passphrase" not in done.model_dump_json()
        again = plan(desired, svc.runner.network(), RULES, secret=svc.store.get_secret)
        assert again.changes == [], [c.describe() for c in again.changes]
        back = await d.revert(cid, "not needed after all", "tester")
        d.approve(back.id, "tester", override="test")
        reverted = await d.deploy(back.id)
        assert reverted.status is ChangeStatus.APPLIED, [
            (r.status, r.error) for r in reverted.devices
        ]
        await svc.runner.observe_all()
        after = view(svc.runner.network())
        # the passphrase is not known to Signalbox: the revert leaves the new one
        assert unkeyed(after) == unkeyed(before)
        # a deployment that does not take: verified, then rolled back from the backup
        cid = (await d.prepare(p, "again", "tester")).id
        d.approve(cid, "tester", override="test")
        sim.fail_write[WIFI] = 500
        failed = await d.deploy(cid)
        assert failed.status is ChangeStatus.ROLLED_BACK
        assert "refused the change" in (failed.devices[0].error or "")
        await svc.runner.observe_all()
        assert unkeyed(view(svc.runner.network())) == unkeyed(before)
    finally:
        svc.close()
