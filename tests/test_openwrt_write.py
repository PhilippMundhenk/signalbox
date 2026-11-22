"""OpenWrt write side against the ubus simulator: UCI staging, apply with rollback, confirm.

The acceptance test for every change is the read side: after ``apply`` the adapter must report
exactly the change's ``new`` value (``signalbox.deploy.matches``).
"""

from __future__ import annotations

import copy
import json
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from factories import (
    SITE,
    iface,
    ip,
)
from signalbox.adapters import AdapterContext, AdapterError, Backup, WritesConfig
from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.adapters.openwrt.ubus import AccessDenied, NoData
from signalbox.adapters.openwrt.write import (
    BACKUP_FORMAT,
    Configs,
    UciOp,
    lease_text,
    restore_ops,
    translate,
)
from signalbox.changes import (
    Change,
    ChangeKind,
    DhcpValue,
    PortValue,
    ReservationValue,
    RouterValue,
    WlanValue,
    observed_dhcp,
    observed_port,
    observed_wlan,
    plan,
)
from signalbox.deploy import Deployer, current_value, matches
from signalbox.desired import parse
from signalbox.history import ChangeStatus, DeviceStatus
from signalbox.merge import merge
from signalbox.model import DeviceRole, Network, Pmf, Security, passphrase_fingerprint
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.sim.openwrt import OpenWrtSim, create_app, uci_delta, uci_op
from signalbox.sim.server import serve
from signalbox.store import DeviceRecord

SIM = OpenWrtSim()
DEV = "ap1"
NATIVE = "home/segment/native"
SECRETS = {"guest-psk": "a new guest passphrase", "main-psk": "another main passphrase"}


@pytest.fixture(scope="module")
def url() -> Iterator[str]:
    with serve(create_app(SIM)) as base:
        yield base


@pytest.fixture
def sim() -> OpenWrtSim:
    SIM.reset()
    return SIM


def config(url: str) -> OpenWrtConfig:
    return OpenWrtConfig(
        url=f"{url}/ubus", password=SecretStr(OpenWrtSim().password), allow_insecure_http=True
    )


@pytest.fixture
async def adapter(sim: OpenWrtSim, url: str) -> AsyncIterator[OpenWrtAdapter]:
    a = OpenWrtAdapter(
        AdapterContext(
            site_id="home",
            device_id=DEV,
            device_name="AP 1",
            role=DeviceRole.AP,
            config=config(url),
        )
    )
    yield a
    await a.close()


async def network(url: str) -> Network:
    """What a fresh adapter (a new session, as the deployment's verify) reads."""
    a = OpenWrtAdapter(
        AdapterContext(
            site_id="home",
            device_id=DEV,
            device_name="AP 1",
            role=DeviceRole.AP,
            config=config(url),
        )
    )
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert not snap.errors, snap.errors
    return merge([SITE], [snap])


def change(kind: ChangeKind, key: str, old: Any, new: Any) -> Change:
    return Change(kind=kind, device_id=DEV, site_id="home", key=key, old=old, new=new)


async def applied(adapter: OpenWrtAdapter, url: str, *changes: Change) -> Network:
    result = await adapter.apply(list(changes), SECRETS, 60)
    assert result.confirm_deadline is not None and result.calls
    await adapter.confirm()
    net = await network(url)
    for c in changes:
        assert matches(net, c, c.new, SECRETS), (c.describe(), current_value(net, c))
    return net


def committed(sim: OpenWrtSim) -> dict[str, Any]:
    return copy.deepcopy(sim.state)


# --- declared kinds -----------------------------------------------------------------------


def test_manifest_declares_what_it_writes() -> None:
    assert OpenWrtAdapter.manifest.writes == {
        ChangeKind.PORT,
        ChangeKind.WLAN,
        ChangeKind.DHCP,
        ChangeKind.RESERVATION,
    }
    assert issubclass(OpenWrtAdapter, WritesConfig)


# --- PORT ---------------------------------------------------------------------------------


async def test_port_new_vlan_tagged_and_untagged(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str
) -> None:
    net = await network(url)
    pid = f"{DEV}/port/lan2"
    c = change(ChangeKind.PORT, pid, observed_port(net, pid), PortValue(untagged=20, tagged=[30]))
    net = await applied(adapter, url, c)
    vlans = {s["vlan"]: s for _, s in _of(sim, "network", "bridge-vlan")}
    assert vlans["30"]["ports"] == ["lan2:t"] and "lan2:u*" in vlans["20"]["ports"]
    assert "lan2" not in " ".join(vlans["1"]["ports"])
    seg30 = net.segment("home/segment/30")
    assert seg30 is not None and seg30.name is None  # no interface on VLAN 30


async def test_port_leaving_its_last_vlan_removes_the_vlan(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str
) -> None:
    net = await network(url)
    pid = f"{DEV}/port/lan1"
    c = change(ChangeKind.PORT, pid, observed_port(net, pid), PortValue(untagged="native"))
    net = await applied(adapter, url, c)
    assert [s["vlan"] for _, s in _of(sim, "network", "bridge-vlan")] == ["1"]
    assert net.segment("home/segment/20") is None
    assert "iot" in sim.state["network"]  # still used by the IoT SSID: kept


async def test_port_removed_from_everything(adapter: OpenWrtAdapter, url: str) -> None:
    net = await network(url)
    pid = f"{DEV}/port/lan3"
    c = change(ChangeKind.PORT, pid, observed_port(net, pid), None)
    await applied(adapter, url, c)


async def test_port_refusals(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    c = change(ChangeKind.PORT, f"{DEV}/port/eth0", None, PortValue(untagged="native"))
    with pytest.raises(AdapterError, match="eth0 is not a port of a bridge"):
        await adapter.plan_changes([c], {})
    sim.state["network"] = {
        n: s for n, s in sim.state["network"].items() if s[".type"] != "bridge-vlan"
    }
    c = change(ChangeKind.PORT, f"{DEV}/port/lan1", None, PortValue(untagged=20))
    with pytest.raises(AdapterError, match="br-lan has no bridge VLANs"):
        await adapter.plan_changes([c], {})


# --- WLAN ---------------------------------------------------------------------------------


GUEST = WlanValue(
    ssid="Example-Guest",
    security=Security.WPA2_WPA3,
    pmf=Pmf.REQUIRED,
    segment=20,
    roaming_80211r=True,
    roaming_80211k=False,
    roaming_80211v=True,
    passphrase_secret="guest-psk",
)


async def test_wlan_new_ssid_on_every_radio(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str
) -> None:
    c = change(ChangeKind.WLAN, GUEST.ssid, None, GUEST)
    net = await applied(adapter, url, c)
    guest = [w for w in net.wlans if w.ssid == GUEST.ssid]
    assert sorted(w.radio_id for w in guest) == [f"{DEV}/radio/radio0", f"{DEV}/radio/radio1"]
    sections = [s for _, s in _of(sim, "wireless", "wifi-iface") if s.get("ssid") == GUEST.ssid]
    assert all(s["network"] == "iot" and s["key"] == SECRETS["guest-psk"] for s in sections)
    assert all(s["ieee80211w"] == "2" and "hidden" not in s for s in sections)
    assert {c.mac for c in net.clients} >= {"02:00:00:00:20:01"}  # stations still read


async def test_wlan_on_a_vlan_created_in_the_same_change(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str
) -> None:
    net = await network(url)
    pid = f"{DEV}/port/lan1"
    port = change(
        ChangeKind.PORT, pid, observed_port(net, pid), PortValue(untagged="native", tagged=[20, 30])
    )
    wlan = change(
        ChangeKind.WLAN, "Guest", None, GUEST.model_copy(update={"ssid": "Guest", "segment": 30})
    )
    net = await applied(adapter, url, port, wlan)
    assert sim.state["network"]["vlan30"] == {
        ".anonymous": False,
        ".type": "interface",
        "device": "br-lan.30",
        "proto": "none",
    }
    seg = net.segment("home/segment/30")
    assert seg is not None and seg.name == "vlan30"


async def test_wlan_update_and_remove(sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str) -> None:
    net = await network(url)
    old = observed_wlan(net, DEV, "Example")
    assert old is not None
    new = old.model_copy(
        update={
            "security": Security.WPA2,
            "hidden": True,
            "enabled": False,
            "pmf": Pmf.DISABLED,
            "roaming_80211r": False,
            "segment": 20,
            "passphrase_secret": "main-psk",
        }
    )
    iot = observed_wlan(net, DEV, "Example-IoT")
    gone = change(ChangeKind.WLAN, "Example-IoT", iot, None)
    net = await applied(adapter, url, change(ChangeKind.WLAN, "Example", old, new), gone)
    main = sim.state["wireless"]["default_radio0"]
    assert (main["encryption"], main["key"], main["network"]) == (
        "psk2",
        SECRETS["main-psk"],
        "iot",
    )
    assert "iot_radio0" not in sim.state["wireless"]
    assert "isolate" not in main  # not declared: left alone
    isolated = new.model_copy(update={"client_isolation": True})
    net = await applied(adapter, url, change(ChangeKind.WLAN, "Example", new, isolated))
    assert sim.state["wireless"]["default_radio0"]["isolate"] == "1"
    w = observed_wlan(net, DEV, "Example")
    assert w is not None and w.client_isolation is True
    new = isolated
    open_net = new.model_copy(
        update={"security": Security.OPEN, "pmf": None, "passphrase_secret": None, "enabled": True}
    )
    await applied(adapter, url, change(ChangeKind.WLAN, "Example", new, open_net))
    assert "key" not in sim.state["wireless"]["default_radio0"]


@pytest.mark.parametrize(
    ("value", "secrets", "message"),
    [
        (GUEST.model_copy(update={"security": Security.WPA2_ENTERPRISE}), SECRETS, "RADIUS"),
        (GUEST.model_copy(update={"passphrase_secret": None}), SECRETS, "needs a passphrase"),
        (GUEST, {}, "secret 'guest-psk' was not provided"),
        (GUEST.model_copy(update={"segment": 99}), SECRETS, "VLAN 99 is not on any port"),
    ],
)
async def test_wlan_refusals(
    adapter: OpenWrtAdapter, value: WlanValue, secrets: dict[str, str], message: str
) -> None:
    with pytest.raises(AdapterError, match=message):
        await adapter.plan_changes([change(ChangeKind.WLAN, value.ssid, None, value)], secrets)


async def test_wlan_without_radios_or_native_network(
    sim: OpenWrtSim, adapter: OpenWrtAdapter
) -> None:
    sim.state["network"]["lan"]["device"] = "eth0"
    native = GUEST.model_copy(update={"segment": "native"})
    with pytest.raises(AdapterError, match="the untagged network is not on any port"):
        await adapter.plan_changes([change(ChangeKind.WLAN, "x", None, native)], SECRETS)
    sim.state["wireless"] = {}
    with pytest.raises(AdapterError, match="no radios"):
        await adapter.plan_changes([change(ChangeKind.WLAN, "x", None, GUEST)], SECRETS)


# --- DHCP and reservations ----------------------------------------------------------------


async def test_dhcp_switched_on_changed_and_off(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str
) -> None:
    net = await network(url)
    old = observed_dhcp(net, DEV, NATIVE)
    on = DhcpValue(
        enabled=True,
        pool=(ip("192.0.2.150"), ip("192.0.2.199")),
        dns=[ip("192.0.2.53")],
        lease_seconds=1800,
    )
    await applied(adapter, url, change(ChangeKind.DHCP, NATIVE, old, on))
    lan = sim.state["dhcp"]["lan"]
    assert "ignore" not in lan
    assert (lan["start"], lan["limit"], lan["leasetime"]) == ("150", "50", "30m")
    assert lan["dhcp_option"] == ["6,192.0.2.53"]
    off = on.model_copy(update={"enabled": False, "dns": None})
    await applied(adapter, url, change(ChangeKind.DHCP, NATIVE, on, off))
    assert (
        sim.state["dhcp"]["lan"]["ignore"] == "1" and "dhcp_option" not in sim.state["dhcp"]["lan"]
    )


async def test_dhcp_removed_and_created(sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str) -> None:
    net = await network(url)
    old = observed_dhcp(net, DEV, NATIVE)
    await applied(adapter, url, change(ChangeKind.DHCP, NATIVE, old, None))
    assert "lan" not in sim.state["dhcp"]
    new = DhcpValue(enabled=True, pool=(ip("192.0.2.100"), ip("192.0.2.109")), lease_seconds=7)
    await applied(adapter, url, change(ChangeKind.DHCP, NATIVE, None, new))
    assert sim.state["dhcp"]["lan"]["leasetime"] == "7"


async def test_dhcp_router_mode_keeps_other_options(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str
) -> None:
    sim.router = True
    sim.state["dhcp"]["lan"]["dhcp_option"] = ["3,192.0.2.2", "6,192.0.2.1"]
    net = await network(url)
    old = observed_dhcp(net, DEV, NATIVE)
    assert old is not None and old.enabled
    new = old.model_copy(update={"dns": None, "lease_seconds": 2 * 3600})
    await applied(adapter, url, change(ChangeKind.DHCP, NATIVE, old, new))
    assert sim.state["dhcp"]["lan"]["dhcp_option"] == ["3,192.0.2.2"]


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("home/segment/20", DhcpValue(enabled=False), "no interface with an IPv4 address"),
        (NATIVE, DhcpValue(enabled=True), "give the pool"),
        (
            NATIVE,
            DhcpValue(enabled=True, pool=(ip("198.51.100.10"), ip("198.51.100.20"))),
            "not inside 192.0.2.0/24",
        ),
    ],
)
async def test_dhcp_refusals(
    adapter: OpenWrtAdapter, key: str, value: DhcpValue, message: str
) -> None:
    with pytest.raises(AdapterError, match=message):
        await adapter.plan_changes([change(ChangeKind.DHCP, key, None, value)], {})


async def test_reservations(sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str) -> None:
    printer = ReservationValue(
        mac="00:00:5e:00:53:01", address=ip("192.0.2.50"), hostname="printer"
    )
    camera = ReservationValue(mac="02:00:00:00:10:03", address=ip("192.0.2.60"), hostname="camera")
    moved = printer.model_copy(update={"address": ip("192.0.2.51"), "hostname": None})
    await applied(
        adapter,
        url,
        change(ChangeKind.RESERVATION, f"{NATIVE}/{camera.mac}", None, camera),
        change(ChangeKind.RESERVATION, f"{NATIVE}/{printer.mac}", printer, moved),
    )
    assert sim.state["dhcp"]["host_020000001003"]["name"] == "camera"
    assert "name" not in sim.state["dhcp"]["cfg06fe63"]
    await applied(
        adapter, url, change(ChangeKind.RESERVATION, f"{NATIVE}/{printer.mac}", moved, None)
    )
    assert "cfg06fe63" not in sim.state["dhcp"]


async def test_reservation_in_a_host_with_several_macs(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str
) -> None:
    sim.state["dhcp"]["cfg06fe63"]["mac"] = "00:00:5e:00:53:01 02:00:00:00:10:04"
    printer = ReservationValue(
        mac="00:00:5e:00:53:01", address=ip("192.0.2.50"), hostname="printer"
    )
    moved = printer.model_copy(update={"address": ip("192.0.2.52")})
    await applied(
        adapter, url, change(ChangeKind.RESERVATION, f"{NATIVE}/{printer.mac}", printer, moved)
    )
    assert sim.state["dhcp"]["cfg06fe63"]["mac"] == ["02:00:00:00:10:04"]
    sim.state["dhcp"]["cfg06fe63"]["mac"] = ["02:00:00:00:10:04", "00:00:5e:00:53:01"]
    await applied(
        adapter, url, change(ChangeKind.RESERVATION, f"{NATIVE}/{printer.mac}", moved, None)
    )
    assert sim.state["dhcp"]["cfg06fe63"]["mac"] == ["02:00:00:00:10:04"]
    assert "host_020000001001" not in sim.state["dhcp"]


def test_router_changes_are_refused() -> None:
    c = Change(
        kind=ChangeKind.ROUTER,
        device_id=DEV,
        site_id="home",
        key=NATIVE,
        new=RouterValue(address=iface("192.0.2.1/24")),
    )
    empty = {name: {"values": {}} for name in ("network", "wireless", "dhcp")}
    with pytest.raises(AdapterError, match="cannot change router"):
        translate([c], empty, {"interface": []}, "home", {})
    with pytest.raises(AdapterError, match=r"uci\.get \(dhcp\)"):
        translate([], {**empty, "dhcp": {"values": []}}, {"interface": []}, "home", {})


# --- plan, secrets ------------------------------------------------------------------------


async def test_plan_lists_the_uci_calls_and_changes_nothing(
    sim: OpenWrtSim, adapter: OpenWrtAdapter
) -> None:
    before = committed(sim)
    calls = await adapter.plan_changes([change(ChangeKind.WLAN, GUEST.ssid, None, GUEST)], SECRETS)
    assert [(c.method, c.target) for c in calls] == [
        ("uci.add", "wireless.example_guest_radio0"),
        ("uci.add", "wireless.example_guest_radio1"),
    ]
    assert calls[0].payload["values"]["key"] == "***"  # type: ignore[index, call-overload]
    assert calls[0].payload["type"] == "wifi-iface"
    assert SECRETS["guest-psk"] not in json.dumps([c.model_dump() for c in calls])
    assert committed(sim) == before and sim.staged == {} and sim.history == []


async def test_secrets_never_leave_in_calls(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    result = await adapter.apply([change(ChangeKind.WLAN, GUEST.ssid, None, GUEST)], SECRETS, 60)
    assert SECRETS["guest-psk"] not in result.model_dump_json()
    await adapter.confirm()


def test_uci_op_masks_secret_options_only() -> None:
    op = UciOp(
        "set",
        "wireless",
        "x",
        {
            "config": "wireless",
            "section": "x",
            "values": {"key": "s", "sae_password": "t", "ssid": "n"},
        },
        "d",
    )
    assert op.call().payload["values"] == {"key": "***", "sae_password": "***", "ssid": "n"}
    assert op.args["values"]["key"] == "s"  # the call itself still carries it


def test_lease_text() -> None:
    assert [lease_text(s) for s in (7200, 600, 45)] == ["2h", "10m", "45"]


# --- transaction: confirm timer, revert, ACL, session ------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


async def test_not_confirmed_in_time_the_device_rolls_back(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str
) -> None:
    clock = Clock()
    sim.clock = clock
    before = committed(sim)
    c = change(ChangeKind.WLAN, GUEST.ssid, None, GUEST)
    result = await adapter.apply([c], SECRETS, 30)
    assert result.confirm_deadline is not None
    assert 25 < (result.confirm_deadline - datetime.now(UTC)).total_seconds() <= 30
    assert matches(await network(url), c, GUEST, SECRETS)  # applied, waiting
    clock.now += 31
    net = await network(url)
    assert not matches(net, c, GUEST, SECRETS) and committed(sim) == before
    assert sim.history == ["apply", "timeout-rollback"]
    with pytest.raises(AdapterError, match="device rolled the change back"):
        await adapter.confirm()


async def test_confirmed_in_time_stays(sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str) -> None:
    clock = Clock()
    sim.clock = clock
    c = change(ChangeKind.WLAN, GUEST.ssid, None, GUEST)
    await adapter.apply([c], SECRETS, 30)
    clock.now += 29
    await adapter.confirm()
    clock.now += 60
    assert matches(await network(url), c, GUEST, SECRETS)
    assert sim.history == ["apply", "confirm"]


async def test_nothing_to_do_applies_nothing(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str
) -> None:
    net = await network(url)
    pid = f"{DEV}/port/lan1"
    same = change(ChangeKind.PORT, pid, observed_port(net, pid), observed_port(net, pid))
    result = await adapter.apply([same], {}, 30)
    assert result.confirm_deadline is None and result.calls == [] and sim.history == []


@pytest.mark.parametrize(
    ("switch", "named"),
    [
        ({"writable": set()}, r"uci\.add \(network\): the login .* is not allowed"),
        ({"writable": {"network"}}, r"uci\.add \(wireless\)"),
        ({"denied": {"uci.apply"}}, r"uci\.apply"),
    ],
)
async def test_acl_denied_changes_nothing(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str, switch: dict[str, Any], named: str
) -> None:
    for name, value in switch.items():
        setattr(sim, name, value)
    before = committed(sim)
    net = await network(url)
    pid = f"{DEV}/port/lan1"
    port = change(
        ChangeKind.PORT, pid, observed_port(net, pid), PortValue(untagged="native", tagged=[20, 30])
    )
    with pytest.raises(AccessDenied, match=named):
        await adapter.apply([port, change(ChangeKind.WLAN, GUEST.ssid, None, GUEST)], SECRETS, 30)
    assert committed(sim) == before and sim.staged == {}
    assert sim.logins >= 2  # tried once more in a new session before calling it the ACL


async def test_apply_refused_while_another_waits(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str
) -> None:
    c = change(ChangeKind.WLAN, GUEST.ssid, None, GUEST)
    await adapter.apply([c], SECRETS, 30)
    other = OpenWrtAdapter(adapter.context)
    try:
        net = await network(url)
        pid = f"{DEV}/port/lan2"
        port = change(ChangeKind.PORT, pid, observed_port(net, pid), PortValue(untagged=20))
        # rpcd gives the other login the session of the pending apply ("reclaim"): the port
        # change is staged there, the apply is refused, and so is the revert of the staging
        with pytest.raises(AdapterError, match="waits for its confirmation"):
            await other.apply([port], {}, 30)
        assert other.ubus.session == adapter.ubus.session
    finally:
        await other.close()
    await adapter.confirm()
    # the next transaction of the session drops what the other client left staged
    camera = ReservationValue(mac="02:00:00:00:10:03", address=ip("192.0.2.60"))
    await applied(
        adapter, url, change(ChangeKind.RESERVATION, f"{NATIVE}/{camera.mac}", None, camera)
    )
    vlan20 = [s for _, s in _of(sim, "network", "bridge-vlan") if s.get("vlan") == "20"]
    assert vlan20 and all("lan2" not in s["ports"] for s in vlan20)  # the port change never came


async def test_a_pending_apply_is_not_reclaimed_once_its_session_ended(
    sim: OpenWrtSim, adapter: OpenWrtAdapter
) -> None:
    await adapter.apply([change(ChangeKind.WLAN, GUEST.ssid, None, GUEST)], SECRETS, 30)
    sid = adapter.ubus.session
    sim.expire_sessions()  # the applying session ends: the next login gets a new one
    other = OpenWrtAdapter(adapter.context)
    try:
        await other.ubus.login()
        assert other.ubus.session != sid
    finally:
        await other.close()


async def test_session_lost_while_staging_starts_over(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = sim._data
    lost: list[str] = []

    def data(sid: str, obj: str, method: str, args: dict[str, Any]) -> Any:
        if obj == "uci" and method == "add" and not lost:
            lost.append(sid)
            sim.expire_sessions()  # the session ends between two staged operations
            return [6]
        return real(sid, obj, method, args)

    await adapter.read_system()
    monkeypatch.setattr(sim, "_data", data)
    net = await network(url)
    pid = f"{DEV}/port/lan1"
    port = change(
        ChangeKind.PORT, pid, observed_port(net, pid), PortValue(untagged="native", tagged=[20, 30])
    )
    wlan = change(ChangeKind.WLAN, GUEST.ssid, None, GUEST)
    await applied(adapter, url, port, wlan)
    assert lost and lost[0] not in sim.staged
    assert sim.history.count("apply") == 1


async def test_error_before_apply_reverts_the_staging(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = sim._data

    def data(sid: str, obj: str, method: str, args: dict[str, Any]) -> Any:
        if obj == "uci" and method == "add":
            return [2]  # invalid argument
        return real(sid, obj, method, args)

    monkeypatch.setattr(sim, "_data", data)
    before = committed(sim)
    with pytest.raises(AdapterError, match="invalid argument"):
        await adapter.apply([change(ChangeKind.WLAN, GUEST.ssid, None, GUEST)], SECRETS, 30)
    assert committed(sim) == before and sim.staged == {} and sim.history == ["revert wireless"]


# --- backup and restore -------------------------------------------------------------------


def _of(sim: OpenWrtSim, config: str, kind: str) -> list[tuple[str, dict[str, Any]]]:
    return [(n, s) for n, s in sim.state[config].items() if s[".type"] == kind]


def _plain(state: dict[str, Any]) -> dict[str, Any]:
    """Configs without the anonymous flag (a restored anonymous section comes back named)."""
    return {
        c: {n: {k: v for k, v in s.items() if k != ".anonymous"} for n, s in secs.items()}
        for c, secs in state.items()
    }


async def test_backup_and_restore_round_trip(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str
) -> None:
    before = committed(sim)
    backup = await adapter.backup()
    assert backup.format == BACKUP_FORMAT and backup.device_id == DEV
    assert set(json.loads(backup.content)) == {"network", "wireless", "dhcp"}
    net = await network(url)
    pid = f"{DEV}/port/lan1"
    printer = ReservationValue(
        mac="00:00:5e:00:53:01", address=ip("192.0.2.50"), hostname="printer"
    )
    await applied(
        adapter,
        url,
        change(ChangeKind.PORT, pid, observed_port(net, pid), PortValue(untagged=20, tagged=[30])),
        change(ChangeKind.WLAN, "Example-IoT", observed_wlan(net, DEV, "Example-IoT"), None),
        change(ChangeKind.WLAN, GUEST.ssid, None, GUEST.model_copy(update={"segment": 30})),
        change(ChangeKind.RESERVATION, f"{NATIVE}/{printer.mac}", printer, None),
    )
    sim.state["network"]["lan"]["mtu"] = "1400"  # an option the backup does not have
    sim.state["dhcp"]["cfg06fe63"] = {".anonymous": True, ".type": "domain", "name": "x"}
    assert _plain(committed(sim)) != _plain(before)
    await adapter.restore(backup)
    assert _plain(committed(sim)) == _plain(before)
    assert list(sim.state["wireless"]) == list(before["wireless"])  # order too
    assert sim.pending is None and sim.history[-1] == "apply"
    await adapter.restore(backup)  # nothing left to do: no apply
    assert sim.history.count("apply") == 2


async def test_restore_while_our_change_waits_rolls_it_back(
    sim: OpenWrtSim, adapter: OpenWrtAdapter
) -> None:
    before = committed(sim)
    backup = await adapter.backup()
    await adapter.apply([change(ChangeKind.WLAN, GUEST.ssid, None, GUEST)], SECRETS, 30)
    await adapter.restore(backup)
    assert committed(sim) == before and sim.pending is None
    # rpcd put the rolled back changes into the session again; they are dropped before restoring
    assert sim.history == ["apply", "rollback", "revert wireless"] and sim.staged == {}


@pytest.mark.parametrize(
    ("fmt", "content", "message"),
    [
        ("fake-json", "{}", "not an OpenWrt backup"),
        (BACKUP_FORMAT, "{", "not valid JSON"),
        (BACKUP_FORMAT, '{"firewall": {}}', "does not hold UCI configs"),
        (BACKUP_FORMAT, "[]", "does not hold UCI configs"),
    ],
)
async def test_restore_refuses_other_content(
    adapter: OpenWrtAdapter, fmt: str, content: str, message: str
) -> None:
    backup = Backup(device_id=DEV, taken_at=datetime.now(UTC), format=fmt, content=content)
    with pytest.raises(AdapterError, match=message):
        await adapter.restore(backup)


async def test_backup_of_an_odd_answer(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = sim._data
    monkeypatch.setattr(
        sim,
        "_data",
        lambda sid, obj, m, a: [0, {"values": []}] if obj == "uci" else real(sid, obj, m, a),
    )
    with pytest.raises(AdapterError, match=r"uci\.get"):
        await adapter.backup()


def test_restore_ops_type_change_and_order() -> None:
    current = {"network": {"a": {".type": "x", ".index": 0}, "b": {".type": "y", ".index": 1}}}
    saved = {"network": {"b": {".type": "y", ".index": 0}, "a": {".type": "z", ".index": 1}}}
    ops = restore_ops(saved, current)
    assert [(o.method, o.section) for o in ops] == [("delete", "a"), ("add", "a")]
    saved["network"]["a"][".type"] = "x"
    [op] = restore_ops(saved, current)
    assert (op.method, op.args["sections"]) == ("order", ["b", "a"])


def test_translate_from_configuration_alone() -> None:
    """No running interface yet: the static address of the UCI interface is used."""

    def uci(*sections: tuple[str, str, dict[str, Any]]) -> dict[str, Any]:
        return {
            "values": {
                n: {".type": t, ".name": n, ".index": i, **o}
                for i, (t, n, o) in enumerate(sections)
            }
        }

    data = {
        "network": uci(
            ("device", "br", {"type": "bridge", "name": "br-lan", "ports": ["lan1"]}),
            ("device", "br2", {"type": "bridge", "name": "br-x", "ports": ["lan9"]}),
            ("bridge-vlan", "v1", {"device": "br-lan", "vlan": "1", "ports": ["lan1:u*"]}),
            ("bridge-vlan", "vx", {"device": "br-lan", "vlan": "x", "ports": ["lan1"]}),
            ("bridge-vlan", "v9", {"device": "br-x", "vlan": "9", "ports": ["lan9"]}),
            (
                "interface",
                "lan",
                {
                    "device": "br-lan.1",
                    "ipaddr": ["bad", "2001:db8::1/64", "192.0.2.2"],
                    "netmask": "255.255.255.0",
                },
            ),
            ("interface", "nope", {"device": "br-lan.1", "ipaddr": "bad"}),
        ),
        "wireless": uci(),
        "dhcp": uci(),
    }
    dhcp = DhcpValue(enabled=True, pool=(ip("192.0.2.10"), ip("192.0.2.19")))
    port = PortValue(untagged="native", tagged=[5])
    cfg = translate(
        [
            Change(kind=ChangeKind.DHCP, device_id=DEV, site_id="home", key=NATIVE, new=dhcp),
            Change(
                kind=ChangeKind.PORT,
                device_id=DEV,
                site_id="home",
                key=f"{DEV}/port/lan1",
                new=port,
            ),
        ],
        data,
        {"interface": []},
        "home",
        {},
    )
    assert cfg.values("dhcp")["lan"]["start"] == "10" and cfg.values("dhcp")["lan"]["limit"] == "10"
    assert cfg.values("network")["br_lan_5"]["ports"] == ["lan1:t"]
    assert cfg.values("network")["v9"]["ports"] == ["lan9"]  # another bridge: untouched


def test_configs_add_picks_a_free_name() -> None:
    cfg = Configs({"network": {"values": {"x": {".type": "interface", ".index": "odd"}}}})
    assert cfg.add("network", "interface", "x", {}, "") == "x_2"
    assert cfg.values("network")["x_2"][".index"] == 1


# --- simulator details --------------------------------------------------------------------


def test_simulator_uci_operations() -> None:
    config: dict[str, Any] = {"s": {".type": "t", "a": "1"}}
    assert uci_op(config, "add", {"type": ""}, 1) == [2]
    assert uci_op(config, "add", {"type": "u", "name": "s"}, 1) == [0, {"section": "s"}]
    assert config["s"] == {".type": "u", "a": "1"}  # rpcd: an existing name only changes type
    assert uci_op(config, "add", {"type": "t", "values": {"on": True, "n": 3}}, 1) == [
        0,
        {"section": "cfg000001"},
    ]
    assert config["cfg000001"] == {".anonymous": True, ".type": "t", "on": "1", "n": "3"}
    assert uci_op(config, "set", {"section": "nope", "values": {}}, 0) == [4]
    assert uci_op(config, "set", {"section": "s", "values": "x"}, 0) == [2]
    assert uci_op(config, "order", {"sections": ["s", "nope"]}, 0) == [4]
    assert uci_op(config, "delete", {"section": "s", "options": ["x"]}, 0) == [4]
    assert uci_op(config, "delete", {"section": "s", "option": "x"}, 0) == [4]
    assert uci_op(config, "delete", {"section": "s", "option": "a"}, 0) == [0]
    assert config["s"] == {".type": "u"}


async def test_simulator_uci_reads_and_odd_calls(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    ubus = adapter.ubus
    lan = await ubus.call("uci", "get", {"config": "network", "section": "lan"})
    assert lan["values"]["device"] == "br-lan.1"
    with pytest.raises(AdapterError, match="not found"):
        await ubus.call("uci", "get", {"config": "network", "section": "nope"})
    with pytest.raises(AdapterError, match="not found"):
        await ubus.call("uci", "set", {"config": "firewall", "section": "x", "values": {}})
    await ubus.call("uci", "set", {"config": "network", "section": "lan", "values": {"mtu": 1400}})
    changes = await ubus.call("uci", "changes", {})
    assert changes["changes"]["network"][0][0] == "set"
    lan = await ubus.call("uci", "get", {"config": "network", "section": "lan"})
    assert lan["values"]["mtu"] == "1400"  # the session sees its staging
    assert "mtu" not in sim.state["network"]["lan"]  # nobody else does
    with pytest.raises(AdapterError, match="no data"):
        await OpenWrtAdapter(adapter.context).ubus.call("uci", "apply", {})
    with pytest.raises(AdapterError, match="not found"):
        await ubus.call("uci", "rename", {"config": "network"})
    await ubus.call("uci", "apply", {})  # without rollback: committed at once
    assert sim.state["network"]["lan"]["mtu"] == "1400" and sim.pending is None
    with pytest.raises(NoData):
        await ubus.call("uci", "rollback", {}, keep_session=True)


async def test_simulator_disabled_radio_runs_nothing(sim: OpenWrtSim, url: str) -> None:
    sim.state["wireless"]["radio1"]["disabled"] = "1"
    net = await network(url)
    radio1 = next(r for r in net.radios if r.name == "radio1")
    assert not radio1.enabled
    assert {c.seen_on for c in net.clients if c.seen_on} == {
        f"{DEV}/wlan/default_radio0",
        f"{DEV}/wlan/iot_radio0",
    }


# --- a whole deployment ----------------------------------------------------------------------

ENV = {"SIGNALBOX_AUTH_PASSWORD": "x" * 12, "SIGNALBOX_DEPLOY_ENABLED": "true"}
WANT = """
sites:
  home:
    segments:
      - {vlan: 30, name: guest}
    wlans:
      - ssid: Example-Guest
        security: wpa2-wpa3
        segment: 30
        passphrase_secret: guest-psk
        devices: [ap1]
        roaming: {r: true, k: true, v: true}
    ports:
      - {device: ap1, port: lan1, untagged: native, tagged: [20, 30]}
"""


@pytest.fixture
def svc(sim: OpenWrtSim, url: str, tmp_path: Path) -> Iterator[Services]:
    s = build(tmp_path, env=ENV, adapters={"openwrt": OpenWrtAdapter}, rules=RULES, link_sources=[])
    s.store.put_site(SITE)
    rec = DeviceRecord(
        id=DEV,
        site_id="home",
        name="AP 1",
        role=DeviceRole.AP,
        adapter="openwrt",
        allow_writes=True,
    )
    values = {"url": f"{url}/ubus", "password": OpenWrtSim().password, "allow_insecure_http": True}
    s.store.put_device(rec, values, OpenWrtConfig)
    s.store.set_secret("guest-psk", SECRETS["guest-psk"])
    yield s
    s.close()


async def test_deployment_adds_a_vlan_and_an_ssid_then_reverts(
    sim: OpenWrtSim, svc: Services
) -> None:
    before = committed(sim)
    await svc.runner.observe_all()
    p = plan(parse(WANT), svc.runner.network(), RULES, secret=svc.store.get_secret)
    assert [c.kind for c in p.changes] == [ChangeKind.PORT, ChangeKind.WLAN]
    d = Deployer(svc.runner)
    rec = await d.prepare(p, "guest network", "tester")
    [calls] = [r.calls for r in rec.devices]
    assert [(c.method, c.target) for c in calls] == [
        ("uci.add", "network.br_lan_30"),
        ("uci.add", "network.vlan30"),
        ("uci.add", "wireless.example_guest_radio0"),
        ("uci.add", "wireless.example_guest_radio1"),
    ]
    assert SECRETS["guest-psk"] not in rec.model_dump_json()
    override = "lab" if rec.plan.blocking else None
    d.approve(rec.id, "tester", override=override)
    done = await d.deploy(rec.id)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    assert done.devices[0].status is DeviceStatus.CONFIRMED
    assert sim.history == ["apply", "confirm"] and sim.pending is None
    assert "Example-Guest" in {s.get("ssid") for s in sim.state["wireless"].values()}
    again = plan(parse(WANT), svc.runner.network(), RULES, secret=svc.store.get_secret)
    assert again.changes == []
    back = await d.revert(rec.id, "guest network not needed", "tester")
    d.approve(back.id, "tester", override="lab" if back.plan.blocking else None)
    undone = await d.deploy(back.id)
    assert undone.status is ChangeStatus.APPLIED, [r.error for r in undone.devices]
    assert committed(sim) == before


async def test_revert_restores_the_replaced_passphrase(sim: OpenWrtSim, svc: Services) -> None:
    # #188: the secret held the AP's passphrase before it was replaced, so a revert knows it
    svc.store.set_secret("main-psk", "example-passphrase")
    svc.store.set_secret("main-psk", SECRETS["main-psk"])
    want = """
sites:
  home:
    wlans:
      - {ssid: Example, security: wpa2-wpa3, passphrase_secret: main-psk, devices: [ap1]}
"""
    before = committed(sim)
    await svc.runner.observe_all()

    def fingerprints() -> set[str | None]:
        net = svc.runner.network()
        return {w.passphrase_fingerprint for w in net.wlans if w.ssid == "Example"}

    original = fingerprints()
    assert original == {passphrase_fingerprint("Example", "example-passphrase")}
    p = plan(parse(want), svc.runner.network(), RULES, secret=svc.store.get_secret)
    assert [c.kind for c in p.changes] == [ChangeKind.WLAN]
    d = Deployer(svc.runner)
    rec = await d.prepare(p, "new passphrase", "tester")
    d.approve(rec.id, "tester", override="lab" if rec.plan.blocking else None)
    done = await d.deploy(rec.id)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    assert fingerprints() == {passphrase_fingerprint("Example", SECRETS["main-psk"])}
    back = await d.revert(rec.id, "back to the old passphrase", "tester")
    d.approve(back.id, "tester", override="lab" if back.plan.blocking else None)
    undone = await d.deploy(back.id)
    assert undone.status is ChangeStatus.APPLIED, [r.error for r in undone.devices]
    assert committed(sim) == before
    await svc.runner.observe_all()
    assert fingerprints() == original


async def test_deployment_that_fails_verification_is_restored(
    sim: OpenWrtSim, svc: Services, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = committed(sim)
    await svc.runner.observe_all()
    p = plan(parse(WANT), svc.runner.network(), RULES, secret=svc.store.get_secret)
    d = Deployer(svc.runner)
    rec = await d.prepare(p, "guest network", "tester")
    d.approve(rec.id, "tester", override="lab")
    real = sim._data

    def data(sid: str, obj: str, method: str, args: dict[str, Any]) -> Any:
        if obj == "uci" and method == "add" and args.get("type") == "wifi-iface":
            args = {**args, "values": {**args["values"], "hidden": "1"}}  # the device differs
        return real(sid, obj, method, args)

    monkeypatch.setattr(sim, "_data", data)
    done = await d.deploy(rec.id)
    assert done.status is ChangeStatus.ROLLED_BACK
    assert "not applied as planned" in (done.devices[0].error or "")
    assert committed(sim) == before and sim.history[:2] == ["apply", "rollback"]


# --- rpcd details confirmed against its source (rpcd uci.c) and the real device (#137) ------


async def test_rolled_back_changes_come_back_staged_and_are_dropped(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, url: str
) -> None:
    clock = Clock()
    sim.clock = clock
    await adapter.apply([change(ChangeKind.WLAN, GUEST.ssid, None, GUEST)], SECRETS, 30)
    clock.now += 31
    await network(url)  # the timer runs out
    assert sim.history == ["apply", "timeout-rollback"]
    assert set(sim.staged[adapter.ubus.session or ""]) == {"wireless"}  # rpcd restores the delta
    camera = ReservationValue(mac="02:00:00:00:10:03", address=ip("192.0.2.60"))
    key = f"{NATIVE}/{camera.mac}"
    await applied(adapter, url, change(ChangeKind.RESERVATION, key, None, camera))
    assert GUEST.ssid not in {s.get("ssid") for s in sim.state["wireless"].values()}


async def test_restore_while_another_change_waits_is_reported(
    sim: OpenWrtSim, adapter: OpenWrtAdapter
) -> None:
    backup = await adapter.backup()
    other = OpenWrtAdapter(adapter.context)
    try:
        await other.apply([change(ChangeKind.WLAN, GUEST.ssid, None, GUEST)], SECRETS, 30)
        with pytest.raises(AdapterError, match="backup was not applied"):
            await adapter.restore(backup)
        await other.confirm()
    finally:
        await other.close()
    assert GUEST.ssid in {s.get("ssid") for s in sim.state["wireless"].values()}


@pytest.mark.parametrize(
    ("answer", "found"),
    [({"neighbors": None}, None), ({"neighbors": {"lldp": ["odd", {}]}}, 0)],
)
async def test_lldpd_status_shapes(
    sim: OpenWrtSim,
    adapter: OpenWrtAdapter,
    monkeypatch: pytest.MonkeyPatch,
    answer: dict[str, Any],
    found: int | None,
) -> None:
    real = sim._data

    def data(sid: str, obj: str, method: str, args: dict[str, Any]) -> Any:
        return [0, answer] if obj == "luci.lldpd" else real(sid, obj, method, args)

    monkeypatch.setattr(sim, "_data", data)
    snap = await adapter.observe()
    if found is None:
        assert [e.message for e in snap.errors] == [
            "lldpd is installed but not running (luci.lldpd getStatus has no neighbours)"
        ]
    else:
        assert not snap.errors and len(snap.neighbours) == found


def test_simulator_lists_changes_like_rpcd() -> None:
    add = {"config": "c", "type": "host", "name": "h", "values": {"ip": "1", "mac": ["a", "b"]}}
    assert uci_delta("add", add) == [
        ["add", "h", "host"],
        ["set", "h", "ip", "1"],
        ["remove", "h", "mac"],
        ["list-add", "h", "mac", "a"],
        ["list-add", "h", "mac", "b"],
    ]
    assert uci_delta("delete", {"section": "h"}) == [["remove", "h"]]
    assert uci_delta("delete", {"section": "h", "option": "ip"}) == [["remove", "h", "ip"]]
    assert uci_delta("order", {"sections": ["a", "b"]}) == [["order", "a", 0], ["order", "b", 1]]
