"""Omada write side (issue #44): changes through the controller, against the simulator."""

from __future__ import annotations

import copy
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from ipaddress import ip_address, ip_interface
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from factories import SITE
from signalbox.adapters import AdapterContext, AdapterError, AuthFailed, Backup
from signalbox.adapters.omada import OmadaAdapter, OmadaConfig
from signalbox.adapters.omada.writes import Writer
from signalbox.changes import (
    Change,
    ChangeKind,
    DhcpValue,
    PortValue,
    RouterValue,
    WlanValue,
    make_plan,
    observed_dhcp,
    observed_port,
    observed_router,
    observed_wlan,
    plan,
)
from signalbox.deploy import Deployer, matches
from signalbox.desired import parse
from signalbox.history import ChangeStatus
from signalbox.merge import merge
from signalbox.model import DeviceRole, Network, Pmf, Security, passphrase_fingerprint
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.sim.omada import CLIENT_ID, CLIENT_SECRET, SWITCH, OmadaSimulator
from signalbox.sim.omada import SITE as SITE_PATH
from signalbox.sim.server import serve
from signalbox.store import DeviceRecord

SIM = OmadaSimulator()
DEV = "omada1"
SW = f"{DEV}/switch-020000000b01"
AP1 = f"{DEV}/eap-020000000c01"
AP2 = f"{DEV}/eap-020000000c02"
GW = f"{DEV}/gateway-020000000a01"
NETS = f"{SITE_PATH}/lan-networks"
SSIDS = f"{SITE_PATH}/wireless-network/wlans/wlan-default/ssids"
PORTS = f"{SITE_PATH}/switches/{SWITCH}/ports"
SECRETS = {"psk": "a new passphrase"}
ENV = {"SIGNALBOX_AUTH_PASSWORD": "x" * 12, "SIGNALBOX_DEPLOY_ENABLED": "true"}


@pytest.fixture(scope="module")
def url() -> Iterator[str]:
    with serve(SIM.app()) as base:
        yield base


@pytest.fixture(autouse=True)
def sim() -> OmadaSimulator:
    SIM.__dict__.update(OmadaSimulator().__dict__)
    return SIM


def adapter(url: str) -> OmadaAdapter:
    config = OmadaConfig(
        url=url,
        client_id=CLIENT_ID,
        client_secret=SecretStr(CLIENT_SECRET),
        allow_insecure_http=True,
    )
    return OmadaAdapter(
        AdapterContext(
            site_id="home",
            device_id=DEV,
            device_name="Omada",
            role=DeviceRole.OTHER,
            config=config,
            timeout=5.0,
        )
    )


async def network(url: str) -> Network:
    a = adapter(url)
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status.value == "ok", snap.errors
    return merge([SITE], [snap])


async def apply(url: str, changes: list[Change], secrets: dict[str, str] = SECRETS) -> list[Any]:
    a = adapter(url)
    try:
        result = await a.apply(changes, secrets, 60)
    finally:
        await a.close()
    assert result.confirm_deadline is None
    return result.calls


async def round_trip(url: str, changes: list[Change], secrets: dict[str, str] = SECRETS) -> None:
    """apply → the read side shows the new values; the inverse → the old ones."""
    await apply(url, changes, secrets)
    after = await network(url)
    assert [c.id for c in changes if not matches(after, c, c.new, secrets)] == []
    inverse = [c.inverse() for c in reversed(changes)]
    await apply(url, inverse, secrets)
    back = await network(url)
    assert [c.id for c in inverse if not matches(back, c, c.new, secrets)] == []


def change(kind: ChangeKind, dev: str, key: str, old: Any, new: Any) -> Change:
    return Change(kind=kind, device_id=dev, site_id="home", key=key, old=old, new=new)


def wlan(net: Network, dev: str, ssid: str, new: WlanValue | None) -> Change:
    return change(ChangeKind.WLAN, dev, ssid, observed_wlan(net, dev, ssid), new)


def port(net: Network, n: int, untagged: Any, tagged: list[int]) -> Change:
    pid = f"{SW}/port/{n}"
    return change(
        ChangeKind.PORT,
        SW,
        pid,
        observed_port(net, pid),
        PortValue(untagged=untagged, tagged=tagged),
    )


def router(net: Network, vlan: int | None, new: RouterValue | None) -> Change:
    key = f"home/segment/{vlan or 'native'}"
    return change(ChangeKind.ROUTER, GW, key, observed_router(net, GW, key), new)


def dhcp(net: Network, vlan: int | None, new: DhcpValue | None) -> Change:
    key = f"home/segment/{vlan or 'native'}"
    return change(ChangeKind.DHCP, GW, key, observed_dhcp(net, GW, key), new)


def iface(text: str) -> Any:
    return ip_interface(text)


def ip(text: str) -> Any:
    return ip_address(text)


# --- WLAN ------------------------------------------------------------------------------------


async def test_create_ssid_reaches_the_whole_wlan_group(url: str, sim: OmadaSimulator) -> None:
    net = await network(url)
    new = WlanValue(
        ssid="Office",
        security=Security.WPA2_WPA3,
        pmf=Pmf.REQUIRED,
        segment=20,
        passphrase_secret="psk",
    )
    c = wlan(net, AP1, "Office", new)
    await round_trip(url, [c])
    posted = [w for w in sim.writes if w[0] == "POST"]
    assert posted[0][2]["pskSetting"] == {
        "versionPsk": 4,  # WPA2-PSK/WPA3-SAE
        "encryptionPsk": 3,
        "gikRekeyPskEnable": False,
        "securityKey": "a new passphrase",
    }
    assert posted[0][2]["band"] == 3 and posted[0][2]["vlanId"] == 20
    assert (posted[0][2]["pmfMode"], posted[0][2]["deviceType"]) == (1, 1)
    # the second EAP of the group saw it too, while it existed
    await apply(url, [c])
    assert matches(await network(url), wlan(net, AP2, "Office", new), new, SECRETS)


async def test_update_ssid_and_back(url: str, sim: OmadaSimulator) -> None:
    net = await network(url)
    old = observed_wlan(net, AP1, "Home")
    assert old is not None
    new = old.model_copy(
        update={
            "security": Security.WPA2_WPA3,
            "hidden": True,
            "segment": 20,
            "pmf": Pmf.REQUIRED,
            "passphrase_secret": "psk",
        }
    )
    await round_trip(url, [wlan(net, AP1, "Home", new)])
    home = next(s for s in sim.data[SSIDS] if s["name"] == "Home")
    assert home["pskSetting"]["versionPsk"] == 2 and "vlanId" not in home
    # the inverse has no passphrase: the one set on the way stays
    assert home["pskSetting"]["securityKey"] == "a new passphrase"
    paths = [p for m, p, _ in sim.writes]
    assert all(p.endswith("/update-basic-config") for p in paths), paths
    # disabled (a call of its own) and without PMF
    off = old.model_copy(update={"pmf": None, "enabled": False})
    await round_trip(url, [wlan(net, AP1, "Home", off)])
    assert any(p.endswith("/wireless-network/ssids/ssid-home/enable") for _, p, _ in sim.writes)
    # open: the passphrase is gone with it, back to WPA2 needs a new one
    plain = old.model_copy(update={"security": Security.OPEN, "pmf": None})
    await apply(url, [wlan(net, AP1, "Home", plain)])
    home = next(s for s in sim.data[SSIDS] if s["name"] == "Home")
    assert home["security"] == 0 and "pskSetting" not in home
    back = wlan(await network(url), AP1, "Home", old)
    with pytest.raises(AdapterError, match="needs a passphrase"):
        await apply(url, [back])
    await apply(
        url, [back.model_copy(update={"new": old.model_copy(update={"passphrase_secret": "psk"})})]
    )


async def test_delete_ssid_and_recreate(url: str) -> None:
    net = await network(url)
    await round_trip(url, [wlan(net, AP2, "Guest", None)])
    again = await network(url)
    assert observed_wlan(again, AP1, "Guest") == observed_wlan(net, AP1, "Guest")
    gone = WlanValue(ssid="Missing", security=Security.OPEN)
    await apply(url, [change(ChangeKind.WLAN, AP2, "Missing", gone, None)])  # nothing to do


async def test_plan_shows_no_secret_and_names_the_group(url: str, sim: OmadaSimulator) -> None:
    net = await network(url)
    new = WlanValue(ssid="Office", security=Security.WPA2, passphrase_secret="psk")
    a = adapter(url)
    try:
        calls = await a.plan_changes([wlan(net, AP1, "Office", new)], SECRETS)
        backup = await a.backup()
    finally:
        await a.close()
    assert len(calls) == 1 and calls[0].method == "POST" and calls[0].target == SSIDS
    assert calls[0].payload["pskSetting"] == {
        "versionPsk": 2,
        "encryptionPsk": 3,
        "gikRekeyPskEnable": False,
        "securityKey": "***",
    }
    assert "a new passphrase" not in json.dumps([c.model_dump() for c in calls])
    assert "WLAN group Default (EAPs AP 1, AP 2)" in calls[0].description
    assert not sim.writes  # planning and backing up write nothing
    assert backup.format == "omada-openapi-json"


@pytest.mark.parametrize(
    ("update", "secrets", "message"),
    [
        ({"security": Security.WPA2_ENTERPRISE}, SECRETS, "cannot set wpa2-enterprise"),
        ({"security": Security.WPA3}, SECRETS, "WPA3 only together with WPA2"),
        ({"security": Security.OWE}, SECRETS, "does not report OWE back"),
        ({"roaming_80211r": True}, SECRETS, "fast roaming"),
        ({"client_isolation": True}, SECRETS, "client isolation is not read or changed"),
        ({"passphrase_secret": "other"}, SECRETS, "secret 'other' was not provided"),
        ({"passphrase_secret": "psk"}, {"psk": "short"}, "8 to 63 characters"),
        ({"passphrase_secret": None}, SECRETS, "needs a passphrase"),
        ({"segment": 99}, SECRETS, "no LAN network for VLAN 99"),
    ],
)
async def test_wlan_refusals(
    url: str, update: dict[str, Any], secrets: dict[str, str], message: str
) -> None:
    net = await network(url)
    base = WlanValue(ssid="Office", security=Security.WPA2, passphrase_secret="psk")
    with pytest.raises(AdapterError, match=message) as info:
        await apply(url, [wlan(net, AP1, "Office", base.model_copy(update=update))], secrets)
    assert "a new passphrase" not in str(info.value)


async def test_ssid_from_open_to_wpa_needs_a_passphrase(url: str) -> None:
    net = await network(url)
    old = observed_wlan(net, AP1, "Guest")
    assert old is not None
    with pytest.raises(AdapterError, match="needs a passphrase"):
        await apply(
            url, [wlan(net, AP1, "Guest", old.model_copy(update={"security": Security.WPA2}))]
        )


# --- ports -----------------------------------------------------------------------------------


async def test_port_override_and_back_to_a_profile(url: str, sim: OmadaSimulator) -> None:
    net = await network(url)
    c = port(net, 5, 20, [30])
    await apply(url, [c])
    row = next(r for r in sim.data[PORTS] if r["port"] == 5)
    assert row["profileOverrideEnable"] is True and row["nativeNetworkId"] == "net-iot"
    assert matches(await network(url), c, c.new, {})
    await apply(url, [c.inverse()])
    row = next(r for r in sim.data[PORTS] if r["port"] == 5)
    assert (row["profileId"], row["profileOverrideEnable"]) == ("prof-lan", False)
    assert matches(await network(url), c, c.old, {})


async def test_port_change_that_matches_a_profile(url: str, sim: OmadaSimulator) -> None:
    net = await network(url)
    a = adapter(url)
    try:
        calls = await a.plan_changes([port(net, 8, "native", [20, 30])], {})
    finally:
        await a.close()
    assert "(profile All)" in calls[0].description
    await round_trip(url, [port(net, 8, "native", [20, 30]), port(net, 7, 30, [20])])


async def test_port_refusals_and_plan_placeholders(url: str) -> None:
    net = await network(url)
    with pytest.raises(AdapterError, match="always has a native"):
        await apply(url, [port(net, 3, None, [20])])
    with pytest.raises(AdapterError, match="cannot be sent tagged"):
        await apply(url, [port(net, 3, 20, [1])])
    with pytest.raises(AdapterError, match="both untagged and tagged"):
        await apply(url, [port(net, 3, 20, [20])])
    with pytest.raises(AdapterError, match="no LAN network for VLAN 40"):
        await apply(url, [port(net, 3, 40, [])])
    bad = port(net, 3, 20, []).model_copy(update={"key": f"{SW}/port/99"})
    with pytest.raises(AdapterError, match="has no port 99"):
        await apply(url, [bad])
    a = adapter(url)
    try:  # for the review, a network made earlier in the same change is named instead
        calls = await a.plan_changes([port(net, 3, 40, [])], {})
    finally:
        await a.close()
    assert calls[0].payload["nativeNetworkId"] == "<network of VLAN 40>"


# --- LAN networks and DHCP ---------------------------------------------------------------------


async def test_create_network_with_dhcp_and_remove_it(url: str, sim: OmadaSimulator) -> None:
    net = await network(url)
    changes = [
        router(net, 40, RouterValue(vlan=40, name="Lab", address=iface("203.0.113.1/24"))),
        dhcp(
            net,
            40,
            DhcpValue(
                enabled=True,
                pool=(ip("203.0.113.100"), ip("203.0.113.199")),
                dns=[ip("203.0.113.1")],
                lease_seconds=3600,
            ),
        ),
    ]
    await round_trip(url, changes)
    assert [w[0] for w in sim.writes] == ["POST", "DELETE"]
    assert sim.writes[0][2]["dhcpSettingsVO"]["dhcpns"] == "auto"
    assert [n["id"] for n in sim.data[NETS]] == ["net-lan", "net-iot", "net-guest"]


async def test_update_network_and_dhcp_and_back(url: str, sim: OmadaSimulator) -> None:
    net = await network(url)
    changes = [
        router(net, 20, RouterValue(vlan=20, name="Things", address=iface("198.51.100.254/24"))),
        dhcp(
            net,
            20,
            DhcpValue(enabled=False, pool=(ip("198.51.100.10"), ip("198.51.100.20")), dns=None),
        ),
    ]
    await round_trip(url, changes)
    # the router alone; the DHCP router address follows it
    lan = router(net, None, RouterValue(name="LAN", address=iface("192.0.2.254/24")))
    await apply(url, [lan])
    row = next(n for n in sim.data[NETS] if n["id"] == "net-lan")
    assert row["dhcpSettingsVO"]["gateway"] == "192.0.2.254"
    assert matches(await network(url), lan, lan.new, {})


async def test_router_on_a_vlan_only_network_and_back(url: str, sim: OmadaSimulator) -> None:
    net = await network(url)
    c = router(net, 30, RouterValue(vlan=30, name="Guest", address=iface("203.0.113.1/24")))
    await round_trip(url, [c])
    guest = next(n for n in sim.data[NETS] if n["id"] == "net-guest")
    assert (guest["name"], guest["purpose"], guest["vlan"]) == ("Guest", 0, 30)
    assert "gatewaySubnet" not in guest and "dhcpSettingsVO" not in guest


async def test_dhcp_removal_and_back(url: str) -> None:
    net = await network(url)
    await round_trip(url, [dhcp(net, 20, None)])


@pytest.mark.parametrize(
    ("make", "message"),
    [
        (lambda n: router(n, None, None), "native network cannot be removed"),
        (lambda n: router(n, 40, RouterValue(vlan=40, address=iface("203.0.113.1/24"))), "name"),
        (lambda n: dhcp(n, 40, DhcpValue(enabled=True)), "no LAN network for VLAN 40"),
        (lambda n: dhcp(n, 30, DhcpValue(enabled=True)), "gateway address"),
        (
            lambda n: dhcp(
                n, 20, DhcpValue(enabled=True, dns=[ip(f"192.0.2.{i}") for i in (1, 2, 3)])
            ),
            "at most two DNS",
        ),
        (lambda n: dhcp(n, 20, DhcpValue(enabled=True, lease_seconds=90)), "whole minutes"),
        (
            lambda n: router(n, 20, RouterValue(vlan=21, address=iface("198.51.100.1/24"))),
            "does not match",
        ),
        (
            lambda n: router(
                n, 20, RouterValue(vlan=20, address=iface("198.51.100.1/24"))
            ).model_copy(update={"key": "elsewhere/segment/20"}),
            "not a segment of site home",
        ),
        (
            lambda n: router(
                n, 20, RouterValue(vlan=20, address=iface("198.51.100.1/24"))
            ).model_copy(update={"device_id": SW}),
            "not a gateway managed by this controller",
        ),
        (
            lambda n: change(
                ChangeKind.RESERVATION, GW, "home/segment/native/02:00:00:00:00:99", None, None
            ),
            "",
        ),
    ],
)
async def test_network_refusals(url: str, make: Any, message: str) -> None:
    net = await network(url)
    try:
        c = make(net)
    except ValueError:  # a change needs an old or new value
        c = Change.model_construct(
            kind=ChangeKind.RESERVATION, device_id=GW, site_id="home", key="k", old=None, new=None
        )
        message = "cannot change reservation"
    with pytest.raises(AdapterError, match=message):
        await apply(url, [c])


async def test_removing_dhcp_with_the_router_is_refused_if_dhcp_stays(url: str) -> None:
    net = await network(url)
    keep = observed_dhcp(net, GW, "home/segment/20")
    with pytest.raises(AdapterError, match="DHCP needs"):
        await apply(url, [router(net, 20, None), dhcp(net, 20, keep)])
    gone = RouterValue(vlan=40, name="Lab", address=iface("203.0.113.1/24"))
    await apply(url, [change(ChangeKind.ROUTER, GW, "home/segment/40", gone, None)])


async def test_controller_without_gateway_owns_the_networks(url: str, sim: OmadaSimulator) -> None:
    sim.data[f"{SITE_PATH}/devices"] = [
        d for d in sim.data[f"{SITE_PATH}/devices"] if d["type"] != "gateway"
    ]
    net = await network(url)
    key = "home/segment/20"
    old = observed_router(net, DEV, key)
    assert old is not None
    c = change(ChangeKind.ROUTER, DEV, key, old, old.model_copy(update={"name": "Things"}))
    await round_trip(url, [c])


# --- refused writes ------------------------------------------------------------------------------


async def test_viewer_role_is_refused(url: str, sim: OmadaSimulator) -> None:
    sim.read_only = True
    net = await network(url)
    with pytest.raises(AdapterError, match="Admin role"):
        await apply(url, [port(net, 5, 20, [])])


async def test_refused_write_and_expired_token(url: str, sim: OmadaSimulator) -> None:
    net = await network(url)
    sim.write_error[f"{PORTS}/5"] = (-39999, "Device busy.")
    with pytest.raises(AdapterError, match=r"the controller refused: .*-39999: Device busy"):
        await apply(url, [port(net, 5, 20, [])])
    sim.write_error.clear()
    a = adapter(url)
    try:
        await a.read_system()
        sim.expire_next = True  # the write's token expired: renewed once
        await Writer(a).send("PATCH", f"{PORTS}/5", {"nativeNetworkId": "net-iot"})
    finally:
        await a.close()
    assert next(r for r in sim.data[PORTS] if r["port"] == 5)["nativeNetworkId"] == "net-iot"


async def test_token_refused_twice_on_a_write(url: str, sim: OmadaSimulator) -> None:
    a = adapter(url)
    try:
        await a.read_system()

        async def no_token() -> None:
            sim.tokens.clear()

        real = a._authorise
        a._authorise = no_token  # type: ignore[method-assign]
        sim.tokens.clear()
        with pytest.raises(AuthFailed, match="refused the access token"):
            await Writer(a).send("PATCH", f"{PORTS}/5", {})
        a._authorise = real  # type: ignore[method-assign]
        await a.read_system()
        async with httpx.AsyncClient(base_url=url, trust_env=False) as raw:
            answer = await raw.patch(
                f"{PORTS}/5", content=b"{", headers={"Authorization": f"AccessToken={a._token}"}
            )
        assert answer.status_code == 400  # Tomcat's own page, like the real controller
    finally:
        await a.close()


async def test_network_used_only_by_an_ssid_stays_as_a_vlan(url: str, sim: OmadaSimulator) -> None:
    profiles = sim.data[f"{SITE_PATH}/lan-profiles"]
    for row in [*profiles, *sim.data[PORTS]]:
        if row.get("nativeNetworkId") == "net-iot":
            row["nativeNetworkId"] = "net-lan"
        row["tagNetworkIds"] = [t for t in row.get("tagNetworkIds") or [] if t != "net-iot"]
    net = await network(url)
    await apply(url, [router(net, 20, None), dhcp(net, 20, None)])
    iot = next(n for n in sim.data[NETS] if n["id"] == "net-iot")
    assert iot["purpose"] == 0 and "gatewaySubnet" not in iot


async def test_site_without_wlan_group(url: str, sim: OmadaSimulator) -> None:
    net = await network(url)
    sim.data[f"{SITE_PATH}/wireless-network/wlans"] = []
    new = WlanValue(ssid="Office", security=Security.OPEN)
    with pytest.raises(AdapterError, match="no WLAN group"):
        await apply(url, [wlan(net, AP1, "Office", new)])


async def test_simulator_refuses_what_a_controller_would(url: str, sim: OmadaSimulator) -> None:
    a = adapter(url)
    w = Writer(a)
    try:
        await a.read_system()
        net = {"purpose": 0, "igmpSnoopEnable": False}
        ssid = {
            "deviceType": 1, "band": 3, "guestNetEnable": False, "security": 0,
            "broadcast": True, "vlanEnable": False, "mloEnable": False, "pmfMode": 2,
            "enable11r": False, "hidePwd": False,
        }  # fmt: skip
        basic = f"{SSIDS}/ssid-home/update-basic-config"
        for method, path, body, message in [
            ("POST", NETS, {**net, "name": "x", "vlan": 20}, "-34517: This VLAN ID is already"),
            ("POST", NETS, {**net, "vlan": 41}, r"-1001: Parameter \[name\]"),
            ("POST", NETS, {"name": "x", "vlan": 41}, r"Parameter \[purpose\]"),
            ("POST", NETS, {**net, "name": "x", "vlan": 5000}, "1-4094"),
            ("POST", NETS, {**net, "name": "x", "vlan": 41, "purpose": 1}, r"\[gatewaySubnet\]"),
            (
                "POST",
                NETS,
                {**net, "name": "x", "vlan": 41, "purpose": 1, "gatewaySubnet": "203.0.113.1/24"},
                "-33515: LAN interfaces could not be none",
            ),
            (
                "POST",
                NETS,
                {
                    **net,
                    "name": "x",
                    "vlan": 41,
                    "purpose": 1,
                    "interfaceIds": ["2_x"],
                    "gatewaySubnet": "192.0.2.129/25",
                },
                "-33502: This range of IP address already exists",
            ),
            (
                "POST",
                NETS,
                {
                    **net,
                    "name": "x",
                    "vlan": 41,
                    "purpose": 1,
                    "interfaceIds": ["2_x"],
                    "gatewaySubnet": "nonsense",
                },
                "Invalid request",
            ),
            ("POST", NETS, [], "Invalid request"),
            ("PATCH", f"{NETS}/net-iot", {"name": "x"}, r"Parameter \[purpose\]"),
            ("POST", SSIDS, {**ssid, "name": "Home"}, "-33219: This SSID already exists"),
            ("POST", SSIDS, {"name": "x"}, r"Parameter \[deviceType\]"),
            ("POST", SSIDS, {**ssid, "name": ""}, r"Parameter \[name\]"),
            ("POST", SSIDS, {**ssid, "name": "x", "security": 3}, "-33223: The security key"),
            ("PATCH", basic, {"broadcast": False}, r"Parameter \[name\]"),
            ("PATCH", basic, [], "Invalid request"),
            ("PATCH", f"{SSIDS}/nope/update-basic-config", {}, "does not exist"),
            ("PATCH", f"{SITE_PATH}/wireless-network/ssids/nope/enable", {}, "does not exist"),
            (
                "PATCH",
                f"{SITE_PATH}/wireless-network/ssids/ssid-home/enable",
                {},
                r"\[ssidEnable\]",
            ),
            ("DELETE", f"{NETS}/nope", None, "-33503: This network does not exist"),
            ("PATCH", f"{PORTS}/1", {"nativeNetworkId": "nope"}, "network does not exist"),
            ("PATCH", f"{PORTS}/1", {"profileId": "nope"}, "profile does not exist"),
            ("PATCH", f"{PORTS}/1", [], "Invalid request"),
            ("PATCH", f"{PORTS}/99", {}, "Not found"),
        ]:
            with pytest.raises(AdapterError, match=message):
                await w.send(method, path, body)  # type: ignore[arg-type]
        for method, path, status in [
            ("POST", f"{SITE_PATH}/devices", "404"),
            ("PATCH", f"{SITE_PATH}/x/y", "404"),
            ("PATCH", f"{SSIDS}/ssid-home", "405"),  # SSIDs change through update-basic-config
            ("DELETE", f"{PORTS}/1", "405"),
            ("POST", NETS, "400"),  # "purpose" is a number
            ("PATCH", f"{NETS}/net-iot", "400"),
            ("POST", f"{SITE_PATH}/x/update-basic-config", "404"),
        ]:
            body = {"purpose": "vlan"} if path.startswith(NETS) else {}
            with pytest.raises(AdapterError, match=status):
                await w.send(method, path, body)
        await w.send("DELETE", f"{NETS}/net-iot")  # in use by an SSID and ports: still gone
    finally:
        await a.close()


# --- backup and restore --------------------------------------------------------------------------


def state(sim: OmadaSimulator) -> dict[str, Any]:
    return copy.deepcopy({p: sim.data[p] for p in (NETS, SSIDS, PORTS)})


async def test_backup_and_restore_round_trip(url: str, sim: OmadaSimulator) -> None:
    original = state(sim)
    a = adapter(url)
    try:
        backup = await a.backup()
    finally:
        await a.close()
    content = json.loads(backup.content)
    assert content["site"] == SITE_PATH and set(content) == {
        "site",
        "lan_networks",
        "ssids",
        "ports",
    }
    net = await network(url)
    await apply(
        url,
        [
            router(net, 40, RouterValue(vlan=40, name="Lab", address=iface("203.0.113.1/24"))),
            router(net, 20, RouterValue(vlan=20, name="Things", address=iface("198.51.100.1/24"))),
        ],
    )
    net = await network(url)
    await apply(url, [port(net, 4, 40, [20])])
    await apply(
        url,
        [
            wlan(net, AP1, "Guest", None),
            wlan(net, AP1, "Lab", WlanValue(ssid="Lab", security=Security.OPEN, segment=40)),
        ],
    )
    next(x for x in sim.data[SSIDS] if x["name"] == "Home")["broadcast"] = False
    # a network of the backup deleted meanwhile (recreated with a new id on restore)
    sim.data[NETS] = [n for n in sim.data[NETS] if n["id"] != "net-guest"]
    sim.data[f"{SITE_PATH}/lan-profiles"][0]["tagNetworkIds"] = ["net-iot"]
    for r in sim.data[PORTS]:
        if r.get("nativeNetworkId") == "net-guest":
            r["nativeNetworkId"] = "net-lan"
    assert state(sim) != original
    a = adapter(url)
    try:
        await a.restore(backup)
        await a.restore(backup)  # already as backed up: nothing to do
    finally:
        await a.close()
    now = state(sim)
    guest = next(n for n in now[NETS] if n["name"] == "Guest")
    assert guest["id"] != "net-guest"
    port8 = next(r for r in now[PORTS] if r["port"] == 8)
    assert port8["nativeNetworkId"] == guest["id"]

    # apart from the new id of the recreated network (and SSIDs recreated), all is as before
    def same(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
        return sorted(
            ({k: v for k, v in r.items() if k != key} for r in rows), key=lambda r: str(r)
        )

    def differences(a: list[dict[str, Any]], b: list[dict[str, Any]]) -> list[str]:
        by_name = {r["name"]: r for r in b}
        return [
            f"{r['name']}.{k}: {r.get(k)!r} != {by_name.get(r['name'], {}).get(k)!r}"
            for r in a
            for k in sorted(set(r) | set(by_name.get(r["name"], {})))
            if k not in ("id", "ssidId") and r.get(k) != by_name.get(r["name"], {}).get(k)
        ]

    assert differences(now[NETS], original[NETS]) == []
    assert len(now[NETS]) == len(original[NETS]) and len(now[SSIDS]) == len(original[SSIDS])
    ssids_now = [{k: v for k, v in r.items() if k != "id"} for r in now[SSIDS]]
    ssids_then = [{k: v for k, v in r.items() if k != "id"} for r in original[SSIDS]]
    assert differences(ssids_now, ssids_then) == []
    fixed = [{**r, "nativeNetworkId": "net-guest"} if r["port"] == 8 else r for r in now[PORTS]]
    assert fixed == original[PORTS]


async def test_restore_takes_over_a_network_with_the_same_vlan(
    url: str, sim: OmadaSimulator
) -> None:
    a = adapter(url)
    try:
        backup = await a.backup()
        sim.data[NETS][2] = {**sim.data[NETS][2], "id": "net-other", "name": "Other"}
        await a.restore(backup)
    finally:
        await a.close()
    guest = sim.data[NETS][2]
    assert (guest["id"], guest["name"], guest["purpose"], guest["vlan"]) == (
        "net-other",
        "Guest",
        0,
        30,
    )


@pytest.mark.parametrize(
    ("fmt", "content", "message"),
    [
        ("other", "{}", "format 'other'"),
        ("omada-openapi-json", "nonsense", "not an Omada backup"),
        ("omada-openapi-json", "{}", "not an Omada backup"),
        (
            "omada-openapi-json",
            json.dumps({"site": "/elsewhere", "lan_networks": [], "ssids": {}, "ports": {}}),
            "another controller or site",
        ),
    ],
)
async def test_restore_refusals(url: str, fmt: str, content: str, message: str) -> None:
    a = adapter(url)
    try:
        with pytest.raises(AdapterError, match=message):
            await a.restore(
                Backup(device_id=DEV, taken_at=datetime.now(UTC), format=fmt, content=content)
            )
    finally:
        await a.close()


async def test_restore_of_a_missing_port_and_created_ids(url: str, sim: OmadaSimulator) -> None:
    a = adapter(url)
    try:
        backup = await a.backup()
        content = json.loads(backup.content)
        content["ports"][SWITCH].append({"port": 9, "profileId": "prof-lan"})
        content["lan_networks"].append(
            {"id": "net-x", "name": "X", "vlan": 50, "purpose": 0, "igmpSnoopEnable": False}
        )
        changed = backup.model_copy(update={"content": json.dumps(content)})
        await a.restore(changed)
        assert any(n.get("vlan") == 50 for n in sim.data[NETS])
        assert Writer._new_id("net-y", NETS) == "net-y"
        with pytest.raises(AdapterError, match="did not say which id"):
            Writer._new_id({}, NETS)
    finally:
        await a.close()


# --- a whole deployment through the controller ---------------------------------------------------

WANT = f"""
sites:
  home:
    segments:
      - vlan: 40
        name: Lab
        gateway: {{device: {GW}, address: 203.0.113.1/24}}
        dhcp:
          enabled: true
          pool: [203.0.113.100, 203.0.113.199]
          dns: [203.0.113.1]
          lease_seconds: 3600
    ports:
      - {{device: {SW}, port: "5", untagged: 40, tagged: [20]}}
    wlans:
      - {{ssid: Lab, security: wpa2-psk, segment: 40, passphrase_secret: lab-psk}}
"""


@pytest.fixture
def svc(tmp_path: Path, url: str) -> Iterator[Services]:
    s = build(tmp_path, env=ENV, adapters={"omada": OmadaAdapter}, rules=RULES, link_sources=[])
    s.store.put_site(SITE)
    rec = DeviceRecord(
        id=DEV,
        site_id="home",
        name="Omada",
        role=DeviceRole.OTHER,
        adapter="omada",
        allow_writes=True,
    )
    s.store.put_device(
        rec,
        {
            "url": url,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "allow_insecure_http": True,
        },
        OmadaConfig,
    )
    s.store.set_secret("lab-psk", "the lab passphrase")
    yield s
    s.close()


async def test_deployment_through_the_controller_and_revert(
    svc: Services, sim: OmadaSimulator
) -> None:
    original = state(sim)
    await svc.runner.observe_all()
    net = svc.runner.network()
    assert {d.managed_by for d in net.devices if d.id != DEV} == {DEV}
    p = plan(parse(WANT), net, RULES, secret=svc.store.get_secret)
    assert sorted({c.device_id for c in p.changes}) == [AP1, AP2, GW, SW]
    d = Deployer(svc.runner)
    rec = await d.prepare(p, "a lab network", "tester")
    assert "the lab passphrase" not in rec.model_dump_json()
    d.approve(rec.id, "tester", override="test" if p.blocking else None)
    done = await d.deploy(rec.id)
    assert done.status is ChangeStatus.APPLIED, [
        (e.device_id, e.event, e.detail) for e in svc.store.events(rec.id)
    ]
    assert plan(parse(WANT), svc.runner.network(), RULES, secret=svc.store.get_secret).changes == []
    lab = next(s for s in sim.data[SSIDS] if s["name"] == "Lab")
    assert lab["pskSetting"]["securityKey"] == "the lab passphrase"
    back = await d.revert(rec.id, "undo", "tester")
    d.approve(back.id, "tester", override="test" if back.plan.blocking else None)
    reverted = await d.deploy(back.id)
    assert reverted.status is ChangeStatus.APPLIED, [
        (e.device_id, e.event, e.detail) for e in svc.store.events(back.id)
    ]
    now = state(sim)
    assert now[NETS] == original[NETS] and now[SSIDS] == original[SSIDS]
    final = svc.runner.network()
    assert all(matches(final, c, c.old, {}) for c in p.changes)


async def deploy_passphrase(svc: Services, d: Deployer, ssid: str, secret: str) -> str:
    """Set an SSID's passphrase on both access points (one controller WLAN); the change id."""
    await svc.runner.observe_all()
    net = svc.runner.network()
    changes = []
    for ap in (AP1, AP2):
        old = observed_wlan(net, ap, ssid)
        assert old is not None
        changes.append(wlan(net, ap, ssid, old.model_copy(update={"passphrase_secret": secret})))
    rec = await d.prepare(make_plan(changes, net, RULES), "new passphrase", "tester")
    d.approve(rec.id, "tester", override="test" if rec.plan.blocking else None)
    done = await d.deploy(rec.id)
    assert done.status is ChangeStatus.APPLIED, [
        (e.device_id, e.event, e.detail) for e in svc.store.events(rec.id)
    ]
    return rec.id


async def revert(svc: Services, d: Deployer, cid: str) -> None:
    back = await d.revert(cid, "back to the old passphrase", "tester")
    d.approve(back.id, "tester", override="test" if back.plan.blocking else None)
    done = await d.deploy(back.id)
    assert done.status is ChangeStatus.APPLIED, [
        (e.device_id, e.event, e.detail) for e in svc.store.events(back.id)
    ]


def fingerprints(net: Network, ssid: str) -> set[str | None]:
    return {w.passphrase_fingerprint for w in net.wlans if w.ssid == ssid}


async def test_revert_restores_the_replaced_passphrase(svc: Services, sim: OmadaSimulator) -> None:
    # #188: IoT reports its key, and the secret held it before it was replaced
    original = state(sim)
    svc.store.set_secret("iot-psk", "example-iot-passphrase")
    svc.store.set_secret("iot-psk", "the new IoT passphrase")
    await svc.runner.observe_all()
    before = fingerprints(svc.runner.network(), "IoT")
    assert before == {passphrase_fingerprint("IoT", "example-iot-passphrase")}
    d = Deployer(svc.runner)
    cid = await deploy_passphrase(svc, d, "IoT", "iot-psk")
    iot = next(s for s in sim.data[SSIDS] if s["name"] == "IoT")
    assert iot["pskSetting"]["securityKey"] == "the new IoT passphrase"
    await revert(svc, d, cid)
    iot = next(s for s in sim.data[SSIDS] if s["name"] == "IoT")
    assert iot["pskSetting"] == next(s for s in original[SSIDS] if s["name"] == "IoT")["pskSetting"]
    await svc.runner.observe_all()
    assert fingerprints(svc.runner.network(), "IoT") == before


async def test_revert_without_a_readable_key_uses_what_signalbox_set(
    svc: Services, sim: OmadaSimulator
) -> None:
    # Home does not report its key: only the passphrase Signalbox deployed itself is trusted
    await svc.runner.observe_all()
    assert fingerprints(svc.runner.network(), "Home") == {None}
    d = Deployer(svc.runner)
    svc.store.set_secret("home-psk", "the first home passphrase")
    await deploy_passphrase(svc, d, "Home", "home-psk")
    svc.store.set_secret("home-psk", "the second home passphrase")
    cid = await deploy_passphrase(svc, d, "Home", "home-psk")
    home = next(s for s in sim.data[SSIDS] if s["name"] == "Home")
    assert home["pskSetting"]["securityKey"] == "the second home passphrase"
    await revert(svc, d, cid)
    home = next(s for s in sim.data[SSIDS] if s["name"] == "Home")
    assert home["pskSetting"]["securityKey"] == "the first home passphrase"


async def test_failed_deployment_restores_the_controller(
    svc: Services, sim: OmadaSimulator
) -> None:
    original = state(sim)
    await svc.runner.observe_all()
    p = plan(parse(WANT), svc.runner.network(), RULES, secret=svc.store.get_secret)
    d = Deployer(svc.runner)
    rec = await d.prepare(p, "a lab network", "tester")
    d.approve(rec.id, "tester", override="test")
    sim.write_error[SSIDS] = (-39999, "Device busy.")  # the WLAN step fails
    done = await d.deploy(rec.id)
    assert done.status is ChangeStatus.ROLLED_BACK
    now = state(sim)
    assert now[NETS] == original[NETS] and now[SSIDS] == original[SSIDS]
