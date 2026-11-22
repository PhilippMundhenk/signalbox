"""Fritz!Box write side (DHCP and existing WLANs over TR-064) against the simulator."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from factories import SITE
from signalbox.adapters import AdapterContext, AdapterError, Backup, WritesConfig
from signalbox.adapters.fritzbox import FritzboxAdapter, FritzboxConfig
from signalbox.adapters.fritzbox.write import (
    BACKUP_FORMAT,
    backup_content,
    lan_calls,
    parse_backup,
    wlan_calls,
)
from signalbox.changes import (
    Change,
    ChangeKind,
    RouterValue,
    WlanValue,
    observed_dhcp,
    observed_wlan,
    plan,
)
from signalbox.deploy import Deployer, matches
from signalbox.desired import parse
from signalbox.history import ChangeStatus, DeviceStatus
from signalbox.model import DeviceRole, Network, Pmf, Security, passphrase_fingerprint
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.sim import fritzbox as fritz_sim
from signalbox.sim.fritzbox import FritzboxSim, create_app
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve
from signalbox.store import DeviceRecord

SIM = FritzboxSim()
NATIVE = "home/segment/native"
NEW_KEY = "a brand new passphrase"


@pytest.fixture(scope="module")
def cert(tmp_path_factory: pytest.TempPathFactory) -> TlsFiles:
    return self_signed_certificate(tmp_path_factory.mktemp("tls"), "fritzbox")


@pytest.fixture(scope="module")
def url(cert: TlsFiles) -> Iterator[str]:
    with serve(create_app(SIM), tls=cert) as base:
        yield base


@pytest.fixture(scope="module")
def http_url() -> Iterator[str]:
    with serve(create_app(SIM)) as base:
        yield base


@pytest.fixture
def sim() -> FritzboxSim:
    SIM.reset()
    return SIM


@pytest.fixture
async def adapter(sim: FritzboxSim, http_url: str) -> AsyncIterator[FritzboxAdapter]:
    """Plain http for speed: TLS and pinning are covered by test_fritzbox.py and the
    deployment tests below."""
    a = FritzboxAdapter(
        AdapterContext(
            site_id="home",
            device_id="fb",
            device_name="Fritz!Box",
            role=DeviceRole.GATEWAY,
            config=FritzboxConfig(
                url=http_url,
                password=SecretStr(FritzboxSim().password),
                allow_insecure_http=True,
            ),
        )
    )
    yield a
    await a.close()


async def network(a: FritzboxAdapter) -> Network:
    """What the read side reports for the settings the write side changes (DHCP, Wi-Fi)."""
    dhcp, wireless = await a.read_dhcp(), await a.read_wireless()
    return Network(dhcp_servers=dhcp.dhcp_servers, radios=wireless.radios, wlans=wireless.wlans)


def wlan_change(net: Network, key: str, **update: Any) -> Change:
    old = observed_wlan(net, "fb", key)
    assert old is not None
    return Change(
        kind=ChangeKind.WLAN,
        device_id="fb",
        site_id="home",
        key=key,
        old=old,
        new=old.model_copy(update=update),
    )


def dhcp_change(net: Network, **update: Any) -> Change:
    old = observed_dhcp(net, "fb", NATIVE)
    assert old is not None
    return Change(
        kind=ChangeKind.DHCP,
        device_id="fb",
        site_id="home",
        key=NATIVE,
        old=old,
        new=old.model_copy(update=update),
    )


async def round_trip(a: FritzboxAdapter, c: Change, secrets: dict[str, str]) -> None:
    """apply -> the read side reports the new value; inverse -> the old one again."""
    result = await a.apply([c], secrets, 60)
    assert result.confirm_deadline is None and result.calls
    assert matches(await network(a), c, c.new, secrets)
    await a.confirm()
    inverse = c.inverse()
    await a.apply([inverse], secrets, 60)
    assert matches(await network(a), c, c.old, secrets)


def test_manifest_declares_what_is_implemented() -> None:
    assert FritzboxAdapter.manifest.writes == {ChangeKind.DHCP, ChangeKind.WLAN}
    assert issubclass(FritzboxAdapter, WritesConfig)


# --- per kind: apply, read, inverse -------------------------------------------------------


@pytest.mark.parametrize(
    ("ssid", "update"),
    [
        ("Example", {"security": Security.WPA2}),
        ("Example", {"security": Security.WPA3}),
        ("Example", {"security": Security.OPEN}),
        ("Example", {"hidden": True}),
        ("Example", {"enabled": False}),
        ("Example-Guest", {"enabled": False, "security": Security.WPA2_WPA3, "hidden": True}),
    ],
)
async def test_wlan_round_trip(
    adapter: FritzboxAdapter, sim: FritzboxSim, ssid: str, update: dict[str, Any]
) -> None:
    before = json.dumps(sim.wlans, sort_keys=True)
    c = wlan_change(await network(adapter), ssid, **update)
    await round_trip(adapter, c, {})
    assert json.dumps(sim.wlans, sort_keys=True) == before
    assert sim.writes  # it went to the box


async def test_wlan_same_ssid_on_both_bands(adapter: FritzboxAdapter, sim: FritzboxSim) -> None:
    c = wlan_change(await network(adapter), "Example", hidden=True)
    calls = await adapter.plan_changes([c], {})
    assert [call.target for call in calls] == [
        "WLANConfiguration1 X_AVM-DE_SetBeaconAdvertisement",
        "WLANConfiguration2 X_AVM-DE_SetBeaconAdvertisement",
    ]
    await adapter.apply([c], {}, 60)
    wlans = [w for w in (await network(adapter)).wlans if w.ssid == "Example"]
    assert len(wlans) == 2 and all(w.hidden for w in wlans)
    assert sim.wlans[3]["NewBeaconAdvertisementEnabled"] == "1"  # the guest is untouched


async def test_wlan_passphrase(adapter: FritzboxAdapter, sim: FritzboxSim) -> None:
    secrets = {"psk": NEW_KEY}
    c = wlan_change(await network(adapter), "Example", passphrase_secret="psk")
    calls = await adapter.plan_changes([c], secrets)
    assert [x.target for x in calls] == [
        "WLANConfiguration1 SetSecurityKeys",
        "WLANConfiguration2 SetSecurityKeys",
    ]
    assert calls[0].payload["NewKeyPassphrase"] == "***"
    assert NEW_KEY not in json.dumps([x.model_dump() for x in calls])
    result = await adapter.apply([c], secrets, 60)
    assert NEW_KEY not in result.model_dump_json()
    net = await network(adapter)
    assert matches(net, c, c.new, secrets)
    fp = passphrase_fingerprint("Example", NEW_KEY)
    assert {w.passphrase_fingerprint for w in net.wlans if w.ssid == "Example"} == {fp}
    assert sim.passphrases[1] == sim.passphrases[2] == NEW_KEY
    # the same passphrase again: nothing to send
    assert await adapter.plan_changes([c], secrets) == []
    # an inverse without a secret leaves the key alone (the restore of the backup puts it back)
    await adapter.apply([c.inverse()], secrets, 60)
    assert matches(await network(adapter), c, c.old, secrets)


async def test_wlan_open_ignores_the_passphrase(adapter: FritzboxAdapter) -> None:
    c = wlan_change(
        await network(adapter), "Example", security=Security.OPEN, passphrase_secret="psk"
    )
    calls = await adapter.plan_changes([c], {})  # no secret needed for an open network
    assert {x.target.split()[1] for x in calls} == {"SetBeaconType"}


async def test_wlan_rename_is_an_update_of_the_same_index(
    adapter: FritzboxAdapter, sim: FritzboxSim
) -> None:
    c = wlan_change(await network(adapter), "Example-Guest", ssid="Guests")
    await adapter.apply([c], {}, 60)
    net = await network(adapter)
    renamed = observed_wlan(net, "fb", "Guests")
    assert renamed == c.new and sim.wlans[3]["NewSSID"] == "Guests"
    assert "fb/wlan/3" in {w.id for w in net.wlans if w.ssid == "Guests"}
    await adapter.apply([c.inverse()], {}, 60)  # found by its current name
    assert matches(await network(adapter), c, c.old, {})


@pytest.mark.parametrize(
    "update",
    [
        {"enabled": False},
        {"pool": (ip_address("192.0.2.50"), ip_address("192.0.2.150"))},
        {"enabled": False, "pool": (ip_address("192.0.2.100"), ip_address("192.0.2.110"))},
    ],
)
async def test_dhcp_round_trip(
    adapter: FritzboxAdapter, sim: FritzboxSim, update: dict[str, Any]
) -> None:
    c = dhcp_change(await network(adapter), **update)
    await round_trip(adapter, c, {})
    assert sim.lan == fritz_sim.LAN


async def test_dhcp_order_of_calls(adapter: FritzboxAdapter) -> None:
    net = await network(adapter)
    pool = (ip_address("192.0.2.30"), ip_address("192.0.2.40"))
    off = dhcp_change(net, enabled=False, pool=pool)
    assert [x.target for x in await adapter.plan_changes([off], {})] == [
        "LANHostConfigManagement1 SetDHCPServerEnable",
        "LANHostConfigManagement1 SetAddressRange",
    ]
    await adapter.apply([off], {}, 60)
    on = off.inverse()
    assert [x.target for x in await adapter.plan_changes([on], {})] == [
        "LANHostConfigManagement1 SetAddressRange",
        "LANHostConfigManagement1 SetDHCPServerEnable",
    ]
    assert await adapter.plan_changes([dhcp_change(await network(adapter))], {}) == []


async def test_several_changes_at_once(adapter: FritzboxAdapter) -> None:
    net = await network(adapter)
    first = dhcp_change(net, enabled=False)
    second = dhcp_change(
        net, enabled=False, pool=(ip_address("192.0.2.30"), ip_address("192.0.2.40"))
    )
    calls = await adapter.plan_changes([first, second], {})
    assert [x.target.split()[1] for x in calls] == ["SetDHCPServerEnable", "SetAddressRange"]
    a = wlan_change(net, "Example", hidden=True)
    b = wlan_change(net, "Example", hidden=True, enabled=False)
    calls = await adapter.plan_changes([a, b], {})
    assert [x.target.split()[1] for x in calls].count("X_AVM-DE_SetBeaconAdvertisement") == 2


# --- plan without secrets, refusals -------------------------------------------------------


async def test_plan_changes_without_secrets(adapter: FritzboxAdapter, sim: FritzboxSim) -> None:
    net = await network(adapter)
    c = wlan_change(net, "Example", passphrase_secret="psk", security=Security.WPA2)
    with pytest.raises(AdapterError, match="secret 'psk' was not given"):
        await adapter.plan_changes([c], {})
    plain = wlan_change(net, "Example", security=Security.WPA2)
    calls = await adapter.plan_changes([plain], {})
    assert [x.target for x in calls] == [
        "WLANConfiguration1 SetBeaconType",
        "WLANConfiguration2 SetBeaconType",
    ]
    assert calls[0].payload == {"NewBeaconType": "11i"} and calls[0].method == "SOAP"
    assert sim.writes == []  # planning changes nothing


@pytest.mark.parametrize(
    ("fault", "update", "message"),
    [
        ({"SetBeaconType": 402}, {"security": Security.WPA2}, "security .*invalid arguments"),
        ({"SetEnable": 606}, {"enabled": False}, "switch off: .*not authorised"),
        ({"X_AVM-DE_SetBeaconAdvertisement": 401}, {"hidden": True}, "hide .*not supported"),
        ({"SetSSID": 820}, {"ssid": "Other"}, "SSID Other: .*internal error"),
    ],
)
async def test_refused_wlan_write(
    adapter: FritzboxAdapter,
    sim: FritzboxSim,
    fault: dict[str, int],
    update: dict[str, Any],
    message: str,
) -> None:
    c = wlan_change(await network(adapter), "Example", **update)
    sim.faults = fault
    with pytest.raises(AdapterError, match=message):
        await adapter.apply([c], {}, 60)


async def test_refused_passphrase_does_not_leak(adapter: FritzboxAdapter, sim: FritzboxSim) -> None:
    c = wlan_change(await network(adapter), "Example", passphrase_secret="psk")
    sim.faults = {"SetSecurityKeys": 402}
    with pytest.raises(AdapterError) as err:
        await adapter.apply([c], {"psk": NEW_KEY}, 60)
    assert "passphrase: refused" in str(err.value) and NEW_KEY not in str(err.value)
    with pytest.raises(AdapterError, match="8 to 63 characters") as err:
        await adapter.plan_changes([c], {"psk": "short"})
    assert "short" not in str(err.value)


async def test_refused_dhcp_write(adapter: FritzboxAdapter, sim: FritzboxSim) -> None:
    net = await network(adapter)
    outside = dhcp_change(net, pool=(ip_address("198.51.100.10"), ip_address("198.51.100.20")))
    with pytest.raises(AdapterError, match=r"DHCP address range .* refused .*invalid arguments"):
        await adapter.apply([outside], {}, 60)
    sim.denied = {"SetDHCPServerEnable"}
    with pytest.raises(AdapterError, match=r"switch the DHCP server off: refused .*not authorised"):
        await adapter.apply([dhcp_change(net, enabled=False)], {}, 60)
    assert sim.lan == fritz_sim.LAN


async def test_create_of_a_new_ssid_is_refused(adapter: FritzboxAdapter) -> None:
    new = WlanValue(ssid="Brand-New", security=Security.WPA2)
    c = Change(kind=ChangeKind.WLAN, device_id="fb", site_id="home", key="Brand-New", new=new)
    with pytest.raises(AdapterError, match="cannot create a Wi-Fi network; its networks are fixed"):
        await adapter.plan_changes([c], {})
    with pytest.raises(AdapterError, match="cannot delete a Wi-Fi network; set enabled: false"):
        await adapter.apply([c.inverse()], {}, 60)


async def test_unsupported_wlan_settings_are_refused(adapter: FritzboxAdapter) -> None:
    net = await network(adapter)
    cases = [
        ({"segment": 20}, "has no VLANs"),
        ({"pmf": Pmf.REQUIRED}, "pmf cannot be set"),
        ({"roaming_80211r": True, "roaming_80211v": False}, "802.11r, 802.11v cannot be set"),
        ({"security": Security.OWE}, "security owe cannot be set"),
        ({"security": Security.WPA2_ENTERPRISE}, "security wpa2-enterprise cannot be set"),
    ]
    for update, message in cases:
        with pytest.raises(AdapterError, match=message):
            await adapter.plan_changes([wlan_change(net, "Example", **update)], {})
    gone = wlan_change(net, "Example", hidden=True)
    gone = gone.model_copy(update={"old": gone.old.model_copy(update={"ssid": "Gone"})})  # type: ignore[union-attr]
    with pytest.raises(AdapterError, match="SSID Gone: no Wi-Fi network of the Fritz!Box has it"):
        await adapter.plan_changes([gone], {})


async def test_beacon_type_the_box_does_not_offer(
    adapter: FritzboxAdapter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fritz_sim, "POSSIBLE_BEACON_TYPES", "None,11i,11iandWPA3")
    c = wlan_change(await network(adapter), "Example", security=Security.WPA3)
    with pytest.raises(AdapterError, match=r"does not offer wpa3-sae .*it offers None,11i"):
        await adapter.plan_changes([c], {})


async def test_unsupported_dhcp_changes_are_refused(adapter: FritzboxAdapter) -> None:
    net = await network(adapter)
    cases = [
        (dhcp_change(net, lease_seconds=3600), "lease time cannot be set"),
        (dhcp_change(net, dns=[ip_address("192.0.2.53")]), "DNS servers .* cannot be set"),
        (dhcp_change(net, pool=None), "always has an address range"),
        (
            dhcp_change(net, pool=(ip_address("2001:db8::10"), ip_address("2001:db8::20"))),
            "IPv4 addresses only",
        ),
    ]
    for c, message in cases:
        with pytest.raises(AdapterError, match=message):
            await adapter.plan_changes([c], {})
    base = dhcp_change(net)
    with pytest.raises(AdapterError, match="cannot be removed; set enabled: false"):
        await adapter.plan_changes([base.model_copy(update={"new": None})], {})
    with pytest.raises(AdapterError, match="reported no DHCP server"):
        await adapter.plan_changes([base.model_copy(update={"old": None})], {})
    other = base.model_copy(update={"key": "home/segment/20"})
    with pytest.raises(AdapterError, match="one DHCP server, on its LAN"):
        await adapter.plan_changes([other], {})
    router = Change(
        kind=ChangeKind.ROUTER,
        device_id="fb",
        site_id="home",
        key=NATIVE,
        new=RouterValue(address="192.0.2.1/24"),  # type: ignore[arg-type]
    )
    with pytest.raises(AdapterError, match="cannot change router"):
        await adapter.plan_changes([router], {})
    # unchanged DNS servers are fine
    assert await adapter.plan_changes([dhcp_change(net, dns=[ip_address("192.0.2.1")])], {}) == []


async def test_without_beacon_advertisement_action(
    adapter: FritzboxAdapter, sim: FritzboxSim
) -> None:
    sim.beacon_advertisement = False
    net = await network(adapter)
    assert not any(w.hidden for w in net.wlans)
    c = wlan_change(net, "Example", hidden=True)
    with pytest.raises(AdapterError, match=r"hide the SSID: refused .*not supported"):
        await adapter.apply([c], {}, 60)
    sim.beacon_advertisement = True
    sim.faults = {"X_AVM-DE_GetBeaconAdvertisement": 820}
    assert (await adapter.observe()).errors  # another fault is an error, not "not hidden"


# --- backup and restore -------------------------------------------------------------------


async def test_backup_restore_round_trip(adapter: FritzboxAdapter, sim: FritzboxSim) -> None:
    original = await network(adapter)
    backup = await adapter.backup()
    assert backup.format == BACKUP_FORMAT == "fritzbox-tr064-values" and backup.device_id == "fb"
    content = json.loads(backup.content)
    assert content["lan"] == {
        "NewDHCPServerEnable": "1",
        "NewMinAddress": "192.0.2.20",
        "NewMaxAddress": "192.0.2.200",
    }
    assert content["wlans"]["3"]["NewSSID"] == "Example-Guest"
    assert content["wlans"]["1"]["NewKeyPassphrase"] == "example-passphrase"
    net = original
    changes = [
        dhcp_change(net, enabled=False, pool=(ip_address("192.0.2.30"), ip_address("192.0.2.40"))),
        wlan_change(net, "Example", security=Security.WPA3, hidden=True, passphrase_secret="psk"),
        wlan_change(net, "Example-Guest", ssid="Renamed", enabled=False),
    ]
    await adapter.apply(changes, {"psk": NEW_KEY}, 60)
    assert sim.passphrases[1] == NEW_KEY
    sim.writes.clear()
    await adapter.restore(backup)
    assert sim.wlans == fritz_sim.WLANS and sim.lan == fritz_sim.LAN
    assert sim.passphrases == fritz_sim.PASSPHRASES
    after = await network(adapter)
    for c in changes:
        assert matches(after, c, c.old, {})
    assert {w.id: w.passphrase_fingerprint for w in after.wlans} == {
        w.id: w.passphrase_fingerprint for w in original.wlans
    }
    sim.writes.clear()
    await adapter.restore(backup)  # nothing differs: nothing is sent
    assert sim.writes == []


async def test_backup_without_the_right_for_keys(
    adapter: FritzboxAdapter, sim: FritzboxSim
) -> None:
    sim.denied = {"GetSecurityKeys"}
    backup = await adapter.backup()
    assert "NewKeyPassphrase" not in backup.content
    sim.denied = set()
    await adapter.restore(backup)


async def test_restore_refuses_other_backups(adapter: FritzboxAdapter, sim: FritzboxSim) -> None:
    good = await adapter.backup()
    other = good.model_copy(update={"format": "uci"})
    with pytest.raises(AdapterError, match="backup format 'uci' is not 'fritzbox-tr064-values'"):
        await adapter.restore(other)
    for content in (
        "not json",
        "[]",
        json.dumps({"format": "x"}),
        json.dumps({"format": BACKUP_FORMAT}),
    ):
        with pytest.raises(AdapterError, match="not a fritzbox-tr064-values backup"):
            await adapter.restore(good.model_copy(update={"content": content}))
    data = json.loads(good.content)
    data["wlans"]["4"] = data["wlans"]["1"]
    with pytest.raises(
        AdapterError, match="WLANConfiguration 4, which this Fritz!Box does not have"
    ):
        await adapter.restore(good.model_copy(update={"content": json.dumps(data)}))
    sim.faults = {"SetSSID": 501}
    changed = wlan_change(await network(adapter), "Example-Guest", ssid="Renamed")
    sim.faults = {}
    await adapter.apply([changed], {}, 60)
    sim.faults = {"SetSSID": 501}
    with pytest.raises(AdapterError, match=r"SSID Example-Guest: refused .*action failed"):
        await adapter.restore(good)


def test_backup_helpers() -> None:
    content = backup_content({"NewDHCPServerEnable": "1", "Other": "x"}, {1: {"NewSSID": "A"}})
    assert parse_backup(content) == ({"NewDHCPServerEnable": "1"}, {1: {"NewSSID": "A"}})
    assert lan_calls({}, {}) == [] and wlan_calls("WLANConfiguration1", {}, {}, None) == []


# --- a full deployment --------------------------------------------------------------------

ENV = {"SIGNALBOX_AUTH_PASSWORD": "x" * 12, "SIGNALBOX_DEPLOY_ENABLED": "true"}
WANT = """
sites:
  home:
    segments:
      - vlan: native
        dhcp: {enabled: true, pool: [192.0.2.50, 192.0.2.150]}
    wlans:
      - {ssid: Example, security: wpa2-psk, passphrase_secret: psk, hidden: true, devices: [fb]}
      - {ssid: Example-Guest, security: wpa2-wpa3, devices: [fb]}
"""


@pytest.fixture
def svc(tmp_path: Path, sim: FritzboxSim, url: str, cert: TlsFiles) -> Iterator[Services]:
    s = build(
        tmp_path, env=ENV, adapters={"fritzbox": FritzboxAdapter}, rules=RULES, link_sources=[]
    )
    s.store.put_site(SITE)
    rec = DeviceRecord(
        id="fb",
        site_id="home",
        name="Fritz!Box",
        role=DeviceRole.GATEWAY,
        adapter="fritzbox",
        allow_writes=True,
        pinned_fingerprint=cert.fingerprint,
    )
    s.store.put_device(rec, {"url": url, "password": sim.password}, FritzboxConfig)
    s.store.set_secret("psk", NEW_KEY)
    yield s
    s.close()


async def deploy(d: Deployer, cid: str) -> ChangeStatus:
    rec = d.store.change(cid)
    assert rec is not None
    d.approve(cid, "tester", override="test" if rec.plan.blocking else None)
    return (await d.deploy(cid)).status


async def test_deployment_from_desired_state_and_revert(svc: Services, sim: FritzboxSim) -> None:
    await svc.runner.observe_all()
    p = plan(parse(WANT), svc.runner.network(), RULES, secret=svc.store.get_secret)
    assert sorted(c.kind.value for c in p.changes) == ["dhcp", "wlan", "wlan"]
    d = Deployer(svc.runner)
    rec = await d.prepare(p, "harden the Wi-Fi", "tester")
    assert NEW_KEY not in rec.model_dump_json()
    assert await deploy(d, rec.id) is ChangeStatus.APPLIED
    done = svc.store.change(rec.id)
    assert done is not None and [r.status for r in done.devices] == [DeviceStatus.CONFIRMED]
    assert NEW_KEY not in done.model_dump_json()
    assert sim.lan["NewMinAddress"] == "192.0.2.50" and sim.wlans[1]["NewBeaconType"] == "11i"
    assert sim.wlans[3]["NewBeaconType"] == "11iandWPA3" and sim.passphrases[2] == NEW_KEY
    net = svc.runner.network()
    assert plan(parse(WANT), net, RULES, secret=svc.store.get_secret).changes == []

    back = await d.revert(rec.id, "undo", "tester")
    status = await deploy(d, back.id)
    assert status is ChangeStatus.APPLIED, [(e.event, e.detail) for e in svc.store.events(back.id)]
    assert sim.lan == fritz_sim.LAN and sim.wlans == fritz_sim.WLANS
    # the inverse of a passphrase change has no secret: the new passphrase stays
    assert sim.passphrases[1] == NEW_KEY


async def test_deployment_that_does_not_verify_is_restored(svc: Services, sim: FritzboxSim) -> None:
    await svc.runner.observe_all()
    p = plan(parse(WANT), svc.runner.network(), RULES, secret=svc.store.get_secret)
    d = Deployer(svc.runner)
    rec = await d.prepare(p, "harden the Wi-Fi", "tester")
    sim.ignore = {"SetAddressRange"}  # the box says yes but keeps the old range
    assert await deploy(d, rec.id) is ChangeStatus.ROLLED_BACK
    assert sim.lan == fritz_sim.LAN and sim.wlans == fritz_sim.WLANS
    assert sim.passphrases == fritz_sim.PASSPHRASES  # the backup put the old key back
    events = [e.event for e in svc.store.events(rec.id)]
    assert "verify-failed" in events and "rolled-back" in events


async def test_backup_object_is_plain_data(adapter: FritzboxAdapter) -> None:
    b = await adapter.backup()
    assert Backup.model_validate_json(b.model_dump_json()) == b


@pytest.mark.parametrize(
    ("service", "action", "args"),
    [
        ("LANHostConfigManagement1", "SetDHCPServerEnable", {"NewDHCPServerEnable": "yes"}),
        ("LANHostConfigManagement1", "SetAddressRange", {"NewMinAddress": "x"}),
        ("LANHostConfigManagement1", "SetIPRouter", {}),
        ("WLANConfiguration1", "SetSSID", {"NewSSID": "x" * 33}),
        ("WLANConfiguration1", "SetBeaconType", {"NewBeaconType": "WEP"}),
        ("WLANConfiguration1", "SetSecurityKeys", {"NewKeyPassphrase": "short"}),
        ("WLANConfiguration1", "SetEnable", {"NewEnable": "on"}),
        ("WLANConfiguration1", "X_AVM-DE_SetBeaconAdvertisement", {}),
    ],
)
async def test_simulator_checks_write_arguments(
    adapter: FritzboxAdapter, sim: FritzboxSim, service: str, action: str, args: dict[str, str]
) -> None:
    with pytest.raises(AdapterError, match=r"UPnP error 40[12]"):
        await adapter.tr064.call(service, action, **args)
    assert sim.writes == [] and sim.lan == fritz_sim.LAN and sim.wlans == fritz_sim.WLANS


async def test_dhcp_without_a_reported_range(
    adapter: FritzboxAdapter, monkeypatch: pytest.MonkeyPatch
) -> None:
    c = dhcp_change(await network(adapter), enabled=False, pool=None)

    async def no_range() -> dict[str, str]:
        return {"NewDHCPServerEnable": "1", "NewDNSServers": "192.0.2.1"}

    monkeypatch.setattr(adapter, "_lan_values", no_range)
    calls = await adapter.plan_changes([c], {})
    assert [x.target for x in calls] == ["LANHostConfigManagement1 SetDHCPServerEnable"]
