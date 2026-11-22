"""The Omada adapter against TP-Link's real Omada Software Controller in Docker (#140).

The controller (tools/integration/omada/controller.py) is set up through its own first-start
wizard and holds one site "Default" without any managed device (no gateway, switch or access
point can run in CI): the native network "Default" moved to 192.0.2.1/24 with DHCP
192.0.2.100-199, the VLAN-only networks IoT (20) and Guest (30), the interface network Lab
(40, 203.0.113.1/24, DHCP with two DNS servers, a day's lease), the port profile "IoT access",
and in the WLAN group "Default" the SSIDs Home (WPA2, PMF capable), IoT (hidden, 2.4 GHz,
VLAN 20) and Guest (open, VLAN 30). Two Open API applications: one with the Viewer role
(IT_OMADA_USER/PASSWORD), one with the Admin role (IT_OMADA_WRITE_*).

Without a gateway the controller itself owns the networks (``omada1/gateway``): router and
DHCP changes go through the Deployer like on any site. SSIDs belong to an access point in
Signalbox; with none on the controller, they are written through the adapter's write module
for a stand-in EAP and checked in the controller's own answers. Switch ports, radios and
clients need managed devices and stay simulator-only (tests/test_omada*.py).

Every write test ends with the controller as it started (revert or restore), so the tests can
run in any order against one controller.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from factories import SITE
from integration.conftest import Target
from signalbox.adapters import AdapterContext, AdapterError
from signalbox.adapters.https import fingerprint, peer_certificate
from signalbox.adapters.omada import PMF_MODES, OmadaAdapter, OmadaConfig, _security
from signalbox.adapters.omada.writes import Writer
from signalbox.changes import Change, ChangeKind, RouterValue, WlanValue, plan
from signalbox.deploy import Deployer
from signalbox.desired import parse
from signalbox.history import ChangeStatus, DeviceStatus
from signalbox.merge import merge
from signalbox.model import DeviceRole, Network, Pmf, Security, passphrase_fingerprint
from signalbox.model import DeviceStatus as ReadStatus
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.store import DeviceRecord
from signalbox.testing import assert_contract

DEV = "omada1"
NATIVE, IOT, GUEST, LAB = (f"home/segment/{v}" for v in ("native", 20, 30, 40))
TIMEOUT = 60.0
#: A stand-in for an access point of the site (there is none on the test controller).
EAP = f"{DEV}/eap-020000000c01"


@pytest.fixture(scope="session")
def ctrl(target: Callable[[str], Target]) -> dict[str, str]:
    t = target("omada")
    assert t.write_username and t.write_password and t.pin, "IT_OMADA_WRITE_* and PIN"
    return {
        "URL": t.url,
        "PIN": t.pin,
        "ID": t.username,
        "SECRET": t.password,
        "WRITE_ID": t.write_username,
        "WRITE_SECRET": t.write_password,
        **t.extra,
    }


def adapter(
    ctrl: dict[str, str],
    write: bool = False,
    pin: str | None = "",
    secret: str | None = None,
    site: str = "Default",
) -> OmadaAdapter:
    prefix = "WRITE_" if write else ""
    config = OmadaConfig(
        url=ctrl["URL"],
        site=site,
        client_id=ctrl[f"{prefix}ID"],
        client_secret=SecretStr(secret if secret is not None else ctrl[f"{prefix}SECRET"]),
    )
    ctx = AdapterContext(
        site_id="home",
        device_id=DEV,
        device_name="Omada",
        role=DeviceRole.OTHER,
        config=config,
        pinned_fingerprint=ctrl["PIN"] if pin == "" else pin,
        timeout=TIMEOUT,
    )
    return OmadaAdapter(ctx)


async def network(ctrl: dict[str, str]) -> Network:
    a = adapter(ctrl)
    try:
        return merge([SITE], [await a.observe()])
    finally:
        await a.close()


async def networks(ctrl: dict[str, str]) -> dict[int, dict[str, Any]]:
    """The LAN networks as the controller lists them, by VLAN, without derived values."""
    a = adapter(ctrl)
    try:
        await a.read_system()
        rows = await a._rows(f"{a._site_path}/lan-networks")
    finally:
        await a.close()
    out = {}
    for r in rows:
        dhcp = r.get("dhcpSettingsVO") or {}
        out[r["vlan"]] = {
            "name": r.get("name"),
            "purpose": r.get("purpose"),
            "gatewaySubnet": r.get("gatewaySubnet"),
            "dhcp": {k: v for k, v in dhcp.items() if k not in ("ipRangeStart", "ipRangeEnd")},
        }
    return out


async def ssids(ctrl: dict[str, str]) -> dict[str, dict[str, Any]]:
    """The SSIDs of the WLAN group with their details, by name."""
    a = adapter(ctrl)
    try:
        await a.read_system()
        _, primary = await a._wlan_groups()
        assert primary is not None
        return {s["name"]: s for s in await a._ssids(primary)}
    finally:
        await a.close()


# --- reading -------------------------------------------------------------------------------


async def test_certificate_pinning_with_the_real_certificate(ctrl: dict[str, str]) -> None:
    host = ctrl["URL"].split("://", 1)[1]
    name, port = host.rsplit(":", 1)
    seen = fingerprint(await peer_certificate(name, int(port), TIMEOUT))
    assert seen == ctrl["PIN"]
    for pin in (None, "00" * 32):
        a = adapter(ctrl, pin=pin)
        try:
            snap = await a.observe()
        finally:
            await a.close()
        assert snap.status is ReadStatus.UNTRUSTED, snap.errors
        assert seen in snap.errors[0].message


async def test_read_contract(ctrl: dict[str, str]) -> None:
    a = adapter(ctrl)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    assert snap.device.firmware is not None
    assert snap.device.firmware.current == ctrl["VERSION"], snap.device.firmware
    assert (snap.device.vendor, snap.device.model) == ("TP-Link", "Omada Controller")


async def test_mapping_of_the_test_site(ctrl: dict[str, str]) -> None:
    net = await network(ctrl)
    assert [d.id for d in net.devices] == [DEV]  # no managed devices
    assert net.ports == [] and net.radios == [] and net.wlans == [] and net.clients == []
    segs = {s.id: s for s in net.segments}
    assert {k: (s.name, s.vlan) for k, s in segs.items()} == {
        NATIVE: ("Default", None),
        IOT: ("IoT", 20),
        GUEST: ("Guest", 30),
        LAB: ("Lab", 40),
    }
    subnets = {(s.segment_id, str(s.interface), s.device_id, s.gateway) for s in net.subnets}
    assert subnets == {
        (NATIVE, "192.0.2.1/24", DEV, True),
        (LAB, "203.0.113.1/24", DEV, True),
    }  # the VLAN-only networks have no gateway address
    dhcp = {s.segment_id: s for s in net.dhcp_servers}
    assert set(dhcp) == {NATIVE, LAB}
    native = dhcp[NATIVE]
    assert native.enabled and native.lease_seconds == 120 * 60
    assert [(str(p.start), str(p.end)) for p in native.pools] == [("192.0.2.100", "192.0.2.199")]
    assert str(native.router) == "192.0.2.1"
    assert [str(a) for a in native.dns_servers] == ["192.0.2.1"]  # dhcpns auto: the gateway
    lab = dhcp[LAB]
    assert lab.enabled and lab.lease_seconds == 1440 * 60
    assert [(str(p.start), str(p.end)) for p in lab.pools] == [("203.0.113.100", "203.0.113.199")]
    assert [str(a) for a in lab.dns_servers] == ["203.0.113.1", "198.51.100.53"]


async def test_ssids_and_port_profiles(ctrl: dict[str, str]) -> None:
    """What the read side makes of the controller's SSIDs (it reports them per access point,
    so without one they are checked through the parser) and port profiles."""
    a = adapter(ctrl)
    try:
        await a.read_system()
        groups, primary = await a._wlan_groups()
        assert primary is not None and groups[primary] == "Default"
        rows = {s["name"]: s for s in await a._ssids(primary)}
        profiles = {p["name"]: p for p in await a._optional_rows(f"{a._site_path}/lan-profiles")}
        nets = {n.vlan: n.id for n in (await a._networks()).values()}
    finally:
        await a.close()
    assert set(rows) == {"Home", "IoT", "Guest"}
    home, iot, guest = rows["Home"], rows["IoT"], rows["Guest"]
    assert (_security(home), PMF_MODES[home["pmfMode"]], home["band"]) == (
        Security.WPA2,
        Pmf.OPTIONAL,
        3,
    )
    # the detail has the passphrase (the list does not): Signalbox keeps its fingerprint
    assert home["pskSetting"]["securityKey"] == "example-home-passphrase"
    assert (_security(iot), iot["broadcast"], iot["vlanEnable"], iot["vlanId"]) == (
        Security.WPA2,
        False,
        True,
        20,
    )
    assert PMF_MODES[iot["pmfMode"]] is Pmf.DISABLED
    assert (_security(guest), guest["vlanId"], "pmfMode" in guest) == (Security.OPEN, 30, False)
    assert all(s["ssidEnable"] is True for s in rows.values())
    assert profiles["IoT access"]["nativeNetworkId"] == nets[20]
    assert profiles["All"]["nativeNetworkId"] == nets[1]
    assert set(profiles["All"]["tagNetworkIds"]) == {nets[20], nets[30], nets[40]}


async def test_refused_secret_is_auth_failed(ctrl: dict[str, str]) -> None:
    a = adapter(ctrl, secret="not-the-secret")
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is ReadStatus.AUTH_FAILED, snap.errors
    assert "-44106" in snap.errors[0].message


async def test_unknown_site(ctrl: dict[str, str]) -> None:
    a = adapter(ctrl, site="Nowhere")
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert "no site 'Nowhere' (sites: Default)" in snap.errors[0].message


async def test_refused_token_is_renewed_once(ctrl: dict[str, str]) -> None:
    """The controller answers a token it does not know (expired or never issued) with
    -44112; the adapter asks for a new one and repeats the request."""
    a = adapter(ctrl)
    try:
        await a.read_system()
        path = f"{a._site_path}/lan-networks"
        renewed = []
        real = a._authorise

        async def counting() -> None:
            renewed.append(1)
            await real()

        a._authorise = counting  # type: ignore[method-assign]
        a._token = "AT-0000000000000000"
        rows = await a._rows(path)
        assert len(rows) == 4 and renewed == [1]
    finally:
        await a.close()
    async with httpx.AsyncClient(verify=False, trust_env=False, timeout=TIMEOUT) as client:
        r = await client.get(
            ctrl["URL"] + path + "?page=1&pageSize=10",
            headers={"Authorization": "AccessToken=AT-0000000000000000"},
        )
    assert r.json()["errorCode"] == -44112


async def test_viewer_role_cannot_write(ctrl: dict[str, str]) -> None:
    net = await network(ctrl)
    old = next(s for s in net.subnets if s.segment_id == LAB)
    c = Change(
        kind=ChangeKind.ROUTER,
        device_id=DEV,
        site_id="home",
        key=LAB,
        old=RouterValue(vlan=40, name="Lab", address=old.interface),
        new=RouterValue(vlan=40, name="Lab2", address=old.interface),
    )
    a = adapter(ctrl)
    try:
        with pytest.raises(AdapterError, match=r"-1007: .*\(changes need .* Admin role\)"):
            await a.apply([c], {}, 60)
    finally:
        await a.close()
    assert (await networks(ctrl))[40]["name"] == "Lab"


# --- writing through the Deployer ----------------------------------------------------------


@pytest.fixture
def svc(tmp_path: Path, ctrl: dict[str, str]) -> Iterator[Services]:
    env = {
        "SIGNALBOX_AUTH_PASSWORD": "x" * 12,
        "SIGNALBOX_DEPLOY_ENABLED": "true",
        "SIGNALBOX_OBSERVE_TIMEOUT_SECONDS": str(TIMEOUT),
    }
    s = build(tmp_path, env=env, adapters={"omada": OmadaAdapter}, rules=RULES, link_sources=[])
    s.store.put_site(SITE)
    rec = DeviceRecord(
        id=DEV,
        site_id="home",
        name="Omada",
        role=DeviceRole.OTHER,
        adapter="omada",
        allow_writes=True,
        pinned_fingerprint=ctrl["PIN"],
    )
    cfg = {"url": ctrl["URL"], "client_id": ctrl["WRITE_ID"]}
    cfg["client_secret"] = ctrl["WRITE_SECRET"]
    s.store.put_device(rec, cfg, OmadaConfig)
    yield s
    s.close()


def events(svc: Services, cid: str) -> list[str]:
    return [f"{e.event} {e.detail}" for e in svc.store.events(cid)]


async def deploy(svc: Services, want: str, kinds: set[ChangeKind]) -> tuple[Deployer, str]:
    await svc.runner.observe_all()
    p = plan(parse(want), svc.runner.network(), RULES)
    assert {c.kind for c in p.changes} == kinds, [c.describe() for c in p.changes]
    d = Deployer(svc.runner)
    rec = await d.prepare(p, "integration test", "ci")
    d.approve(rec.id, "ci", override="integration test" if rec.plan.blocking else None)
    done = await d.deploy(rec.id)
    assert done.status is ChangeStatus.APPLIED, events(svc, rec.id)
    assert done.devices[0].status is DeviceStatus.CONFIRMED
    assert plan(parse(want), svc.runner.network(), RULES).changes == []
    return d, rec.id


async def revert(svc: Services, d: Deployer, cid: str) -> None:
    back = await d.revert(cid, "integration test done", "ci")
    d.approve(back.id, "ci", override="integration test" if back.plan.blocking else None)
    done = await d.deploy(back.id)
    assert done.status is ChangeStatus.APPLIED, events(svc, back.id)


NEW_NETWORK = f"""
sites:
  home:
    segments:
      - vlan: 60
        name: Lab6
        gateway: {{device: {DEV}, address: 198.51.100.129/25}}
        dhcp:
          enabled: true
          pool: [198.51.100.130, 198.51.100.200]
          dns: [198.51.100.129]
          lease_seconds: 3600
"""


async def test_new_network_with_dhcp_then_revert(svc: Services, ctrl: dict[str, str]) -> None:
    before = await networks(ctrl)
    d, cid = await deploy(svc, NEW_NETWORK, {ChangeKind.ROUTER, ChangeKind.DHCP})
    after = await networks(ctrl)
    assert after[60]["name"] == "Lab6" and after[60]["purpose"] == 1
    assert after[60]["gatewaySubnet"] == "198.51.100.129/25"
    assert after[60]["dhcp"]["dhcpns"] == "auto" and after[60]["dhcp"]["leasetime"] == 60
    net = await network(ctrl)
    server = next(s for s in net.dhcp_servers if s.segment_id == "home/segment/60")
    assert [(str(p.start), str(p.end)) for p in server.pools] == [
        ("198.51.100.130", "198.51.100.200")
    ]
    await revert(svc, d, cid)
    assert await networks(ctrl) == before


CHANGE_EXISTING = f"""
sites:
  home:
    segments:
      - vlan: native
        gateway: {{device: {DEV}, address: 192.0.2.254/24}}
      - vlan: 40
        name: Lab
        gateway: {{device: {DEV}, address: 203.0.113.1/24}}
        dhcp:
          enabled: true
          pool: [203.0.113.150, 203.0.113.160]
          dns: [203.0.113.1]
          lease_seconds: 7200
"""


async def test_change_native_router_and_dhcp_then_revert(
    svc: Services, ctrl: dict[str, str]
) -> None:
    before = await networks(ctrl)
    d, cid = await deploy(svc, CHANGE_EXISTING, {ChangeKind.ROUTER, ChangeKind.DHCP})
    after = await networks(ctrl)
    assert after[1]["gatewaySubnet"] == "192.0.2.254/24" and after[1]["name"] == "Default"
    assert after[40]["dhcp"]["dhcpns"] == "auto" and "priDns" not in after[40]["dhcp"]
    assert (after[40]["dhcp"]["ipaddrStart"], after[40]["dhcp"]["leasetime"]) == (
        "203.0.113.150",
        120,
    )
    await revert(svc, d, cid)
    assert await networks(ctrl) == before


GUEST_ROUTER = f"""
sites:
  home:
    segments:
      - vlan: 30
        name: Guest
        gateway: {{device: {DEV}, address: 198.51.100.1/25}}
"""


async def test_vlan_only_network_gets_a_gateway_then_backup_restore(
    svc: Services, ctrl: dict[str, str]
) -> None:
    """VLAN only → interface; then the restore of the backup taken before (interface → VLAN
    only, the whole network in one PATCH)."""
    before = await networks(ctrl)
    _, cid = await deploy(svc, GUEST_ROUTER, {ChangeKind.ROUTER})
    after = await networks(ctrl)
    assert (after[30]["purpose"], after[30]["gatewaySubnet"]) == (1, "198.51.100.1/25")
    rec = svc.store.change(cid)
    assert rec is not None and rec.devices[0].backup_id
    backup = svc.store.backup(rec.devices[0].backup_id)
    assert backup is not None and backup.format == "omada-openapi-json"
    assert "example-home-passphrase" in backup.content  # stored encrypted, restorable
    d = Deployer(svc.runner)
    restore = await d.restore_backup(rec.devices[0].backup_id, "integration test", "ci")
    d.approve(restore.id, "ci")
    done = await d.deploy(restore.id)
    assert done.status is ChangeStatus.APPLIED, events(svc, restore.id)
    assert await networks(ctrl) == before


async def test_refusal_of_the_controller_names_the_code(ctrl: dict[str, str]) -> None:
    """A VLAN used twice: the controller's own check, its code and message in the error."""
    a = adapter(ctrl, write=True)
    try:
        await a.read_system()
        body = {"name": "Twice", "purpose": 0, "vlan": 20, "igmpSnoopEnable": False}
        with pytest.raises(AdapterError, match="-34517: This VLAN ID is already used"):
            await Writer(a).send("POST", f"{a._site_path}/lan-networks", body)
    finally:
        await a.close()
    assert set(await networks(ctrl)) == {1, 20, 30, 40}


# --- SSIDs through the write module --------------------------------------------------------


@pytest.fixture
def stand_in_eap(monkeypatch: pytest.MonkeyPatch) -> None:
    """The site's access point for the WLAN changes (the controller has none)."""
    from signalbox.adapters.omada import _Managed

    real = Writer._device

    async def device(self: Writer, change: Change, kind: str) -> _Managed | None:
        if kind == "eap" and change.device_id == EAP:
            return _Managed(
                mac="02:00:00:00:0c:01",
                raw_mac="02-00-00-00-0C-01",
                name="AP 1",
                kind="eap",
                model=None,
                firmware=None,
                wlan_id=None,
                slug="eap-020000000c01",
            )
        return await real(self, change, kind)

    monkeypatch.setattr(Writer, "_device", device)


async def apply(ctrl: dict[str, str], changes: list[Change], secrets: dict[str, str]) -> None:
    a = adapter(ctrl, write=True)
    try:
        await a.apply(changes, secrets, 60)
    finally:
        await a.close()


def wlan(ssid: str, old: WlanValue | None, new: WlanValue | None) -> Change:
    return Change(kind=ChangeKind.WLAN, device_id=EAP, site_id="home", key=ssid, old=old, new=new)


@pytest.mark.usefixtures("stand_in_eap")
async def test_ssid_create_change_disable_delete(ctrl: dict[str, str]) -> None:
    secrets = {"lab": "example-lab-passphrase", "lab2": "another-lab-passphrase"}
    new = WlanValue(
        ssid="Lab",
        security=Security.WPA2_WPA3,
        pmf=Pmf.REQUIRED,
        segment=20,
        passphrase_secret="lab",
    )
    await apply(ctrl, [wlan("Lab", None, new)], secrets)
    lab = (await ssids(ctrl))["Lab"]
    assert (lab["security"], lab["pskSetting"]["versionPsk"], lab["pmfMode"]) == (3, 4, 1)
    assert (lab["vlanEnable"], lab["vlanId"], lab["broadcast"], lab["band"]) == (True, 20, True, 3)
    assert lab["pskSetting"]["securityKey"] == "example-lab-passphrase"
    assert _security(lab) is Security.WPA2_WPA3

    changed = new.model_copy(
        update={
            "security": Security.WPA2,
            "pmf": Pmf.OPTIONAL,
            "hidden": True,
            "segment": "native",
            "passphrase_secret": "lab2",
        }
    )
    await apply(ctrl, [wlan("Lab", new, changed)], secrets)
    lab = (await ssids(ctrl))["Lab"]
    assert (lab["pskSetting"]["versionPsk"], lab["pmfMode"], lab["broadcast"]) == (2, 2, False)
    assert lab["vlanEnable"] is False and "vlanId" not in lab
    key = lab["pskSetting"]["securityKey"]
    assert passphrase_fingerprint("Lab", key) == passphrase_fingerprint(
        "Lab", "another-lab-passphrase"
    )

    off = changed.model_copy(update={"enabled": False, "passphrase_secret": None})
    await apply(ctrl, [wlan("Lab", changed, off)], secrets)
    lab = (await ssids(ctrl))["Lab"]
    assert lab["ssidEnable"] is False
    assert lab["pskSetting"]["securityKey"] == "another-lab-passphrase"  # kept

    await apply(ctrl, [wlan("Lab", off, None)], secrets)
    assert set(await ssids(ctrl)) == {"Home", "IoT", "Guest"}


@pytest.mark.usefixtures("stand_in_eap")
async def test_ssid_change_then_restore_of_the_backup(ctrl: dict[str, str]) -> None:
    """Home open and visible on VLAN 30, Guest deleted: the restore puts both back, the
    passphrase of Home included."""
    before = await ssids(ctrl)
    a = adapter(ctrl, write=True)
    try:
        backup = await a.backup()
    finally:
        await a.close()
    home = WlanValue(ssid="Home", security=Security.WPA2, pmf=Pmf.OPTIONAL)
    plain = WlanValue(ssid="Home", security=Security.OPEN, segment=30)
    guest = WlanValue(ssid="Guest", security=Security.OPEN, segment=30)
    await apply(ctrl, [wlan("Home", home, plain), wlan("Guest", guest, None)], {})
    now = await ssids(ctrl)
    assert set(now) == {"Home", "IoT"} and now["Home"]["security"] == 0
    assert "pskSetting" not in now["Home"]
    a = adapter(ctrl, write=True)
    try:
        await a.restore(backup)
    finally:
        await a.close()
    after = await ssids(ctrl)

    def basic(rows: dict[str, dict[str, Any]]) -> dict[str, Any]:
        keys = ("security", "pskSetting", "pmfMode", "broadcast", "vlanEnable", "vlanId", "band")
        return {n: {k: r.get(k) for k in keys} for n, r in rows.items()}

    assert basic(after) == basic(before)
    assert after["Home"]["ssidId"] == before["Home"]["ssidId"]  # changed back, not recreated


def test_controller_still_answers(ctrl: dict[str, str]) -> None:
    """Last: the controller survived the suite."""
    r = httpx.get(ctrl["URL"] + "/api/info", verify=False, timeout=TIMEOUT, trust_env=False)
    assert r.status_code == 200 and r.json()["result"]["configured"] is True
