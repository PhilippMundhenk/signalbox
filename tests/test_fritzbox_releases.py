"""The Fritz!Box adapter against older FRITZ!OS releases (#413): 7.29 and 6.83.

``FritzboxSim(release=...)`` serves the descriptions of that release, without the actions and
answer arguments it lacks. The adapter reads what is there, falls back where it can and never
fails the whole read for a missing action.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext, AdapterError
from signalbox.adapters.fritzbox import FritzboxAdapter, FritzboxConfig, fritzos_release
from signalbox.adapters.fritzbox.soap import login_page_version
from signalbox.changes import Change, ChangeKind, observed_wlan
from signalbox.model import DeviceRole, DeviceStatus, Network
from signalbox.sim import tr064
from signalbox.sim.fritzbox import FritzboxSim, create_app
from signalbox.sim.server import serve
from signalbox.testing import assert_contract
from test_fritzbox_scpd import problems

RELEASES = ["6.83", "7.29"]


@pytest.fixture(scope="module", params=RELEASES)
def box(request: pytest.FixtureRequest) -> Iterator[tuple[FritzboxSim, str]]:
    sim = FritzboxSim(release=request.param)
    with serve(create_app(sim)) as url:
        yield sim, url


def _adapter(sim: FritzboxSim, url: str, username: str | None = None) -> FritzboxAdapter:
    return FritzboxAdapter(
        AdapterContext(
            site_id="home",
            device_id="fb",
            device_name="Fritz!Box",
            role=DeviceRole.GATEWAY,
            config=FritzboxConfig(
                url=url,
                username=sim.username if username is None else username,
                password=SecretStr(sim.password),
                allow_insecure_http=True,
            ),
        )
    )


@pytest.fixture
async def adapter(box: tuple[FritzboxSim, str]) -> AsyncIterator[FritzboxAdapter]:
    sim, url = box
    sim.reset()
    a = _adapter(sim, url)
    yield a
    await a.close()


def test_release_selects_the_descriptions() -> None:
    assert FritzboxSim(release="6.83").version == "fritzos-6.83"
    assert FritzboxSim(release="7.29").fritzos == (7, 29)
    assert FritzboxSim(release="6.83").fritzos == (6, 83)
    with pytest.raises(ValueError, match="unknown release"):
        FritzboxSim(release="5.50")
    for name in tr064.OLDER:
        assert tr064.load(name).services


def test_older_descriptions_lack_what_came_later() -> None:
    old, mid = tr064.load("fritzos-6.83"), tr064.load("fritzos-7.29")
    users = "/upnp/control/lanconfigsecurity"
    assert "X_AVM-DE_GetUserList" in mid.services[users].actions
    assert "X_AVM-DE_GetUserList" not in old.services[users].actions
    assert "X_AVM-DE_GetWLANExtInfo" not in old.services["/upnp/control/wlanconfig1"].actions
    # the real 7.29 files have no default-password flag and no frequency band in GetInfo
    outputs = {a.name for a in mid.services[users].actions["GetInfo"].outputs}
    assert "NewX_AVM-DE_IsDefaultPasswordActive" not in outputs


@pytest.mark.parametrize(
    ("text", "release"),
    [
        ("154.07.57", (7, 57)),
        ("113.06.83", (6, 83)),
        ("7.29", (7, 29)),
        ("256.07.29-92446", (7, 29)),
        ("", None),
        (None, None),
        ("abc", None),
        ("8", None),
    ],
)
def test_fritzos_release(text: str | None, release: tuple[int, int] | None) -> None:
    assert fritzos_release(text) == release


async def test_contract_and_system(box: tuple[FritzboxSim, str], adapter: FritzboxAdapter) -> None:
    sim, _ = box
    snap = await assert_contract(adapter)
    assert snap.status is DeviceStatus.OK, snap.errors
    assert snap.device.firmware is not None
    assert snap.device.firmware.current == sim.description.value("Display")
    assert len(snap.wlans) == 3 and len(snap.radios) == 2
    guest = [w for w in snap.wlans if w.ssid == "Example-Guest"]
    assert guest and guest[0].segment_id.endswith("guest")  # found without X_AVM-DE_GetWLANExtInfo
    assert snap.dhcp_servers and snap.clients
    assert snap.uplinks and snap.firewalls[0].port_forwards


async def test_every_call_is_described_by_the_release(
    box: tuple[FritzboxSim, str], adapter: FritzboxAdapter
) -> None:
    sim, _ = box
    desc = tr064.load(sim.version)
    await adapter.observe()
    backup = await adapter.backup()
    dhcp, wireless = await adapter.read_dhcp(), await adapter.read_wireless()
    net = Network(dhcp_servers=dhcp.dhcp_servers, radios=wireless.radios, wlans=wireless.wlans)
    old = observed_wlan(net, "fb", "Example")
    assert old is not None
    result = await adapter.apply(
        [
            Change(
                kind=ChangeKind.WLAN,
                device_id="fb",
                site_id="home",
                key="Example",
                old=old,
                new=old.model_copy(update={"hidden": True}),
            )
        ],
        {},
        60,
    )
    assert result.calls
    await adapter.restore(backup)
    assert problems(desc, sim.calls) == []


async def test_missing_actions_are_tolerated(
    box: tuple[FritzboxSim, str], adapter: FritzboxAdapter
) -> None:
    sim, _ = box
    sim.ext_info = sim.host_list = sim.beacon_advertisement = False
    sim.lan.update(NewIPRouters="", NewSubnetMask="", NewMinAddress="", NewMaxAddress="")
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.OK, snap.errors
    assert [e for e in snap.errors if not e.optional] == []


async def test_old_release_names_the_missing_user_list() -> None:
    sim = FritzboxSim(release="6.83")
    with serve(create_app(sim)) as url:
        a = _adapter(sim, url)
        try:
            snap = await a.observe()
        finally:
            await a.close()
    assert snap.status is DeviceStatus.OK, snap.errors
    assert snap.device.accounts is None
    (gap,) = [e for e in snap.errors if e.message.startswith("accounts")]
    assert gap.optional and gap.message_id == "fritzbox.accountsOld"
    assert "6.83" in gap.message
    assert snap.device.default_credentials is None


async def test_7_29_has_the_user_list_but_no_default_password_flag() -> None:
    sim = FritzboxSim(release="7.29")
    with serve(create_app(sim)) as url:
        a = _adapter(sim, url)
        try:
            snap = await a.observe()
        finally:
            await a.close()
    assert [x.name for x in snap.device.accounts or []] == ["fritz0000", "signalbox"]
    assert snap.device.default_credentials is None
    assert not [e for e in snap.errors if e.message.startswith("accounts")]


def test_wpa3_only_from_7_20() -> None:
    assert "11iandWPA3" in FritzboxSim(release="7.29").offered_beacon_types
    old = FritzboxSim(release="6.83")
    assert "11iandWPA3" not in old.offered_beacon_types
    assert old.wlans[1]["NewBeaconType"] == "11i"
    old.reset()
    assert old.wlans[1]["NewBeaconType"] == "11i"  # reset keeps the release


# login page ------------------------------------------------------------------------------


def test_login_page_version() -> None:
    assert login_page_version(FritzboxSim(release="6.83").login_page().encode()) == 1
    assert login_page_version(FritzboxSim(release="7.29").login_page().encode()) == 2


@pytest.mark.parametrize("strict", [False, True])
async def test_password_only_on_old_box_keeps_the_empty_user_error(strict: bool) -> None:
    """Before 7.24 the login page has no user list (version 1 fallback): the empty name stays
    and the error says why."""
    sim = FritzboxSim(release="6.83", password_only=True, strict_login_version=strict)
    with serve(create_app(sim)) as url:
        a = _adapter(sim, url, username="")
        try:
            with pytest.raises(AdapterError) as exc:
                await a.read_system()
        finally:
            await a.close()
    assert exc.value.message_id == "fritzbox.noUserNameOld"
    assert exc.value.fix_id == "fritzbox.noUserNameOld.fix"
    assert "dslf-config" in (exc.value.fix or "")
    assert sim.password not in str(exc.value) + (exc.value.fix or "")


async def test_password_only_on_7_29_looks_the_user_up() -> None:
    sim = FritzboxSim(release="7.29", password_only=True)
    with serve(create_app(sim)) as url:
        a = _adapter(sim, url, username="")
        try:
            snap = await a.observe()
        finally:
            await a.close()
    assert snap.status is DeviceStatus.OK, snap.errors
