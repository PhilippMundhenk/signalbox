"""The Fritz!Box adapter and simulator against AVM's TR-064 descriptions (tests/fixtures/tr064).

Every action the adapter sends, with every argument, must exist in the SCPD of its service
with a valid value; every output argument it reads must be described there. The check is
independent of the simulator's own validation, runs for each FRITZ!OS version whose
descriptions are in the fixtures, and covers every action name in the adapter's source.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Iterator
from ipaddress import ip_address
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext
from signalbox.adapters.fritzbox import FritzboxAdapter, FritzboxConfig
from signalbox.adapters.fritzbox.soap import SERVICES, envelope
from signalbox.changes import Change, ChangeKind, observed_dhcp, observed_wlan
from signalbox.model import DeviceRole, DeviceStatus, Network, Security
from signalbox.sim import tr064
from signalbox.sim.fritzbox import FritzboxSim, create_app
from signalbox.sim.server import serve
from signalbox.sim.tr064 import ArgumentError, Description, StateVariable

ADAPTER = Path(__file__).parents[1] / "src" / "signalbox" / "adapters" / "fritzbox"
#: ``.call(service, "Action"`` and ``._try(...)`` in the adapter, ``Call(...)`` in write.py
_CALL = re.compile(r'(?:\.call\(|Call\(|\._try\()\s*[\w.\[\]"-]+,\s*"([\w-]+)"', re.S)
#: Output argument names the adapter reads (``"NewSSID"``...)
_NEW = re.compile(r'"(New[\w-]+)"')


def _service(desc: Description, adapter_service: str) -> tr064.Service:
    service_type, control = SERVICES[adapter_service]
    described = desc.services.get(control)
    assert described is not None, f"{adapter_service}: {control} is not in tr64desc.xml"
    assert described.service_type == service_type
    return described


def problems(desc: Description, calls: list[tuple[str, str, dict[str, str]]]) -> list[str]:
    """Calls (``WLANConfiguration:1``, action, args) that do not match the description."""
    found = []
    for name, action, args in calls:
        service = next((s for s in desc.services.values() if s.name == name), None)
        if service is None:
            found.append(f"{name}: no such service")
            continue
        described = service.actions.get(action)
        if described is None:
            found.append(f"{name} {action}: no such action")
            continue
        try:
            described.check_inputs(args)
        except ArgumentError as exc:
            found.append(f"{name} {action}: {exc}")
    return found


def source_actions() -> set[str]:
    return {m for f in ADAPTER.glob("*.py") for m in _CALL.findall(f.read_text())}


def source_arguments() -> set[str]:
    return {m for f in ADAPTER.glob("*.py") for m in _NEW.findall(f.read_text())}


@pytest.fixture(scope="module", params=tr064.VERSIONS)
def box(request: pytest.FixtureRequest) -> Iterator[tuple[FritzboxSim, str]]:
    sim = FritzboxSim(version=request.param)
    with serve(create_app(sim)) as url:
        yield sim, url


@pytest.fixture
async def adapter(box: tuple[FritzboxSim, str]) -> AsyncIterator[FritzboxAdapter]:
    sim, url = box
    sim.reset()
    a = FritzboxAdapter(
        AdapterContext(
            site_id="home",
            device_id="fb",
            device_name="Fritz!Box",
            role=DeviceRole.GATEWAY,
            config=FritzboxConfig(
                url=url,
                username=sim.username,
                password=SecretStr(sim.password),
                allow_insecure_http=True,
            ),
        )
    )
    yield a
    await a.close()


def _change(net: Network, kind: ChangeKind, key: str, **update: object) -> Change:
    old = (
        observed_wlan(net, "fb", key) if kind is ChangeKind.WLAN else observed_dhcp(net, "fb", key)
    )
    assert old is not None
    return Change(
        kind=kind,
        device_id="fb",
        site_id="home",
        key=key,
        old=old,
        new=old.model_copy(update=update),
    )


async def _network(a: FritzboxAdapter) -> Network:
    dhcp, wireless = await a.read_dhcp(), await a.read_wireless()
    return Network(dhcp_servers=dhcp.dhcp_servers, radios=wireless.radios, wlans=wireless.wlans)


async def test_every_call_of_the_adapter_is_described(
    box: tuple[FritzboxSim, str], adapter: FritzboxAdapter
) -> None:
    """Read, every write, restore and the fallbacks: all calls against the SCPD."""
    sim, _ = box
    desc = tr064.load(sim.version)  # parsed again, independent of the simulator's copy
    sim.mesh = True  # the mesh list (#171) is only called on a box that has a mesh
    assert (await adapter.observe()).status is DeviceStatus.OK
    backup = await adapter.backup()
    net = await _network(adapter)
    changes = [
        _change(
            net,
            ChangeKind.DHCP,
            "home/segment/native",
            enabled=False,
            pool=(ip_address("192.0.2.30"), ip_address("192.0.2.40")),
        ),
        _change(net, ChangeKind.WLAN, "Example", security=Security.OPEN, hidden=True),
        _change(
            net,
            ChangeKind.WLAN,
            "Example-Guest",
            ssid="Renamed",
            enabled=False,
            passphrase_secret="psk",
        ),
    ]
    result = await adapter.apply(changes, {"psk": "a brand new passphrase"}, 60)
    assert result.calls
    open_beacon = sim.wlans[1]["NewBeaconType"]
    assert open_beacon.lower() == "none"
    assert open_beacon == sim.beacon_spelling("none")  # the spelling of this FRITZ!OS
    await adapter.restore(backup)
    # fallbacks of older FRITZ!OS and sparse answers
    sim.ext_info = sim.host_list = sim.beacon_advertisement = False
    sim.lan.update(NewIPRouters="", NewSubnetMask="", NewMinAddress="", NewMaxAddress="")
    await adapter.observe()
    # behind another router over LAN 1 (#375): the address only from GetExternalIPAddress
    sim.behind("192.0.2.20", "192.0.2.1", "198.51.100.1")
    await adapter.observe()
    assert problems(desc, sim.calls) == []
    called = {action for _, action, _ in sim.calls}
    served = {service for service, _, _ in sim.calls}  # management services (#173)
    for name in ("RemoteAccess", "MyFritz", "Storage", "UPnP"):
        assert f"urn:dslforum-org:service:X_AVM-DE_{name}:1" in served or any(
            name in x for x in served
        ), served
    assert source_actions() <= called, "an action of the adapter was not exercised"


def test_the_adapter_source_names_only_described_actions_and_arguments() -> None:
    for version in tr064.VERSIONS:
        desc = tr064.load(version)
        services = {name: _service(desc, name) for name in SERVICES if name != "WLANConfiguration4"}
        actions = {a for s in services.values() for a in s.actions}
        arguments = {
            arg.name
            for s in services.values()
            for a in s.actions.values()
            for arg in (*a.inputs, *a.outputs)
        }
        assert source_actions() - actions == set(), version
        assert source_arguments() - arguments == set(), version


def test_a_wrong_name_is_found() -> None:
    desc = tr064.load()
    assert problems(
        desc,
        [
            ("WLANConfiguration:1", "X_AVM-DE_GetBeaconAdvertisement", {}),
            ("WLANConfiguration:1", "SetEnable", {"Enable": "1"}),
            ("WLANConfiguration:1", "SetBeaconType", {"NewBeaconType": "WEP"}),
            ("Hosts:1", "GetGenericHostEntry", {"NewIndex": "70000"}),
            ("Nothing:1", "GetInfo", {}),
            ("WLANConfiguration:1", "SetEnable", {"NewEnable": "1"}),
        ],
    ) == [
        "WLANConfiguration:1 X_AVM-DE_GetBeaconAdvertisement: no such action",
        "WLANConfiguration:1 SetEnable: SetEnable: missing ['NewEnable'], unknown ['Enable']",
        "WLANConfiguration:1 SetBeaconType: BeaconType: 'WEP' is not one of "
        + ", ".join(
            desc.services["/upnp/control/wlanconfig1"]
            .actions["SetBeaconType"]
            .inputs[0]
            .variable.allowed
        ),
        "Hosts:1 GetGenericHostEntry: HostNumberOfEntries: 70000 is out of range 0..65535",
        "Nothing:1: no such service",
    ]


def test_state_variable_checks() -> None:
    assert StateVariable("x", "boolean").check("true") is None
    for variable, value, code in [
        (StateVariable("x", "boolean"), "on", 600),
        (StateVariable("x", "ui1"), "-1", 601),
        (StateVariable("x", "ui1"), "1.5", 600),
        (StateVariable("x", "ui2", minimum=1, maximum=3), "4", 601),
        (StateVariable("x", "string", ("a", "b")), "c", 600),
    ]:
        with pytest.raises(ArgumentError) as info:
            variable.check(value)
        assert info.value.code == code


def test_missing_descriptions(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="part of the source tree"):
        tr064.load(tmp_path)
    (tmp_path / "tr64desc.xml").write_bytes(
        (tr064.FIXTURES / tr064.VERSIONS[0] / "tr64desc.xml").read_bytes()
    )
    assert tr064.load(tmp_path).services == {}  # no SCPD files: no services


async def test_descriptions_are_served_without_authentication(
    box: tuple[FritzboxSim, str],
) -> None:
    sim, url = box
    async with httpx.AsyncClient(base_url=url, trust_env=False) as client:
        desc = await client.get("/tr64desc.xml")
        assert desc.status_code == 200 and b"urn:dslforum-org:device-1-0" in desc.content
        assert desc.content == (tr064.FIXTURES / sim.version / "tr64desc.xml").read_bytes()
        scpd = await client.get("/wlanconfigSCPD.xml")
        assert scpd.status_code == 200 and b"<name>SetBeaconAdvertisement</name>" in scpd.content
        assert (await client.get("/nothingSCPD.xml")).status_code == 404
        challenge = await client.post("/upnp/control/deviceinfo")
        assert challenge.status_code == 401
        header = challenge.headers["www-authenticate"]
        assert re.fullmatch(
            r'Digest realm="F!Box SOAP-Auth",nonce="[0-9A-F]{16}",algorithm=MD5,qop="auth"', header
        )


async def test_described_but_not_simulated_action(box: tuple[FritzboxSim, str]) -> None:
    sim, url = box
    async with httpx.AsyncClient(
        base_url=url, trust_env=False, auth=httpx.DigestAuth(sim.username, sim.password)
    ) as client:
        response = await client.post(
            "/upnp/control/wlanconfig1",
            content=envelope("urn:dslforum-org:service:WLANConfiguration:1", "GetSSID", {}),
            headers={"SOAPAction": "urn:dslforum-org:service:WLANConfiguration:1#GetSSID"},
        )
    assert response.status_code == 500 and b"<errorCode>501</errorCode>" in response.content


def test_simulator_answers_must_match_the_description() -> None:
    action = tr064.load().services["/upnp/control/deviceinfo"].actions["GetSecurityPort"]
    with pytest.raises(AssertionError, match="answers"):
        action.check_outputs({})
    with pytest.raises(AssertionError, match="not an integer"):
        action.check_outputs({"NewSecurityPort": "x"})
