"""ISC DHCP settings through the helper script of #242: the script, the adapter and the setup."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from types import TracebackType
from typing import Any

import asyncssh
import pytest
from pydantic import SecretStr

from signalbox.adapters import (
    AdapterContext,
    AdapterError,
    SetupRequest,
    StepState,
    UntrustedHostKey,
)
from signalbox.adapters.opnsense import ISC_SCRIPT, OpnsenseAdapter, OpnsenseConfig, isc_script
from signalbox.adapters.opnsense.provision import (
    AUTH_KEYS,
    SCRIPT_PATH,
    SCRIPT_TEXT,
    authorized_line,
)
from signalbox.adapters.ssh import PinnedSsh, ShellResult
from signalbox.model import DeviceRole, Dhcp6Mode, DhcpServer, RaMode
from signalbox.sim.opnsense import KEY, SECRET, OpnsenseSimulator
from signalbox.sim.opnsense_ssh import (
    ROOT_PASSWORD,
    SAMPLE_CONFIG,
    SECRETS,
    OpnsenseSsh,
    serve_ssh,
)
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve

SIM = OpnsenseSimulator()
HOST_KEY = "SHA256:" + "A" * 43


# --- the script ---------------------------------------------------------------------------------


def test_script_prints_only_the_listed_fields() -> None:
    out = isc_script.extract(SAMPLE_CONFIG)
    text = json.dumps(out)
    for secret in SECRETS:
        assert secret not in text
    for name in ("ddnsdomainkey", "descr", "cid", "ignored", "password", "wireguard", "psk"):
        assert name not in text
    assert sorted(out) == ["dhcpd", "dhcpdv6", "version"]
    lan = out["dhcpd"]["lan"]
    assert lan == {
        "enable": True,
        "range": {"from": "192.0.2.100", "to": "192.0.2.199"},
        "gateway": "192.0.2.1",
        "domain": "home.example",
        "dnsserver": ["192.0.2.53", "198.51.100.53"],
        "ntpserver": ["192.0.2.123"],
        "defaultleasetime": 3600,
        "maxleasetime": 7200,
        "failover_peerip": "192.0.2.2",
        "staticmap": [
            {"mac": "02:00:00:00:00:41", "ipaddr": "192.0.2.41", "hostname": "printer"},
            {"mac": "02:00:00:00:00:42", "ipaddr": "192.0.2.42", "hostname": "nas"},
        ],
    }
    assert out["dhcpd"]["opt3"]["enable"] is False  # no <enable>: not served
    assert out["dhcpdv6"]["lan"]["staticmap"] == [
        {"duid": "00:01:00:01:aa:bb:cc:dd", "ipaddrv6": "2001:db8::41", "hostname": "printer"}
    ]


def test_script_drops_values_that_are_not_what_they_claim_to_be() -> None:
    xml = """<opnsense><dhcpd><lan><enable/><gateway>hunter2-password</gateway>
      <dnsserver>S3CRET</dnsserver><domain>bad domain!</domain>
      <defaultleasetime>abc</defaultleasetime><range><from>1.2.3.4</from></range>
      <staticmap><mac>02:00:00:00:00:01</mac><hostname>only-name</hostname></staticmap>
      </lan><bad.name><enable/></bad.name></dhcpd></opnsense>"""
    out = isc_script.extract(xml)
    assert out["dhcpd"] == {
        "lan": {"enable": True, "dnsserver": [], "ntpserver": [], "staticmap": []}
    }
    assert out["dhcpdv6"] == {}
    assert "hunter2" not in json.dumps(out) and "S3CRET" not in json.dumps(out)
    assert isc_script.extract("<opnsense/>")["dhcpd"] == {}


def test_script_main(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "config.xml"
    config.write_text(SAMPLE_CONFIG)
    assert isc_script.main(str(config)) == 0
    printed = capsys.readouterr().out
    assert json.loads(printed)["version"] == 1 and not any(s in printed for s in SECRETS)
    config.write_text("<broken")
    assert isc_script.main(str(config)) == 1
    assert capsys.readouterr().err.strip() == "signalbox-isc-dhcp: ParseError"
    assert isc_script.main(str(tmp_path / "missing.xml")) == 1
    assert "FileNotFoundError" in capsys.readouterr().err


def test_script_runs_standalone_and_is_the_installed_file() -> None:
    file = Path(isc_script.__file__)
    assert file.read_text() == SCRIPT_TEXT and SCRIPT_TEXT.startswith("#!/usr/local/bin/python3\n")
    # run as a program, the way sshd runs it: without /conf/config.xml it fails quietly
    done = subprocess.run(
        [sys.executable, "-I", str(file)], capture_output=True, text=True, check=False
    )
    if not Path("/conf/config.xml").exists():
        assert done.returncode == 1 and done.stdout == ""
    # nothing but the standard library
    imports = {
        line.split()[1].split(".")[0]
        for line in SCRIPT_TEXT.splitlines()
        if line.startswith(("import ", "from "))
    }
    assert imports <= set(sys.stdlib_module_names) | {"__future__"}


# --- the adapter, with a fake SSH ---------------------------------------------------------------


@pytest.fixture(scope="module")
def http_url() -> Iterator[str]:
    with serve(SIM.app()) as url:
        yield url


@pytest.fixture(autouse=True)
def sim() -> OpnsenseSimulator:
    SIM.__dict__.update(OpnsenseSimulator().__dict__)
    return SIM


def private_key() -> str:
    return asyncssh.generate_private_key("ssh-ed25519").export_private_key().decode()


def config(url: str, **cfg: Any) -> OpnsenseConfig:
    return OpnsenseConfig(
        url=url,
        api_key=SecretStr(KEY),
        api_secret=SecretStr(SECRET),
        allow_insecure_http=url.startswith("http://"),
        **cfg,
    )


def adapter(url: str, **cfg: Any) -> OpnsenseAdapter:
    return OpnsenseAdapter(
        AdapterContext(
            site_id="home",
            device_id="fw",
            device_name="Firewall",
            role=DeviceRole.GATEWAY,
            config=config(url, **cfg),
            timeout=5.0,
        )
    )


class FakeSsh:
    """What ``OpnsenseAdapter._ssh`` returns in these tests."""

    def __init__(self, result: ShellResult | Exception) -> None:
        self.result = result
        self.commands: list[str] = []

    async def __aenter__(self) -> FakeSsh:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None

    async def command(self, command: str, timeout: float | None = None) -> ShellResult:
        self.commands.append(command)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def says(text: str, code: int = 0, err: str = "") -> ShellResult:
    return ShellResult(code=code, out=text.encode(), err=err)


async def guest_of(
    a: OpnsenseAdapter, fake: FakeSsh, monkeypatch: pytest.MonkeyPatch
) -> DhcpServer:
    monkeypatch.setattr(a, "_ssh", lambda: fake)
    try:
        snap = await a.observe()
    finally:
        await a.close()
    return next(s for s in snap.dhcp_servers if s.id == "fw/dhcp/isc-opt2")


@pytest.fixture
def key_cfg() -> dict[str, Any]:
    return {"isc_ssh_key": SecretStr(private_key()), "isc_ssh_host_key": HOST_KEY}


async def test_adapter_fills_the_isc_server_from_the_script(
    http_url: str, monkeypatch: pytest.MonkeyPatch, key_cfg: dict[str, Any]
) -> None:
    fake = FakeSsh(says(json.dumps(isc_script.extract(SAMPLE_CONFIG))))
    a = adapter(http_url, **key_cfg)
    monkeypatch.setattr(a, "_ssh", lambda: fake)
    snap = await a.observe()
    await a.close()
    assert fake.commands == [ISC_SCRIPT]
    ids = [s.id for s in snap.dhcp_servers]
    assert "fw/dhcp/isc-lan" not in ids  # Kea serves lan: Kea first
    guest = next(s for s in snap.dhcp_servers if s.id == "fw/dhcp/isc-opt2")
    assert [(str(p.start), str(p.end)) for p in guest.pools] == [("203.0.113.100", "203.0.113.150")]
    assert [str(x) for x in guest.dns_servers] == ["203.0.113.1"]
    assert guest.router is None and guest.ntp_servers == [] and guest.domain is None
    assert guest.lease_seconds == 7200 and guest.failover_peer is None
    assert [(r.mac, str(r.address), r.hostname) for r in guest.reservations] == [
        ("02:00:00:00:00:50", "203.0.113.50", "kiosk")
    ]
    assert guest.vendor_extra == {"server": "isc", "settings": "signalbox-isc-dhcp"}
    assert guest.leases  # the lease table is still read through the API


async def test_all_fields_of_an_interface(
    http_url: str, monkeypatch: pytest.MonkeyPatch, key_cfg: dict[str, Any]
) -> None:
    data = isc_script.extract(SAMPLE_CONFIG)
    data["dhcpd"]["opt2"] = data["dhcpd"]["lan"]
    guest = await guest_of(
        adapter(http_url, **key_cfg), FakeSsh(says(json.dumps(data))), monkeypatch
    )
    assert str(guest.router) == "192.0.2.1" and guest.domain == "home.example"
    assert [str(x) for x in guest.dns_servers] == ["192.0.2.53", "198.51.100.53"]
    assert [str(x) for x in guest.ntp_servers] == ["192.0.2.123"]
    assert guest.lease_seconds == 3600 and guest.failover_peer == "192.0.2.2"
    assert len(guest.reservations) == 2


@pytest.mark.parametrize(
    ("result", "why"),
    [
        (says("", code=1, err="signalbox-isc-dhcp: OSError"), "exited with status 1"),
        (says("not json"), "Expecting value"),
        (says('{"version": 2}'), "unexpected output"),
        (says('{"version": 1}'), "no dhcpd section"),
        (AdapterError("cannot open an SSH connection"), "cannot open"),
    ],
)
async def test_script_failures_keep_the_lease_only_read(
    http_url: str,
    monkeypatch: pytest.MonkeyPatch,
    key_cfg: dict[str, Any],
    result: ShellResult | Exception,
    why: str,
) -> None:
    guest = await guest_of(adapter(http_url, **key_cfg), FakeSsh(result), monkeypatch)
    assert not guest.pools and guest.leases
    note = guest.vendor_extra["note"]
    assert why in note and "could not be read over SSH" in note


async def test_without_a_key_nothing_is_read_over_ssh(
    http_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = adapter(http_url)

    def boom() -> None:
        raise AssertionError("no SSH without a key")

    monkeypatch.setattr(a, "_ssh", boom)
    snap = await a.observe()
    await a.close()
    guest = next(s for s in snap.dhcp_servers if s.id == "fw/dhcp/isc-opt2")
    assert not guest.pools and "optional helper script" in guest.vendor_extra["note"]


def test_config_rules(key_cfg: dict[str, Any]) -> None:
    config("https://192.0.2.1", **key_cfg)
    assert config("https://192.0.2.1", isc_ssh_key=SecretStr(" ")).isc_ssh_key is None
    # a key pasted into a one-line field (line breaks lost) is restored
    flat = " ".join(key_cfg["isc_ssh_key"].get_secret_value().split())
    cfg = config("https://192.0.2.1", isc_ssh_key=SecretStr(flat), isc_ssh_host_key="SHA256:x")
    assert cfg.isc_ssh_key is not None
    asyncssh.import_private_key(cfg.isc_ssh_key.get_secret_value())


# --- the setup and a real SSH connection --------------------------------------------------------


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> TlsFiles:
    return self_signed_certificate(tmp_path_factory.mktemp("tls"))


@pytest.fixture(scope="module")
def url(tls: TlsFiles) -> Iterator[str]:
    with serve(SIM.app(), tls=tls) as served:
        yield served


@pytest.fixture
def device() -> OpnsenseSsh:
    return OpnsenseSsh()


@pytest.fixture
async def ssh(device: OpnsenseSsh) -> AsyncIterator[tuple[int, str]]:
    async with serve_ssh(device) as served:
        yield served


def request(url: str, tls: TlsFiles, ssh: tuple[int, str] | None, **kw: Any) -> SetupRequest:
    extra: dict[str, Any] = {}
    if ssh is not None:
        extra = {
            "ssh_step": True,
            "ssh_secret": SecretStr(ROOT_PASSWORD),
            "ssh_port": ssh[0],
            "ssh_trust": kw.pop("ssh_trust", ssh[1]),
        }
    return SetupRequest(
        config={"url": url},
        admin_user=KEY,
        admin_secret=SecretStr(SECRET),
        trust=tls.fingerprint,
        timeout=10,
        **extra,
        **kw,
    )


async def test_ssh_host_key_is_confirmed_before_the_password_is_sent(
    url: str, tls: TlsFiles, ssh: tuple[int, str], device: OpnsenseSsh, sim: OpnsenseSimulator
) -> None:
    plan = await OpnsenseAdapter.plan_setup(request(url, tls, ssh, ssh_trust=None))
    assert plan.trusted and plan.ssh_trusted is False and plan.ssh_fingerprint == ssh[1]
    assert plan.steps == [] and "ssh-keygen" in plan.ssh_compare and device.scripts == []
    with pytest.raises(UntrustedHostKey):
        await OpnsenseAdapter.apply_setup(request(url, tls, ssh, ssh_trust="SHA256:" + "B" * 43))
    assert [u["name"] for u in sim.accounts.users] == ["root"] and device.files == {}


async def test_not_ticked_touches_no_ssh(
    url: str, tls: TlsFiles, ssh: tuple[int, str], device: OpnsenseSsh
) -> None:
    result = await OpnsenseAdapter.apply_setup(request(url, tls, None))
    assert result.ok and set(result.settings) == {"url"} and "isc_ssh_key" not in result.secrets
    plan = await OpnsenseAdapter.plan_setup(request(url, tls, None))
    assert plan.ssh_trusted is None and [s.id for s in plan.steps] == ["user", "privileges", "key"]
    assert device.scripts == [] and device.files == {}


async def read_guest(http_url: str, **cfg: Any) -> DhcpServer:
    """The ISC server as the adapter reads it (over plain http; the SSH host is 127.0.0.1)."""
    a = adapter(http_url, **cfg)
    try:
        snap = await a.observe()
    finally:
        await a.close()
    return next(s for s in snap.dhcp_servers if s.id == "fw/dhcp/isc-opt2")


async def test_install_read_reinstall_and_remove(
    http_url: str, url: str, tls: TlsFiles, ssh: tuple[int, str], device: OpnsenseSsh
) -> None:
    plan = await OpnsenseAdapter.plan_setup(request(url, tls, ssh))
    ids = [s.id for s in plan.steps]
    assert plan.ssh_trusted and ids == ["user", "privileges", "key", "isc-script", "isc-key"]
    assert device.files == {}  # a plan changes nothing

    result = await OpnsenseAdapter.apply_setup(request(url, tls, ssh))
    assert result.ok, result.steps
    assert device.files[SCRIPT_PATH] == SCRIPT_TEXT and device.modes[SCRIPT_PATH] == "0755"
    assert device.modes[AUTH_KEYS] == "600"
    (line,) = device.key_lines()
    assert line.startswith(f'command="{SCRIPT_PATH}",restrict ssh-ed25519 ')
    assert result.settings["isc_ssh_host_key"] == ssh[1]
    assert result.settings["isc_ssh_port"] == ssh[0]
    private = result.secrets["isc_ssh_key"].get_secret_value()
    # nothing secret was sent in clear or shown
    shown = json.dumps([s.model_dump() for s in result.steps])
    for secret in (ROOT_PASSWORD, private, *private.splitlines()[1:-2]):
        assert secret not in shown and not any(secret in text for text in device.scripts)

    # the adapter, configured from the result, reads the settings over real SSH
    cfg = {
        "isc_ssh_key": result.secrets["isc_ssh_key"],
        "isc_ssh_host_key": result.settings["isc_ssh_host_key"],
        "isc_ssh_port": result.settings["isc_ssh_port"],
    }
    guest = await read_guest(http_url, **cfg)
    assert [(str(p.start), str(p.end)) for p in guest.pools] == [("203.0.113.100", "203.0.113.150")]
    assert device.ran == [SCRIPT_PATH]
    for secret in SECRETS:
        assert secret not in guest.model_dump_json()

    # no host key configured: the key is not used either
    nopin = await read_guest(http_url, isc_ssh_key=cfg["isc_ssh_key"])
    assert not nopin.pools and "could not be read over SSH" in nopin.vendor_extra["note"]
    assert device.ran == [SCRIPT_PATH]

    # a wrong host key: the key is not used
    wrong = await read_guest(http_url, **{**cfg, "isc_ssh_host_key": "SHA256:" + "C" * 43})
    assert not wrong.pools and "could not be read over SSH" in wrong.vendor_extra["note"]
    assert device.ran == [SCRIPT_PATH]

    # again: the script is unchanged, the key is replaced (one line only)
    again = await OpnsenseAdapter.plan_setup(request(url, tls, ssh))
    assert again.steps[3].state is StepState.UNCHANGED and again.steps[4].state is StepState.TODO
    second = await OpnsenseAdapter.apply_setup(request(url, tls, ssh))
    assert second.ok and len(device.key_lines()) == 1 and device.key_lines()[0] != line
    assert not (await read_guest(http_url, **cfg)).pools  # the first key no longer works
    # other keys in the file stay
    device.files[AUTH_KEYS] += "ssh-ed25519 AAAAother admin@example\n"
    await OpnsenseAdapter.apply_setup(request(url, tls, ssh))
    assert (
        any(k.endswith("admin@example") for k in device.key_lines())
        and len(device.key_lines()) == 2
    )

    gone_plan = await OpnsenseAdapter.plan_setup(request(url, tls, ssh, remove=True))
    assert [s.state for s in gone_plan.steps[1:]] == [StepState.TODO, StepState.TODO]
    gone = await OpnsenseAdapter.apply_setup(request(url, tls, ssh, remove=True))
    assert gone.ok and SCRIPT_PATH not in device.files
    assert device.key_lines() == ["ssh-ed25519 AAAAother admin@example"]
    twice = await OpnsenseAdapter.plan_setup(request(url, tls, ssh, remove=True))
    assert [s.state for s in twice.steps[1:]] == [StepState.UNCHANGED, StepState.UNCHANGED]


async def test_setup_errors(
    url: str, tls: TlsFiles, ssh: tuple[int, str], device: OpnsenseSsh
) -> None:
    device.python = False
    with pytest.raises(AdapterError, match="python3 is missing"):
        await OpnsenseAdapter.plan_setup(request(url, tls, ssh))
    device.python = True
    with pytest.raises(AdapterError, match="SSH password"):
        await OpnsenseAdapter.plan_setup(
            SetupRequest(
                config={"url": url}, admin_user=KEY, admin_secret=SecretStr(SECRET), ssh_step=True
            )
        )
    # a failing install stops and is reported
    real = device.run
    device.run = lambda script: (  # type: ignore[method-assign]
        (1, b"", "disk full") if script.startswith("set -e\ncat >") else real(script)
    )
    result = await OpnsenseAdapter.apply_setup(request(url, tls, ssh))
    assert not result.ok and "disk full" in result.steps[3].message
    assert result.steps[4].state is StepState.SKIPPED and not result.secrets
    device.inspect = lambda: "garbage"  # type: ignore[method-assign]
    with pytest.raises(AdapterError, match="did not answer like OPNsense"):
        await OpnsenseAdapter.plan_setup(request(url, tls, ssh))


async def test_forced_command_runs_whatever_is_asked(
    url: str, tls: TlsFiles, ssh: tuple[int, str], device: OpnsenseSsh
) -> None:
    result = await OpnsenseAdapter.apply_setup(request(url, tls, ssh))
    async with PinnedSsh(
        "127.0.0.1",
        ssh[0],
        "root",
        "",
        ssh[1],
        5,
        private_key=result.secrets["isc_ssh_key"].get_secret_value(),
    ) as conn:
        out = await conn.command("cat /conf/config.xml")
    assert json.loads(out.text)["version"] == 1 and "S3CRET" not in out.text
    assert device.ran == [SCRIPT_PATH]


def test_authorized_line_forces_the_command() -> None:
    line = authorized_line("ssh-ed25519 AAAA")
    assert line == f'command="{SCRIPT_PATH}",restrict ssh-ed25519 AAAA signalbox-isc-dhcp'


def test_script_prints_router_advertisement_settings_of_dhcpdv6_only() -> None:
    lan = isc_script.extract(SAMPLE_CONFIG)["dhcpdv6"]["lan"]
    assert lan["ramode"] == "assist" and lan["radnsserver"] == ["2001:db8::53"]
    xml = """<opnsense><dhcpd><lan><ramode>managed</ramode></lan></dhcpd><dhcpdv6><lan>
      <ramode>S3CRET</ramode><radnsserver>not-an-address</radnsserver><ranodefault/>
      <radomainsearchlist>home.example bad!name</radomainsearchlist></lan></dhcpdv6></opnsense>"""
    out = isc_script.extract(xml)
    assert "ramode" not in out["dhcpd"]["lan"]
    assert out["dhcpdv6"]["lan"]["ranodefault"] is True
    assert out["dhcpdv6"]["lan"]["radomainsearchlist"] == ["home.example"]
    assert "ramode" not in out["dhcpdv6"]["lan"] and "S3CRET" not in json.dumps(out)


async def test_adapter_reads_router_advertisements_and_dhcpv6(
    http_url: str, monkeypatch: pytest.MonkeyPatch, key_cfg: dict[str, Any]
) -> None:
    fake = FakeSsh(says(json.dumps(isc_script.extract(SAMPLE_CONFIG))))
    a = adapter(http_url, **key_cfg)
    monkeypatch.setattr(a, "_ssh", lambda: fake)
    snap = await a.observe()
    await a.close()
    assert fake.commands == [ISC_SCRIPT]  # one run for the DHCPv4 and the IPv6 settings
    [ra] = snap.router_adverts
    assert ra.id == "fw/ra/lan" and ra.mode is RaMode.STATEFUL and ra.managed and ra.other
    assert [str(x) for x in ra.rdnss] == ["2001:db8::53"]
    [server] = [s for s in snap.dhcp6_servers if s.id == "fw/dhcp6/isc-lan"]
    assert server.mode is Dhcp6Mode.STATEFUL and server.lease_seconds == 7200
    assert [(str(p.start), str(p.end)) for p in server.pools] == [
        ("2001:db8::100", "2001:db8::1ff")
    ]
