"""Dynamic DNS on Linux: ddclient and inadyn (#450), and the optional name resolution."""

from __future__ import annotations

import logging
import subprocess
from ipaddress import IPv4Address, ip_address

import pytest

from factories import uplink
from signalbox.adapters.linux import collect, ddns
from signalbox.adapters.linux.collect import split
from signalbox.adapters.linux.setup import sudoers
from signalbox.config import Config
from signalbox.ddns_resolve import apply, hostnames, resolve_names
from signalbox.model import DdnsResult, DynamicDns, Network, object_id
from signalbox.rules import evaluate
from signalbox.rules.multiwan import mismatch
from signalbox.sim.linux import _files
from test_linux import adapter_for, device

SECRETS = ["S3cr3t-Passw0rd", "tok_ABCDEF123456", "bob-the-account", "hunter2 with space"]

DDCLIENT = f"""# ddclient 3.9 / 3.10 / 3.11
daemon=300
ssl=yes
use=if, if=eth1
protocol=dyndns2
server=members.dyndns.org
login={SECRETS[2]}
password='{SECRETS[3]}'
home.example.org
protocol=cloudflare, zone=example.org, \\
  login=token, password={SECRETS[1]}, \\
  ttl=1
usev6=webv6, web=checkipv6.example
cf.example.org,cf2.example.org
protocol=duckdns, ssl=no
password={SECRETS[0]}
duck.example.org
"""

INADYN = f"""period = 300
provider default@no-ip.com {{
    username = {SECRETS[2]}
    password = "{SECRETS[3]}"
    hostname = {{ "a.example.org", "b.example.org" }}
}}
custom mine {{
    ddns-server = ddns.example.net
    ddns-path = "/update?user=%u&pass=%p&host=%h"
    username = {SECRETS[2]}
    password = {SECRETS[0]}
    hostname = c.example.org
    ssl = false
}}
provider default@duckdns.org:alias {{
    password = {SECRETS[1]}
    hostname = d.example.org
    ssl = false
}}
"""

CACHE = """mtime=1700000000,atime=1700000100,wtime=0,status=good,ip=203.0.113.7 home.example.org
mtime=1700000200,status=failed-authentication,ip=198.51.100.9 cf.example.org
"""


def test_ddclient_conf_names_providers_and_tls() -> None:
    got = {c.hostname: c for c in ddns.ddclient_conf(DDCLIENT)}
    assert sorted(got) == [
        "cf.example.org",
        "cf2.example.org",
        "duck.example.org",
        "home.example.org",
    ]
    home = got["home.example.org"]
    assert (home.provider, home.tls, home.interface, home.families) == (
        "dyndns2",
        True,
        "eth1",
        [4],
    )
    assert got["cf.example.org"].provider == "cloudflare"
    assert got["cf.example.org"].families == [4, 6]  # sticky use= and usev6=
    assert got["duck.example.org"].provider == "duckdns" and got["duck.example.org"].tls is False


def test_inadyn_conf_blocks() -> None:
    got = {c.hostname: c for c in ddns.inadyn_conf(INADYN)}
    assert sorted(got) == ["a.example.org", "b.example.org", "c.example.org", "d.example.org"]
    assert (got["a.example.org"].provider, got["a.example.org"].tls) == ("noip", True)
    assert (got["c.example.org"].provider, got["c.example.org"].tls) == ("other", False)
    assert (got["d.example.org"].provider, got["d.example.org"].tls) == ("duckdns", False)


def test_caches() -> None:
    cache = ddns.ddclient_cache(CACHE)
    assert str(cache["home.example.org"].address) == "203.0.113.7"
    assert cache["cf.example.org"].status.startswith("failed")
    one = ddns.inadyn_cache("/var/cache/inadyn/a.example.org.cache", "198.51.100.4\n", 1700000000)
    assert one is not None and one[0] == "a.example.org" and one[1].stamp == 1700000000
    assert ddns.inadyn_cache("/var/cache/inadyn/inadyn.cache", "198.51.100.4", 1) is None


def _sections(box_conf: str, path: str = "/etc/ddclient.conf") -> dict[str, str]:
    return {
        "ddns-conf": _files({path: box_conf}),
        "ddns-cache": _files(
            {
                "/var/cache/ddclient/ddclient.cache": CACHE,
                "/var/cache/inadyn/a.example.org.cache": "198.51.100.4\n",
            }
        ),
        "ddns-mtime": "1700000300 /var/cache/inadyn/a.example.org.cache\n",
    }


async def test_adapter_reads_ddclient_with_cache_and_never_the_secrets(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The raw file (a device whose filter failed, or an older script) carries every secret."""
    box = device()
    box.sections.update(_sections(DDCLIENT))
    caplog.set_level(logging.DEBUG)
    async with adapter_for(box) as adapter:
        await adapter.read_system()
        obs = await adapter.read_interfaces()
    by_host = {d.hostname: d for d in obs.ddns}
    home = by_host["home.example.org"]
    assert home.id == "gw2/ddns/ddclient-home.example.org"
    assert (home.last_result, str(home.published_address)) == (DdnsResult.OK, "203.0.113.7")
    assert home.last_update is not None and home.last_update.timestamp() == 1700000000
    assert by_host["cf.example.org"].last_result is DdnsResult.ERROR
    assert by_host["duck.example.org"].last_result is DdnsResult.UNKNOWN
    everything = (
        "".join(d.model_dump_json() for d in obs.ddns)
        + obs.model_dump_json()
        + caplog.text
        + "".join(g.message + g.fix for g in obs.incomplete)
    )
    for secret in SECRETS:
        assert secret not in everything
    assert "password" not in "".join(d.model_dump_json() for d in obs.ddns).lower()


async def test_adapter_reads_inadyn_with_file_times() -> None:
    box = device()
    box.sections.update(_sections(INADYN, "/etc/inadyn.conf"))
    async with adapter_for(box) as adapter:
        await adapter.read_system()
        obs = await adapter.read_interfaces()
    a = next(d for d in obs.ddns if d.hostname == "a.example.org")
    assert a.id == "gw2/ddns/inadyn-a.example.org"
    assert str(a.published_address) == "198.51.100.4"
    assert a.last_update is not None and a.last_update.timestamp() == 1700000300
    for secret in SECRETS:
        assert secret not in "".join(d.model_dump_json() for d in obs.ddns)


async def test_unreadable_config_is_an_optional_gap_and_old_scripts_report_nothing() -> None:
    box = device()
    box.sections["ddns-conf"] = "@@! /etc/ddclient.conf\n"
    async with adapter_for(box) as adapter:
        await adapter.read_system()
        obs = await adapter.read_interfaces()
        adapter._answer = split("@@os\n@@end\n")
        assert ddns.read("gw2", adapter.answer, [])[0] == []
    assert obs.ddns == []
    (gap,) = [g for g in obs.incomplete if g.message_id == "linux.ddnsUnreadable"]
    assert gap.optional and "/etc/ddclient.conf" in gap.message


def test_scrub_drops_every_credential_part() -> None:
    text = "login=a, password='x y', zone=z\nPASSWORD = q\nsecret-token=1\nuse=web\n"
    out = ddns.scrub(text)
    assert "x y" not in out and "q" not in out.replace("PASSWORD", "") and "=1" not in out
    assert "use=web" in out


def test_device_filter_removes_credentials_before_they_leave_the_device(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "ddclient.conf"
    path.write_text(DDCLIENT + INADYN)
    run = subprocess.run(
        f"cat {path} | {collect.DDNS_CLEAN}",
        shell=True,
        capture_output=True,
        text=True,
        check=True,
    )
    for secret in SECRETS:
        assert secret not in run.stdout
    assert "home.example.org" in run.stdout and "protocol=dyndns2" in run.stdout


def test_read_script_uses_sudo_only_for_the_two_files_and_filters_them() -> None:
    script = collect.READ
    assert "sudo -n /bin/cat" in script and script.count("sudo -n /bin/cat") == 1
    assert collect.DDNS_CLEAN in script
    rule = sudoers("signalbox")
    assert "/bin/cat /etc/ddclient.conf" in rule and "/bin/cat /etc/inadyn.conf" in rule
    assert rule.count("/bin/cat") == 2


# --- name resolution (opt-in) -------------------------------------------------------------


def _net(published: str | None) -> Network:
    up = uplink("gw", "wan", public_ipv4=ip_address("203.0.113.7"), up=True)
    entry = DynamicDns(
        id=object_id("gw", "ddns", "x"),
        device_id="gw",
        hostname="x.example.org",
        published_address=ip_address(published) if published else None,
    )
    return Network(sites=[], devices=[], uplinks=[up], ddns=[entry])


def test_resolution_is_off_by_default() -> None:
    assert Config().ddns.resolve is False


def test_apply_prefers_an_answer_the_connection_has() -> None:
    net = _net(None)
    got = apply(net, {"x.example.org": [IPv4Address("198.51.100.1"), IPv4Address("203.0.113.7")]})
    assert str(got.ddns[0].published_address) == "203.0.113.7"
    assert apply(net, {}) is net
    assert hostnames(net) == {"x.example.org"}


def test_resolved_name_feeds_ddns_mismatch() -> None:
    net = apply(_net(None), {"x.example.org": [IPv4Address("198.51.100.77")]})
    (finding,) = evaluate(net, [mismatch])
    assert "198.51.100.77" in finding.message and "203.0.113.7" in finding.message
    same = apply(_net(None), {"x.example.org": [IPv4Address("203.0.113.7")]})
    assert not evaluate(same, [mismatch])


async def test_unresolvable_name_gives_no_answer() -> None:
    got = await resolve_names({"nothing.invalid"}, 1.0)
    assert got == {"nothing.invalid": []}
