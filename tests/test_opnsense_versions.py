"""OPNsense 25.1 and 24.7 besides 26.7 (#390): simulator variants, contract tests, fallbacks.

The variants follow the public sources of ``opnsense/core`` (tags 24.7.12, 25.1.12, 25.7.11,
26.1.11); see docs/adapters/opnsense.md, "Versions".
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext, AdapterError, SetupRequest
from signalbox.adapters.opnsense import OpnsenseAdapter, OpnsenseConfig, compat, vitals
from signalbox.adapters.opnsense import write as w
from signalbox.model import DeviceRole, DeviceStatus, Snapshot
from signalbox.sim.opnsense import KEY, RELEASES, SECRET, OpnsenseSimulator
from signalbox.sim.server import self_signed_certificate, serve
from signalbox.testing import assert_contract

OLD = ("25.1", "24.7")


def adapter(url: str) -> OpnsenseAdapter:
    return OpnsenseAdapter(
        AdapterContext(
            site_id="home",
            device_id="fw",
            device_name="Firewall",
            role=DeviceRole.GATEWAY,
            config=OpnsenseConfig(
                url=url,
                api_key=SecretStr(KEY),
                api_secret=SecretStr(SECRET),
                allow_insecure_http=True,
            ),
            timeout=5.0,
        )
    )


@pytest.fixture(scope="module", params=sorted(RELEASES))
def served(request: pytest.FixtureRequest) -> Iterator[tuple[str, OpnsenseSimulator]]:
    sim = OpnsenseSimulator(release=request.param)
    with serve(sim.app()) as url:
        yield url, sim


async def observe(url: str) -> Snapshot:
    a = adapter(url)
    try:
        return await assert_contract(a)
    finally:
        await a.close()


async def test_contract_per_release(served: tuple[str, OpnsenseSimulator]) -> None:
    url, sim = served
    snap = await observe(url)
    assert snap.status is DeviceStatus.OK
    assert snap.device.firmware is not None
    assert snap.device.firmware.current == RELEASES[sim.release]
    assert snap.subnets and snap.clients and snap.dhcp_servers and snap.dns_services


async def test_firewall_and_health_per_release(served: tuple[str, OpnsenseSimulator]) -> None:
    url, sim = served
    snap = await observe(url)
    [fw] = snap.firewalls
    gaps = {e.message_id: e for e in snap.errors}
    health = snap.device.health
    assert health is not None
    # df -h sizes are rounded but present
    root = next(s for s in health.storage if s.name == "/")
    assert root.total_bytes is not None and root.used_bytes is not None
    if sim.release == "26.7":
        assert fw.rules_complete and fw.port_forwards_complete
        assert "opnsense.forwardsUnread" not in gaps
        assert root.total_bytes == 27917287424
    else:
        assert not fw.port_forwards_complete
        assert gaps["opnsense.forwardsUnread"].optional
        assert f"OPNsense {sim.release}" in gaps["opnsense.forwardsUnread"].message
        assert root.total_bytes == 26 * 1024**3
        if sim.release == "25.1":  # show_all=1 lists the legacy and automatic rules, too
            assert fw.rules_complete and fw.rules
            assert "opnsense.rulesIncomplete" not in gaps
        else:  # 24.7 lists four columns only: no rules read
            assert not fw.rules_complete and fw.rules == []
            assert "opnsense.rulesIncomplete" in gaps


@pytest.mark.parametrize("release", OLD)
def test_older_release_data(release: str) -> None:
    sim = OpnsenseSimulator(release=release)
    data = sim.data
    assert "/api/firewall/d_nat/search_rule" not in data
    assert "/api/ntpd/service/status" not in data
    assert ("/api/dnsmasq/settings/get" in data) is (release == "25.1")
    # search_rule: 25.1 needs show_all=1 for the legacy and automatic rules, 24.7 has 4 columns
    plain = sim.old_filter_rows(False)["rows"]
    full = sim.old_filter_rows(True)["rows"]
    if release == "25.1":
        assert not any("sort_order" in r for r in plain)
        assert any(r.get("legacy") for r in full) and any("sort_order" in r for r in full)
    else:
        assert plain == full and set(full[0]) <= {
            "uuid",
            "enabled",
            "sequence",
            "action",
            "description",
        }


def test_unknown_release() -> None:
    with pytest.raises(ValueError, match="unknown OPNsense release"):
        OpnsenseSimulator(release="23.7")


async def test_camel_case_only_release() -> None:
    """A release that does not know snake_case actions is read through the camelCase ones."""
    sim = OpnsenseSimulator(release="24.7", snake_case=False)
    with serve(sim.app()) as url:
        snap = await observe(url)
    assert snap.status is DeviceStatus.OK and snap.dhcp_servers and snap.subnets


async def test_user_manager_missing_before_25_1(tmp_path: Path) -> None:
    sim = OpnsenseSimulator(release="24.7")
    tls = self_signed_certificate(tmp_path)
    with serve(sim.app(), tls=tls) as url, pytest.raises(AdapterError) as err:
        await OpnsenseAdapter.plan_setup(
            SetupRequest(
                config={"url": url},
                admin_user=KEY,
                admin_secret=SecretStr(SECRET),
                allow_writes=False,
                trust=tls.fingerprint,
                timeout=5,
            )
        )
    assert err.value.message_id == "opnsense.noUserApi"
    assert "25.1" in str(err.value) and err.value.fix_id == "opnsense.noUserApi.fix"


def test_interface_negation_needs_25_1() -> None:
    st: Any = w.WriteState.__new__(w.WriteState)
    st.interface_not, st.release, st.zones, st.interfaces = False, "24.7", {"lan"}, {"lan"}
    with pytest.raises(AdapterError) as err:
        w._zones_of("!lan", st, "rule x")
    assert err.value.message_id == "opnsense.noInterfaceNot"
    assert "24.7" in str(err.value)
    st.interface_not = True
    assert w._zones_of("!lan", st, "rule x") == ("lan", True)
    assert w._zones_of("lan", st, "rule x") == ("lan", False)


# --- helpers ---------------------------------------------------------------------------------


def test_parse_version() -> None:
    assert compat.parse_version("25.1.12_4") == (25, 1, 12)
    assert compat.parse_version("24.7") == (24, 7, 0)
    assert compat.parse_version("26.7.8_1") >= compat.DNAT_API
    assert compat.parse_version("unknown") is None
    assert compat.release((25, 1, 12)) == "25.1"


def test_camel_path() -> None:
    assert (
        compat.camel_path("/api/firewall/filter/search_rule") == "/api/firewall/filter/searchRule"
    )
    assert (
        compat.camel_path("/api/kea/dhcpv4/set_subnet/9f_ab") == "/api/kea/dhcpv4/setSubnet/9f_ab"
    )
    assert compat.camel_path("/api/firewall/d_nat/get") == "/api/firewall/d_nat/get"
    assert compat.camel_path("/api/core/firmware/status") == "/api/core/firmware/status"
    assert compat.camel_path("/ui/x/y_z") == "/ui/x/y_z"
    assert compat.camel_path("/api/x") == "/api/x"


def test_df_sizes() -> None:
    assert vitals.size_bytes("1.5K") == 1536
    assert vitals.size_bytes("28G") == 28 * 1024**3
    assert vitals.size_bytes("0B") == 0
    assert vitals.size_bytes(512) == 512
    assert vitals.size_bytes("1.2Gi") == int(1.2 * 1024**3)
    assert vitals.size_bytes(True) is None
    assert vitals.size_bytes("-") is None
    assert vitals.size_bytes(None) is None
    row = {"mountpoint": "/", "type": "ufs", "blocks": "28G", "used": "1.5G"}
    health = vitals.health_of({}, {}, {"devices": [row]}, [], None)
    assert [(s.name, s.total_bytes, s.used_bytes) for s in health.storage] == [
        ("/", 28 * 1024**3, int(1.5 * 1024**3))
    ]


def test_uptime_in_another_language() -> None:
    """The word for "days" follows the web interface's language."""
    assert vitals.uptime("3 days, 04:05:06") == 273906
    assert vitals.uptime("3 Tage, 04:05:06") == 273906
    assert vitals.uptime("1 jour, 00:00:01") == 86401
    assert vitals.uptime("04:05:06") == 14706
    assert vitals.uptime("soon") is None
