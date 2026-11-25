"""Fast roaming and UPnP rules (#90, #124)."""

from typing import Any

from factories import SITE, device, iface, service
from signalbox.merge import merge
from signalbox.model import (
    DeviceRole,
    Network,
    Segment,
    SegmentPurpose,
    ServiceKind,
    Site,
    Snapshot,
    Subnet,
    segment_id,
)
from signalbox.rules import Finding, Rule, Severity, evaluate
from signalbox.rules.roaming_upnp import RULES, roaming, upnp
from test_rules_wireless import ap, wlan

LAN = segment_id(SITE.id, None)
IOT = segment_id(SITE.id, 20)


def run_wifi(*snaps: Snapshot) -> list[Finding]:
    net = merge([SITE, Site(id="cabin", name="Cabin")], snaps, [])
    return [f for f in evaluate(net, [roaming]) if f.rule_id == roaming.id]


def test_rules_are_exported() -> None:
    assert [r.id for r in RULES] == ["wifi.roaming", "security.upnp"]


# wifi.roaming ---------------------------------------------------------------------------------


def test_roaming_on_a_single_access_point() -> None:
    (f,) = run_wifi(ap("ap1"))
    assert f.severity is Severity.INFO
    assert f.message_id == "wifi.roamingSingleAp"
    assert "only ap1 broadcasts it" in f.message
    assert f.params == {"ssid": "'Example'", "ap": "ap1"}


def test_roaming_quiet_with_two_access_points_or_without_80211r() -> None:
    assert run_wifi(ap("ap1"), ap("ap2")) == []
    off = ap("ap1", wlans=[wlan("ap1", roaming_80211r=False)])
    assert run_wifi(off) == []
    unknown = ap("ap1", wlans=[wlan("ap1", roaming_80211r=None)])
    assert run_wifi(unknown) == []
    disabled = ap("ap1", wlans=[wlan("ap1", enabled=False)])
    assert run_wifi(disabled) == []


def test_roaming_counts_access_points_per_site() -> None:
    far = ap("ap2", site_id="cabin")
    assert len(run_wifi(ap("ap1"), far)) == 2  # one access point at each site


def test_roaming_without_k_or_v() -> None:
    both = ap("ap1", wlans=[wlan("ap1", roaming_80211k=False, roaming_80211v=False)])
    (f,) = [f for f in run_wifi(both, ap("ap2")) if f.message_id == "wifi.roamingNoKv"]
    assert f.severity is Severity.INFO
    assert f.params["missing"] == "802.11k and 802.11v"
    only_v = ap("ap1", wlans=[wlan("ap1", roaming_80211v=False)])
    (f,) = run_wifi(only_v, ap("ap2"))
    assert f.params["missing"] == "802.11v"
    assert f.objects == ["ap1/wlan/Example/radio0"]


def test_roaming_quiet_when_k_and_v_are_unknown() -> None:
    unknown = ap("ap1", wlans=[wlan("ap1", roaming_80211k=None, roaming_80211v=None)])
    assert run_wifi(unknown, ap("ap2")) == []


def test_roaming_single_ap_without_k_gives_two_findings() -> None:
    one = ap("ap1", wlans=[wlan("ap1", roaming_80211k=False)])
    assert {f.message_id for f in run_wifi(one)} == {"wifi.roamingSingleAp", "wifi.roamingNoKv"}


# security.upnp --------------------------------------------------------------------------------


def seg(sid: str, vlan: int | None, purpose: SegmentPurpose | None = None) -> Segment:
    return Segment(id=sid, site_id=SITE.id, vlan=vlan, purpose=purpose)


def sub(sid: str, addr: str) -> Subnet:
    return Subnet(
        id=f"gw/subnet/{sid}", segment_id=sid, interface=iface(addr), device_id="gw", gateway=True
    )


def make(*services: Any, iot: SegmentPurpose = SegmentPurpose.IOT) -> Network:
    return Network(
        sites=[SITE],
        devices=[device("gw", DeviceRole.GATEWAY)],
        segments=[seg(LAN, None, SegmentPurpose.MAIN), seg(IOT, 20, iot)],
        subnets=[sub(LAN, "192.0.2.1/24"), sub(IOT, "198.51.100.1/24")],
        services=list(services),
    )


def run_upnp(n: Network, r: Rule = upnp) -> list[Finding]:
    return [f for f in evaluate(n, [r]) if f.rule_id == r.id]


def test_upnp_for_an_iot_network_is_a_warning() -> None:
    (f,) = run_upnp(make(service("gw", ServiceKind.UPNP)))
    assert f.severity is Severity.WARNING
    assert f.message_id == "security.upnpUntrusted"
    assert f.message.startswith("UPnP is enabled on gw for ")
    assert IOT in f.objects and "gw/service/upnp" in f.objects


def test_upnp_enabled_elsewhere_is_information() -> None:
    n = make(service("gw", ServiceKind.UPNP, segments=[LAN]))
    (f,) = run_upnp(n)
    assert f.severity is Severity.INFO
    assert f.message == "UPnP is enabled on gw"
    assert f.message_id == "security.upnpEnabled"
    (g,) = run_upnp(make(service("gw", ServiceKind.UPNP), iot=SegmentPurpose.SERVERS))
    assert g.severity is Severity.INFO


def test_upnp_quiet_when_off_missing_or_not_a_device() -> None:
    assert run_upnp(make(service("gw", ServiceKind.UPNP, enabled=False))) == []
    assert run_upnp(make()) == []
    assert run_upnp(make(service("gw", ServiceKind.SSH))) == []
    assert run_upnp(make(service("nobody", ServiceKind.UPNP))) == []


def test_upnp_uses_the_networks_the_device_names() -> None:
    n = make(service("gw", ServiceKind.UPNP, segments=[IOT]))
    (f,) = run_upnp(n)
    assert f.severity is Severity.WARNING
