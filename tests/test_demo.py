from pathlib import Path

import pytest

from signalbox.__main__ import main
from signalbox.demo import CABLES, demo_devices
from signalbox.model import DeviceStatus, LinkKind
from signalbox.service import build


async def test_demo_devices_are_readable_and_show_findings(tmp_path: Path) -> None:
    svc = build(tmp_path, env={"SIGNALBOX_AUTH_PASSWORD": "x" * 12})
    try:
        with demo_devices(svc) as urls:
            # two sites (#324); the switches of Switchyard are optional
            assert {
                "gateway-a",
                "gateway-b",
                "core-switch",
                "ap-1",
                "ap-2",
                "ap-b",
                "router-b",
                "omada",
                "adguard",
                "pihole",
            } <= set(urls)
            net, findings = await svc.runner.observe_all()
            partly = {d for d, st in net.statuses.items() if st is not DeviceStatus.OK}
            assert partly == {"router-b"}  # its user may not read the firewall
            assert {d.site_id for d in net.devices} == {"site-a", "site-b"}
            assert len(net.devices) >= 12
            rules = {f.rule_id for f in findings}
            assert {"wifi.channel-overlap", "dns.forwarder-loop"} <= rules
            assert not any(
                f.severity == "error" and f.rule_id.startswith("addr.") for f in findings
            )
            # the demo shows a handful of checks, not every rule the independent simulators trip
            assert len(findings) < 40
            # the WireGuard link of the two gateways is found from the keys; the two cables
            # between the switches are both there
            vpn = [li for li in net.links if li.kind is LinkKind.VPN]
            assert [(li.a, li.b) for li in vpn] == [
                ("gateway-a/tunnel/wg0", "gateway-b/tunnel/wg0")
            ]
            if "access-switch" in urls:
                bundle = [li for li in net.links if li.b.startswith("access-switch/port/")]
                assert {li.a for li in bundle} >= {"core-switch/port/lan2", "core-switch/port/lan3"}
            # network purposes (#164): the IoT and guest VLANs are guessed from their names
            purposes = {s.id: (s.purpose, s.purpose_source) for s in net.segments}
            assert purposes["site-a/segment/20"] == ("iot", "heuristic")
            assert purposes["site-a/segment/30"] == ("guest", "heuristic")
            assert "segment.purpose-missing" in rules
        # a second start reuses the certificates, so the stored pins stay valid
        with demo_devices(svc):
            net, _ = await svc.runner.observe_all()
            assert {d for d, st in net.statuses.items() if st is not DeviceStatus.OK} == {
                "router-b"
            }
            assert len(svc.store.links()) == len(CABLES)
    finally:
        svc.close()


def test_demo_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    seen: dict[str, object] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw))
    monkeypatch.setenv("SIGNALBOX_AUTH_PASSWORD", "x" * 12)
    assert main(["--data", str(tmp_path), "demo"]) == 0
    assert seen["port"] == 8080
    assert (tmp_path / "demo-certificates" / "gateway-a.crt").exists()


async def test_compact_demo_is_the_small_network_of_the_tests(tmp_path: Path) -> None:
    svc = build(tmp_path, env={"SIGNALBOX_AUTH_PASSWORD": "x" * 12})
    try:
        with demo_devices(svc, compact=True) as urls:
            assert set(urls) == {"gateway", "ap-1", "ap-2"}
            net, findings = await svc.runner.observe_all()
            assert set(net.statuses.values()) == {DeviceStatus.OK}
            assert "wifi.channel-overlap" in {f.rule_id for f in findings}
            assert len(svc.store.links()) == 1
        with demo_devices(svc, compact=True):  # the stored pins stay valid
            net, _ = await svc.runner.observe_all()
            assert set(net.statuses.values()) == {DeviceStatus.OK}
    finally:
        svc.close()
