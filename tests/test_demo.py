from pathlib import Path

import pytest

from signalbox.__main__ import main
from signalbox.demo import demo_devices
from signalbox.model import DeviceStatus
from signalbox.service import build


async def test_demo_devices_are_readable_and_show_findings(tmp_path: Path) -> None:
    svc = build(tmp_path, env={"SIGNALBOX_AUTH_PASSWORD": "x" * 12})
    try:
        with demo_devices(svc) as urls:
            assert set(urls) == {"gateway", "ap-1", "ap-2"}
            net, findings = await svc.runner.observe_all()
            assert set(net.statuses.values()) == {DeviceStatus.OK}
            rules = {f.rule_id for f in findings}
            assert "wifi.channel-overlap" in rules
            assert not any(
                f.severity == "error" and f.rule_id.startswith("addr.") for f in findings
            )
            # network purposes (#164): the IoT and guest VLANs are guessed from their names, so
            # the demo suggests declaring them and cannot check the router's firewall yet
            purposes = {s.id: (s.purpose, s.purpose_source) for s in net.segments}
            assert purposes["home/segment/20"] == ("iot", "heuristic")
            assert purposes["home/segment/30"] == ("guest", "heuristic")
            assert purposes["home/segment/native"] == (None, None)
            assert "segment.purpose-missing" in rules
            # the gateway's firewall is read (#135): it keeps IoT and guest away from the
            # web interface, so nothing is reported and nothing is "not checked"
            exposure = [f for f in findings if f.rule_id.endswith("-exposure")]
            assert not any(f.objects and f.objects[0] == "gateway" for f in exposure)
            assert not rules & {"wifi.guest-isolation", "segment.guest-no-isolation"}
            iot = [w for w in net.wlans if w.ssid == "Example-IoT"]
            assert iot and all(w.client_isolation for w in iot)
        # a second start reuses the certificates, so the stored pins stay valid
        with demo_devices(svc):
            net, _ = await svc.runner.observe_all()
            assert set(net.statuses.values()) == {DeviceStatus.OK}
            assert len(svc.store.links()) == 1
    finally:
        svc.close()


def test_demo_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    seen: dict[str, object] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw))
    monkeypatch.setenv("SIGNALBOX_AUTH_PASSWORD", "x" * 12)
    assert main(["--data", str(tmp_path), "demo"]) == 0
    assert seen["port"] == 8080
    assert (tmp_path / "demo-certificates" / "gateway.crt").exists()
