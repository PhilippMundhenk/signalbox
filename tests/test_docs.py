import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def load_tool():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("gen_docs", ROOT / "tools" / "gen_docs.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("name", ["CONFIGURATION.md", "MATURITY.md"])
def test_generated_docs_are_current(name: str) -> None:
    mod = load_tool()
    assert (ROOT / "docs" / name).read_text() == mod.OUTPUTS[name](), "run python tools/gen_docs.py"


def test_maturity_reads_reports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = load_tool()
    reports = tmp_path / "r.json"
    reports.write_text('{"openwrt": {"capabilities": ["wireless"], "devices": ["Example AP 1"]}}')
    monkeypatch.setattr(mod, "REPORTS", reports)
    row = next(
        line for line in mod.maturity().splitlines() if line.startswith("|") and "`openwrt`" in line
    )
    assert "confirmed" in row and "Example AP 1" in row


def test_configuration_lists_every_setting() -> None:
    text = load_tool().configuration()
    for var in (
        "SIGNALBOX_SERVER_PORT",
        "SIGNALBOX_MQTT_HOST",
        "SIGNALBOX_OBSERVE_INTERVAL_SECONDS",
    ):
        assert var in text
