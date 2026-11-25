"""Offline MAC vendor database (#84)."""

from __future__ import annotations

import lzma
from importlib import resources

import pytest

from signalbox import oui
from signalbox.model import ClientCategory


def test_known_vendors() -> None:
    assert oui.vendor("D4:8A:FC:12:34:56") == "Espressif"
    assert oui.vendor("d4-8a-fc-12-34-56") == "Espressif"
    assert oui.vendor("d48a.fc12.3456") == "Espressif"
    assert "Hikvision" in (oui.vendor("0c:75:d2:00:00:01") or "")


def test_no_vendor_for_randomised_group_unknown_or_invalid() -> None:
    assert oui.vendor("d6:8a:fc:12:34:56") is None  # locally administered: never guessed
    assert oui.vendor("02:00:00:00:00:01") is None
    assert oui.vendor("d5:8a:fc:12:34:56") is None  # group address
    assert oui.vendor("not a mac") is None
    assert oui.vendor("") is None


def test_database_is_complete_and_small() -> None:
    assert len(oui.database()) > 30000
    size = len(resources.files("signalbox").joinpath("data", oui.DATA_FILE).read_bytes())
    assert size < 1_000_000


def test_encode_decode_roundtrip() -> None:
    entries = {0x000102: "A", 0x000103: "A", 0xABCDEF: "Zed \u00e9"}
    assert oui.decode(oui.encode(entries)) == entries
    assert oui.decode(oui.encode({})) == {}
    with pytest.raises(ValueError):
        oui.decode(b"nope")
    with pytest.raises(ValueError):
        oui.encode({1: "a\nb"})
    assert lzma.decompress(lzma.compress(oui.encode(entries)))


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("Espressif", ClientCategory.IOT),
        ("Tuya Smart", ClientCategory.IOT),
        ("Shelly Europe", ClientCategory.IOT),
        ("Sonos", ClientCategory.IOT),
        ("Hangzhou Hikvision Digital Technology", ClientCategory.CAMERA),
        ("Zhejiang Dahua Technology", ClientCategory.CAMERA),
        ("Ring LLC", ClientCategory.CAMERA),
        ("Axis Communications", ClientCategory.CAMERA),
        ("Apple", None),
        ("Amazon Technologies", None),
        ("Bring Systems", None),  # "ring" only counts as a whole word at the start
        ("Acme Ring", None),
        ("Wiznet", None),
        ("", None),
        (None, None),
    ],
)
def test_vendor_category(name: str | None, kind: ClientCategory | None) -> None:
    assert oui.vendor_category(name) == kind


def test_mac_category() -> None:
    assert oui.mac_category("d4:8a:fc:00:00:01") is ClientCategory.IOT
    assert oui.mac_category("d6:8a:fc:00:00:01") is None
