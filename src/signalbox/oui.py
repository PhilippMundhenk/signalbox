"""Offline MAC vendor database (issue #84): which company was assigned the first three bytes.

The data is the IEEE MA-L (OUI) registry, reduced to prefix -> short vendor name by
``tools/gen_oui.py`` and shipped as ``data/oui.bin.xz`` (see ``docs/OUI.md``). Nothing is fetched at
run time.

Two rules keep the answer honest:

* A locally administered MAC (the second-lowest bit of the first byte is set: a phone's "private
  address", a virtual machine) has no vendor; never guess one for it.
* A group (multicast) address is not a device address and has no vendor either.

Then :func:`vendor_category` says which kind of device a vendor mostly builds, only for the few
vendors whose products are (almost) all IoT devices or cameras.
"""

from __future__ import annotations

import lzma
import re
import struct
from functools import lru_cache
from importlib import resources

from signalbox.model import ClientCategory

MAGIC = b"OUI1"
DATA_FILE = "oui.bin.xz"

_MAC = re.compile(r"^[0-9a-f]{2}([:\-.]?[0-9a-f]{2}){5}$", re.IGNORECASE)


def encode(entries: dict[int, str]) -> bytes:
    """The uncompressed file: magic, name count and size, names (one per line), then per prefix
    the 3-byte prefix and the 2-byte index of its name, sorted by prefix."""
    names = sorted(set(entries.values()))
    if len(names) >= 1 << 16 or any("\n" in n for n in names):
        raise ValueError("too many vendor names or a name with a line break")
    index = {n: i for i, n in enumerate(names)}
    blob = "\n".join(names).encode("utf-8")
    out = bytearray(MAGIC + struct.pack(">II", len(names), len(blob)) + blob)
    for prefix in sorted(entries):
        out += prefix.to_bytes(3, "big") + struct.pack(">H", index[entries[prefix]])
    return bytes(out)


def decode(raw: bytes) -> dict[int, str]:
    if raw[:4] != MAGIC:
        raise ValueError("not an OUI database")
    count, size = struct.unpack(">II", raw[4:12])
    names = raw[12 : 12 + size].decode("utf-8").split("\n") if count else []
    body = raw[12 + size :]
    out: dict[int, str] = {}
    for pos in range(0, len(body), 5):
        (idx,) = struct.unpack(">H", body[pos + 3 : pos + 5])
        out[int.from_bytes(body[pos : pos + 3], "big")] = names[idx]
    return out


@lru_cache(maxsize=1)
def database() -> dict[int, str]:
    """prefix (the first three bytes as a number) -> short vendor name."""
    data = resources.files("signalbox").joinpath("data", DATA_FILE).read_bytes()
    return decode(lzma.decompress(data))


def vendor(mac: str) -> str | None:
    """The vendor of the MAC address, or None: unknown prefix, locally administered (randomised)
    or group address, or not a MAC address."""
    if not _MAC.match(mac.strip()):
        return None
    digits = re.sub(r"[^0-9a-f]", "", mac.lower())
    if int(digits[:2], 16) & 0x03:  # bit 0: group address, bit 1: locally administered
        return None
    return database().get(int(digits[:6], 16))


# What a vendor mostly builds. Conservative on purpose: only vendors whose products are (almost)
# all IoT devices (smart plugs, bulbs, speakers, chips inside them) or cameras. Vendors that also
# make computers, phones, routers or media players (Amazon, Google, Xiaomi, Samsung, Apple,
# TP-Link, Ubiquiti, Sercomm, Belkin, Bosch, Murata, ...) are left out: a wrong guess produces a
# wrong finding. A tuple is a run of words in the vendor name; True: it must start the name.
_IOT = ClientCategory.IOT
_CAMERA = ClientCategory.CAMERA
_KINDS: tuple[tuple[tuple[str, ...], bool, ClientCategory], ...] = (
    # chips and platforms inside smart-home devices
    (("espressif",), False, _IOT),
    (("tuya",), False, _IOT),
    (("broadlink",), False, _IOT),
    (("meross",), False, _IOT),
    (("shelly",), False, _IOT),
    (("allterco",), False, _IOT),
    (("lumi", "united"), False, _IOT),
    (("wiz",), True, _IOT),
    # lighting
    (("signify",), True, _IOT),
    (("philips", "lighting"), True, _IOT),
    (("ledvance",), True, _IOT),
    (("nanoleaf",), True, _IOT),
    (("ikea", "of", "sweden"), True, _IOT),
    # speakers, thermostats, sensors, robots, locks, shutters
    (("sonos",), True, _IOT),
    (("tmall",), False, _IOT),
    (("nest", "labs"), True, _IOT),
    (("ecobee",), True, _IOT),
    (("tado",), True, _IOT),
    (("netatmo",), True, _IOT),
    (("withings",), True, _IOT),
    (("smartthings",), True, _IOT),
    (("somfy",), True, _IOT),
    (("lutron",), True, _IOT),
    (("irobot",), True, _IOT),
    (("roborock",), False, _IOT),
    (("dreame",), True, _IOT),
    (("chamberlain",), False, _IOT),
    # cameras and doorbells
    (("hikvision",), False, _CAMERA),
    (("dahua",), False, _CAMERA),
    (("uniview",), False, _CAMERA),
    (("ezviz",), False, _CAMERA),
    (("reolink",), True, _CAMERA),
    (("amcrest",), True, _CAMERA),
    (("vivotek",), True, _CAMERA),
    (("axis", "communications"), True, _CAMERA),
    (("hanwha", "vision"), True, _CAMERA),
    (("ring",), True, _CAMERA),
    (("blink",), True, _CAMERA),
    (("arlo",), True, _CAMERA),
    (("wyze",), True, _CAMERA),
    (("simplisafe",), True, _CAMERA),
)


def vendor_category(name: str | None) -> ClientCategory | None:
    """``iot`` or ``camera`` when the vendor mostly builds such devices, else None."""
    if not name:
        return None
    words = re.findall(r"[a-z0-9]+", name.lower())
    for needle, anchored, category in _KINDS:
        n = len(needle)
        spots = [0] if anchored else range(len(words) - n + 1)
        if any(tuple(words[i : i + n]) == needle for i in spots):
            return category
    return None


def mac_category(mac: str) -> ClientCategory | None:
    """What the MAC address's vendor mostly builds (None for randomised or unknown MACs)."""
    return vendor_category(vendor(mac))
