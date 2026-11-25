"""TR-064 device and service descriptions (``tr64desc.xml`` and SCPD files) for the simulator.

AVM publishes the interface of a Fritz!Box as a device description (``tr64desc.xml``: services,
control URLs, SCPD URLs) and one service description (SCPD) per service type: its actions,
their ``in``/``out`` arguments and the state variable (data type, allowed values, range) of
every argument. The Fritz!Box simulator is built from these files (``tests/fixtures/tr064/``,
see ``SOURCES.md`` there), so it answers only actions and arguments that exist on the real
device, with the real data types; the tests check the adapter against the same files.

The checks follow the UPnP Device Architecture, which TR-064 uses: an unknown action is fault
401, missing or unknown arguments 402, a value that is not of the argument's data type or
not in its ``allowedValueList`` 600, a number outside its type or ``allowedValueRange`` 601.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

DEVICE_NS = "{urn:dslforum-org:device-1-0}"
SERVICE_NS = "{urn:dslforum-org:service-1-0}"

#: The descriptions in the source tree (``tests/fixtures/tr064/<version>/``).
FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "tr064"
#: FRITZ!OS versions with complete descriptions of a real box; the first one is the default.
VERSIONS = ("fritzos-7.57", "fritzos-8.02")
#: The older releases (#413): 7.29 is the files of a real box, 6.83 is derived from them (the
#: actions that appeared after 6.x removed, see tests/fixtures/tr064/SOURCES.md). They lack
#: actions and arguments the adapter reads, so the all-actions-present checks do not apply.
OLDER = ("fritzos-7.29", "fritzos-6.83")
#: ``FritzboxSim(release=...)`` -> directory of the descriptions
RELEASES: dict[str, str] = {
    "6.83": "fritzos-6.83",
    "7.29": "fritzos-7.29",
    "7.57": "fritzos-7.57",
    "8.02": "fritzos-8.02",
}

#: integer data types -> (minimum, maximum)
INTEGERS: dict[str, tuple[int, int]] = {
    "ui1": (0, 2**8 - 1),
    "ui2": (0, 2**16 - 1),
    "ui4": (0, 2**32 - 1),
    "i1": (-(2**7), 2**7 - 1),
    "i2": (-(2**15), 2**15 - 1),
    "i4": (-(2**31), 2**31 - 1),
}
#: UPnP boolean spellings
BOOLEANS = {"0", "1", "true", "false", "yes", "no"}
_INT = re.compile(r"[+-]?\d+\Z")


class ArgumentError(ValueError):
    """An argument does not fit its state variable; ``code`` is the UPnP error to answer."""

    def __init__(self, code: int, text: str) -> None:
        super().__init__(text)
        self.code = code


@dataclass(frozen=True)
class StateVariable:
    name: str
    data_type: str
    allowed: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None

    def check(self, value: str) -> None:
        """Raise ArgumentError when ``value`` is not a valid value of this variable."""
        if self.data_type == "boolean":
            if value.strip().lower() not in BOOLEANS:
                raise ArgumentError(600, f"{self.name}: {value!r} is not a boolean")
            return
        if self.data_type in INTEGERS:
            if not _INT.match(value.strip()):
                raise ArgumentError(600, f"{self.name}: {value!r} is not an integer")
            number = int(value)
            low, high = INTEGERS[self.data_type]
            if self.minimum is not None:
                low = max(low, self.minimum)
            if self.maximum is not None:
                high = min(high, self.maximum)
            if not low <= number <= high:
                raise ArgumentError(601, f"{self.name}: {number} is out of range {low}..{high}")
            return
        if self.allowed and value not in self.allowed:
            raise ArgumentError(
                600, f"{self.name}: {value!r} is not one of {', '.join(self.allowed)}"
            )


@dataclass(frozen=True)
class Argument:
    name: str
    variable: StateVariable


@dataclass(frozen=True)
class Action:
    name: str
    inputs: tuple[Argument, ...]
    outputs: tuple[Argument, ...]

    def check_inputs(self, args: dict[str, str]) -> None:
        """Exactly the ``in`` arguments, each a valid value (402 / 600 / 601 otherwise)."""
        wanted = [a.name for a in self.inputs]
        if sorted(args) != sorted(wanted):
            missing = sorted(set(wanted) - set(args))
            unknown = sorted(set(args) - set(wanted))
            raise ArgumentError(
                402, f"{self.name}: missing {missing or 'nothing'}, unknown {unknown or 'nothing'}"
            )
        for a in self.inputs:
            a.variable.check(args[a.name])

    def check_outputs(self, values: dict[str, str]) -> None:
        """The simulator's own answer: every ``out`` argument, valid (a simulator bug if not)."""
        wanted = [a.name for a in self.outputs]
        if sorted(values) != sorted(wanted):
            raise AssertionError(
                f"simulated {self.name} answers {sorted(values)}, the description has {wanted}"
            )
        for a in self.outputs:
            try:
                a.variable.check(values[a.name])
            except ArgumentError as exc:
                raise AssertionError(f"simulated {self.name}: {exc}") from exc


@dataclass(frozen=True)
class Service:
    service_type: str  # urn:dslforum-org:service:WLANConfiguration:1
    control_url: str  # /upnp/control/wlanconfig1
    scpd_url: str  # /wlanconfigSCPD.xml
    actions: dict[str, Action]

    @property
    def name(self) -> str:
        """``WLANConfiguration:1``"""
        return self.service_type.removeprefix("urn:dslforum-org:service:")


@dataclass
class Description:
    """``tr64desc.xml`` and its SCPD files, as files and parsed."""

    directory: Path
    services: dict[str, Service] = field(default_factory=dict)  # by control URL
    files: dict[str, bytes] = field(default_factory=dict)  # URL path -> content

    def service_by_type(self, service_type: str) -> Service | None:
        return next((s for s in self.services.values() if s.service_type == service_type), None)

    def value(self, tag: str) -> str:
        """Text of the first element ``tag`` of ``tr64desc.xml`` (``modelName``, ``Display``)."""
        root = ET.fromstring(self.files["/tr64desc.xml"])
        return next((e.text or "" for e in root.iter(f"{DEVICE_NS}{tag}")), "")


def parse_scpd(content: bytes) -> dict[str, Action]:
    root = ET.fromstring(content)
    variables: dict[str, StateVariable] = {}
    for sv in root.iter(f"{SERVICE_NS}stateVariable"):
        name = sv.findtext(f"{SERVICE_NS}name") or ""
        rng = sv.find(f"{SERVICE_NS}allowedValueRange")
        low = rng.findtext(f"{SERVICE_NS}minimum") if rng is not None else None
        high = rng.findtext(f"{SERVICE_NS}maximum") if rng is not None else None
        variables[name] = StateVariable(
            name,
            (sv.findtext(f"{SERVICE_NS}dataType") or "string").strip(),
            tuple(
                (v.text or "").strip()
                for v in sv.iter(f"{SERVICE_NS}allowedValue")
                if (v.text or "").strip()
            ),
            int(low) if low else None,
            int(high) if high else None,
        )
    actions: dict[str, Action] = {}
    for a in root.iter(f"{SERVICE_NS}action"):
        args: dict[str, list[Argument]] = {"in": [], "out": []}
        for arg in a.iter(f"{SERVICE_NS}argument"):
            var = (arg.findtext(f"{SERVICE_NS}relatedStateVariable") or "").strip()
            direction = (arg.findtext(f"{SERVICE_NS}direction") or "").strip()
            args[direction].append(
                Argument(
                    (arg.findtext(f"{SERVICE_NS}name") or "").strip(),
                    variables.get(var, StateVariable(var, "string")),
                )
            )
        name = (a.findtext(f"{SERVICE_NS}name") or "").strip()
        actions[name] = Action(name, tuple(args["in"]), tuple(args["out"]))
    return actions


def load(version: str | Path = VERSIONS[0]) -> Description:
    """The description of one FRITZ!OS version (a name from VERSIONS, or a directory).

    Services whose SCPD file is not in the directory are left out: the simulator answers
    their control URL with 404, as a box without that service would.
    """
    directory = Path(version) if isinstance(version, Path) else FIXTURES / version
    tr64desc = directory / "tr64desc.xml"
    if not tr64desc.is_file():
        raise FileNotFoundError(
            f"{tr64desc}: the TR-064 descriptions are part of the source tree "
            "(tests/fixtures/tr064/); run the simulator from a checkout"
        )
    desc = Description(directory)
    desc.files["/tr64desc.xml"] = tr64desc.read_bytes()
    parsed: dict[str, dict[str, Action]] = {}
    for s in ET.fromstring(desc.files["/tr64desc.xml"]).iter(f"{DEVICE_NS}service"):
        service_type = (s.findtext(f"{DEVICE_NS}serviceType") or "").strip()
        control = (s.findtext(f"{DEVICE_NS}controlURL") or "").strip()
        scpd = (s.findtext(f"{DEVICE_NS}SCPDURL") or "").strip()
        file = directory / scpd.lstrip("/")
        if not file.is_file():
            continue
        if scpd not in parsed:
            desc.files[scpd] = file.read_bytes()
            parsed[scpd] = parse_scpd(desc.files[scpd])
        desc.services[control] = Service(service_type, control, scpd, parsed[scpd])
    return desc
