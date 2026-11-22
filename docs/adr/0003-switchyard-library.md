# 0003. Switchyard as an optional, pinned library for the switch protocols

Date: 2026-11-22 · Status: accepted

## Context

NETGEAR ProSAFE Plus (NSDP) and TP-Link Easy Smart switches have no API, only the UDP protocol
of the vendor's Windows utility. [Switchyard](https://github.com/PhilippMundhenk/switchyard)
(same author, MIT) implements both behind one driver interface (`switchyard.drivers`), copes
with the firmware differences, and ships simulators of both (`switchyard.sim`,
`switchyard.easysmart.sim`). Signalbox should not maintain a second implementation.

Switchyard is a normal Python package (`src/switchyard`, built with hatchling) whose runtime
dependencies (FastAPI, uvicorn, paho-mqtt) Signalbox has already. It is not on PyPI and has no
release tags yet. Most Signalbox installations will never see such a switch.

## Decision

- Signalbox gets Switchyard through the optional extra `signalbox-net[switches]`, a direct
  reference pinned to a commit:
  `switchyard @ git+https://github.com/PhilippMundhenk/switchyard@<commit>` (today
  `4f8e93fd196c408fa45338a45837f61c97cf32a9`, Switchyard main with both drivers and the
  simulators). A tag replaces the commit once Switchyard has releases. Nothing of Switchyard is
  copied into Signalbox.
- The adapters (`signalbox.adapters.plusswitch`: `prosafe`, `easysmart`) import Switchyard
  only inside their read methods. The entry points load without it, so the adapter list, the
  generated docs and the UI work everywhere; reading such a switch without the extra is a
  read error with the install hint.
- Signalbox uses Switchyard's protocol layer only: the transports, the per-switch drivers and
  their read methods, the identity probe, and the simulators in tests. Not its manager, store,
  web UI or MQTT.
- CI installs `.[dev,switches]` in the test jobs and sets `REQUIRE_SWITCH_TESTS=1`, so
  the simulator tests fail instead of being skipped when Switchyard is missing. Locally they
  are skipped with the reason.
- The container image includes Switchyard: the build stage builds a wheel from the same pinned
  commit (it needs git there, not in the final image).

## Consequences

- Updating Switchyard is a one-line change of the pin in `pyproject.toml` and `Dockerfile`,
  reviewed like any change; a moved branch can never change what Signalbox runs.
- The adapters depend on Switchyard's driver dictionaries (`read_info`, `read_ports`,
  `read_vlan`, `read_lag`) and exceptions (`switchyard.drivers.base`), which are not a declared
  stable API. The mapping lives in one pure module (`plusswitch/mapping.py`) with its own
  tests, and the simulator tests catch a change of shape when the pin moves.
- Installing the extra needs git and access to GitHub. Hatchling has to allow direct
  references (`tool.hatch.metadata.allow-direct-references`), and PyPI does not accept
  packages with them: before Signalbox is published on PyPI, Switchyard has to be published
  there (the extra then becomes `switchyard>=X.Y`), or the extra is dropped from the published
  metadata.
- Switchyard has no type information; mypy treats it as untyped (`ignore_missing_imports`),
  so the adapter code checks the shapes it gets at run time.

## Simulator fidelity (#141, 2026-11-22)

Switches cannot run their firmware emulated, so Switchyard's simulators are the reference for
ProSAFE Plus and Easy Smart, and they are only as good as the captures they were built from.

- **Captures are pinned with the commit.** `tests/fixtures/switches/captures.json` holds the
  published captures of real switches that Switchyard documents, with their source and the
  Switchyard commit they belong to; `tests/test_switch_captures.py` checks that the pinned
  Switchyard decodes and re-encodes them byte for byte and that its simulator of that switch
  answers the captured request with the captured reply. A pin bump updates the commit in the
  fixture and adds the captures Switchyard has gained.
- **What exists today.** Switchyard documents one real capture: an Easy Smart TL-SG105E 3.0
  reply (port count) and the static RC4 keystream (`docs/PROTOCOL-EASYSMART.md` section 3.4,
  from tplink-ess-lib). Its NSDP notes (`docs/PROTOCOL.md`) say none of the ProSAFE Plus
  protocol is verified on real hardware yet, so there is no NSDP capture to pin.
- **One known difference.** A first-generation Easy Smart switch puts its session token into
  every reply (17956 in the capture); Switchyard's simulator only into the answer to the token
  request. Signalbox does not read the token from other replies; the test compares it
  separately.
- **Pin evaluated, unchanged.** On 2026-11-22 Switchyard's `main` was the pinned commit
  `4f8e93fd196c408fa45338a45837f61c97cf32a9`; there was nothing newer to bump to. The switch
  tests (`REQUIRE_SWITCH_TESTS=1`, `tests/test_plusswitch*.py`, `tests/test_switch_captures.py`)
  pass against it.
