# 0001. Python, FastAPI, Pydantic v2, SQLite and a UI without build step

Date: 2026-11-21 · Status: accepted

## Context

Signalbox talks to many kinds of devices through adapters that third parties should be able to
write. The useful client libraries for home and small office network devices (for example
`fritzconnection` for TR-064, `netjsonconfig` for OpenWrt, the NSDP library in
[Switchyard](https://github.com/PhilippMundhenk/switchyard)) are Python. The model must be typed
and published as a contract. One container, small, multi-arch.

Go would give a single static binary, but adapters would have to be compiled in, or run out of
process from day one, and the existing libraries would have to be rewritten.

## Decision

Python 3.11+, Pydantic v2 for the model (JSON Schema export is the published contract),
FastAPI for the API, SQLite through the standard library, plain HTML/JS for the UI with no
build step and a strict CSP, `mypy --strict` and ruff, adapters and rules discovered through
Python entry points.

## Consequences

- Adapters are ordinary Python packages; installing one is `pip install`.
- Type safety depends on discipline: `mypy --strict` runs in CI with no baseline.
- The out-of-process adapter runtime (phase 4) needs a JSON-RPC bridge; the typed model makes
  that a serialisation problem only.
- Same toolchain as Switchyard, so its code can be reused for the ProSAFE Plus adapter.
