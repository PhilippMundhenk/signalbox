#!/usr/bin/env python3
"""Record what a real device answers, neutralised, as a Signalbox regression test.

Reads the device once through its Signalbox adapter (only reads: nothing is changed on the
device), records every HTTP exchange, replaces private data (addresses, MACs, names, SSIDs,
secrets; see ``signalbox.recording.Neutraliser``), replays the result through the adapter and
stores what it reported. The file can be attached to a device report (#21) and committed as
``tests/fixtures/recordings/<adapter>-<model>-<firmware>.json``; ``tests/test_recordings.py``
then checks every later Signalbox against it.

    export SIGNALBOX_RECORD_PASSWORD=...        # never on the command line
    python tools/record_device.py --adapter fritzbox --url https://192.0.2.1:49443 \\
        --username signalbox --show-fingerprint
    python tools/record_device.py --adapter fritzbox --url https://192.0.2.1:49443 \\
        --username signalbox --pin <fingerprint> --out fritzbox-7590-7.57.json

Works for the adapters that talk HTTP(S) through ``DeviceHttp`` (fritzbox, openwrt, opnsense,
mikrotik, omada). Read the output before publishing it: names inside free text and MACs
written without separators are not found.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import SecretStr

from signalbox.adapters import AdapterContext, load_adapters
from signalbox.adapters.https import fingerprint, peer_certificate
from signalbox.model import DeviceRole
from signalbox.recording import Exchange, build, recording, replay_snapshot


def _value(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return text


async def record(args: argparse.Namespace) -> int:
    parts = urlsplit(args.url)
    if args.show_fingerprint:
        port = parts.port or (443 if parts.scheme == "https" else 80)
        der = await peer_certificate(parts.hostname or "", port, args.timeout)
        print(fingerprint(der))
        return 0
    cls = load_adapters()[args.adapter]
    fields = cls.manifest.config.model_fields
    secret_fields = [n for n, f in fields.items() if "SecretStr" in str(f.annotation)]
    secrets: dict[str, str] = {}
    for i, name in enumerate(secret_fields):
        env = args.password_env if i == 0 else f"SIGNALBOX_RECORD_{name.upper()}"
        value = os.environ.get(env)
        if value is None and not fields[name].is_required():
            continue  # an optional secret (OPNsense's isc_ssh_key): only when given
        if value is None:
            print(f"set {name} in the environment variable {env}", file=sys.stderr)
            return 2
        secrets[name] = value
    extra = dict(kv.split("=", 1) for kv in args.set)
    settings: dict[str, Any] = {k: _value(v) for k, v in extra.items()}
    if args.username is not None:
        settings["username"] = args.username
    config = cls.manifest.config(
        url=args.url, **settings, **{k: SecretStr(v) for k, v in secrets.items()}
    )
    adapter = cls(
        AdapterContext(
            site_id="home",
            device_id="recorded",
            device_name="recorded device",
            role=DeviceRole(args.role),
            config=config,
            pinned_fingerprint=args.pin,
            timeout=args.timeout,
        )
    )
    exchanges: list[Exchange] = []
    try:
        with recording(exchanges):
            snapshot = await adapter.observe()
    finally:
        await adapter.close()
    print(f"observed: {snapshot.status.value}, {len(exchanges)} HTTP exchanges", file=sys.stderr)
    for error in snapshot.errors:
        print(f"  {error.capability}: {error.message}", file=sys.stderr)
    device = {"model": snapshot.device.model or "", "firmware": ""}
    if snapshot.device.firmware is not None:
        device["firmware"] = snapshot.device.firmware.current or ""
    data = build(
        args.adapter,
        exchanges,
        role=args.role,
        path=parts.path,
        settings=extra,
        password=list(secrets.values()),
        username=args.username,
        note=args.note,
        device=device,
        secret_names=list(secrets),
    )
    data["snapshot"], unmatched = await replay_snapshot(data)
    for line in unmatched:
        print(f"warning: the replay asked for something not recorded: {line}", file=sys.stderr)
    out = Path(args.out)
    out.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    print(
        f"wrote {out}; read it before publishing (names in free text are not replaced)",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--adapter", required=True, help="adapter id, for example fritzbox")
    p.add_argument("--url", required=True, help="the URL as in the adapter's settings")
    p.add_argument("--username", help="the user name setting, if the adapter has one")
    p.add_argument(
        "--password-env",
        default="SIGNALBOX_RECORD_PASSWORD",
        help="environment variable with the password (the first secret setting); further "
        "secret settings in SIGNALBOX_RECORD_<SETTING>, for example SIGNALBOX_RECORD_API_SECRET",
    )
    p.add_argument("--pin", help="SHA-256 fingerprint of the device certificate")
    p.add_argument("--show-fingerprint", action="store_true", help="print it and stop")
    p.add_argument("--role", default="gateway", choices=[r.value for r in DeviceRole])
    p.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="another adapter setting (JSON values allowed)",
    )
    p.add_argument("--note", default="", help="a line about the device, kept in the file")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--out", default="recording.json")
    return asyncio.run(record(p.parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())
