"""Rewrite the expected snapshot of every committed recording after a model or adapter change.

A recording (tests/fixtures/recordings/*.json) holds the device's answers and the snapshot they
must give. When a model field is added or an adapter reads more, the expected snapshot changes;
this replays every recording and stores what it gives now. Review the diff before committing:
the snapshot is the expectation of the regression test.

    python tools/regen_recordings.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from signalbox.recording import load, replay_snapshot

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    for path in sorted((ROOT / "tests" / "fixtures" / "recordings").glob("*.json")):
        raw = json.loads(path.read_text())
        snapshot, unmatched = asyncio.run(replay_snapshot(load(path)))
        if unmatched:
            print(f"{path.name}: calls without a recorded answer: {unmatched}", file=sys.stderr)
            return 1
        raw["snapshot"] = snapshot
        path.write_text(json.dumps(raw, indent=1, ensure_ascii=False) + "\n")
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
