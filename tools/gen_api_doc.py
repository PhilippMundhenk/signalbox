"""Write docs/API.md from the app's OpenAPI description (run: python tools/gen_api_doc.py)."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from signalbox.service import build
from signalbox.web.app import create_app

OUT = Path(__file__).resolve().parent.parent / "docs" / "API.md"


def render() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        svc = build(Path(tmp), env={"SIGNALBOX_AUTH_PASSWORD": "x" * 12}, adapters={}, rules=[])
        try:
            spec = create_app(svc, run_background=False).openapi()
        finally:
            svc.close()
    lines = [
        "# HTTP API",
        "",
        "The web interface uses this API; scripts can too. Log in with `POST /api/login`",
        '(`{"password": "..."}`) and send the `signalbox_session` cookie with every request.',
        "Requests that change something must be JSON (`content-type: application/json`) and come",
        'from the same origin. Errors are `{"error": "<code>", "message": "<text>"}`.',
        "",
        "Generated from the code by `tools/gen_api_doc.py`; a test keeps it current.",
        "",
        "| Method | Path | What it does |",
        "| --- | --- | --- |",
    ]
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            summary = (op.get("description") or op.get("summary", "")).strip().splitlines()[0]
            lines.append(f"| {method.upper()} | `{path}` | {summary} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    OUT.write_text(render())
    sys.stdout.write(f"wrote {OUT}\n")
