"""Command line entry point."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from signalbox import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="signalbox", description=__doc__)
    parser.add_argument("--version", action="version", version=f"signalbox {__version__}")
    parser.add_argument("--data", default=None, help="data directory (default /data)")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("version", help="print the version")
    sub.add_parser("schema", help="print the JSON Schema of the network model")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in (None, "version"):
        print(f"signalbox {__version__}")
        return 0
    if args.command == "schema":
        from signalbox.model import json_schema

        print(json.dumps(json_schema(), indent=2, sort_keys=True))
        return 0
    parser.error(f"unknown command {args.command}")  # pragma: no cover - argparse rejects first
    return 2  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
