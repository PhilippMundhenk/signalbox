"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Sequence

from signalbox import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="signalbox", description=__doc__)
    parser.add_argument("--version", action="version", version=f"signalbox {__version__}")
    parser.add_argument("--data", default=None, help="data directory (default /data)")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("version", help="print the version")
    sub.add_parser("schema", help="print the JSON Schema of the network model")
    sub.add_parser("serve", help="run the web interface and the observation loop")
    sub.add_parser("reset-password", help="generate a new web interface password")
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

    from signalbox.service import build, data_dir_from

    services = build(data_dir_from(args.data))
    if args.command == "reset-password":
        from signalbox.web.auth import reset_password

        password = reset_password(services.store)
        services.close()
        print(f"New web interface password: {password}\nRestart Signalbox to use it.")
        return 0

    import uvicorn

    from signalbox.web.app import create_app

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    app = create_app(services)
    try:
        uvicorn.run(
            app,
            host=services.config.server.host,
            port=services.config.server.port,
            log_level="info",
            proxy_headers=True,
        )
    finally:
        services.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
