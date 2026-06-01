"""Command-line entry point for tcptrace-ng."""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence

from nicegui import ui

from . import __version__
from .app import build_page


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tcptrace-ng",
        description="Local web UI for tcptrace pcap analysis with interactive graphs.",
    )
    p.add_argument("dir", nargs="?", default=".", help="directory containing pcap files (default: cwd)")
    p.add_argument("--port", type=int, default=None, help="port to bind (default: pick free)")
    p.add_argument("--no-browser", action="store_true", help="don't auto-open browser")
    p.add_argument("--timeout", type=float, default=60.0, help="per-subprocess timeout seconds (default: 60)")
    p.add_argument("--debug", action="store_true", help="verbose logs, show suppressed lines")
    p.add_argument("-V", "--version", action="version", version=f"tcptrace-ng {__version__}")
    return p


def main(argv: Sequence[str] | None = None) -> None:
    args = build_arg_parser().parse_args(argv)
    # Apply CLI overrides to the shared module-level state before building
    # the page so handlers close over the configured values.
    from .app import state as _state

    _state.timeout = args.timeout
    _state.debug = args.debug

    os.chdir(args.dir)
    build_page()
    ui.run(
        port=args.port,
        show=not args.no_browser,
        reload=False,
        title="tcptrace-ng",
        dark=True,
    )


if __name__ == "__main__":
    main()
