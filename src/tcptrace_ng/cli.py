"""Command-line entry point for tcptrace-ng."""

from __future__ import annotations

import argparse
import os
import socket
from collections.abc import Sequence

from nicegui import ui

from . import __version__
from .app import build_page

_DEFAULT_PORT = 8080


def _pick_free_port(preferred: int = _DEFAULT_PORT) -> int:
    """Pick a TCP port to bind to. Try `preferred` first; if it's busy, ask
    the kernel for any free port (bind to 0). Small TOCTOU window between
    this probe and NiceGUI's actual bind; if another process grabs the port
    in between, NiceGUI surfaces the error normally.
    """
    for candidate in (preferred, 0):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("", candidate))
                return s.getsockname()[1]
        except OSError:
            continue
    raise RuntimeError("no free TCP port available")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tcptrace-ng",
        description="Local web UI for tcptrace pcap analysis with interactive graphs.",
    )
    p.add_argument(
        "dir", nargs="?", default=".", help="directory containing pcap files (default: cwd)"
    )
    p.add_argument("--port", type=int, default=None, help="port to bind (default: pick free)")
    p.add_argument("--no-browser", action="store_true", help="don't auto-open browser")
    p.add_argument(
        "--timeout", type=float, default=60.0, help="per-subprocess timeout seconds (default: 60)"
    )
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
    # An explicit --port respects the user's choice (and fails loudly if
    # busy); omitting --port auto-picks so the canonical default port being
    # taken doesn't keep the UI from launching.
    port = args.port if args.port is not None else _pick_free_port()
    # Replace NiceGUI's generic "NiceGUI ready to go" line with a branded
    # banner that names the app and the URL the user can click.
    print(f"tcptrace-ng → http://localhost:{port}", flush=True)
    ui.run(
        port=port,
        show=not args.no_browser,
        reload=False,
        title="tcptrace-ng",
        dark=True,
        show_welcome_message=False,
        # NiceGUI's default reconnect_timeout=3s yields a 2s socket.io
        # ping_timeout — a single heavy CPU step (synthesize + figure build
        # on dense conns) overruns that and the browser declares the server
        # dead. 30s gives the threadpool room to finish even the worst pcap.
        reconnect_timeout=30.0,
    )


if __name__ == "__main__":
    main()
