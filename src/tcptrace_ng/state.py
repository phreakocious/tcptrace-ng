"""Module-level UI state and cache-version composition.

`_State` is a plain dataclass-shaped container for the NiceGUI page's
session state. `cache_version()` composes the on-disk cache key from
the app version plus user-toggleable tcptrace flags; toggling a flag
yields a new key so the cache layer auto-invalidates.

This module imports nothing from `nicegui` and nothing from `app.py`.
"""

from __future__ import annotations

from pathlib import Path

from . import __version__
from .csum import CsumEvent
from .decap import DECAP_VERSION
from .desegment import DESEGMENT_VERSION
from .diagnose import Finding
from .runner import AnalyzeResult, ConnRow
from .stats_parser import STATS_PARSER_VERSION, ConnStats


class _State:
    """Module-level state. NiceGUI page is rebuilt per-client; state stays here."""

    def __init__(self) -> None:
        self.selected_pcap: Path | None = None
        self.effective_pcap: Path | None = None
        self.decap_encaps: set[str] = set()
        self.desegment_kinds: set[str] = set()
        self.desegment_coalesces: list[dict] = []
        self.pcap_warnings: list[str] = []
        self.conns_with_lro: set[int] = set()
        self.stats: list[ConnStats | ConnRow] = []
        self.analyzing: bool = False
        self.selected_conn: int | None = None
        self.stats_generation: int = 0
        self.conn_filter: str = ""
        self.chip_filters: set[str] = set()
        self.sort_key: str = "n"
        self.analyses: dict[int, AnalyzeResult] = {}
        self.findings: dict[int, list[Finding]] = {}
        self.figure_cache: dict[tuple, object] = {}
        self.timeout: float = 60.0
        self.debug: bool = False
        self.dns: bool = False
        self.with_rtt: bool = False
        self.with_warnings: bool = False
        self.zero_x_axis: bool = False
        self.bad_csum_events: list[CsumEvent] = []
        self.show_info: bool = False
        self.rate_unit: str = "bits"
        self.seq_mode: str = "rel"
        self.dock_summary: bool = False


state = _State()


def _escape_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def cache_version(s: _State) -> str:
    """Compose the cache-version key from `__version__` plus active tcptrace
    flag toggles plus the decap-output schema version. Toggling a flag changes
    the key so `invalidate_if_stale_version` wipes the previous cache."""
    parts = [
        __version__,
        f"d{DECAP_VERSION}",
        f"s{STATS_PARSER_VERSION}",
        f"x{DESEGMENT_VERSION}",
    ]
    if not s.dns:
        parts.append("n")
    if s.with_rtt:
        parts.append("r")
    if s.with_warnings:
        parts.append("w")
    if s.zero_x_axis:
        parts.append("zx")
    return "+".join(parts)


def _figure_cache_key(conn_n: int, metric: str, show_info: bool) -> tuple[int, str, bool]:
    """Cache key for a built plotly figure. Includes `show_info` so the
    markers-on and markers-off variants cache separately. The bool third
    element never collides with the `(conn, metric, "model")` model key."""
    return (conn_n, metric, show_info)
