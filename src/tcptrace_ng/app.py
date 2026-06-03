"""NiceGUI page and reactive state. The only module that imports nicegui.

Layout: top header (pcap dropdown + cache controls) + left drawer
(filter + clickable connection list + xpl-zip button) + main panel
(tabs over plotly graphs + collapsible color-coded tcptrace output).

Clicking a connection runs tcptrace for that connection on demand
(off the event loop via `run.io_bound`) and renders it in the main panel.
Analyzed connections stay in `state.analyses` so re-clicking is instant.
"""

from __future__ import annotations

import io
import json
import os
import re
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from nicegui import background_tasks, run, ui

from . import __version__
from .cache import (
    CacheLayout,
    clear_pcap_cache,
    invalidate_if_stale_version,
    is_fresh,
    load_stats,
    save_stats,
    total_cache_size,
    write_version,
)
from .classifier import Class, classify
from .csum import CsumEvent, scan_pcap as scan_csums
from .decap import DECAP_VERSION, decap_pcap, detect_encaps
from .offload import detect_offload
from .plotly_adapter import to_paired_plotly_figure, to_plotly_figure, to_throughput_figure, to_tsg_figure
from .tcp_inspect import synthesize as synthesize_tsg
from .throughput import DirectionSummary, ThroughputModelPair, synthesize_throughput
from .runner import (
    AnalyzeResult,
    ConnRow,
    RunnerError,
    analyze_all,
    analyze_connection,
    list_connections,
    try_convert_to_pcap,
)
from .stats_parser import STATS_PARSER_VERSION, ConnStats
from .theme import DARK_CSS
from .xpl_grouper import GroupedXpl, group_xpls
from .xpl_parser import XplPlot, parse_xpl

PCAP_GLOBS = ("*.pcap", "*.pcapng", "*.cap")

# How often to rescan the working directory for new/updated pcaps. The user
# generally writes captures while the page is open; long enough to be cheap
# (one round of stats() per pcap), short enough to feel live.
_PCAP_RESCAN_SECONDS = 30.0


def _scan_pcaps(cwd: Path) -> list[tuple[Path, os.stat_result]]:
    """Pcaps paired with their stat() result, sorted by mtime descending.

    One stat() per pcap; the result feeds both the sort key and the
    size/relative-time labels rendered into the dropdown.
    """
    found: list[tuple[Path, os.stat_result]] = []
    for pat in PCAP_GLOBS:
        for p in cwd.glob(pat):
            found.append((p, p.stat()))
    found.sort(key=lambda pair: pair[1].st_mtime, reverse=True)
    return found


def _humanize_delta(seconds: float) -> tuple[float, str]:
    """Pick the largest sensible unit for `seconds`. Returns (value, unit-suffix).

    Callers decide on precision: durations want one decimal (3.4s), relative
    timestamps want int (3s ago). ms is sub-second only; d is for spans ≥ a day.
    """
    if seconds < 1:
        return (seconds * 1000, "ms")
    if seconds < 60:
        return (seconds, "s")
    if seconds < 3600:
        return (seconds / 60, "m")
    if seconds < 86400:
        return (seconds / 3600, "h")
    return (seconds / 86400, "d")


def _format_mtime(stat_result: os.stat_result, now: float) -> str:
    """Terse relative time, ISO-date once we're past a week.

    Clamps a negative delta to zero so clock skew (NTP, dual-boot, VM snapshot)
    doesn't surface as a nonsense `-3s ago` label.
    """
    delta = max(0.0, now - stat_result.st_mtime)
    if delta >= 7 * 86400:
        return datetime.fromtimestamp(stat_result.st_mtime, tz=UTC).strftime("%Y-%m-%d")
    value, unit = _humanize_delta(delta)
    # mtime granularity for the user is seconds; sub-second deltas (clamped
    # future-mtime, just-written file) collapse to "0s ago" rather than "0ms".
    if unit == "ms":
        return "0s ago"
    return f"{int(value)}{unit} ago"


def _pcap_options(pcaps: list[tuple[Path, os.stat_result]], now: float) -> dict[str, str]:
    return {
        str(p): f"{p.name}  ({_format_size(st.st_size)} · {_format_mtime(st, now)})"
        for p, st in pcaps
    }


class _State:
    """Module-level state. NiceGUI page is rebuilt per-client; state stays here."""

    def __init__(self) -> None:
        self.selected_pcap: Path | None = None
        # The actual pcap fed to tcptrace. Equals selected_pcap unless outer
        # tunnel encaps (Geneve/VXLAN/GRE) were detected and stripped; then
        # it points at <cache>/decap.pcap. Always None when no pcap is picked.
        self.effective_pcap: Path | None = None
        self.decap_encaps: set[str] = set()
        # Findings from pre-flight scans (NIC offload, etc.) that don't break
        # analysis but distort the results the user is about to see.
        self.pcap_warnings: list[str] = []
        # Connection numbers where coalesced/LRO segments have been detected
        # mid-analysis. The pre-flight offload scan is bounded to the first
        # N frames and misses LRO that starts later; we top up the warning
        # list as analyses complete and reveal it.
        self.conns_with_lro: set[int] = set()
        self.stats: list[
            ConnStats | ConnRow
        ] = []  # may be ConnStats (rich) or ConnRow (basic) per pick
        self.analyzing: bool = False
        self.selected_conn: int | None = None
        self.conn_filter: str = ""
        self.chip_filters: set[str] = set()
        self.sort_key: str = "n"
        self.analyses: dict[int, AnalyzeResult] = {}
        # Built plotly figure dicts keyed by (conn_n, metric). Populated lazily
        # when a tab is activated; survives tab switches and re-clicks so
        # already-built figures don't re-parse the xpl or rebuild the dict.
        # Cleared when the pcap or flag set changes (i.e. cache version changes).
        self.figure_cache: dict[tuple[int, str], dict | None] = {}
        self.timeout: float = 60.0
        self.debug: bool = False
        # tcptrace command-line flag toggles. All default-off; we treat
        # `dns` as an opt-in (tcptrace's default *is* to resolve names, but
        # that hangs the UI on captures with many distinct endpoints, so the
        # app inverts it and passes `-n` unless the user opts in).
        self.dns: bool = False
        self.with_rtt: bool = False
        self.with_warnings: bool = False
        self.zero_x_axis: bool = False
        # All packets whose TCP checksum failed our independent verification
        # (csum.scan_pcap). One scan per pcap; per-connection use filters by
        # endpoints. We deliberately never invoke tcptrace's `--checksum`
        # filter — it drops bad-csum packets and hides half the connection
        # whenever NIC TX offload leaves outbound checksums zeroed.
        self.bad_csum_events: list[CsumEvent] = []
        # When False (default), info-tier TSG annotations (partial-ACK,
        # coalesced, benign dup-ACK, small win shrinks, …) are hidden from
        # the chart and summarized in a top strip instead. The toggle is
        # session-global so a user investigating a flow sees consistent
        # density across whichever connection they jump into.
        self.show_info: bool = False
        # Rate unit for throughput display. "bits" → bps/kbps/Mbps/Gbps
        # (decimal 1000s, conventional for network rates). "bytes" → keeps
        # the byte-prefixed display.
        self.rate_unit: str = "bits"
        # Sequence-number display. "rel" → subtract per-direction baseline
        # so axes read 0..bytes_sent; "abs" → raw uint32 from the wire.
        self.seq_mode: str = "rel"


state = _State()


def _escape_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _cache_version() -> str:
    """Compose the cache-version key from `__version__` plus any active tcptrace
    flag toggles plus the decap-output schema version. Toggling a flag changes
    the key, so `invalidate_if_stale_version` wipes the previous cache
    automatically — different flag sets yield different tcptrace output and
    can't share artifacts. The decap version is always included so changes to
    decap rewrite semantics invalidate every cache (including for plain pcaps
    that didn't trigger decap)."""
    parts = [__version__, f"d{DECAP_VERSION}", f"s{STATS_PARSER_VERSION}"]
    if not state.dns:
        parts.append("n")
    if state.with_rtt:
        parts.append("r")
    if state.with_warnings:
        parts.append("w")
    if state.zero_x_axis:
        parts.append("zx")
    return "+".join(parts)


def _format_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    return f"{n / 1024 / 1024 / 1024:.2f} GB"


def _matches_filter(row, q: str) -> bool:
    if not q:
        return True
    needle = q.lower()
    return needle in str(row.n) or needle in row.host_a.lower() or needle in row.host_b.lower()


def build_xpl_zip(analyses: dict[int, AnalyzeResult]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for n, result in analyses.items():
            for xpl in result.xpl_files:
                zf.write(xpl, arcname=f"conn-{n}/{xpl.name}")
    return buf.getvalue()


def _format_duration(s: float) -> str:
    value, unit = _humanize_delta(s)
    if unit == "ms":
        return f"{value:.0f}ms"
    return f"{value:.1f}{unit}"


def _badges(stats: ConnStats) -> list[str]:
    out: list[str] = []
    if stats.rexmt_packets > 0:
        out.append("RX")
    if stats.has_rst:
        out.append("RST")
    if stats.complete_handshake:
        out.append("FIN")
    else:
        out.append("INC")
    a, b = _csum_counts_for_endpoints(stats.host_a, stats.host_b)
    if a + b > 0:
        # The chip shows a→b/b→a totals. The acked-vs-lost split lives in the
        # per-direction summary block under the chart; the chip is for triage
        # at a glance.
        out.append(f"CSUM {a}/{b}")
    return out


def _split_endpoint(ep: str) -> tuple[str, int] | None:
    """Parse `1.2.3.4:5` into `("1.2.3.4", 5)`. Returns None if it doesn't split."""
    if ":" not in ep:
        return None
    ip, _, port = ep.rpartition(":")
    if not port.isdigit():
        return None
    return ip, int(port)


def _csum_times_directed(src: str, dst: str) -> list[float]:
    """Bad-csum event times for packets going `src` → `dst` (each endpoint as
    `ip:port`). Empty list when either endpoint won't parse."""
    s = _split_endpoint(src)
    d = _split_endpoint(dst)
    if s is None or d is None:
        return []
    return [
        ev.time
        for ev in state.bad_csum_events
        if (ev.src_ip, ev.src_port) == s and (ev.dst_ip, ev.dst_port) == d
    ]


def _csum_counts_for_endpoints(host_a: str, host_b: str) -> tuple[int, int]:
    """(a→b, b→a) bad-checksum counts for one connection."""
    return len(_csum_times_directed(host_a, host_b)), len(_csum_times_directed(host_b, host_a))


_VERDICT_CSS = {
    Class.GOOD: "tcptrace-dot-good",
    Class.LOOK: "tcptrace-dot-look",
    Class.BAD: "tcptrace-dot-bad",
    Class.NORMAL: "tcptrace-dot-normal",
}


_BULK_BYTES_THRESHOLD = 100 * 1024  # 100 KB; hardcoded per spec


def _matches_chips(row, chips: set[str]) -> bool:
    if not chips:
        return True
    if not isinstance(row, ConnStats):
        # Stats-less fallback rows never satisfy stats-based chips
        return False
    if "bad" in chips and row.verdict != Class.BAD:
        return False
    if "rst" in chips and not row.has_rst:
        return False
    if "rexmt" in chips and row.rexmt_packets == 0:
        return False
    if "incomplete" in chips and row.complete_handshake:
        return False
    return not ("bulk" in chips and row.total_bytes < _BULK_BYTES_THRESHOLD)


def _sort_rows(rows: list, key: str) -> list:
    def get(r, attr, default):
        return getattr(r, attr, default)

    if key == "n":
        return sorted(rows, key=lambda r: get(r, "n", 0))
    if key == "bytes":
        return sorted(rows, key=lambda r: get(r, "total_bytes", 0), reverse=True)
    if key == "duration":
        return sorted(rows, key=lambda r: get(r, "duration_s", 0.0), reverse=True)
    if key == "rexmt":
        return sorted(rows, key=lambda r: get(r, "rexmt_packets", 0), reverse=True)
    return rows


_METRIC_LABELS = {
    "tsg": "Time-sequence",
    "tput": "Throughput",
    "rtt": "RTT",
    "owin": "Outstanding window",
    "ssize": "Segment size",
    "tline": "Timeline",
}


def _direction_labels(row) -> tuple[str, str]:
    """Return (forward_label, backward_label) using client/server when known."""
    if isinstance(row, ConnStats) and row.client_is_a is not None:
        return (
            ("client → server", "server → client")
            if row.client_is_a
            else ("server → client", "client → server")
        )
    return (
        f"{row.host_a} → {row.host_b}",
        f"{row.host_b} → {row.host_a}",
    )


def _build_metric_figure(
    forward: Path | None,
    backward: Path | None,
    combined: Path | None,
    fwd_label: str,
    bwd_label: str,
    metric: str | None = None,
    details_text: str = "",
    show_info: bool = False,
    rate_unit: str = "bytes",
    seq_mode: str = "abs",
) -> dict | None:
    """Parse xpl(s) and build a plotly figure dict. Returns None if no data.

    The TSG metric routes through tcp_inspect.synthesize() + to_tsg_figure()
    for semantic tooltips, anomaly annotations, and the in-flight overlay.
    All other metrics use the generic paired path unchanged.
    """
    if metric == "tsg":
        fwd_plot = None
        bwd_plot = None
        if forward is not None:
            plot, _err = _safe_parse_xpl(forward)
            if plot is not None and plot.commands:
                fwd_plot = plot
        if backward is not None:
            plot, _err = _safe_parse_xpl(backward)
            if plot is not None and plot.commands:
                bwd_plot = plot
        if fwd_plot is None and bwd_plot is None:
            return None
        fwd_csum, bwd_csum = _csum_for_plots(fwd_plot, bwd_plot)
        pair = synthesize_tsg(
            fwd_plot,
            bwd_plot,
            details_text,
            bad_csum_times_fwd=fwd_csum,
            bad_csum_times_bwd=bwd_csum,
        )
        return to_tsg_figure(pair, show_info=show_info, seq_mode=seq_mode)

    if metric == "tput":
        tput_pair = _build_tput_model(forward, backward, details_text)
        if tput_pair is None:
            return None
        return to_throughput_figure(tput_pair, show_info=show_info, rate_unit=rate_unit)

    if combined is not None:
        plot, _err = _safe_parse_xpl(combined)
        if plot is None or not plot.commands:
            return None
        return to_plotly_figure(plot, metric=metric)

    fwd_plot = None
    bwd_plot = None
    if forward is not None:
        plot, _err = _safe_parse_xpl(forward)
        if plot is not None and plot.commands:
            fwd_plot = plot
    if backward is not None:
        plot, _err = _safe_parse_xpl(backward)
        if plot is not None and plot.commands:
            bwd_plot = plot
    if fwd_plot is None and bwd_plot is None:
        return None
    return to_paired_plotly_figure(
        fwd_plot, bwd_plot, fwd_label, bwd_label, metric=metric
    )


def _safe_parse_xpl(xpl: Path) -> tuple[XplPlot | None, str | None]:
    """Single try/except wrapper around parse_xpl. Returns (plot, None) on
    success or (None, message) on failure so callers can pick recovery."""
    try:
        return parse_xpl(xpl), None
    except Exception as exc:
        return None, f"{xpl.name}: {exc}"


def _csum_for_plots(
    fwd_plot: XplPlot | None, bwd_plot: XplPlot | None
) -> tuple[list[float], list[float]]:
    """Map per-direction csum times by parsing endpoints out of the xpl titles.

    Each tsg xpl carries a `<src:port> ==> <dst:port>` title; we use that as
    the directional filter rather than the connection's `ConnStats` row, so
    this also works for the raw-xpl preview path where stats aren't loaded.
    """
    from .tcp_inspect import _parse_endpoints  # avoid widening tcp_inspect's API

    fwd_times: list[float] = []
    bwd_times: list[float] = []
    if fwd_plot is not None:
        src, dst = _parse_endpoints(fwd_plot.title)
        if src and dst:
            fwd_times = _csum_times_directed(src, dst)
    if bwd_plot is not None:
        src, dst = _parse_endpoints(bwd_plot.title)
        if src and dst:
            bwd_times = _csum_times_directed(src, dst)
    return fwd_times, bwd_times


def _build_tput_model(
    forward: Path | None,
    backward: Path | None,
    details_text: str,
) -> ThroughputModelPair | None:
    fwd_plot = None
    bwd_plot = None
    if forward is not None:
        plot, _err = _safe_parse_xpl(forward)
        if plot is not None and plot.commands:
            fwd_plot = plot
    if backward is not None:
        plot, _err = _safe_parse_xpl(backward)
        if plot is not None and plot.commands:
            bwd_plot = plot
    if fwd_plot is None and bwd_plot is None:
        return None
    fwd_csum, bwd_csum = _csum_for_plots(fwd_plot, bwd_plot)
    tsg_pair = synthesize_tsg(
        fwd_plot,
        bwd_plot,
        details_text,
        bad_csum_times_fwd=fwd_csum,
        bad_csum_times_bwd=bwd_csum,
    )
    stats = (
        tsg_pair.fwd.summary if tsg_pair.fwd is not None
        else tsg_pair.bwd.summary if tsg_pair.bwd is not None
        else None
    )
    return synthesize_throughput(tsg_pair, stats)


_LRO_WARNING_PREFIX = "NIC offload (LRO/GRO): "


def _has_lro_anomaly(pair) -> bool:
    """True if either direction of the pair has any coalesced segment.

    `pair` is a TsgModelPair or None. coalesced anomalies are emitted by
    tcp_inspect across the whole capture, so this catches LRO that begins
    after the pre-flight bounded scan's frame budget runs out.
    """
    if pair is None:
        return False
    for model in (pair.fwd, pair.bwd):
        if model is None:
            continue
        if any(a.kind == "coalesced" for a in model.anomalies):
            return True
    return False


def _sync_lro_warning(state: "_State") -> None:
    """Add/refresh the LRO warning string in state.pcap_warnings.

    Drops any stale LRO entry first, then appends a fresh one reflecting
    the current `state.conns_with_lro` count. n=0 just drops.
    """
    state.pcap_warnings = [
        w for w in state.pcap_warnings if not w.startswith(_LRO_WARNING_PREFIX)
    ]
    n = len(state.conns_with_lro)
    if n == 0:
        return
    state.pcap_warnings.append(
        f"{_LRO_WARNING_PREFIX}coalesced segments detected in {n} "
        f"connection{'s' if n != 1 else ''}. See per-connection LRO "
        f"counts in the TSG info strip. MSS, time-sequence staircases, "
        f"and retransmit detection are unreliable for these flows."
    )


def _build_tsg_model(
    forward: Path | None,
    backward: Path | None,
    details_text: str,
):
    """Parse + synthesize a TsgModelPair without building the figure.
    Module-level so callers can run it through run.io_bound separately
    from the figure build."""
    fwd_plot = None
    bwd_plot = None
    if forward is not None:
        plot, _err = _safe_parse_xpl(forward)
        if plot is not None and plot.commands:
            fwd_plot = plot
    if backward is not None:
        plot, _err = _safe_parse_xpl(backward)
        if plot is not None and plot.commands:
            bwd_plot = plot
    if fwd_plot is None and bwd_plot is None:
        return None
    fwd_csum, bwd_csum = _csum_for_plots(fwd_plot, bwd_plot)
    return synthesize_tsg(
        fwd_plot,
        bwd_plot,
        details_text,
        bad_csum_times_fwd=fwd_csum,
        bad_csum_times_bwd=bwd_csum,
    )


def _format_bytes(n: float | int | None) -> str:
    if n is None:
        return "—"
    n = float(n)
    if n < 1024:
        return f"{n:.0f} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.2f} GB"


def _format_ms(v: float | None) -> str:
    if v is None:
        return "—"
    return f"{v:.1f} ms"


def _format_count(v: int | None) -> str:
    if v is None:
        return "—"
    return f"{v:,}"


def _format_throughput_Bps(v: float | None) -> str:  # noqa: N802 — `B` vs `b` is load-bearing; Bps ≠ bps
    if v is None:
        return "—"
    if v < 1024:
        return f"{v:.0f} B/s"
    if v < 1024 * 1024:
        return f"{v / 1024:.1f} KB/s"
    if v < 1024 * 1024 * 1024:
        return f"{v / (1024 * 1024):.1f} MB/s"
    return f"{v / (1024 * 1024 * 1024):.2f} GB/s"


def _format_rate_bps(v_Bps: float | None) -> str:  # noqa: N802
    """Same shape as `_format_throughput_Bps` but bits-per-second, SI (1000s).

    Network engineers conventionally read line rates in decimal bits; matching
    that here avoids a silent IEC-vs-SI confusion when the user expects Mbps.
    """
    if v_Bps is None:
        return "—"
    v = v_Bps * 8.0
    if v < 1000:
        return f"{v:.0f} bps"
    if v < 1000 * 1000:
        return f"{v / 1000:.1f} kbps"
    if v < 1000 * 1000 * 1000:
        return f"{v / (1000 * 1000):.1f} Mbps"
    return f"{v / (1000 * 1000 * 1000):.2f} Gbps"


def _format_rate(v_Bps: float | None, unit: str) -> str:
    """Dispatch on `state.rate_unit` for any throughput display site."""
    return _format_rate_bps(v_Bps) if unit == "bits" else _format_throughput_Bps(v_Bps)


_CTX_RATE_RE = re.compile(r"(\d+)\s+Bps")


def _apply_rate_unit_to_ctx(ctx: str, unit: str) -> str:
    """Rewrite `NN Bps` substrings inside a conn-header context line.

    `ctx` is built by `stats_parser.build_context_lines` and embeds tcptrace's
    raw Bps integer; this re-renders it through `_format_rate` at view time so
    flipping the toggle doesn't require re-parsing the tcptrace output.
    """
    if unit == "bytes":
        return ctx
    return _CTX_RATE_RE.sub(lambda m: _format_rate_bps(float(m.group(1))), ctx)


def _format_bad_csum(ws) -> str:
    """Render the bad-csum slot for the Reliability column.

    Splits the count into `acked` (likely NIC offload) and `lost` (segment
    later retransmitted, so the original was dropped). When everything's
    acked we say so plainly; when nothing's acked we omit the split.
    """
    total = ws.n_bad_csum
    if ws.n_bad_csum_lost > 0 and ws.n_bad_csum_acked > 0:
        return (
            f"{total} bad csum ({ws.n_bad_csum_lost} lost, "
            f"{ws.n_bad_csum_acked} acked)"
        )
    if ws.n_bad_csum_lost > 0:
        return f"{total} bad csum ({ws.n_bad_csum_lost} lost)"
    if ws.n_bad_csum_acked > 0:
        return f"{total} bad csum (all acked)"
    return f"{total} bad csum"


def _sev(value: str, severity: str) -> str:
    """Wrap a stat-token in a severity span. Severity in {ok, notable, bad}."""
    return f'<span class="tt-{severity}">{value}</span>' if severity else value


def _retx_severity(n_retx: int, n_segs: int) -> str:
    if n_retx == 0:
        return "ok"
    pct = (n_retx / n_segs) if n_segs else 0.0
    if pct >= 0.05:
        return "bad"
    if pct >= 0.01:
        return "notable"
    return ""


def _stats_grid_html(label: str, ws, rate_unit: str = "bytes") -> str:
    pct = (100.0 * ws.n_retx / ws.n_segs) if ws.n_segs else 0.0
    retx_sev = _retx_severity(ws.n_retx, ws.n_segs)
    rto_sev = "bad" if ws.n_rto > 0 else "ok"
    fast_sev = "notable" if ws.n_fast > 0 else "ok"
    shrink_sev = "bad" if ws.n_win_shrink >= 1000 else "notable" if ws.n_win_shrink >= 100 else "ok"
    zerow_sev = "bad" if ws.n_zero_win >= 10 else "notable" if ws.n_zero_win >= 1 else "ok"
    csum_sev = "bad" if ws.n_bad_csum_lost > 0 else "notable" if ws.n_bad_csum > 0 else ""

    csum_text = _format_bad_csum(ws)
    other_anom = (
        f"{ws.n_dup_ack} dup · {ws.n_partial_ack} partial · "
        f"{ws.n_coalesced} coal · {ws.n_ooo} OOO"
    )
    reliability_extras = (
        f"{other_anom} · {_sev(csum_text, csum_sev)}"
        if ws.n_bad_csum > 0
        else other_anom
    )

    rows = [
        ("Volume",
         f"{_format_count(ws.n_segs)} segs",
         f"{_format_bytes(ws.bytes_sent)} sent",
         f"{_format_rate(ws.throughput_eff_Bps, rate_unit)} eff",
         f"{_format_count(ws.n_sack_regions)} SACK"),
        ("Reliability",
         _sev(f"{ws.n_retx} retx ({pct:.1f}%)", retx_sev),
         f" · {_sev(f'{ws.n_rto} RTO', rto_sev)}",
         f" · {_sev(f'{ws.n_fast} fast', fast_sev)}",
         reliability_extras),
        ("Latency",
         f"p50 {_format_ms(ws.rtt_p50_ms)}",
         f"p95 {_format_ms(ws.rtt_p95_ms)}",
         f"min/max {_format_ms(ws.rtt_min_ms)}/{_format_ms(ws.rtt_max_ms)}",
         f"jitter {_format_ms(ws.jitter_ms)}"),
        ("Receiver",
         f"rwnd peak {_format_bytes(ws.rwin_peak)}",
         f"scale ×{ws.rwin_scale}" if ws.rwin_scale is not None else "scale unknown",
         _sev(f"shrinks: {ws.n_win_shrink}", shrink_sev),
         _sev(f"0-win: {ws.n_zero_win}", zerow_sev)),
    ]
    parts = [f'<div class="dir-label">{label}</div>']
    # Render as four columns; each column is one category.
    titles = [r[0] for r in rows]
    values = [r[1:] for r in rows]
    for col_idx, title in enumerate(titles):
        parts.append(f'<div><div class="col-title">{title}</div>')
        for v in values[col_idx]:
            parts.append(f"<div>{v}</div>")
        parts.append("</div>")
    return "".join(parts)


def _throughput_stats_grid_html(label: str, summary: DirectionSummary, rate_unit: str = "bytes") -> str:
    bdp = (
        f"{summary.bdp_utilization_frac * 100:.1f}%"
        if summary.bdp_utilization_frac is not None
        else "—"
    )
    rows = [
        ("Goodput",
         f"avg {_format_rate(summary.mean_goodput_Bps, rate_unit)}",
         f"p50 {_format_rate(summary.p50_goodput_Bps, rate_unit)}",
         f"p95 {_format_rate(summary.p95_goodput_Bps, rate_unit)}",
         f"peak {_format_rate(summary.peak_goodput_Bps, rate_unit)}"),
        ("Wire",
         f"{_format_bytes(summary.total_wire_bytes)} total",
         f"{summary.retx_overhead_frac * 100:.1f}% retx overhead"),
        ("BDP utilization",
         bdp),
        ("Anomalies",
         f"{summary.stall_count} stalls ({summary.total_stall_s:.2f}s total)",
         f"{summary.cliff_count} cliffs"),
    ]
    parts = [f'<div class="dir-label">{label}</div>']
    titles = [r[0] for r in rows]
    values = [r[1:] for r in rows]
    for col_idx, title in enumerate(titles):
        parts.append(f'<div><div class="col-title">{title}</div>')
        for v in values[col_idx]:
            parts.append(f"<div>{v}</div>")
        parts.append("</div>")
    return "".join(parts)


def _render_throughput_stats_panel(
    container,
    pair: ThroughputModelPair,
    fwd_label: str,
    bwd_label: str,
    t0: float | None,
    t1: float | None,
) -> None:
    container.clear()
    with container:
        html_parts: list[str] = []
        if pair.fwd is not None:
            html_parts.append(_throughput_stats_grid_html(fwd_label, pair.fwd.window_stats(t0, t1), state.rate_unit))
        if pair.bwd is not None:
            html_parts.append(_throughput_stats_grid_html(bwd_label, pair.bwd.window_stats(t0, t1), state.rate_unit))
        ui.html(f'<div class="tsg-stats">{"".join(html_parts)}</div>')


def _xrange_from_relayout(args: dict) -> tuple[float | None, float | None]:
    """Extract (t0, t1) in epoch seconds from a plotly_relayout event payload.

    Returns (None, None) on autorange resets (double-click). x-axis is type=date,
    so Plotly emits ISO strings (with timezone Z or +00:00)."""
    # Autorange reset.
    if args.get("xaxis.autorange") is True or args.get("autosize") is True:
        return (None, None)
    r0 = args.get("xaxis.range[0]")
    r1 = args.get("xaxis.range[1]")
    if r0 is None or r1 is None:
        return (None, None)

    def _to_epoch(v) -> float | None:
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str):
            # Plotly emits e.g. "2018-09-28 23:46:24.7389" with millisecond precision.
            for fmt in (
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
            ):
                try:
                    dt = datetime.strptime(v, fmt)
                    return dt.replace(tzinfo=UTC).timestamp()
                except ValueError:
                    continue
        return None

    return (_to_epoch(r0), _to_epoch(r1))


def _render_stats_panel(
    container,
    pair,
    fwd_label: str,
    bwd_label: str,
    t0: float | None,
    t1: float | None,
) -> None:
    container.clear()
    with container:
        html_parts: list[str] = []
        if pair.fwd is not None:
            html_parts.append(_stats_grid_html(fwd_label, pair.fwd.window_stats(t0, t1), state.rate_unit))
        if pair.bwd is not None:
            html_parts.append(_stats_grid_html(bwd_label, pair.bwd.window_stats(t0, t1), state.rate_unit))
        ui.html(f'<div class="tsg-stats">{"".join(html_parts)}</div>')


def build_page() -> None:
    """Register the `/` route on the default NiceGUI app."""

    @ui.page("/")
    def index() -> None:
        ui.add_head_html(f"<style>{DARK_CSS}</style>")

        cwd = Path.cwd()
        pcaps = _scan_pcaps(cwd)
        pcap_options = _pcap_options(pcaps, time.time())

        # =========== header ===========
        with ui.header(elevated=False).classes("tcptrace-header items-center gap-3 px-4"):
            ui.label("tcptrace-ng").classes("tcptrace-brand text-base")
            ui.label("›").classes("tcptrace-sep")  # noqa: RUF001 — intentional brand separator (single right-pointing angle quotation mark)
            pcap_select = (
                ui.select(
                    options=pcap_options or {"": "no pcaps in this directory"},
                    value=str(state.selected_pcap) if state.selected_pcap else None,
                )
                .props("dense dark outlined options-dense")
                .classes("min-w-[280px]")
            )
            with ui.row().classes("items-center gap-2 tcptrace-flag-strip"):
                dns_check = (
                    ui.checkbox("DNS", value=state.dns)
                    .props("dense dark")
                    .tooltip(
                        "resolve hostnames and port names (slow on captures with"
                        " many distinct endpoints; off by default)"
                    )
                )
                rtt_check = (
                    ui.checkbox("RTT", value=state.with_rtt)
                    .props("dense dark")
                    .tooltip("-r: include RTT statistics in the long output")
                )
                warn_check = (
                    ui.checkbox("warn", value=state.with_warnings)
                    .props("dense dark")
                    .tooltip("-w: include tcptrace warning messages")
                )
                zerox_check = (
                    ui.checkbox("0-axis", value=state.zero_x_axis)
                    .props("dense dark")
                    .tooltip("-zx: plot graph time axis from 0 instead of wallclock")
                )
                rate_toggle = (
                    ui.toggle(["bits", "bytes"], value=state.rate_unit)
                    .props("dense dark unelevated toggle-color=primary")
                    .tooltip("throughput display unit (default bits)")
                )
                seq_toggle = (
                    ui.toggle(["rel", "abs"], value=state.seq_mode)
                    .props("dense dark unelevated toggle-color=primary")
                    .tooltip("sequence number display (default relative)")
                )
            ui.space()
            # Warning pill — hidden when there are no findings. Click opens a
            # dialog with the full text; tooltip shows the first line on hover.
            warning_chip = (
                ui.button("")
                .props("flat dense no-caps color=warning")
                .classes("tcptrace-warning-chip mr-2")
            )
            warning_chip.visible = False
            warning_dialog = ui.dialog()
            cache_label = ui.label().classes("tcptrace-cache-label mr-2")
            clear_btn = ui.button("Clear cache").props("flat dense no-caps color=grey-5")
            reanalyze_btn = ui.button("Reanalyze").props("flat dense no-caps color=grey-5")

        def refresh_cache_label() -> None:
            parts = [f"cache: {_format_size(total_cache_size(cwd))}"]
            if state.decap_encaps:
                parts.append(f"decap: {'+'.join(sorted(state.decap_encaps))}")
            cache_label.set_text(" · ".join(parts))

        def refresh_warnings() -> None:
            """Refresh the warning chip + dialog from `state.pcap_warnings`.

            Enters the chip's own slot so we can safely create the Tooltip
            child element from a background task (e.g. when LRO surfaces
            mid-render of a TSG figure).
            """
            warnings = state.pcap_warnings
            if not warnings:
                warning_chip.visible = False
                return
            n = len(warnings)
            label = f"⚠ {n} warning" if n == 1 else f"⚠ {n} warnings"
            warning_chip.set_text(label)
            with warning_chip:
                warning_chip.tooltip(warnings[0] if n == 1 else f"{warnings[0]}  (+{n - 1} more)")
            warning_chip.visible = True
            warning_dialog.clear()
            with warning_dialog, ui.card().classes("tcptrace-warning-card"):
                ui.label("Capture warnings").classes("tcptrace-warning-title")
                for w in warnings:
                    ui.label(w).classes("tcptrace-warning-body")
                ui.button("close", on_click=warning_dialog.close).props("flat dense")

        def refresh_pcap_dropdown() -> None:
            """Rescan cwd and update the dropdown so new captures (and aging
            relative-time labels) surface without a full page reload."""
            fresh = _scan_pcaps(cwd)
            options = _pcap_options(fresh, time.time()) or {"": "no pcaps in this directory"}
            pcap_select.set_options(options, value=pcap_select.value)

        # =========== sidebar ===========
        with (
            ui.left_drawer(fixed=True, value=True)
            .props("width=300 bordered")
            .classes("tcptrace-sidebar p-0"),
            ui.column().classes("w-full h-full gap-0 no-wrap"),
        ):
            with ui.column().classes("w-full tcptrace-sidebar-header px-3 py-2 gap-1"):
                conn_count_label = ui.label("").classes("text-xs text-gray-500")
                with ui.row().classes("tcptrace-chip-row w-full gap-1"):
                    for key, label in [
                        ("bad", "Bad"),
                        ("rst", "RST"),
                        ("rexmt", "Retransmits"),
                        ("incomplete", "Incomplete"),
                        ("bulk", "Bulk ≥100K"),
                    ]:
                        chip = ui.chip(label).props("dense outline clickable")

                        def _toggle(_, k=key, c=chip):
                            if k in state.chip_filters:
                                state.chip_filters.discard(k)
                            else:
                                state.chip_filters.add(k)
                            c.props("color=primary" if k in state.chip_filters else "color=grey-8")
                            render_sidebar()

                        chip.on("click", _toggle)
                        chip.props("color=grey-8")
                filter_input = (
                    ui.input(placeholder="filter…")
                    .props("dense dark borderless debounce=150")
                    .classes("tcptrace-filter w-full")
                )
                sort_select = (
                    ui.select(
                        options={
                            "n": "sort: #",
                            "bytes": "sort: bytes ↓",
                            "duration": "sort: duration ↓",
                            "rexmt": "sort: retransmits ↓",
                        },
                        value=state.sort_key,
                    )
                    .props("dense dark borderless options-dense")
                    .classes("tcptrace-sort w-full")
                )

                def _on_sort_change(e):
                    state.sort_key = e.value or "n"
                    render_sidebar()

                sort_select.on_value_change(_on_sort_change)
            conn_list_container = ui.column().classes("w-full flex-grow overflow-auto gap-0")
            with ui.row().classes("w-full tcptrace-sidebar-footer px-3 py-2"):
                download_btn = (
                    ui.button("↓ xpl zip")
                    .props("flat dense no-caps color=grey-5 disable")
                    .classes("w-full")
                )

        # =========== main ===========
        main_container = ui.column().classes("tcptrace-main w-full gap-3")

        # ---------- helpers ----------

        def _download_zip() -> None:
            if not state.analyses or state.selected_pcap is None:
                return
            data = build_xpl_zip(state.analyses)
            ui.download(data, filename=f"{state.selected_pcap.name}-xpl.zip")

        def _refresh_download_btn() -> None:
            if state.analyses:
                download_btn.props(remove="disable")
            else:
                download_btn.props("disable")

        def render_main() -> None:
            main_container.clear()
            with main_container:
                if not pcaps:
                    ui.label(f"no pcap files in {cwd}").classes("tcptrace-empty text-red")
                    return
                if state.selected_pcap is None:
                    ui.label("select a pcap from the header").classes("tcptrace-empty w-full")
                    return
                if state.selected_conn is None:
                    ui.label("click a connection on the left to analyze it").classes(
                        "tcptrace-empty w-full"
                    )
                    return
                n = state.selected_conn
                row = next((r for r in state.stats if r.n == n), None)
                title_main = f"Conn {n}"
                subtitle = ""
                fwd_ctx = bwd_ctx = ""
                fwd_label = bwd_label = ""
                if row is not None:
                    subtitle = f"{row.host_a}  ↔  {row.host_b}"
                    if isinstance(row, ConnStats):
                        fwd_label, bwd_label = _direction_labels(row)
                        fwd_ctx, bwd_ctx = row.fwd_ctx, row.bwd_ctx
                groups, tabs, default_tab = [], None, ""
                output_dialog = (
                    _build_output_dialog(state.analyses[n])
                    if n in state.analyses
                    else None
                )
                with ui.column().classes("w-full gap-0 tcptrace-sticky-head"):
                    with ui.row().classes("w-full items-center no-wrap"):
                        ui.label(title_main).classes("tcptrace-title")
                        ui.space()
                        if output_dialog is not None:
                            ui.button(
                                "tcptrace output", on_click=output_dialog.open
                            ).props("flat dense").classes("tcptrace-rawout-btn")
                    if subtitle:
                        ui.label(subtitle).classes("tcptrace-subtitle")
                    if fwd_ctx:
                        ui.label(
                            f"{fwd_label}  {_apply_rate_unit_to_ctx(fwd_ctx, state.rate_unit)}"
                        ).classes("tcptrace-context")
                    if bwd_ctx:
                        ui.label(
                            f"{bwd_label}  {_apply_rate_unit_to_ctx(bwd_ctx, state.rate_unit)}"
                        ).classes("tcptrace-context")
                    if n in state.analyses:
                        groups, tabs, default_tab = _render_tabs_head(state.analyses[n])
                if n not in state.analyses:
                    with ui.row().classes("w-full items-center gap-2 mt-6"):
                        ui.spinner(size="md")
                        ui.label(f"running tcptrace for conn {n}…").classes("text-gray-400")
                    return
                _render_analysis(state.analyses[n], groups, tabs, default_tab)

        def _render_tabs_head(result: AnalyzeResult) -> tuple[list[GroupedXpl], object | None, str]:
            """Render the tab strip. Returns (groups, tabs_element, default_tab_label).

            Returns ([], None, "") when tcptrace emitted no xpl files for this
            connection; caller renders an empty-state in _render_analysis.
            Emptiness of any individual group is determined lazily when the
            user activates its tab — pre-parsing every xpl just to check would
            block the asyncio loop for hundreds of ms on dense captures.
            """
            groups = group_xpls(result.xpl_files)
            if not groups:
                return [], None, ""
            default_metric = "tsg" if any(g.metric == "tsg" for g in groups) else groups[0].metric
            with (
                ui.tabs()
                .props("dense dark active-color=white outside-arrows mobile-arrows")
                .classes("w-full") as tabs
            ):
                for g in groups:
                    ui.tab(_METRIC_LABELS[g.metric])
            return groups, tabs, _METRIC_LABELS[default_metric]

        def _render_analysis(
            result: AnalyzeResult,
            groups: list[GroupedXpl],
            tabs,
            default_tab: str,
        ) -> None:
            """Render the tab panels as empty containers and wire lazy population.

            Only the active tab's figure is built; other tabs build on click,
            and each (conn, metric) figure is memoized in `state.figure_cache`
            so re-activation is instant. Figure construction runs through
            `run.io_bound` so the asyncio loop keeps ticking — without that,
            a busy figure build (~hundreds of ms on dense captures) would
            block the websocket and trip NiceGUI's client-side ping timeout.
            """
            if not (groups and tabs is not None):
                ui.label("no graphs available").classes("tcptrace-empty w-full")
                return
            row = next((r for r in state.stats if r.n == state.selected_conn), None)
            fwd_label, bwd_label = _direction_labels(row) if row is not None else ("→", "←")
            conn_n = state.selected_conn

            panel_containers: dict[str, ui.column] = {}
            with (
                ui.tab_panels(tabs, value=default_tab)
                .classes("w-full")
                .style("background: transparent;")
            ):
                for g in groups:
                    with ui.tab_panel(_METRIC_LABELS[g.metric]).classes("p-0"):
                        panel_containers[g.metric] = ui.column().classes("w-full gap-0")

            metric_by_label = {_METRIC_LABELS[g.metric]: g.metric for g in groups}
            group_by_metric = {g.metric: g for g in groups}
            activated: set[str] = set()

            def _show_figure(metric: str, fig: dict | None) -> None:
                container = panel_containers[metric]
                container.clear()
                with container:
                    if fig is None:
                        ui.label("no data in this direction").classes(
                            "tcptrace-empty w-full"
                        ).style("margin-top: 32px;")
                        return
                    if metric == "tsg":
                        with ui.row().classes(
                            "items-center gap-2 px-3 py-1 w-full justify-end"
                        ):
                            info_switch = (
                                ui.switch(
                                    "Show info markers", value=state.show_info
                                )
                                .props("dense dark")
                                .tooltip(
                                    "Partial-ACK, coalesced (LRO), benign dup-ACK,"
                                    " small win shrinks — off by default to keep"
                                    " the chart focused on alerts and protocol"
                                    " markers"
                                )
                            )
                    plotly_el = ui.plotly(fig).classes("w-full").style(
                        "height: calc(100vh - 320px); min-height: 480px;"
                    )
                    if metric == "tsg":
                        model_pair = state.figure_cache.get((conn_n, metric, "model"))
                        if model_pair is not None:
                            stats_box = ui.column().classes("w-full")
                            _render_stats_panel(
                                stats_box, model_pair, fwd_label, bwd_label, None, None
                            )

                            def _on_relayout(e) -> None:
                                t0, t1 = _xrange_from_relayout(e.args or {})
                                _render_stats_panel(
                                    stats_box, model_pair, fwd_label, bwd_label, t0, t1
                                )

                            plotly_el.on("plotly_relayout", _on_relayout)

                            def _on_info_toggle(e) -> None:
                                state.show_info = bool(e.value)
                                new_fig = to_tsg_figure(
                                    model_pair, show_info=state.show_info, seq_mode=state.seq_mode
                                )
                                state.figure_cache[(conn_n, metric)] = new_fig
                                plotly_el.update_figure(new_fig)

                            info_switch.on_value_change(_on_info_toggle)
                    if metric == "tput":
                        with ui.row().classes(
                            "items-center gap-2 px-3 py-1 w-full justify-end"
                        ):
                            tput_info_switch = (
                                ui.switch(
                                    "Show info anomalies", value=state.show_info
                                )
                                .props("dense dark")
                                .tooltip(
                                    "Show info-tier stalls and cliffs — minor pauses"
                                    " and small throughput drops; off by default"
                                )
                            )
                        tput_pair = state.figure_cache.get((conn_n, metric, "model"))
                        if tput_pair is not None:
                            tput_stats_box = ui.column().classes("w-full")
                            _render_throughput_stats_panel(
                                tput_stats_box, tput_pair, fwd_label, bwd_label, None, None
                            )

                            def _on_tput_relayout(e) -> None:
                                t0, t1 = _xrange_from_relayout(e.args or {})
                                _render_throughput_stats_panel(
                                    tput_stats_box, tput_pair, fwd_label, bwd_label, t0, t1
                                )

                            plotly_el.on("plotly_relayout", _on_tput_relayout)

                            def _on_tput_info_toggle(e) -> None:
                                state.show_info = bool(e.value)
                                new_fig = to_throughput_figure(
                                    tput_pair, show_info=state.show_info, rate_unit=state.rate_unit
                                )
                                state.figure_cache[(conn_n, metric)] = new_fig
                                plotly_el.update_figure(new_fig)

                            tput_info_switch.on_value_change(_on_tput_info_toggle)

            async def _populate(metric: str) -> None:
                if metric in activated:
                    return
                activated.add(metric)
                g = group_by_metric.get(metric)
                if g is None:
                    return
                cache_key = (conn_n, metric)
                if cache_key in state.figure_cache:
                    if state.selected_conn != conn_n:
                        return
                    _show_figure(metric, state.figure_cache[cache_key])
                    return
                container = panel_containers[metric]
                with container:
                    ui.spinner(size="md").classes("self-center").style("margin-top: 32px;")
                tsg_g = group_by_metric.get("tsg") if metric == "tput" else None
                src_fwd = tsg_g.forward if tsg_g is not None else g.forward
                src_bwd = tsg_g.backward if tsg_g is not None else g.backward
                details = state.analyses[conn_n].details_text
                try:
                    if metric == "tput":
                        # Run synthesis once: build the model, store it, render
                        # the figure from it — avoids a second synthesize_tsg call.
                        tput_pair = await run.io_bound(
                            _build_tput_model,
                            src_fwd,
                            src_bwd,
                            details,
                        )
                        state.figure_cache[(conn_n, metric, "model")] = tput_pair
                        fig = to_throughput_figure(tput_pair, show_info=state.show_info, rate_unit=state.rate_unit) if tput_pair is not None else None
                    else:
                        fig = await run.io_bound(
                            _build_metric_figure,
                            src_fwd,
                            src_bwd,
                            g.combined,
                            fwd_label,
                            bwd_label,
                            g.metric,
                            details,
                            state.show_info,
                            state.rate_unit,
                            state.seq_mode,
                        )
                except Exception as exc:
                    if state.selected_conn != conn_n:
                        return
                    container.clear()
                    with container:
                        ui.label(f"[render error: {exc}]").classes("text-red")
                    return
                state.figure_cache[cache_key] = fig
                if metric == "tsg":
                    model_pair = await run.io_bound(
                        _build_tsg_model,
                        g.forward,
                        g.backward,
                        details,
                    )
                    state.figure_cache[(conn_n, metric, "model")] = model_pair
                    if _has_lro_anomaly(model_pair) and conn_n not in state.conns_with_lro:
                        state.conns_with_lro.add(conn_n)
                        _sync_lro_warning(state)
                        refresh_warnings()
                if state.selected_conn != conn_n:
                    return
                _show_figure(metric, fig)

            async def _on_tab_change(e) -> None:
                metric = metric_by_label.get(e.value)
                if metric is not None:
                    await _populate(metric)

            tabs.on_value_change(_on_tab_change)

            # Kick off the default tab's build without blocking this render —
            # NiceGUI doesn't fire on_value_change for programmatically-set
            # initial values, so we drive the first activation explicitly.
            default_metric = next(
                (g.metric for g in groups if _METRIC_LABELS[g.metric] == default_tab),
                None,
            )
            if default_metric is not None:
                background_tasks.create(_populate(default_metric))

        def _build_output_dialog(result: AnalyzeResult) -> ui.dialog:
            """Color-coded raw tcptrace output in a centered modal — opened
            from the sticky-header button, dismissed by click-outside or ESC."""
            legend_html = (
                '<div class="tcptrace-legend">'
                '<span class="swatch good">GOOD</span>'
                '<span class="swatch look">INTERESTING</span>'
                '<span class="swatch bad">BAD</span>'
                "</div>"
            )
            html_lines: list[str] = []
            for line in result.details_text.splitlines():
                cls = classify(line)
                if cls is None:
                    if not state.debug:
                        continue
                    cls = Class.NORMAL
                html_lines.append(
                    f'<span class="{cls.value}">{_escape_html(line)}</span>'
                )
            pre_html = (
                '<pre class="tcptrace-output">' + "\n".join(html_lines) + "</pre>"
            )

            dialog = ui.dialog()
            with dialog, ui.card().classes("tcptrace-output-card p-0"):
                ui.html(legend_html)
                ui.html(pre_html)
            return dialog

        def render_sidebar() -> None:
            conn_list_container.clear()
            if state.selected_pcap is None:
                conn_count_label.set_text("pick a pcap")
                return
            filtered = [
                r
                for r in state.stats
                if _matches_filter(r, state.conn_filter) and _matches_chips(r, state.chip_filters)
            ]
            filtered = _sort_rows(filtered, state.sort_key)
            total = len(state.stats)
            shown = len(filtered)
            if state.analyzing:
                conn_count_label.set_text("analyzing…")
            elif total == 0:
                conn_count_label.set_text("no connections")
            elif shown == total:
                conn_count_label.set_text(f"{total} connections")
            else:
                conn_count_label.set_text(f"{shown} of {total}")
            with conn_list_container, ui.list().props("dense").classes("w-full"):
                for row in filtered:
                    selected = state.selected_conn == row.n
                    cls = "tcptrace-conn-row"
                    if selected:
                        cls += " tcptrace-conn-selected"
                    item = ui.item(on_click=lambda r=row: _on_conn_click(r.n)).classes(cls)
                    with item, ui.item_section():
                        if isinstance(row, ConnStats):
                            dot_cls = _VERDICT_CSS[row.verdict]
                            badge_str = " ".join(_badges(row))
                            bytes_str = _format_size(row.total_bytes)
                            dur_str = _format_duration(row.duration_s)
                            pkts_str = f"{row.total_packets} pkts"
                            ui.html(
                                f'<div class="conn-meta-top">'
                                f'<span class="conn-num">{row.n}</span>'
                                f'<span class="tcptrace-conn-dot {dot_cls}"></span>'
                                f'<span class="conn-badges">{_escape_html(badge_str)}</span>'
                                f"</div>"
                                f'<div class="conn-host">{_escape_html(row.host_a)}</div>'
                                f'<div class="conn-host">↔ {_escape_html(row.host_b)}</div>'
                                f'<div class="conn-meta-bot">'
                                f"{bytes_str} · {dur_str} · {pkts_str}</div>"
                            )
                        else:
                            # Stats-less fallback (cheap listing)
                            ui.html(
                                f'<div class="conn-num">{row.n}</div>'
                                f'<div class="conn-host">{_escape_html(row.host_a)}</div>'
                                f'<div class="conn-host">↔ {_escape_html(row.host_b)}</div>'
                            )

        async def _on_conn_click(n: int) -> None:
            if state.selected_pcap is None:
                return
            state.selected_conn = n
            render_main()
            render_sidebar()
            if n in state.analyses:
                return
            layout = CacheLayout(state.selected_pcap)
            layout.ensure_conn(n)
            details_path = layout.conn_details(n)
            xpls_pattern = f"conn-{n}--*.xpl"
            cached_xpls = sorted(layout.conn_dir(n).glob(xpls_pattern))
            fresh = (
                is_fresh(
                    details_path,
                    state.selected_pcap,
                    _cache_version(),
                    layout.version_file,
                )
                and all(
                    is_fresh(
                        x,
                        state.selected_pcap,
                        _cache_version(),
                        layout.version_file,
                    )
                    for x in cached_xpls
                )
                and len(cached_xpls) > 0
            )
            if fresh:
                state.analyses[n] = AnalyzeResult(
                    details_text=details_path.read_text(),
                    xpl_files=cached_xpls,
                )
            else:
                try:
                    result = await run.io_bound(
                        analyze_connection,
                        state.effective_pcap,
                        n,
                        layout.conn_dir(n),
                        state.timeout,
                        no_dns=not state.dns,
                        with_rtt=state.with_rtt,
                        with_warnings=state.with_warnings,
                        zero_x_axis=state.zero_x_axis,
                    )
                except Exception as exc:
                    ui.notify(f"conn {n} failed: {exc}", type="negative")
                    state.selected_conn = None
                    render_main()
                    render_sidebar()
                    return
                details_path.write_text(result.details_text)
                state.analyses[n] = result
            refresh_cache_label()
            _refresh_download_btn()
            render_main()
            render_sidebar()

        def _on_filter_change(e) -> None:
            state.conn_filter = e.value or ""
            render_sidebar()

        async def _ensure_decapped(src: Path, layout: CacheLayout) -> Path:
            """Detect outer encaps; if any, return path to a cached decap'd copy.

            Falls back to `src` on any error so a flaky decap can't break the
            normal analysis path. The decap output lives at
            `<cache>/decap.pcap` next to the other cached artifacts.
            """
            try:
                encaps = await run.io_bound(detect_encaps, src)
            except Exception:
                state.decap_encaps = set()
                return src
            if not encaps:
                state.decap_encaps = set()
                return src
            decap_path = layout.decap_pcap
            if is_fresh(decap_path, src, _cache_version(), layout.version_file):
                try:
                    meta = json.loads(layout.decap_meta.read_text())
                    state.decap_encaps = set(meta.get("encaps", []))
                except (OSError, json.JSONDecodeError):
                    state.decap_encaps = encaps
                return decap_path
            layout.ensure_root()
            try:
                res = await run.io_bound(decap_pcap, src, decap_path)
            except Exception as exc:
                ui.notify(f"decap failed, analyzing original: {exc}", type="warning")
                state.decap_encaps = set()
                return src
            layout.decap_meta.write_text(
                json.dumps(
                    {
                        "encaps": sorted(res.encaps),
                        "frames_total": res.frames_total,
                        "frames_decapped": res.frames_decapped,
                    }
                )
            )
            state.decap_encaps = res.encaps
            return decap_path

        async def _scan_for_warnings(pcap: Path) -> None:
            """Populate `state.pcap_warnings` with pre-flight findings.

            Currently: NIC offload (LSO/GSO/TSO/LRO/GRO) — TCP payloads
            larger than 1500 B mean coalescing distorts the MSS field,
            time-sequence staircases, and retransmit detection. Future
            detectors append to the same list.
            """
            state.pcap_warnings = []
            try:
                offload = await run.io_bound(detect_offload, pcap)
            except Exception:
                return
            state.pcap_warnings.extend(offload.warnings)

        async def _on_pcap_pick(e) -> None:
            value = e.value
            state.selected_pcap = Path(value) if value else None
            state.effective_pcap = state.selected_pcap
            state.decap_encaps = set()
            state.pcap_warnings = []
            state.conns_with_lro = set()
            refresh_warnings()
            state.selected_conn = None
            state.stats = []
            state.analyses = {}
            state.figure_cache = {}
            state.conn_filter = ""
            filter_input.set_value("")
            _refresh_download_btn()
            render_main()
            render_sidebar()
            if state.selected_pcap is None:
                return

            invalidate_if_stale_version(state.selected_pcap, _cache_version())

            layout = CacheLayout(state.selected_pcap)
            state.effective_pcap = await _ensure_decapped(state.selected_pcap, layout)
            refresh_cache_label()
            if state.decap_encaps:
                ui.notify(
                    f"decap'd outer {'/'.join(sorted(state.decap_encaps))}",
                    type="info",
                )
            await _scan_for_warnings(state.effective_pcap)
            refresh_warnings()
            # Independent per-packet TCP-checksum scan. Cheap on small pcaps
            # and the only source of `bad_csum` anomalies; we never let
            # tcptrace --checksum filter packets out of the analysis.
            try:
                state.bad_csum_events = await run.io_bound(
                    scan_csums, state.effective_pcap
                )
            except Exception:
                state.bad_csum_events = []
            cached = load_stats(layout, _cache_version())
            if cached is not None:
                state.stats = cached
                render_sidebar()
                return

            state.analyzing = True
            render_sidebar()
            try:
                stats = await run.io_bound(
                    analyze_all,
                    state.effective_pcap,
                    state.timeout,
                    no_dns=not state.dns,
                    with_rtt=state.with_rtt,
                    with_warnings=state.with_warnings,
                )
            except RunnerError as exc:
                # Fall back to cheap listing (preserves today's convert-to-pcap retry).
                fallback_ok = False
                try:
                    state.stats = await run.io_bound(
                        list_connections,
                        state.effective_pcap,
                        state.timeout,
                        no_dns=not state.dns,
                    )
                    fallback_ok = True
                except RunnerError:
                    try:
                        converted = await run.io_bound(
                            try_convert_to_pcap, state.selected_pcap, state.timeout
                        )
                        state.selected_pcap = converted
                        layout = CacheLayout(state.selected_pcap)
                        # Re-run encap detection against the converted pcap; a
                        # pcapng with Geneve inside would otherwise slip past.
                        state.effective_pcap = await _ensure_decapped(
                            state.selected_pcap, layout
                        )
                        await _scan_for_warnings(state.effective_pcap)
                        refresh_warnings()
                        state.stats = await run.io_bound(
                            list_connections,
                            state.effective_pcap,
                            state.timeout,
                            no_dns=not state.dns,
                        )
                        fallback_ok = True
                    except RunnerError as exc2:
                        ui.notify(f"tcptrace failed: {exc2}", type="negative")
                        state.stats = []
                state.analyzing = False
                if fallback_ok:
                    ui.notify(
                        f"rich stats unavailable, showing basic listing ({exc})", type="warning"
                    )
                render_sidebar()
                return
            except Exception as exc:
                ui.notify(f"tcptrace failed: {exc}", type="negative")
                state.stats = []
                state.analyzing = False
                render_sidebar()
                return

            state.stats = stats
            state.analyzing = False
            write_version(layout, _cache_version())
            save_stats(layout, stats)
            render_sidebar()

        async def _clear_all() -> None:
            import shutil as _sh

            root = cwd / ".tcptrace"
            if root.exists():
                _sh.rmtree(root)
            state.analyses.clear()
            state.figure_cache.clear()
            state.conns_with_lro.clear()
            _sync_lro_warning(state)
            refresh_warnings()
            state.selected_conn = None
            refresh_cache_label()
            _refresh_download_btn()
            render_main()
            render_sidebar()
            ui.notify("cache cleared", type="positive")
            # The decap'd copy lived inside the wiped tree; re-prime the pick
            # so effective_pcap is rebuilt before the next analysis.
            if state.selected_pcap is not None:
                await _on_pcap_pick(SimpleNamespace(value=str(state.selected_pcap)))

        async def _reanalyze() -> None:
            if state.selected_pcap is None:
                ui.notify("no pcap selected", type="warning")
                return
            clear_pcap_cache(state.selected_pcap)
            state.analyses.clear()
            state.figure_cache.clear()
            state.conns_with_lro.clear()
            _sync_lro_warning(state)
            refresh_warnings()
            state.selected_conn = None
            refresh_cache_label()
            _refresh_download_btn()
            render_main()
            render_sidebar()
            ui.notify(
                f"cache cleared for {state.selected_pcap.name}",
                type="positive",
            )
            await _on_pcap_pick(SimpleNamespace(value=str(state.selected_pcap)))

        async def _on_flag_change(field: str, value: bool) -> None:
            """Set the flag on state, then re-trigger the pick for the current
            pcap so the analyze flow re-runs with the new flags. The cache key
            changes via `_cache_version()`, so any on-disk cache from the old
            flag set is wiped by `invalidate_if_stale_version`."""
            setattr(state, field, bool(value))
            if state.selected_pcap is None:
                return
            await _on_pcap_pick(SimpleNamespace(value=str(state.selected_pcap)))

        def _on_display_change(field: str, value: str) -> None:
            """Display-only flag change: clear the figure cache and re-render
            the current connection. Analyses on disk are untouched because
            these toggles never reach tcptrace's CLI."""
            setattr(state, field, value)
            state.figure_cache.clear()
            if state.selected_conn is not None:
                render_main()

        # ---------- wire events ----------
        clear_btn.on_click(_clear_all)
        reanalyze_btn.on_click(_reanalyze)
        warning_chip.on_click(warning_dialog.open)
        download_btn.on_click(_download_zip)
        filter_input.on_value_change(_on_filter_change)
        pcap_select.on_value_change(_on_pcap_pick)
        dns_check.on_value_change(lambda e: _on_flag_change("dns", e.value))
        rtt_check.on_value_change(lambda e: _on_flag_change("with_rtt", e.value))
        warn_check.on_value_change(lambda e: _on_flag_change("with_warnings", e.value))
        zerox_check.on_value_change(lambda e: _on_flag_change("zero_x_axis", e.value))
        rate_toggle.on_value_change(lambda e: _on_display_change("rate_unit", e.value))
        seq_toggle.on_value_change(lambda e: _on_display_change("seq_mode", e.value))
        ui.timer(_PCAP_RESCAN_SECONDS, refresh_pcap_dropdown)

        # ---------- initial render ----------
        refresh_cache_label()
        refresh_warnings()
        _refresh_download_btn()
        render_main()
        render_sidebar()
