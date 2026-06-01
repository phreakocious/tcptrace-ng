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
import os
import sys
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from nicegui import run, ui

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
from .plotly_adapter import to_paired_plotly_figure, to_plotly_figure
from .runner import (
    AnalyzeResult,
    ConnRow,
    RunnerError,
    analyze_all,
    analyze_connection,
    list_connections,
    try_convert_to_pcap,
)
from .stats_parser import ConnStats
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
        self.stats: list[
            ConnStats | ConnRow
        ] = []  # may be ConnStats (rich) or ConnRow (basic) per pick
        self.analyzing: bool = False
        self.selected_conn: int | None = None
        self.conn_filter: str = ""
        self.chip_filters: set[str] = set()
        self.sort_key: str = "n"
        self.analyses: dict[int, AnalyzeResult] = {}
        self.timeout: float = 60.0
        self.debug: bool = False
        # tcptrace command-line flag toggles. All default-off (matches the
        # stock tcptrace default of resolving names + no extra long-output
        # sections + wallclock graph axes).
        self.no_dns: bool = False
        self.with_rtt: bool = False
        self.with_warnings: bool = False
        self.zero_x_axis: bool = False


state = _State()


def _escape_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _cache_version() -> str:
    """Compose the cache-version key from `__version__` plus any active tcptrace
    flag toggles. Toggling a flag changes the key, so `invalidate_if_stale_version`
    wipes the previous cache automatically — different flag sets yield different
    tcptrace output and can't share artifacts."""
    parts = [__version__]
    if state.no_dns:
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
    return out


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
                no_dns_check = (
                    ui.checkbox("no DNS", value=state.no_dns)
                    .props("dense dark")
                    .tooltip("-n: skip hostname / port-name resolution (much faster)")
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
            ui.space()
            cache_label = ui.label().classes("tcptrace-cache-label mr-2")
            clear_btn = ui.button("Clear cache").props("flat dense no-caps color=grey-5")
            reanalyze_btn = ui.button("Reanalyze").props("flat dense no-caps color=grey-5")

        def refresh_cache_label() -> None:
            cache_label.set_text(f"cache: {_format_size(total_cache_size(cwd))}")

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
                        ui.label(f"{fwd_label}  {fwd_ctx}").classes("tcptrace-context")
                    if bwd_ctx:
                        ui.label(f"{bwd_label}  {bwd_ctx}").classes("tcptrace-context")
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

            Returns ([], None, "") when there are no plottable groups; caller is
            responsible for rendering an empty-state in _render_analysis.
            """
            groups = [g for g in group_xpls(result.xpl_files) if _group_has_data(g)]
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
            row = next((r for r in state.stats if r.n == state.selected_conn), None)
            if groups and tabs is not None:
                fwd_label, bwd_label = _direction_labels(row) if row is not None else ("→", "←")
                with (
                    ui.tab_panels(tabs, value=default_tab)
                    .classes("w-full")
                    .style("background: transparent;")
                ):
                    for g in groups:
                        with ui.tab_panel(_METRIC_LABELS[g.metric]).classes("p-0"):
                            _render_metric_panel(g, fwd_label, bwd_label)
            else:
                ui.label("no graphs available").classes("tcptrace-empty w-full")

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

        def _try_parse(xpl: Path) -> tuple[XplPlot | None, str | None]:
            """Single try/except wrapper around parse_xpl. Returns (plot, None)
            on success or (None, message) on failure so callers can pick their
            own recovery (skip, render-error-label, fall back to other side)."""
            try:
                return parse_xpl(xpl), None
            except Exception as exc:
                return None, f"{xpl.name}: {exc}"

        def _group_has_data(g: GroupedXpl) -> bool:
            for xpl in (g.forward, g.backward, g.combined):
                if xpl is None:
                    continue
                plot, _err = _try_parse(xpl)
                if plot is not None and plot.commands:
                    return True
            return False

        def _render_metric_panel(g: GroupedXpl, fwd_label: str, bwd_label: str) -> None:
            if g.combined is not None:
                _render_xpl(g.combined)
                return
            if g.forward is None and g.backward is None:
                ui.label("no data in this direction").classes("tcptrace-empty w-full").style(
                    "margin-top: 32px;"
                )
                return
            _render_paired_xpls(g.forward, g.backward, fwd_label, bwd_label)

        def _render_paired_xpls(
            fwd: Path | None, bwd: Path | None, fwd_label: str, bwd_label: str
        ) -> None:
            """Render forward and backward together as a single stacked figure."""
            fwd_plot = _try_parse(fwd)[0] if fwd is not None else None
            bwd_plot = _try_parse(bwd)[0] if bwd is not None else None
            # Drop empty plots so the stack collapses to a single subplot when
            # one direction is header-only.
            if fwd_plot is not None and not fwd_plot.commands:
                fwd_plot = None
            if bwd_plot is not None and not bwd_plot.commands:
                bwd_plot = None
            if fwd_plot is None and bwd_plot is None:
                ui.label("no data in this direction").classes("tcptrace-empty w-full").style(
                    "margin-top: 32px;"
                )
                return
            fig = to_paired_plotly_figure(fwd_plot, bwd_plot, fwd_label, bwd_label)
            # Stacked: each subplot needs vertical room. Scale with the viewport
            # so a 13" laptop doesn't push the tcptrace-output below the fold
            # and a 4K display doesn't leave a giant blank gap. 240px leaves
            # room for the header + sticky title/context/tab strip; the floor
            # keeps both subplots usable on small viewports.
            ui.plotly(fig).classes("w-full").style(
                "height: calc(100vh - 240px); min-height: 480px;"
            )

        def _render_xpl(xpl: Path) -> None:
            plot, err = _try_parse(xpl)
            if err is not None:
                ui.label(f"[unparseable graph: {err}]").classes("text-red")
                return
            if not plot.commands:
                ui.label("no data in this direction").classes("tcptrace-empty w-full").style(
                    "margin-top: 32px;"
                )
                return
            if state.debug and plot.unknown:
                for cmd in plot.unknown:
                    print(
                        f"[tcptrace-ng debug] unknown xpl command in {xpl.name}: {cmd}",
                        file=sys.stderr,
                    )
            ui.plotly(to_plotly_figure(plot)).classes("w-full")

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
                        state.selected_pcap,
                        n,
                        layout.conn_dir(n),
                        state.timeout,
                        no_dns=state.no_dns,
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

        async def _on_pcap_pick(e) -> None:
            value = e.value
            state.selected_pcap = Path(value) if value else None
            state.selected_conn = None
            state.stats = []
            state.analyses = {}
            state.conn_filter = ""
            filter_input.set_value("")
            _refresh_download_btn()
            render_main()
            render_sidebar()
            if state.selected_pcap is None:
                return

            invalidate_if_stale_version(state.selected_pcap, _cache_version())

            layout = CacheLayout(state.selected_pcap)
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
                    state.selected_pcap,
                    state.timeout,
                    no_dns=state.no_dns,
                    with_rtt=state.with_rtt,
                    with_warnings=state.with_warnings,
                )
            except RunnerError as exc:
                # Fall back to cheap listing (preserves today's convert-to-pcap retry).
                fallback_ok = False
                try:
                    state.stats = await run.io_bound(
                        list_connections,
                        state.selected_pcap,
                        state.timeout,
                        no_dns=state.no_dns,
                    )
                    fallback_ok = True
                except RunnerError:
                    try:
                        converted = await run.io_bound(
                            try_convert_to_pcap, state.selected_pcap, state.timeout
                        )
                        state.selected_pcap = converted
                        layout = CacheLayout(state.selected_pcap)
                        state.stats = await run.io_bound(
                            list_connections,
                            state.selected_pcap,
                            state.timeout,
                            no_dns=state.no_dns,
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

        def _clear_all() -> None:
            import shutil as _sh

            root = cwd / ".tcptrace"
            if root.exists():
                _sh.rmtree(root)
            state.analyses.clear()
            state.selected_conn = None
            refresh_cache_label()
            _refresh_download_btn()
            render_main()
            render_sidebar()
            ui.notify("cache cleared", type="positive")

        def _reanalyze() -> None:
            if state.selected_pcap is None:
                ui.notify("no pcap selected", type="warning")
                return
            clear_pcap_cache(state.selected_pcap)
            state.analyses.clear()
            state.selected_conn = None
            refresh_cache_label()
            _refresh_download_btn()
            render_main()
            render_sidebar()
            ui.notify(
                f"cache cleared for {state.selected_pcap.name}",
                type="positive",
            )

        async def _on_flag_change(field: str, value: bool) -> None:
            """Set the flag on state, then re-trigger the pick for the current
            pcap so the analyze flow re-runs with the new flags. The cache key
            changes via `_cache_version()`, so any on-disk cache from the old
            flag set is wiped by `invalidate_if_stale_version`."""
            setattr(state, field, bool(value))
            if state.selected_pcap is None:
                return
            await _on_pcap_pick(SimpleNamespace(value=str(state.selected_pcap)))

        # ---------- wire events ----------
        clear_btn.on_click(_clear_all)
        reanalyze_btn.on_click(_reanalyze)
        download_btn.on_click(_download_zip)
        filter_input.on_value_change(_on_filter_change)
        pcap_select.on_value_change(_on_pcap_pick)
        no_dns_check.on_value_change(lambda e: _on_flag_change("no_dns", e.value))
        rtt_check.on_value_change(lambda e: _on_flag_change("with_rtt", e.value))
        warn_check.on_value_change(lambda e: _on_flag_change("with_warnings", e.value))
        zerox_check.on_value_change(lambda e: _on_flag_change("zero_x_axis", e.value))
        ui.timer(_PCAP_RESCAN_SECONDS, refresh_pcap_dropdown)

        # ---------- initial render ----------
        refresh_cache_label()
        _refresh_download_btn()
        render_main()
        render_sidebar()
