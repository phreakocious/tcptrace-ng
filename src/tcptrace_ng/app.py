"""NiceGUI page and reactive state. The only module that imports nicegui.

Layout: top header (pcap dropdown + cache controls) + left drawer
(filter + clickable connection list + xpl-zip button) + main panel
(tabs over plotly graphs + collapsible color-coded tcptrace output).

Clicking a connection runs tcptrace for that connection on demand
(off the event loop via `run.io_bound`) and renders it in the main panel.
Analyzed connections stay in `state.analyses` so re-clicking is instant.
"""

from __future__ import annotations

import dataclasses
import io
import sys
import zipfile
from pathlib import Path

from nicegui import run, ui

from . import __version__
from .cache import (
    CacheLayout,
    clear_pcap_cache,
    invalidate_if_stale_version,
    is_fresh,
    load_listing,
    save_listing,
    total_cache_size,
    write_version,
)
from .classifier import Class, classify
from .plotly_adapter import to_plotly_figure
from .runner import (
    AnalyzeResult,
    ConnRow,
    RunnerError,
    analyze_connection,
    list_connections,
    try_convert_to_pcap,
)
from .theme import DARK_CSS
from .xpl_parser import parse_xpl

PCAP_GLOBS = ("*.pcap", "*.pcapng", "*.cap")


def _scan_pcaps(cwd: Path) -> list[Path]:
    found: list[Path] = []
    for pat in PCAP_GLOBS:
        found.extend(sorted(cwd.glob(pat)))
    return found


class _State:
    """Module-level state. NiceGUI page is rebuilt per-client; state stays here."""

    def __init__(self) -> None:
        self.selected_pcap: Path | None = None
        self.listing: list[ConnRow] = []
        self.selected_conn: int | None = None
        self.conn_filter: str = ""
        self.analyses: dict[int, AnalyzeResult] = {}
        self.timeout: float = 60.0
        self.debug: bool = False


state = _State()


def _escape_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _format_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    return f"{n / 1024 / 1024 / 1024:.2f} GB"


def _matches_filter(row: ConnRow, q: str) -> bool:
    if not q:
        return True
    needle = q.lower()
    return (
        needle in str(row.n)
        or needle in row.host_a.lower()
        or needle in row.host_b.lower()
    )


def build_xpl_zip(analyses: dict[int, AnalyzeResult]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for n, result in analyses.items():
            for xpl in result.xpl_files:
                zf.write(xpl, arcname=f"conn-{n}/{xpl.name}")
    return buf.getvalue()


def build_page() -> None:
    """Register the `/` route on the default NiceGUI app."""

    @ui.page("/")
    def index() -> None:
        ui.add_head_html(f"<style>{DARK_CSS}</style>")

        cwd = Path.cwd()
        pcaps = _scan_pcaps(cwd)
        pcap_options: dict[str, str] = {
            str(p): f"{p.name}  ({_format_size(p.stat().st_size)})" for p in pcaps
        }

        # =========== header ===========
        with ui.header(elevated=False).classes(
            "tcptrace-header items-center gap-3 px-4"
        ):
            ui.label("tcptrace-ng").classes("tcptrace-brand text-base")
            ui.label("›").classes("tcptrace-sep")
            pcap_select = (
                ui.select(
                    options=pcap_options or {"": "no pcaps in this directory"},
                    value=str(state.selected_pcap) if state.selected_pcap else None,
                )
                .props("dense dark outlined options-dense")
                .classes("min-w-[280px]")
            )
            ui.space()
            cache_label = ui.label().classes("tcptrace-cache-label mr-2")
            clear_btn = ui.button("Clear cache").props(
                "flat dense no-caps color=grey-5"
            )
            reanalyze_btn = ui.button("Reanalyze").props(
                "flat dense no-caps color=grey-5"
            )

        def refresh_cache_label() -> None:
            cache_label.set_text(f"cache: {_format_size(total_cache_size(cwd))}")

        # =========== sidebar ===========
        with ui.left_drawer(fixed=True, value=True).props(
            "width=300 bordered"
        ).classes("tcptrace-sidebar p-0"):
            with ui.column().classes("w-full h-full gap-0 no-wrap"):
                with ui.column().classes(
                    "w-full tcptrace-sidebar-header px-3 py-2 gap-1"
                ):
                    conn_count_label = ui.label("").classes(
                        "text-xs text-gray-500"
                    )
                    filter_input = (
                        ui.input(placeholder="filter…")
                        .props("dense dark borderless debounce=150")
                        .classes("tcptrace-filter w-full")
                    )
                conn_list_container = ui.column().classes(
                    "w-full flex-grow overflow-auto gap-0"
                )
                with ui.row().classes(
                    "w-full tcptrace-sidebar-footer px-3 py-2"
                ):
                    download_btn = (
                        ui.button("↓ xpl zip").props(
                            "flat dense no-caps color=grey-5 disable"
                        ).classes("w-full")
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
                    ui.label(f"no pcap files in {cwd}").classes(
                        "tcptrace-empty text-red"
                    )
                    return
                if state.selected_pcap is None:
                    ui.label("select a pcap from the header").classes(
                        "tcptrace-empty w-full"
                    )
                    return
                if state.selected_conn is None:
                    ui.label(
                        "click a connection on the left to analyze it"
                    ).classes("tcptrace-empty w-full")
                    return
                n = state.selected_conn
                row = next((r for r in state.listing if r.n == n), None)
                if row is None:
                    title_main = f"Conn {n}"
                    subtitle = ""
                else:
                    title_main = f"Conn {n}"
                    subtitle = f"{row.host_a}  ↔  {row.host_b}"
                with ui.column().classes("w-full gap-0"):
                    ui.label(title_main).classes("tcptrace-title")
                    if subtitle:
                        ui.label(subtitle).classes("tcptrace-subtitle")
                if n not in state.analyses:
                    with ui.row().classes("w-full items-center gap-2 mt-6"):
                        ui.spinner(size="md")
                        ui.label(
                            f"running tcptrace for conn {n}…"
                        ).classes("text-gray-400")
                    return
                _render_analysis(state.analyses[n])

        def _render_analysis(result: AnalyzeResult) -> None:
            if result.xpl_files:
                tab_names = [
                    xpl.stem.split("--", 1)[-1] for xpl in result.xpl_files
                ]
                with ui.tabs().props(
                    "dense dark active-color=white outside-arrows mobile-arrows"
                ).classes("w-full") as tabs:
                    for name in tab_names:
                        ui.tab(name)
                with ui.tab_panels(tabs, value=tab_names[0]).classes(
                    "w-full"
                ).style("background: transparent;"):
                    for xpl, name in zip(result.xpl_files, tab_names):
                        with ui.tab_panel(name).classes("p-0"):
                            try:
                                plot = parse_xpl(xpl)
                            except Exception as exc:
                                ui.label(
                                    f"[unparseable graph: {xpl.name}: {exc}]"
                                ).classes("text-red")
                                continue
                            if not plot.commands:
                                ui.label(
                                    "no data in this direction"
                                ).classes(
                                    "tcptrace-empty w-full"
                                ).style("margin-top: 32px;")
                                continue
                            if state.debug and plot.unknown:
                                for cmd in plot.unknown:
                                    print(
                                        f"[tcptrace-ng debug] unknown xpl "
                                        f"command in {xpl.name}: {cmd}",
                                        file=sys.stderr,
                                    )
                            ui.plotly(to_plotly_figure(plot)).classes("w-full")

            with ui.expansion("tcptrace output", value=False).classes(
                "w-full tcptrace-expansion"
            ):
                ui.html(
                    '<div class="tcptrace-legend">'
                    '<span class="swatch"><span class="tcptrace-output good">'
                    "GOOD</span></span>"
                    '<span class="swatch"><span class="tcptrace-output look">'
                    "INTERESTING</span></span>"
                    '<span class="swatch"><span class="tcptrace-output bad">'
                    "BAD</span></span>"
                    "</div>"
                )
                html_lines: list[str] = []
                for line in result.details_text.splitlines():
                    cls = classify(line)
                    if cls is None:
                        if not state.debug:
                            continue
                        cls = Class.NORMAL
                    css = cls.value
                    html_lines.append(
                        f'<span class="{css}">{_escape_html(line)}</span>'
                    )
                pre_html = (
                    '<pre class="tcptrace-output">'
                    + "\n".join(html_lines)
                    + "</pre>"
                )
                ui.html(pre_html)

        def render_sidebar() -> None:
            conn_list_container.clear()
            if state.selected_pcap is None:
                conn_count_label.set_text("pick a pcap")
                return
            filtered = [
                r for r in state.listing if _matches_filter(r, state.conn_filter)
            ]
            total = len(state.listing)
            shown = len(filtered)
            if total == 0:
                conn_count_label.set_text("no connections")
            elif shown == total:
                conn_count_label.set_text(f"{total} connections")
            else:
                conn_count_label.set_text(f"{shown} of {total}")
            with conn_list_container:
                with ui.list().props("dense").classes("w-full"):
                    for row in filtered:
                        selected = state.selected_conn == row.n
                        analyzed = row.n in state.analyses
                        cls = "tcptrace-conn-row"
                        if selected:
                            cls += " tcptrace-conn-selected"
                        if analyzed:
                            cls += " tcptrace-conn-analyzed"
                        item = ui.item(
                            on_click=lambda r=row: _on_conn_click(r.n)
                        ).classes(cls)
                        with item, ui.item_section():
                            dot = (
                                '<span class="tcptrace-conn-dot"></span>'
                                if analyzed
                                else ""
                            )
                            ui.html(
                                f'<div class="conn-num">{dot}'
                                f"{row.n}</div>"
                                f'<div class="conn-host">'
                                f"{_escape_html(row.host_a)}</div>"
                                f'<div class="conn-host">↔ '
                                f"{_escape_html(row.host_b)}</div>"
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
                    __version__,
                    layout.version_file,
                )
                and all(
                    is_fresh(
                        x,
                        state.selected_pcap,
                        __version__,
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
            state.listing = []
            state.analyses = {}
            state.conn_filter = ""
            filter_input.set_value("")
            _refresh_download_btn()
            render_main()
            render_sidebar()
            if state.selected_pcap is None:
                return

            invalidate_if_stale_version(state.selected_pcap, __version__)

            layout = CacheLayout(state.selected_pcap)
            cached_rows = load_listing(layout, __version__)
            if cached_rows is not None:
                state.listing = [ConnRow(**r) for r in cached_rows]
                render_sidebar()
                return

            try:
                state.listing = await run.io_bound(
                    list_connections, state.selected_pcap, state.timeout
                )
            except RunnerError as exc:
                try:
                    converted = await run.io_bound(
                        try_convert_to_pcap, state.selected_pcap, state.timeout
                    )
                except RunnerError:
                    ui.notify(f"tcptrace failed: {exc}", type="negative")
                    state.listing = []
                    render_sidebar()
                    return
                state.selected_pcap = converted
                layout = CacheLayout(state.selected_pcap)
                try:
                    state.listing = await run.io_bound(
                        list_connections, state.selected_pcap, state.timeout
                    )
                except RunnerError as exc2:
                    ui.notify(f"tcptrace failed: {exc2}", type="negative")
                    state.listing = []
                    render_sidebar()
                    return
            except Exception as exc:
                ui.notify(f"tcptrace failed: {exc}", type="negative")
                state.listing = []
                render_sidebar()
                return

            write_version(layout, __version__)
            save_listing(
                layout, [dataclasses.asdict(r) for r in state.listing]
            )
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

        # ---------- wire events ----------
        clear_btn.on_click(_clear_all)
        reanalyze_btn.on_click(_reanalyze)
        download_btn.on_click(_download_zip)
        filter_input.on_value_change(_on_filter_change)
        pcap_select.on_value_change(_on_pcap_pick)

        # ---------- initial render ----------
        refresh_cache_label()
        _refresh_download_btn()
        render_main()
        render_sidebar()
