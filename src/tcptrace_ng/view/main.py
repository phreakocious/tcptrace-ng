"""Main analysis panel: sticky head, tab strip, tab panels (figures + stats).

`build(state, callbacks…)` constructs the main container once and returns a
`MainHandle` with the surgical-refresh surface (show_empty, show_pending,
show_analysis_for, refresh_findings_panel, …) per spec §Main panel reactive
contract.

Dependency rule: imports from `..state`, `..view.format`, and pure
adapters (plotly, throughput types) — but never from `..app`. Model
callables app.py owns (the figure builders, ensure_tsg_pair) are
injected via build()'s callback params.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from nicegui import background_tasks, run, ui

from ..classifier import Class, classify
from ..plotly_adapter import to_throughput_figure, to_tsg_figure
from ..runner import AnalyzeResult

# state singleton is for module-level helpers below; inside build(),
# the `state` parameter shadows this (same object in practice).
from ..state import _escape_html, _figure_cache_key, _State, state
from ..stats_parser import ConnStats
from ..throughput import ThroughputModelPair
from ..xpl_grouper import GroupedXpl, group_xpls
from .format import (
    _apply_rate_unit_to_ctx,
    _desegment_banner_text,
    _direction_labels,
    _findings_panel_html,
    _phase_label_text,
    _stats_grid_html,
    _throughput_stats_grid_html,
)

_METRIC_LABELS = {
    "tsg": "Time-sequence",
    "tput": "Throughput",
    "rtt": "RTT",
    "owin": "Outstanding window",
    "ssize": "Segment size",
    "tline": "Timeline",
}


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
            html_parts.append(
                _throughput_stats_grid_html(
                    fwd_label, pair.fwd.window_stats(t0, t1), state.rate_unit
                )
            )
        if pair.bwd is not None:
            html_parts.append(
                _throughput_stats_grid_html(
                    bwd_label, pair.bwd.window_stats(t0, t1), state.rate_unit
                )
            )
        ui.html(f'<div class="tsg-stats">{"".join(html_parts)}</div>')


def _is_shape_only_relayout(args: dict) -> bool:
    """True iff the relayout payload only contains shape changes — the
    client-side hover crossbar (see view/hover_crossbar.py) updates a layout
    shape on every hover, which fires plotly_relayout for what's really just
    a cursor move. Stats panels shouldn't re-render for that."""
    if not args:
        return False
    return all(k.startswith("shapes") for k in args)


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
            html_parts.append(
                _stats_grid_html(fwd_label, pair.fwd.window_stats(t0, t1), state.rate_unit)
            )
        if pair.bwd is not None:
            html_parts.append(
                _stats_grid_html(bwd_label, pair.bwd.window_stats(t0, t1), state.rate_unit)
            )
        ui.html(f'<div class="tsg-stats">{"".join(html_parts)}</div>')


@dataclass
class MainHandle:
    """Public surface of the main analysis panel.

    Zone primitives are exposed as private attributes (prefixed `_`) for
    tests to introspect. The public surface is the methods (show_empty,
    show_pending, show_analysis_for, refresh_*).
    """

    main_container: ui.column
    show_empty: Callable[[str], None]
    show_pending: Callable[[int, str], None]
    show_analysis_for: Callable[[int], None]
    refresh_context_lines: Callable[[], None]
    refresh_findings_panel: Callable[[int], None]
    refresh_active_tab: Callable[[], Awaitable[None]]
    refresh_stats_panel: Callable[[str | None, float | None, float | None], None]
    refresh_throughput_stats_panel: Callable[[str | None, float | None, float | None], None]
    _empty_zone: ui.column
    _sticky_head_zone: ui.column
    _analysis_zone: ui.column
    _empty_label: ui.label
    _pending_row: ui.row
    _pending_spinner: ui.spinner
    _pending_label: ui.label
    _figures_zone: ui.column
    _title_label: ui.label
    _subtitle_label: ui.label
    _fwd_ctx_label: ui.label
    _bwd_ctx_label: ui.label
    _findings_html: ui.html
    _output_btn_slot: ui.row
    _tabs_slot: ui.column
    _current_dialog: dict[str, ui.dialog | None]
    _active_tab_state: dict[str, dict]


def build(
    state: _State,
    *,
    initial_pcaps: list[tuple[Path, os.stat_result]],
    cwd: Path,
    ensure_tsg_pair: Callable[[int], Awaitable[object | None]],
    build_tput_pair_pure: Callable[[object | None], object | None],
    build_combined_figure_pure: Callable[[Path], dict | None],
    build_paired_figure_pure: Callable[[Path, Path, str, str], dict | None],
    on_download_conn_pcap: Callable[[int], Awaitable[None]],
) -> MainHandle:
    """Build the main analysis container once. Returns refresh hook + container ref."""
    main_container = ui.column().classes("tcptrace-main w-full gap-3")
    with main_container:
        _empty_zone = ui.column().classes("w-full")
        with _empty_zone:
            _empty_label = ui.label("").classes("tcptrace-empty w-full")
        _sticky_head_zone = ui.column().classes("w-full gap-0 tcptrace-sticky-head")
        with _sticky_head_zone:
            with ui.row().classes("w-full items-center no-wrap"):
                _title_label = ui.label("").classes("tcptrace-title")
                ui.space()
                _output_btn_slot = ui.row().classes("items-center gap-0")
            _subtitle_label = ui.label("").classes("tcptrace-subtitle")
            _fwd_ctx_label = ui.label("").classes("tcptrace-context")
            _bwd_ctx_label = ui.label("").classes("tcptrace-context")
            _findings_html = ui.html("")
            _tabs_slot = ui.column().classes("w-full gap-0")
        _analysis_zone = ui.column().classes("w-full gap-3")
        with _analysis_zone:
            _pending_row = ui.row().classes("w-full items-center gap-2 mt-6 tcptrace-zone-hidden")
            with _pending_row:
                _pending_spinner = ui.spinner(size="md")
                _pending_label = ui.label("").classes("text-muted")
            _figures_zone = ui.column().classes("w-full gap-3 tcptrace-zone-hidden")

    _current_dialog: dict[str, ui.dialog | None] = {"d": None}

    # Updated by _show_figure when a tab is activated so refresh_active_tab
    # and refresh_stats_panel can find the live plotly element + model.
    # Keys: metric ("tsg", "tput"). Values: dict with keys
    # "plotly_el", "model_pair", "stats_box", "fwd_label", "bwd_label",
    # "container", "conn_n".
    _active_tab_state: dict[str, dict] = {}

    def _set_label_visibility(label: ui.label, text: str) -> None:
        if text:
            label.set_text(text)
            label.classes(remove="tcptrace-zone-hidden")
        else:
            label.set_text("")
            label.classes(add="tcptrace-zone-hidden")

    def _set_html_visibility(html_el: ui.html, content: str) -> None:
        if content:
            html_el.content = content
            html_el.classes(remove="tcptrace-zone-hidden")
        else:
            html_el.content = ""
            html_el.classes(add="tcptrace-zone-hidden")

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
            html_lines.append(f'<span class="{cls.value}">{_escape_html(line)}</span>')
        pre_html = '<pre class="tcptrace-output">' + "\n".join(html_lines) + "</pre>"

        dialog = ui.dialog()
        with dialog, ui.card().classes("tcptrace-output-card p-0"):
            banner = _desegment_banner_text(state.desegment_kinds, state.desegment_coalesces)
            if banner:
                ui.html(f'<div class="tcptrace-desegment-banner">{_escape_html(banner)}</div>')
            ui.html(legend_html)
            ui.html(pre_html)
        return dialog

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
            .props("dense dark active-color=emph outside-arrows mobile-arrows")
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
            # Quasar's default slide-left/right transition translateX-es
            # the active panel, which creates a new containing block for
            # any fixed-positioned descendants — so the docked stats
            # panel rides the slide horizontally on tab switch. Fade is
            # purely opacity and leaves the fixed panel anchored.
            .props('transition-prev="fade" transition-next="fade"')
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
                    ui.label("no data in this direction").classes("tcptrace-empty w-full").style(
                        "margin-top: 32px;"
                    )
                    return
                if metric == "tsg":
                    with ui.row().classes("items-center gap-2 px-3 py-1 w-full justify-end"):
                        info_switch = (
                            ui.switch("Show info markers", value=state.show_info)
                            .props("dense dark")
                            .tooltip(
                                "Partial-ACK, coalesced (LRO), benign dup-ACK,"
                                " small win shrinks — off by default to keep"
                                " the chart focused on alerts and protocol"
                                " markers"
                            )
                        )
                plotly_el = (
                    ui.plotly(fig)
                    .classes("w-full")
                    .style(
                        # --tt-plot-h / --tt-plot-min-h are unset by default
                        # (fallbacks win); body.tt-dock sets them so the
                        # plot shrinks to clear the fixed dock panel and
                        # allows a smaller min on narrower viewports.
                        "height: var(--tt-plot-h, calc(100vh - 320px));"
                        " min-height: var(--tt-plot-min-h, 480px);"
                    )
                )
                if metric == "tsg":
                    model_pair = state.figure_cache.get((conn_n, metric, "model"))
                    _active_tab_state["tsg"] = {
                        "plotly_el": plotly_el,
                        "model_pair": model_pair,
                        "stats_box": None,
                        "fwd_label": fwd_label,
                        "bwd_label": bwd_label,
                        "container": container,
                        "conn_n": conn_n,
                    }
                    if model_pair is not None:
                        stats_box = ui.column().classes("w-full")
                        _render_stats_panel(stats_box, model_pair, fwd_label, bwd_label, None, None)
                        _active_tab_state["tsg"]["stats_box"] = stats_box
                        # Debounced relayout: plotly fires bursts of these
                        # during a pan/zoom; cancel the pending task and
                        # reschedule, so the stats panel rebuilds once
                        # ~150 ms after the user stops moving instead of
                        # once per intermediate event.
                        pending_relayout: dict[str, asyncio.Task | None] = {"task": None}

                        async def _do_relayout(t0, t1):
                            try:
                                await asyncio.sleep(0.15)
                            except asyncio.CancelledError:
                                return
                            if state.selected_conn != conn_n:
                                return
                            _render_stats_panel(stats_box, model_pair, fwd_label, bwd_label, t0, t1)

                        def _on_relayout(e) -> None:
                            args = e.args or {}
                            if _is_shape_only_relayout(args):
                                return
                            t0, t1 = _xrange_from_relayout(args)
                            prev = pending_relayout["task"]
                            if prev is not None and not prev.done():
                                prev.cancel()
                            pending_relayout["task"] = background_tasks.create(_do_relayout(t0, t1))

                        plotly_el.on("plotly_relayout", _on_relayout)

                        async def _on_info_toggle(e) -> None:
                            state.show_info = bool(e.value)
                            new_fig = await run.io_bound(
                                to_tsg_figure,
                                model_pair,
                                show_info=state.show_info,
                                seq_mode=state.seq_mode,
                            )
                            state.figure_cache[
                                _figure_cache_key(conn_n, metric, state.show_info)
                            ] = new_fig
                            if state.selected_conn == conn_n:
                                plotly_el.update_figure(new_fig)

                        info_switch.on_value_change(_on_info_toggle)
                if metric == "tput":
                    with ui.row().classes("items-center gap-2 px-3 py-1 w-full justify-end"):
                        tput_info_switch = (
                            ui.switch("Show info anomalies", value=state.show_info)
                            .props("dense dark")
                            .tooltip(
                                "Show info-tier stalls and cliffs — minor pauses"
                                " and small throughput drops; off by default"
                            )
                        )
                    tput_pair = state.figure_cache.get((conn_n, metric, "model"))
                    _active_tab_state["tput"] = {
                        "plotly_el": plotly_el,
                        "model_pair": tput_pair,
                        "stats_box": None,
                        "fwd_label": fwd_label,
                        "bwd_label": bwd_label,
                        "container": container,
                        "conn_n": conn_n,
                    }
                    if tput_pair is not None:
                        tput_stats_box = ui.column().classes("w-full")
                        _render_throughput_stats_panel(
                            tput_stats_box, tput_pair, fwd_label, bwd_label, None, None
                        )
                        _active_tab_state["tput"]["stats_box"] = tput_stats_box
                        pending_tput_relayout: dict[str, asyncio.Task | None] = {"task": None}

                        async def _do_tput_relayout(t0, t1):
                            try:
                                await asyncio.sleep(0.15)
                            except asyncio.CancelledError:
                                return
                            if state.selected_conn != conn_n:
                                return
                            _render_throughput_stats_panel(
                                tput_stats_box, tput_pair, fwd_label, bwd_label, t0, t1
                            )

                        def _on_tput_relayout(e) -> None:
                            args = e.args or {}
                            if _is_shape_only_relayout(args):
                                return
                            t0, t1 = _xrange_from_relayout(args)
                            prev = pending_tput_relayout["task"]
                            if prev is not None and not prev.done():
                                prev.cancel()
                            pending_tput_relayout["task"] = background_tasks.create(
                                _do_tput_relayout(t0, t1)
                            )

                        plotly_el.on("plotly_relayout", _on_tput_relayout)

                        async def _on_tput_info_toggle(e) -> None:
                            state.show_info = bool(e.value)
                            new_fig = await run.io_bound(
                                to_throughput_figure,
                                tput_pair,
                                show_info=state.show_info,
                                rate_unit=state.rate_unit,
                            )
                            state.figure_cache[
                                _figure_cache_key(conn_n, metric, state.show_info)
                            ] = new_fig
                            if state.selected_conn == conn_n:
                                plotly_el.update_figure(new_fig)

                        tput_info_switch.on_value_change(_on_tput_info_toggle)

        async def _populate(metric: str) -> None:
            if metric in activated:
                return
            activated.add(metric)
            g = group_by_metric.get(metric)
            if g is None:
                return
            cache_key = _figure_cache_key(conn_n, metric, state.show_info)
            if cache_key in state.figure_cache:
                if state.selected_conn != conn_n:
                    return
                _show_figure(metric, state.figure_cache[cache_key])
                return
            container = panel_containers[metric]
            with container:
                ui.spinner(size="md").classes("self-center").style("margin-top: 32px;")
            try:
                if metric == "tsg":
                    # Model is built (or already cached) by `select_conn`.
                    # Tab activation is figure-build only — cheap; io_bound
                    # is the right tool (cpu_bound would pickle the whole
                    # model pair and pay overhead exceeding the work).
                    pair = await ensure_tsg_pair(conn_n)
                    fig = (
                        await run.io_bound(
                            to_tsg_figure,
                            pair,
                            show_info=state.show_info,
                            seq_mode=state.seq_mode,
                        )
                        if pair is not None
                        else None
                    )
                elif metric == "tput":
                    # Throughput tab reuses the cached TSG pair (the model
                    # the user is staring at on the TSG tab), then derives
                    # the throughput model. Two cheap pure ops.
                    tsg_pair = await ensure_tsg_pair(conn_n)
                    tput_pair = await run.io_bound(build_tput_pair_pure, tsg_pair)
                    state.figure_cache[(conn_n, metric, "model")] = tput_pair
                    fig = (
                        await run.io_bound(
                            to_throughput_figure,
                            tput_pair,
                            show_info=state.show_info,
                            rate_unit=state.rate_unit,
                        )
                        if tput_pair is not None
                        else None
                    )
                elif g.combined is not None:
                    fig = await run.io_bound(build_combined_figure_pure, g.combined)
                else:
                    fig = await run.io_bound(
                        build_paired_figure_pure,
                        g.forward,
                        g.backward,
                        fwd_label,
                        bwd_label,
                    )
            except Exception as exc:
                if state.selected_conn != conn_n:
                    return
                container.clear()
                with container:
                    ui.label(f"[render error: {exc}]").classes("text-bad")
                return
            state.figure_cache[cache_key] = fig
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

    def _show_only(zone: ui.column) -> None:
        for z in (_empty_zone, _sticky_head_zone, _analysis_zone):
            z.classes(add="tcptrace-zone-hidden")
        zone.classes(remove="tcptrace-zone-hidden")

    def _show_only_pair(*zones: ui.column) -> None:
        _empty_zone.classes(add="tcptrace-zone-hidden")
        for z in zones:
            z.classes(remove="tcptrace-zone-hidden")

    def show_empty(reason: str) -> None:
        _empty_label.set_text(reason)
        _show_only(_empty_zone)

    def show_pending(n: int, phase: str) -> None:
        _pending_label.set_text(_phase_label_text(n, phase))
        _pending_row.classes(remove="tcptrace-zone-hidden")
        _figures_zone.classes(add="tcptrace-zone-hidden")
        _title_label.set_text(f"Conn {n}")
        _show_only_pair(_sticky_head_zone, _analysis_zone)

    def show_analysis_for(n: int) -> None:
        result = state.analyses.get(n)
        if result is None:
            show_pending(n, "analyzing")
            return
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

        _title_label.set_text(title_main)
        _set_label_visibility(_subtitle_label, subtitle)
        _set_label_visibility(
            _fwd_ctx_label,
            f"{fwd_label}  {_apply_rate_unit_to_ctx(fwd_ctx, state.rate_unit)}" if fwd_ctx else "",
        )
        _set_label_visibility(
            _bwd_ctx_label,
            f"{bwd_label}  {_apply_rate_unit_to_ctx(bwd_ctx, state.rate_unit)}" if bwd_ctx else "",
        )
        _set_html_visibility(
            _findings_html,
            _findings_panel_html(state.findings.get(n), fwd_label, bwd_label)
            if state.findings.get(n)
            else "",
        )

        _active_tab_state.clear()
        old_dialog = _current_dialog["d"]
        if old_dialog is not None:
            old_dialog.delete()
            _current_dialog["d"] = None
        with main_container:
            new_dialog = _build_output_dialog(result)
        _current_dialog["d"] = new_dialog
        _output_btn_slot.clear()
        with _output_btn_slot:
            with ui.column().classes("items-end gap-1"):
                ui.button("tcptrace output", on_click=new_dialog.open).props(
                    "flat dense"
                ).classes("tcptrace-rawout-btn")
                ui.button(
                    "download pcap",
                    on_click=lambda _e, n=n: on_download_conn_pcap(n),
                ).props("flat dense").classes("tcptrace-rawout-btn")

        _tabs_slot.clear()
        with _tabs_slot:
            groups, tabs, default_tab = _render_tabs_head(result)

        _pending_row.classes(add="tcptrace-zone-hidden")
        _figures_zone.classes(remove="tcptrace-zone-hidden")
        _figures_zone.clear()
        with _figures_zone:
            if groups:
                _render_analysis(result, groups, tabs, default_tab)
            else:
                ui.label("no graphs available").classes("tcptrace-empty w-full")

        _show_only_pair(_sticky_head_zone, _analysis_zone)

    def refresh_context_lines() -> None:
        """Re-apply rate-unit formatting to the persistent context labels.
        No figure rebuild, no tab interaction, no DOM construction."""
        n = state.selected_conn
        if n is None:
            return
        row = next((r for r in state.stats if r.n == n), None)
        if row is None or not isinstance(row, ConnStats):
            return
        fwd_label, bwd_label = _direction_labels(row)
        _set_label_visibility(
            _fwd_ctx_label,
            f"{fwd_label}  {_apply_rate_unit_to_ctx(row.fwd_ctx, state.rate_unit)}"
            if row.fwd_ctx
            else "",
        )
        _set_label_visibility(
            _bwd_ctx_label,
            f"{bwd_label}  {_apply_rate_unit_to_ctx(row.bwd_ctx, state.rate_unit)}"
            if row.bwd_ctx
            else "",
        )

    def refresh_findings_panel(n: int) -> None:
        """Mutate _findings_html when findings arrive for connection n.
        Other zone children untouched."""
        if state.selected_conn != n:
            return
        row = next((r for r in state.stats if r.n == n), None)
        fwd_label = bwd_label = ""
        if row is not None and isinstance(row, ConnStats):
            fwd_label, bwd_label = _direction_labels(row)
        findings = state.findings.get(n) or []
        _set_html_visibility(
            _findings_html,
            _findings_panel_html(findings, fwd_label, bwd_label) if findings else "",
        )

    async def refresh_active_tab() -> None:
        """Re-run the figure build for whichever tab is showing the current
        connection. No-op for non-figure tabs or when _active_tab_state is
        empty for the active metrics."""
        n = state.selected_conn
        if n is None:
            return
        for metric in ("tsg", "tput"):
            tab_state = _active_tab_state.get(metric)
            if tab_state is None or tab_state.get("conn_n") != n:
                continue
            model_pair = tab_state["model_pair"]
            if model_pair is None:
                continue
            if metric == "tsg":
                new_fig = await run.io_bound(
                    to_tsg_figure,
                    model_pair,
                    show_info=state.show_info,
                    seq_mode=state.seq_mode,
                )
            else:
                new_fig = await run.io_bound(
                    to_throughput_figure,
                    model_pair,
                    show_info=state.show_info,
                    rate_unit=state.rate_unit,
                )
            state.figure_cache[_figure_cache_key(n, metric, state.show_info)] = new_fig
            if state.selected_conn == n:
                tab_state["plotly_el"].update_figure(new_fig)

    def refresh_stats_panel(direction: str | None, t0: float | None, t1: float | None) -> None:
        """Re-render the TSG stats panel for the current zoom range."""
        tab_state = _active_tab_state.get("tsg")
        if tab_state is None:
            return
        if tab_state.get("conn_n") != state.selected_conn:
            return
        stats_box = tab_state.get("stats_box")
        model_pair = tab_state.get("model_pair")
        if stats_box is None or model_pair is None:
            return
        _render_stats_panel(
            stats_box, model_pair, tab_state["fwd_label"], tab_state["bwd_label"], t0, t1
        )

    def refresh_throughput_stats_panel(
        direction: str | None, t0: float | None, t1: float | None
    ) -> None:
        """Re-render the throughput stats panel for the current zoom range."""
        tab_state = _active_tab_state.get("tput")
        if tab_state is None:
            return
        if tab_state.get("conn_n") != state.selected_conn:
            return
        stats_box = tab_state.get("stats_box")
        model_pair = tab_state.get("model_pair")
        if stats_box is None or model_pair is None:
            return
        _render_throughput_stats_panel(
            stats_box, model_pair, tab_state["fwd_label"], tab_state["bwd_label"], t0, t1
        )

    return MainHandle(
        main_container=main_container,
        show_empty=show_empty,
        show_pending=show_pending,
        show_analysis_for=show_analysis_for,
        refresh_context_lines=refresh_context_lines,
        refresh_findings_panel=refresh_findings_panel,
        refresh_active_tab=refresh_active_tab,
        refresh_stats_panel=refresh_stats_panel,
        refresh_throughput_stats_panel=refresh_throughput_stats_panel,
        _empty_zone=_empty_zone,
        _sticky_head_zone=_sticky_head_zone,
        _analysis_zone=_analysis_zone,
        _empty_label=_empty_label,
        _pending_row=_pending_row,
        _pending_spinner=_pending_spinner,
        _pending_label=_pending_label,
        _figures_zone=_figures_zone,
        _title_label=_title_label,
        _subtitle_label=_subtitle_label,
        _fwd_ctx_label=_fwd_ctx_label,
        _bwd_ctx_label=_bwd_ctx_label,
        _findings_html=_findings_html,
        _output_btn_slot=_output_btn_slot,
        _tabs_slot=_tabs_slot,
        _current_dialog=_current_dialog,
        _active_tab_state=_active_tab_state,
    )
