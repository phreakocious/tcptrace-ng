"""NiceGUI page and reactive state. The only module that imports nicegui.

Layout: top header (pcap dropdown + cache controls) + left drawer
(filter + clickable connection list + xpl-zip button) + main panel
(tabs over plotly graphs + collapsible color-coded tcptrace output).

Clicking a connection runs tcptrace for that connection on demand
(off the event loop via `run.io_bound`) and renders it in the main panel.
Analyzed connections stay in `state.analyses` so re-clicking is instant.
"""

from __future__ import annotations

import asyncio
import io
import zipfile
from collections.abc import Callable
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace

from nicegui import app as _ng_app
from nicegui import background_tasks, run, ui

from .cache import (
    CacheLayout,
    clear_pcap_cache,
    invalidate_if_stale_version,
    is_fresh,
    load_stats,
    save_stats,
    write_version,
)
from .csum import CsumEvent
from .csum import scan_pcap as scan_csums
from .diagnose import Finding, diagnose
from .pcap_extract import extract_conversation
from .pcap_setup import ensure_decapped, ensure_desegmented, scan_for_warnings
from .plotly_adapter import (
    to_paired_plotly_figure,
    to_plotly_figure,
    to_throughput_figure,
    to_tsg_figure,
)
from .reorder_pipeline import classify_connection_pure
from .runner import (
    AnalyzeResult,
    RunnerError,
    analyze_all,
    analyze_connection,
    list_connections,
    try_convert_to_pcap,
)
from .state import _State, cache_version, state
from .stats_parser import ConnStats
from .tcp_inspect import synthesize as synthesize_tsg
from .theme import DARK_CSS, FONT_FACES, quasar_colors
from .throughput import synthesize_throughput
from .view import header as view_header
from .view import hover_crossbar
from .view import main as view_main
from .view import sidebar as view_sidebar
from .view.format import _split_endpoint
from .xpl_grouper import group_xpls
from .xpl_parser import XplPlot, parse_xpl

# Self-host the DejaVu Sans Mono woff2s shipped in the package so the
# `@font-face` rules in `FONT_FACES` resolve regardless of network access.
# Mounted once at module-import time — adding it inside the page handler
# would re-register the route on every request.
_ng_app.add_static_files(
    "/_tt/fonts",
    str(files("tcptrace_ng") / "static" / "fonts"),
)

# How often to rescan the working directory for new/updated pcaps. The user
# generally writes captures while the page is open; long enough to be cheap
# (one round of stats() per pcap), short enough to feel live.
_PCAP_RESCAN_SECONDS = 30.0


def build_xpl_zip(analyses: dict[int, AnalyzeResult]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for n, result in analyses.items():
            for xpl in result.xpl_files:
                zf.write(xpl, arcname=f"conn-{n}/{xpl.name}")
    return buf.getvalue()


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


def _coalesces_directed(src: str, dst: str) -> list[dict]:
    """Desegment manifest entries for coalesced data going `src` → `dst` (each
    `ip:port`). The manifest is pcap-wide; filtering by endpoint avoids a
    cross-connection seq collision (tagging itself is by timestamp+seq). Empty
    when either endpoint won't parse. Mirrors `_csum_times_directed`."""
    s = _split_endpoint(src)
    d = _split_endpoint(dst)
    if s is None or d is None:
        return []
    return [
        c
        for c in state.desegment_coalesces
        if _split_endpoint(c.get("src", "")) == s and _split_endpoint(c.get("dst", "")) == d
    ]


def _safe_parse_xpl(xpl: Path) -> tuple[XplPlot | None, str | None]:
    """Single try/except wrapper around parse_xpl. Returns (plot, None) on
    success or (None, message) on failure so callers can pick recovery."""
    try:
        return parse_xpl(xpl), None
    except Exception as exc:
        return None, f"{xpl.name}: {exc}"


def _csum_times_directed_pure(src: str, dst: str, bad_csum_events: list[CsumEvent]) -> list[float]:
    s = _split_endpoint(src)
    d = _split_endpoint(dst)
    if s is None or d is None:
        return []
    return [
        ev.time
        for ev in bad_csum_events
        if (ev.src_ip, ev.src_port) == s and (ev.dst_ip, ev.dst_port) == d
    ]


def _coalesces_directed_pure(src: str, dst: str, coalesces: list[dict]) -> list[dict]:
    s = _split_endpoint(src)
    d = _split_endpoint(dst)
    if s is None or d is None:
        return []
    return [
        c
        for c in coalesces
        if _split_endpoint(c.get("src", "")) == s and _split_endpoint(c.get("dst", "")) == d
    ]


def _build_tsg_model_pure(
    forward: Path | None,
    backward: Path | None,
    details_text: str,
    bad_csum_events: list[CsumEvent],
    desegment_coalesces: list[dict],
):
    """Parse xpls + filter csum/coalesces from passed events + synthesize.

    Pickleable (no module-state reads), so `run.cpu_bound` can ship this off
    to a worker process — synthesize is the heaviest CPU step per conn click
    (hundreds of ms on dense captures), and the process pool sidesteps GIL
    contention with NiceGUI's event loop and outbox.
    """
    from .tcp_inspect import _parse_endpoints  # avoid widening tcp_inspect's API

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

    def _csum_for(plot):
        if plot is None:
            return []
        src, dst = _parse_endpoints(plot.title)
        if not (src and dst):
            return []
        return _csum_times_directed_pure(src, dst, bad_csum_events)

    def _co_for(plot):
        if plot is None:
            return []
        src, dst = _parse_endpoints(plot.title)
        if not (src and dst):
            return []
        return _coalesces_directed_pure(src, dst, desegment_coalesces)

    return synthesize_tsg(
        fwd_plot,
        bwd_plot,
        details_text,
        bad_csum_times_fwd=_csum_for(fwd_plot),
        bad_csum_times_bwd=_csum_for(bwd_plot),
        coalesces_fwd=_co_for(fwd_plot),
        coalesces_bwd=_co_for(bwd_plot),
    )


def _build_tput_pair_pure(tsg_pair):
    """Pickleable: build a ThroughputModelPair from an already-synthesized TSG
    pair. Avoids the second `synthesize_tsg` call that the old _build_tput_model
    did — the model the user is staring at on the TSG tab is identical to the
    input the throughput synthesis needs."""
    if tsg_pair is None:
        return None
    stats = (
        tsg_pair.fwd.summary
        if tsg_pair.fwd is not None
        else tsg_pair.bwd.summary
        if tsg_pair.bwd is not None
        else None
    )
    return synthesize_throughput(tsg_pair, stats)


def _build_paired_figure_pure(
    forward: Path | None, backward: Path | None, fwd_label: str, bwd_label: str
) -> dict | None:
    """Generic two-direction figure for non-tsg/tput metrics (rtt/owin/ssize)."""
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
    return to_paired_plotly_figure(fwd_plot, bwd_plot, fwd_label, bwd_label)


def _build_combined_figure_pure(combined: Path) -> dict | None:
    """Combined-single-direction figure (the tline metric)."""
    plot, _err = _safe_parse_xpl(combined)
    if plot is None or not plot.commands:
        return None
    return to_plotly_figure(plot)


def _compute_findings_pure(
    n: int,
    result: AnalyzeResult,
    stats: ConnStats | None,
    tsg_pair,
) -> list[Finding]:
    """Pickleable: run diagnose() against the pre-built TSG model.

    Mirrors the old `_compute_findings` but takes inputs as args instead of
    reading module state, so it can run in `run.cpu_bound`. tsg may be None
    when no TSG xpl was emitted (stats-only findings). `result` and `n` are
    accepted for parity / future detectors that may want details_text or
    the conn number."""
    return diagnose(stats, tsg_pair, None)


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


def _sync_lro_warning(state: _State) -> None:
    """Add/refresh the LRO warning string in state.pcap_warnings.

    Drops any stale LRO entry first, then appends a fresh one reflecting
    the current `state.conns_with_lro` count. n=0 just drops.
    """
    state.pcap_warnings = [w for w in state.pcap_warnings if not w.startswith(_LRO_WARNING_PREFIX)]
    n = len(state.conns_with_lro)
    if n == 0:
        return
    state.pcap_warnings.append(
        f"{_LRO_WARNING_PREFIX}coalesced segments detected in {n} "
        f"connection{'s' if n != 1 else ''}. See per-connection LRO "
        f"counts in the TSG info strip. MSS, time-sequence staircases, "
        f"and retransmit detection are unreliable for these flows."
    )


async def _ensure_tsg_pair(n: int, refresh_warnings_fn: Callable[[], None] | None = None):
    """Compute (or fetch) the cached TSG model for conn n.

    Heavy synthesis runs in `run.cpu_bound` (process pool) so the event
    loop and outbox keep ticking — synthesize is the biggest single
    CPU step in the conn-click flow (hundreds of ms on dense captures),
    and a thread-pool worker would hold the GIL long enough to drop
    socket.io pongs.

    Cached in `state.figure_cache[(n, 'tsg', 'model')]` so the
    findings, the TSG tab, and the throughput tab all reuse one pair
    instead of synthesizing three times. Returns None when there's no
    TSG xpl (degenerate captures) — caller treats that as 'no model'.

    `refresh_warnings_fn` is called (if provided) when a new LRO anomaly is
    detected mid-analysis — the header handle is not available at module scope
    so it is injected by index() via a lambda.
    """
    cache_key = (n, "tsg", "model")
    if cache_key in state.figure_cache:
        return state.figure_cache[cache_key]
    result = state.analyses.get(n)
    if result is None:
        return None
    g_tsg = next((g for g in group_xpls(result.xpl_files) if g.metric == "tsg"), None)
    if g_tsg is None:
        state.figure_cache[cache_key] = None
        return None
    try:
        pair = await run.cpu_bound(
            _build_tsg_model_pure,
            g_tsg.forward,
            g_tsg.backward,
            result.details_text,
            state.bad_csum_events,
            state.desegment_coalesces,
        )
    except Exception:
        pair = None
    state.figure_cache[cache_key] = pair
    # Mid-analysis LRO surfacing — the bounded pre-flight scan misses
    # offload that begins after its frame budget, so check the model.
    if pair is not None and _has_lro_anomaly(pair) and n not in state.conns_with_lro:
        state.conns_with_lro.add(n)
        _sync_lro_warning(state)
        if refresh_warnings_fn is not None:
            refresh_warnings_fn()
    return pair


# Backward-compat shims. The hot path (build_page → select_conn → _populate)
# uses the `*_pure` variants directly with state slices passed as args. These
# state-reading wrappers exist for tests and for any out-of-page caller that
# may rely on the historical signatures.


def _build_tsg_model(
    forward: Path | None,
    backward: Path | None,
    details_text: str,
):
    return _build_tsg_model_pure(
        forward,
        backward,
        details_text,
        state.bad_csum_events,
        state.desegment_coalesces,
    )


def _build_tput_model(
    forward: Path | None,
    backward: Path | None,
    details_text: str,
):
    return _build_tput_pair_pure(_build_tsg_model(forward, backward, details_text))


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
    if metric == "tsg":
        pair = _build_tsg_model(forward, backward, details_text)
        return None if pair is None else to_tsg_figure(pair, show_info=show_info, seq_mode=seq_mode)
    if metric == "tput":
        pair = _build_tput_model(forward, backward, details_text)
        return (
            None
            if pair is None
            else to_throughput_figure(pair, show_info=show_info, rate_unit=rate_unit)
        )
    if combined is not None:
        return _build_combined_figure_pure(combined)
    return _build_paired_figure_pure(forward, backward, fwd_label, bwd_label)


def _compute_findings(n: int) -> list[Finding]:
    result = state.analyses.get(n)
    if result is None:
        return []
    stats = next((r for r in state.stats if isinstance(r, ConnStats) and r.n == n), None)
    g_tsg = next((g for g in group_xpls(result.xpl_files) if g.metric == "tsg"), None)
    tsg = (
        _build_tsg_model(g_tsg.forward, g_tsg.backward, result.details_text)
        if g_tsg is not None
        else None
    )
    return _compute_findings_pure(n, result, stats, tsg)


def build_page() -> None:
    """Register the `/` route on the default NiceGUI app."""

    @ui.page("/")
    def index() -> None:
        # Layer order: Quasar dark baseline → palette CSS vars → fonts → chrome
        # → behavior. Every later layer reads/overrides values from the earlier
        # ones (see docs/superpowers/specs/2026-06-04-retheme-design.md §2).
        ui.dark_mode().enable()
        ui.colors(**quasar_colors())
        ui.add_head_html(FONT_FACES)
        ui.add_head_html(f"<style>{DARK_CSS}</style>")
        hover_crossbar.install(ui)

        cwd = Path.cwd()
        header = view_header.build(state, cwd)

        # =========== sidebar ===========

        def _do_download_zip() -> None:
            if not state.analyses or state.selected_pcap is None:
                return
            data = build_xpl_zip(state.analyses)
            ui.download(data, filename=f"{state.selected_pcap.name}-xpl.zip")

        sidebar = view_sidebar.build(
            state,
            # Lambda for forward ref: select_conn is defined later in
            # this index() body — the lambda body resolves the name lazily
            # at click time, by which point all intents are in scope.
            on_conn_click=lambda n: select_conn(n),
            on_download_zip=_do_download_zip,
            csum_counts_for_endpoints=_csum_counts_for_endpoints,
        )

        header.menu_btn.on("click", lambda: sidebar.drawer.toggle())

        # =========== main ===========

        async def _download_conn_pcap(n: int) -> None:
            """Filter the effective pcap to conn `n`'s 5-tuple, classic-pcap on disk.

            Walks the *effective* pcap (post-decap/desegment) rather than the
            on-disk original because that's the data tcptrace analyzed and
            what the user is viewing. The filter runs through `run.io_bound`
            so the websocket keeps ticking on large captures.
            """
            if state.effective_pcap is None or state.selected_pcap is None:
                return
            row = next((r for r in state.stats if r.n == n), None)
            if row is None:
                return
            data = await run.io_bound(
                extract_conversation, state.effective_pcap, row.host_a, row.host_b
            )
            if not data:
                ui.notify("could not extract conversation", color="negative")
                return
            ui.download(data, filename=f"{state.selected_pcap.stem}-conn-{n}.pcap")

        main = view_main.build(
            state,
            initial_pcaps=header.initial_pcaps,
            cwd=cwd,
            ensure_tsg_pair=lambda n: _ensure_tsg_pair(n, header.refresh_warnings),
            build_tput_pair_pure=_build_tput_pair_pure,
            build_combined_figure_pure=_build_combined_figure_pure,
            build_paired_figure_pure=_build_paired_figure_pure,
            on_download_conn_pcap=_download_conn_pcap,
        )

        # =========== intents ===========
        # Each intent is one named user action. Intents are the only sites
        # where state mutates *and* refresh hooks fire — keeping that
        # invariant means the data flow stays debuggable by Cmd-F'ing the
        # intent name.

        def change_filter(e) -> None:
            state.conn_filter = e.value or ""
            sidebar.apply_filter(state.conn_filter)

        async def select_conn(n: int) -> None:
            if state.selected_pcap is None:
                return
            captured_gen = state.stats_generation
            old = state.selected_conn
            state.selected_conn = n
            main.show_pending(n, "analyzing")
            sidebar.refresh_selection(old, n)
            # Force the NiceGUI outbox to flush — without this, the spinner
            # frame and the analyze-result frame batch into a single websocket
            # update on cache-hit, so the user sees nothing during the (often
            # ~hundreds of ms) cache load.
            await asyncio.sleep(0)
            if n in state.analyses:
                # Already cached: jump straight to render-with-pending-findings.
                pass
            else:
                layout = CacheLayout(state.selected_pcap)
                layout.ensure_conn(n)
                details_path = layout.conn_details(n)
                xpls_pattern = f"conn-{n}--*.xpl"
                cached_xpls = sorted(layout.conn_dir(n).glob(xpls_pattern))
                fresh = (
                    is_fresh(
                        details_path,
                        state.selected_pcap,
                        cache_version(state),
                        layout.version_file,
                    )
                    and all(
                        is_fresh(
                            x,
                            state.selected_pcap,
                            cache_version(state),
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
                        if state.selected_conn == n:
                            state.selected_conn = None
                            main.show_empty("click a connection on the left to analyze it")
                            sidebar.refresh_selection(n, None)
                        return
                    details_path.write_text(result.details_text)
                    state.analyses[n] = result
                if state.stats_generation != captured_gen:
                    return  # registry rebuilt; this completion is stale
                header.refresh_cache_label()
                sidebar.refresh_download_btn()
            # Phase 2: synthesizing TSG model.
            main.show_pending(n, "synthesizing")
            await asyncio.sleep(0)
            tsg_pair = await _ensure_tsg_pair(n, header.refresh_warnings)
            # Phase 2.5: reorder classification (data layer; cached for Plan-4 presentation).
            if n not in state.reorder and state.selected_pcap is not None:
                _row = next((r for r in state.stats if r.n == n), None)
                _stats_row = next(
                    (r for r in state.stats if isinstance(r, ConnStats) and r.n == n), None
                )
                if _row is not None:
                    _layout = CacheLayout(state.selected_pcap)
                    try:
                        state.reorder[n] = await run.cpu_bound(
                            classify_connection_pure,
                            _layout.decap_pcap,
                            state.selected_pcap,
                            _row.host_a,
                            _row.host_b,
                            _stats_row,
                        )
                    except Exception:
                        state.reorder[n] = None
            # Phase 3: diagnosing.
            if n not in state.findings:
                main.show_pending(n, "diagnosing")
                await asyncio.sleep(0)
                stats_row = next(
                    (r for r in state.stats if isinstance(r, ConnStats) and r.n == n), None
                )
                result = state.analyses.get(n)
                try:
                    state.findings[n] = await run.cpu_bound(
                        _compute_findings_pure, n, result, stats_row, tsg_pair
                    )
                except Exception:
                    state.findings[n] = []
            if state.stats_generation != captured_gen:
                return  # registry rebuilt; this completion is stale
            if state.selected_conn == n:
                main.show_analysis_for(n)
                sidebar.refresh_row(n)

        async def pick_pcap(e) -> None:
            value = e.value
            state.selected_pcap = Path(value) if value else None
            state.effective_pcap = state.selected_pcap
            state.decap_encaps = set()
            state.pcap_warnings = []
            state.conns_with_lro = set()
            header.refresh_warnings()
            state.selected_conn = None
            state.stats = []
            state.analyses = {}
            state.findings = {}
            state.reorder = {}
            state.figure_cache = {}
            state.conn_filter = ""
            sidebar.filter_input.set_value("")
            sidebar.refresh_download_btn()
            if state.selected_pcap is None:
                main.show_empty("select a pcap from the header")
            else:
                main.show_empty("click a connection on the left to analyze it")
            sidebar.populate_rows([])
            if state.selected_pcap is None:
                return

            invalidate_if_stale_version(state.selected_pcap, cache_version(state))

            layout = CacheLayout(state.selected_pcap)
            state.effective_pcap = await ensure_decapped(state, state.selected_pcap, layout)
            state.effective_pcap = await ensure_desegmented(state, state.effective_pcap, layout)
            header.refresh_cache_label()
            if state.decap_encaps:
                ui.notify(
                    f"decap'd outer {'/'.join(sorted(state.decap_encaps))}",
                    type="info",
                )
            if state.desegment_kinds:
                ui.notify(
                    f"de-coalesced offload ({'/'.join(sorted(state.desegment_kinds))})",
                    type="info",
                )
            await scan_for_warnings(state, state.effective_pcap)
            header.refresh_warnings()
            # Independent per-packet TCP-checksum scan. Cheap on small pcaps
            # and the only source of `bad_csum` anomalies; we never let
            # tcptrace --checksum filter packets out of the analysis.
            try:
                state.bad_csum_events = await run.io_bound(scan_csums, state.effective_pcap)
            except Exception:
                state.bad_csum_events = []
            cached = load_stats(layout, cache_version(state))
            if cached is not None:
                state.stats = cached
                sidebar.populate_rows(cached)
                return

            state.analyzing = True
            sidebar.refresh_count_label()
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
                        state.effective_pcap = await ensure_decapped(
                            state, state.selected_pcap, layout
                        )
                        state.effective_pcap = await ensure_desegmented(
                            state, state.effective_pcap, layout
                        )
                        await scan_for_warnings(state, state.effective_pcap)
                        header.refresh_warnings()
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
                sidebar.populate_rows(state.stats)
                return
            except Exception as exc:
                ui.notify(f"tcptrace failed: {exc}", type="negative")
                state.stats = []
                state.analyzing = False
                sidebar.populate_rows([])
                return

            state.stats = stats
            state.analyzing = False
            write_version(layout, cache_version(state))
            save_stats(layout, stats)
            sidebar.populate_rows(stats)

        async def clear_cache() -> None:
            import shutil as _sh

            root = cwd / ".tcptrace"
            if root.exists():
                _sh.rmtree(root)
            state.analyses.clear()
            state.findings.clear()
            state.figure_cache.clear()
            state.conns_with_lro.clear()
            _sync_lro_warning(state)
            header.refresh_warnings()
            state.selected_conn = None
            header.refresh_cache_label()
            sidebar.refresh_download_btn()
            main.show_empty(
                "select a pcap from the header"
                if state.selected_pcap is None
                else "click a connection on the left to analyze it"
            )
            sidebar.populate_rows([])
            ui.notify("cache cleared", type="positive")
            # The decap'd copy lived inside the wiped tree; re-prime the pick
            # so effective_pcap is rebuilt before the next analysis.
            if state.selected_pcap is not None:
                await pick_pcap(SimpleNamespace(value=str(state.selected_pcap)))

        async def reanalyze() -> None:
            if state.selected_pcap is None:
                ui.notify("no pcap selected", type="warning")
                return
            clear_pcap_cache(state.selected_pcap)
            state.analyses.clear()
            state.findings.clear()
            state.figure_cache.clear()
            state.conns_with_lro.clear()
            _sync_lro_warning(state)
            header.refresh_warnings()
            state.selected_conn = None
            header.refresh_cache_label()
            sidebar.refresh_download_btn()
            main.show_empty(
                "select a pcap from the header"
                if state.selected_pcap is None
                else "click a connection on the left to analyze it"
            )
            sidebar.populate_rows([])
            ui.notify(
                f"cache cleared for {state.selected_pcap.name}",
                type="positive",
            )
            await pick_pcap(SimpleNamespace(value=str(state.selected_pcap)))

        async def toggle_flag(field: str, value: bool) -> None:
            """Set the flag on state, then re-trigger the pick for the current
            pcap so the analyze flow re-runs with the new flags. The cache key
            changes via `cache_version(state)`, so any on-disk cache from the old
            flag set is wiped by `invalidate_if_stale_version`."""
            setattr(state, field, bool(value))
            if state.selected_pcap is None:
                return
            await pick_pcap(SimpleNamespace(value=str(state.selected_pcap)))

        def _drop_figure_cache_keep_models() -> None:
            """Cached figures depend on rate_unit/seq_mode; cached models don't.
            Drop figures so the next tab activation rebuilds them with the new
            display setting — but keep models so synthesize_tsg doesn't re-run."""
            state.figure_cache = {k: v for k, v in state.figure_cache.items() if k[-1] == "model"}

        def toggle_rate_unit(value: str) -> None:
            state.rate_unit = value
            _drop_figure_cache_keep_models()
            if state.selected_conn is not None:
                main.refresh_context_lines()
                background_tasks.create(main.refresh_active_tab())

        def toggle_seq_mode(value: str) -> None:
            state.seq_mode = value
            _drop_figure_cache_keep_models()
            if state.selected_conn is not None:
                background_tasks.create(main.refresh_active_tab())

        def toggle_dock(value: bool) -> None:
            """Toggle the body-level dock class. CSS turns the stats panes into
            sticky-bottom strips against `body.tt-dock` — no figure rebuild and
            no re-render needed, just a class flip. Trigger Plotly.Plots.resize
            after the flip because Plotly caches its internal dimensions and
            won't redraw to the new CSS-driven container height on its own."""
            state.dock_summary = bool(value)
            js_bool = "true" if state.dock_summary else "false"
            ui.run_javascript(
                f"document.body.classList.toggle('tt-dock', {js_bool});"
                " requestAnimationFrame(() => document.querySelectorAll"
                "('.js-plotly-plot').forEach(p => window.Plotly &&"
                " window.Plotly.Plots.resize(p)));"
            )

        # ---------- wire events ----------
        sidebar.filter_input.on_value_change(change_filter)
        header.clear_btn.on_click(clear_cache)
        header.reanalyze_btn.on_click(reanalyze)
        header.warning_chip.on_click(header.warning_dialog.open)
        header.pcap_select.on_value_change(pick_pcap)
        header.dns_check.on_value_change(lambda e: toggle_flag("dns", e.value))
        header.rtt_check.on_value_change(lambda e: toggle_flag("with_rtt", e.value))
        header.warn_check.on_value_change(lambda e: toggle_flag("with_warnings", e.value))
        header.zerox_check.on_value_change(lambda e: toggle_flag("zero_x_axis", e.value))
        header.rate_toggle.on_value_change(lambda e: toggle_rate_unit(e.value))
        header.seq_toggle.on_value_change(lambda e: toggle_seq_mode(e.value))
        header.dock_check.on_value_change(lambda e: toggle_dock(e.value))
        ui.timer(_PCAP_RESCAN_SECONDS, header.refresh_pcap_dropdown)

        # ---------- initial render ----------
        header.refresh_cache_label()
        header.refresh_warnings()
        sidebar.refresh_download_btn()
        main.show_empty(
            f"no pcap files in {cwd}"
            if not header.initial_pcaps
            else "select a pcap from the header"
        )
        sidebar.populate_rows([])
        # Sync the body-level dock class with the persisted state so the page
        # honors the user's prior choice without waiting for the toggle to fire.
        if state.dock_summary:
            ui.run_javascript("document.body.classList.add('tt-dock');")
