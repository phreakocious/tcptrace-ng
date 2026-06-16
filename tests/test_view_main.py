"""Tests for view/main.py — zone scaffolding + surgical refresh contract.

Adds onto the existing smoke test in this module.
"""

from __future__ import annotations

import pytest
from nicegui import ui
from nicegui.testing import User

from tcptrace_ng.app import build_page
from tcptrace_ng.classifier import Class
from tcptrace_ng.runner import AnalyzeResult
from tcptrace_ng.state import _State
from tcptrace_ng.stats_parser import ConnStats
from tcptrace_ng.view.main import build as build_main


@pytest.fixture
def empty_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


async def test_main_renders_empty_placeholder(user: User, empty_cwd):
    build_page()
    await user.open("/")
    await user.should_see("no pcap files")


def _stats(n: int) -> ConnStats:
    return ConnStats(
        n=n,
        host_a=f"10.0.0.{n}:5000{n}",
        host_b=f"10.0.0.{n + 100}:443",
        client_is_a=True,
        total_bytes=1000 * n,
        total_packets=10,
        duration_s=0.1 * n,
        rexmt_packets=0,
        has_rst=False,
        complete_handshake=True,
        verdict=Class.NORMAL,
        fwd_ctx=f"fwd ctx {n}",
        bwd_ctx=f"bwd ctx {n}",
    )


def _fake_analyze(n: int, tmp_path) -> AnalyzeResult:
    details = tmp_path / f"conn-{n}.details.txt"
    details.write_text("normal output line\n")
    return AnalyzeResult(details_text="normal output line\n", xpl_files=[])


@pytest.fixture
def main_handle(tmp_path, monkeypatch):
    """Build the main panel inside a fresh page context.

    Yields (state, _index). Tests await `user.open("/")` to trigger body.
    """
    monkeypatch.chdir(tmp_path)
    state = _State()

    @ui.page("/")
    def _index():
        async def _ensure(_n):
            return None

        handle = build_main(
            state,
            initial_pcaps=[],
            cwd=tmp_path,
            ensure_tsg_pair=_ensure,
            build_tput_pair_pure=lambda p: None,
            build_combined_figure_pure=lambda f: None,
            build_paired_figure_pure=lambda fwd, bwd, fl, bl: None,
            on_download_conn_pcap=_ensure,
        )
        _index.handle = handle  # type: ignore[attr-defined]
        _index.state = state  # type: ignore[attr-defined]

    return _index, tmp_path


async def test_show_empty_renders_reason_and_hides_other_zones(user: User, main_handle):
    _index, _ = main_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    handle.show_empty("pick a pcap")
    assert "tcptrace-zone-hidden" not in (handle._empty_zone._classes or [])
    assert "tcptrace-zone-hidden" in handle._sticky_head_zone._classes
    assert "tcptrace-zone-hidden" in handle._analysis_zone._classes
    assert handle._empty_label.text == "pick a pcap"


async def test_show_pending_displays_phase_label(user: User, main_handle):
    _index, _ = main_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    handle.show_pending(7, "analyzing")
    assert "tcptrace-zone-hidden" in handle._empty_zone._classes
    assert "tcptrace-zone-hidden" not in (handle._sticky_head_zone._classes or [])
    assert "tcptrace-zone-hidden" not in (handle._analysis_zone._classes or [])
    assert handle._pending_label.text == "analyzing connection 7"


async def test_show_pending_phase_change_mutates_label_only(user: User, main_handle):
    """Re-calling show_pending with a new phase must not rebuild the
    spinner — only the label text changes."""
    _index, _ = main_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    handle.show_pending(7, "analyzing")
    spinner_id_before = id(handle._pending_spinner)
    label_id_before = id(handle._pending_label)
    handle.show_pending(7, "synthesizing")
    assert id(handle._pending_spinner) == spinner_id_before
    assert id(handle._pending_label) == label_id_before
    assert handle._pending_label.text == "synthesizing time-sequence model"


async def test_show_analysis_for_owns_one_dialog_at_a_time(user: User, main_handle, tmp_path):
    """show_analysis_for builds the output dialog once at build() time.
    Switching connections updates _current but keeps the same dialog object."""
    _index, _ = main_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    state = _index.state  # type: ignore[attr-defined]
    state.selected_pcap = tmp_path / "fake.pcap"
    state.stats = [_stats(1), _stats(2)]
    state.analyses = {1: _fake_analyze(1, tmp_path), 2: _fake_analyze(2, tmp_path)}
    state.selected_conn = 1
    handle.show_analysis_for(1)
    dlg = handle._output_dialog
    assert dlg is not None
    assert handle._current["result"] is state.analyses[1]
    state.selected_conn = 2
    handle.show_analysis_for(2)
    assert handle._output_dialog is dlg  # same object — built once
    assert handle._current["result"] is state.analyses[2]


async def test_show_analysis_for_persistent_sticky_head_handles(user: User, main_handle, tmp_path):
    """Title and subtitle labels survive across show_analysis_for calls
    for *different* connections — their text changes, but identity
    persists. Tabs are allowed to rebuild (they're conn-keyed)."""
    _index, _ = main_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    state = _index.state  # type: ignore[attr-defined]
    state.selected_pcap = tmp_path / "fake.pcap"
    state.stats = [_stats(1), _stats(2)]
    state.analyses = {1: _fake_analyze(1, tmp_path), 2: _fake_analyze(2, tmp_path)}
    handle.show_analysis_for(1)
    title_id = id(handle._title_label)
    subtitle_id = id(handle._subtitle_label)
    fwd_id = id(handle._fwd_ctx_label)
    handle.show_analysis_for(2)
    assert id(handle._title_label) == title_id
    assert id(handle._subtitle_label) == subtitle_id
    assert id(handle._fwd_ctx_label) == fwd_id
    assert handle._title_label.text == "Conn 2"
    assert "10.0.0.2:50002" in handle._subtitle_label.text


async def test_refresh_context_lines_does_not_touch_figure_cache(user: User, main_handle, tmp_path):
    """rate-unit toggle re-renders the context line label text via
    refresh_context_lines — figure_cache must not be touched."""
    _index, _ = main_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    state = _index.state  # type: ignore[attr-defined]
    state.selected_pcap = tmp_path / "fake.pcap"
    state.stats = [_stats(1)]
    state.analyses = {1: _fake_analyze(1, tmp_path)}
    state.selected_conn = 1
    handle.show_analysis_for(1)
    state.figure_cache = {("sentinel",): object()}
    cache_id = id(state.figure_cache[("sentinel",)])
    state.rate_unit = "bytes"
    handle.refresh_context_lines()
    assert id(state.figure_cache[("sentinel",)]) == cache_id


async def test_refresh_findings_panel_does_not_rebuild_tabs(user: User, main_handle, tmp_path):
    """Findings arrival after the main panel rendered must update only
    the findings html — the tabs slot identity is unchanged."""
    _index, _ = main_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    state = _index.state  # type: ignore[attr-defined]
    state.selected_pcap = tmp_path / "fake.pcap"
    state.stats = [_stats(1)]
    state.analyses = {1: _fake_analyze(1, tmp_path)}
    state.selected_conn = 1
    handle.show_analysis_for(1)
    tabs_slot_id = id(handle._tabs_slot)
    findings_id = id(handle._findings_html)
    # No findings yet — html is empty + hidden.
    assert handle._findings_html.content == ""
    # Findings arrive.
    state.findings[1] = []  # Empty list = no findings panel; non-empty would render.
    handle.refresh_findings_panel(1)
    assert id(handle._tabs_slot) == tabs_slot_id
    assert id(handle._findings_html) == findings_id


async def test_output_controls_built_once_survive_switch(user: User, main_handle, tmp_path):
    """Switching connections does NOT recreate the output buttons or dialog."""
    _index, _ = main_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    state = _index.state  # type: ignore[attr-defined]
    state.selected_pcap = tmp_path / "fake.pcap"
    state.stats = [_stats(1), _stats(2)]
    state.analyses = {1: _fake_analyze(1, tmp_path), 2: _fake_analyze(2, tmp_path)}
    state.selected_conn = 1
    handle.show_analysis_for(1)
    dlg = handle._output_dialog
    btn_slot_id = id(handle._output_btn_slot)
    state.selected_conn = 2
    handle.show_analysis_for(2)
    assert handle._output_dialog is dlg            # same dialog object, content swapped lazily
    assert id(handle._output_btn_slot) == btn_slot_id


async def test_no_show_analysis_at_startup(user: User, main_handle, tmp_path, monkeypatch):
    """Page load with no pcaps must not auto-fire show_analysis_for.
    Pins the startup wiring property; the per-click "show_pending once,
    show_analysis_for once" property is covered end-to-end by the
    cached-conn smoke test in test_app_smoke.py."""
    from tcptrace_ng import app as app_module

    _index, _ = main_handle
    pcap = tmp_path / "fake.pcap"
    pcap.write_bytes(b"")

    show_pending_calls: list[tuple[int, str]] = []
    show_analysis_calls: list[int] = []

    real_build = app_module.view_main.build

    def _instrumented_build(state, **kw):
        h = real_build(state, **kw)
        original_pending = h.show_pending
        original_analysis = h.show_analysis_for

        def _spy_pending(n: int, phase: str) -> None:
            show_pending_calls.append((n, phase))
            original_pending(n, phase)

        def _spy_analysis(n: int) -> None:
            show_analysis_calls.append(n)
            original_analysis(n)

        h.show_pending = _spy_pending
        h.show_analysis_for = _spy_analysis
        return h

    monkeypatch.setattr(app_module.view_main, "build", _instrumented_build)
    monkeypatch.chdir(tmp_path)
    app_module.build_page()
    await user.open("/")
    assert show_analysis_calls == []
    assert show_pending_calls == []
