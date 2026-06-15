"""Tests for view/sidebar.py — smoke + per-row registry reactive contract."""

from __future__ import annotations

import pytest
from nicegui import ui
from nicegui.testing import User

from tcptrace_ng.app import build_page
from tcptrace_ng.classifier import Class
from tcptrace_ng.state import _State
from tcptrace_ng.stats_parser import ConnStats
from tcptrace_ng.view.sidebar import build as build_sidebar


@pytest.fixture
def empty_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


async def test_sidebar_renders_chips_and_filter(user: User, empty_cwd):
    build_page()
    await user.open("/")
    await user.should_see("Bad")
    await user.should_see("RST")
    await user.should_see("Retransmits")
    await user.should_see("filter")


# --- per-row registry contract ---


def _stats(n: int, **kw) -> ConnStats:
    base = {
        "host_a": f"10.0.0.{n}:5000{n}",
        "host_b": f"10.0.0.{n + 100}:443",
        "client_is_a": True,
        "total_bytes": 1000 * n,
        "total_packets": 10,
        "duration_s": 0.1 * n,
        "rexmt_packets": 0,
        "has_rst": False,
        "complete_handshake": True,
        "verdict": Class.NORMAL,
        "fwd_ctx": "",
        "bwd_ctx": "",
    }
    base.update(kw)
    return ConnStats(n=n, **base)


@pytest.fixture
def sidebar_handle(empty_cwd):
    """Build the sidebar inside a fresh NiceGUI page context with three rows.

    Yields (state, _index) where _index has `.handle` attached after the page
    body runs. Tests await `user.open("/")` to trigger the body.
    """
    state = _State()
    state.selected_pcap = empty_cwd / "fake.pcap"

    @ui.page("/")
    def _index():
        handle = build_sidebar(
            state,
            on_conn_click=lambda n: None,
            on_download_zip=lambda: None,
            csum_counts_for_endpoints=lambda a, b: (0, 0),
        )
        state.stats = [_stats(1), _stats(2), _stats(3)]
        handle.populate_rows(state.stats)
        # page body runs on `user.open`; attribute attach is the standard
        # NiceGUI testing escape hatch.
        _index.handle = handle  # type: ignore[attr-defined]

    return state, _index


async def test_populate_rows_bumps_stats_generation(user: User, sidebar_handle):
    state, _index = sidebar_handle
    assert state.stats_generation == 0
    await user.open("/")
    assert state.stats_generation == 1


async def test_refresh_selection_only_mutates_two_rows(user: User, sidebar_handle):
    """Selection change calls .classes() on rows[old] and rows[new] only —
    no other row is touched."""
    _state, _index = sidebar_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    handle.refresh_selection(old=None, new=2)
    assert "tcptrace-conn-selected" not in (handle._rows[1].item._classes or [])
    # _classes is NiceGUI's internal-but-stable attribute; no public API exists.
    assert "tcptrace-conn-selected" in handle._rows[2].item._classes
    assert "tcptrace-conn-selected" not in (handle._rows[3].item._classes or [])
    handle.refresh_selection(old=2, new=3)
    assert "tcptrace-conn-selected" not in handle._rows[2].item._classes
    assert "tcptrace-conn-selected" in handle._rows[3].item._classes


async def test_apply_filter_toggles_row_hidden_without_rebuild(user: User, sidebar_handle):
    state, _index = sidebar_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    pre_ids = {n: id(rh.item) for n, rh in handle._rows.items()}
    state.conn_filter = "10.0.0.2"
    handle.apply_filter("10.0.0.2")
    post_ids = {n: id(rh.item) for n, rh in handle._rows.items()}
    assert pre_ids == post_ids
    assert "row-hidden" in handle._rows[1].item._classes
    assert "row-hidden" not in (handle._rows[2].item._classes or [])
    assert "row-hidden" in handle._rows[3].item._classes


async def test_apply_filter_clear_unhides_all(user: User, sidebar_handle):
    state, _index = sidebar_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    state.conn_filter = "10.0.0.2"
    handle.apply_filter("10.0.0.2")
    state.conn_filter = ""
    handle.apply_filter("")
    for n in (1, 2, 3):
        assert "row-hidden" not in (handle._rows[n].item._classes or [])


async def test_apply_sort_assigns_css_order_no_reorder(user: User, sidebar_handle):
    state, _index = sidebar_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    pre_ids = {n: id(rh.item) for n, rh in handle._rows.items()}
    state.sort_key = "bytes"
    handle.apply_sort("bytes")
    post_ids = {n: id(rh.item) for n, rh in handle._rows.items()}
    assert pre_ids == post_ids
    # bytes desc: conn 3 (3000) > conn 2 (2000) > conn 1 (1000)
    assert "order" in handle._rows[3].item._style
    assert handle._rows[3].item._style["order"] == "0"
    assert handle._rows[2].item._style["order"] == "1"
    assert handle._rows[1].item._style["order"] == "2"


async def test_refresh_row_swaps_one_body(user: User, sidebar_handle):
    state, _index = sidebar_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    other_before = handle._rows[1].body.content
    state.findings[2] = []  # findings arrived; verdict computed
    handle.refresh_row(2)
    assert handle._rows[1].body.content == other_before
    assert "tcptrace-dot-pending" not in handle._rows[2].body.content


async def test_refresh_row_is_noop_for_unknown_n(user: User, sidebar_handle):
    _state, _index = sidebar_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    handle.refresh_row(999)  # no exception


async def test_populate_rows_again_replaces_registry(user: User, sidebar_handle):
    state, _index = sidebar_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    pre_gen = state.stats_generation
    pre_ids = {n: id(rh.item) for n, rh in handle._rows.items()}
    state.stats = [_stats(1), _stats(4)]
    handle.populate_rows(state.stats)
    assert state.stats_generation == pre_gen + 1
    post_ids = {n: id(rh.item) for n, rh in handle._rows.items()}
    assert set(post_ids) == {1, 4}
    assert post_ids[1] != pre_ids[1]


async def test_refresh_count_label_reflects_filter(user: User, sidebar_handle):
    state, _index = sidebar_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    handle.refresh_count_label()
    assert handle.conn_count_label.text == "3 connections"
    state.conn_filter = "10.0.0.2"
    handle.apply_filter("10.0.0.2")
    assert handle.conn_count_label.text == "1 of 3"


async def test_refresh_count_label_analyzing(user: User, sidebar_handle):
    state, _index = sidebar_handle
    state.analyzing = True
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    handle.refresh_count_label()
    assert handle.conn_count_label.text == "analyzing…"


async def test_row_handle_identity_survives_unrelated_intents(user: User, sidebar_handle):
    """Spec test: selection, filter, sort, and content swaps must not allocate
    new _RowHandle objects."""
    state, _index = sidebar_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    before = {n: (id(rh.item), id(rh.body)) for n, rh in handle._rows.items()}
    handle.refresh_selection(None, 2)
    handle.refresh_selection(2, 1)
    state.conn_filter = "10.0.0.3"
    handle.apply_filter("10.0.0.3")
    state.conn_filter = ""
    handle.apply_filter("")
    state.sort_key = "bytes"
    handle.apply_sort("bytes")
    state.findings[2] = []
    handle.refresh_row(2)
    after = {n: (id(rh.item), id(rh.body)) for n, rh in handle._rows.items()}
    assert before == after


async def test_filter_plus_selection_invariant_across_stats_arrival(user: User, sidebar_handle):
    """Spec test: filter and selection state stay consistent when stats refresh
    underneath — selection persists across populate_rows() and the current
    filter is re-applied."""
    state, _index = sidebar_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    state.selected_conn = 2
    state.conn_filter = "10.0.0"
    handle.refresh_selection(None, 2)
    handle.apply_filter("10.0.0")
    handle.populate_rows([_stats(1), _stats(2), _stats(3)])
    assert "tcptrace-conn-selected" in handle._rows[2].item._classes
    for n in (1, 2, 3):
        assert "row-hidden" not in (handle._rows[n].item._classes or [])
    # "10.0.0.1:" targets only conn 1's host_a ("10.0.0.1:50001"); a bare
    # "10.0.0.1" would substring-match conn 2's host_b ("10.0.0.102:443").
    state.conn_filter = "10.0.0.1:"
    handle.apply_filter("10.0.0.1:")
    assert "row-hidden" in handle._rows[2].item._classes
    assert "tcptrace-conn-selected" in handle._rows[2].item._classes


async def test_refresh_row_after_populate_rows_silently_drops_old_n(user: User, sidebar_handle):
    """End-to-end shape of the stale-completion guard: a callback captured
    before populate_rows() runs again must not crash if it calls
    refresh_row(n) for a conn id that's no longer in the rebuilt registry."""
    state, _index = sidebar_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    captured_gen = state.stats_generation
    handle.populate_rows([_stats(99)])  # bumps generation; conn 2 gone
    assert state.stats_generation != captured_gen
    handle.refresh_row(2)  # no exception, no-op
