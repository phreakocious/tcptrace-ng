"""Tests for view/sidebar.py — smoke + single-blob render contract.

The conn list is now one HTML blob; per-row reactivity is client-side JS
(verified by running the app). These tests cover the server-observable
surface: the generated blob and the count label.
"""

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
        "pkts_a": 10,
        "pkts_b": 10,
        "verdict": Class.NORMAL,
        "fwd_ctx": "",
        "bwd_ctx": "",
    }
    base.update(kw)
    return ConnStats(n=n, **base)


@pytest.fixture
def sidebar_handle(empty_cwd):
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
        state.stats = [_stats(1), _stats(2, has_rst=True), _stats(3)]
        handle.populate_rows(state.stats)
        _index.handle = handle  # type: ignore[attr-defined]

    return state, _index


async def test_populate_bumps_generation_and_renders_rows(user: User, sidebar_handle):
    state, _index = sidebar_handle
    assert state.stats_generation == 0
    await user.open("/")
    assert state.stats_generation == 1
    html = _index.handle.conn_list_html.content  # type: ignore[attr-defined]
    assert html.startswith('<div class="tcptrace-conn-flex">')
    for n in (1, 2, 3):
        assert f'data-n="{n}"' in html


async def test_populate_bakes_flags_and_order_and_selection(user: User, sidebar_handle):
    state, _index = sidebar_handle
    state.selected_conn = 2
    state.sort_key = "bytes"  # 3(3000) > 2(2000) > 1(1000)
    await user.open("/")
    html = _index.handle.conn_list_html.content  # type: ignore[attr-defined]
    assert 'class="tcptrace-conn-row tcptrace-conn-selected" data-n="2"' in html
    assert 'data-flags="rst"' in html
    assert 'data-n="3"' in html and "order:0" in html


async def test_populate_empty_when_no_pcap(user: User, sidebar_handle):
    state, _index = sidebar_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    state.selected_pcap = None
    handle.populate_rows([])
    assert handle.conn_list_html.content == ""


async def test_apply_filter_updates_count_label(user: User, sidebar_handle):
    state, _index = sidebar_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    handle.refresh_count_label()
    assert handle.conn_count_label.text == "3 connections"
    state.conn_filter = "10.0.0.2"
    handle.apply_filter("10.0.0.2")
    assert handle.conn_count_label.text == "1 of 3"
    handle.apply_filter("")
    assert handle.conn_count_label.text == "3 connections"


async def test_count_label_analyzing(user: User, sidebar_handle):
    state, _index = sidebar_handle
    state.analyzing = True
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    handle.refresh_count_label()
    assert handle.conn_count_label.text == "analyzing…"


async def test_interactive_methods_do_not_raise(user: User, sidebar_handle):
    state, _index = sidebar_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    handle.refresh_selection(None, 2)
    handle.apply_sort("bytes")
    state.findings[2] = []
    handle.refresh_row(2)
    handle.refresh_row(999)
    handle.refresh_all_rows()


async def test_populate_again_replaces_blob(user: User, sidebar_handle):
    state, _index = sidebar_handle
    await user.open("/")
    handle = _index.handle  # type: ignore[attr-defined]
    pre_gen = state.stats_generation
    state.stats = [_stats(1), _stats(4)]
    handle.populate_rows(state.stats)
    assert state.stats_generation == pre_gen + 1
    html = handle.conn_list_html.content
    assert 'data-n="4"' in html and 'data-n="2"' not in html
