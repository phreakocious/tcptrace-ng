import asyncio
import importlib
import io
import os
import time
import zipfile
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from nicegui import ui as _ui
from nicegui.testing import User

from tcptrace_ng.app import _format_mtime, _scan_pcaps, build_page, build_xpl_zip
from tcptrace_ng.runner import AnalyzeResult, ConnRow, RunnerError


@pytest.fixture
def empty_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _select_element(user):
    # The page has two ui.select widgets: the pcap picker (header) and the
    # sort dropdown (sidebar). Pick the pcap one by excluding the sort menu.
    for el in user.find(kind=_ui.select).elements:
        values = " ".join(str(v) for v in el.options.values())
        if "sort:" not in values:
            return el
    raise AssertionError("no pcap select element found")


def _conn_items(user):
    return list(user.find(kind=_ui.item).elements)


async def test_page_renders_brand_and_empty_state(user: User, empty_cwd):
    build_page()
    await user.open("/")
    await user.should_see("tcptrace-ng")
    await user.should_see("no pcap files")


async def test_page_shows_no_pcap_message_when_empty(user: User, empty_cwd):
    build_page()
    await user.open("/")
    await user.should_see("no pcap files")


async def test_pcap_picker_lists_available_files(user: User, tmp_path, monkeypatch):
    (tmp_path / "first.pcap").write_bytes(b"")
    (tmp_path / "second.pcap").write_bytes(b"")
    monkeypatch.chdir(tmp_path)
    build_page()
    await user.open("/")
    select = _select_element(user)
    labels = " ".join(str(v) for v in select.options.values())
    assert "first.pcap" in labels
    assert "second.pcap" in labels


async def test_conn_click_renders_classified_text(user: User, tmp_path, monkeypatch):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"")
    monkeypatch.chdir(tmp_path)

    # NiceGUI's user fixture pops tcptrace_ng.app from sys.modules between
    # tests; re-import so build_page() closes over the *current* module
    # whose globals match the patches.
    app_mod = importlib.import_module("tcptrace_ng.app")

    fake_rows = [ConnRow(n=1, host_a="a:1", host_b="b:2", raw_line="  1: a:1 - b:2 (a2b)")]
    fake_result = AnalyzeResult(
        details_text=("    complete conn: yes\n    rexmt data pkts: 3   rexmt data pkts: 0\n"),
        xpl_files=[],
    )

    class _InlineRun:
        @staticmethod
        async def io_bound(fn, *a, **k):
            return fn(*a, **k)

    with (
        patch.object(app_mod, "analyze_all", side_effect=RunnerError("stub")),
        patch.object(app_mod, "list_connections", return_value=fake_rows),
        patch.object(app_mod, "analyze_connection", return_value=fake_result),
        patch.object(app_mod, "run", _InlineRun),
    ):
        app_mod.build_page()
        await user.open("/")

        select = _select_element(user)
        select.set_value(str(pcap))
        await user.should_see("a:1")  # conn row in sidebar

        # NiceGUI Item.on_click wraps the callback in handle_event(), which
        # schedules async callbacks as background tasks. To exercise the
        # full path deterministically without racing the loop, dispatch the
        # registered listener and explicitly await its scheduled task.
        items = _conn_items(user)
        assert items, "expected at least one conn item in sidebar"
        items[0]._handle_event({"listener_id": next(iter(items[0]._event_listeners)), "args": {}})
        # Allow scheduled background tasks (the async _on_conn_click) to run.
        for _ in range(20):
            await asyncio.sleep(0)
            if app_mod.state.selected_conn == 1 and 1 in app_mod.state.analyses:
                break

        # Open the (default-collapsed) tcptrace output expansion to make
        # the classified text visible to the user fixture.
        expansion = next(iter(user.find(kind=_ui.expansion).elements))
        expansion.value = True

        await user.should_see("complete conn: yes")
        await user.should_see("rexmt data pkts: 3")


async def test_cache_size_shown_in_header(user: User, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".tcptrace").mkdir()
    (tmp_path / ".tcptrace" / "blob").write_bytes(b"x" * 4096)
    build_page()
    await user.open("/")
    await user.should_see("4.0 KB")


async def test_clear_cache_button_wipes_directory(user: User, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cache = tmp_path / ".tcptrace" / "p.pcap"
    cache.mkdir(parents=True)
    (cache / "junk").write_bytes(b"x")
    build_page()
    await user.open("/")
    user.find("Clear cache").click()
    await user.should_see("cache: 0 B")
    assert not (tmp_path / ".tcptrace").exists() or not any((tmp_path / ".tcptrace").iterdir())


def test_scan_pcaps_returns_most_recently_modified_first(tmp_path, monkeypatch):
    """Newest pcap on top so users find what they just captured without scrolling."""
    old = tmp_path / "old.pcap"
    mid = tmp_path / "mid.pcapng"
    new = tmp_path / "new.cap"
    old.write_bytes(b"")
    mid.write_bytes(b"")
    new.write_bytes(b"")
    os.utime(old, (1_000_000, 1_000_000))
    os.utime(mid, (2_000_000, 2_000_000))
    os.utime(new, (3_000_000, 3_000_000))

    paths = [p for p, _ in _scan_pcaps(tmp_path)]
    assert paths == [new, mid, old]


def test_scan_pcaps_returns_stat_result_alongside_path(tmp_path):
    """Stat() is called once per pcap so the dropdown can derive size/mtime
    without re-stat'ing each label."""
    p = tmp_path / "x.pcap"
    p.write_bytes(b"abc")
    [(returned_path, returned_stat)] = _scan_pcaps(tmp_path)
    assert returned_path == p
    assert returned_stat.st_size == 3


def test_format_mtime_seconds_minutes_hours_days(tmp_path):
    """Relative-time labels are terse and skim-friendly."""
    p = tmp_path / "x.pcap"
    p.write_bytes(b"")

    now = 1_000_000_000.0

    os.utime(p, (now - 30, now - 30))
    assert _format_mtime(p.stat(), now) == "30s ago"
    os.utime(p, (now - 120, now - 120))
    assert _format_mtime(p.stat(), now) == "2m ago"
    os.utime(p, (now - 3 * 3600, now - 3 * 3600))
    assert _format_mtime(p.stat(), now) == "3h ago"
    os.utime(p, (now - 5 * 86400, now - 5 * 86400))
    assert _format_mtime(p.stat(), now) == "5d ago"


def test_format_mtime_falls_back_to_iso_date_after_a_week(tmp_path):
    p = tmp_path / "x.pcap"
    p.write_bytes(b"")

    now = 1_700_000_000.0
    when = now - 10 * 86400
    os.utime(p, (when, when))
    expected = datetime.fromtimestamp(when, tz=UTC).strftime("%Y-%m-%d")
    assert _format_mtime(p.stat(), now) == expected


def test_format_mtime_clamps_negative_delta_from_clock_skew(tmp_path):
    """Mtime in the future (NTP drift, dual-boot, VM snapshot) must not yield
    a nonsense '-3s ago' label — clamp to 0s ago."""
    p = tmp_path / "x.pcap"
    p.write_bytes(b"")

    now = 1_700_000_000.0
    os.utime(p, (now + 10, now + 10))
    assert _format_mtime(p.stat(), now) == "0s ago"


async def test_pcap_dropdown_includes_relative_mtime(user: User, tmp_path, monkeypatch):
    (tmp_path / "fresh.pcap").write_bytes(b"")
    (tmp_path / "stale.pcap").write_bytes(b"")

    now = time.time()
    os.utime(tmp_path / "fresh.pcap", (now - 60, now - 60))
    os.utime(tmp_path / "stale.pcap", (now - 10 * 86400, now - 10 * 86400))
    monkeypatch.chdir(tmp_path)

    build_page()
    await user.open("/")
    select = _select_element(user)
    fresh_label = next(v for k, v in select.options.items() if "fresh.pcap" in str(v))
    stale_label = next(v for k, v in select.options.items() if "stale.pcap" in str(v))
    assert "ago" in fresh_label
    assert "2026" in stale_label or "2025" in stale_label
    # Most-recent-first ordering preserved in the dropdown.
    ordered = list(select.options.values())
    assert ordered.index(fresh_label) < ordered.index(stale_label)


def test_build_xpl_zip_packs_xpl_files(tmp_path):
    xpl = tmp_path / "conn-1--a2b_tsg.xpl"
    xpl.write_text("go\n")
    blob = build_xpl_zip({1: AnalyzeResult(details_text="x", xpl_files=[xpl])})
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        assert "conn-1/conn-1--a2b_tsg.xpl" in zf.namelist()


async def test_pcap_switch_clears_analysis_state(user: User, tmp_path, monkeypatch):
    """Switching pcaps clears in-memory analyses, selection, and listing."""
    pcap_a = tmp_path / "a.pcap"
    pcap_b = tmp_path / "b.pcap"
    pcap_a.write_bytes(b"")
    pcap_b.write_bytes(b"")
    monkeypatch.chdir(tmp_path)

    app_mod = importlib.import_module("tcptrace_ng.app")

    rows_a = [ConnRow(n=1, host_a="a:1", host_b="b:2", raw_line="  1: a:1 - b:2 (a2b)")]
    rows_b = [ConnRow(n=9, host_a="x:1", host_b="y:2", raw_line="  9: x:1 - y:2 (a2b)")]

    def fake_list(pcap, timeout=60.0):
        return rows_a if pcap.name == "a.pcap" else rows_b

    with (
        patch.object(app_mod, "analyze_all", side_effect=RunnerError("stub")),
        patch.object(app_mod, "list_connections", side_effect=fake_list),
    ):
        app_mod.build_page()
        await user.open("/")

        select = _select_element(user)
        select.set_value(str(pcap_a))
        await user.should_see("a:1")
        app_mod.state.analyses = {1: AnalyzeResult(details_text="prior", xpl_files=[])}
        app_mod.state.selected_conn = 1
        assert app_mod.state.selected_pcap == pcap_a

        select.set_value(str(pcap_b))
        await user.should_see("x:1")
        assert app_mod.state.analyses == {}
        assert app_mod.state.selected_conn is None
        assert app_mod.state.selected_pcap == pcap_b
        assert [r.n for r in app_mod.state.stats] == [9]


async def test_on_pick_falls_back_to_pcap_conversion(user: User, tmp_path, monkeypatch):
    """list_connections raising RunnerError triggers try_convert_to_pcap."""
    cap = tmp_path / "weird.cap"
    cap.write_bytes(b"")
    converted = tmp_path / "weird.cap.pcap"
    monkeypatch.chdir(tmp_path)

    app_mod = importlib.import_module("tcptrace_ng.app")

    converted_rows = [ConnRow(n=1, host_a="a:1", host_b="b:2", raw_line="  1: a:1 - b:2 (a2b)")]

    call_log: list[str] = []

    def fake_list(pcap, timeout=60.0):
        call_log.append(f"list:{pcap.name}")
        if pcap == cap:
            raise RunnerError("not a pcap")
        return converted_rows

    def fake_convert(pcap, timeout=60.0):
        call_log.append(f"convert:{pcap.name}")
        converted.write_bytes(b"")
        return converted

    with (
        patch.object(app_mod, "analyze_all", side_effect=RunnerError("stub")),
        patch.object(app_mod, "list_connections", side_effect=fake_list),
        patch.object(app_mod, "try_convert_to_pcap", side_effect=fake_convert),
    ):
        app_mod.build_page()
        await user.open("/")

        select = _select_element(user)
        select.set_value(str(cap))
        await user.should_see("a:1")

        assert "list:weird.cap" in call_log
        assert "convert:weird.cap" in call_log
        assert "list:weird.cap.pcap" in call_log
        assert app_mod.state.selected_pcap == converted
        assert [r.n for r in app_mod.state.stats] == [1]


async def test_on_pick_surfaces_error_when_conversion_also_fails(user: User, tmp_path, monkeypatch):
    """When conversion also fails, the original list_connections error is surfaced."""
    cap = tmp_path / "broken.cap"
    cap.write_bytes(b"")
    monkeypatch.chdir(tmp_path)

    app_mod = importlib.import_module("tcptrace_ng.app")

    def fake_list(pcap, timeout=60.0):
        raise RunnerError("not a pcap")

    def fake_convert(pcap, timeout=60.0):
        raise RunnerError("editcap missing")

    with (
        patch.object(app_mod, "analyze_all", side_effect=RunnerError("stub")),
        patch.object(app_mod, "list_connections", side_effect=fake_list),
        patch.object(app_mod, "try_convert_to_pcap", side_effect=fake_convert),
    ):
        app_mod.build_page()
        await user.open("/")

        select = _select_element(user)
        select.set_value(str(cap))

        # Wait for the async pick handler to flush. should_see polls.
        await user.should_see("click a connection")

        assert app_mod.state.stats == []
        assert app_mod.state.selected_pcap == cap
