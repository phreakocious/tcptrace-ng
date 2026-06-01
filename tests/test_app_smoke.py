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

        # Open the raw-output dialog via its sticky-header button so the
        # classified text becomes visible to the user fixture (the dialog is
        # in the DOM from initial render but Quasar hides it until opened).
        user.find("tcptrace output", kind=_ui.button).click()

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


async def test_toggling_no_dns_reanalyzes_with_n_flag(user: User, tmp_path, monkeypatch):
    """Flipping the 'no DNS' checkbox re-runs analyze_all with no_dns=True so
    tcptrace's own `-n` flag is propagated through."""
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"")
    monkeypatch.chdir(tmp_path)

    app_mod = importlib.import_module("tcptrace_ng.app")

    calls: list[bool] = []

    def fake_analyze_all(pcap, timeout=60.0, *, no_dns=False, **_kw):
        calls.append(no_dns)
        raise RunnerError("stub")  # bail to fallback path; we only care about kwargs

    def fake_list(pcap, timeout=60.0, **_kw):
        return [ConnRow(n=1, host_a="a:1", host_b="b:2", raw_line="  1: a:1 - b:2 (a2b)")]

    with (
        patch.object(app_mod, "analyze_all", side_effect=fake_analyze_all),
        patch.object(app_mod, "list_connections", side_effect=fake_list),
    ):
        app_mod.build_page()
        await user.open("/")

        select = _select_element(user)
        select.set_value(str(pcap))
        await user.should_see("a:1")
        assert calls == [False]  # first analyze: no_dns default off

        # Find the "no DNS" checkbox via its label and flip it.
        no_dns = next(
            c for c in user.find(kind=_ui.checkbox).elements if c.text == "no DNS"
        )
        no_dns.set_value(True)
        # Allow the async analyze handler (scheduled off the value-change event)
        # to flush before asserting.
        for _ in range(20):
            await asyncio.sleep(0)
            if len(calls) >= 2:
                break
        # Second analyze ran with no_dns=True.
        assert len(calls) >= 2, f"expected re-analyze on toggle, got calls={calls}"
        assert calls[-1] is True
        # And the in-memory state reflects the toggle.
        assert app_mod.state.no_dns is True


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

    def fake_list(pcap, timeout=60.0, **_kw):
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

    def fake_list(pcap, timeout=60.0, **_kw):
        call_log.append(f"list:{pcap.name}")
        if pcap == cap:
            raise RunnerError("not a pcap")
        return converted_rows

    def fake_convert(pcap, timeout=60.0, **_kw):
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

    def fake_list(pcap, timeout=60.0, **_kw):
        raise RunnerError("not a pcap")

    def fake_convert(pcap, timeout=60.0, **_kw):
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


async def test_picking_geneve_pcap_triggers_decap(user: User, tmp_path, monkeypatch):
    """A pcap with Geneve outer frames is auto-decapped; the runner gets the
    decap'd copy, and state.decap_encaps records what was stripped."""
    import struct

    import dpkt

    monkeypatch.chdir(tmp_path)
    pcap = tmp_path / "geneve.pcap"

    # Build one Geneve-wrapped frame: outer Ethernet + IPv4 + UDP/6081 +
    # Geneve(TEB) + inner Ethernet + IPv4 + TCP.
    inner_tcp = dpkt.tcp.TCP(sport=12345, dport=80, seq=1, ack=0, off_x2=0x50, flags=0x02)
    inner_ip = dpkt.ip.IP(
        src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02",
        p=dpkt.ip.IP_PROTO_TCP, data=bytes(inner_tcp),
    )
    inner_ip.len = 40
    inner_eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55", dst=b"\xaa\xbb\xcc\xdd\xee\xff",
        type=0x0800, data=bytes(inner_ip),
    )
    geneve = struct.pack("!BBH", 0x00, 0x00, 0x6558) + b"\x00\x00\x00\x00"
    outer_udp = dpkt.udp.UDP(sport=33333, dport=6081, data=geneve + bytes(inner_eth))
    outer_udp.ulen = 8 + len(outer_udp.data)
    outer_ip = dpkt.ip.IP(
        src=b"\xc0\xa8\x01\x01", dst=b"\xc0\xa8\x01\x02",
        p=dpkt.ip.IP_PROTO_UDP, data=bytes(outer_udp),
    )
    outer_ip.len = 20 + 8 + len(outer_udp.data)
    outer_eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x00\x00\x00\x00\x01", dst=b"\x00\x00\x00\x00\x00\x02",
        type=0x0800, data=bytes(outer_ip),
    )
    with pcap.open("wb") as f:
        w = dpkt.pcap.Writer(f, linktype=1)
        w.writepkt(bytes(outer_eth), ts=1000.0)

    app_mod = importlib.import_module("tcptrace_ng.app")

    seen_paths: list = []

    def fake_analyze_all(p, timeout=60.0, **_kw):
        seen_paths.append(p)
        raise RunnerError("stub")

    def fake_list(p, timeout=60.0, **_kw):
        seen_paths.append(p)
        return [ConnRow(n=1, host_a="a:1", host_b="b:2", raw_line="  1: a:1 - b:2 (a2b)")]

    with (
        patch.object(app_mod, "analyze_all", side_effect=fake_analyze_all),
        patch.object(app_mod, "list_connections", side_effect=fake_list),
    ):
        app_mod.build_page()
        await user.open("/")
        select = _select_element(user)
        select.set_value(str(pcap))
        await user.should_see("a:1")

        assert app_mod.state.decap_encaps == {"geneve"}
        assert app_mod.state.effective_pcap != pcap
        assert app_mod.state.effective_pcap.name == "decap.pcap"
        # Every runner call should have been fed the decap'd copy, not the source.
        assert seen_paths, "runner was never invoked"
        for p in seen_paths:
            assert p == app_mod.state.effective_pcap, f"runner got {p}, not decap path"
