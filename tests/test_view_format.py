"""Tests for view/format.py — pure formatters and HTML builders."""

from __future__ import annotations

from tcptrace_ng.classifier import Class
from tcptrace_ng.diagnose import Finding
from tcptrace_ng.runner import ConnRow
from tcptrace_ng.stats_parser import ConnStats
from tcptrace_ng.view.format import (
    _build_conn_list_html,
    _conn_filter_js,
    _conn_flags,
    _conn_search_text,
    _conn_select_js,
    _conn_set_row_js,
    _conn_sort_js,
    _desegment_banner_text,
    _escape_attr,
    _findings_panel_html,
    _format_throughput_Bps,
    _issue_summary,
    _matches_chips,
    _matches_filter,
    _output_dialog_html,
    _phase_label_text,
    _stats_grid_html,
    _verdict_dot_class,
    _warn_badge_html,
)


def _cs(n=1, **kw):
    # unidirectional is a @property derived from pkts_a/pkts_b, not a ctor field;
    # translate the convenience kwarg before constructing.
    kw = dict(kw)
    if "unidirectional" in kw:
        if kw.pop("unidirectional"):
            kw.setdefault("pkts_b", 0)
        else:
            kw.setdefault("pkts_a", 10)
            kw.setdefault("pkts_b", 10)
    base = {
        "host_a": f"10.0.0.{n}:5000{n}",
        "host_b": f"10.0.0.{n + 100}:443",
        "client_is_a": True,
        "total_bytes": 1000,
        "total_packets": 10,
        "duration_s": 0.1,
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


def test_conn_search_text_has_number_and_both_hosts():
    t = _conn_search_text(_cs(2))
    assert "2" in t and "10.0.0.2:50002" in t and "10.0.0.102:443" in t


def test_conn_flags_empty_for_clean_stats():
    assert _conn_flags(_cs(1)) == set()


def test_conn_flags_collects_each_condition():
    row = _cs(1, has_rst=True, rexmt_packets=3, complete_handshake=False,
              unidirectional=True, verdict=Class.BAD, total_bytes=200_000)
    assert _conn_flags(row) == {"rst", "rexmt", "incomplete", "uni", "bad", "bulk"}


def test_conn_flags_bulk_threshold_is_100k():
    assert "bulk" not in _conn_flags(_cs(1, total_bytes=100 * 1024 - 1))
    assert "bulk" in _conn_flags(_cs(1, total_bytes=100 * 1024))


def test_matches_chips_is_subset_of_flags():
    row = _cs(1, has_rst=True)
    assert _matches_chips(row, set())
    assert _matches_chips(row, {"rst"})
    assert not _matches_chips(row, {"rst", "uni"})


def test_conn_flags_empty_for_stats_less_row():
    row = ConnRow(n=1, host_a="10.0.0.1:1234", host_b="10.0.0.2:443", raw_line="  1: 10.0.0.1:1234 - 10.0.0.2:443 (a2b)")
    assert _conn_flags(row) == set()
    assert not _matches_chips(row, {"rst"})


def test_matches_filter_substring_case_insensitive():
    row = _cs(2)
    assert _matches_filter(row, "")
    assert _matches_filter(row, "10.0.0.2")
    assert _matches_filter(row, "443")
    assert not _matches_filter(row, "zzz")


def _f(severity, code="x", scope="conn", headline="h", detail="d"):
    return Finding(code=code, severity=severity, scope=scope, headline=headline, detail=detail)


def test_throughput_bytes_rate_uses_si_matching_chart():
    """L8: byte-mode throughput rates use SI (1000) prefixes — matching the
    chart's d3 '.3s' axis and the bits-mode formatter — not binary (1024), which
    made the same flow read '1.5 MB/s' on the chart but '1.4 MB/s' in the grid."""
    assert _format_throughput_Bps(1_500_000) == "1.5 MB/s"  # SI; binary would be 1.4
    assert _format_throughput_Bps(1_500_000_000) == "1.50 GB/s"  # SI; binary would be 1.40


def test_verdict_dot_class_pending_when_not_computed():
    """H5: a connection whose findings aren't computed yet (lazy, on open) gets
    a pending dot (None) — never the legacy line-color classifier, which flags
    BAD on benign captures and contradicts the findings panel."""
    assert _verdict_dot_class(None) is None


def test_verdict_dot_class_clean_when_computed_no_findings():
    assert _verdict_dot_class([]) == Class.NORMAL


def test_verdict_dot_class_bad_from_findings():
    assert _verdict_dot_class([_f("bad"), _f("interesting")]) == Class.BAD


def test_verdict_dot_class_look_when_only_interesting():
    assert _verdict_dot_class([_f("interesting")]) == Class.LOOK


def test_verdict_dot_class_good_when_only_good_finding():
    assert _verdict_dot_class([_f("good")]) == Class.GOOD


def test_issue_summary_none_when_no_issues():
    assert _issue_summary([]) is None
    assert _issue_summary([_f("good")]) is None


def test_issue_summary_counts_interesting_and_bad_excludes_good():
    assert _issue_summary([_f("interesting"), _f("bad"), _f("good")]) == (2, Class.BAD)


def test_issue_summary_worst_is_look_when_only_interesting():
    assert _issue_summary([_f("interesting"), _f("interesting")]) == (2, Class.LOOK)


def test_warn_badge_html_blank_when_no_issues():
    assert _warn_badge_html([]) == ""
    assert _warn_badge_html([_f("good")]) == ""


def test_warn_badge_html_bad_is_red_with_count():
    html = _warn_badge_html([_f("bad"), _f("interesting")])
    assert "conn-warn-bad" in html
    assert "⚠2" in html


def test_warn_badge_html_interesting_is_look():
    html = _warn_badge_html([_f("interesting")])
    assert "conn-warn-look" in html
    assert "⚠1" in html


def test_findings_panel_html_blank_when_empty():
    assert _findings_panel_html([], "c→s", "s→c") == ""


def test_findings_panel_html_renders_headline_detail_scope_and_dot():
    f = _f(
        "bad",
        code="loss_storm",
        scope="a2b",
        headline="High retransmission rate",
        detail="18 of 120 segs",
    )
    html = _findings_panel_html([f], "client→server", "server→client")
    assert "tcptrace-findings" in html
    assert "High retransmission rate" in html
    assert "18 of 120 segs" in html
    assert "client→server" in html
    assert "tcptrace-dot-bad" in html


def test_findings_panel_html_conn_scope_label_and_escaping():
    f = _f("good", scope="conn", headline="A <b> & C", detail="d")
    html = _findings_panel_html([f], "", "")
    assert ">conn<" in html
    assert "&lt;b&gt;" in html
    assert "&amp;" in html
    assert "tcptrace-dot-good" in html


def test_findings_panel_html_b2a_uses_bwd_label_with_fallback():
    f = _f("interesting", scope="b2a", headline="rev finding")
    assert "server→client" in _findings_panel_html([f], "client→server", "server→client")
    # Empty bwd_label falls back to the default direction glyph.
    assert "b→a" in _findings_panel_html([f], "", "")


def test_desegment_banner_text_reflects_manifest():
    kinds = {"lro/gro/tso"}
    coalesces = [{"pieces": 6}, {"pieces": 6}]
    txt = _desegment_banner_text(kinds, coalesces)
    assert txt is not None and "2 offload frames" in txt and "12 segments" in txt


def test_desegment_banner_text_none_without_offload():
    assert _desegment_banner_text(set(), []) is None


def test_stats_grid_shows_reconstructed_count():
    from tcptrace_ng.tcp_inspect import Segment, TsgModel

    m = TsgModel(
        segments=[
            Segment(1.0, 0, 1460, None, None, None, 0, True),
            Segment(2.0, 1460, 2920, None, None, None, 0, False),
        ]
    )
    html = _stats_grid_html("a→b", m.window_stats(None, None))
    assert "reconstructed" in html


def test_build_conn_row_html_connstats_includes_badges_findings_and_hosts():
    from tcptrace_ng.stats_parser import ConnStats
    from tcptrace_ng.view.format import _build_conn_row_html

    stats = ConnStats(
        n=7,
        host_a="10.0.0.1:50000",
        host_b="10.0.0.2:443",
        client_is_a=True,
        total_bytes=4096,
        total_packets=14,
        duration_s=0.5,
        rexmt_packets=0,
        has_rst=False,
        complete_handshake=True,
        verdict=Class.NORMAL,
        fwd_ctx="",
        bwd_ctx="",
    )
    html = _build_conn_row_html(stats, badges_str="FIN", findings=[_f("interesting")])
    assert "10.0.0.1:50000" in html
    assert "10.0.0.2:443" in html
    assert ">7<" in html  # conn number
    assert "FIN" in html  # badges injected verbatim
    assert "⚠1" in html  # findings drive warn badge
    assert "tcptrace-dot-look" in html  # findings drive dot


def test_build_conn_row_html_connrow_fallback_is_minimal():
    from tcptrace_ng.runner import ConnRow
    from tcptrace_ng.view.format import _build_conn_row_html

    row = ConnRow(n=3, host_a="a:1", host_b="b:2", raw_line="  3: a:1 - b:2 (a2b)")
    html = _build_conn_row_html(row, badges_str="", findings=[])
    assert ">3<" in html
    assert "a:1" in html
    assert "b:2" in html
    assert "conn-meta-top" not in html
    assert "conn-meta-bot" not in html


def test_phase_label_text_each_phase():
    assert _phase_label_text(42, "analyzing") == "analyzing connection 42"
    assert _phase_label_text(42, "synthesizing") == "synthesizing time-sequence model"
    assert _phase_label_text(42, "diagnosing") == "computing diagnostics"


def test_phase_label_text_unknown_phase_falls_back_to_analyzing():
    assert _phase_label_text(7, "wat") == "analyzing connection 7"


def test_escape_attr_escapes_quote_and_amp():
    assert _escape_attr('a"&<b') == "a&quot;&amp;&lt;b"


def test_build_conn_list_html_one_div_per_row_with_attrs():
    rows = [_cs(1), _cs(2, has_rst=True)]
    html = _build_conn_list_html(
        rows, selected_n=2,
        badges_map={1: "FIN", 2: "RST FIN"},
        findings_map={1: [], 2: []},
        order_map={1: 0, 2: 1},
    )
    assert html.startswith('<div class="tcptrace-conn-flex">')
    assert 'data-n="1"' in html and 'data-n="2"' in html
    assert 'class="tcptrace-conn-row tcptrace-conn-selected" data-n="2"' in html
    assert 'class="tcptrace-conn-row" data-n="1"' in html
    assert 'data-flags="rst"' in html
    assert 'style="order:1"' in html and 'style="order:0"' in html
    assert 'data-text="2 10.0.0.2:50002 10.0.0.102:443"' in html


def test_filter_js_json_encodes_args():
    assert _conn_filter_js("ab", {"rst"}) == \
        'window.ttConnList && window.ttConnList.filter("ab", ["rst"])'


def test_filter_js_escapes_quotes():
    assert '"a\\"b"' in _conn_filter_js('a"b', set())


def test_sort_js_lists_order():
    assert _conn_sort_js([3, 2, 1]) == \
        "window.ttConnList && window.ttConnList.sort([3, 2, 1])"


def test_select_js_uses_null_for_none():
    assert _conn_select_js(None, 2) == \
        "window.ttConnList && window.ttConnList.select(null, 2)"


def test_set_row_js_encodes_html():
    out = _conn_set_row_js(2, "<b>x</b>")
    assert out.startswith("window.ttConnList && window.ttConnList.setRow(2, ")
    assert '"<b>x</b>"' in out


def test_output_dialog_html_hides_only_suppressed_lines_unless_debug():
    # "urgent data" matches classifier._SUPPRESS (classify -> None); "plain line"
    # is unrecognized -> Class.NORMAL. The original dialog hides only suppressed
    # lines in non-debug and always shows NORMAL/colored lines.
    text = "urgent data\nplain line\n"
    banner, pre = _output_dialog_html(
        text, debug=False, desegment_kinds=set(), desegment_coalesces=[]
    )
    assert banner == ""
    assert "urgent data" not in pre
    assert "plain line" in pre
    _, pre_dbg = _output_dialog_html(
        text, debug=True, desegment_kinds=set(), desegment_coalesces=[]
    )
    assert "urgent data" in pre_dbg
