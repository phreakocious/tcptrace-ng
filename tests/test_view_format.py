"""Tests for view/format.py — pure formatters and HTML builders."""

from __future__ import annotations

from tcptrace_ng.classifier import Class
from tcptrace_ng.diagnose import Finding
from tcptrace_ng.view.format import (
    _desegment_banner_text,
    _findings_panel_html,
    _format_throughput_Bps,
    _issue_summary,
    _phase_label_text,
    _stats_grid_html,
    _verdict_dot_class,
    _warn_badge_html,
)


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
