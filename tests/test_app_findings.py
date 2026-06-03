"""Unit tests for the Finding UI helpers (pure, no running NiceGUI server)."""

from __future__ import annotations

import tcptrace_ng.app as app_mod
from tcptrace_ng.app import _findings_panel_html, _issue_summary, _warn_badge_html
from tcptrace_ng.classifier import Class
from tcptrace_ng.diagnose import Finding
from tcptrace_ng.runner import AnalyzeResult, ConnRow
from tcptrace_ng.stats_parser import ConnStats


def _f(severity, code="x", scope="conn", headline="h", detail="d"):
    return Finding(code=code, severity=severity, scope=scope, headline=headline, detail=detail)


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


def test_state_initializes_findings_dict():
    from tcptrace_ng.app import _State

    assert _State().findings == {}


def _connstats(n=1, **kw):
    base = {
        "n": n,
        "host_a": "10.0.0.1:50000",
        "host_b": "10.0.0.2:443",
        "client_is_a": True,
        "total_bytes": 4000,
        "total_packets": 14,
        "duration_s": 0.2,
        "rexmt_packets": 0,
        "has_rst": False,
        "complete_handshake": True,
        "verdict": Class.NORMAL,
        "fwd_ctx": "",
        "bwd_ctx": "",
    }
    base.update(kw)
    return ConnStats(**base)


def test_compute_findings_capture_vantage_from_stats_when_no_xpl(monkeypatch):
    # No xpl -> tsg is None -> only stats-based detectors run (capture_vantage).
    monkeypatch.setattr(app_mod.state, "stats", [_connstats(rtt_3whs_a=80.0, rtt_3whs_b=0.1)])
    monkeypatch.setattr(
        app_mod.state, "analyses", {1: AnalyzeResult(details_text="", xpl_files=[])}
    )
    out = app_mod._compute_findings(1)
    assert [f.code for f in out] == ["capture_vantage"]


def test_compute_findings_empty_when_conn_not_analyzed(monkeypatch):
    monkeypatch.setattr(app_mod.state, "stats", [])
    monkeypatch.setattr(app_mod.state, "analyses", {})
    assert app_mod._compute_findings(99) == []


def test_compute_findings_none_stats_for_connrow(monkeypatch):
    # A stats-less ConnRow (basic listing) -> stats=None; with no xpl -> tsg=None
    # -> diagnose(None, None, None) returns [] without crashing.
    monkeypatch.setattr(
        app_mod.state,
        "stats",
        [ConnRow(n=1, host_a="a:1", host_b="b:2", raw_line="  1: a:1 - b:2 (a2b)")],
    )
    monkeypatch.setattr(
        app_mod.state, "analyses", {1: AnalyzeResult(details_text="", xpl_files=[])}
    )
    assert app_mod._compute_findings(1) == []
