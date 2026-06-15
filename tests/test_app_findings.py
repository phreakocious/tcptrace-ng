"""Unit tests for the Finding UI helpers (pure, no running NiceGUI server)."""

from __future__ import annotations

import tcptrace_ng.app as app_mod
from tcptrace_ng.classifier import Class
from tcptrace_ng.runner import AnalyzeResult, ConnRow
from tcptrace_ng.stats_parser import ConnStats


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


def test_coalesces_directed_filters_by_direction(monkeypatch):
    monkeypatch.setattr(
        app_mod.state,
        "desegment_coalesces",
        [
            {
                "time": 1.0,
                "src": "10.0.0.2:443",
                "dst": "10.0.0.1:50000",
                "parent_seq_start": 1,
                "parent_seq_end": 2,
                "pieces": 1,
                "mss": 1460,
                "mss_source": "syn",
            },
            {
                "time": 2.0,
                "src": "10.0.0.9:80",
                "dst": "10.0.0.1:50000",
                "parent_seq_start": 1,
                "parent_seq_end": 2,
                "pieces": 1,
                "mss": 1460,
                "mss_source": "syn",
            },
        ],
    )
    got = app_mod._coalesces_directed("10.0.0.2:443", "10.0.0.1:50000")
    assert len(got) == 1 and got[0]["time"] == 1.0
    # reverse direction must not match (the manifest is directional)
    assert app_mod._coalesces_directed("10.0.0.1:50000", "10.0.0.2:443") == []
