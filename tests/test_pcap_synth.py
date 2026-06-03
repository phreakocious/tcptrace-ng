# tests/test_pcap_synth.py
"""The synthetic builder must produce a flow the real tcptrace parses cleanly."""

from __future__ import annotations

import shutil

import pytest

from tcptrace_ng.csum import scan_pcap
from tcptrace_ng.runner import analyze_all
from tests.pcap_synth import TcpFlow

pytestmark = pytest.mark.skipif(
    shutil.which("tcptrace") is None
    and not __import__(
        "tcptrace_ng.runner", fromlist=["_VENDORED_TCPTRACE"]
    )._VENDORED_TCPTRACE.is_file(),
    reason="tcptrace binary not available",
)


def _simple_flow(path):
    fl = TcpFlow()
    t = fl.handshake(0.0, rtt=0.080)  # client vantage: a->b 3WHS ~80ms
    fl.send(t + 0.0001, "c", 50)  # request
    fl.ack(t + 0.080, "s")  # server acks request 80ms later
    seq_t = t + 0.080
    for _ in range(3):
        fl.send(seq_t, "s", 1448)  # response segments
        fl.ack(seq_t + 0.0001, "c")
        seq_t += 0.0005
    fl.fin(seq_t + 0.001, "s")
    fl.fin(seq_t + 0.082, "c")
    fl.write(path)


def test_builder_flow_is_checksum_clean(tmp_path):
    p = tmp_path / "f.pcap"
    _simple_flow(p)
    assert scan_pcap(p) == []  # dpkt computed correct checksums


def test_builder_flow_parses_as_one_complete_conn(tmp_path):
    p = tmp_path / "f.pcap"
    _simple_flow(p)
    conns = analyze_all(p, with_rtt=True, no_dns=True)
    assert len(conns) == 1
    assert conns[0].complete_handshake is True
    assert conns[0].mss_a == 1460 and conns[0].wscale_a == 7


def test_pipeline_returns_findings_list(tmp_path):
    # Smoke test of the pipeline plumbing only (diagnose has no detectors wired
    # yet); detection behavior is covered in test_diagnose_e2e.py (Tasks 5-6).
    from tests.diag_pipeline import run_pipeline

    p = tmp_path / "f.pcap"
    _simple_flow(p)
    findings = run_pipeline(p)
    assert isinstance(findings, list)
