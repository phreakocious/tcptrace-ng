from dataclasses import dataclass
from pathlib import Path

from tcptrace_ng.cache import CacheLayout
from tcptrace_ng.reorder import classify
from tcptrace_ng.reorder_pipeline import ReorderSummary, bootstrap_rtt, reorder_source_pcap, summarize_spans, ReorderResult, classify_connection_pure
from tests.pcap_synth import TcpFlow

A, B = "10.0.0.1:50000", "10.0.0.2:443"


def test_source_prefers_decap_when_present(tmp_path):
    decap = tmp_path / "decap.pcap"
    decap.write_bytes(b"\xd4\xc3\xb2\xa1")  # any non-empty file => "exists"
    selected = tmp_path / "orig.pcap"
    selected.write_bytes(b"\xd4\xc3\xb2\xa1")
    assert reorder_source_pcap(decap, selected) == decap


def test_source_falls_back_to_selected_when_no_decap(tmp_path):
    decap = tmp_path / "decap.pcap"          # never created => no encapsulation
    selected = tmp_path / "orig.pcap"
    selected.write_bytes(b"\xd4\xc3\xb2\xa1")
    assert reorder_source_pcap(decap, selected) == selected


@dataclass(frozen=True)
class _FakeStats:
    rtt_3whs_a: float | None = None
    rtt_3whs_b: float | None = None
    rtt_avg_a: float | None = None
    rtt_avg_b: float | None = None


def test_bootstrap_rtt_prefers_3whs_mean_in_seconds():
    s = _FakeStats(rtt_3whs_a=10.0, rtt_3whs_b=30.0, rtt_avg_a=100.0)
    assert bootstrap_rtt(s) == 0.020          # mean(10,30) ms = 20 ms = 0.020 s


def test_bootstrap_rtt_falls_back_to_tcptrace_r_avg():
    s = _FakeStats(rtt_avg_a=40.0, rtt_avg_b=60.0)
    assert bootstrap_rtt(s) == 0.050          # mean(40,60) ms = 50 ms


def test_bootstrap_rtt_none_when_nothing_known():
    assert bootstrap_rtt(_FakeStats()) is None
    assert bootstrap_rtt(None) is None


def test_summary_counts_bytes_by_copy_status(tmp_path):
    # in-order original [1001,2001) then an overlapping resend [1001,2001).
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, _hi = f.send(t, "c", 1000)
    f.retransmit(t + 0.05, "c", lo, 1000)              # overlaps => retransmission, byte-certain
    spans = [s for s in classify(f.write(tmp_path / "s.pcap").read_bytes(), A, B) if s.src == A]
    summ = summarize_spans(spans)
    assert isinstance(summ, ReorderSummary)
    assert summ.original_bytes == 1000
    assert summ.retransmit_bytes == 1000
    assert summ.max_tier == "hi"                       # overlaps retransmission floors hi
    assert summ.n_spans == len(spans)


def test_summary_counts_spurious_and_episodes(tmp_path):
    # gap-open at [2001,3001) (opens_gap) + an already_had spurious resend.
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, hi = f.send(t, "c", 1000)                      # [1001,2001)
    f.ack(t + 0.02, "s", cumack=hi)
    f.retransmit(t + 0.30, "c", lo, 1000)             # already_had spurious
    f.seq["c"] = hi + 1000                             # leave a gap, then send above it
    f.send(t + 0.40, "c", 1000)                        # opens_gap
    spans = [s for s in classify(f.write(tmp_path / "g.pcap").read_bytes(), A, B) if s.src == A]
    summ = summarize_spans(spans)
    assert summ.spurious_retransmit_spans == 1
    assert summ.loss_episodes == 1


def test_summary_empty():
    summ = summarize_spans([])
    assert summ == ReorderSummary(0, 0, 0, 0, 0, 0, "lo", 0)


def test_classify_connection_pure_end_to_end(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, _hi = f.send(t, "c", 1000)
    f.retransmit(t + 0.05, "c", lo, 1000)
    selected = f.write(tmp_path / "orig.pcap")
    decap_missing = tmp_path / "decap.pcap"            # no encap => fall back to selected
    res = classify_connection_pure(decap_missing, selected, A, B, None)
    assert isinstance(res, ReorderResult)
    assert res.host_a == A and res.host_b == B
    assert res.summary.retransmit_bytes == 1000
    assert any(s.copy_status == "retransmission" for s in res.spans)


def test_classify_connection_pure_none_on_unparseable_hosts(tmp_path):
    f = TcpFlow()
    f.handshake(0.0, 0.01)
    selected = f.write(tmp_path / "orig.pcap")
    # unparseable endpoint strings (no ':' separator) => extract_conversation returns b""
    res = classify_connection_pure(tmp_path / "decap.pcap", selected,
                                   "invalid", "notanendpoint", None)
    assert res is None


def test_classify_connection_pure_empty_result_on_absent_valid_hosts(tmp_path):
    f = TcpFlow()
    f.handshake(0.0, 0.01)
    selected = f.write(tmp_path / "orig.pcap")
    # valid hosts not present in capture => extract returns non-empty header => n_spans == 0
    res = classify_connection_pure(tmp_path / "decap.pcap", selected,
                                   "203.0.113.9:1", "203.0.113.9:2", None)
    assert res is not None
    assert res.summary.n_spans == 0


def test_connection_open_orchestration(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, _hi = f.send(t, "c", 1000)
    f.retransmit(t + 0.05, "c", lo, 1000)
    selected = f.write(tmp_path / "cap.pcap")
    layout = CacheLayout(selected)                     # decap_pcap won't exist (no encap)
    # exactly what app.py passes to run.cpu_bound:
    res = classify_connection_pure(layout.decap_pcap, selected, A, B, None)
    assert res is not None
    assert res.summary.retransmit_bytes == 1000
