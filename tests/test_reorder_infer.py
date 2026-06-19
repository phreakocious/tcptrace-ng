# tests/test_reorder_infer.py
from tcptrace_ng.reorder import SpanObs, classify
from tests.pcap_synth import TcpFlow

A, B = "10.0.0.1:50000", "10.0.0.2:443"


def test_spanobs_inferred_defaults():
    s = SpanObs(frame_ordinal=0, src=A, dst=B, lo=0, hi=1, time=0.0,
                sequence_observation="in_order", arrived_below_seen_edge=False)
    assert s.generation_order == "unknown"
    assert s.copy_status == "unknown"
    assert s.original_visibility == "unknown"
    assert s.recovery_trigger == "unknown"
    assert s.receiver_duplicate_reported == "no"
    assert s.tier == "lo"


def test_classify_chains_and_keeps_one_span_per_data_frame(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    f.send(t, "c", 1000)
    spans = classify(f.write(tmp_path / "c.pcap").read_bytes(), A, B, rtt=None)
    data = [s for s in spans if s.src == A]
    assert len(data) == 1
    # observed axes intact; copy_status set by _copy_status (Task 5)
    assert data[0].sequence_observation == "in_order"
    assert data[0].copy_status == "original"
