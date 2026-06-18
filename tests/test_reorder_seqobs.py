from tcptrace_ng.reorder import parse_frames, replay
from tests.pcap_synth import TcpFlow

A, B = "10.0.0.1:50000", "10.0.0.2:443"


def _spans(f, tmp_path, name):
    return replay(parse_frames(f.write(tmp_path / name).read_bytes(), A, B))


def test_in_order_then_gap_then_fill(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    f.send(t + 0.00, "c", 1000)            # in_order
    f.seq["c"] += 1000                      # skip 1000 B → simulate an unseen segment
    f.send(t + 0.01, "c", 1000)            # opens_gap (seq jumped past snd_max)
    f.retransmit(t + 0.20, "c", f.seq["c"] - 2000, 1000)  # fills_gap: resend the unseen gap seg, below max
    spans = [s for s in _spans(f, tmp_path, "g.pcap") if s.src == A]
    kinds = [s.sequence_observation for s in spans]
    assert kinds == ["in_order", "opens_gap", "fills_gap"], kinds
    assert spans[2].arrived_below_seen_edge is True
    assert spans[0].arrived_below_seen_edge is False


def test_overlap_is_overlaps(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, _ = f.send(t, "c", 1000)
    f.retransmit(t + 0.2, "c", lo, 1000)   # exact resend of seen bytes
    spans = [s for s in _spans(f, tmp_path, "o.pcap") if s.src == A]
    assert spans[-1].sequence_observation == "overlaps"


def test_union_coverage_is_overlaps(tmp_path):
    # bytes seen across two ADJACENT segments → a covering retransmit is 'overlaps'
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    f.send(t + 0.00, "c", 1000)
    f.send(t + 0.01, "c", 1000)                              # adjacent → coalesces
    f.retransmit(t + 0.20, "c", f.seq["c"] - 1500, 1000)     # union-covered span
    spans = [s for s in _spans(f, tmp_path, "u.pcap") if s.src == A]
    assert spans[-1].sequence_observation == "overlaps"


def test_genuine_partial(tmp_path):
    # half previously-seen, half novel → 'partial'
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    f.send(t + 0.00, "c", 1000)
    f.retransmit(t + 0.10, "c", f.seq["c"] - 500, 1000)      # 500 seen + 500 novel
    spans = [s for s in _spans(f, tmp_path, "pa.pcap") if s.src == A]
    assert spans[-1].sequence_observation == "partial"


def test_prebaseline(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    f.send(t, "c", 1000)
    f.retransmit(t + 0.1, "c", f.seq["c"] - 2000, 500)       # seq below first-seen baseline
    spans = [s for s in _spans(f, tmp_path, "pb.pcap") if s.src == A]
    assert spans[-1].sequence_observation == "prebaseline"
