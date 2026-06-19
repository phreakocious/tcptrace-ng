# tests/test_reorder_genorder.py
from tcptrace_ng.reorder import infer, parse_frames, replay
from tests.pcap_synth import TcpFlow

A, B = "10.0.0.1:50000", "10.0.0.2:443"


def _gap_then_fill(tmp_path, name, fill_tsval, fill_ipid):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    _lo1, hi1 = f.send(t + 0.00, "c", 1000, tsval=100, ip_id=10)   # seg1 in_order
    f.seq["c"] += 1000                                              # skip the gap [hi1, hi1+1000)
    f.send(t + 0.01, "c", 1000, tsval=300, ip_id=30)               # successor (opens_gap), lo=hi1+1000
    f.retransmit(t + 0.05, "c", hi1, 1000, tsval=fill_tsval, ip_id=fill_ipid)  # fills the gap
    fr = parse_frames(f.write(tmp_path / name).read_bytes(), A, B)
    spans = infer(fr, replay(fr))
    fill = next(s for s in spans if s.src == A and s.sequence_observation == "fills_gap")
    return fill


def test_fill_stamped_after_successor(tmp_path):
    fill = _gap_then_fill(tmp_path, "a.pcap", fill_tsval=500, fill_ipid=50)  # both > successor's 300/30
    assert fill.generation_order == "after_successor"


def test_fill_stamped_before_successor(tmp_path):
    fill = _gap_then_fill(tmp_path, "b.pcap", fill_tsval=200, fill_ipid=20)  # both < successor's 300/30
    assert fill.generation_order == "before_successor"


def test_ipid_disagrees_with_tsval_is_unknown(tmp_path):
    fill = _gap_then_fill(tmp_path, "c.pcap", fill_tsval=500, fill_ipid=20)  # TSval after, IP-ID before
    assert fill.generation_order == "unknown"
