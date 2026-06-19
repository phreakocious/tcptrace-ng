# tests/test_reorder_corpus.py
from tcptrace_ng.reorder import classify
from tests.pcap_synth import TcpFlow

A, B = "10.0.0.1:50000", "10.0.0.2:443"


def _classify(f, tmp_path, name, rtt=0.01):
    return [s for s in classify(f.write(tmp_path / name).read_bytes(), A, B, rtt=rtt) if s.src == A]


def test_true_reorder_late_original(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    _lo1, hi1 = f.send(t + 0.000, "c", 1000, tsval=100, ip_id=10)
    f.seq["c"] += 1000
    f.send(t + 0.010, "c", 1000, tsval=300, ip_id=30)
    f.retransmit(t + 0.012, "c", hi1, 1000, tsval=200, ip_id=20)     # generated before successor
    fill = next(s for s in _classify(f, tmp_path, "reorder.pcap")
                if s.sequence_observation == "fills_gap")
    assert fill.copy_status == "original"


def test_rto_retransmit_of_unseen(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    _lo1, hi1 = f.send(t + 0.00, "c", 1000, tsval=100, ip_id=10)
    f.seq["c"] += 1000
    f.send(t + 0.01, "c", 1000, tsval=300, ip_id=30)
    f.retransmit(t + 0.40, "c", hi1, 1000, tsval=500, ip_id=50)      # unseen original, after successor
    fill = next(s for s in _classify(f, tmp_path, "rtou.pcap")
                if s.sequence_observation == "fills_gap")
    assert fill.copy_status == "retransmission"
    assert fill.original_visibility == "unseen"


def test_network_duplicate_stays_probable(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, _hi = f.send(t + 0.0000, "c", 500, ip_id=7, tsval=100)
    f.retransmit(t + 0.0005, "c", lo, 500, ip_id=7, tsval=100)       # tap/network dup (Δt<1ms)
    dup = _classify(f, tmp_path, "dup.pcap")[-1]
    assert dup.copy_status == "probable_capture_duplicate"


def test_in_flight_not_a_hole_is_unknown(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    f.send(t, "c", 1000)                              # never ACKed; not a hole
    s = _classify(f, tmp_path, "inflight.pcap")[0]
    assert s.receiver_state == "unknown"
    assert s.copy_status == "original"
