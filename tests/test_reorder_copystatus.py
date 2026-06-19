# tests/test_reorder_copystatus.py
from tcptrace_ng.reorder import classify
from tests.pcap_synth import TcpFlow

A, B = "10.0.0.1:50000", "10.0.0.2:443"


def _spans(f, tmp_path, name):
    pcap = f.write(tmp_path / name).read_bytes()
    return [s for s in classify(pcap, A, B) if s.src == A]


def test_in_order_is_original(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    f.send(t, "c", 1000)
    s = _spans(f, tmp_path, "o.pcap")[0]
    assert s.copy_status == "original"


def test_fill_after_successor_is_retransmission_unseen(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    _lo1, hi1 = f.send(t, "c", 1000, tsval=100, ip_id=10)
    f.seq["c"] += 1000
    f.send(t + 0.01, "c", 1000, tsval=300, ip_id=30)                 # successor
    f.retransmit(t + 0.05, "c", hi1, 1000, tsval=500, ip_id=50)      # after_successor
    fill = next(s for s in _spans(f, tmp_path, "f.pcap") if s.sequence_observation == "fills_gap")
    assert fill.copy_status == "retransmission"
    assert fill.original_visibility == "unseen"


def test_already_had_outranks_original(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, hi = f.send(t, "c", 1000)
    f.ack(t + 0.02, "s", cumack=hi)                  # server cum-ACKs past hi BEFORE the resend
    f.retransmit(t + 0.30, "c", lo, 1000)            # in_order-at-snd_max copy of unseen-to-us bytes
    spans = _spans(f, tmp_path, "a.pcap")
    resend = spans[-1]
    assert resend.copy_status == "retransmission"    # NOT original
    assert "already_had_spurious" in resend.evidence
