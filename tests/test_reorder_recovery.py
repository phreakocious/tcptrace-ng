# tests/test_reorder_recovery.py
from tcptrace_ng.reorder import infer, parse_frames, replay
from tests.pcap_synth import TcpFlow

A, B = "10.0.0.1:50000", "10.0.0.2:443"


def _spans(f, tmp_path, name, rtt):
    fr = parse_frames(f.write(tmp_path / name).read_bytes(), A, B)
    return [s for s in infer(fr, replay(fr), rtt=rtt) if s.src == A]


def test_fast_ack_from_three_dupacks(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    _lo1, hi1 = f.send(t + 0.00, "c", 1000)            # seg1
    f.seq["c"] += 1000
    _lo3, _hi3 = f.send(t + 0.01, "c", 1000)          # seg3 (gap [hi1, hi1+1000))
    for i in range(3):                                 # 3 dup-ACKs at hi1
        f.ack(t + 0.02 + i * 0.001, "s", cumack=hi1)
    f.retransmit(t + 0.05, "c", hi1, 1000)            # fast retransmit of the gap
    fill = next(s for s in _spans(f, tmp_path, "fa.pcap", rtt=0.01)
                if s.sequence_observation == "fills_gap")
    assert fill.copy_status == "retransmission"
    assert fill.recovery_trigger == "fast_ack"


def test_rto_needs_seen_original_and_timeout(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, _hi = f.send(t + 0.00, "c", 1000)              # SEEN original at the cum-ACK frontier
    f.retransmit(t + 0.50, "c", lo, 1000)            # resend 500ms later, no ACK progress
    s = _spans(f, tmp_path, "rto.pcap", rtt=0.01)[-1]
    assert s.copy_status == "retransmission"
    assert s.recovery_trigger == "rto"               # >= max(200ms, 3*10ms)=200ms, frontier, no progress


def test_no_rtt_cannot_be_rto(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, _hi = f.send(t + 0.00, "c", 1000)
    f.retransmit(t + 0.50, "c", lo, 1000)
    s = _spans(f, tmp_path, "nr.pcap", rtt=None)[-1]
    assert s.recovery_trigger == "loss_recovery"     # abstain without rtt


def test_late_original_within_window(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    _lo1, hi1 = f.send(t + 0.000, "c", 1000, tsval=100, ip_id=10)
    f.seq["c"] += 1000
    f.send(t + 0.010, "c", 1000, tsval=300, ip_id=30)                  # successor at t+0.010
    f.retransmit(t + 0.012, "c", hi1, 1000, tsval=200, ip_id=20)       # before_successor, +2ms (<0.5*rtt=5ms)
    fill = next(s for s in _spans(f, tmp_path, "lo.pcap", rtt=0.01)
                if s.sequence_observation == "fills_gap")
    assert fill.generation_order == "before_successor"
    assert fill.copy_status == "original"
    assert "late_original" in fill.evidence
