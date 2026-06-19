# tests/test_reorder_tier.py
from tcptrace_ng.reorder import classify, infer, parse_frames, replay
from tests.pcap_synth import TcpFlow

A, B = "10.0.0.1:50000", "10.0.0.2:443"


def test_tier_hi_when_genorder_and_receiver_agree(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    _lo1, hi1 = f.send(t + 0.00, "c", 1000, tsval=100, ip_id=10)
    f.seq["c"] += 1000
    f.send(t + 0.01, "c", 1000, tsval=300, ip_id=30)                 # successor
    for i in range(3):
        f.ack(t + 0.02 + i * 0.001, "s", cumack=hi1)                 # 3 dup-ACKs => missing_before
    f.retransmit(t + 0.05, "c", hi1, 1000, tsval=500, ip_id=50)      # after_successor + hole
    # Use classify() (full observe chain) so receiver_state is populated
    fill = next(s for s in classify(f.write(tmp_path / "hi.pcap").read_bytes(), A, B, rtt=0.01)
                if s.src == A and s.sequence_observation == "fills_gap")
    assert fill.copy_status == "retransmission"
    assert fill.generation_order == "after_successor"
    assert fill.receiver_state == "missing_before"
    assert fill.tier == "hi"


def test_tier_lo_when_unknown(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    f.seq["c"] += 1000                                # midstream-ish gap with no signals
    f.send(t, "c", 1000)
    fr = parse_frames(f.write(tmp_path / "lo.pcap").read_bytes(), A, B)
    spans = [s for s in infer(fr, replay(fr)) if s.src == A]
    assert spans and all(s.tier == "lo" for s in spans)
