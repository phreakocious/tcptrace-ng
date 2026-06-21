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


def test_tier_hi_overlaps_is_byte_certain(tmp_path):
    # Both copies physically in the capture (byte-overlap) => retransmission is direct,
    # not inferred. No reverse ACK yet, no generation_order: the pure byte-certain case.
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, _hi = f.send(t, "c", 1000)
    f.retransmit(t + 0.05, "c", lo, 1000)                        # resend seen bytes, no ACK between
    spans = [s for s in classify(f.write(tmp_path / "ov.pcap").read_bytes(), A, B) if s.src == A]
    resend = next(s for s in spans if s.sequence_observation == "overlaps")
    assert resend.copy_status == "retransmission"
    assert "overlaps_seen" in resend.evidence
    assert resend.receiver_state == "unknown"                   # no corroborator — byte evidence alone
    assert resend.tier == "hi"


def test_tier_hi_already_had_retransmission(tmp_path):
    # Receiver provably already held the bytes (cum-ACK past them before the resend):
    # direct receiver evidence => hi, independent of generation_order.
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, hi = f.send(t, "c", 1000)
    f.ack(t + 0.02, "s", cumack=hi)                             # receiver cum-ACKs past hi first
    f.retransmit(t + 0.30, "c", lo, 1000)
    spans = [s for s in classify(f.write(tmp_path / "ah.pcap").read_bytes(), A, B) if s.src == A]
    resend = next(s for s in spans if s.receiver_state == "already_had")
    assert resend.copy_status == "retransmission"
    assert resend.tier == "hi"


def test_tier_med_probable_capture_duplicate(tmp_path):
    # Sharp positive fingerprint match but tap-vs-wire is irreducibly ambiguous
    # ("never certain") => med, never hi; not lo (it's a positive obs, not abstention).
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, _ = f.send(t, "c", 500, ip_id=7, tsval=100)
    f.retransmit(t + 0.0005, "c", lo, 500, ip_id=7, tsval=100)  # tap dup: same everything, Δt<1ms
    spans = [s for s in classify(f.write(tmp_path / "dup.pcap").read_bytes(), A, B) if s.src == A]
    dup = next(s for s in spans if s.copy_status == "probable_capture_duplicate")
    assert dup.tier == "med"


def test_tier_med_late_original_not_promoted_by_conflicting_hole(tmp_path):
    # fills_gap + before_successor within the late-original window => copy_status "original".
    # The only reachable corroborator is missing_before (3 dup-ACKs at the hole) — which
    # CONTRADICTS the late-original reading (it's the false-fast-retransmit setup), so it must
    # NOT lift the tier to hi. Stays med (flat).
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    rtt = 0.01
    _lo1, hi1 = f.send(t + 0.000, "c", 1000, tsval=100, ip_id=10)   # [1001,2001)
    f.seq["c"] += 1000                                             # gap [2001,3001)
    f.send(t + 0.010, "c", 1000, tsval=300, ip_id=30)             # successor [3001,4001)
    for i in range(3):
        f.ack(t + 0.0105 + i * 0.0002, "s", cumack=hi1)           # 3 dup-ACKs at the hole
    f.retransmit(t + 0.012, "c", hi1, 1000, tsval=200, ip_id=20)  # before_successor, in-window
    spans = [s for s in classify(f.write(tmp_path / "lo.pcap").read_bytes(), A, B, rtt=rtt)
             if s.src == A]
    fill = next(s for s in spans if s.sequence_observation == "fills_gap")
    assert fill.copy_status == "original"
    assert "late_original" in fill.evidence
    assert fill.generation_order == "before_successor"
    assert fill.receiver_state == "missing_before"               # the conflicting corroborator
    assert fill.tier == "med"                                    # NOT hi
