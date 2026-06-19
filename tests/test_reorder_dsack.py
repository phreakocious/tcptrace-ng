from tcptrace_ng.reorder import classify, infer, parse_frames, replay
from tests.pcap_synth import TcpFlow

A, B = "10.0.0.1:50000", "10.0.0.2:443"


def _spans(f, tmp_path, name):
    fr = parse_frames(f.write(tmp_path / name).read_bytes(), A, B)
    return [s for s in infer(fr, replay(fr), rtt=0.01) if s.src == A]


def test_dsack_after_fill_marks_duplicate_reported(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, hi = f.send(t + 0.00, "c", 1000)              # original (seen)
    f.retransmit(t + 0.50, "c", lo, 1000)            # spurious resend (rto)
    f.ack(t + 0.52, "s", sack=[(lo, hi)])            # D-SACK reports [lo,hi) redundantly received
    resend = _spans(f, tmp_path, "ds.pcap")[-1]
    assert resend.copy_status == "retransmission"
    assert resend.receiver_duplicate_reported == "yes"
    assert "dsack_confirmed" in resend.evidence


def test_non_retransmission_is_not_duplicate_reported(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    f.send(t, "c", 1000)
    s = _spans(f, tmp_path, "n.pcap")[0]
    assert s.copy_status == "original"
    assert s.receiver_duplicate_reported == "no"


def test_ambiguous_dsack_two_copies_is_unknown(tmp_path):
    # Two retransmissions of the same range, one DSACK covering both -> the DSACK
    # proves *a* redundant delivery but not *which* copy: honest abstention "unknown".
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, hi = f.send(t + 0.00, "c", 1000)            # original
    f.retransmit(t + 0.30, "c", lo, 1000)           # copy 1 (overlaps -> retransmission)
    f.retransmit(t + 0.60, "c", lo, 1000)           # copy 2
    f.ack(t + 0.62, "s", sack=[(lo, hi)])           # one DSACK covering [lo,hi) -> both copies
    resends = [s for s in _spans(f, tmp_path, "amb.pcap") if s.copy_status == "retransmission"]
    assert len(resends) >= 2
    assert all(s.receiver_duplicate_reported == "unknown" for s in resends)
    assert all("dsack_suspected" in s.evidence for s in resends)


def test_already_had_with_dsack_is_yes_without_confirmed_evidence(tmp_path):
    # receiver_state=already_had short-circuits to "yes" BEFORE event scanning, and
    # its evidence must NOT carry "dsack_confirmed" even when a DSACK is also present.
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, hi = f.send(t + 0.00, "c", 1000)
    f.ack(t + 0.02, "s", cumack=hi)                 # cum-ACK past hi BEFORE the resend -> already_had
    f.retransmit(t + 0.30, "c", lo, 1000)
    f.ack(t + 0.32, "s", sack=[(lo, hi)])           # plus a DSACK
    spans = [s for s in classify(f.write(tmp_path / "ah.pcap").read_bytes(), A, B, rtt=0.01)
             if s.src == A]
    resend = [s for s in spans if s.copy_status == "retransmission"][-1]
    assert resend.receiver_duplicate_reported == "yes"      # via the already_had short-circuit
    assert "dsack_confirmed" not in resend.evidence         # suppressed for already_had
