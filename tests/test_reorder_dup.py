from tcptrace_ng.reorder import duplicate_observation, parse_frames, replay
from tests.pcap_synth import TcpFlow

A, B = "10.0.0.1:50000", "10.0.0.2:443"


def test_near_simultaneous_identical_frame_is_duplicate(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, _ = f.send(t + 0.0, "c", 500, ip_id=7, tsval=100)
    f.retransmit(t + 0.0005, "c", lo, 500, ip_id=7, tsval=100)  # tap dup: same everything, Δt<1ms
    fr = parse_frames(f.write(tmp_path / "d.pcap").read_bytes(), A, B)
    spans = [s for s in duplicate_observation(fr, replay(fr)) if s.src == A]
    assert spans[-1].duplicate_observation is True
    assert spans[-2].duplicate_observation is False


def test_later_retransmit_is_not_duplicate(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, _ = f.send(t, "c", 500, ip_id=7, tsval=100)
    f.retransmit(t + 0.3, "c", lo, 500, ip_id=99, tsval=400)    # real resend, Δt large
    fr = parse_frames(f.write(tmp_path / "r.pcap").read_bytes(), A, B)
    spans = [s for s in duplicate_observation(fr, replay(fr)) if s.src == A]
    assert spans[-1].duplicate_observation is False
