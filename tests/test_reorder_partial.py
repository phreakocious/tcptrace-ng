# tests/test_reorder_partial.py
from tcptrace_ng.reorder import infer, parse_frames, replay
from tests.pcap_synth import TcpFlow

A, B = "10.0.0.1:50000", "10.0.0.2:443"


def _spans(f, tmp_path, name):
    fr = parse_frames(f.write(tmp_path / name).read_bytes(), A, B)
    return fr, infer(fr, replay(fr))


def test_partial_split_into_overlaps_and_forward(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    _lo1, hi1 = f.send(t, "c", 1000)                      # [_lo1, hi1) in_order, snd_max=hi1
    # straddle: re-send [hi1-500, hi1+500) -> overlaps [hi1-500,hi1) + forward [hi1,hi1+500)
    f.retransmit(t + 0.1, "c", hi1 - 500, 1000)
    _fr, spans = _spans(f, tmp_path, "p.pcap")
    a = [s for s in spans if s.src == A]
    # the straddling frame's ordinal now yields TWO sub-spans, no "partial" remains
    assert not any(s.sequence_observation == "partial" for s in a)
    straddle = [s for s in a if s.frame_ordinal == a[-1].frame_ordinal]
    kinds = sorted(s.sequence_observation for s in straddle)
    assert kinds == ["in_order", "overlaps"], kinds
    over = next(s for s in straddle if s.sequence_observation == "overlaps")
    fwd = next(s for s in straddle if s.sequence_observation == "in_order")
    assert (over.lo, over.hi) == (hi1 - 500, hi1)
    assert (fwd.lo, fwd.hi) == (hi1, hi1 + 500)
