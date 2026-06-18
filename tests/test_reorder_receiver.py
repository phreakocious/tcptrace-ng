import struct

import dpkt

from tcptrace_ng.reorder import parse_frames, receiver_state, replay
from tests.pcap_synth import TcpFlow

A, B = "10.0.0.1:50000", "10.0.0.2:443"


def _run(f, tmp_path, name):
    fr = parse_frames(f.write(tmp_path / name).read_bytes(), A, B)
    return receiver_state(fr, replay(fr))


def test_plain_inflight_is_unknown_not_missing(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    f.send(t, "c", 1000)  # never ACKed in this capture, but that's not a hole
    spans = [s for s in _run(f, tmp_path, "i.pcap") if s.src == A]
    assert spans[0].receiver_state == "unknown"


def test_already_had_when_cumack_passed_end(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, hi = f.send(t, "c", 1000)
    f.cumack["s"] = hi
    f.ack(t + 0.02, "s")                       # server cum-ACKs past hi
    f.retransmit(t + 0.30, "c", lo, 1000)      # later resend
    spans = [s for s in _run(f, tmp_path, "a.pcap") if s.src == A]
    assert spans[-1].receiver_state == "already_had"


def test_3dup_ack_missing_before(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    _, gap_lo = f.send(t, "c", 1000)   # [S0, S0+1000); f.seq["c"] == gap_lo here
    # 3 dup-ACKs stuck at gap_lo (f.seq["c"] is gap_lo so f.ack emits ack=gap_lo)
    f.ack(t + 0.02, "s")
    f.ack(t + 0.03, "s")
    f.ack(t + 0.04, "s")
    f.seq["c"] += 1000                 # open the gap without sending [gap_lo, gap_lo+1000)
    f.send(t + 0.06, "c", 1000)        # [S0+2000, S0+3000) — arrives out of order
    f.retransmit(t + 0.10, "c", gap_lo, 1000)  # fill the gap
    spans = [s for s in _run(f, tmp_path, "dup.pcap") if s.src == A]
    fill = [s for s in spans if s.sequence_observation == "fills_gap"]
    assert len(fill) == 1
    assert fill[0].receiver_state == "missing_before"


def test_sack_above_missing_before(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    _, gap_lo = f.send(t, "c", 1000)   # [S0, S0+1000); gap_lo = S0+1000
    f.seq["c"] += 1000                 # open the gap
    lo3, hi3 = f.send(t + 0.01, "c", 1000)  # [S0+2000, S0+3000)
    # One server ACK: cumack stuck at gap_lo, SACK block covering the received OOO data
    sack_opts = (struct.pack("!BB", dpkt.tcp.TCP_OPT_SACK, 10)
                 + struct.pack("!II", lo3, hi3))
    f._emit(t + 0.02, "s", f.seq["s"], gap_lo, 0x10, f.win["s"] >> f.wscale, opts=sack_opts)
    f.retransmit(t + 0.05, "c", gap_lo, 1000)  # fill the gap
    spans = [s for s in _run(f, tmp_path, "sack.pcap") if s.src == A]
    fill = [s for s in spans if s.sequence_observation == "fills_gap"]
    assert len(fill) == 1
    assert fill[0].receiver_state == "missing_before"


def test_partial_ack_past_lo_resets_missing_before(tmp_path):
    # 3 dup-ACKs stuck at gap_lo, then a partial ACK advancing cumack PAST gap_lo
    # (but below the gap's end). Fixed cumack guard -> 'unknown'; the old
    # any()-based guard would have kept it 'missing_before'.
    # NB: f.ack() auto-ACKs the latest data (cumack[frm]=seq[other]), so exact
    # stuck/partial ACK values must be emitted via raw _emit.
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    _, gap_lo = f.send(t, "c", 1000)              # [S0, gap_lo)
    f.seq["c"] += 1000                            # open gap [gap_lo, gap_lo+1000)
    f.send(t + 0.01, "c", 1000)                   # [gap_lo+1000, gap_lo+2000) out-of-order
    w = f.win["s"] >> f.wscale
    f._emit(t + 0.02, "s", f.seq["s"], gap_lo, 0x10, w)          # dup-ACK at gap_lo
    f._emit(t + 0.03, "s", f.seq["s"], gap_lo, 0x10, w)
    f._emit(t + 0.04, "s", f.seq["s"], gap_lo, 0x10, w)
    f._emit(t + 0.05, "s", f.seq["s"], gap_lo + 500, 0x10, w)    # partial ACK past gap_lo
    f.retransmit(t + 0.10, "c", gap_lo, 1000)                    # fill [gap_lo, gap_lo+1000)
    spans = [s for s in _run(f, tmp_path, "partial.pcap") if s.src == A]
    fill = [s for s in spans if s.sequence_observation == "fills_gap"]
    assert len(fill) == 1
    assert fill[0].receiver_state == "unknown"


def test_synack_excluded_from_dupack_count(tmp_path):
    # Server re-ACKs at ISN+1 twice BEFORE any client data. With the SYN-ACK
    # wrongly counted, that's 3 'dup-ACKs' at the first segment's left edge ->
    # old code: 'missing_before'. Fixed code excludes the SYN-ACK -> 2 -> 'unknown'.
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    f.ack(t + 0.001, "s")                     # server re-ACK at client ISN+1
    f.ack(t + 0.002, "s")                     # again
    f.send(t + 0.01, "c", 1000)              # first data; sp.lo == ISN+1 == SYN-ACK.ack
    spans = [s for s in _run(f, tmp_path, "syn2.pcap") if s.src == A]
    assert spans[0].receiver_state == "unknown"
