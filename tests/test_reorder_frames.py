import struct

import dpkt

from tcptrace_ng.reorder import _opts, parse_frames
from tests.pcap_synth import TcpFlow


def test_parses_data_frames_with_signals(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, hi = f.send(t, "c", 1460, ip_id=4321, tsval=5000)
    p = f.write(tmp_path / "c.pcap")
    frames = parse_frames(p.read_bytes(), "10.0.0.1:50000", "10.0.0.2:443")
    data = [fr for fr in frames if fr.payload_len > 0]
    assert len(data) == 1
    fr = data[0]
    assert (fr.seq, fr.end, fr.payload_len) == (lo, hi, 1460)
    assert fr.ip_id == 4321 and fr.tsval == 5000
    assert fr.src == "10.0.0.1:50000" and fr.dst == "10.0.0.2:443"
    assert fr.ordinal == frames.index(fr)  # ordinal is capture position


def test_sack_and_dsack_flags(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    # client sends 100 bytes (seq 1001..1101)
    lo, hi = f.send(t, "c", 100)
    t += 0.001
    # server sends a pure ACK with a D-SACK block: right edge (hi) == ack (hi)
    sack_opt = struct.pack("!BB", dpkt.tcp.TCP_OPT_SACK, 10) + struct.pack("!II", lo, hi)
    f._emit(t, "s", f.seq["s"], hi, 0x10, f.win["s"] >> f.wscale, opts=sack_opt)
    p = f.write(tmp_path / "s.pcap")
    frames = parse_frames(p.read_bytes(), "10.0.0.1:50000", "10.0.0.2:443")
    # the D-SACK frame: first (and only) frame carrying SACK blocks
    dsack_frames = [fr for fr in frames if fr.sack_blocks]
    assert len(dsack_frames) == 1
    fr = dsack_frames[0]
    assert fr.dsack is True
    assert fr.sack_blocks == ((lo, hi),)
    # normal data frame carries no SACK and dsack must be False
    data_frames = [fr for fr in frames if fr.payload_len > 0]
    assert len(data_frames) == 1
    assert data_frames[0].dsack is False


def test_opts_survives_malformed_options():
    tcp = dpkt.tcp.TCP(sport=1, dport=2, seq=0, ack=0, flags=0x10, win=0, sum=0, data=b"")
    tcp.opts = bytes([8])  # truncated TS option -> parse_opts returns [None]
    assert _opts(tcp) == (None, None, ())  # must not raise
