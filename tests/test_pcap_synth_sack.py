# tests/test_pcap_synth_sack.py
from tcptrace_ng.reorder import parse_frames
from tests.pcap_synth import TcpFlow

A, B = "10.0.0.1:50000", "10.0.0.2:443"


def _frames(f, tmp_path, name):
    return parse_frames(f.write(tmp_path / name).read_bytes(), A, B)


def test_sack_block_above_cumack_is_a_hole_not_dsack(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, _hi = f.send(t, "c", 1000)                 # client data [lo, hi)
    # server selectively ACKs [lo+2000, lo+3000) while cum-ACK stays at lo (a hole)
    f.ack(t + 0.02, "s", sack=[(lo + 2000, lo + 3000)], cumack=lo)
    sf = [fr for fr in _frames(f, tmp_path, "h.pcap") if fr.src == B and fr.sack_blocks]
    assert len(sf) == 1
    assert sf[0].sack_blocks == ((lo + 2000, lo + 3000),)
    assert sf[0].ack == lo
    assert sf[0].dsack is False                   # block is above cum-ACK


def test_sack_block_below_cumack_is_dsack(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    lo, hi = f.send(t, "c", 1000)
    # server cum-ACKs past hi AND reports [lo, hi) as a duplicate (D-SACK)
    f.ack(t + 0.02, "s", sack=[(lo, hi)])         # cumack defaults to seq[c] (>= hi)
    sf = [fr for fr in _frames(f, tmp_path, "d.pcap") if fr.src == B and fr.sack_blocks]
    assert len(sf) == 1
    assert sf[0].sack_blocks == ((lo, hi),)
    assert sf[0].dsack is True
