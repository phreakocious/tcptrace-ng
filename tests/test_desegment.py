from pathlib import Path

import dpkt

from tcptrace_ng.desegment import (
    DESEGMENT_VERSION,
    CoalesceEvent,
    DesegmentResult,
    connection_mss,
    desegment_pcap,
)
from tcptrace_ng.offload import _tcp_payload_len
from tcptrace_ng.pcap_io import open_reader
from tests.pcap_synth import TcpFlow


def test_module_constants_and_dataclasses():
    assert DESEGMENT_VERSION == "1"
    ev = CoalesceEvent(
        time=1.0,
        src="10.0.0.1:5000",
        dst="10.0.0.2:80",
        parent_seq_start=100,
        parent_seq_end=100 + 8000,
        pieces=6,
        mss=1448,
        mss_source="syn",
    )
    assert ev.pieces == 6 and ev.mss_source == "syn"
    res = DesegmentResult()
    assert res.frames_split == 0 and res.coalesces == [] and res.residual_conns == set()


# TcpFlow defaults: client "c" 10.0.0.1:50000, server "s" 10.0.0.2:443, mss=1460
_CLI = "10.0.0.1:50000"
_SRV = "10.0.0.2:443"


def _flow_with_handshake(tmp_path: Path) -> Path:
    fl = TcpFlow()  # mss=1460 (both sides advertise this in their SYN/SYN-ACK)
    fl.handshake(0.0, rtt=0.01)
    fl.send(0.10, "s", 8000)  # one coalesced super-segment, server->client
    fl.ack(0.11, "c")
    return fl.write(tmp_path / "hs.pcap")


def test_connection_mss_from_syn(tmp_path):
    p = _flow_with_handshake(tmp_path)
    table = connection_mss(p)
    # slicing the server's data uses the *client's* advertised MSS (TcpFlow default mss=1460)
    mss, source = table.slice_mss(_SRV, _CLI)  # (sender, receiver)
    assert mss == 1460 and source == "syn"


def test_connection_mss_modal_inference_no_syn(tmp_path):
    fl = TcpFlow()
    # No handshake. 20 full-size 1448 B segments + 1 coalesced 8000 B one, all server->client.
    t = 0.0
    for _ in range(20):
        fl.send(t, "s", 1448)
        t += 0.001
    fl.send(t, "s", 8000)
    table = connection_mss(fl.write(tmp_path / "midstream.pcap"))
    mss, source = table.slice_mss(_SRV, _CLI)
    assert mss == 1448 and source == "inferred"


def test_connection_mss_residual_when_unknowable(tmp_path):
    fl = TcpFlow()
    fl.send(0.0, "s", 8000)  # only a coalesced segment, no SYN, no full-size sample
    table = connection_mss(fl.write(tmp_path / "blind.pcap"))
    assert table.slice_mss(_SRV, _CLI) is None


def _payloads(pcap: Path) -> list[int]:
    out = []
    with pcap.open("rb") as f:
        for _ts, buf in open_reader(f):
            n = _tcp_payload_len(buf)
            if n:
                out.append(n)
    return out


def test_desegment_splits_oversized_into_mss(tmp_path):
    src = _flow_with_handshake(tmp_path)  # 8000 B server->client seg, advertised MSS 1460
    out = tmp_path / "deseg.pcap"
    res = desegment_pcap(src, out)
    sizes = _payloads(out)
    assert 8000 not in sizes  # the fat segment is gone
    # 8000 / 1460 -> 5x1460 + 1x700
    assert sizes.count(1460) >= 5 and 700 in sizes
    assert res.frames_split == 1 and res.pieces_emitted == 6
    assert len(res.coalesces) == 1
    ev = res.coalesces[0]
    assert ev.pieces == 6 and ev.mss == 1460 and ev.mss_source == "syn"


def test_desegment_split_frames_reparse_cleanly(tmp_path):
    # the split must produce frames tcptrace can read: correct on-wire payload len + seq spacing
    src = _flow_with_handshake(tmp_path)
    out = tmp_path / "deseg.pcap"
    desegment_pcap(src, out)
    payloads = _payloads(out)
    assert payloads[:5] == [1460, 1460, 1460, 1460, 1460] and payloads[5] == 700
    seqs = []
    with out.open("rb") as f:
        for _ts, buf in open_reader(f):
            eth = dpkt.ethernet.Ethernet(buf)
            tcp = eth.data.data
            if isinstance(tcp, dpkt.tcp.TCP) and len(bytes(tcp.data)) in (1460, 700):
                seqs.append(tcp.seq)
    assert seqs[1] - seqs[0] == 1460 and seqs[2] - seqs[1] == 1460  # pieces are exactly MSS apart


def test_desegment_passes_through_residual_and_control(tmp_path):
    fl = TcpFlow()
    fl.send(0.0, "s", 8000)  # no SYN, no full-size -> residual
    out = tmp_path / "r.pcap"
    res = desegment_pcap(fl.write(tmp_path / "r_in.pcap"), out)
    assert 8000 in _payloads(out)  # untouched
    assert res.frames_split == 0
    assert res.residual_conns == {frozenset({("10.0.0.2", 443), ("10.0.0.1", 50000)})}
