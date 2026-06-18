import dpkt

from tests.pcap_synth import TcpFlow


def _frames(path):
    with open(path, "rb") as fh:
        return [(t, dpkt.ethernet.Ethernet(buf)) for t, buf in dpkt.pcap.Reader(fh)]


def _tsval(tcp):
    for kind, data in dpkt.tcp.parse_opts(tcp.opts):
        if kind == dpkt.tcp.TCP_OPT_TIMESTAMP:
            import struct
            return struct.unpack("!II", data)[0]
    return None


def test_data_frames_carry_distinct_ipid_and_monotonic_tsval(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    f.send(t + 0.000, "c", 1460)
    f.send(t + 0.010, "c", 1460)
    p = f.write(tmp_path / "x.pcap")
    frames = [(t, e) for t, e in _frames(p) if isinstance(e.data, dpkt.ip.IP)]
    data = [(t, e) for t, e in frames if len(e.data.data.data) > 0]
    ids = [e.data.id for _, e in data]
    tsv = [_tsval(e.data.data) for _, e in data]
    assert len(set(ids)) == len(ids), f"IP-IDs must differ per frame: {ids}"
    assert all(v is not None for v in tsv), "data frames must carry a TS option"
    assert tsv == sorted(tsv), f"TSval must be monotonic non-decreasing: {tsv}"


def test_explicit_overrides_take_effect(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    f.send(t, "c", 100, ip_id=0, tsval=4242)
    p = f.write(tmp_path / "y.pcap")
    data = [e for _, e in _frames(p)
            if isinstance(e.data, dpkt.ip.IP) and len(e.data.data.data) > 0]
    assert data[0].data.id == 0
    assert _tsval(data[0].data.data) == 4242
