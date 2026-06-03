"""Coverage for the format-sniffing capture reader (classic pcap vs pcapng).

C1 regression guard. csum/offload/decap used to construct ``dpkt.pcap.Reader``
directly, which raises ``ValueError`` on a pcapng Section Header Block — so on
the modern default capture format all three detectors silently returned empty.
``open_reader`` peeks the 4-byte magic and dispatches to the right dpkt reader.
"""

from __future__ import annotations

from pathlib import Path

import dpkt

from tcptrace_ng.pcap_io import open_reader


def _eth_tcp_frame() -> bytes:
    tcp = dpkt.tcp.TCP(
        sport=12345, dport=80, seq=1, ack=0, off_x2=0x50, flags=0x10, data=b"\x00" * 100
    )
    ip = dpkt.ip.IP(
        src=b"\x0a\x00\x00\x01",
        dst=b"\x0a\x00\x00\x02",
        p=dpkt.ip.IP_PROTO_TCP,
        data=bytes(tcp),
    )
    ip.len = 20 + 20 + 100
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\xaa\xbb\xcc\xdd\xee\xff",
        type=0x0800,
        data=bytes(ip),
    )
    return bytes(eth)


def _write_classic(tmp_path: Path, frames: list[bytes]) -> Path:
    out = tmp_path / "classic.pcap"
    with out.open("wb") as f:
        w = dpkt.pcap.Writer(f, linktype=1)
        for i, fr in enumerate(frames):
            w.writepkt(fr, ts=1000.0 + i * 0.001)
    return out


def _write_pcapng(tmp_path: Path, frames: list[bytes]) -> Path:
    out = tmp_path / "modern.pcapng"
    with out.open("wb") as f:
        w = dpkt.pcapng.Writer(f, snaplen=65535, linktype=1)
        for i, fr in enumerate(frames):
            w.writepkt(fr, ts=1000.0 + i * 0.001)
    return out


def test_open_reader_dispatches_pcapng(tmp_path):
    p = _write_pcapng(tmp_path, [_eth_tcp_frame()])
    with p.open("rb") as f:
        reader = open_reader(f)
        assert isinstance(reader, dpkt.pcapng.Reader)


def test_open_reader_dispatches_classic_pcap(tmp_path):
    p = _write_classic(tmp_path, [_eth_tcp_frame()])
    with p.open("rb") as f:
        reader = open_reader(f)
        assert isinstance(reader, dpkt.pcap.Reader)


def test_open_reader_rewinds_so_first_frame_survives_the_peek(tmp_path):
    """The 4-byte magic sniff must seek back to 0, or frame 1 is lost."""
    p = _write_pcapng(tmp_path, [_eth_tcp_frame() for _ in range(3)])
    with p.open("rb") as f:
        reader = open_reader(f)
        assert reader.datalink() == 1
        assert sum(1 for _ in reader) == 3
