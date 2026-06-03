"""Coverage for the independent TCP-checksum scanner."""

from __future__ import annotations

import struct
from pathlib import Path

import dpkt

from tcptrace_ng.csum import _pseudo_header_partial, scan_pcap


def _tcp_frame(sport: int, dport: int, payload: bytes, checksum: int) -> bytes:
    """Build a TCP/IPv4/Ethernet frame with the exact `checksum` written into
    the TCP cksum field, regardless of what the real checksum would be."""
    src = b"\x0a\x00\x00\x01"
    dst = b"\x0a\x00\x00\x02"
    tcp = dpkt.tcp.TCP(
        sport=sport,
        dport=dport,
        seq=1,
        ack=0,
        off_x2=0x50,
        flags=0x18,  # PSH+ACK
        data=payload,
    )
    tcp.sum = checksum
    ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_TCP, data=bytes(tcp))
    ip.len = 20 + 20 + len(payload)
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\xaa\xbb\xcc\xdd\xee\xff",
        type=0x0800,
        data=bytes(ip),
    )
    return bytes(eth)


def _correct_checksum(src: bytes, dst: bytes, payload: bytes) -> int:
    """Honest RFC 793 TCP checksum so we can write a known-good frame."""
    tcp = dpkt.tcp.TCP(
        sport=12345,
        dport=80,
        seq=1,
        ack=0,
        off_x2=0x50,
        flags=0x18,
        data=payload,
    )
    tcp_bytes = bytes(tcp)  # cksum starts at 0; we recompute and patch in.
    zeroed = tcp_bytes[:16] + b"\x00\x00" + tcp_bytes[18:]
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(zeroed))
    data = pseudo + zeroed
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _write_pcap(tmp_path: Path, frames: list[bytes]) -> Path:
    out = tmp_path / "x.pcap"
    with out.open("wb") as f:
        w = dpkt.pcap.Writer(f, linktype=1)
        for i, fr in enumerate(frames):
            w.writepkt(fr, ts=1000.0 + i * 0.001)
    return out


def test_scan_skips_correct_checksum(tmp_path):
    payload = b"hello world"
    good = _correct_checksum(b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", payload)
    pcap = _write_pcap(tmp_path, [_tcp_frame(12345, 80, payload, good)])
    assert scan_pcap(pcap) == []


def test_scan_flags_genuinely_bad_checksum(tmp_path):
    payload = b"hello world"
    pcap = _write_pcap(tmp_path, [_tcp_frame(12345, 80, payload, checksum=0xDEAD)])
    events = scan_pcap(pcap)
    assert len(events) == 1
    assert events[0].src_port == 12345
    assert events[0].dst_port == 80


def test_scan_filters_pseudo_header_partial_offload(tmp_path):
    # Linux TX checksum offload leaves the TCP cksum field set to the
    # pseudo-header partial sum; we must not flag those packets as bad.
    payload = b"hello world"
    src = b"\x0a\x00\x00\x01"
    dst = b"\x0a\x00\x00\x02"
    tcp_len = 20 + len(payload)
    partial = _pseudo_header_partial(src, dst, tcp_len)
    pcap = _write_pcap(tmp_path, [_tcp_frame(12345, 80, payload, checksum=partial)])
    assert scan_pcap(pcap) == []


def test_scan_skips_udp_and_non_ip_frames(tmp_path):
    udp = dpkt.udp.UDP(sport=12345, dport=53, data=b"\x00" * 16)
    udp.ulen = 8 + 16
    ip = dpkt.ip.IP(
        src=b"\x0a\x00\x00\x01",
        dst=b"\x0a\x00\x00\x02",
        p=dpkt.ip.IP_PROTO_UDP,
        data=bytes(udp),
    )
    ip.len = 20 + 8 + 16
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\xaa\xbb\xcc\xdd\xee\xff",
        type=0x0800,
        data=bytes(ip),
    )
    pcap = _write_pcap(tmp_path, [bytes(eth)])
    assert scan_pcap(pcap) == []
