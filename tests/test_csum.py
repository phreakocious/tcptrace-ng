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


def _write_pcapng(tmp_path: Path, frames: list[bytes]) -> Path:
    out = tmp_path / "x.pcapng"
    with out.open("wb") as f:
        w = dpkt.pcapng.Writer(f, snaplen=65535, linktype=1)
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


def test_scan_reads_pcapng(tmp_path):
    """C1: the only source of bad_csum anomalies must read pcapng (the modern
    default). It used dpkt.pcap.Reader, which rejects pcapng, so genuine
    on-wire corruption was never surfaced on the common capture format."""
    payload = b"hello world"
    pcap = _write_pcapng(tmp_path, [_tcp_frame(12345, 80, payload, checksum=0xDEAD)])
    events = scan_pcap(pcap)
    assert len(events) == 1
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


# --------------------------- VLAN + IPv6 (M3) ---------------------------

_V6_SRC = b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01"
_V6_DST = b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x02"


def _vlan_frame(payload: bytes, checksum: int) -> bytes:
    """An 802.1Q-tagged IPv4 TCP frame (18 B L2 header). Inner TCP checksum is
    identical to the untagged case (the pseudo-header uses the IP addresses).
    sport/dport match `_correct_checksum` (12345/80) so its good-sum lines up."""
    inner = _tcp_frame(12345, 80, payload, checksum)  # full Ethernet/IPv4/TCP
    ip_bytes = inner[14:]  # strip the plain 14 B Ethernet header
    # dst(6) src(6) 0x8100 TCI(vid=100) innertype(0x0800) + IP
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x81\x00\x00\x64\x08\x00" + ip_bytes


def _ipv6_frame(payload: bytes, checksum: int) -> bytes:
    tcp = dpkt.tcp.TCP(sport=1111, dport=80, seq=1, ack=0, off_x2=0x50, flags=0x18, data=payload)
    tcp.sum = checksum
    ip6 = dpkt.ip6.IP6(src=_V6_SRC, dst=_V6_DST, nxt=dpkt.ip.IP_PROTO_TCP, data=bytes(tcp))
    ip6.plen = 20 + len(payload)
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\xaa\xbb\xcc\xdd\xee\xff",
        type=0x86DD,
        data=bytes(ip6),
    )
    return bytes(eth)


def _v6_correct_checksum(payload: bytes) -> int:
    """Independent RFC 2460 IPv6 TCP checksum (40 B pseudo-header)."""
    tcp = dpkt.tcp.TCP(sport=1111, dport=80, seq=1, ack=0, off_x2=0x50, flags=0x18, data=payload)
    seg = bytes(tcp)
    zeroed = seg[:16] + b"\x00\x00" + seg[18:]
    pseudo = _V6_SRC + _V6_DST + struct.pack("!I", len(zeroed)) + b"\x00\x00\x00\x06"
    data = pseudo + zeroed
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def test_scan_flags_bad_checksum_on_vlan_frame(tmp_path):
    """M3: 802.1Q-tagged frames must be checksum-verified. The L2 header is 18 B
    (14 + 4 B VLAN tag); skipping tagged traffic (and the hardcoded 14 B offset)
    hid real corruption on tagged captures — while offload.py already handles them."""
    pcap = _write_pcap(tmp_path, [_vlan_frame(b"hello world", checksum=0xDEAD)])
    events = scan_pcap(pcap)
    assert len(events) == 1
    assert events[0].dst_port == 80


def test_scan_skips_good_checksum_on_vlan_frame(tmp_path):
    good = _correct_checksum(b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", b"hello world")
    pcap = _write_pcap(tmp_path, [_vlan_frame(b"hello world", checksum=good)])
    assert scan_pcap(pcap) == []


def test_scan_flags_bad_checksum_on_ipv6_frame(tmp_path):
    """M3: IPv6 TCP must be verified with the 40 B IPv6 pseudo-header."""
    pcap = _write_pcap(tmp_path, [_ipv6_frame(b"hello world", checksum=0xDEAD)])
    events = scan_pcap(pcap)
    assert len(events) == 1
    assert events[0].dst_port == 80
    assert ":" in events[0].src_ip  # rendered as an IPv6 address


def test_scan_skips_good_checksum_on_ipv6_frame(tmp_path):
    good = _v6_correct_checksum(b"hello world")
    pcap = _write_pcap(tmp_path, [_ipv6_frame(b"hello world", checksum=good)])
    assert scan_pcap(pcap) == []
