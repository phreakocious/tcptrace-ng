"""Coverage for the NIC-offload detector."""

from __future__ import annotations

from pathlib import Path

import dpkt

from tcptrace_ng.offload import detect_offload


def _tcp_frame(payload_len: int) -> bytes:
    """An Ethernet/IPv4/TCP frame whose TCP payload is exactly `payload_len`."""
    tcp = dpkt.tcp.TCP(
        sport=12345,
        dport=80,
        seq=1,
        ack=0,
        off_x2=0x50,
        flags=0x10,
        data=b"\x00" * payload_len,
    )
    ip = dpkt.ip.IP(
        src=b"\x0a\x00\x00\x01",
        dst=b"\x0a\x00\x00\x02",
        p=dpkt.ip.IP_PROTO_TCP,
        data=bytes(tcp),
    )
    ip.len = 20 + 20 + payload_len
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\xaa\xbb\xcc\xdd\xee\xff",
        type=0x0800,
        data=bytes(ip),
    )
    return bytes(eth)


def _udp_frame() -> bytes:
    """An Ethernet/IPv4/UDP frame — must not register as TCP."""
    udp = dpkt.udp.UDP(sport=12345, dport=53, data=b"\x00" * 32)
    udp.ulen = 8 + 32
    ip = dpkt.ip.IP(
        src=b"\x0a\x00\x00\x01",
        dst=b"\x0a\x00\x00\x02",
        p=dpkt.ip.IP_PROTO_UDP,
        data=bytes(udp),
    )
    ip.len = 20 + 8 + 32
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\xaa\xbb\xcc\xdd\xee\xff",
        type=0x0800,
        data=bytes(ip),
    )
    return bytes(eth)


def _write_pcap(tmp_path: Path, frames: list[bytes], name: str = "x.pcap") -> Path:
    out = tmp_path / name
    with out.open("wb") as f:
        w = dpkt.pcap.Writer(f, linktype=1)
        for i, fr in enumerate(frames):
            w.writepkt(fr, ts=1000.0 + i * 0.001)
    return out


def test_detect_offload_finds_no_offload_on_mtu_traffic(tmp_path):
    pcap = _write_pcap(tmp_path, [_tcp_frame(1400) for _ in range(5)])
    rep = detect_offload(pcap)
    assert rep.tcp_segments == 5
    assert rep.oversized_segments == 0
    assert rep.max_payload == 1400
    assert rep.warnings == []


def test_detect_offload_flags_oversized_segment(tmp_path):
    pcap = _write_pcap(
        tmp_path,
        [_tcp_frame(1400), _tcp_frame(32768), _tcp_frame(1400)],
    )
    rep = detect_offload(pcap)
    assert rep.tcp_segments == 3
    assert rep.oversized_segments == 1
    assert rep.max_payload == 32768
    assert len(rep.warnings) == 1
    assert "32768" in rep.warnings[0]
    assert "1500" in rep.warnings[0]
    assert "LSO/GSO/TSO/LRO/GRO" in rep.warnings[0]


def test_detect_offload_ignores_non_tcp_frames(tmp_path):
    pcap = _write_pcap(tmp_path, [_udp_frame() for _ in range(3)])
    rep = detect_offload(pcap)
    assert rep.frames_scanned == 3
    assert rep.tcp_segments == 0
    assert rep.warnings == []


def test_detect_offload_bounded_by_max_frames(tmp_path):
    # 50 frames, all "offloaded" — but we cap the scan at 5.
    pcap = _write_pcap(tmp_path, [_tcp_frame(8000) for _ in range(50)])
    rep = detect_offload(pcap, max_frames=5)
    assert rep.frames_scanned == 5
    assert rep.tcp_segments == 5
    assert rep.oversized_segments == 5


def test_detect_offload_returns_empty_for_non_ethernet_linktype(tmp_path):
    """SLL/raw/Linux cooked linktypes pass through unscanned (we'd need
    different framing to extract TCP payload sizes safely)."""
    out = tmp_path / "x.pcap"
    with out.open("wb") as f:
        # linktype 113 = LINUX_SLL
        w = dpkt.pcap.Writer(f, linktype=113)
        w.writepkt(b"\x00" * 64, ts=1.0)
    rep = detect_offload(out)
    assert rep.frames_scanned == 0
    assert rep.warnings == []


def test_detect_offload_handles_truncated_pcap(tmp_path):
    out = tmp_path / "trunc.pcap"
    out.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 8)  # half a pcap header
    rep = detect_offload(out)
    assert rep.warnings == []


def test_detect_offload_handles_ipv6(tmp_path):
    """IPv6+TCP payloads must trigger the same threshold logic as v4."""
    tcp = dpkt.tcp.TCP(
        sport=12345,
        dport=80,
        seq=1,
        ack=0,
        off_x2=0x50,
        flags=0x10,
        data=b"\x00" * 16384,
    )
    ip6 = dpkt.ip6.IP6(
        src=b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01",
        dst=b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x02",
        nxt=dpkt.ip.IP_PROTO_TCP,
        data=bytes(tcp),
    )
    ip6.plen = 20 + 16384
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\xaa\xbb\xcc\xdd\xee\xff",
        type=0x86DD,
        data=bytes(ip6),
    )
    pcap = _write_pcap(tmp_path, [bytes(eth)])
    rep = detect_offload(pcap)
    assert rep.tcp_segments == 1
    assert rep.oversized_segments == 1
    assert rep.max_payload == 16384
