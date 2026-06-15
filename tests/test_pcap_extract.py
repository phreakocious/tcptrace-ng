"""Coverage for the per-conversation pcap extractor."""

from __future__ import annotations

import io
import socket
from pathlib import Path

import dpkt

from tcptrace_ng.pcap_extract import extract_conversation


def _tcp_frame(
    src_ip: str,
    sport: int,
    dst_ip: str,
    dport: int,
    *,
    payload: bytes = b"",
    flags: int = 0x10,  # ACK
) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    tcp = dpkt.tcp.TCP(
        sport=sport, dport=dport, seq=1, ack=0, off_x2=0x50, flags=flags, data=payload
    )
    ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_TCP, data=bytes(tcp))
    ip.len = 20 + 20 + len(payload)
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\xaa\xbb\xcc\xdd\xee\xff",
        type=0x0800,
        data=bytes(ip),
    )
    return bytes(eth)


def _tcp_frame_v6(
    src_ip: str,
    sport: int,
    dst_ip: str,
    dport: int,
    *,
    payload: bytes = b"",
) -> bytes:
    src = socket.inet_pton(socket.AF_INET6, src_ip)
    dst = socket.inet_pton(socket.AF_INET6, dst_ip)
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=1, ack=0, off_x2=0x50, flags=0x10, data=payload)
    ip = dpkt.ip6.IP6(src=src, dst=dst, nxt=dpkt.ip.IP_PROTO_TCP, data=bytes(tcp))
    ip.plen = 20 + len(payload)
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\xaa\xbb\xcc\xdd\xee\xff",
        type=0x86DD,
        data=bytes(ip),
    )
    return bytes(eth)


def _write_pcap(tmp_path: Path, frames: list[bytes], *, name: str = "x.pcap") -> Path:
    out = tmp_path / name
    with out.open("wb") as f:
        w = dpkt.pcap.Writer(f, linktype=1, snaplen=65535)
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


def _read_back(pcap_bytes: bytes) -> list[bytes]:
    """Parse classic-pcap bytes and return the wire frames in order."""
    return [buf for _ts, buf in dpkt.pcap.Reader(io.BytesIO(pcap_bytes))]


def test_keeps_only_requested_conversation(tmp_path):
    a, b = _tcp_frame("10.0.0.1", 50000, "10.0.0.2", 443), _tcp_frame(
        "10.0.0.2", 443, "10.0.0.1", 50000
    )
    other = _tcp_frame("10.0.0.3", 1234, "10.0.0.4", 80)
    pcap = _write_pcap(tmp_path, [a, other, b, other, a])

    out = extract_conversation(pcap, "10.0.0.1:50000", "10.0.0.2:443")
    frames = _read_back(out)
    assert frames == [a, b, a]


def test_either_direction_matches(tmp_path):
    fwd = _tcp_frame("10.0.0.1", 50000, "10.0.0.2", 443)
    rev = _tcp_frame("10.0.0.2", 443, "10.0.0.1", 50000)
    pcap = _write_pcap(tmp_path, [fwd, rev])

    # Swapping host_a/host_b shouldn't change the result.
    a_first = extract_conversation(pcap, "10.0.0.1:50000", "10.0.0.2:443")
    b_first = extract_conversation(pcap, "10.0.0.2:443", "10.0.0.1:50000")
    assert _read_back(a_first) == [fwd, rev]
    assert _read_back(b_first) == [fwd, rev]


def test_drops_other_5tuples(tmp_path):
    target = _tcp_frame("10.0.0.1", 50000, "10.0.0.2", 443)
    # Same IPs, different port — separate connection.
    sibling = _tcp_frame("10.0.0.1", 50001, "10.0.0.2", 443)
    # Same ports, different IPs.
    cousin = _tcp_frame("10.0.0.3", 50000, "10.0.0.2", 443)
    pcap = _write_pcap(tmp_path, [target, sibling, cousin])

    out = extract_conversation(pcap, "10.0.0.1:50000", "10.0.0.2:443")
    assert _read_back(out) == [target]


def test_drops_non_tcp_frames(tmp_path):
    target = _tcp_frame("10.0.0.1", 50000, "10.0.0.2", 443)
    # UDP between the same endpoints — must be dropped.
    udp = dpkt.udp.UDP(sport=50000, dport=443, data=b"x")
    udp.ulen = 8 + 1
    ip = dpkt.ip.IP(
        src=socket.inet_aton("10.0.0.1"),
        dst=socket.inet_aton("10.0.0.2"),
        p=dpkt.ip.IP_PROTO_UDP,
        data=bytes(udp),
    )
    ip.len = 20 + len(bytes(udp))
    udp_frame = bytes(
        dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55",
            dst=b"\xaa\xbb\xcc\xdd\xee\xff",
            type=0x0800,
            data=bytes(ip),
        )
    )
    pcap = _write_pcap(tmp_path, [target, udp_frame])

    out = extract_conversation(pcap, "10.0.0.1:50000", "10.0.0.2:443")
    assert _read_back(out) == [target]


def test_reads_pcapng_input(tmp_path):
    """The extractor must handle pcapng — that's what modern capture tools write."""
    a = _tcp_frame("10.0.0.1", 50000, "10.0.0.2", 443)
    b = _tcp_frame("10.0.0.2", 443, "10.0.0.1", 50000)
    pcap = _write_pcapng(tmp_path, [a, b])

    out = extract_conversation(pcap, "10.0.0.1:50000", "10.0.0.2:443")
    assert _read_back(out) == [a, b]


def test_output_is_classic_pcap_not_pcapng(tmp_path):
    a = _tcp_frame("10.0.0.1", 50000, "10.0.0.2", 443)
    pcap = _write_pcapng(tmp_path, [a])

    out = extract_conversation(pcap, "10.0.0.1:50000", "10.0.0.2:443")
    # Classic-pcap magic, either endianness, either timestamp resolution.
    assert out[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1")


def test_ipv6_endpoints(tmp_path):
    a = _tcp_frame_v6("2001:db8::1", 50000, "2001:db8::2", 443)
    b = _tcp_frame_v6("2001:db8::2", 443, "2001:db8::1", 50000)
    pcap = _write_pcap(tmp_path, [a, b])

    out = extract_conversation(pcap, "2001:db8::1:50000", "2001:db8::2:443")
    assert _read_back(out) == [a, b]


def test_ipv4_mapped_ipv6_with_tcptrace_quirk(tmp_path):
    """tcptrace formats `::ffff:1.2.3.4` as `:ffff:0102:0304` (single leading
    colon). The extractor must still match the real `::ffff:1.2.3.4` frames."""
    a = _tcp_frame_v6("2001:db8::1", 50000, "::ffff:188.111.4.158", 443)
    b = _tcp_frame_v6("::ffff:188.111.4.158", 443, "2001:db8::1", 50000)
    pcap = _write_pcap(tmp_path, [a, b])

    # tcptrace-format endpoint (single leading colon, hex-encoded v4 octets).
    out = extract_conversation(pcap, "2001:db8::1:50000", ":ffff:bc6f:049e:443")
    assert _read_back(out) == [a, b]


def test_empty_when_endpoints_unparseable(tmp_path):
    a = _tcp_frame("10.0.0.1", 50000, "10.0.0.2", 443)
    pcap = _write_pcap(tmp_path, [a])

    # Missing port — _split_endpoint returns None.
    assert extract_conversation(pcap, "10.0.0.1", "10.0.0.2:443") == b""
    # Bogus IP — _canon returns None.
    assert extract_conversation(pcap, "not-an-ip:1", "10.0.0.2:443") == b""
