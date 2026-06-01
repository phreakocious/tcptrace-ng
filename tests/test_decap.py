"""Tests for outer-encap detection and stripping.

We build tiny pcaps in memory with dpkt and then ask `decap` to identify
the outer wrapping and rewrite. Verifies the inner TCP segment makes it
through with the right ethertype and is parseable as a normal Ethernet
frame after decap.
"""

from __future__ import annotations

import struct
from pathlib import Path

import dpkt

from tcptrace_ng.decap import (
    ETH_TYPE_IP,
    ETH_TYPE_TEB,
    GENEVE_PORT,
    VXLAN_PORT,
    decap_pcap,
    detect_encaps,
)

# --------------------------- frame builders ---------------------------


def _inner_tcp_eth() -> bytes:
    """A minimal Ethernet+IPv4+TCP frame to use as the 'inner' payload."""
    tcp = dpkt.tcp.TCP(sport=12345, dport=80, seq=1, ack=0, off_x2=0x50, flags=0x02, win=64240)
    ip = dpkt.ip.IP(
        src=b"\x0a\x00\x00\x01",
        dst=b"\x0a\x00\x00\x02",
        p=dpkt.ip.IP_PROTO_TCP,
        data=bytes(tcp),
    )
    ip.len = 20 + 20
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\xaa\xbb\xcc\xdd\xee\xff",
        type=ETH_TYPE_IP,
        data=bytes(ip),
    )
    return bytes(eth)


def _outer_ip_udp(payload: bytes, dport: int) -> bytes:
    udp = dpkt.udp.UDP(sport=33333, dport=dport, data=payload)
    udp.ulen = 8 + len(payload)
    ip = dpkt.ip.IP(
        src=b"\xc0\xa8\x01\x01",
        dst=b"\xc0\xa8\x01\x02",
        p=dpkt.ip.IP_PROTO_UDP,
        data=bytes(udp),
    )
    ip.len = 20 + 8 + len(payload)
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x00\x00\x00\x00\x01",
        dst=b"\x00\x00\x00\x00\x00\x02",
        type=ETH_TYPE_IP,
        data=bytes(ip),
    )
    return bytes(eth)


def _build_geneve_frame() -> bytes:
    inner = _inner_tcp_eth()
    # Ver=0, OptLen=0, no flags, proto=TEB (inner is L2 Ethernet)
    geneve = struct.pack("!BBH", 0x00, 0x00, ETH_TYPE_TEB) + b"\x00\x00\x00\x00"
    return _outer_ip_udp(geneve + inner, GENEVE_PORT)


def _build_vxlan_frame() -> bytes:
    inner = _inner_tcp_eth()
    vxlan = b"\x08\x00\x00\x00" + b"\x00\x00\x01\x00"  # I-flag set, VNI=1
    return _outer_ip_udp(vxlan + inner, VXLAN_PORT)


def _build_gre_frame() -> bytes:
    """GRE wrapping bare IPv4 (most common GRE shape)."""
    tcp = dpkt.tcp.TCP(sport=22, dport=4444, seq=1, ack=0, off_x2=0x50, flags=0x02, win=8192)
    inner_ip = dpkt.ip.IP(
        src=b"\x0a\x00\x00\x05",
        dst=b"\x0a\x00\x00\x06",
        p=dpkt.ip.IP_PROTO_TCP,
        data=bytes(tcp),
    )
    inner_ip.len = 20 + 20
    # GRE header: flags=0, version=0, protocol=IPv4 (0x0800)
    gre = struct.pack("!HH", 0x0000, ETH_TYPE_IP) + bytes(inner_ip)
    outer_ip = dpkt.ip.IP(
        src=b"\x01\x02\x03\x04",
        dst=b"\x05\x06\x07\x08",
        p=dpkt.ip.IP_PROTO_GRE,
        data=gre,
    )
    outer_ip.len = 20 + len(gre)
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x00\x00\x00\x00\x01",
        dst=b"\x00\x00\x00\x00\x00\x02",
        type=ETH_TYPE_IP,
        data=bytes(outer_ip),
    )
    return bytes(eth)


def _write_pcap(tmp_path: Path, frames: list[bytes], name: str = "in.pcap") -> Path:
    out = tmp_path / name
    with out.open("wb") as f:
        writer = dpkt.pcap.Writer(f, linktype=1)  # DLT_EN10MB
        for i, buf in enumerate(frames):
            writer.writepkt(buf, ts=1000.0 + i * 0.001)
    return out


def _read_pcap_frames(p: Path) -> list[bytes]:
    with p.open("rb") as f:
        return [buf for _ts, buf in dpkt.pcap.Reader(f)]


# --------------------------- detection ---------------------------


def test_detect_plain_pcap_returns_empty(tmp_path):
    pcap = _write_pcap(tmp_path, [_inner_tcp_eth()])
    assert detect_encaps(pcap) == set()


def test_detect_geneve(tmp_path):
    pcap = _write_pcap(tmp_path, [_build_geneve_frame()])
    assert detect_encaps(pcap) == {"geneve"}


def test_detect_vxlan(tmp_path):
    pcap = _write_pcap(tmp_path, [_build_vxlan_frame()])
    assert detect_encaps(pcap) == {"vxlan"}


def test_detect_gre(tmp_path):
    pcap = _write_pcap(tmp_path, [_build_gre_frame()])
    assert detect_encaps(pcap) == {"gre"}


def test_detect_mixed(tmp_path):
    pcap = _write_pcap(
        tmp_path,
        [_build_geneve_frame(), _build_vxlan_frame(), _inner_tcp_eth()],
    )
    assert detect_encaps(pcap) == {"geneve", "vxlan"}


def test_detect_ignores_non_ethernet_linktype(tmp_path):
    out = tmp_path / "raw.pcap"
    with out.open("wb") as f:
        writer = dpkt.pcap.Writer(f, linktype=12)  # DLT_RAW
        writer.writepkt(b"\x45" + b"\x00" * 19, ts=1000.0)
    assert detect_encaps(out) == set()


def test_detect_bounded_by_max_frames(tmp_path):
    """Encap after the scan window is not reported."""
    frames = [_inner_tcp_eth()] * 5 + [_build_geneve_frame()]
    pcap = _write_pcap(tmp_path, frames)
    assert detect_encaps(pcap, max_frames=3) == set()
    assert detect_encaps(pcap, max_frames=10) == {"geneve"}


# --------------------------- decap ---------------------------


def test_decap_geneve_emits_inner_eth(tmp_path):
    pcap = _write_pcap(tmp_path, [_build_geneve_frame()])
    out = tmp_path / "out.pcap"
    res = decap_pcap(pcap, out)
    assert res.frames_total == 1
    assert res.frames_decapped == 1
    assert res.encaps == {"geneve"}

    frames = _read_pcap_frames(out)
    assert len(frames) == 1
    eth = dpkt.ethernet.Ethernet(frames[0])
    assert isinstance(eth.data, dpkt.ip.IP)
    ip = eth.data
    assert isinstance(ip.data, dpkt.tcp.TCP)
    assert ip.data.dport == 80


def test_decap_vxlan_emits_inner_eth(tmp_path):
    pcap = _write_pcap(tmp_path, [_build_vxlan_frame()])
    out = tmp_path / "out.pcap"
    res = decap_pcap(pcap, out)
    assert res.encaps == {"vxlan"}
    eth = dpkt.ethernet.Ethernet(_read_pcap_frames(out)[0])
    assert isinstance(eth.data, dpkt.ip.IP)
    assert eth.data.data.dport == 80


def test_decap_gre_synthesizes_eth_for_bare_ip(tmp_path):
    pcap = _write_pcap(tmp_path, [_build_gre_frame()])
    out = tmp_path / "out.pcap"
    res = decap_pcap(pcap, out)
    assert res.encaps == {"gre"}
    inner = _read_pcap_frames(out)[0]
    eth = dpkt.ethernet.Ethernet(inner)
    assert eth.type == ETH_TYPE_IP
    assert isinstance(eth.data, dpkt.ip.IP)
    assert eth.data.data.dport == 4444


def test_decap_passes_through_unrecognized_frames(tmp_path):
    plain = _inner_tcp_eth()
    pcap = _write_pcap(tmp_path, [plain, _build_geneve_frame()])
    out = tmp_path / "out.pcap"
    res = decap_pcap(pcap, out)
    assert res.frames_total == 2
    assert res.frames_decapped == 1
    frames = _read_pcap_frames(out)
    assert len(frames) == 2
    # First frame untouched
    assert frames[0] == plain


def test_decap_non_ethernet_passes_through(tmp_path):
    src = tmp_path / "raw.pcap"
    raw_pkt = b"\x45\x00\x00\x14" + b"\x00" * 16
    with src.open("wb") as f:
        w = dpkt.pcap.Writer(f, linktype=12)
        w.writepkt(raw_pkt, ts=1000.0)
    out = tmp_path / "out.pcap"
    res = decap_pcap(src, out)
    assert res.frames_total == 1
    assert res.frames_decapped == 0
    assert res.encaps == set()


def test_detect_handles_truncated_pcap(tmp_path):
    pcap = tmp_path / "bad.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 10)  # header, no frames
    assert detect_encaps(pcap) == set()
