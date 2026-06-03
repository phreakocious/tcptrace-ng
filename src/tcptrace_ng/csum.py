"""Independent per-packet TCP checksum verification.

tcptrace's `--checksum` flag *drops* bad-checksum packets from analysis,
which is the wrong behavior when the capture was taken on a host with
NIC TX checksum offload: outbound packets carry stub/zero checksums and
get filtered out, hiding half the connection. We never want that
filtering; we want per-packet `bad_csum` events surfaced as anomalies,
direction-aware so the consumer can reason about offload (TX side, near
the capture host) vs real corruption (RX side, paths upstream).

The scanner walks the pcap once with dpkt, computes the expected TCP
checksum for every IPv4 TCP segment, and yields events for the ones
that don't match — keyed by `(src_ip:port, dst_ip:port)` so the caller
can route them per direction. IPv6 and non-TCP frames are skipped.

**Partial-offload filter.** Linux/Windows TX checksum offload writes the
pseudo-header *partial* checksum into the TCP cksum field before
handing the frame to the NIC, which then adds the body's contribution
on egress. Captures taken before the NIC fixes the checksum (e.g.
`tcpdump` on the sending host, or LRO-coalesced inbound on the
receiving host) carry that partial value. Wireshark 4.2+ recognises
this and marks such packets "valid but partial." We do the same here:
if the on-wire checksum equals the pseudo-header partial sum, it's a
known-good offload artifact, not a real bad checksum, and we suppress
the event entirely so the chart only flags packets a TCP stack would
actually drop.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from pathlib import Path

import dpkt

from .pcap_io import open_reader

CSUM_VERSION = "1"

_DLT_EN10MB = 1
_IPPROTO_TCP = 6


@dataclass(frozen=True)
class CsumEvent:
    time: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int


def scan_pcap(pcap_path: Path, max_frames: int | None = None) -> list[CsumEvent]:
    """Return one CsumEvent for each IPv4 TCP segment with a bad checksum.

    Optional `max_frames` caps the scan for very large captures. None walks
    the whole file. Frames we can't parse (truncated, non-IPv4, non-TCP) are
    silently skipped — they're not in the user's TCP-conn view either.
    """
    events: list[CsumEvent] = []
    with pcap_path.open("rb") as f:
        try:
            reader = open_reader(f)
        except (ValueError, dpkt.dpkt.NeedData):
            return events
        if reader.datalink() != _DLT_EN10MB:
            return events
        for i, (ts, buf) in enumerate(reader):
            if max_frames is not None and i >= max_frames:
                break
            event = _verify_one(ts, buf)
            if event is not None:
                events.append(event)
    return events


def _verify_one(ts: float, buf: bytes) -> CsumEvent | None:
    """Parse one frame; return a CsumEvent if its TCP checksum is wrong.

    Handles plain Ethernet, 802.1Q VLAN tags (dpkt unwraps the inner IP but the
    4-byte tag stays in the wire bytes, so the L2 header is 18 B, not 14), and
    both IPv4 and IPv6 — each with its own checksum pseudo-header. This matches
    offload.py, which already accepts tagged / v6 traffic; skipping them here hid
    real corruption on those captures.
    """
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return None
    ip = eth.data
    # dpkt only sets `vlan_tags` when 802.1Q tags are present; each adds 4 B.
    l2_len = 14 + 4 * len(getattr(eth, "vlan_tags", ()))
    if isinstance(ip, dpkt.ip.IP):
        if ip.p != _IPPROTO_TCP:
            return None
        ip_hdr_len = ip.hl * 4
        tcp_len = ip.len - ip_hdr_len  # IP total length minus the IP header
        is_v6 = False
    elif isinstance(ip, dpkt.ip6.IP6):
        # Only the no-extension-header case (next header is TCP directly). With
        # extension headers the TCP offset isn't a fixed 40 B; skip rather than
        # risk a wrong slice and a false bad_csum.
        if ip.nxt != _IPPROTO_TCP:
            return None
        ip_hdr_len = 40
        tcp_len = ip.plen  # IPv6 payload length (no ext headers here)
        is_v6 = True
    else:
        return None

    tcp = ip.data
    if not isinstance(tcp, dpkt.tcp.TCP):
        return None

    tcp_bytes = buf[l2_len + ip_hdr_len :]
    if tcp_len <= 0 or tcp_len > len(tcp_bytes):
        return None
    tcp_bytes = tcp_bytes[:tcp_len]  # trim any FCS/padding past the IP payload
    if len(tcp_bytes) < 20:
        return None

    on_wire_sum = struct.unpack("!H", tcp_bytes[16:18])[0]
    if on_wire_sum == _compute_tcp_checksum(ip.src, ip.dst, tcp_bytes, is_v6):
        return None
    # Partial-offload short-circuit: if the on-wire checksum is the bare
    # pseudo-header sum, the NIC hadn't folded in the body yet (TX offload
    # captured pre-egress, or RX after LRO coalescing). Wireshark 4.2+ treats
    # this as "valid but partial"; so do we.
    if on_wire_sum == _pseudo_header_partial(ip.src, ip.dst, len(tcp_bytes), is_v6):
        return None

    return CsumEvent(
        time=float(ts),
        src_ip=_ip_str(ip.src, is_v6),
        src_port=tcp.sport,
        dst_ip=_ip_str(ip.dst, is_v6),
        dst_port=tcp.dport,
    )


def _ip_str(addr: bytes, is_v6: bool) -> str:
    return socket.inet_ntop(socket.AF_INET6 if is_v6 else socket.AF_INET, addr)


def _pseudo_header(src: bytes, dst: bytes, tcp_len: int, is_v6: bool) -> bytes:
    """The TCP checksum pseudo-header bytes for IPv4 or IPv6.

    IPv4 (RFC 793): src(4) dst(4) zero(1) proto(1) len(2) — 12 B.
    IPv6 (RFC 2460): src(16) dst(16) upper-layer-len(4) zero(3) next-hdr(1) — 40 B.
    """
    if is_v6:
        return src + dst + struct.pack("!I", tcp_len) + struct.pack("!BBBB", 0, 0, 0, _IPPROTO_TCP)
    return src + dst + struct.pack("!BBH", 0, _IPPROTO_TCP, tcp_len)


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total & 0xFFFF


def _pseudo_header_partial(src: bytes, dst: bytes, tcp_len: int, is_v6: bool = False) -> int:
    """Folded ones-complement sum of the pseudo-header alone — the value
    Linux/Windows write into the TCP cksum field before TX checksum offload
    completes."""
    return _ones_complement_sum(_pseudo_header(src, dst, tcp_len, is_v6))


def _compute_tcp_checksum(src: bytes, dst: bytes, tcp_bytes: bytes, is_v6: bool = False) -> int:
    """Standard TCP checksum over the (IPv4 or IPv6) pseudo-header + TCP segment.

    `tcp_bytes` is the on-wire TCP header+payload with the checksum field left in
    place; we mask it to zero in the computation."""
    zeroed = tcp_bytes[:16] + b"\x00\x00" + tcp_bytes[18:]
    data = _pseudo_header(src, dst, len(zeroed), is_v6) + zeroed
    return (~_ones_complement_sum(data)) & 0xFFFF
