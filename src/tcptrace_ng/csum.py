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

CSUM_VERSION = "1"

_DLT_EN10MB = 1
_ETH_TYPE_IP = 0x0800
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
            reader = dpkt.pcap.Reader(f)
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
    """Parse one frame; return a CsumEvent if its TCP checksum is wrong."""
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return None
    if eth.type != _ETH_TYPE_IP:
        return None
    ip = eth.data
    if not isinstance(ip, dpkt.ip.IP) or ip.p != _IPPROTO_TCP:
        return None
    tcp = ip.data
    if not isinstance(tcp, dpkt.tcp.TCP):
        return None

    # Slice the wire bytes for the TCP segment. Offsets: 14 Ethernet header
    # (no VLAN handling — frames with 802.1Q would have eth.type != IP and
    # already be skipped above) + IP header length (`ip.hl` is in 32-bit words).
    eth_hdr_len = 14
    ip_hdr_len = ip.hl * 4
    tcp_bytes = buf[eth_hdr_len + ip_hdr_len :]
    # IP's total length tells us how much of the trailing buffer is the IP
    # payload — anything past that is FCS/padding the kernel added.
    ip_total = ip.len
    tcp_len = ip_total - ip_hdr_len
    if tcp_len <= 0 or tcp_len > len(tcp_bytes):
        return None
    tcp_bytes = tcp_bytes[:tcp_len]

    if len(tcp_bytes) < 20:
        return None
    on_wire_sum = struct.unpack("!H", tcp_bytes[16:18])[0]
    expected = _compute_tcp_checksum(ip.src, ip.dst, tcp_bytes)
    if on_wire_sum == expected:
        return None
    # Partial-offload short-circuit: if the on-wire checksum is the bare
    # pseudo-header sum, the NIC hadn't folded in the body yet (TX offload
    # captured pre-egress, or RX after LRO coalescing). Wireshark 4.2+ treats
    # this as "valid but partial"; so do we.
    if on_wire_sum == _pseudo_header_partial(ip.src, ip.dst, len(tcp_bytes)):
        return None

    return CsumEvent(
        time=float(ts),
        src_ip=socket.inet_ntoa(ip.src),
        src_port=tcp.sport,
        dst_ip=socket.inet_ntoa(ip.dst),
        dst_port=tcp.dport,
    )


def _pseudo_header_partial(src: bytes, dst: bytes, tcp_len: int) -> int:
    """Sum of the IPv4 pseudo-header in 16-bit ones-complement arithmetic —
    the value Linux/Windows write into the TCP cksum field before TX
    checksum offload completes."""
    data = src + dst + struct.pack("!BBH", 0, _IPPROTO_TCP, tcp_len)
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total & 0xFFFF


def _compute_tcp_checksum(src: bytes, dst: bytes, tcp_bytes: bytes) -> int:
    """Standard RFC 793 TCP checksum over IPv4 pseudo-header + TCP segment.

    `tcp_bytes` is the on-wire TCP header+payload with the checksum field
    left in place; we mask it to zero in the computation."""
    zeroed = tcp_bytes[:16] + b"\x00\x00" + tcp_bytes[18:]
    pseudo = src + dst + struct.pack("!BBH", 0, _IPPROTO_TCP, len(zeroed))
    data = pseudo + zeroed
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF
