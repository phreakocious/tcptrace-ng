"""Detect NIC offload artifacts that distort tcptrace analysis.

Modern Linux/BSD NICs and stacks transparently coalesce TCP segments before
they reach pcap. tcptrace has no concept of this and reports the captured
segment size as if it were the on-wire MSS.

  - Outbound: LSO/GSO/TSO — the kernel hands the NIC a single 32-64 KB
    "segment" that the NIC slices into MTU-sized frames on the wire.
  - Inbound: LRO/GRO — NIC/driver merges arriving frames into one logical
    segment before delivery to the stack and pcap.

Either way the pcap shows segments much larger than the on-wire MTU, which
distorts the per-connection summary's MSS, time-sequence plots (giant
vertical jumps instead of MTU-stepped staircases), and retransmit
detection (coalesced retransmissions hide). Per-ACK RTT is largely
unaffected because RTT is measured per ACK at the sender's egress.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import dpkt

from .pcap_io import open_reader

OFFLOAD_VERSION = "1"

# A TCP payload larger than the on-wire MTU can't have crossed an ordinary link
# un-sliced — the kernel hadn't segmented it yet on TX (LSO/GSO/TSO) or the NIC
# re-coalesced on RX (LRO/GRO). The path MTU isn't recorded in the pcap, so the
# oversized threshold adapts to the capture's own typical frame size (see
# _oversized_threshold): floored at the standard 1500 B Ethernet MTU and capped
# at the largest jumbo frame. Without this a jumbo path (9000 MTU) would read as
# all-offloaded — false-flagging every capture in DC/storage environments.
_STANDARD_MTU_PAYLOAD = 1500
_MAX_JUMBO_PAYLOAD = 9216
_SCAN_FRAMES = 1000
_DLT_EN10MB = 1


@dataclass
class OffloadReport:
    frames_scanned: int = 0
    tcp_segments: int = 0
    oversized_segments: int = 0
    max_payload: int = 0
    warnings: list[str] = field(default_factory=list)


def detect_offload(pcap_path: Path, max_frames: int = _SCAN_FRAMES) -> OffloadReport:
    """Scan a bounded prefix of `pcap_path` and report NIC offload signs.

    Bounded so this stays a fast pre-flight check; the threshold is picked
    high enough that a single oversized payload is signal, not noise.
    """
    report = OffloadReport()
    payloads: list[int] = []
    try:
        with pcap_path.open("rb") as f:
            reader = open_reader(f)
            if reader.datalink() != _DLT_EN10MB:
                return report
            for i, (_ts, buf) in enumerate(reader):
                if i >= max_frames:
                    break
                report.frames_scanned += 1
                payload_len = _tcp_payload_len(buf)
                if payload_len is None:
                    continue
                report.tcp_segments += 1
                report.max_payload = max(report.max_payload, payload_len)
                payloads.append(payload_len)
    except (dpkt.dpkt.NeedData, ValueError, OSError):
        # Truncated / unreadable pcap: return what we got so far.
        pass

    threshold = _oversized_threshold(payloads)
    report.oversized_segments = sum(1 for p in payloads if p > threshold)
    if report.oversized_segments > 0:
        report.warnings.append(
            f"NIC offload (LSO/GSO/TSO/LRO/GRO): "
            f"{report.oversized_segments} of {report.tcp_segments} TCP segments "
            f"exceed {threshold} B (max {report.max_payload} B). "
            f"MSS in the per-connection summary, time-sequence staircases, and "
            f"retransmit detection are unreliable on this capture."
        )
    return report


def _oversized_threshold(payloads: list[int]) -> int:
    """On-wire-MTU estimate above which a TCP payload is NIC-coalesced.

    The path MTU isn't in the pcap, so estimate the link's normal max frame from
    the capture's own median data payload — floored at the standard 1500 B MTU
    and capped at the largest jumbo frame (~9216 B). This stops every jumbo-frame
    segment from reading as offload while still catching coalesced super-segments;
    any payload above the jumbo ceiling can't have crossed a link un-sliced, so
    it is offload regardless of the capture's size distribution.
    """
    data = sorted(p for p in payloads if p > 0)
    median = data[len(data) // 2] if data else 0
    return min(max(_STANDARD_MTU_PAYLOAD, median), _MAX_JUMBO_PAYLOAD)


def _tcp_payload_len(buf: bytes) -> int | None:
    """Return the on-wire TCP payload byte length, or None if `buf` is not TCP.

    Derived from the IP total-length field, NOT len(tcp.data): dpkt clamps
    tcp.data to the bytes actually captured, so on a snaplen-truncated capture
    (`tcpdump -s`) an offloaded super-segment reads short and slips under the
    threshold. We take the max of the on-wire length and the captured length,
    so the TX-side TSO case — where the IP length field can be left 0 for the
    NIC to fill while the full pre-slice payload is captured — is still caught.
    """
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return None
    ip = eth.data
    if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return None
    tcp = ip.data
    if not isinstance(tcp, dpkt.tcp.TCP):
        return None
    tcp_hdr_len = tcp.off * 4
    if isinstance(ip, dpkt.ip.IP):
        on_wire = ip.len - ip.hl * 4 - tcp_hdr_len
    else:  # IPv6: plen is everything after the 40 B fixed header.
        on_wire = ip.plen - tcp_hdr_len
    return max(on_wire, len(tcp.data))
