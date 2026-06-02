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

OFFLOAD_VERSION = "1"

# Standard Ethernet MTU is 1500 B; TCP MSS lives just under that. A TCP
# payload over 1500 B can't have travelled an ordinary link without
# offload — either the kernel hadn't sliced it yet on TX, or the NIC
# re-coalesced on RX. Jumbo-frame deployments (9000 MTU) still trip this
# on the offload path, which is still the finding we care about.
_OFFLOAD_PAYLOAD_THRESHOLD = 1500
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
    try:
        with pcap_path.open("rb") as f:
            reader = dpkt.pcap.Reader(f)
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
                if payload_len > report.max_payload:
                    report.max_payload = payload_len
                if payload_len > _OFFLOAD_PAYLOAD_THRESHOLD:
                    report.oversized_segments += 1
    except (dpkt.dpkt.NeedData, ValueError, OSError):
        # Truncated / unreadable pcap: return what we got so far.
        pass

    if report.oversized_segments > 0:
        report.warnings.append(
            f"NIC offload (LSO/GSO/TSO/LRO/GRO): "
            f"{report.oversized_segments} of {report.tcp_segments} TCP segments "
            f"exceed {_OFFLOAD_PAYLOAD_THRESHOLD} B (max {report.max_payload} B). "
            f"MSS in the per-connection summary, time-sequence staircases, and "
            f"retransmit detection are unreliable on this capture."
        )
    return report


def _tcp_payload_len(buf: bytes) -> int | None:
    """Return the TCP payload byte length, or None if `buf` is not TCP."""
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
    return len(tcp.data)
