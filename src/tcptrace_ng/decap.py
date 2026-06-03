"""Strip outer tunnel encapsulations so tcptrace sees the inner TCP flow.

tcptrace 6.6.7 knows IPv4/IPv6 + TCP/UDP/ICMP and stops there. Modern pcaps
from cloud and SDN environments routinely wrap real traffic in one of:

  - Geneve  (UDP/6081, RFC 8926) -- NSX, OVN/OVS, AWS
  - VXLAN   (UDP/4789, RFC 7348) -- NSX-V, Kubernetes CNIs
  - GRE     (IP proto 47, RFC 2784/2890) -- classic tunneling, NVGRE, EoGRE

We detect by scanning the first few hundred frames; if any encap is present,
we rewrite the pcap once with outer headers removed and let the runner feed
tcptrace the decapsulated copy. Bare-IP inners get a synthetic Ethernet
header so the output stays DLT_EN10MB.

Only DLT_EN10MB (linktype 1) inputs are supported; other linktypes pass
through unchanged.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

import dpkt

from .pcap_io import open_reader

# Schema version: bump when decap output semantics change so caches invalidate.
DECAP_VERSION = "1"

GENEVE_PORT = 6081
VXLAN_PORT = 4789

ETH_TYPE_IP = 0x0800
ETH_TYPE_IPV6 = 0x86DD
ETH_TYPE_TEB = 0x6558  # Transparent Ethernet Bridging (inner is full L2 frame)

DLT_EN10MB = 1
DETECT_FRAMES = 200

_FAKE_MAC = b"\x02\x00\x00\x00\x00\x00"


@dataclass
class DecapResult:
    frames_total: int = 0
    frames_decapped: int = 0
    encaps: set[str] = field(default_factory=set)


def detect_encaps(pcap_path: Path, max_frames: int = DETECT_FRAMES) -> set[str]:
    """Return the set of encap kinds found in the first `max_frames` frames.

    Cheap, bounded scan. Returns an empty set for plain captures or for
    pcaps whose linktype we don't decap.
    """
    found: set[str] = set()
    try:
        with pcap_path.open("rb") as f:
            reader = open_reader(f)
            if reader.datalink() != DLT_EN10MB:
                return found
            for i, (_ts, buf) in enumerate(reader):
                if i >= max_frames:
                    break
                kind = _classify_outer(buf)
                if kind:
                    found.add(kind)
    except (dpkt.dpkt.NeedData, ValueError, OSError):
        # truncated pcap or unreadable; treat as no encap detected
        pass
    return found


def decap_pcap(in_path: Path, out_path: Path) -> DecapResult:
    """Rewrite `in_path` to `out_path` with outer encaps stripped.

    Frames without a recognized outer encap are written through unchanged.
    Output keeps DLT_EN10MB; bare-IP inners get a synthetic Ethernet header.
    """
    result = DecapResult()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with in_path.open("rb") as fin, out_path.open("wb") as fout:
        reader = open_reader(fin)
        if reader.datalink() != DLT_EN10MB:
            # Just copy through; nothing to do for non-Ethernet linktypes.
            writer = dpkt.pcap.Writer(fout, linktype=reader.datalink())
            for ts, buf in reader:
                writer.writepkt(buf, ts)
                result.frames_total += 1
            return result
        writer = dpkt.pcap.Writer(fout, linktype=DLT_EN10MB)
        for ts, buf in reader:
            result.frames_total += 1
            inner, kind = _strip_outer(buf)
            if inner is None:
                writer.writepkt(buf, ts)
                continue
            result.frames_decapped += 1
            result.encaps.add(kind)
            writer.writepkt(inner, ts)
    return result


def _classify_outer(buf: bytes) -> str | None:
    """Return encap kind for `buf`, or None. Detection only (no payload parse)."""
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return None
    ip = eth.data
    if isinstance(ip, dpkt.ip.IP):
        proto = ip.p
    elif isinstance(ip, dpkt.ip6.IP6):
        proto = ip.nxt
    else:
        return None
    if proto == dpkt.ip.IP_PROTO_GRE:
        return "gre"
    if proto == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
        dport = ip.data.dport
        if dport == GENEVE_PORT:
            return "geneve"
        if dport == VXLAN_PORT:
            return "vxlan"
    return None


def _strip_outer(buf: bytes) -> tuple[bytes | None, str | None]:
    """Return (inner_eth_frame, kind) if `buf` carries a recognized encap, else (None, None)."""
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return None, None
    ip = eth.data
    if isinstance(ip, dpkt.ip.IP):
        proto = ip.p
    elif isinstance(ip, dpkt.ip6.IP6):
        proto = ip.nxt
    else:
        return None, None

    if proto == dpkt.ip.IP_PROTO_GRE:
        inner = _unwrap_gre(bytes(ip.data))
        return (inner, "gre") if inner else (None, None)

    if proto == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
        udp = ip.data
        payload = bytes(udp.data)
        if udp.dport == GENEVE_PORT:
            inner = _unwrap_geneve(payload)
            return (inner, "geneve") if inner else (None, None)
        if udp.dport == VXLAN_PORT:
            inner = _unwrap_vxlan(payload)
            return (inner, "vxlan") if inner else (None, None)
    return None, None


def _unwrap_geneve(payload: bytes) -> bytes | None:
    """Strip the Geneve header. Returns the inner Ethernet frame, or None on bad input."""
    if len(payload) < 8:
        return None
    ver_optlen, _flags, proto_type = struct.unpack("!BBH", payload[:4])
    version = ver_optlen >> 6
    if version != 0:
        return None
    opt_len_words = ver_optlen & 0x3F
    hdr_len = 8 + opt_len_words * 4
    if len(payload) < hdr_len:
        return None
    inner = payload[hdr_len:]
    return _wrap_inner(inner, proto_type)


def _unwrap_vxlan(payload: bytes) -> bytes | None:
    """Strip the 8-byte VXLAN header. Returns the inner Ethernet frame, or None."""
    if len(payload) < 8:
        return None
    return payload[8:]


def _unwrap_gre(payload: bytes) -> bytes | None:
    """Strip GRE header (RFC 2784/2890). Returns the inner Ethernet frame, or None."""
    if len(payload) < 4:
        return None
    flags_ver, proto_type = struct.unpack("!HH", payload[:4])
    version = flags_ver & 0x07
    if version != 0:
        return None
    has_csum = bool(flags_ver & 0x8000)
    has_key = bool(flags_ver & 0x2000)
    has_seq = bool(flags_ver & 0x1000)
    hdr_len = 4 + (4 if has_csum else 0) + (4 if has_key else 0) + (4 if has_seq else 0)
    if len(payload) < hdr_len:
        return None
    inner = payload[hdr_len:]
    return _wrap_inner(inner, proto_type)


def _wrap_inner(inner: bytes, proto_type: int) -> bytes | None:
    """Return an Ethernet-framed copy of `inner` based on its protocol type.

    If `proto_type` is TEB (0x6558), `inner` is already a full Ethernet frame.
    Otherwise we prepend a synthetic Ethernet header for IPv4/IPv6 payloads.
    """
    if not inner:
        return None
    if proto_type == ETH_TYPE_TEB:
        return inner
    if proto_type in (ETH_TYPE_IP, ETH_TYPE_IPV6):
        return _FAKE_MAC + _FAKE_MAC + struct.pack("!H", proto_type) + inner
    return None
