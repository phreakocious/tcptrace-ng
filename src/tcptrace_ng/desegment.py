"""Split NIC-offload-coalesced TCP super-segments back into MSS-sized segments.

Runs after decap, before tcptrace. LRO/GRO (RX) and LSO/GSO/TSO (TX) hand the
stack one fat segment that the wire would have carried as N MSS-sized frames.
We reconstruct those N frames so tcptrace's MSS, staircases, segment counts and
retransmit *rate* are correct, and emit a manifest so each fabricated frame is
visible downstream. Only split when MSS is known/inferable (never fabricate
against a guess); otherwise pass the connection through and let the warning
stand. See docs/superpowers/specs/2026-06-03-desegment-offload-design.md.
"""

from __future__ import annotations

import socket
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import dpkt

from .offload import (
    _MAX_JUMBO_PAYLOAD,
    _STANDARD_MTU_PAYLOAD,
    _tcp_payload_len,
)
from .pcap_io import open_reader

DESEGMENT_VERSION = "1"  # bump to invalidate caches when split semantics change


@dataclass(frozen=True)
class CoalesceEvent:
    time: float
    src: str
    dst: str
    parent_seq_start: int
    parent_seq_end: int
    pieces: int
    mss: int
    mss_source: Literal["syn", "inferred"]


@dataclass
class DesegmentResult:
    frames_total: int = 0
    frames_split: int = 0
    pieces_emitted: int = 0
    coalesces: list[CoalesceEvent] = field(default_factory=list)
    residual_conns: set = field(default_factory=set)
    kinds: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# MSS-derivation scan (Task 2)
# ---------------------------------------------------------------------------

_DLT_EN10MB = 1
_SCAN_FRAMES = 100_000  # MSS scan is connection-wide; generous but bounded
_MIN_MODE_COUNT = 4  # a "clear" mode needs at least this many full-size samples
_MODE_DOMINANCE = 0.5  # and must be > half of the sub-threshold samples


def _ip_str(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET if len(raw) == 4 else socket.AF_INET6, raw)


def _endpoint(ip_raw: bytes, port: int) -> str:
    return f"{_ip_str(ip_raw)}:{port}"


def _flow_key(ip, tcp) -> frozenset:
    """Unordered connection key: frozenset of the two host:port endpoints."""
    a = (_ip_str(ip.src), tcp.sport)
    b = (_ip_str(ip.dst), tcp.dport)
    return frozenset((a, b))


def _syn_mss(tcp: dpkt.tcp.TCP) -> int | None:
    """The MSS option value advertised in a SYN/SYN-ACK, or None."""
    try:
        for opt_type, opt_data in dpkt.tcp.parse_opts(tcp.opts):
            if opt_type == dpkt.tcp.TCP_OPT_MSS and len(opt_data) == 2:
                return int.from_bytes(opt_data, "big")
    except Exception:
        return None
    return None


def _parse_tcp(buf: bytes) -> tuple | None:
    """Return (ip, tcp, on_wire_payload_len) or None if `buf` isn't TCP/IP."""
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
    payload_len = _tcp_payload_len(buf)
    return ip, tcp, (payload_len if payload_len is not None else 0)


@dataclass
class MssTable:
    # advertised_mss[endpoint] = the MSS that endpoint advertised in its SYN
    advertised_mss: dict[str, int] = field(default_factory=dict)
    # inferred_mss[endpoint] = modal sub-threshold size of segments SENT BY endpoint
    inferred_mss: dict[str, int] = field(default_factory=dict)

    def slice_mss(self, sender: str, receiver: str) -> tuple[int, str] | None:
        """MSS to slice `sender`->`receiver` data, plus its source, or None (residual)."""
        if receiver in self.advertised_mss:
            return self.advertised_mss[receiver], "syn"
        if sender in self.inferred_mss:
            return self.inferred_mss[sender], "inferred"
        return None


def desegment_pcap(in_path: Path, out_path: Path) -> DesegmentResult:
    """Rewrite `in_path` to `out_path`, splitting oversized TCP data segments.

    Pieces share the parent's timestamp (true to within the coalesce window).
    Connections whose MSS is unknown pass through untouched and are recorded in
    `residual_conns`. Non-Ethernet linktypes copy through.
    """
    result = DesegmentResult()
    table = connection_mss(in_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with in_path.open("rb") as fin, out_path.open("wb") as fout:
        reader = open_reader(fin)
        link = reader.datalink()
        writer = dpkt.pcap.Writer(fout, snaplen=65535, linktype=link)  # 65535: see gotcha 2
        if link != _DLT_EN10MB:
            for ts, buf in reader:
                writer.writepkt(buf, ts)
                result.frames_total += 1
            return result
        for ts, buf in reader:
            result.frames_total += 1
            pieces = _split_frame(buf, ts, table, result)
            if pieces is None:
                writer.writepkt(buf, ts)
            else:
                for piece in pieces:
                    writer.writepkt(piece, ts)
    return result


def _split_frame(buf, ts, table: MssTable, result: DesegmentResult):
    """Return a list of split frame bytes, or None to pass `buf` through."""
    parsed = _parse_tcp(buf)
    if parsed is None:
        return None
    ip, tcp, payload_len = parsed
    if payload_len <= _STANDARD_MTU_PAYLOAD:
        return None  # not coalesced; control/pure-ack/<=MTU
    sender = _endpoint(ip.src, tcp.sport)
    receiver = _endpoint(ip.dst, tcp.dport)
    mss_info = table.slice_mss(sender, receiver)
    if mss_info is None or payload_len <= mss_info[0]:
        if mss_info is None:
            result.residual_conns.add(_flow_key(ip, tcp))
        return None
    mss, source = mss_info
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    data = bytes(tcp.data)
    if len(data) < payload_len:  # snaplen-truncated -> zero-pad
        data = data + b"\x00" * (payload_len - len(data))
    base_seq = tcp.seq
    base_ipid = ip.id if isinstance(ip, dpkt.ip.IP) else 0
    n = -(-payload_len // mss)  # ceil
    pieces: list[bytes] = []
    for i in range(n):
        off = i * mss
        chunk = data[off : off + mss]
        p_eth = dpkt.ethernet.Ethernet(buf)  # fresh copy per piece
        p_ip = p_eth.data
        p_tcp = p_ip.data
        p_tcp.seq = (base_seq + off) & 0xFFFFFFFF
        # PSH only on the last piece; keep ACK, drop nothing else structural.
        if i < n - 1:
            p_tcp.flags &= ~dpkt.tcp.TH_PUSH
        p_tcp.data = chunk
        p_tcp.sum = 0
        if isinstance(p_ip, dpkt.ip.IP):
            p_ip.id = (base_ipid + i) & 0xFFFF
            p_ip.len = p_ip.hl * 4 + len(p_tcp)  # len(tcp) includes header+opts+data
            p_ip.sum = 0
        else:
            p_ip.plen = len(p_tcp)
        pieces.append(bytes(p_eth))  # dpkt recomputes sums on serialize (sum=0)
    result.frames_split += 1
    result.pieces_emitted += n
    result.kinds.add("lro/gro/tso")
    result.coalesces.append(
        CoalesceEvent(
            time=float(ts),
            src=sender,
            dst=receiver,
            parent_seq_start=base_seq,
            parent_seq_end=(base_seq + payload_len) & 0xFFFFFFFF,
            pieces=n,
            mss=mss,
            mss_source=source,
        )
    )
    return pieces


def connection_mss(pcap_path: Path, max_frames: int = _SCAN_FRAMES) -> MssTable:
    """First scan: per-endpoint advertised MSS (SYN option) + modal inference."""
    table = MssTable()
    sub_threshold: dict[str, Counter] = {}
    try:
        with pcap_path.open("rb") as f:
            reader = open_reader(f)
            if reader.datalink() != _DLT_EN10MB:
                return table
            for i, (_ts, buf) in enumerate(reader):
                if i >= max_frames:
                    break
                parsed = _parse_tcp(buf)
                if parsed is None:
                    continue
                ip, tcp, payload_len = parsed
                sender = _endpoint(ip.src, tcp.sport)
                if tcp.flags & dpkt.tcp.TH_SYN:
                    mss = _syn_mss(tcp)
                    if mss:
                        table.advertised_mss[sender] = mss
                if 0 < payload_len <= _MAX_JUMBO_PAYLOAD:
                    sub_threshold.setdefault(sender, Counter())[payload_len] += 1
    except (dpkt.dpkt.NeedData, ValueError, OSError):
        pass
    for sender, counts in sub_threshold.items():
        size, n = counts.most_common(1)[0]
        if (
            size >= 1000  # real MSS is >= ~536; 1000 rejects sub-MSS app-chunk modes
            and n >= _MIN_MODE_COUNT
            and n > _MODE_DOMINANCE * sum(counts.values())
        ):
            table.inferred_mss[sender] = size
    return table
