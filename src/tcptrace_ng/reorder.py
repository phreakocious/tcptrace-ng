"""Raw-pcap TCP segment classifier — observed-facts layer (Plan 1).

Pure, deterministic. Replays a connection's pre-desegment packets and records
what the trace objectively shows per byte-span. Inference is Plan 2.
"""
from __future__ import annotations

import io
import socket
import struct
from dataclasses import dataclass
from dataclasses import replace as _dc_replace
from typing import Literal

import dpkt

_WRAP = 1 << 32
_HALF = 1 << 31


def seq_diff(a: int, b: int) -> int:
    """Signed forward distance a-b in (-2**31, 2**31] (RFC 1982, 32-bit)."""
    d = (a - b) & (_WRAP - 1)
    return d if d <= _HALF else d - _WRAP


def seq_lt(a: int, b: int) -> bool:
    return seq_diff(a, b) < 0


def seq_gt(a: int, b: int) -> bool:
    return seq_diff(a, b) > 0


def seq_le(a: int, b: int) -> bool:
    return seq_diff(a, b) <= 0


def seq_ge(a: int, b: int) -> bool:
    return seq_diff(a, b) >= 0


@dataclass(frozen=True, slots=True)
class Frame:
    ordinal: int
    time: float
    src: str
    dst: str
    seq: int
    end: int
    payload_len: int
    flags: int
    ack: int
    tsval: int | None
    tsecr: int | None
    ip_id: int | None
    sack_blocks: tuple[tuple[int, int], ...]
    dsack: bool


def _ipport(ip_bytes: bytes, port: int) -> str:
    fam = socket.AF_INET6 if len(ip_bytes) == 16 else socket.AF_INET
    return f"{socket.inet_ntop(fam, ip_bytes)}:{port}"


def _opts(tcp: dpkt.tcp.TCP) -> tuple[int | None, int | None, tuple[tuple[int, int], ...]]:
    tsval = tsecr = None
    sacks: list[tuple[int, int]] = []
    try:
        for opt in dpkt.tcp.parse_opts(tcp.opts):
            if opt is None:            # parse_opts sentinel: malformed/truncated option
                break
            kind, data = opt
            if kind == dpkt.tcp.TCP_OPT_TIMESTAMP and len(data) >= 8:
                tsval, tsecr = struct.unpack("!II", data[:8])
            elif kind == dpkt.tcp.TCP_OPT_SACK and len(data) % 8 == 0:
                for i in range(0, len(data), 8):
                    lo, hi = struct.unpack("!II", data[i:i + 8])
                    sacks.append((lo, hi))
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, struct.error, TypeError, ValueError):
        pass
    return tsval, tsecr, tuple(sacks)


def parse_frames(pcap_bytes: bytes, host_a: str, host_b: str) -> list[Frame]:
    """Parse all TCP frames from pre-filtered pcap bytes; host_a/host_b are accepted for interface compatibility but not used to filter (caller pre-filters to one connection)."""
    frames: list[Frame] = []
    reader = dpkt.pcap.Reader(io.BytesIO(pcap_bytes))
    for ordinal, (ts, buf) in enumerate(reader):
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            continue
        plen = len(tcp.data)
        tsval, tsecr, sacks = _opts(tcp)
        ip_id = ip.id if isinstance(ip, dpkt.ip.IP) else None
        dsack = bool(sacks) and seq_le(sacks[0][1], tcp.ack)
        frames.append(Frame(
            ordinal=ordinal, time=float(ts),
            src=_ipport(ip.src, tcp.sport), dst=_ipport(ip.dst, tcp.dport),
            seq=tcp.seq, end=(tcp.seq + plen) & 0xFFFFFFFF, payload_len=plen,
            flags=tcp.flags, ack=tcp.ack, tsval=tsval, tsecr=tsecr,
            ip_id=ip_id, sack_blocks=sacks, dsack=dsack,
        ))
    return frames


SeqObs = Literal["in_order", "opens_gap", "fills_gap", "overlaps", "partial", "prebaseline"]


@dataclass(frozen=True, slots=True)
class SpanObs:
    frame_ordinal: int
    src: str
    dst: str
    lo: int
    hi: int
    time: float
    sequence_observation: SeqObs
    arrived_below_seen_edge: bool
    evidence: tuple[str, ...] = ()
    receiver_state: Literal["missing_before", "already_had", "unknown"] = "unknown"
    duplicate_observation: bool = False


class _DirState:
    __slots__ = ("baseline", "seen", "snd_max")

    def __init__(self) -> None:
        self.baseline: int | None = None
        self.snd_max: int | None = None
        self.seen: list[tuple[int, int]] = []  # coalesced byte ranges — the true union of seen bytes


def _covered(seen: list[tuple[int, int]], lo: int, hi: int) -> bool:
    return any(seq_le(s, lo) and seq_le(hi, e) for s, e in seen)


def _overlaps_any(seen: list[tuple[int, int]], lo: int, hi: int) -> bool:
    return any(seq_lt(lo, e) and seq_lt(s, hi) for s, e in seen)


def _merge(seen: list[tuple[int, int]], lo: int, hi: int) -> None:
    """Insert [lo, hi) into the seen set, coalescing any overlapping or
    adjacent range so membership tests see the true union of seen bytes."""
    mlo, mhi = lo, hi
    rest: list[tuple[int, int]] = []
    for s, e in seen:
        if seq_le(s, mhi) and seq_le(mlo, e):  # overlap or adjacency
            if seq_lt(s, mlo):
                mlo = s
            if seq_lt(mhi, e):
                mhi = e
        else:
            rest.append((s, e))
    rest.append((mlo, mhi))
    seen[:] = rest


def _classify_span(st: _DirState, lo: int, hi: int) -> SeqObs:
    if st.baseline is not None and seq_lt(lo, st.baseline):
        return "prebaseline"
    if st.snd_max is None or lo == st.snd_max:
        return "in_order"
    if seq_gt(lo, st.snd_max):
        return "opens_gap"
    # lo < snd_max
    if _covered(st.seen, lo, hi):
        return "overlaps"
    if _overlaps_any(st.seen, lo, hi):
        return "partial"
    return "fills_gap"


def replay(frames: list[Frame]) -> list[SpanObs]:
    states: dict[str, _DirState] = {}
    out: list[SpanObs] = []
    for fr in frames:
        if fr.payload_len == 0:
            continue
        st = states.setdefault(fr.src, _DirState())
        if st.baseline is None:
            st.baseline = fr.seq
        kind = _classify_span(st, fr.seq, fr.end)
        below = st.snd_max is not None and seq_lt(fr.seq, st.snd_max)
        out.append(SpanObs(
            frame_ordinal=fr.ordinal, src=fr.src, dst=fr.dst,
            lo=fr.seq, hi=fr.end, time=fr.time,
            sequence_observation=kind, arrived_below_seen_edge=below,
        ))
        _merge(st.seen, fr.seq, fr.end)
        if st.snd_max is None or seq_gt(fr.end, st.snd_max):
            st.snd_max = fr.end
    return out


def receiver_state(frames: list[Frame], spans: list[SpanObs]) -> list[SpanObs]:
    by_ord = {fr.ordinal: fr for fr in frames}
    out: list[SpanObs] = []
    for sp in spans:
        fr = by_ord[sp.frame_ordinal]
        # reverse-direction frames strictly before this span's frame, in capture order
        rev = [g for g in frames
               if g.src == sp.dst and g.dst == sp.src and g.ordinal < fr.ordinal]
        had = any(seq_ge(g.ack, sp.hi) for g in rev) or any(
            seq_le(blo, sp.lo) and seq_le(sp.hi, bhi)
            for g in rev for (blo, bhi) in g.sack_blocks)
        # dup-ACK run at this span's left edge (exclude SYN/FIN control frames)
        dups = sum(1 for g in rev
                   if g.ack == sp.lo and g.payload_len == 0
                   and not (g.flags & (dpkt.tcp.TH_SYN | dpkt.tcp.TH_FIN)))
        sack_above = any(seq_ge(blo, sp.hi) for g in rev for (blo, _bhi) in g.sack_blocks)
        cumack_at_or_below = bool(rev) and not any(seq_gt(g.ack, sp.lo) for g in rev)
        if had:
            state = "already_had"
        elif cumack_at_or_below and (sack_above or dups >= 3):
            state = "missing_before"
        else:
            state = "unknown"
        out.append(_dc_replace(sp, receiver_state=state))
    return out


def duplicate_observation(frames: list[Frame], spans: list[SpanObs],
                          *, dt_epsilon: float = 0.001) -> list[SpanObs]:
    # cheap fingerprint -> list of times already seen, same direction
    seen: dict[tuple, list[float]] = {}
    dup_ords: set[int] = set()
    # frames arrive in ordinal order from parse_frames
    for fr in frames:
        if fr.payload_len == 0:
            continue
        fp = (fr.src, fr.seq, fr.end, fr.flags, fr.ack, fr.payload_len)
        prior = seen.get(fp)
        if prior:
            # lazy: only now do we care about exact payload + Δt
            for ptime in prior:
                if abs(fr.time - ptime) <= dt_epsilon:
                    dup_ords.add(fr.ordinal)
                    break
        seen.setdefault(fp, []).append(fr.time)
    return [_dc_replace(sp, duplicate_observation=(sp.frame_ordinal in dup_ords))
            for sp in spans]


def observe(pcap_bytes: bytes, host_a: str, host_b: str) -> list[SpanObs]:
    """Run parse_frames → replay → receiver_state → duplicate_observation and
    return fully-populated observed-fact spans. This is the surface Plan 2 consumes.

    Input MUST be a single pre-filtered connection (e.g. from extract_conversation).
    """
    frames = parse_frames(pcap_bytes, host_a, host_b)
    if len({f.src for f in frames if f.payload_len > 0}) > 2:
        raise ValueError(
            "observe() expects a single pre-filtered connection; got data from >2 sources"
        )
    spans = replay(frames)
    spans = receiver_state(frames, spans)
    spans = duplicate_observation(frames, spans)
    return spans
