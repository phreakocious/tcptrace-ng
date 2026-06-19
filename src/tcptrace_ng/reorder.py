"""Raw-pcap TCP segment classifier — observed-facts layer (Plan 1).

Pure, deterministic. Replays a connection's pre-desegment packets and records
what the trace objectively shows per byte-span. Inference is Plan 2.
"""
from __future__ import annotations

import io
import itertools
import socket
import struct
from dataclasses import dataclass
from dataclasses import replace as _dc_replace
from typing import Literal

import dpkt

_WRAP = 1 << 32
_HALF = 1 << 31

_WRAP16 = 1 << 16
_HALF16 = 1 << 15


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


def _seq_diff16(a: int, b: int) -> int:
    """Signed 16-bit serial distance a-b (RFC 1982, for IP-ID)."""
    d = (a - b) & (_WRAP16 - 1)
    return d if d <= _HALF16 else d - _WRAP16


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

GenOrder = Literal["after_successor", "before_successor", "unknown"]
CopyStatus = Literal["original", "retransmission", "probable_capture_duplicate", "unknown"]
OrigVisibility = Literal["seen", "unseen", "unknown"]
RecoveryTrigger = Literal["fast_ack", "rto", "loss_recovery", "unknown"]
DupReported = Literal["yes", "no", "unknown"]
Tier = Literal["hi", "med", "lo"]


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
    generation_order: GenOrder = "unknown"
    copy_status: CopyStatus = "unknown"
    original_visibility: OrigVisibility = "unknown"
    recovery_trigger: RecoveryTrigger = "unknown"
    receiver_duplicate_reported: DupReported = "no"
    tier: Tier = "lo"


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


def _split_range(seen: list[tuple[int, int]], snd_max: int, lo: int, hi: int):
    """Yield (sub_lo, sub_hi, seqobs) across [lo, hi): covered bytes -> overlaps,
    novel bytes at/above snd_max -> in_order, novel below snd_max -> fills_gap."""
    edges = set()
    if seq_lt(lo, snd_max) and seq_lt(snd_max, hi):
        edges.add(snd_max)
    for s, e in seen:
        if seq_lt(lo, s) and seq_lt(s, hi):
            edges.add(s)
        if seq_lt(lo, e) and seq_lt(e, hi):
            edges.add(e)
    points = [lo, *sorted(edges, key=lambda x: seq_diff(x, lo)), hi]
    for a, b in itertools.pairwise(points):
        if a == b:
            continue
        if _covered(seen, a, b):
            yield a, b, "overlaps"
        elif seq_ge(a, snd_max):
            yield a, b, "in_order"
        else:
            yield a, b, "fills_gap"


def _split_partials(spans: list[SpanObs]) -> list[SpanObs]:
    out: list[SpanObs] = []
    seen_by_src: dict[str, list[tuple[int, int]]] = {}
    sndmax_by_src: dict[str, int] = {}
    for sp in spans:
        seen = seen_by_src.setdefault(sp.src, [])
        snd_max = sndmax_by_src.get(sp.src, sp.lo)
        if sp.sequence_observation == "partial":
            for a, b, kind in _split_range(seen, snd_max, sp.lo, sp.hi):
                out.append(_dc_replace(sp, lo=a, hi=b, sequence_observation=kind))
        else:
            out.append(sp)
        _merge(seen, sp.lo, sp.hi)
        if sp.src not in sndmax_by_src or seq_gt(sp.hi, sndmax_by_src[sp.src]):
            sndmax_by_src[sp.src] = sp.hi
    return out


def _successor_map(spans: list[SpanObs]) -> dict[tuple[str, int], int]:
    """(src, start_seq) -> earliest first-observation frame ordinal that opened it."""
    m: dict[tuple[str, int], int] = {}
    for sp in spans:
        if sp.sequence_observation in ("in_order", "opens_gap"):
            key = (sp.src, sp.lo)
            if key not in m or sp.frame_ordinal < m[key]:
                m[key] = sp.frame_ordinal
    return m


def _gen_order_one(fr: Frame, succ: Frame | None) -> GenOrder:
    if succ is None:
        return "unknown"
    ts: GenOrder | None = None
    if fr.tsval is not None and succ.tsval is not None and fr.tsval != succ.tsval:
        ts = "after_successor" if seq_gt(fr.tsval, succ.tsval) else "before_successor"
    ipid: GenOrder | None = None
    if fr.ip_id and succ.ip_id:                       # usable = non-zero on both
        d = _seq_diff16(fr.ip_id, succ.ip_id)
        if d > 0:
            ipid = "after_successor"
        elif d < 0:
            ipid = "before_successor"
    if ts is None and ipid is None:
        return "unknown"
    if ts is not None and ipid is not None and ts != ipid:
        return "unknown"                              # disagreement neutralises
    return ts or ipid                                 # type: ignore[return-value]


def _generation_order(spans: list[SpanObs], by_ord: dict[int, Frame],
                      succ: dict[tuple[str, int], int]) -> list[SpanObs]:
    out: list[SpanObs] = []
    for sp in spans:
        # generation_order is only meaningful for gap-fills (retransmit-of-unseen
        # vs late-original). For in_order/opens_gap/overlaps it is trivially
        # "before_successor" and carries no evidence, so leave it unknown — this
        # also keeps normal baseline spans at default (lo) tier, not med.
        if sp.sequence_observation != "fills_gap":
            out.append(sp)
            continue
        succ_ord = succ.get((sp.src, sp.hi))
        succ_fr = by_ord.get(succ_ord) if succ_ord is not None else None
        go = _gen_order_one(by_ord[sp.frame_ordinal], succ_fr)
        out.append(_dc_replace(sp, generation_order=go))
    return out


def _copy_status_one(sp: SpanObs, seen_before: list[tuple[int, int]]
                     ) -> tuple[CopyStatus, OrigVisibility, tuple[str, ...]]:
    if sp.duplicate_observation:
        return "probable_capture_duplicate", "unknown", ("duplicate_fingerprint",)
    if sp.receiver_state == "already_had":
        vis: OrigVisibility = "seen" if _overlaps_any(seen_before, sp.lo, sp.hi) else "unseen"
        return "retransmission", vis, ("already_had_spurious",)
    if sp.sequence_observation == "overlaps":
        return "retransmission", "seen", ("overlaps_seen",)
    if sp.sequence_observation == "fills_gap":
        if sp.generation_order == "after_successor":
            ev = ("gen_after_successor",)
            if sp.receiver_state == "missing_before":
                ev = (*ev, "receiver_missing_before_fill")
            return "retransmission", "unseen", ev
        return "unknown", "unknown", ()              # before/unknown: timing decides (Task 6)
    if sp.sequence_observation in ("in_order", "opens_gap"):
        return "original", "unknown", ("original_default",)
    return "unknown", "unknown", ()                  # prebaseline / other


def _copy_status(spans: list[SpanObs]) -> list[SpanObs]:
    out: list[SpanObs] = []
    seen_by_src: dict[str, list[tuple[int, int]]] = {}
    for sp in spans:
        seen = seen_by_src.setdefault(sp.src, [])
        cs, vis, ev = _copy_status_one(sp, seen)
        out.append(_dc_replace(sp, copy_status=cs, original_visibility=vis,
                               evidence=sp.evidence + ev))
        _merge(seen, sp.lo, sp.hi)
    return out


MIN_RTO_S = 0.200          # heuristic floor (Linux TCP_RTO_MIN), not ground truth
RTO_RTT_MULT = 3
LATE_ORIG_RTT_MULT = 0.5


def _late_original(sp: SpanObs, by_ord: dict[int, Frame],
                   succ: dict[tuple[str, int], int], rtt: float | None) -> SpanObs:
    if not (sp.sequence_observation == "fills_gap"
            and sp.generation_order == "before_successor"
            and sp.copy_status == "unknown"):
        return sp
    if rtt is None:
        return sp                                     # abstain
    succ_ord = succ.get((sp.src, sp.hi))
    if succ_ord is None:
        return sp
    gap_open = by_ord[succ_ord].time
    if (sp.time - gap_open) <= LATE_ORIG_RTT_MULT * rtt:
        return _dc_replace(sp, copy_status="original", original_visibility="unknown",
                           evidence=(*sp.evidence, "late_original"))
    return sp


def _rto_or_loss(sp: SpanObs, fr: Frame, frames: list[Frame], rtt: float | None) -> RecoveryTrigger:
    orig = next((g for g in frames
                 if g.src == sp.src and g.ordinal < fr.ordinal
                 and g.seq == sp.lo and g.end == sp.hi and g.payload_len > 0), None)
    if orig is None or rtt is None:
        return "loss_recovery"                        # unseen original / no rtt -> not provable
    if (fr.time - orig.time) < max(MIN_RTO_S, RTO_RTT_MULT * rtt):
        return "loss_recovery"
    interval_rev = [g for g in frames if g.src == sp.dst and g.dst == sp.src
                    and orig.time < g.time < fr.time]
    if any(seq_gt(g.ack, sp.lo) for g in interval_rev):
        return "loss_recovery"                        # cum-ACK progressed -> not a clean timeout
    prior_rev = [g for g in frames if g.src == sp.dst and g.dst == sp.src and g.ordinal < fr.ordinal]
    cumack_now = prior_rev[-1].ack if prior_rev else None
    if cumack_now is None or cumack_now != sp.lo:
        return "loss_recovery"                        # not retransmitting the oldest-outstanding byte
    return "rto"


def _recovery_trigger(sp: SpanObs, frames: list[Frame], by_ord: dict[int, Frame],
                      rtt: float | None) -> SpanObs:
    if sp.copy_status != "retransmission":
        return sp
    fr = by_ord[sp.frame_ordinal]
    rev = [g for g in frames if g.src == sp.dst and g.dst == sp.src and g.ordinal < fr.ordinal]
    dups = sum(1 for g in rev if g.ack == sp.lo and g.payload_len == 0
               and not (g.flags & (dpkt.tcp.TH_SYN | dpkt.tcp.TH_FIN)))
    sack_above = any(seq_ge(blo, sp.hi) for g in rev for (blo, _e) in g.sack_blocks)
    if dups >= 3 or sack_above:
        ev = ("dupack_run",) if dups >= 3 else ("sack_hole",)
        return _dc_replace(sp, recovery_trigger="fast_ack", evidence=sp.evidence + ev)
    return _dc_replace(sp, recovery_trigger=_rto_or_loss(sp, fr, frames, rtt))


def _timing(frames: list[Frame], spans: list[SpanObs], by_ord: dict[int, Frame],
            succ: dict[tuple[str, int], int], rtt: float | None) -> list[SpanObs]:
    out: list[SpanObs] = []
    for sp in spans:
        sp = _late_original(sp, by_ord, succ, rtt)
        sp = _recovery_trigger(sp, frames, by_ord, rtt)
        out.append(sp)
    return out


def _dup_reported(sp: SpanObs, spans: list[SpanObs],
                  events: list[tuple[str, str, int, int, float]]) -> DupReported:
    if sp.copy_status != "retransmission":
        return "no"
    if sp.receiver_state == "already_had":
        return "yes"
    best: DupReported = "no"
    for gsrc, gdst, lo, hi, t in events:
        if (gsrc == sp.dst and gdst == sp.src and t >= sp.time
                and seq_le(lo, sp.lo) and seq_le(sp.hi, hi)):
            copies = [o for o in spans
                      if o.src == sp.src and o.copy_status == "retransmission"
                      and seq_le(lo, o.lo) and seq_le(o.hi, hi)]
            if len(copies) <= 1:
                return "yes"
            best = "unknown"
    return best


def _dsack_pass(frames: list[Frame], spans: list[SpanObs]) -> list[SpanObs]:
    events = [(g.src, g.dst, g.sack_blocks[0][0], g.sack_blocks[0][1], g.time)
              for g in frames if g.dsack and g.sack_blocks]
    out: list[SpanObs] = []
    for sp in spans:
        rep = _dup_reported(sp, spans, events)
        ev = (("dsack_confirmed",) if rep == "yes" and sp.receiver_state != "already_had"
              else ("dsack_suspected",) if rep == "unknown" else ())
        out.append(_dc_replace(sp, receiver_duplicate_reported=rep, evidence=sp.evidence + ev))
    return out


def _tier_one(sp: SpanObs) -> Tier:
    if sp.copy_status == "unknown":
        return "lo"
    corroborated = (sp.receiver_state in ("missing_before", "already_had")
                    or sp.receiver_duplicate_reported == "yes")
    if sp.generation_order in ("after_successor", "before_successor"):
        return "hi" if corroborated else "med"
    return "med" if corroborated else "lo"


def _tier(spans: list[SpanObs]) -> list[SpanObs]:
    return [_dc_replace(sp, tier=_tier_one(sp)) for sp in spans]


def infer(frames: list[Frame], spans: list[SpanObs], *, rtt: float | None = None) -> list[SpanObs]:
    """Plan 2 inference: fill the inferred axes on observed spans. Pure and
    deterministic; timing-dependent axes abstain when rtt is None. Pipeline:
    split → generation_order → copy_status → timing → dsack → tier."""
    spans = _split_partials(spans)
    by_ord = {fr.ordinal: fr for fr in frames}
    succ = _successor_map(spans)
    spans = _generation_order(spans, by_ord, succ)
    spans = _copy_status(spans)
    spans = _timing(frames, spans, by_ord, succ, rtt)
    spans = _dsack_pass(frames, spans)
    spans = _tier(spans)
    return spans


def classify(pcap_bytes: bytes, host_a: str, host_b: str,
             *, rtt: float | None = None) -> list[SpanObs]:
    """parse_frames once → observe chain (keeping frames) → infer.

    Does NOT call observe() (which discards frames). Input MUST be a single
    pre-filtered connection.
    """
    frames = parse_frames(pcap_bytes, host_a, host_b)
    if len({f.src for f in frames if f.payload_len > 0}) > 2:
        raise ValueError(
            "classify() expects a single pre-filtered connection; got data from >2 sources"
        )
    spans = replay(frames)
    spans = receiver_state(frames, spans)
    spans = duplicate_observation(frames, spans)
    return infer(frames, spans, rtt=rtt)


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
