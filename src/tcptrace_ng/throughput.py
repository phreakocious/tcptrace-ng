"""Synthesize a ThroughputModelPair from an already-built TsgModelPair.

Pure module — no IO, no subprocess, no plotly. Inputs and outputs are frozen
dataclasses. Consumers are plotly_adapter and app.py's viewport stats panel.
"""
# ruff: noqa: N815 — *_Bps (bytes/sec) vs *_bps (bits/sec) distinction is load-bearing

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Literal

from .stats_parser import ConnStats
from .tcp_inspect import SEVERITY_BY_KIND, TsgModel, TsgModelPair

# Anomaly kinds used by cliff detection (hoisted to avoid rebuilding per loop iteration).
_CLIFF_LOSS_KINDS: frozenset[str] = frozenset({"rto", "fast"})
_CLIFF_SHRINK_KINDS: frozenset[str] = frozenset({"win_shrink", "win_shrink_large"})
_CLIFF_KINDS: frozenset[str] = _CLIFF_LOSS_KINDS | _CLIFF_SHRINK_KINDS


@dataclass(frozen=True)
class RateSample:
    t: float
    goodput_Bps: float
    wire_Bps: float
    max_Bps: float | None
    window_s: float


@dataclass(frozen=True)
class Stall:
    t_start: float
    t_end: float
    duration_s: float
    pending_bytes: int
    rtt_multiple: float
    severity: Literal["info", "warn", "severe"]


@dataclass(frozen=True)
class Cliff:
    t: float
    goodput_before_Bps: float
    goodput_after_Bps: float
    drop_frac: float
    cause_hint: Literal["post-loss", "rwin-shrink", "unknown"]
    severity: Literal["info", "warn", "severe"]


@dataclass(frozen=True)
class DirectionSummary:
    total_payload_bytes: int
    total_wire_bytes: int
    retx_overhead_frac: float
    peak_goodput_Bps: float
    mean_goodput_Bps: float
    p50_goodput_Bps: float
    p95_goodput_Bps: float
    bdp_utilization_frac: float | None
    stall_count: int
    total_stall_s: float
    cliff_count: int


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, round((pct / 100.0) * (len(s) - 1))))
    return s[k]


def _make_summary(
    samples: list[RateSample],
    stalls: list[Stall],
    cliffs: list[Cliff],
    total_payload_bytes: int,
    total_wire_bytes: int,
) -> DirectionSummary:
    retx_frac = 1.0 - total_payload_bytes / total_wire_bytes if total_wire_bytes > 0 else 0.0
    gps = [s.goodput_Bps for s in samples]
    peak = max(gps) if gps else 0.0
    mean = sum(gps) / len(gps) if gps else 0.0
    p50 = _percentile(gps, 50)
    p95 = _percentile(gps, 95)
    # Clip per-sample ratio to [0, 1]. Goodput can briefly exceed the
    # per-window rwin/RTT ceiling when paired-RTT samples in that window are
    # near-zero outliers; clipping avoids reporting >100% BDP utilization.
    bdp_ratios = [
        min(s.goodput_Bps / s.max_Bps, 1.0)
        for s in samples
        if s.max_Bps is not None and s.max_Bps > 0
    ]
    bdp_util = sum(bdp_ratios) / len(bdp_ratios) if bdp_ratios else None
    return DirectionSummary(
        total_payload_bytes=total_payload_bytes,
        total_wire_bytes=total_wire_bytes,
        retx_overhead_frac=retx_frac,
        peak_goodput_Bps=peak,
        mean_goodput_Bps=mean,
        p50_goodput_Bps=p50,
        p95_goodput_Bps=p95,
        bdp_utilization_frac=bdp_util,
        stall_count=len(stalls),
        total_stall_s=sum(st.duration_s for st in stalls),
        cliff_count=len(cliffs),
    )


@dataclass(frozen=True)
class ThroughputModel:
    samples: tuple[RateSample, ...]
    stalls: tuple[Stall, ...]
    cliffs: tuple[Cliff, ...]
    summary: DirectionSummary
    src: str = ""
    dst: str = ""
    # Per-segment time series for exact byte counting in window_stats.
    # Underscore-prefixed: internal coupling between synthesis and viewport stats.
    _payload_seg_times: tuple[float, ...] = field(default=())
    _payload_seg_bytes: tuple[int, ...] = field(default=())
    _wire_seg_times: tuple[float, ...] = field(default=())
    _wire_seg_bytes: tuple[int, ...] = field(default=())

    def window_stats(self, t0: float | None, t1: float | None) -> DirectionSummary:
        sample_times = [s.t for s in self.samples]
        i0 = bisect.bisect_left(sample_times, t0) if t0 is not None else 0
        i1 = bisect.bisect_right(sample_times, t1) if t1 is not None else len(self.samples)
        sliced_samples = list(self.samples[i0:i1])

        sliced_stalls = [
            st for st in self.stalls
            if (t0 is None or st.t_end >= t0) and (t1 is None or st.t_start <= t1)
        ]
        sliced_cliffs = [
            c for c in self.cliffs
            if (t0 is None or c.t >= t0) and (t1 is None or c.t <= t1)
        ]

        # Exact byte counts via bisect into the per-segment time series.
        p_lo = bisect.bisect_left(self._payload_seg_times, t0) if t0 is not None else 0
        p_hi = bisect.bisect_right(self._payload_seg_times, t1) if t1 is not None else len(self._payload_seg_times)
        payload_bytes = sum(self._payload_seg_bytes[p_lo:p_hi])

        w_lo = bisect.bisect_left(self._wire_seg_times, t0) if t0 is not None else 0
        w_hi = bisect.bisect_right(self._wire_seg_times, t1) if t1 is not None else len(self._wire_seg_times)
        wire_bytes = sum(self._wire_seg_bytes[w_lo:w_hi])

        return _make_summary(sliced_samples, sliced_stalls, sliced_cliffs, payload_bytes, wire_bytes)


@dataclass(frozen=True)
class ThroughputModelPair:
    fwd: ThroughputModel | None = None
    bwd: ThroughputModel | None = None


_SEVERITY_RANK = {"severe": 2, "warn": 1, "info": 0, "handshake": 0}


def _severity_of(kind: str) -> Literal["severe", "warn", "info"]:
    raw = SEVERITY_BY_KIND.get(kind, "info")
    if raw == "handshake":
        return "warn"
    return raw  # type: ignore[return-value]


def _window_params(
    tsg: TsgModel, fallback_rtt_min_ms: float | None
) -> tuple[float, float, float, float, float]:
    """Returns (rtt_min_s, window_s, stride_s, t_start, t_end)."""
    rtt_samples_ms = [s.paired_rtt_ms for s in tsg.segments if s.paired_rtt_ms is not None]
    if rtt_samples_ms:
        rtt_min_s = min(rtt_samples_ms) / 1000.0
    elif fallback_rtt_min_ms is not None:
        rtt_min_s = fallback_rtt_min_ms / 1000.0
    else:
        rtt_min_s = 0.100

    window_s = max(0.050, 4.0 * rtt_min_s)
    stride_s = window_s / 4.0

    seg_times = [s.time for s in tsg.segments]
    ack_times = [a.time for a in tsg.acks]

    all_times: list[float] = []
    if seg_times:
        all_times.extend([seg_times[0], seg_times[-1]])
    if ack_times:
        all_times.extend([ack_times[0], ack_times[-1]])

    if not all_times:
        return rtt_min_s, window_s, stride_s, 0.0, 0.0

    t_start = min(all_times) - window_s / 2.0
    t_end = max(all_times) + window_s / 2.0
    return rtt_min_s, window_s, stride_s, t_start, t_end


def _emit_samples(
    tsg: TsgModel,
    window_s: float,
    stride_s: float,
    t_start: float,
    t_end: float,
) -> list[RateSample]:
    seg_times = [s.time for s in tsg.segments]
    ack_times = [a.time for a in tsg.acks]
    samples: list[RateSample] = []
    t = t_start
    while t <= t_end + stride_s * 0.5:
        hw = window_s / 2.0
        lo = t - hw
        hi = t + hw

        si_lo = bisect.bisect_left(seg_times, lo)
        si_hi = bisect.bisect_left(seg_times, hi)
        segs_in = tsg.segments[si_lo:si_hi]

        wire = sum(s.seq_end - s.seq_start for s in segs_in) / window_s
        goodput = sum(
            s.seq_end - s.seq_start
            for s in segs_in
            if s.rtx is None and s.paired_ack_time is not None
        ) / window_s

        ai_lo = bisect.bisect_left(ack_times, lo)
        ai_hi = bisect.bisect_left(ack_times, hi)
        acks_in = tsg.acks[ai_lo:ai_hi]

        rwins = [(a.rwin_scaled if a.rwin_scaled is not None else a.rwin) for a in acks_in]
        rtts_in = [s.paired_rtt_ms for s in segs_in if s.paired_rtt_ms is not None]

        if rwins and rtts_in:
            # Floor RTT at 1ms. Sub-ms paired-RTT samples (e.g. piggybacked ACK
            # arriving in the same pcap tick as the segment) otherwise drive the
            # rwin/RTT ceiling to physically impossible rates (observed 12 GB/s
            # on a 14 KB/s connection).
            rtt_s = max(max(rtts_in) / 1000.0, 0.001)
            max_bps: float | None = min(rwins) / rtt_s
        else:
            max_bps = None

        samples.append(RateSample(t=t, goodput_Bps=goodput, wire_Bps=wire, max_Bps=max_bps, window_s=window_s))
        t += stride_s

    return samples


def _detect_stalls(tsg: TsgModel, rtt_min_s: float) -> list[Stall]:
    if not tsg.acks:
        return []

    stalls: list[Stall] = []
    ack_times_list = [a.time for a in tsg.acks]

    for i in range(len(tsg.segments) - 1):
        seg_a = tsg.segments[i]
        seg_b = tsg.segments[i + 1]
        gap_s = seg_b.time - seg_a.time

        if seg_a.paired_rtt_ms is not None:
            srtt_ms = seg_a.paired_rtt_ms
        else:
            srtt_ms = None
            for j in range(i + 1, len(tsg.segments)):
                if tsg.segments[j].paired_rtt_ms is not None:
                    srtt_ms = tsg.segments[j].paired_rtt_ms
                    break
            if srtt_ms is None:
                srtt_ms = rtt_min_s * 1000.0

        threshold = max(3.0 * (srtt_ms / 1000.0), 0.200)
        if gap_s < threshold:
            continue

        pending = seg_a.in_flight_after

        # Sender has no outstanding bytes — this is app-limited idle, not a
        # stall. The sender chose not to send (or finished its burst), so
        # quiet time here doesn't indicate a throughput problem.
        if pending == 0:
            continue

        # Check whether the sender drained during the gap — ACKs arriving
        # after seg_a may have brought in_flight to zero well before seg_b.
        # If so, the sender wasn't blocked, just idle.
        if tsg.in_flight:
            inf_times = [t for t, _ in tsg.in_flight]
            mid = seg_b.time - min(0.001, gap_s / 2.0)
            idx_inf = bisect.bisect_right(inf_times, mid) - 1
            if idx_inf >= 0 and tsg.in_flight[idx_inf][1] == 0:
                continue

        idx = bisect.bisect_right(ack_times_list, seg_a.time) - 1
        if idx >= 0:
            a = tsg.acks[idx]
            rwin_ceiling = a.rwin_scaled if a.rwin_scaled is not None else a.rwin
        else:
            rwin_ceiling = max(
                (a.rwin_scaled if a.rwin_scaled is not None else a.rwin)
                for a in tsg.acks
            )

        if pending >= 0.95 * rwin_ceiling:
            continue

        rtt_multiple = gap_s / (srtt_ms / 1000.0)
        if rtt_multiple < 5:
            severity: Literal["info", "warn", "severe"] = "info"
        elif rtt_multiple < 10:
            severity = "warn"
        else:
            severity = "severe"

        stalls.append(Stall(
            t_start=seg_a.time,
            t_end=seg_b.time,
            duration_s=gap_s,
            pending_bytes=pending,
            rtt_multiple=rtt_multiple,
            severity=severity,
        ))

    return stalls


def _detect_cliffs(
    samples: list[RateSample],
    tsg: TsgModel,
    window_s: float,
) -> list[Cliff]:
    raw_cliffs: list[Cliff] = []
    anom_times = [a.time for a in tsg.anomalies]
    in_flight_times = [t for t, _ in tsg.in_flight]
    in_flight_values = [b for _, b in tsg.in_flight]

    for i in range(2, len(samples) - 1):
        before = (samples[i - 2].goodput_Bps + samples[i - 1].goodput_Bps) / 2.0
        after = (samples[i].goodput_Bps + samples[i + 1].goodput_Bps) / 2.0
        if before < 1024:
            continue
        drop_frac = 1.0 - after / before
        if drop_frac < 0.5:
            continue

        t_c = samples[i].t

        # Skip cliffs that happen while the sender has no data in flight.
        # A goodput drop when in_flight is already zero is the sender
        # finishing a burst (or being app-limited between bursts), not a
        # throughput cliff.
        if in_flight_times:
            idx = bisect.bisect_right(in_flight_times, t_c) - 1
            in_flight_at_cliff = in_flight_values[idx] if idx >= 0 else 0
            if in_flight_at_cliff == 0:
                continue
        search_lo = t_c - 2.0 * window_s
        search_hi = t_c + 2.0 * window_s
        ai_lo = bisect.bisect_left(anom_times, search_lo)
        ai_hi = bisect.bisect_right(anom_times, search_hi)
        nearby = [a for a in tsg.anomalies[ai_lo:ai_hi] if a.kind in _CLIFF_KINDS]

        if nearby:
            best = max(nearby, key=lambda a: _SEVERITY_RANK[SEVERITY_BY_KIND.get(a.kind, "info")])
            if best.kind in _CLIFF_LOSS_KINDS:
                cause: Literal["post-loss", "rwin-shrink", "unknown"] = "post-loss"
            else:
                cause = "rwin-shrink"
            sev = _severity_of(best.kind)
        else:
            cause = "unknown"
            sev = "warn"

        raw_cliffs.append(Cliff(
            t=t_c,
            goodput_before_Bps=before,
            goodput_after_Bps=after,
            drop_frac=drop_frac,
            cause_hint=cause,
            severity=sev,
        ))

    # Dedup: within window_s, keep deeper drop
    cliffs: list[Cliff] = []
    for c in sorted(raw_cliffs, key=lambda x: x.t):
        if cliffs and abs(c.t - cliffs[-1].t) < window_s:
            if c.drop_frac > cliffs[-1].drop_frac:
                cliffs[-1] = c
        else:
            cliffs.append(c)

    return cliffs


def _build_direction(tsg: TsgModel, rtt_min_fallback_ms: float | None) -> ThroughputModel:
    rtt_min_s, window_s, stride_s, t_start, t_end = _window_params(tsg, rtt_min_fallback_ms)

    # Empty model: no segments and no acks.
    seg_times = [s.time for s in tsg.segments]
    ack_times = [a.time for a in tsg.acks]
    all_times: list[float] = []
    if seg_times:
        all_times.extend([seg_times[0], seg_times[-1]])
    if ack_times:
        all_times.extend([ack_times[0], ack_times[-1]])

    if not all_times:
        return ThroughputModel(
            samples=(),
            stalls=(),
            cliffs=(),
            summary=_make_summary([], [], [], 0, 0),
            src=tsg.src,
            dst=tsg.dst,
        )

    samples = _emit_samples(tsg, window_s, stride_s, t_start, t_end)
    stalls = _detect_stalls(tsg, rtt_min_s)
    cliffs = _detect_cliffs(samples, tsg, window_s)

    total_payload = sum(
        s.seq_end - s.seq_start
        for s in tsg.segments
        if s.rtx is None and s.paired_ack_time is not None
    )
    total_wire = sum(s.seq_end - s.seq_start for s in tsg.segments)

    # Per-segment time series for exact viewport byte counting.
    wire_times = tuple(s.time for s in tsg.segments)
    wire_bytes = tuple(s.seq_end - s.seq_start for s in tsg.segments)
    payload_segs = [s for s in tsg.segments if s.rtx is None and s.paired_ack_time is not None]
    payload_times = tuple(s.time for s in payload_segs)
    payload_bytes_tuple = tuple(s.seq_end - s.seq_start for s in payload_segs)

    summary = _make_summary(samples, stalls, cliffs, total_payload, total_wire)

    return ThroughputModel(
        samples=tuple(samples),
        stalls=tuple(stalls),
        cliffs=tuple(cliffs),
        summary=summary,
        src=tsg.src,
        dst=tsg.dst,
        _payload_seg_times=payload_times,
        _payload_seg_bytes=payload_bytes_tuple,
        _wire_seg_times=wire_times,
        _wire_seg_bytes=wire_bytes,
    )


def synthesize_throughput(
    tsg_pair: TsgModelPair,
    stats: ConnStats | None = None,
) -> ThroughputModelPair:
    def _rtt_fallback(direction: str) -> float | None:
        if stats is None:
            return None
        if direction == "a2b":
            return stats.rtt_min_a
        return stats.rtt_min_b

    fwd = (
        _build_direction(tsg_pair.fwd, _rtt_fallback("a2b"))
        if tsg_pair.fwd is not None
        else None
    )
    bwd = (
        _build_direction(tsg_pair.bwd, _rtt_fallback("b2a"))
        if tsg_pair.bwd is not None
        else None
    )
    return ThroughputModelPair(fwd=fwd, bwd=bwd)
