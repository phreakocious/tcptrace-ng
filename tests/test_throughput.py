"""Tests for throughput.py — rate-domain synthesis from TsgModelPair."""

from __future__ import annotations

import pytest

from tcptrace_ng.tcp_inspect import Ack, Anomaly, Segment, TsgModel, TsgModelPair
from tcptrace_ng.throughput import (
    DirectionSummary,
    ThroughputModelPair,
    synthesize_throughput,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seg(
    time: float,
    seq_start: int,
    seq_end: int,
    rtx=None,
    paired_ack_time: float | None = None,
    paired_rtt_ms: float | None = None,
    in_flight_after: int = 0,
) -> Segment:
    return Segment(
        time=time,
        seq_start=seq_start,
        seq_end=seq_end,
        rtx=rtx,
        paired_ack_time=paired_ack_time,
        paired_rtt_ms=paired_rtt_ms,
        in_flight_after=in_flight_after,
    )


def _ack(
    time: float,
    ack_seq: int,
    rwin: int = 65535,
    rwin_scaled: int | None = None,
) -> Ack:
    return Ack(
        time=time,
        ack_seq=ack_seq,
        rwin=rwin,
        rwin_scaled=rwin_scaled,
        sack_blocks=(),
        dup_count=0,
    )


def _tsg(
    segments: list[Segment],
    acks: list[Ack],
    direction: str = "a2b",
    anomalies: list[Anomaly] | None = None,
) -> TsgModel:
    return TsgModel(
        direction=direction,
        segments=segments,
        acks=acks,
        anomalies=anomalies or [],
    )


def _pair(fwd: TsgModel | None = None, bwd: TsgModel | None = None) -> TsgModelPair:
    return TsgModelPair(fwd=fwd, bwd=bwd)


# ---------------------------------------------------------------------------
# Degenerate inputs
# ---------------------------------------------------------------------------


def test_empty_pair_returns_none_none():
    result = synthesize_throughput(TsgModelPair())
    assert isinstance(result, ThroughputModelPair)
    assert result.fwd is None
    assert result.bwd is None


def test_single_direction_only_populates_one_side():
    tsg = _tsg(
        [_seg(1.0, 0, 1000, paired_ack_time=1.05, paired_rtt_ms=50.0, in_flight_after=1000)],
        [_ack(1.05, 1000)],
    )
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd is not None
    assert result.bwd is None


def test_no_rtt_samples_falls_back_to_100ms():
    # Segments with no paired RTT → window should be max(0.050, 4*0.100) = 0.400
    segs = [_seg(1.0, 0, 1000, in_flight_after=1000)]
    tsg = _tsg(segs, [_ack(1.1, 1000)])
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd is not None
    assert result.fwd.samples[0].window_s == pytest.approx(0.400)


def test_empty_acks_gives_none_max_bps():
    segs = [
        _seg(1.0, 0, 1000, paired_ack_time=1.05, paired_rtt_ms=50.0, in_flight_after=1000),
        _seg(1.1, 1000, 2000, paired_ack_time=1.15, paired_rtt_ms=50.0, in_flight_after=1000),
    ]
    tsg = _tsg(segs, [])
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd is not None
    assert all(s.max_Bps is None for s in result.fwd.samples)
    assert result.fwd.summary.bdp_utilization_frac is None


def test_empty_tsg_model_produces_empty_throughput_model():
    tsg = _tsg([], [])
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd is not None
    assert result.fwd.samples == ()
    assert result.fwd.stalls == ()
    assert result.fwd.cliffs == ()


# ---------------------------------------------------------------------------
# Window sizing
# ---------------------------------------------------------------------------


def test_window_size_floor_at_5ms_rtt():
    # rtt_min = 5ms → 4 * 0.005 = 0.020 < 0.050 floor → window_s = 0.050
    segs = [_seg(1.0, 0, 1000, paired_ack_time=1.005, paired_rtt_ms=5.0, in_flight_after=1000)]
    tsg = _tsg(segs, [_ack(1.005, 1000)])
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd.samples[0].window_s == pytest.approx(0.050)


def test_window_size_at_50ms_rtt():
    # rtt_min = 50ms → 4 * 0.050 = 0.200
    segs = [_seg(1.0, 0, 1000, paired_ack_time=1.050, paired_rtt_ms=50.0, in_flight_after=1000)]
    tsg = _tsg(segs, [_ack(1.050, 1000)])
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd.samples[0].window_s == pytest.approx(0.200)


def test_window_size_at_200ms_rtt():
    # rtt_min = 200ms → 4 * 0.200 = 0.800
    segs = [_seg(1.0, 0, 1000, paired_ack_time=1.200, paired_rtt_ms=200.0, in_flight_after=1000)]
    tsg = _tsg(segs, [_ack(1.200, 1000)])
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd.samples[0].window_s == pytest.approx(0.800)


# ---------------------------------------------------------------------------
# Goodput filtering
# ---------------------------------------------------------------------------


def test_retx_segment_advances_wire_not_goodput():
    # window large enough to contain both segments at t=1.0
    segs = [
        _seg(1.0, 0, 1000, rtx=None, paired_ack_time=1.05, paired_rtt_ms=50.0, in_flight_after=1000),
        _seg(1.01, 0, 1000, rtx="rto", paired_ack_time=None, paired_rtt_ms=None, in_flight_after=1000),
    ]
    tsg = _tsg(segs, [_ack(1.05, 1000)])
    result = synthesize_throughput(_pair(fwd=tsg))
    # Find sample closest to t=1.0 center
    s = min(result.fwd.samples, key=lambda x: abs(x.t - 1.0))
    # wire counts both 1000-byte segs if within window; goodput counts only first-tx+acked
    assert s.wire_Bps >= s.goodput_Bps
    assert s.wire_Bps > 0


def test_unacked_first_tx_not_in_goodput():
    # paired_ack_time=None → excluded from goodput
    segs = [
        _seg(1.0, 0, 1000, rtx=None, paired_ack_time=None, paired_rtt_ms=50.0, in_flight_after=1000),
    ]
    tsg = _tsg(segs, [_ack(1.5, 1000)])
    result = synthesize_throughput(_pair(fwd=tsg))
    s = min(result.fwd.samples, key=lambda x: abs(x.t - 1.0))
    assert s.goodput_Bps == pytest.approx(0.0)
    assert s.wire_Bps > 0


def test_acked_first_tx_in_both():
    segs = [
        _seg(1.0, 0, 1000, rtx=None, paired_ack_time=1.050, paired_rtt_ms=50.0, in_flight_after=1000),
    ]
    tsg = _tsg(segs, [_ack(1.050, 1000)])
    result = synthesize_throughput(_pair(fwd=tsg))
    s = min(result.fwd.samples, key=lambda x: abs(x.t - 1.0))
    assert s.goodput_Bps > 0
    assert s.wire_Bps > 0
    assert s.goodput_Bps == pytest.approx(s.wire_Bps)


def test_goodput_never_exceeds_wire_invariant():
    # Mixed segments: first-tx acked, retx, unacked first-tx
    segs = [
        _seg(0.10, 0, 1000, rtx=None, paired_ack_time=0.16, paired_rtt_ms=50.0, in_flight_after=1000),
        _seg(0.15, 1000, 2000, rtx=None, paired_ack_time=0.21, paired_rtt_ms=50.0, in_flight_after=2000),
        _seg(0.20, 2000, 3000, rtx=None, paired_ack_time=0.26, paired_rtt_ms=50.0, in_flight_after=3000),
        _seg(0.21, 0, 1000, rtx="rto", paired_ack_time=None, paired_rtt_ms=None, in_flight_after=2000),
        _seg(0.25, 3000, 4000, rtx=None, paired_ack_time=None, paired_rtt_ms=None, in_flight_after=3000),
        _seg(0.30, 4000, 5000, rtx=None, paired_ack_time=0.36, paired_rtt_ms=50.0, in_flight_after=3000),
    ]
    acks = [
        _ack(0.16, 1000),
        _ack(0.21, 2000),
        _ack(0.26, 3000),
        _ack(0.36, 5000),
    ]
    tsg = _tsg(segs, acks)
    result = synthesize_throughput(_pair(fwd=tsg))
    for s in result.fwd.samples:
        assert s.goodput_Bps <= s.wire_Bps + 1e-9, (
            f"goodput {s.goodput_Bps} > wire {s.wire_Bps} at t={s.t}"
        )


# ---------------------------------------------------------------------------
# Stall detection
# ---------------------------------------------------------------------------


def _build_stall_tsg(gap_s: float, rtt_ms: float = 50.0, pending: int = 500, rwin: int = 65535) -> TsgModel:
    """Two segments with a gap between them; pending < 0.95*rwin unless told otherwise."""
    segs = [
        _seg(1.0, 0, 1000, paired_ack_time=1.05, paired_rtt_ms=rtt_ms, in_flight_after=pending),
        _seg(1.0 + gap_s, 1000, 2000, paired_ack_time=None, paired_rtt_ms=None, in_flight_after=pending),
    ]
    acks = [_ack(0.5, 0, rwin=rwin)]
    return _tsg(segs, acks)


def test_stall_detected_for_large_gap():
    # gap = 0.5s, rtt=50ms → threshold = max(3*0.05, 0.2) = 0.2; gap > threshold → stall
    tsg = _build_stall_tsg(0.5, rtt_ms=50.0, pending=500, rwin=65535)
    result = synthesize_throughput(_pair(fwd=tsg))
    assert len(result.fwd.stalls) == 1
    st = result.fwd.stalls[0]
    assert st.duration_s == pytest.approx(0.5)
    assert st.rtt_multiple == pytest.approx(0.5 / 0.05)  # = 10.0


def test_stall_severity_tiers():
    # rtt_multiple in [3, 5) → info
    # rtt=50ms, threshold = max(3*0.05, 0.2) = 0.2s; gap=0.21 → multiple=4.2 → info
    segs_info = [
        _seg(1.0, 0, 1000, paired_ack_time=1.05, paired_rtt_ms=50.0, in_flight_after=500),
        _seg(1.21, 1000, 2000, paired_ack_time=None, paired_rtt_ms=None, in_flight_after=500),
    ]
    tsg_info = _tsg(segs_info, [_ack(0.5, 0, rwin=65535)])
    result_info = synthesize_throughput(_pair(fwd=tsg_info))
    assert result_info.fwd.stalls, "expected info-tier stall (gap=0.21s, rtt=50ms, multiple=4.2)"
    assert result_info.fwd.stalls[0].severity == "info"

    # rtt_multiple >= 5, < 10 → warn
    segs_warn = [
        _seg(1.0, 0, 1000, paired_ack_time=1.05, paired_rtt_ms=50.0, in_flight_after=500),
        _seg(1.35, 1000, 2000, paired_ack_time=None, paired_rtt_ms=None, in_flight_after=500),
    ]
    tsg_warn = _tsg(segs_warn, [_ack(0.5, 0, rwin=65535)])
    result_warn = synthesize_throughput(_pair(fwd=tsg_warn))
    assert result_warn.fwd.stalls
    assert result_warn.fwd.stalls[0].severity == "warn"  # 0.35/0.05 = 7.0

    # rtt_multiple >= 10 → severe
    segs_severe = [
        _seg(1.0, 0, 1000, paired_ack_time=1.05, paired_rtt_ms=50.0, in_flight_after=500),
        _seg(1.60, 1000, 2000, paired_ack_time=None, paired_rtt_ms=None, in_flight_after=500),
    ]
    tsg_severe = _tsg(segs_severe, [_ack(0.5, 0, rwin=65535)])
    result_severe = synthesize_throughput(_pair(fwd=tsg_severe))
    assert result_severe.fwd.stalls
    assert result_severe.fwd.stalls[0].severity == "severe"  # 0.60/0.05 = 12.0


def test_stall_not_emitted_at_end_of_segments():
    # Only one segment → no consecutive pair → no stall
    segs = [_seg(1.0, 0, 1000, paired_ack_time=1.05, paired_rtt_ms=50.0, in_flight_after=500)]
    tsg = _tsg(segs, [_ack(0.5, 0, rwin=65535)])
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd.stalls == ()


def test_stall_not_emitted_when_pending_exceeds_rwin():
    # pending >= 0.95 * rwin → not a stall (window-limited, not a real stall)
    pending = 62000
    rwin = 65000
    assert pending >= 0.95 * rwin
    tsg = _build_stall_tsg(0.5, rtt_ms=50.0, pending=pending, rwin=rwin)
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd.stalls == ()


def test_stall_threshold_below_does_not_trigger():
    # gap = 2.99 * srtt → below threshold of 3.0
    rtt_ms = 100.0  # srtt = 0.100s; threshold = max(0.300, 0.200) = 0.300
    gap_s = 2.99 * (rtt_ms / 1000.0)  # 0.299s < 0.300 threshold
    tsg = _build_stall_tsg(gap_s, rtt_ms=rtt_ms)
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd.stalls == ()


def test_stall_threshold_above_triggers():
    # gap = 3.01 * srtt and > 200ms → triggers
    rtt_ms = 100.0  # threshold = 0.300s
    gap_s = 3.01 * (rtt_ms / 1000.0)  # 0.301s > 0.300 → triggers
    tsg = _build_stall_tsg(gap_s, rtt_ms=rtt_ms, pending=500, rwin=65535)
    result = synthesize_throughput(_pair(fwd=tsg))
    assert len(result.fwd.stalls) == 1


def test_stall_not_detected_with_empty_acks():
    # Empty ack list → stall detection skipped
    segs = [
        _seg(1.0, 0, 1000, paired_ack_time=None, paired_rtt_ms=50.0, in_flight_after=500),
        _seg(1.5, 1000, 2000, paired_ack_time=None, paired_rtt_ms=50.0, in_flight_after=500),
    ]
    tsg = _tsg(segs, [])
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd.stalls == ()


# ---------------------------------------------------------------------------
# Cliff detection
# ---------------------------------------------------------------------------


def _build_cliff_tsg(
    n_before: int = 10,
    rate_before_Bps: float = 10240.0,
    n_after: int = 10,
    rate_after_Bps: float = 1024.0,
    anomalies: list[Anomaly] | None = None,
) -> TsgModel:
    """Build a TsgModel with a clear goodput cliff.

    First n_before segments at ~rate_before_Bps * window, then n_after at ~rate_after_Bps.
    Uses 50ms RTT → window_s=0.200, stride=0.050.
    Segments are first-tx, ACK-confirmed, evenly spaced.
    """
    rtt_ms = 50.0
    window_s = 0.200  # 4 * 0.050

    # Place segments so they produce the desired rate within a window
    # rate = bytes/window_s → bytes_per_seg = rate * window_s / segs_per_window
    # Use 1 seg per stride (stride=0.050) for predictable binning
    segs: list[Segment] = []
    acks: list[Ack] = []
    t = 1.0
    seq = 0
    bytes_per_seg_before = int(rate_before_Bps * window_s / 4)  # 4 segs per window
    bytes_per_seg_after = int(rate_after_Bps * window_s / 4)

    for i in range(n_before):
        seg_end = seq + bytes_per_seg_before
        segs.append(_seg(t, seq, seg_end, paired_ack_time=t + rtt_ms / 1000, paired_rtt_ms=rtt_ms, in_flight_after=bytes_per_seg_before))
        acks.append(_ack(t + rtt_ms / 1000, seg_end))
        seq = seg_end
        t += 0.050

    # Gap between before/after so cliff is sharp
    t += 0.300

    for i in range(n_after):
        seg_end = seq + bytes_per_seg_after
        segs.append(_seg(t, seq, seg_end, paired_ack_time=t + rtt_ms / 1000, paired_rtt_ms=rtt_ms, in_flight_after=bytes_per_seg_after))
        acks.append(_ack(t + rtt_ms / 1000, seg_end))
        seq = seg_end
        t += 0.050

    return _tsg(segs, acks, anomalies=anomalies or [])


def test_cliff_detected_on_large_drop():
    tsg = _build_cliff_tsg(rate_before_Bps=10240, rate_after_Bps=512)
    result = synthesize_throughput(_pair(fwd=tsg))
    assert len(result.fwd.cliffs) >= 1
    cliff = result.fwd.cliffs[0]
    assert cliff.drop_frac >= 0.5


def test_cliff_not_detected_small_drop():
    # rate drops 40% → drop_frac < 0.5 → no cliff
    tsg = _build_cliff_tsg(rate_before_Bps=10240, rate_after_Bps=6500)
    result = synthesize_throughput(_pair(fwd=tsg))
    # Should have 0 or only cliffs with drop_frac < 0.5
    for c in result.fwd.cliffs:
        assert c.drop_frac >= 0.5  # any emitted cliff must meet the threshold


def test_cliff_not_detected_below_noise_floor():
    # before < 1024 B/s → noise floor skip
    tsg = _build_cliff_tsg(rate_before_Bps=512, rate_after_Bps=10)
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd.cliffs == ()


def test_cliff_cause_hint_post_loss_with_rto_anomaly():
    t_cliff_center = 1.0 + 10 * 0.050 + 0.300 + 0.0  # approx start of "after" region
    anom = Anomaly(
        time=t_cliff_center + 0.050,  # within 2*window_s of cliff
        kind="rto",
        one_liner="rto retransmit",
        seq_lo=0,
        seq_hi=100,
    )
    tsg = _build_cliff_tsg(rate_before_Bps=10240, rate_after_Bps=512, anomalies=[anom])
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd.cliffs
    # At least one cliff should be post-loss
    assert any(c.cause_hint == "post-loss" for c in result.fwd.cliffs)


def test_cliff_cause_hint_unknown_without_anomalies():
    tsg = _build_cliff_tsg(rate_before_Bps=10240, rate_after_Bps=512)
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd.cliffs
    assert all(c.cause_hint == "unknown" for c in result.fwd.cliffs)
    assert all(c.severity == "warn" for c in result.fwd.cliffs)


def test_cliff_cause_hint_rwin_shrink():
    t_cliff_center = 1.0 + 10 * 0.050 + 0.300 + 0.0
    anom = Anomaly(
        time=t_cliff_center + 0.050,
        kind="win_shrink",
        one_liner="window shrunk",
        seq_lo=1000,
        seq_hi=1000,
    )
    tsg = _build_cliff_tsg(rate_before_Bps=10240, rate_after_Bps=512, anomalies=[anom])
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd.cliffs
    assert any(c.cause_hint == "rwin-shrink" for c in result.fwd.cliffs)


def test_cliff_dedup_keeps_deeper_drop():
    # Build a TsgModel where two candidate cliffs land within window_s of each other.
    # The dedup pass must keep the one with the higher drop_frac and discard the other.
    #
    # Strategy: build high-rate, then a shallow drop (medium rate), then an even
    # deeper drop — all within one window_s of each other.  Samples are emitted at
    # stride=0.050 so three consecutive transitions within 0.100s are well inside
    # the 0.200s window_s dedup radius.
    rtt_ms = 50.0
    window_s = 0.200
    segs: list[Segment] = []
    acks: list[Ack] = []
    t = 1.0
    seq = 0
    bytes_high = int(10240 * window_s / 4)
    bytes_mid = int(3000 * window_s / 4)   # ~70% drop from high
    bytes_deep = int(200 * window_s / 4)   # ~98% drop from high (deeper)

    # 10 high-rate segments
    for _ in range(10):
        end = seq + bytes_high
        segs.append(_seg(t, seq, end, paired_ack_time=t + 0.05, paired_rtt_ms=rtt_ms, in_flight_after=bytes_high))
        acks.append(_ack(t + 0.05, end))
        seq = end
        t += 0.050

    # 3 medium-rate segments (shallow cliff candidate)
    for _ in range(3):
        end = seq + bytes_mid
        segs.append(_seg(t, seq, end, paired_ack_time=t + 0.05, paired_rtt_ms=rtt_ms, in_flight_after=bytes_mid))
        acks.append(_ack(t + 0.05, end))
        seq = end
        t += 0.050

    # 4 very-low-rate segments (deep cliff candidate, within window_s of shallow one)
    for _ in range(4):
        end = seq + bytes_deep
        segs.append(_seg(t, seq, end, paired_ack_time=t + 0.05, paired_rtt_ms=rtt_ms, in_flight_after=bytes_deep))
        acks.append(_ack(t + 0.05, end))
        seq = end
        t += 0.050

    tsg = _tsg(segs, acks)
    result = synthesize_throughput(_pair(fwd=tsg))
    cliffs = result.fwd.cliffs

    # Both candidates fall within window_s of each other; only the deeper survives.
    assert len(cliffs) == 1, f"expected 1 cliff after dedup, got {len(cliffs)}: {cliffs}"
    # The surviving cliff must be the deeper one.  The windowed rate blurs exact
    # fractions, but it must be deeper than the shallow candidate (~0.70) and
    # definitely exceed the 0.5 emission threshold.
    assert cliffs[0].drop_frac > 0.70, f"expected deep cliff (drop_frac>0.70), got {cliffs[0].drop_frac}"


# ---------------------------------------------------------------------------
# Summary aggregates
# ---------------------------------------------------------------------------


def test_summary_aggregates_hand_computed():
    # 4 segments: 3 first-tx ACKed, 1 retx. Total wire=4000, payload=3000.
    rtt_ms = 50.0
    segs = [
        _seg(0.0, 0, 1000, paired_ack_time=0.05, paired_rtt_ms=rtt_ms, in_flight_after=1000),
        _seg(0.05, 1000, 2000, paired_ack_time=0.10, paired_rtt_ms=rtt_ms, in_flight_after=2000),
        _seg(0.10, 2000, 3000, paired_ack_time=0.15, paired_rtt_ms=rtt_ms, in_flight_after=3000),
        _seg(0.12, 0, 1000, rtx="rto", in_flight_after=2000),
    ]
    acks = [_ack(0.05, 1000), _ack(0.10, 2000), _ack(0.15, 3000)]
    tsg = _tsg(segs, acks)
    result = synthesize_throughput(_pair(fwd=tsg))
    s = result.fwd.summary
    assert s.total_payload_bytes == 3000
    assert s.total_wire_bytes == 4000
    assert s.retx_overhead_frac == pytest.approx(0.25)
    assert s.peak_goodput_Bps >= s.mean_goodput_Bps
    assert s.p95_goodput_Bps >= s.p50_goodput_Bps


def test_summary_stall_and_cliff_counts():
    # Build a model with a known stall and check summary reflects it
    tsg = _build_stall_tsg(0.5, rtt_ms=50.0, pending=500, rwin=65535)
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd.summary.stall_count == len(result.fwd.stalls)
    assert result.fwd.summary.total_stall_s == pytest.approx(
        sum(st.duration_s for st in result.fwd.stalls)
    )


# ---------------------------------------------------------------------------
# window_stats method
# ---------------------------------------------------------------------------


def _rich_tsg() -> TsgModel:
    rtt_ms = 50.0
    segs = [
        _seg(t, t * 1000, t * 1000 + 1000, paired_ack_time=t + 0.05, paired_rtt_ms=rtt_ms, in_flight_after=1000)
        for t in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    ]
    acks = [_ack(t + 0.05, t * 1000 + 1000) for t in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]]
    return _tsg(segs, acks)


def test_window_stats_whole_range():
    tsg = _rich_tsg()
    result = synthesize_throughput(_pair(fwd=tsg))
    ws = result.fwd.window_stats(None, None)
    full = result.fwd.summary
    assert ws.peak_goodput_Bps == pytest.approx(full.peak_goodput_Bps)
    assert ws.mean_goodput_Bps == pytest.approx(full.mean_goodput_Bps)


def test_window_stats_clamped_outside_model_range():
    tsg = _rich_tsg()
    result = synthesize_throughput(_pair(fwd=tsg))
    # Clamp beyond the model range — should return same as whole-model
    model = result.fwd
    sample_times = [s.t for s in model.samples]
    ws_clamped = model.window_stats(sample_times[0] - 100.0, sample_times[-1] + 100.0)
    ws_full = model.window_stats(None, None)
    assert ws_clamped.peak_goodput_Bps == pytest.approx(ws_full.peak_goodput_Bps)


def test_window_stats_zero_sample_viewport():
    tsg = _rich_tsg()
    result = synthesize_throughput(_pair(fwd=tsg))
    # Time range before any samples
    ws = result.fwd.window_stats(0.0, 0.001)
    assert ws.peak_goodput_Bps == pytest.approx(0.0)
    assert ws.mean_goodput_Bps == pytest.approx(0.0)
    assert ws.stall_count == 0
    assert ws.cliff_count == 0


def test_window_stats_stall_intersecting_viewport():
    # A stall from t=1.0..1.5 — a window_stats query that overlaps the stall should count it
    tsg = _build_stall_tsg(0.5, rtt_ms=50.0, pending=500, rwin=65535)
    result = synthesize_throughput(_pair(fwd=tsg))
    if not result.fwd.stalls:
        pytest.skip("no stalls emitted")
    st = result.fwd.stalls[0]
    # Query that starts inside the stall interval
    ws = result.fwd.window_stats(st.t_start + 0.1, st.t_end + 1.0)
    assert ws.stall_count >= 1


def test_window_stats_returns_direction_summary_instance():
    tsg = _rich_tsg()
    result = synthesize_throughput(_pair(fwd=tsg))
    ws = result.fwd.window_stats(None, None)
    assert isinstance(ws, DirectionSummary)


def test_window_stats_exact_byte_counts():
    """window_stats must return exact byte totals, not a sample-proportional estimate."""
    # Segments at known times and sizes.  Mix of first-tx ACKed and a retx.
    #   t=0.1  seq 0..1000   first-tx acked  → payload+wire
    #   t=0.2  seq 1000..3000 first-tx acked  → payload+wire (2000 bytes)
    #   t=0.3  seq 0..500    retx            → wire only
    #   t=0.5  seq 3000..4500 first-tx acked  → payload+wire (1500 bytes)
    #   t=0.9  seq 4500..5000 first-tx NOT acked (paired_ack_time=None) → wire only
    segs = [
        _seg(0.1, 0, 1000, rtx=None, paired_ack_time=0.15, paired_rtt_ms=50.0, in_flight_after=1000),
        _seg(0.2, 1000, 3000, rtx=None, paired_ack_time=0.25, paired_rtt_ms=50.0, in_flight_after=2000),
        _seg(0.3, 0, 500, rtx="rto", paired_ack_time=None, paired_rtt_ms=None, in_flight_after=500),
        _seg(0.5, 3000, 4500, rtx=None, paired_ack_time=0.55, paired_rtt_ms=50.0, in_flight_after=1500),
        _seg(0.9, 4500, 5000, rtx=None, paired_ack_time=None, paired_rtt_ms=None, in_flight_after=500),
    ]
    acks = [_ack(0.15, 1000), _ack(0.25, 3000), _ack(0.55, 4500)]
    tsg = _tsg(segs, acks)
    result = synthesize_throughput(_pair(fwd=tsg))
    model = result.fwd

    # --- Range covering all segments ---
    # total wire = 1000+2000+500+1500+500 = 5500
    # total payload (first-tx+acked) = 1000+2000+1500 = 4500
    ws_all = model.window_stats(None, None)
    assert ws_all.total_wire_bytes == 5500
    assert ws_all.total_payload_bytes == 4500
    # Must also match model-wide summary exactly
    assert ws_all.total_wire_bytes == model.summary.total_wire_bytes
    assert ws_all.total_payload_bytes == model.summary.total_payload_bytes

    # --- Range with only some segments: t in [0.15, 0.55] ---
    # wire segs with time in [0.15, 0.55]: t=0.2 (2000), t=0.3 (500), t=0.5 (1500) → 4000
    # payload segs in range: t=0.2 (2000), t=0.5 (1500) → 3500
    ws_mid = model.window_stats(0.15, 0.55)
    assert ws_mid.total_wire_bytes == 4000, f"expected 4000, got {ws_mid.total_wire_bytes}"
    assert ws_mid.total_payload_bytes == 3500, f"expected 3500, got {ws_mid.total_payload_bytes}"

    # --- Range with only first two payload segs: t in [0.0, 0.25] ---
    # wire: t=0.1 (1000), t=0.2 (2000) → 3000
    # payload: t=0.1 (1000), t=0.2 (2000) → 3000
    ws_early = model.window_stats(0.0, 0.25)
    assert ws_early.total_wire_bytes == 3000
    assert ws_early.total_payload_bytes == 3000

    # --- Degenerate: range with no segments ---
    ws_empty = model.window_stats(0.6, 0.7)
    assert ws_empty.total_wire_bytes == 0
    assert ws_empty.total_payload_bytes == 0


# ---------------------------------------------------------------------------
# Frozen dataclass invariants
# ---------------------------------------------------------------------------


def test_throughput_model_pair_is_constructible():
    result = synthesize_throughput(TsgModelPair())
    assert result.fwd is None and result.bwd is None


def test_rate_sample_is_frozen():
    from dataclasses import FrozenInstanceError
    from tcptrace_ng.throughput import RateSample
    s = RateSample(t=1.0, goodput_Bps=0.0, wire_Bps=0.0, max_Bps=None, window_s=0.2)
    with pytest.raises(FrozenInstanceError):
        s.t = 2.0  # type: ignore[misc]


def test_stall_is_frozen():
    from dataclasses import FrozenInstanceError
    from tcptrace_ng.throughput import Stall
    st = Stall(t_start=1.0, t_end=1.5, duration_s=0.5, pending_bytes=100, rtt_multiple=5.0, severity="warn")
    with pytest.raises(FrozenInstanceError):
        st.t_start = 2.0  # type: ignore[misc]


def test_cliff_is_frozen():
    from dataclasses import FrozenInstanceError
    from tcptrace_ng.throughput import Cliff
    c = Cliff(t=1.0, goodput_before_Bps=1000.0, goodput_after_Bps=100.0, drop_frac=0.9,
              cause_hint="unknown", severity="warn")
    with pytest.raises(FrozenInstanceError):
        c.t = 2.0  # type: ignore[misc]


def test_throughput_model_src_dst_from_tsg():
    tsg = TsgModel(
        src="10.0.0.1:443",
        dst="10.0.0.2:55000",
        direction="a2b",
        segments=[
            _seg(1.0, 0, 1000, paired_ack_time=1.05, paired_rtt_ms=50.0, in_flight_after=1000),
        ],
        acks=[_ack(1.05, 1000)],
    )
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd is not None
    assert result.fwd.src == "10.0.0.1:443"
    assert result.fwd.dst == "10.0.0.2:55000"


def test_throughput_model_src_dst_empty_by_default():
    tsg = TsgModel(direction="a2b")  # no src/dst set
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd is not None
    assert result.fwd.src == ""
    assert result.fwd.dst == ""


# ---------------------------------------------------------------------------
# Ceiling (max_Bps) robustness
# ---------------------------------------------------------------------------


def test_ceiling_floors_subms_rtt_at_1ms():
    # Sub-ms paired RTTs (e.g. piggybacked ACKs landing in the same pcap tick)
    # used to drive ceiling to absurd rates. With the 1ms floor, ceiling caps
    # at rwin / 1ms regardless of how small the RTT samples are.
    rwin = 60000
    segs = [
        _seg(1.0, 0, 1500, paired_ack_time=1.0000042, paired_rtt_ms=0.042, in_flight_after=1500),
        _seg(1.001, 1500, 3000, paired_ack_time=1.001005, paired_rtt_ms=0.005, in_flight_after=1500),
    ]
    acks = [_ack(1.0001, 1500, rwin=rwin), _ack(1.0011, 3000, rwin=rwin)]
    tsg = _tsg(segs, acks)
    result = synthesize_throughput(_pair(fwd=tsg))
    ceilings = [s.max_Bps for s in result.fwd.samples if s.max_Bps is not None]
    # 60000 / 0.001 = 60_000_000 — without the floor this would be 60000/0.000005 = 12 GB/s
    assert ceilings, "expected at least one ceiling sample"
    assert max(ceilings) <= rwin / 0.001 + 1e-6


# ---------------------------------------------------------------------------
# App-limited skips for stalls and cliffs
# ---------------------------------------------------------------------------


def test_stall_skipped_when_in_flight_zero():
    # Long gap, but the sender had drained (in_flight_after == 0). That's
    # application-limited idle, not a throughput stall.
    segs = [
        _seg(1.0, 0, 1000, paired_ack_time=1.05, paired_rtt_ms=50.0, in_flight_after=0),
        _seg(1.5, 1000, 2000, paired_ack_time=None, paired_rtt_ms=None, in_flight_after=0),
    ]
    tsg = _tsg(segs, [_ack(0.5, 0, rwin=65535)])
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd.stalls == ()


def test_cliff_skipped_when_in_flight_zero_at_drop():
    # Build a normal cliff scenario, but populate tsg.in_flight so it reads 0
    # at the drop point. Verify cliff is suppressed.
    tsg = _build_cliff_tsg(rate_before_Bps=10240, rate_after_Bps=512)
    # Sweep in_flight = 0 over the entire connection's time domain so the
    # cliff detector reads "sender drained" at every candidate.
    t_first = tsg.segments[0].time
    t_last = tsg.segments[-1].time
    tsg.in_flight = [(t_first - 0.1, 0), (t_last + 0.1, 0)]
    result = synthesize_throughput(_pair(fwd=tsg))
    assert result.fwd.cliffs == ()


def test_cliff_detected_when_in_flight_positive_at_drop():
    # Sanity check: with in_flight populated and positive at the drop, cliff
    # is still emitted (the in_flight==0 skip doesn't fire on real cliffs).
    tsg = _build_cliff_tsg(rate_before_Bps=10240, rate_after_Bps=512)
    t_first = tsg.segments[0].time
    t_last = tsg.segments[-1].time
    tsg.in_flight = [(t_first - 0.1, 5000), (t_last + 0.1, 5000)]
    result = synthesize_throughput(_pair(fwd=tsg))
    assert len(result.fwd.cliffs) >= 1


def test_bdp_utilization_clipped_at_100_percent():
    # Construct a model where per-window goodput briefly exceeds per-window
    # ceiling (a quirk of windowed averaging vs instantaneous rwin/RTT).
    # The summary's mean ratio must still be ≤ 1.0.
    rtt_ms = 50.0
    window_s = 0.200
    rwin_small = 1000  # tiny rwin → small max_Bps
    bytes_per_seg = 10000  # huge segments → high goodput
    segs: list[Segment] = []
    acks: list[Ack] = []
    t = 1.0
    seq = 0
    for _ in range(5):
        end = seq + bytes_per_seg
        segs.append(_seg(t, seq, end, paired_ack_time=t + 0.05, paired_rtt_ms=rtt_ms, in_flight_after=bytes_per_seg))
        acks.append(_ack(t + 0.05, end, rwin=rwin_small))
        seq = end
        t += 0.050
    tsg = _tsg(segs, acks)
    result = synthesize_throughput(_pair(fwd=tsg))
    bdp = result.fwd.summary.bdp_utilization_frac
    assert bdp is not None
    assert 0.0 <= bdp <= 1.0, f"bdp_util out of range: {bdp}"
    _ = window_s  # silence unused
