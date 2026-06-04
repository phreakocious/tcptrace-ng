"""Tests for tcp_inspect — synthesis of TsgModel from parsed xpl + -l text.

Following the same fixture discipline as test_xpl_parser.py: real tcptrace
output verbatim, no invented formats.
"""

from dataclasses import FrozenInstanceError

import pytest

from tcptrace_ng.tcp_inspect import (
    SEVERITY_BY_KIND,
    Ack,
    Anomaly,
    Segment,
    TsgModel,
    TsgModelPair,
    WindowStats,
    synthesize,
)
from tcptrace_ng.xpl_parser import XplPlot, parse_xpl


def test_segment_is_frozen_dataclass():
    seg = Segment(
        time=1.0,
        seq_start=100,
        seq_end=228,
        rtx=None,
        paired_ack_time=None,
        paired_rtt_ms=None,
        in_flight_after=0,
    )
    with pytest.raises(FrozenInstanceError):
        seg.time = 2.0  # type: ignore[misc]


def test_ack_is_frozen_dataclass():
    ack = Ack(
        time=1.0,
        ack_seq=200,
        rwin=64240,
        rwin_scaled=None,
        sack_blocks=(),
        dup_count=0,
    )
    with pytest.raises(FrozenInstanceError):
        ack.time = 2.0  # type: ignore[misc]


def test_anomaly_is_frozen_dataclass():
    a = Anomaly(time=1.0, kind="rto", one_liner="x", seq_lo=None, seq_hi=None)
    with pytest.raises(FrozenInstanceError):
        a.time = 2.0  # type: ignore[misc]


def test_tsg_model_default_lists_are_distinct_instances():
    m1 = TsgModel(src="a", dst="b", direction="a2b")
    m2 = TsgModel(src="a", dst="b", direction="a2b")
    m1.segments.append(
        Segment(
            time=0,
            seq_start=0,
            seq_end=0,
            rtx=None,
            paired_ack_time=None,
            paired_rtt_ms=None,
            in_flight_after=0,
        )
    )
    assert m2.segments == []


def test_tsg_model_pair_default_is_none_none():
    pair = TsgModelPair()
    assert pair.fwd is None
    assert pair.bwd is None


def test_window_stats_constructible_with_all_fields():
    WindowStats(
        n_segs=0,
        bytes_sent=0,
        throughput_eff_Bps=0.0,
        n_retx=0,
        n_rto=0,
        n_fast=0,
        n_dup_ack=0,
        n_ooo=0,
        n_sack_regions=0,
        rtt_p50_ms=None,
        rtt_p95_ms=None,
        rtt_min_ms=None,
        rtt_max_ms=None,
        jitter_ms=None,
        rwin_peak=None,
        rwin_scale=None,
        n_win_shrink=0,
        n_zero_win=0,
    )


def test_synthesize_empty_inputs_returns_empty_pair():
    pair = synthesize(None, None, "")
    assert pair.fwd is None
    assert pair.bwd is None


def test_synthesize_header_only_xpl_returns_empty_model():
    xpl = XplPlot(
        title="1.2.3.4:1 ==> 5.6.7.8:2 (time sequence graph)",
        xlabel="time",
        ylabel="sequence number",
    )
    pair = synthesize(xpl, None, "")
    assert pair.fwd is not None
    assert pair.fwd.segments == []
    assert pair.fwd.acks == []
    assert pair.bwd is None


# Real tsg.xpl excerpt — three white data segments straddling a SYN.
# Lifted verbatim from .tcptrace/firmware_flash.pcapng/conn-12/conn-12--w2x_tsg.xpl
TSG_THREE_SEGS = """\
timeval double
title
172.20.0.100:51325 ==> 172.20.0.2:5009 (time sequence graph)
xlabel
time
ylabel
sequence number
white
orange
diamond 1538187584.738972 3493560571
atext 1538187584.738972 3493560572
SYN
uarrow 1538187584.738972 3493560572
line 1538187584.738972 3493560571 1538187584.738972 3493560572
white
darrow 1538187584.750543 3493560572
diamond 1538187584.750543 3493560700 white
dot 1538187584.750543 3493560700 white
line 1538187584.750543 3493560572 1538187584.750543 3493560700
white
darrow 1538187584.750557 3493560700
diamond 1538187584.750557 3493560736 white
dot 1538187584.750557 3493560736 white
line 1538187584.750557 3493560700 1538187584.750557 3493560736
"""


def test_segments_extracted_from_white_vertical_lines():
    xpl = parse_xpl(TSG_THREE_SEGS)
    pair = synthesize(xpl, None, "")
    segs = pair.fwd.segments
    # Only the two white data segs — the orange SYN is a 1-byte control
    # marker, not data, and is filtered out at extraction.
    assert len(segs) == 2
    # Time-sorted.
    assert all(segs[i].time <= segs[i + 1].time for i in range(len(segs) - 1))
    # First white data seg: 572 -> 700, len 128.
    assert segs[0].seq_start == 3493560572
    assert segs[0].seq_end == 3493560700
    assert segs[0].time == pytest.approx(1538187584.750543)
    assert segs[0].rtx is None


def test_red_vertical_lines_classified_as_rtx_pending():
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
red
line 100.0 1000 100.0 1100
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    segs = pair.fwd.segments
    assert len(segs) == 1
    # Pre-classification: red marks "retx of some kind"; Task 8 narrows to rto/fast/spurious.
    # For now we mark with the placeholder "rto" — gets refined later. The test asserts
    # only that rtx is non-None.
    assert segs[0].rtx is not None


def test_acks_extracted_from_green_steps_with_rwin_from_yellow():
    # Real excerpt — ACK at t=…784126 acking up to 3493560736, rwin top 3493594312.
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
green
line 1538187584.740369 3493560572 1538187584.784126 3493560572
line 1538187584.784126 3493560572 1538187584.784126 3493560736
yellow
line 1538187584.740369 3493593340 1538187584.784126 3493593340
line 1538187584.784126 3493593340 1538187584.784126 3493594312
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    acks = pair.fwd.acks
    assert len(acks) == 1
    a = acks[0]
    assert a.time == pytest.approx(1538187584.784126)
    assert a.ack_seq == 3493560736
    # rwin is the *gap* between top of yellow and the ack seq at that moment.
    assert a.rwin == 3493594312 - 3493560736  # 33576
    assert a.dup_count == 0
    assert a.sack_blocks == ()


def test_dup_ack_count_from_preceding_green_atext():
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
green
atext 1538187584.832115 3493560736
3
line 1538187584.784126 3493560736 1538187584.832115 3493560736
line 1538187584.832115 3493560736 1538187584.832115 3493560736
yellow
line 1538187584.784126 3493594312 1538187584.832115 3493594312
line 1538187584.832115 3493594312 1538187584.832115 3493594721
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    acks = pair.fwd.acks
    assert len(acks) == 1
    assert acks[0].dup_count == 3


def test_sack_blocks_parsed_from_purple_lines():
    # tcptrace draws each SACK block as a PURPLE vertical line from sack_left to
    # sack_right (+ hticks), at the report time — NOT a box (the 2-coord FIN
    # marker), and purple, not yellow (trace.c:127,2398-2412).
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
green
line 100.0 1000 200.0 1000
line 200.0 1000 200.0 1200
yellow
line 100.0 5000 200.0 5000
line 200.0 5000 200.0 6000
purple
line 200.0 2000 200.0 2500
line 200.0 3000 200.0 3500
htick 200.0 2000
htick 200.0 2500
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    acks = pair.fwd.acks
    assert len(acks) == 1
    # Both SACK blocks attach to the ack at t=200 (the purple lines' time).
    assert sorted(acks[0].sack_blocks) == [(2000, 2500), (3000, 3500)]


def test_syn_ack_promotion_respects_client_is_a():
    """L4: the SYN/ACK is the responder's (server's) SYN. With client_is_a=False
    (b is the client — e.g. a server-first / mid-stream capture) the server is a,
    so a2b's SYN is the SYN/ACK and b2a's is the bare client SYN — the reverse of
    the hardcoded 'b2a == SYN/ACK' assumption."""
    from tcptrace_ng.tcp_inspect import _extract_flag_events

    xpl = parse_xpl(
        "timeval double\ntitle\n1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)\n"
        "xlabel\ntime\nylabel\nsequence number\norange\natext 1.0 1000\nSYN\n"
    )
    # a is the server (client_is_a=False) -> a2b's SYN is the SYN/ACK.
    assert [e.kind for e in _extract_flag_events(xpl, "a2b", client_is_a=False)] == ["syn_ack"]
    # b2a carries the client's bare SYN.
    assert [e.kind for e in _extract_flag_events(xpl, "b2a", client_is_a=False)] == ["syn"]
    # Unknown client side falls back to the common assumption (a initiates).
    assert [e.kind for e in _extract_flag_events(xpl, "b2a", client_is_a=None)] == ["syn_ack"]


def test_in_flight_series_tracks_highest_sent_minus_highest_acked():
    # Two segments sent, then an ACK that covers the first; then a third seg.
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.0 1000 1.0 1100
line 2.0 1100 2.0 1200
green
line 0.0 1000 3.0 1000
line 3.0 1000 3.0 1100
yellow
line 0.0 5000 3.0 5000
line 3.0 5000 3.0 5100
white
line 4.0 1200 4.0 1300
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    m = pair.fwd
    # in_flight_after at each segment:
    # t=1: sent 1000..1100, ack=1000  → 100 in flight
    # t=2: sent 1100..1200, ack=1000  → 200 in flight
    # t=4: sent 1200..1300, ack=1100  → 200 in flight
    in_flight_by_t = {s.time: s.in_flight_after for s in m.segments}
    assert in_flight_by_t[1.0] == 100
    assert in_flight_by_t[2.0] == 200
    assert in_flight_by_t[4.0] == 200
    # in_flight series carries both send and ack events.
    times = [t for t, _ in m.in_flight]
    assert 1.0 in times and 2.0 in times and 3.0 in times and 4.0 in times


def test_paired_rtt_computed_for_non_retx_segments():
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.000 1000 1.000 1100
line 1.500 1100 1.500 1200
green
line 0.0 1000 1.045 1000
line 1.045 1000 1.045 1200
yellow
line 0.0 5000 1.045 5000
line 1.045 5000 1.045 5200
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    segs = pair.fwd.segments
    # The ack at t=1.045 covers the first segment (1000..1100); ack_seq=1200 >= 1100.
    # The second segment (t=1.500) has no later ack → no pair.
    paired = [s for s in segs if s.paired_rtt_ms is not None]
    assert len(paired) == 1
    assert paired[0].seq_end == 1100
    assert paired[0].paired_ack_time == pytest.approx(1.045)
    assert paired[0].paired_rtt_ms == pytest.approx(45.0, abs=0.1)
    unpaired = [s for s in segs if s.paired_rtt_ms is None]
    assert len(unpaired) == 1
    assert unpaired[0].seq_end == 1200
    assert unpaired[0].paired_ack_time is None


def test_paired_rtt_skips_retx_segments():
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
red
line 1.000 1000 1.000 1100
green
line 0.0 1000 1.100 1000
line 1.100 1000 1.100 1100
yellow
line 0.0 5000 1.100 5000
line 1.100 5000 1.100 5100
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    segs = pair.fwd.segments
    assert len(segs) == 1
    # Retx: paired RTT must stay None (Karn).
    assert segs[0].paired_rtt_ms is None
    assert segs[0].paired_ack_time is None


def test_retx_classified_fast_when_preceded_by_three_dup_acks():
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
green
atext 1.010 1000
3
line 0.0 1000 1.010 1000
line 1.010 1000 1.010 1000
yellow
line 0.0 5000 1.010 5000
line 1.010 5000 1.010 5100
red
line 1.020 1000 1.020 1100
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    rtx_segs = [s for s in pair.fwd.segments if s.rtx is not None]
    assert len(rtx_segs) == 1
    assert rtx_segs[0].rtx == "fast"


def test_retx_classified_rto_when_no_preceding_dup_acks():
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.000 1000 1.000 1100
red
line 1.500 1000 1.500 1100
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    rtx_segs = [s for s in pair.fwd.segments if s.rtx is not None]
    assert len(rtx_segs) == 1
    assert rtx_segs[0].rtx == "rto"


def test_retx_classified_spurious_when_original_already_acked():
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.000 1000 1.000 1100
green
line 0.0 1000 1.050 1000
line 1.050 1000 1.050 1100
yellow
line 0.0 5000 1.050 5000
line 1.050 5000 1.050 5100
red
line 1.200 1000 1.200 1100
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    rtx_segs = [s for s in pair.fwd.segments if s.rtx is not None]
    assert len(rtx_segs) == 1
    assert rtx_segs[0].rtx == "spurious"


def test_anomaly_rto_emitted_for_rto_retx():
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.000 1000 1.000 1100
red
line 1.500 1000 1.500 1100
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    anomalies = pair.fwd.anomalies
    kinds = [a.kind for a in anomalies]
    assert "rto" in kinds


def test_rwin_known_when_yellow_unchanged_between_acks():
    """tcptrace omits the yellow vertical when the advertised window doesn't
    change between two ACKs — it only emits a horizontal yellow line ending
    at the next ACK's time plus a utick at that point. Previously we only
    consulted yellow verticals, so those ACKs got rwin_known=False and
    rwin=0, collapsing the rwin trace to ack_seq for one sample and creating
    a misleading vertical spike on the chart. The horizontal endpoint + tick
    carry the same level information and must be honored."""
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
green
line 0.0 1000 1.0 1000
line 1.0 1000 1.0 1100
line 1.0 1100 2.0 1100
line 2.0 1100 2.0 1200
yellow
line 0.0 5000 1.0 5000
line 1.0 5000 1.0 5500
line 1.0 5500 2.0 5500
utick 2.0 5500
"""
    pair = synthesize(parse_xpl(xpl_text), None, "")
    acks = pair.fwd.acks
    assert len(acks) == 2
    # rwin level stayed at 5500 between t=1 and t=2; ack 2 at seq 1200.
    assert acks[1].rwin_known is True, "yellow endpoint/tick at ack time should make rwin known"
    assert acks[1].rwin == 5500 - 1200


def test_rwin_uses_post_step_endpoint_on_window_shrink():
    """tcptrace's yellow vertical at an ACK is `line x OLD x NEW` (trace.c:2345
    — y1 is the old windowend, y2 is the new one). Using `max(y1, y2)` was a
    grow-only convenience that silently returned the OLD level on shrinks,
    leaving rwin frozen at the prior value, masking downstream win_shrink /
    zero_win detection, and pinning the chart's yellow line at the old top."""
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
green
line 0.0 1000 1.0 1000
line 1.0 1000 1.0 1100
line 1.0 1100 2.0 1100
line 2.0 1100 2.0 1200
yellow
line 0.0 6500 1.0 6500
line 1.0 6500 1.0 7000
line 1.0 7000 2.0 7000
line 2.0 7000 2.0 5000
"""
    pair = synthesize(parse_xpl(xpl_text), None, "")
    acks = pair.fwd.acks
    assert len(acks) == 2
    # ack 1 at seq 1100 with window top 7000 → rwin = 5900 (grow).
    assert acks[0].rwin == 7000 - 1100
    # ack 2 at seq 1200 with window top 5000 (shrink from 7000) → rwin = 3800.
    assert acks[1].rwin == 5000 - 1200, "post-step y2 should govern; max() returns the old top"
    # win_shrink anomaly should fire — prior code missed it because rwin
    # appeared unchanged.
    kinds = [a.kind for a in pair.fwd.anomalies]
    assert "win_shrink" in kinds or "win_shrink_large" in kinds


def test_in_flight_excludes_syn_fin_orange_verticals():
    """The orange SYN (and FIN) verticals span 1 byte of sequence space — they
    are control packets, not data. Previously they were extracted as Segments
    and fed into _compute_in_flight, so the in-flight series got a sub-pixel
    spike at SYN time and pre_first_baseline anchored at the SYN's seq instead
    of the first data segment's. The cyan in-flight fill rendered starting at
    SYN time, ahead of any data flow.

    Drop them at extraction so the in-flight band anchors at the first real
    data send."""
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
orange
line 0.0 1000 0.0 1001
white
line 1.0 1001 1.0 1501
orange
line 5.0 1501 5.0 1502
green
line 0.0 1001 2.0 1001
line 2.0 1001 2.0 1501
yellow
line 0.0 6000 2.0 6000
line 2.0 6000 2.0 6500
"""
    pair = synthesize(parse_xpl(xpl_text), None, "")
    m = pair.fwd
    # Only the white 1001→1501 data segment survives; SYN and FIN are dropped.
    assert len(m.segments) == 1
    assert m.segments[0].seq_start == 1001
    assert m.segments[0].seq_end == 1501
    # No in-flight series entries at SYN (t=0.0) or FIN (t=5.0) time —
    # neither contributes a send event to the replay.
    times = [t for t, _ in m.in_flight]
    assert 0.0 not in times, f"SYN must not anchor in_flight; got {times}"
    assert 5.0 not in times, f"FIN must not anchor in_flight; got {times}"


def test_anomaly_zero_win_when_rwin_zero_at_ack():
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
green
line 0.0 1000 1.0 1000
line 1.0 1000 1.0 1100
yellow
line 0.0 1000 1.0 1000
line 1.0 1000 1.0 1100
"""
    # rwin top == ack seq → rwin = 0
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    kinds = [a.kind for a in pair.fwd.anomalies]
    assert "zero_win" in kinds


def test_no_zero_win_when_rwin_unknown():
    """L5: a green ACK step with no co-timed yellow rwin line means the window is
    UNKNOWN, not zero. Defaulting rwin to 0 conflated the two and fired a false
    severe zero_win (and could fire a false win_shrink)."""
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
green
line 0.0 1000 1.0 1000
line 1.0 1000 1.0 1100
"""
    pair = synthesize(parse_xpl(xpl_text), None, "")
    assert pair.fwd.acks
    assert pair.fwd.acks[0].rwin_known is False  # no co-timed yellow → unknown
    assert "zero_win" not in [a.kind for a in pair.fwd.anomalies]


def test_anomaly_ooo_when_seg_seq_below_max_seen():
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.0 1000 1.0 1100
line 2.0 1200 2.0 1300
line 3.0 1100 3.0 1200
"""
    # Segment at t=3 sends seq 1100..1200, which is BELOW max seen (1300) → OOO
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    kinds = [a.kind for a in pair.fwd.anomalies]
    assert "ooo" in kinds


def test_anomaly_sack_gap_when_sack_block_above_current_ack():
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
green
line 0.0 1000 1.0 1000
line 1.0 1000 1.0 1100
yellow
line 0.0 5000 1.0 5000
line 1.0 5000 1.0 5100
purple
line 1.0 2000 1.0 2500
"""
    # ACK is at 1100, SACK block (purple line) covers 2000..2500 → gap below it
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    kinds = [a.kind for a in pair.fwd.anomalies]
    assert "sack_gap" in kinds


def test_anomaly_syn_emitted_from_atext_label():
    # tcptrace emits `atext T S` followed by a `SYN` label line for SYN-bearing
    # packets in both directions of the handshake. The b2a xpl in a real trace
    # carries the same shape for the SYN+ACK reply.
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
orange
diamond 1.0 1000
atext 1.0 1001
SYN
uarrow 1.0 1001
line 1.0 1000 1.0 1001
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    syns = [a for a in pair.fwd.anomalies if a.kind == "syn"]
    assert len(syns) == 1
    assert syns[0].time == 1.0


def test_anomaly_syn_in_backward_direction_becomes_syn_ack():
    # The backward direction's "SYN" label is the responder's SYN/ACK half of
    # the handshake — we promote it to syn_ack so the rendered glyph is "SA".
    xpl_text = """\
timeval double
title
2.2.2.2:2 ==> 1.1.1.1:1 (time sequence graph)
xlabel
time
ylabel
sequence number
orange
diamond 1.5 5000
atext 1.5 5001
SYN
uarrow 1.5 5001
line 1.5 5000 1.5 5001
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(None, xpl, "")
    syn_acks = [a for a in pair.bwd.anomalies if a.kind == "syn_ack"]
    assert len(syn_acks) == 1
    assert syn_acks[0].time == 1.5
    # The plain "syn" kind is reserved for the forward (initiator) SYN.
    assert not [a for a in pair.bwd.anomalies if a.kind == "syn"]


def test_anomaly_fin_emitted_from_atext_label():
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
orange
darrow 5.0 2000
line 5.0 2000 5.0 2001
box 5.0 2001
atext 5.0 2001
FIN
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    fins = [a for a in pair.fwd.anomalies if a.kind == "fin"]
    assert len(fins) == 1
    assert fins[0].time == 5.0


def test_anomaly_fin_retx_emitted_from_r_fin_label():
    # Red color + "R FIN" atext: a FIN retransmit. We want it classified as
    # fin_retx (more descriptive), not as a generic rto/spurious.
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
red
darrow 6.0 2000
line 6.0 2000 6.0 2001
box 6.0 2001
atext 6.0 2001
R FIN
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "")
    kinds = [a.kind for a in pair.fwd.anomalies]
    assert "fin_retx" in kinds
    # And the rto/spurious that the segment-classifier would otherwise emit at
    # the same time is suppressed — no double-labeling.
    assert "rto" not in kinds
    assert "spurious" not in kinds
    # M1: the phantom RTO must not survive in the stats panel either. window_stats
    # counts Segment.rtx, so suppression has to clear it — otherwise the chart
    # shows fin_retx while the stats grid shows a bad-colored "1 RTO".
    ws = pair.fwd.window_stats(None, None)
    assert ws.n_rto == 0
    assert ws.n_retx == 0


def test_bad_csum_times_become_anomalies_anchored_to_cumack():
    # Caller-supplied bad-csum times (from csum.scan_pcap) become bad_csum
    # anomalies on the matching direction's model, anchored to the cumack at
    # the event time so labels don't crash to y=0.
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.0 1000 1.0 1100
green
line 0.0 1000 1.5 1000
line 1.5 1000 1.5 1100
yellow
line 0.0 9000 1.5 9000
line 1.5 9000 1.5 9100
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "", bad_csum_times_fwd=[0.5, 2.0])
    bc = [a for a in pair.fwd.anomalies if a.kind == "bad_csum"]
    assert len(bc) == 2
    # First event lands before any ack; falls back to the first ack's seq.
    assert bc[0].seq_lo == 1000
    # Second event after cumack jump → anchored to the new cumack 1100.
    assert bc[1].seq_lo == 1100


def test_bad_csum_classified_acked_when_seq_acked_without_retx():
    # A segment at t=1.0 sending bytes 1000..1100. The cumack reaches 1100 at
    # t=1.5 and no retx of that range happens — so the bad-csum on that
    # original packet is `bad_csum_acked` (likely NIC offload, not corruption).
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.0 1000 1.0 1100
green
line 0.0 1000 1.5 1000
line 1.5 1000 1.5 1100
yellow
line 0.0 9000 1.5 9000
line 1.5 9000 1.5 9100
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "", bad_csum_times_fwd=[1.0])
    bc = [a for a in pair.fwd.anomalies if a.kind.startswith("bad_csum")]
    assert len(bc) == 1
    assert bc[0].kind == "bad_csum_acked"


def test_bad_csum_classified_lost_when_seq_retransmitted():
    # Segment at t=1.0 carrying 1000..1100. Cumack stays at 1000 (no
    # progress); at t=2.0 the same seq range is retransmitted (red). The
    # original is classified as `bad_csum_lost` — actually dropped.
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.0 1000 1.0 1100
red
line 2.0 1000 2.0 1100
green
line 0.0 1000 3.0 1000
yellow
line 0.0 9000 3.0 9000
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "", bad_csum_times_fwd=[1.0])
    bc = [a for a in pair.fwd.anomalies if a.kind.startswith("bad_csum")]
    assert len(bc) == 1
    assert bc[0].kind == "bad_csum_lost"


def test_window_stats_counts_bad_csum():
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.0 1000 1.0 1100
green
line 0.0 1000 1.5 1000
line 1.5 1000 1.5 1100
yellow
line 0.0 9000 1.5 9000
line 1.5 9000 1.5 9100
"""
    xpl = parse_xpl(xpl_text)
    pair = synthesize(xpl, None, "", bad_csum_times_fwd=[0.5, 1.2, 2.0])
    ws = pair.fwd.window_stats(None, None)
    assert ws.n_bad_csum == 3


def test_dup_ack_cross_direction_from_non_advancing_green_after_horizontal():
    # Cross-direction setup: b's pure-ACK markers (in b2a xpl) are classified
    # against a's cumack staircase (in a2b xpl). A pure-ACK at time t whose
    # opposing staircase has a zero-length green point at t — preceded by a
    # horizontal, not by an advancing vertical — is a dup-ACK. The anomaly
    # attaches to the fwd model (where the staircase lives).
    fwd_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.0 1000 1.0 1100
green
line 0.0 1000 1.5 1000
line 1.5 1000 1.5 1100
line 1.5 1100 2.0 1100
line 2.0 1100 2.0 1100
line 2.0 1100 2.5 1100
line 2.5 1100 2.5 1100
yellow
line 0.0 9000 2.5 9000
"""
    bwd_text = """\
timeval double
title
2.2.2.2:2 ==> 1.1.1.1:1 (time sequence graph)
xlabel
time
ylabel
sequence number
white
darrow 2.0 5000
uarrow 2.0 5000
darrow 2.5 5000
uarrow 2.5 5000
green
line 0.0 5000 2.5 5000
yellow
line 0.0 8000 2.5 8000
"""
    pair = synthesize(parse_xpl(fwd_text), parse_xpl(bwd_text), "")
    # The two b→a pure-ACK markers at t=2.0 and t=2.5 land on a stretch of
    # cumack staircase (a's ack of b's data… we set up the *fwd* model's
    # staircase to be flat — meaning b's cumacks of a's data didn't advance —
    # which is what flags both as dup-ACKs.) Anomalies attach to fwd model.
    dups = [a for a in pair.fwd.anomalies if a.kind == "dup_ack"]
    assert len(dups) == 2


def test_dup_ack_skipped_when_opposite_xpl_absent():
    # Without both directions, cross-classification can't run — pure-ACK
    # markers in a single-direction xpl don't produce dup-ACK anomalies.
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
green
line 0.0 1000 1.0 1000
line 1.0 1000 1.0 1100
yellow
line 0.0 9000 1.0 9000
line 1.0 9000 1.0 9100
white
darrow 2.0 1100
uarrow 2.0 1100
darrow 3.0 1100
uarrow 3.0 1100
"""
    pair = synthesize(parse_xpl(xpl_text), None, "")
    dups = [a for a in pair.fwd.anomalies if a.kind == "dup_ack"]
    assert dups == []
    # Pure-ACK times still get extracted for future cross-classification.
    assert len(pair.fwd.pure_ack_times) == 2


def test_no_partial_ack_on_clean_pipelined_transfer():
    """H3: cumack trailing max_sent is the NORMAL condition of any pipelined
    transfer (the sender stays ahead of the ACKs). Without a loss-recovery
    context — an outstanding retransmit or an open SACK gap — an advancing
    cumulative ACK is not a partial ACK; Wireshark's tcp.analysis.partial_ack
    only fires during recovery. A clean lossless transfer must yield zero."""
    from tcptrace_ng.tcp_inspect import _classify_pure_acks

    opp = TsgModel(
        segments=[
            Segment(
                time=1.0,
                seq_start=1,
                seq_end=1001,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=0,
            ),
            Segment(
                time=1.0,
                seq_start=1001,
                seq_end=2001,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=0,
            ),
            Segment(
                time=1.0,
                seq_start=2001,
                seq_end=3001,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=0,
            ),
        ],
        acks=[
            Ack(time=1.1, ack_seq=1001, rwin=9000, rwin_scaled=None, sack_blocks=(), dup_count=0),
            Ack(time=1.2, ack_seq=2001, rwin=9000, rwin_scaled=None, sack_blocks=(), dup_count=0),
            Ack(time=1.3, ack_seq=3001, rwin=9000, rwin_scaled=None, sack_blocks=(), dup_count=0),
        ],
        non_advancing_ack_times=[],
    )
    # Pure ACKs that advance cumack but trail max_sent — normal pipelining.
    anoms = _classify_pure_acks([1.1, 1.2], opp)
    assert [a for a in anoms if a.kind == "partial_ack"] == []


def test_partial_ack_fires_during_loss_recovery():
    """The genuine case Wireshark flags: an advancing cumulative ACK that
    leaves an outstanding *retransmitted* segment only partly acked is a real
    partial ACK and must still be surfaced."""
    from tcptrace_ng.tcp_inspect import _classify_pure_acks

    opp = TsgModel(
        segments=[
            Segment(
                time=1.0,
                seq_start=1,
                seq_end=1001,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=0,
            ),
            # A lost 2000-byte segment, retransmitted (fast) at t=1.5.
            Segment(
                time=1.5,
                seq_start=1001,
                seq_end=3001,
                rtx="fast",
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=0,
            ),
        ],
        acks=[
            Ack(time=1.1, ack_seq=1001, rwin=9000, rwin_scaled=None, sack_blocks=(), dup_count=0),
            # Advances into the retransmit but leaves it short of seq_end (3001).
            Ack(time=1.6, ack_seq=2001, rwin=9000, rwin_scaled=None, sack_blocks=(), dup_count=0),
        ],
        non_advancing_ack_times=[],
    )
    partials = [a for a in _classify_pure_acks([1.6], opp) if a.kind == "partial_ack"]
    assert len(partials) == 1
    assert partials[0].seq_lo == 2001


def test_coalesced_segment_flagged_when_size_exceeds_mss():
    # Single 5000-byte segment with MSS=1460 in details_text → coalesced.
    details = (
        "TCP connection 1:\n"
        "   mss requested:          1460 bytes     mss requested:          1460 bytes\n"
    )
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.0 1000 1.0 6000
green
line 0.0 1000 2.0 1000
line 2.0 1000 2.0 6000
yellow
line 0.0 9000 2.0 9000
"""
    pair = synthesize(parse_xpl(xpl_text), None, details)
    coalesced = [a for a in pair.fwd.anomalies if a.kind == "coalesced"]
    assert len(coalesced) == 1
    assert coalesced[0].seq_lo == 1000
    assert coalesced[0].seq_hi == 6000


def test_coalesced_not_flagged_when_mss_missing_from_details():
    # No -l text means we can't compute coalesce thresholds; segs pass through.
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.0 1000 1.0 6000
yellow
line 0.0 9000 2.0 9000
"""
    pair = synthesize(parse_xpl(xpl_text), None, "")
    coalesced = [a for a in pair.fwd.anomalies if a.kind == "coalesced"]
    assert coalesced == []


def test_window_scale_flows_from_details_to_model_with_correct_pairing():
    """wscale on the a→b model is what host b advertised (b's wscale governs
    the rwin drawn on a→b — receiver's scale). Mirror for b→a."""
    details = """\
TCP connection 1:
\thost a:        1.1.1.1:1111
\thost b:        2.2.2.2:2222
   a->b:                                  b->a:
     adv wind scale:            5           adv wind scale:            8
     mss requested:          1460 bytes     mss requested:          1440 bytes
================================
"""
    xpl_text = """\
timeval double
title
1.1.1.1:1111 ==> 2.2.2.2:2222 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.0 100 1.0 200
yellow
line 0.0 9000 2.0 9000
"""
    xpl_rev = """\
timeval double
title
2.2.2.2:2222 ==> 1.1.1.1:1111 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.0 100 1.0 200
yellow
line 0.0 9000 2.0 9000
"""
    pair = synthesize(parse_xpl(xpl_text), parse_xpl(xpl_rev), details)
    assert pair.fwd is not None and pair.bwd is not None
    # fwd's rwin is b's advertised window → governed by b's wscale shift.
    assert pair.fwd.window_scale == 8
    assert pair.bwd.window_scale == 5
    assert pair.fwd.summary is not None
    assert pair.fwd.summary.host_a == "1.1.1.1:1111"


def test_window_scale_is_none_without_details_text():
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.0 100 1.0 200
yellow
line 0.0 9000 2.0 9000
"""
    pair = synthesize(parse_xpl(xpl_text), None, "")
    assert pair.fwd.window_scale is None
    assert pair.fwd.summary is None


# ---------------------------------------------------------------------------
# Severity classification + escalation
# ---------------------------------------------------------------------------


def test_severity_by_kind_covers_every_anomaly_kind():
    """Every kind must have a known tier so the chart never falls back to
    silent default coloring — adding a new kind without a tier is a bug."""
    from typing import get_args

    from tcptrace_ng.tcp_inspect import AnomalyKind

    for kind in get_args(AnomalyKind):
        assert kind in SEVERITY_BY_KIND, f"{kind!r} missing severity tier"


def test_win_shrink_promoted_to_large_when_shrink_meets_mss():
    """A 1500-byte shrink with MSS=1460 → severe; a 100-byte shrink stays info."""
    from tcptrace_ng.tcp_inspect import _detect_anomalies

    acks_large_shrink = [
        Ack(time=0.0, ack_seq=1000, rwin=10_000, rwin_scaled=None, sack_blocks=(), dup_count=0),
        Ack(time=1.0, ack_seq=1000, rwin=8_500, rwin_scaled=None, sack_blocks=(), dup_count=0),
    ]
    out = _detect_anomalies([], acks_large_shrink, mss=1460)
    kinds = [a.kind for a in out]
    assert "win_shrink_large" in kinds
    assert "win_shrink" not in kinds

    acks_small_shrink = [
        Ack(time=0.0, ack_seq=1000, rwin=10_000, rwin_scaled=None, sack_blocks=(), dup_count=0),
        Ack(time=1.0, ack_seq=1000, rwin=9_900, rwin_scaled=None, sack_blocks=(), dup_count=0),
    ]
    out = _detect_anomalies([], acks_small_shrink, mss=1460)
    kinds = [a.kind for a in out]
    assert "win_shrink" in kinds
    assert "win_shrink_large" not in kinds


def test_win_shrink_without_mss_stays_info():
    """Without MSS we can't threshold — leave shrinks as info to avoid noise."""
    from tcptrace_ng.tcp_inspect import _detect_anomalies

    acks = [
        Ack(time=0.0, ack_seq=1000, rwin=10_000, rwin_scaled=None, sack_blocks=(), dup_count=0),
        Ack(time=1.0, ack_seq=1000, rwin=5_000, rwin_scaled=None, sack_blocks=(), dup_count=0),
    ]
    out = _detect_anomalies([], acks, mss=None)
    kinds = [a.kind for a in out]
    assert "win_shrink" in kinds
    assert "win_shrink_large" not in kinds


def test_dup_ack_escalates_when_cumack_matches_fast_retx_seq():
    """A dup_ack whose cumack matches a same-direction fast-retx seq_start
    becomes dup_ack_drove_retx — distinguishing causal dups from cosmetic ones."""
    from tcptrace_ng.tcp_inspect import _escalate_dup_acks

    model = TsgModel(
        anomalies=[
            Anomaly(time=1.0, kind="dup_ack", one_liner="dup at 1000", seq_lo=1000, seq_hi=1000),
            Anomaly(time=1.5, kind="fast", one_liner="fast retx", seq_lo=1000, seq_hi=1100),
            Anomaly(time=2.0, kind="dup_ack", one_liner="dup at 2000", seq_lo=2000, seq_hi=2000),
        ],
    )
    _escalate_dup_acks(model)
    kinds = [a.kind for a in model.anomalies]
    assert "dup_ack_drove_retx" in kinds  # matched cumack=1000
    assert "dup_ack" in kinds  # unmatched cumack=2000 stays


def test_handshake_ack_is_bare_pure_ack_not_first_data_ack():
    """H2: the 3rd handshake packet is fwd's bare ACK of the responder's ISN+1
    — a zero-payload packet that does NOT advance fwd's cumack staircase, so it
    is absent from fwd.acks. The first cumack-advancing ACK there is the first
    *data* ACK, ~1 RTT + server think-time later; reporting it fabricates a
    large handshake-completion delay. The completer comes from the pure-ACK
    stream (the first zero-payload packet fwd sent after the SYN/ACK)."""
    from tcptrace_ng.tcp_inspect import _emit_handshake_ack

    fwd = TsgModel(
        # First cumack-advancing ACK is the first DATA ACK, long after the
        # handshake completes — must NOT be chosen as the completer.
        acks=[
            Ack(time=2.0, ack_seq=5001, rwin=1024, rwin_scaled=None, sack_blocks=(), dup_count=0),
        ],
        # Bare 3rd-handshake ACK: a zero-payload packet just after the SYN/ACK.
        pure_ack_times=[1.51],
        # Forward SYN marker fixes the a-side initial sequence for the glyph.
        anomalies=[
            Anomaly(time=1.0, kind="syn", one_liner="syn", seq_lo=1000, seq_hi=1000),
        ],
    )
    bwd = TsgModel(
        anomalies=[
            Anomaly(time=1.5, kind="syn_ack", one_liner="syn_ack", seq_lo=5000, seq_hi=5000),
        ],
    )
    _emit_handshake_ack(fwd, bwd)
    hs = [a for a in fwd.anomalies if a.kind == "handshake_ack"]
    assert len(hs) == 1
    # The completer is the pure ACK at 1.51 (+10 ms), not the data ACK at 2.0.
    assert hs[0].time == 1.51
    assert "10.0 ms after SYN/ACK" in hs[0].one_liner
    # Positioned at fwd's handshake sequence (the SYN label), not a data cumack.
    assert hs[0].seq_lo == 1000
    # Must not report the misleading first-data-ACK cumack (5001).
    assert "5,001" not in hs[0].one_liner


# ---------------------------------------------------------------------------
# TsgModel.window_stats() tests
# ---------------------------------------------------------------------------


def _model_with_segments_and_acks() -> TsgModel:
    xpl_text = """\
timeval double
title
1.1.1.1:1 ==> 2.2.2.2:2 (time sequence graph)
xlabel
time
ylabel
sequence number
white
line 1.0 1000 1.0 1100
line 2.0 1100 2.0 1200
line 3.0 1200 3.0 1300
green
line 0.0 1000 1.5 1000
line 1.5 1000 1.5 1100
line 1.5 1100 2.5 1100
line 2.5 1100 2.5 1200
yellow
line 0.0 9000 1.5 9000
line 1.5 9000 1.5 9100
line 1.5 9100 2.5 9100
line 2.5 9100 2.5 9200
"""
    return synthesize(parse_xpl(xpl_text), None, "").fwd


def test_window_stats_whole_connection():
    m = _model_with_segments_and_acks()
    ws = m.window_stats(None, None)
    assert ws.n_segs == 3
    assert ws.bytes_sent == 300


def test_window_stats_slices_by_time_range():
    m = _model_with_segments_and_acks()
    ws = m.window_stats(1.5, 2.5)
    # Segments at t=2.0 only (1.5 < t <= 2.5).
    assert ws.n_segs == 1
    assert ws.bytes_sent == 100


def test_window_stats_returns_throughput_in_Bps():
    m = _model_with_segments_and_acks()
    ws = m.window_stats(1.0, 3.0)
    # 300 bytes over (3.0 - 1.0) = 2.0 s → 150 Bps.
    assert ws.throughput_eff_Bps == pytest.approx(150.0)


def test_segment_has_fabricated_flag_default_false():
    from tcptrace_ng.tcp_inspect import Segment

    s = Segment(
        time=1.0,
        seq_start=0,
        seq_end=1448,
        rtx=None,
        paired_ack_time=None,
        paired_rtt_ms=None,
        in_flight_after=0,
    )
    assert s.fabricated is False


def test_segment_fabricated_can_be_set():
    from tcptrace_ng.tcp_inspect import Segment

    s = Segment(1.0, 0, 1448, None, None, None, 0, True)
    assert s.fabricated is True


def test_tsgmodel_coalesces_defaults_empty():
    from tcptrace_ng.tcp_inspect import TsgModel

    assert TsgModel().coalesces == []


def test_tag_fabricated_by_timestamp_and_seq():
    from tcptrace_ng.tcp_inspect import Segment, _tag_fabricated

    segs = [
        Segment(1.0, 1000, 2448, None, None, None, 0),  # piece 1 of the coalesce
        Segment(1.0, 2448, 3896, None, None, None, 0),  # piece 2
        Segment(2.0, 3896, 5344, None, None, None, 0),  # unrelated, real (other ts)
    ]
    coalesces = [
        {
            "time": 1.0,
            "parent_seq_start": 1000,
            "parent_seq_end": 3896,
            "pieces": 2,
            "mss": 1448,
            "mss_source": "syn",
            "src": "a",
            "dst": "b",
        }
    ]
    tagged = _tag_fabricated(segs, coalesces)
    assert [s.fabricated for s in tagged] == [True, True, False]


def test_tag_fabricated_timestamp_collision_disambiguated_by_seq():
    from tcptrace_ng.tcp_inspect import Segment, _tag_fabricated

    segs = [
        Segment(1.0, 1000, 2000, None, None, None, 0),  # coalesce A
        Segment(1.0, 5000, 6000, None, None, None, 0),  # coalesce B
        Segment(1.0, 9000, 9500, None, None, None, 0),  # real: same ts, outside both spans
    ]
    coalesces = [
        {
            "time": 1.0,
            "parent_seq_start": 1000,
            "parent_seq_end": 2000,
            "pieces": 1,
            "mss": 1000,
            "mss_source": "syn",
            "src": "a",
            "dst": "b",
        },
        {
            "time": 1.0,
            "parent_seq_start": 5000,
            "parent_seq_end": 6000,
            "pieces": 1,
            "mss": 1000,
            "mss_source": "syn",
            "src": "a",
            "dst": "b",
        },
    ]
    assert [s.fabricated for s in _tag_fabricated(segs, coalesces)] == [True, True, False]


def test_tag_fabricated_empty_is_noop():
    from tcptrace_ng.tcp_inspect import Segment, _tag_fabricated

    segs = [Segment(1.0, 0, 1448, None, None, None, 0)]
    assert _tag_fabricated(segs, []) is segs


def test_window_stats_counts_fabricated():
    from tcptrace_ng.tcp_inspect import Segment, TsgModel

    m = TsgModel(
        segments=[
            Segment(1.0, 0, 1460, None, None, None, 0, True),
            Segment(1.0, 1460, 2920, None, None, None, 0, True),
            Segment(2.0, 2920, 4380, None, None, None, 0, False),
        ]
    )
    ws = m.window_stats(None, None)
    assert ws.n_fabricated == 2
    assert ws.n_segs == 3
