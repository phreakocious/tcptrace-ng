# tests/test_diagnose.py
"""Unit tests for the pure diagnosis layer (hand-built models)."""

from __future__ import annotations

from tcptrace_ng.classifier import Class
from tcptrace_ng.diagnose import Finding, diagnose, severity_to_class
from tcptrace_ng.stats_parser import ConnStats
from tcptrace_ng.tcp_inspect import Anomaly, Segment, TsgModel, TsgModelPair
from tcptrace_ng.throughput import ThroughputModelPair


def test_severity_maps_to_class():
    assert severity_to_class("good") is Class.GOOD
    assert severity_to_class("interesting") is Class.LOOK
    assert severity_to_class("bad") is Class.BAD


def test_diagnose_empty_inputs_returns_empty_list():
    out = diagnose(None, TsgModelPair(), ThroughputModelPair())
    assert out == []


def test_finding_is_frozen():
    from dataclasses import FrozenInstanceError

    import pytest

    f = Finding(code="x", severity="good", scope="conn", headline="h", detail="d")
    with pytest.raises(FrozenInstanceError):
        f.code = "y"  # type: ignore[misc]


def _stats(**kw) -> ConnStats:
    base: dict[str, object] = {
        "n": 1,
        "host_a": "10.0.0.1:50000",
        "host_b": "10.0.0.2:443",
        "client_is_a": True,
        "total_bytes": 4000,
        "total_packets": 14,
        "duration_s": 0.2,
        "rexmt_packets": 0,
        "has_rst": False,
        "complete_handshake": True,
        "verdict": Class.NORMAL,
        "fwd_ctx": "",
        "bwd_ctx": "",
    }
    base.update(kw)
    return ConnStats(**base)


def test_vantage_client_side_when_b2a_rtt_near_zero():
    from tcptrace_ng.diagnose import _capture_vantage

    out = _capture_vantage(_stats(rtt_3whs_a=80.0, rtt_3whs_b=0.1))
    assert len(out) == 1
    f = out[0]
    assert f.code == "capture_vantage"
    assert f.evidence["vantage"] == "client"


def test_vantage_silent_on_lan_both_subms():
    from tcptrace_ng.diagnose import _capture_vantage

    assert _capture_vantage(_stats(rtt_3whs_a=0.3, rtt_3whs_b=0.2)) == []


def test_vantage_midpoint_when_both_halves_substantial():
    from tcptrace_ng.diagnose import _capture_vantage

    out = _capture_vantage(_stats(rtt_3whs_a=40.0, rtt_3whs_b=45.0))
    assert out and out[0].evidence["vantage"] == "midpoint"


def test_vantage_midpoint_fires_at_3x_boundary():
    # far == 3*near is inclusive in the midpoint region (near >= 2, far <= 3*near).
    from tcptrace_ng.diagnose import _capture_vantage

    out = _capture_vantage(_stats(rtt_3whs_a=2.0, rtt_3whs_b=6.0))
    assert out and out[0].evidence["vantage"] == "midpoint"


def test_vantage_silent_just_past_3x_boundary():
    # far just past 3*near with near > 1 ms falls into the conservative gap
    # between the adjacent (far >= 5*near) and midpoint (far <= 3*near) branches.
    from tcptrace_ng.diagnose import _capture_vantage

    assert _capture_vantage(_stats(rtt_3whs_a=2.0, rtt_3whs_b=6.1)) == []


def test_vantage_none_when_rtt_absent():
    from tcptrace_ng.diagnose import _capture_vantage

    assert _capture_vantage(_stats(rtt_3whs_a=None, rtt_3whs_b=None)) == []


def test_vantage_server_side_when_adjacent_host_is_server():
    # Same RTT shape (host a adjacent), but here a is the SERVER, not client.
    from tcptrace_ng.diagnose import _capture_vantage

    out = _capture_vantage(_stats(rtt_3whs_a=80.0, rtt_3whs_b=0.1, client_is_a=False))
    assert out and out[0].evidence["vantage"] == "server"


def test_vantage_host_relative_when_handshake_incomplete():
    # Without a full handshake client_is_a is a guess -> stay host-relative.
    from tcptrace_ng.diagnose import _capture_vantage

    out = _capture_vantage(_stats(rtt_3whs_a=80.0, rtt_3whs_b=0.1, complete_handshake=False))
    assert out and out[0].evidence["vantage"] == "endpoint"
    assert "host A" in out[0].headline


def test_vantage_server_side_when_tap_next_to_low_port_host():
    # a->b RTT near zero -> tap next to host B (the :443 server). client_is_a is
    # None (clean 3WHS), so the port heuristic resolves the role: B is the server.
    from tcptrace_ng.diagnose import _capture_vantage

    out = _capture_vantage(_stats(rtt_3whs_a=0.1, rtt_3whs_b=80.0, client_is_a=None))
    assert out and out[0].evidence["adjacent_host"] == "10.0.0.2"
    assert out[0].evidence["vantage"] == "server"


def test_vantage_host_relative_when_role_undeterminable():
    # client_is_a None and both ports equal -> role can't be inferred; stay
    # host-relative rather than guess.
    from tcptrace_ng.diagnose import _capture_vantage

    out = _capture_vantage(
        _stats(
            rtt_3whs_a=80.0,
            rtt_3whs_b=0.1,
            client_is_a=None,
            host_a="10.0.0.1:443",
            host_b="10.0.0.2:443",
        )
    )
    assert out and out[0].evidence["vantage"] == "endpoint"
    assert "host A" in out[0].headline


def _data_seg(t, lo, hi, rtx=None):
    return Segment(
        time=t,
        seq_start=lo,
        seq_end=hi,
        rtx=rtx,
        paired_ack_time=None,
        paired_rtt_ms=None,
        in_flight_after=0,
    )


def _bulk(n, *, retx_idx=(), one_byte_retx_idx=()):
    """n full-size data segments; some marked as rto retx (full-size or 1-byte)."""
    segs = []
    seq = 0
    for i in range(n):
        if i in one_byte_retx_idx:
            segs.append(_data_seg(float(i), seq, seq + 1, rtx="rto"))
        elif i in retx_idx:
            segs.append(_data_seg(float(i), seq, seq + 1448, rtx="rto"))
            seq += 1448
        else:
            segs.append(_data_seg(float(i), seq, seq + 1448))
            seq += 1448
    return TsgModel(direction="a2b", segments=segs, acks=[])


def test_loss_storm_fires_bad_on_heavy_loss():
    from tcptrace_ng.diagnose import _loss_storm

    tsg = TsgModelPair(fwd=_bulk(40, retx_idx=range(0, 12)))  # 30% loss
    out = _loss_storm(tsg)
    assert out and out[0].code == "loss_storm" and out[0].severity == "bad"


def test_loss_storm_silent_on_one_byte_keepalive_retx():
    from tcptrace_ng.diagnose import _loss_storm

    # 40 segments, several "retx" but all 1-byte keepalives -> not loss.
    tsg = TsgModelPair(fwd=_bulk(40, one_byte_retx_idx=(5, 15, 25)))
    assert _loss_storm(tsg) == []


def test_loss_storm_silent_below_segment_floor():
    from tcptrace_ng.diagnose import _loss_storm

    tsg = TsgModelPair(fwd=_bulk(8, retx_idx=(0, 1, 2)))  # only 8 segs
    assert _loss_storm(tsg) == []


def test_loss_storm_caps_severity_when_direction_coalesced():
    # 30% loss would be 'bad', but a per-direction coalesced anomaly means the
    # retransmit count is untrustworthy -> cap at interesting.
    from tcptrace_ng.diagnose import _loss_storm

    fwd = _bulk(40, retx_idx=range(0, 12))
    fwd.anomalies.append(
        Anomaly(
            time=0.0,
            kind="coalesced",
            one_liner="coalesced 4,344 B (> MSS 1,460)",
            seq_lo=None,
            seq_hi=None,
        )
    )
    out = _loss_storm(TsgModelPair(fwd=fwd))
    assert out and out[0].code == "loss_storm"
    assert out[0].severity == "interesting"  # capped, not 'bad'
    assert out[0].evidence["offload_capped"] is True
    assert "offload" in out[0].headline.lower()


def test_loss_storm_caps_severity_on_oversized_segment_without_anomaly():
    # MSS unavailable -> no `coalesced` anomaly was emitted, but a data segment
    # spans more than one MTU. The MSS-free backstop must still cap severity.
    from tcptrace_ng.diagnose import _loss_storm

    fwd = _bulk(40, retx_idx=range(0, 12))
    fwd.segments.append(_data_seg(99.0, 100_000, 104_344))  # > 1 MTU span
    out = _loss_storm(TsgModelPair(fwd=fwd))
    assert out and out[0].severity == "interesting"
    assert out[0].evidence["offload_capped"] is True


def test_loss_storm_not_capped_on_jumbo_path_with_known_mss():
    """M2: on a jumbo path (MSS ~8960) every normal segment exceeds 1500, so the
    hardcoded MSS-free backstop wrongly reports the direction coalesced — capping
    a real loss storm to 'interesting' and appending a fabricated offload note.
    With a known MSS the precise `coalesced` anomaly (absent here) is the only
    valid signal; the 1500 backstop must not run."""
    from tcptrace_ng.diagnose import _loss_storm

    segs = []
    seq = 0
    for i in range(40):
        rtx = "rto" if i < 12 else None  # 30% loss -> 'bad' unless wrongly capped
        segs.append(_data_seg(float(i), seq, seq + 8960, rtx=rtx))  # jumbo, > 1500, <= MSS
        seq += 8960
    fwd = TsgModel(direction="a2b", segments=segs, acks=[], mss=8960)
    out = _loss_storm(TsgModelPair(fwd=fwd))
    assert out and out[0].code == "loss_storm"
    assert out[0].severity == "bad"  # NOT capped to 'interesting'
    assert out[0].evidence["offload_capped"] is False
    assert "offload" not in out[0].headline.lower()


def test_loss_storm_excludes_spurious_retx():
    # Spurious retransmits (data that actually arrived, just re-sent) are NOT
    # loss — tcptrace flags them on reordered/offloaded captures. Only rto/fast
    # count toward the storm.
    from tcptrace_ng.diagnose import _loss_storm

    segs = [_data_seg(float(i), i * 1448, (i + 1) * 1448) for i in range(40)]
    for i in (5, 15, 25, 35):
        segs[i] = _data_seg(float(i), i * 1448, (i + 1) * 1448, rtx="spurious")
    tsg = TsgModelPair(fwd=TsgModel(direction="a2b", segments=segs, acks=[]))
    assert _loss_storm(tsg) == []


def test_diagnose_accepts_none_tsg_runs_capture_vantage_only():
    # tsg=None must not crash; only stats-based detectors run.
    stats = _stats(rtt_3whs_a=80.0, rtt_3whs_b=0.1)
    out = diagnose(stats, None, None)
    assert [f.code for f in out] == ["capture_vantage"]


def test_diagnose_all_none_returns_empty():
    assert diagnose(None, None, None) == []


# ---------------------------------------------------------------------------
# _sack_confirmed_loss
# ---------------------------------------------------------------------------


def _ack(t, ack_seq, sack_blocks=(), dup_count=0):
    from tcptrace_ng.tcp_inspect import Ack

    return Ack(
        time=t,
        ack_seq=ack_seq,
        rwin=65535,
        rwin_scaled=65535,
        sack_blocks=tuple(sack_blocks),
        dup_count=dup_count,
        rwin_known=True,
    )


def _seg(t, lo, hi, rtx=None):
    from tcptrace_ng.tcp_inspect import Segment

    return Segment(t, lo, hi, rtx, None, None, 0)


def _fwd_only(segments, acks):
    from tcptrace_ng.tcp_inspect import TsgModel, TsgModelPair

    return TsgModelPair(
        fwd=TsgModel(
            src="10.0.0.1:50000", dst="10.0.0.2:80", direction="a2b", segments=segments, acks=acks
        ),
        bwd=None,
    )


def test_sack_confirmed_loss_fires_bad_on_three_retx_gaps():
    from tcptrace_ng.diagnose import diagnose

    acks, segs = [], []
    for i in range(3):
        base = 1000 + i * 10_000
        acks.append(_ack(1.0 + i, base, sack_blocks=((base + 1000, base + 2000),)))
        segs.append(_seg(2.0 + i, base, base + 1000, rtx="rto"))  # retransmits the gap, later
    findings = diagnose(None, _fwd_only(segs, acks), None)
    hit = [f for f in findings if f.code == "sack_confirmed_loss"]
    assert hit and hit[0].severity == "bad" and hit[0].evidence["sack_confirmed"] == 3


def test_sack_gap_resolved_without_retx_is_reordering_not_loss():
    from tcptrace_ng.diagnose import diagnose

    acks = [_ack(1.0, 1000, sack_blocks=((2000, 3000),), dup_count=1)]  # gap, but...
    segs = [_seg(1.0, 1000, 2000, rtx=None)]  # ...no retransmit, <3 dup
    findings = diagnose(None, _fwd_only(segs, acks), None)
    assert not any(f.code == "sack_confirmed_loss" for f in findings)


def test_sack_confirmed_loss_single_gap_is_interesting_not_bad():
    from tcptrace_ng.diagnose import diagnose

    acks = [_ack(1.0, 1000, sack_blocks=((2000, 3000),))]
    segs = [_seg(2.0, 1000, 2000, rtx="rto")]  # one confirmed gap
    findings = diagnose(None, _fwd_only(segs, acks), None)
    hit = [f for f in findings if f.code == "sack_confirmed_loss"]
    assert hit and hit[0].severity == "interesting"


def test_sack_confirmed_loss_via_three_dup_acks():
    from tcptrace_ng.diagnose import diagnose

    acks = [_ack(1.0, 1000, sack_blocks=((2000, 3000),), dup_count=3)]  # 3 dup-ACKs, no retx needed
    findings = diagnose(None, _fwd_only([], acks), None)
    assert any(f.code == "sack_confirmed_loss" for f in findings)


def test_direction_is_coalesced_treats_mss_zero_as_unavailable():
    # mss==0 is tcptrace's no-SYN sentinel; an oversized segment then reads as coalesced
    from tcptrace_ng.diagnose import _direction_is_coalesced
    from tcptrace_ng.tcp_inspect import Segment, TsgModel

    m = TsgModel(mss=0, segments=[Segment(1.0, 0, 3000, None, None, None, 0)])
    assert _direction_is_coalesced(m) is True


def test_direction_is_coalesced_false_for_known_jumbo_mss():
    # a real jumbo MSS with an in-MSS segment and no coalesced anomaly is NOT coalesced
    from tcptrace_ng.diagnose import _direction_is_coalesced
    from tcptrace_ng.tcp_inspect import Segment, TsgModel

    m = TsgModel(mss=8960, segments=[Segment(1.0, 0, 8000, None, None, None, 0)])
    assert _direction_is_coalesced(m) is False


def test_direction_is_coalesced_none_mss_backstop():
    from tcptrace_ng.diagnose import _direction_is_coalesced
    from tcptrace_ng.tcp_inspect import Segment, TsgModel

    m = TsgModel(mss=None, segments=[Segment(1.0, 0, 3000, None, None, None, 0)])
    assert _direction_is_coalesced(m) is True
