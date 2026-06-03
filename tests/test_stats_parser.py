from pathlib import Path

import pytest

from tcptrace_ng.classifier import Class
from tcptrace_ng.stats_parser import ConnStats, build_context_lines, parse_stats

FIXTURE = Path(__file__).parent / "fixtures" / "tcptrace_l_two_conns.txt"


def test_parse_stats_returns_two_connections():
    rows = parse_stats(FIXTURE.read_text())
    assert len(rows) == 2
    assert all(isinstance(r, ConnStats) for r in rows)
    assert rows[0].n == 1
    assert rows[1].n == 2


def test_parse_stats_hosts():
    rows = parse_stats(FIXTURE.read_text())
    assert rows[0].host_a == "100.99.98.101:49405"
    assert rows[0].host_b == "100.99.98.97:80"


def test_parse_stats_handles_two_letter_host_labels():
    """tcptrace rolls over from single-letter (a/b … y/z) to two-letter
    host labels (aa/ab, ac/ad, …) at conn 14. The parser must keep host
    fields populated past that rollover."""
    text = """\
TCP connection 14:
\thost aa:       10.0.0.1:51365
\thost ab:       10.0.0.2:8009
\ttotal packets:           5             total packets:           3
\tunique bytes sent:    100              unique bytes sent:      50
\telapsed time:    0:00:01.000000
TCP connection 56:
\thost dg:       10.0.0.10:51420
\thost dh:       10.0.0.11:5009
\ttotal packets:           7             total packets:           4
\tunique bytes sent:    200              unique bytes sent:     100
\telapsed time:    0:00:02.000000
"""
    rows = parse_stats(text)
    assert len(rows) == 2
    assert rows[0].n == 14
    assert rows[0].host_a == "10.0.0.1:51365"
    assert rows[0].host_b == "10.0.0.2:8009"
    assert rows[1].n == 56
    assert rows[1].host_a == "10.0.0.10:51420"
    assert rows[1].host_b == "10.0.0.11:5009"


def test_parse_stats_counts_and_bytes_summed_across_directions():
    rows = parse_stats(FIXTURE.read_text())
    # Connection 1 (just_attack.pcap conn 1): a->b=3pkts/226B, b->a=2pkts/0B.
    assert rows[0].total_packets == 5
    assert rows[0].total_bytes == 226


def test_parse_stats_duration_in_seconds():
    rows = parse_stats(FIXTURE.read_text())
    # `elapsed time: 0:00:00.001347`
    assert rows[0].duration_s == pytest.approx(0.001347, abs=1e-6)


def test_parse_stats_flags_for_incomplete_connection():
    rows = parse_stats(FIXTURE.read_text())
    # `complete conn: no` for both connections in the fixture.
    assert rows[0].complete_handshake is False
    assert rows[0].rexmt_packets == 0
    assert rows[0].has_rst is False


def test_parse_stats_flags_from_synthetic_complete_block():
    synthetic = """\
TCP connection 7:
\thost a:        1.1.1.1:1111
\thost b:        2.2.2.2:2222
\tcomplete conn: yes\t(SYNs: 2)  (FINs: 2)
\telapsed time:  0:00:00.100000
   a->b:                                  b->a:
     total packets:             4           total packets:             4
     unique bytes sent:        50           unique bytes sent:        50
     rexmt data pkts:           3           rexmt data pkts:           1
     resets sent:               2           resets sent:               0
     SYN/FIN pkts sent:       1/1           SYN/FIN pkts sent:       1/1
================================
"""
    rows = parse_stats(synthetic)
    assert len(rows) == 1
    assert rows[0].complete_handshake is True
    assert rows[0].rexmt_packets == 4  # 3 + 1
    assert rows[0].has_rst is True


def test_verdict_is_bad_when_any_line_is_bad():
    # `rexmt` is a BAD pattern in classifier.py
    body = """\
TCP connection 9:
\thost a:        1.1.1.1:1111
\thost b:        2.2.2.2:2222
\tcomplete conn: yes\t(SYNs: 2)  (FINs: 2)
\telapsed time:  0:00:00.100000
   a->b:                                  b->a:
     rexmt data pkts:           5           rexmt data pkts:           0
     SYN/FIN pkts sent:       1/1           SYN/FIN pkts sent:       1/1
================================
"""
    rows = parse_stats(body)
    assert rows[0].verdict == Class.BAD


def test_verdict_falls_back_to_normal_when_no_signals():
    body = """\
TCP connection 1:
\thost a:        1.1.1.1:1
\thost b:        2.2.2.2:2
================================
"""
    rows = parse_stats(body)
    assert rows[0].verdict == Class.NORMAL


def test_verdict_look_beats_normal():
    # `sacks sent` is a LOOK pattern; values != 0 so the GOOD variant
    # `(sacks sent:\s+0\s+){2}` does not match. Host lines are NORMAL.
    body = """\
TCP connection 1:
\thost a:        1.1.1.1:1
\thost b:        2.2.2.2:2
   a->b:                                  b->a:
     sacks sent:                5           sacks sent:                3
================================
"""
    rows = parse_stats(body)
    assert rows[0].verdict == Class.LOOK


def test_verdict_good_when_only_good_signals():
    # `(rexmt data \w+:\s+0\s+){2}` matches both `pkts: 0 ... pkts: 0` and
    # `bytes: 0 ... bytes: 0`. GOOD is checked before BAD in classify(),
    # so the bare `rexmt` BAD pattern is not reached.
    body = """\
TCP connection 1:
\thost a:        1.1.1.1:1
\thost b:        2.2.2.2:2
   a->b:                                  b->a:
     rexmt data pkts:           0           rexmt data pkts:           0
     rexmt data bytes:          0           rexmt data bytes:          0
================================
"""
    rows = parse_stats(body)
    assert rows[0].verdict == Class.GOOD


def test_verdict_bad_beats_look():
    # `sacks sent: 5 / 3` is LOOK; `rexmt data pkts: 5 / 0` is BAD
    # (does not match the GOOD `\w+:\s+0` twice variant because the first
    # direction has 5). BAD must win.
    body = """\
TCP connection 1:
\thost a:        1.1.1.1:1
\thost b:        2.2.2.2:2
   a->b:                                  b->a:
     sacks sent:                5           sacks sent:                3
     rexmt data pkts:           5           rexmt data pkts:           0
================================
"""
    rows = parse_stats(body)
    assert rows[0].verdict == Class.BAD


def test_client_is_a_when_a_sent_more_syns():
    body = """\
TCP connection 1:
\thost a:        1.1.1.1:1111
\thost b:        2.2.2.2:2222
   a->b:                                  b->a:
     SYN/FIN pkts sent:       1/1           SYN/FIN pkts sent:       0/1
================================
"""
    rows = parse_stats(body)
    assert rows[0].client_is_a is True


def test_client_is_b_when_b_sent_more_syns():
    body = """\
TCP connection 1:
\thost a:        1.1.1.1:1111
\thost b:        2.2.2.2:2222
   a->b:                                  b->a:
     SYN/FIN pkts sent:       0/1           SYN/FIN pkts sent:       1/1
================================
"""
    rows = parse_stats(body)
    assert rows[0].client_is_a is False


def test_build_context_lines_extracts_per_direction_tcp_params():
    """Render terse, tcptrace-native context for each direction.

    Audience knows MSS/winscale/SACK without explanation; format is dense
    by intent (per user-audience memory).
    """
    body = """\
TCP connection 1:
\thost a:        1.1.1.1:1111
\thost b:        2.2.2.2:2222
   a->b:                                  b->a:
     adv wind scale:            5           adv wind scale:            3
     req sack:                  Y           req sack:                  Y
     mss requested:          1460 bytes     mss requested:          1440 bytes
     max win adv:          137088 bytes     max win adv:           17136 bytes
     throughput:               96 Bps       throughput:           116491 Bps
================================
"""
    fwd, bwd = build_context_lines(body)
    assert "MSS 1460" in fwd
    assert "ws 5" in fwd
    assert "SACK" in fwd
    assert "137088" in fwd or "133K" in fwd or "134K" in fwd
    assert "96 Bps" in fwd
    assert "MSS 1440" in bwd
    assert "ws 3" in bwd
    assert "116491 Bps" in bwd or "114K" in bwd or "113K" in bwd


def test_build_context_lines_omits_sack_when_not_negotiated():
    """If SACK is N, omit it entirely — terse, no `noSACK` clutter."""
    body = """\
TCP connection 1:
\thost a:        1.1.1.1:1
\thost b:        2.2.2.2:2
   a->b:                                  b->a:
     adv wind scale:            0           adv wind scale:            0
     req sack:                  N           req sack:                  N
     mss requested:          1460 bytes     mss requested:          1460 bytes
================================
"""
    fwd, bwd = build_context_lines(body)
    assert "SACK" not in fwd
    assert "SACK" not in bwd


def test_build_context_lines_missing_fields_are_skipped():
    """A minimal block (no MSS/ws/SACK at all) returns empty strings, not crashes."""
    body = """\
TCP connection 1:
\thost a:        1.1.1.1:1
\thost b:        2.2.2.2:2
   a->b:                                  b->a:
================================
"""
    fwd, bwd = build_context_lines(body)
    assert fwd == ""
    assert bwd == ""


def test_client_undetermined_when_both_sent_syns():
    body = """\
TCP connection 1:
\thost a:        1.1.1.1:1111
\thost b:        2.2.2.2:2222
   a->b:                                  b->a:
     SYN/FIN pkts sent:       1/1           SYN/FIN pkts sent:       1/1
================================
"""
    rows = parse_stats(body)
    assert rows[0].client_is_a is None


RTT_FIXTURE = Path(__file__).parent / "fixtures" / "tcptrace_l_with_rtt.txt"


def test_parse_stats_extracts_per_direction_rtt():
    rows = parse_stats(RTT_FIXTURE.read_text())
    assert len(rows) >= 1
    r = rows[0]
    # The fixture is conn 12 of firmware_flash.pcapng, captured with -r.
    # Both directions should report RTT min/avg/max as floats (ms).
    assert r.rtt_min_a is not None and r.rtt_min_a > 0
    assert r.rtt_max_a is not None and r.rtt_max_a >= r.rtt_min_a
    assert r.rtt_avg_a is not None
    assert r.rtt_min_b is not None
    assert r.rtt_max_b is not None
    assert r.rtt_avg_b is not None


def test_parse_stats_extracts_per_direction_mss_and_wscale():
    body = """\
TCP connection 1:
\thost a:        1.1.1.1:1111
\thost b:        2.2.2.2:2222
   a->b:                                  b->a:
     adv wind scale:            5           adv wind scale:            8
     mss requested:          1460 bytes     mss requested:          1440 bytes
================================
"""
    rows = parse_stats(body)
    assert rows[0].mss_a == 1460
    assert rows[0].mss_b == 1440
    assert rows[0].wscale_a == 5
    assert rows[0].wscale_b == 8


def test_parse_stats_typed_fields_are_none_when_missing():
    body = """\
TCP connection 1:
\thost a:        1.1.1.1:1
\thost b:        2.2.2.2:2
================================
"""
    rows = parse_stats(body)
    assert rows[0].mss_a is None
    assert rows[0].mss_b is None
    assert rows[0].wscale_a is None
    assert rows[0].wscale_b is None
    assert rows[0].rtt_3whs_a is None
    assert rows[0].rtt_3whs_b is None


def test_parses_rtt_from_3whs():
    body = """TCP connection 1:
\thost a:        10.0.0.1:50000
\thost b:        10.0.0.2:443
\tcomplete conn: yes
   a->b:\t\t\t      b->a:
     SYN/FIN pkts sent:       1/1           SYN/FIN pkts sent:       1/1
     RTT from 3WHS:          80.0 ms        RTT from 3WHS:           0.1 ms
"""
    conns = parse_stats(body)
    assert conns[0].rtt_3whs_a == 80.0
    assert conns[0].rtt_3whs_b == 0.1
