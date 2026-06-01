from tcptrace_ng.classifier import Class, classify


def test_returns_none_for_suppressed_urgent_data():
    assert classify("    urgent data sent:           0") is None


def test_returns_none_for_suppressed_zwnd_probe():
    assert classify("    zwnd probe pkts:            0") is None


def test_returns_none_for_truncated():
    assert classify("truncated packets:    0 pkts") is None


def test_good_complete_conn():
    assert classify("    complete conn: yes") == Class.GOOD


def test_good_matching_req_sack():
    line = "    req sack:                Y       req sack:                Y"
    assert classify(line) == Class.GOOD


def test_good_zero_rexmt_both_directions():
    line = "    rexmt data pkts:         0       rexmt data pkts:         0"
    assert classify(line) == Class.GOOD


def test_good_matching_mss():
    line = "    mss requested:        1460 bytes  mss requested:        1460 bytes"
    assert classify(line) == Class.GOOD


def test_bad_on_rexmt_nonzero():
    line = "    rexmt data pkts:         3       rexmt data pkts:         0"
    assert classify(line) == Class.BAD


def test_bad_on_warning():
    assert classify("WARNING: something is wrong") == Class.BAD


def test_bad_on_outoforder():
    assert classify("    outoforder pkts:         5       outoforder pkts:         0") == Class.BAD


def test_bad_on_1323_nn():
    assert classify("    req 1323 ws/ts:        N/N      req 1323 ws/ts:        N/N") == Class.BAD


def test_look_on_zero_syns():
    assert classify("    SYNs: 0") == Class.LOOK


def test_look_on_zero_fins():
    assert classify("    FINs: 0") == Class.LOOK


def test_look_on_sack_pkts_sent():
    assert classify("    sack pkts sent:          4       sack pkts sent:          2") == Class.LOOK


def test_look_on_synfin_01():
    assert classify("    SYN/FIN pkts sent:     0/1     SYN/FIN pkts sent:     1/0") == Class.LOOK


def test_window_scale_both_over_seven_is_bad():
    line = "    adv wind scale:          8       adv wind scale:          9"
    assert classify(line) == Class.BAD


def test_window_scale_mismatched_is_look():
    line = "    adv wind scale:          5       adv wind scale:          3"
    assert classify(line) == Class.LOOK


def test_window_scale_matched_under_seven_is_good():
    line = "    adv wind scale:          7       adv wind scale:          7"
    assert classify(line) == Class.GOOD


def test_normal_for_uninteresting_line():
    assert classify("host a:                  10.0.0.1:443") == Class.NORMAL
