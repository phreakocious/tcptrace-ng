from tcptrace_ng.classifier import Class
from tcptrace_ng.stats_parser import ConnStats
from tcptrace_ng.view.format import _matches_chips


def _row(**kw):
    base = {
        "n": 1,
        "host_a": "a",
        "host_b": "b",
        "client_is_a": None,
        "total_bytes": 0,
        "total_packets": 0,
        "duration_s": 0.0,
        "rexmt_packets": 0,
        "has_rst": False,
        "complete_handshake": True,
        "verdict": Class.NORMAL,
        "fwd_ctx": "",
        "bwd_ctx": "",
    }
    base.update(kw)
    return ConnStats(**base)


def test_chips_empty_matches_all():
    assert _matches_chips(_row(), set()) is True


def test_bad_chip_requires_bad_verdict():
    assert _matches_chips(_row(verdict=Class.LOOK), {"bad"}) is False
    assert _matches_chips(_row(verdict=Class.BAD), {"bad"}) is True


def test_rst_chip_requires_has_rst():
    assert _matches_chips(_row(has_rst=False), {"rst"}) is False
    assert _matches_chips(_row(has_rst=True), {"rst"}) is True


def test_rexmt_chip_requires_nonzero_retransmits():
    assert _matches_chips(_row(rexmt_packets=0), {"rexmt"}) is False
    assert _matches_chips(_row(rexmt_packets=1), {"rexmt"}) is True


def test_incomplete_chip_requires_incomplete_handshake():
    assert _matches_chips(_row(complete_handshake=True), {"incomplete"}) is False
    assert _matches_chips(_row(complete_handshake=False), {"incomplete"}) is True


def test_bulk_chip_requires_min_bytes():
    assert _matches_chips(_row(total_bytes=99 * 1024), {"bulk"}) is False
    assert _matches_chips(_row(total_bytes=200 * 1024), {"bulk"}) is True


def test_chips_and_together():
    row = _row(verdict=Class.BAD, has_rst=True)
    assert _matches_chips(row, {"bad", "rst"}) is True
    assert _matches_chips(row, {"bad", "rst", "rexmt"}) is False
