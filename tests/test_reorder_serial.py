from tcptrace_ng.reorder import seq_diff, seq_ge, seq_gt, seq_le, seq_lt

WRAP = 1 << 32


def test_basic_order():
    assert seq_lt(10, 20) and seq_gt(20, 10)
    assert seq_le(10, 10) and seq_ge(10, 10)
    assert not seq_lt(10, 10)


def test_wrap_near_boundary():
    a, b = (WRAP - 5) % WRAP, 5  # b is 10 ahead of a across the wrap
    assert seq_lt(a, b), "a precedes b across the 32-bit wrap"
    assert seq_gt(b, a)
    assert seq_diff(b, a) == 10
    assert seq_diff(a, b) == -10


def test_half_window_is_forward():
    assert seq_diff(0x80000000, 0) == 0x80000000  # exactly half: defined forward


def test_one_step_wrap():
    assert seq_diff(0, 0xFFFFFFFF) == 1
    assert seq_gt(0, 0xFFFFFFFF) and seq_lt(0xFFFFFFFF, 0)


def test_le_ge_across_wrap():
    a, b = 0xFFFFFFFB, 5
    assert seq_le(a, b) and seq_ge(b, a)
    assert not seq_ge(a, b)


def test_half_window_symmetric():
    # RFC 1982: exactly 2**31 apart -> 'forward' for BOTH directions (documented convention)
    assert seq_diff(0, 0x80000000) == 0x80000000
    assert seq_gt(0, 0x80000000) and seq_gt(0x80000000, 0)
