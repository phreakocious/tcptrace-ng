"""Tests for state.py — _State and cache_version."""

from __future__ import annotations

from tcptrace_ng.state import _figure_cache_key, _State, cache_version


def test_figure_cache_key_is_show_info_sensitive():
    """The cache key includes `show_info`. Without it, toggling info-markers
    while flipping between connections would serve a figure built for the
    wrong toggle state."""
    assert _figure_cache_key(7, "tsg", True) != _figure_cache_key(7, "tsg", False)
    assert _figure_cache_key(7, "tsg", False) == (7, "tsg", False)


def test_state_initializes_findings_dict():
    """_State always carries an empty findings dict so callers can index by
    conn id without guarding for None on a fresh state."""
    s = _State()
    assert s.findings == {}


def test_cache_version_includes_version_and_flag_toggles():
    """cache_version composes app version + decap/stats/desegment schema
    versions + flag toggle suffixes. Toggling a flag must change the key."""
    s = _State()
    baseline = cache_version(s)
    s.with_rtt = True
    assert cache_version(s) != baseline


def test_cache_version_dns_flag_inverted():
    """The `n` (no-DNS) suffix appears when dns is False — tcptrace's default
    resolves names; the app inverts that with `-n` unless opted in. So the
    `n` token is present on a *fresh* state."""
    assert "n" in cache_version(_State()).split("+")


def test_state_stats_generation_starts_zero():
    """The sidebar registry bumps `stats_generation` on every `populate_rows`
    call. Background-completion paths in app.py capture it on entry and drop
    the result if it changed, so a reanalyze can't have a stale callback
    update the wrong row identity."""
    assert _State().stats_generation == 0
