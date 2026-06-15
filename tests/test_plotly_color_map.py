"""Tests for the xplot color-name → palette-hex mapping. See spec §0 + §5.

Load-bearing policy: xplot 'red' is per-event 'trouble' (RTOs, dupacks,
SACK arrows) — overwhelmingly routine in real traffic. Map to PALETTE.bad
(orange) so the eye scans for clusters, not individual ticks. PALETTE.crit
(red) stays reserved for the findings layer that has actually inspected
the connection state.
"""

from __future__ import annotations

from tcptrace_ng.plotly_adapter import COLOR_MAP
from tcptrace_ng.theme import PALETTE


def test_xplot_red_maps_to_bad_not_crit():
    assert COLOR_MAP["red"] == PALETTE.bad
    assert COLOR_MAP["red"] != PALETTE.crit


def test_xplot_green_yellow_blue_cyan_orange_match_palette():
    assert COLOR_MAP["green"] == PALETTE.good
    assert COLOR_MAP["yellow"] == PALETTE.notable
    assert COLOR_MAP["blue"] == PALETTE.info
    assert COLOR_MAP["cyan"] == PALETTE.accent
    assert COLOR_MAP["orange"] == PALETTE.bad  # both xplot red and orange land on bad


def test_xplot_black_lifts_to_dim_not_invisible():
    """The in-file comment is verbatim correct: 'black on black is invisible; lift to mid-gray'."""
    assert COLOR_MAP["black"] == PALETTE.text_dim


def test_xplot_white_is_text_emph():
    assert COLOR_MAP["white"] == PALETTE.text_emph


def test_xplot_purple_magenta_pink_match_palette():
    assert COLOR_MAP["purple"] == PALETTE.rare
    assert COLOR_MAP["magenta"] == PALETTE.magenta
    assert COLOR_MAP["pink"] == PALETTE.magenta


def test_color_map_keys_unchanged_from_pre_retheme():
    """No xplot semantics lost — same eleven keys as the prior COLOR_MAP."""
    assert set(COLOR_MAP.keys()) == {
        "white",
        "red",
        "green",
        "yellow",
        "blue",
        "magenta",
        "cyan",
        "orange",
        "purple",
        "pink",
        "black",
    }


def test_color_map_values_are_six_digit_hexes():
    import re

    hex_re = re.compile(r"#[0-9a-fA-F]{6}")
    for k, v in COLOR_MAP.items():
        assert hex_re.fullmatch(v), f"COLOR_MAP[{k!r}]={v!r} is not a 6-digit hex"
