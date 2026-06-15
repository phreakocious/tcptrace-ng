"""Tests for the Palette single-source-of-truth. See spec §1, §2.

These guard the load-bearing policy decisions:
- orange is the everyday `negative`/bad, red is the rarer `crit` tier
- primary slot drives selection + active-tab indicator and is cyan (PALETTE.accent)
- every Quasar slot is filled and every brand token is exposed
"""

from __future__ import annotations

import dataclasses
import re

import pytest

from tcptrace_ng.theme import PALETTE, Palette, quasar_colors


def test_palette_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        PALETTE.bad = "#000000"  # type: ignore[misc]


def test_palette_fields_are_six_digit_hexes():
    hex_re = re.compile(r"#[0-9a-fA-F]{6}")
    for f in dataclasses.fields(Palette):
        v = getattr(PALETTE, f.name)
        assert hex_re.fullmatch(v), f"{f.name}={v!r} is not a 6-digit hex"


def test_palette_has_all_documented_tokens():
    """Spec §1 — 16 tokens, named by role."""
    expected = {
        "bg_page",
        "bg_surface",
        "bg_panel",
        "border",
        "text_emph",
        "text_body",
        "text_muted",
        "text_dim",
        "good",
        "notable",
        "bad",
        "crit",
        "info",
        "accent",
        "rare",
        "magenta",
    }
    actual = {f.name for f in dataclasses.fields(Palette)}
    assert actual == expected, f"missing: {expected - actual}; extra: {actual - expected}"


def test_quasar_colors_fills_every_built_in_slot():
    qc = quasar_colors()
    expected_slots = {
        "primary",
        "secondary",
        "accent",
        "dark",
        "dark_page",
        "positive",
        "negative",
        "info",
        "warning",
    }
    assert expected_slots <= qc.keys()


def test_quasar_colors_primary_is_cyan_accent():
    """primary drives Quasar's selection bar / active tab — must be PALETTE.accent
    (cyan). Spec §2 + §3 (selection bar fix)."""
    assert quasar_colors()["primary"] == PALETTE.accent


def test_quasar_colors_negative_is_orange_bad_not_red_crit():
    """The 'orange is the everyday bad; red is critical' policy. Spec §0 doctrine
    + §2 slot table. negative slot binds to PALETTE.bad so default Quasar 'bad'
    widgets render orange; crit stays opt-in via the `crit` brand token."""
    qc = quasar_colors()
    assert qc["negative"] == PALETTE.bad
    assert qc["negative"] != PALETTE.crit


def test_quasar_colors_exposes_brand_tokens():
    """Spec §2 — brand tokens are addressable as color=<name> / var(--q-<name>)
    and via the utility classes in DARK_CSS §3."""
    qc = quasar_colors()
    for tok in (
        "good",
        "notable",
        "bad",
        "crit",
        "emph",
        "body",
        "muted",
        "dim",
        "panel",
        "border",
    ):
        assert tok in qc, f"missing brand token: {tok}"


def test_quasar_colors_short_text_tokens_map_to_palette_text_fields():
    qc = quasar_colors()
    assert qc["emph"] == PALETTE.text_emph
    assert qc["body"] == PALETTE.text_body
    assert qc["muted"] == PALETTE.text_muted
    assert qc["dim"] == PALETTE.text_dim


def test_quasar_colors_exposes_hue_named_passthrough_tokens():
    """Spec §2 — hue-named tokens (sol_red, sol_orange, …) kept for symmetry
    and rare external consumers (e.g. an out-of-tree xpl colorizer)."""
    qc = quasar_colors()
    for tok in (
        "sol_red",
        "sol_orange",
        "sol_yellow",
        "sol_green",
        "sol_cyan",
        "sol_blue",
        "sol_violet",
        "sol_magenta",
    ):
        assert tok in qc, f"missing hue-named token: {tok}"
    assert qc["sol_red"] == PALETTE.crit  # the only red lives in `crit`
    assert qc["sol_cyan"] == PALETTE.accent
