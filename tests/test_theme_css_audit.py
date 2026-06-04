"""Audit guards from spec §0 doctrine and §1 single-source-of-truth.

After the re-theme, every 6-digit hex in src/tcptrace_ng/ must live in
theme.py's Palette dataclass (or the documented LEGEND_BG rgba). This test
runs `grep` over the package and asserts no other file matches.
"""
from __future__ import annotations

import re
from pathlib import Path

PKG = Path(__file__).parent.parent / "src" / "tcptrace_ng"
HEX_RE = re.compile(rb"#[0-9a-fA-F]{6}")
# LEGEND_BG uses an rgba (alpha channel) — documented exception. Match its
# numeric value so the test stays sensitive to *new* rgba literals elsewhere.
RGBA_RE = re.compile(rb"rgba\(\s*14\s*,\s*17\s*,\s*21\s*,\s*0\.4\s*\)")


def test_only_theme_py_holds_literal_hexes():
    """Spec §1 — single source of truth. After the rewrite, only theme.py has hex literals."""
    offenders: list[str] = []
    for f in PKG.rglob("*.py"):
        if f.name == "theme.py":
            continue
        if "__pycache__" in f.parts:
            continue
        for m in HEX_RE.finditer(f.read_bytes()):
            offenders.append(f"{f.relative_to(PKG)}: {m.group().decode()}")
    assert not offenders, "literal hexes found outside theme.py:\n  " + "\n  ".join(offenders)


def test_dark_css_uses_no_literal_hexes():
    """The CSS in DARK_CSS reads palette CSS vars only. The Plotly constants
    after DARK_CSS in the same file are allowed literals (sourced from PALETTE)."""
    from tcptrace_ng.theme import DARK_CSS

    offenders = HEX_RE.findall(DARK_CSS.encode())
    assert not offenders, f"DARK_CSS contains literal hexes: {offenders}"


def test_legend_bg_is_only_rgba_in_pkg():
    """The single allowed rgba (LEGEND_BG alpha) lives in theme.py only."""
    for f in PKG.rglob("*.py"):
        if f.name == "theme.py":
            continue
        if "__pycache__" in f.parts:
            continue
        assert not RGBA_RE.search(f.read_bytes()), f"rgba(14,17,21,0.4) appears outside theme.py: {f}"
