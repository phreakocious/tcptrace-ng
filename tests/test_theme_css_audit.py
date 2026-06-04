"""Audit guards from spec §0 doctrine and §1 single-source-of-truth.

After the re-theme, every 6-digit hex in src/tcptrace_ng/ must live in
theme.py's Palette dataclass (or the documented LEGEND_BG rgba derived
via `theme._rgba`). This test runs `grep` over the package and asserts
no other file matches.
"""
from __future__ import annotations

import re
from pathlib import Path

from tcptrace_ng.theme import LEGEND_BG

PKG = Path(__file__).parent.parent / "src" / "tcptrace_ng"
HEX_RE = re.compile(rb"#[0-9a-fA-F]{6}")
# Match the LEGEND_BG value as currently derived — escape the parens and
# dots so a regex special doesn't slip past. Keeps the test sensitive to
# *new* rgba literals appearing anywhere outside theme.py.
LEGEND_BG_RE = re.compile(re.escape(LEGEND_BG).encode())


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


def test_legend_bg_string_only_appears_in_theme_py():
    """The single allowed rgba (LEGEND_BG, derived via theme._rgba) lives in
    theme.py only. The literal value is computed from PALETTE.bg_surface so
    a future hex change there propagates without needing to update this test."""
    for f in PKG.rglob("*.py"):
        if f.name == "theme.py":
            continue
        if "__pycache__" in f.parts:
            continue
        assert not LEGEND_BG_RE.search(f.read_bytes()), (
            f"LEGEND_BG value ({LEGEND_BG!r}) appears outside theme.py: {f}"
        )
