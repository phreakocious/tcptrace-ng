"""Palette + dark theme + Plotly palette constants.

Three layers all feed off the single `Palette` dataclass below:

1. `quasar_colors()` returns the kwargs for `ui.colors(...)` — fills every
   Quasar slot (`primary`/`positive`/…) and registers our brand tokens
   (`good`/`bad`/`emph`/`muted`/…) as `--q-<name>` CSS vars on `body`.
2. `DARK_CSS` reads those CSS vars and shapes the surfaces that don't map to
   a Quasar slot (sidebar, dialog cards, classifier output spans, severity
   tints, dots, findings panel).
3. Plotly constants below resolve to concrete hexes at server-render time
   (Plotly's layout JSON can't see CSS vars).

After this rewrite, every 6-digit hex in `src/tcptrace_ng/` lives in the
`Palette` dataclass and the documented `LEGEND_BG` rgba — the audit is
`grep -rnE "#[0-9a-fA-F]{6}" src/tcptrace_ng/`.

The `.tcptrace-output` block and color classes are load-bearing: they style
the color-coded tcptrace text output that the classifier categorizes line by
line. Everything else is chrome.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Palette:
    """Every hex in the app. Solarized-derived foreground colors over near-black
    terminal backgrounds. Field names are role-semantic ('bad', 'emph') so a
    future palette tweak ("orange shouldn't be bad anymore") is a one-line edit
    here rather than a grep across the codebase."""

    # backgrounds
    bg_page: str = "#0a0a0a"
    bg_surface: str = "#0e1115"
    bg_panel: str = "#0e1115"
    border: str = "#1f2629"

    # text (Solarized base scale)
    text_emph: str = "#eee8d5"
    text_body: str = "#93a1a1"
    text_muted: str = "#657b83"
    text_dim: str = "#586e75"

    # status — semantic, not hue-named
    good: str = "#859900"     # Solarized green
    notable: str = "#b58900"  # Solarized yellow — "look here"
    bad: str = "#cb4b16"      # Solarized orange — everyday bad / warn
    crit: str = "#dc322f"     # Solarized red — reserved for critical
    info: str = "#268bd2"     # Solarized blue
    accent: str = "#2aa198"   # Solarized cyan — selection / primary
    rare: str = "#6c71c4"     # Solarized violet
    magenta: str = "#d33682"  # Solarized magenta — xpl-magenta passthrough


PALETTE = Palette()


def quasar_colors() -> dict[str, str]:
    """Kwargs for `ui.colors(...)`. Quasar slots cover the semantic role they
    best fit; short brand tokens become `--q-<name>` CSS vars on body. The
    utility classes (`.text-good`, `.text-emph`, …) that resolve those vars
    are emitted in DARK_CSS below — Quasar doesn't auto-generate them for
    custom brand tokens, only for its own slots.

    Note on the `accent` collision: `Palette.accent` is Solarized cyan and
    feeds Quasar's `primary` slot (it's the everyday accent — selection
    bar, active-tab indicator). Quasar's own `accent` slot binds to
    `Palette.rare` (violet), reserved for the rarer "extra emphasis" tier.
    So `color="primary"` in app.py paints cyan; `color="accent"` paints
    violet. The two names look similar but serve opposite frequencies."""
    p = PALETTE
    return {
        # Quasar built-in slots — drive every default-Quasar widget surface.
        "primary": p.accent,     # cyan — everyday accent / selection / active tab
        "secondary": p.info,     # blue — secondary buttons/badges (rarely used today)
        "accent": p.rare,        # violet — rare emphasis (NOT the cyan accent)
        "dark": p.bg_surface,    # surface bg for cards/menus in dark mode
        "dark_page": p.bg_page,  # body bg in dark mode
        "positive": p.good,      # Quasar "ok"-semantic widgets
        "negative": p.bad,       # Quasar "bad"-semantic widgets — orange, NOT crit red
        "info": p.info,
        "warning": p.notable,    # warning chip / amber surfaces
        # Semantic brand tokens — addressable via `color=<name>` and var(--q-<name>).
        "good": p.good, "notable": p.notable, "bad": p.bad, "crit": p.crit,
        # Text-role brand tokens.
        "emph": p.text_emph, "body": p.text_body, "muted": p.text_muted, "dim": p.text_dim,
        # Surface brand tokens — `panel` is decoupled from Quasar's `dark` slot in case
        # those two values diverge later (sidebar/header vs cards/menus).
        "panel": p.bg_panel, "border": p.border,
        # Hue-named tokens — for symmetry and rare external consumers
        # (e.g. an out-of-tree xpl colorizer that asks for "sol_cyan" by name).
        "sol_red": p.crit, "sol_orange": p.bad, "sol_yellow": p.notable,
        "sol_green": p.good, "sol_cyan": p.accent, "sol_blue": p.info,
        "sol_violet": p.rare, "sol_magenta": p.magenta,
    }


# ---------------------------------------------------------------------------
# Plotly-side constants. Concrete hexes (not CSS vars) because Plotly's layout
# JSON is rendered client-side by Plotly's own code, which can't resolve
# var(--q-…). Source from PALETTE so changing the dataclass rebuilds figures
# with the new color on the next render.

LINE_DIM_COLOR = PALETTE.border
GRID_COLOR = PALETTE.bg_surface
ZERO_LINE_COLOR = PALETTE.border
SUBPLOT_LABEL_COLOR = PALETTE.text_muted

HOVER_BG = PALETTE.bg_surface
HOVER_BORDER = PALETTE.border
HOVER_TEXT = PALETTE.text_body

def rgba(hex6: str, alpha: float) -> str:
    """Convert `#rrggbb` + alpha to `rgba(r,g,b,a)`. Used for the few places
    Plotly needs an alpha channel (legend bg) — keeps those derived from
    Palette rather than hand-mirrored."""
    r = int(hex6[1:3], 16)
    g = int(hex6[3:5], 16)
    b = int(hex6[5:7], 16)
    return f"rgba({r},{g},{b},{alpha})"


# Legend bg — Plotly needs an alpha channel for the semi-transparent overlay,
# so we derive an rgba from PALETTE.bg_surface rather than store a literal.
LEGEND_BG = rgba(PALETTE.bg_surface, 0.4)
LEGEND_BORDER = PALETTE.border

PLOTLY_MONO_FAMILY = '"DejaVu Sans Mono", monospace'

DARK_CSS = """
/* Utility classes — Quasar bakes in `.text-primary` / `.text-positive` etc.
   for its own slots; we mirror the pattern for our custom brand tokens so
   `.classes("text-muted")` / `.classes("text-bad")` resolve correctly. */
.text-emph    { color: var(--q-emph) !important; }
.text-body    { color: var(--q-body) !important; }
.text-muted   { color: var(--q-muted) !important; }
.text-dim     { color: var(--q-dim) !important; }
.text-good    { color: var(--q-good) !important; }
.text-notable { color: var(--q-notable) !important; }
.text-bad     { color: var(--q-bad) !important; }
.text-crit    { color: var(--q-crit) !important; }
.bg-panel     { background: var(--q-panel) !important; }

/* The q-page padding override remains — NiceGUI default would re-introduce it. */
.q-page { padding: 0 !important; }

/* ---- top bar ---- */
.tcptrace-header {
    background: var(--q-panel) !important;
    border-bottom: 1px solid var(--q-border);
    box-shadow: none !important;
    min-height: 44px;
}
.tcptrace-brand { color: var(--q-emph); font-weight: 500; letter-spacing: 0.02em; }
.tcptrace-sep   { color: var(--q-dim); }

/* ---- left drawer ---- */
.tcptrace-sidebar { background: var(--q-panel) !important; border-right: 1px solid var(--q-border) !important; }
.tcptrace-sidebar-header { border-bottom: 1px solid var(--q-border); }
.tcptrace-sidebar-footer { border-top:    1px solid var(--q-border); }
.tcptrace-filter input   { color: var(--q-body) !important; font-size: 12px !important; }

/* ---- connection rows ---- */
.tcptrace-conn-row {
    cursor: pointer;
    padding: 6px 12px !important;
    min-height: 0 !important;
    border-left: 2px solid transparent;
    transition: background 80ms ease;
}
/* hover lifts ~8% toward body text — works even when panel and dark share a value */
.tcptrace-conn-row:hover { background: color-mix(in srgb, var(--q-panel) 92%, var(--q-body)); }
/* selection bar = cyan (--q-primary), not violet (--q-accent), not phosphor green */
.tcptrace-conn-selected {
    background: color-mix(in srgb, var(--q-panel) 80%, var(--q-body));
    border-left: 2px solid var(--q-primary) !important;
}
.tcptrace-conn-row .conn-num { color: var(--q-dim); font-family: var(--mono); font-size: 11px; }
.tcptrace-conn-row .conn-host { color: var(--q-body); font-size: 12px; }
.tcptrace-conn-row .conn-meta-top { display: flex; align-items: center; gap: 6px;
                                    font-family: var(--mono); font-size: 10px;
                                    color: var(--q-dim); margin-bottom: 2px; }
.tcptrace-conn-row .conn-badges  { letter-spacing: 0.04em; color: var(--q-muted); }
.tcptrace-conn-row .conn-meta-bot { font-family: var(--mono); font-size: 10px;
                                    color: var(--q-dim); margin-top: 2px; }

/* dots */
.tcptrace-conn-dot {
    width: 6px; height: 6px; border-radius: 50%;
    display: inline-block; opacity: 0.9;
}
.tcptrace-dot-good   { background: var(--q-good); }
.tcptrace-dot-look   { background: var(--q-notable); }
.tcptrace-dot-bad    { background: var(--q-bad); }
.tcptrace-dot-crit   { background: var(--q-crit); }
.tcptrace-dot-normal { background: var(--q-dim); }
.tcptrace-dot-pending { background: transparent; box-shadow: inset 0 0 0 1.5px var(--q-dim); }

/* ---- findings panel ---- */
.tcptrace-findings { display: flex; flex-direction: column; gap: 7px; margin: 8px 0 4px; }
.finding-row { display: grid; grid-template-columns: 8px 1fr auto; gap: 2px 8px; align-items: baseline; }
.finding-row .tcptrace-conn-dot { margin-top: 5px; }
.finding-head { color: var(--q-body); font-size: 13px; }
.finding-scope { font-family: var(--mono); font-size: 10px; color: var(--q-dim); justify-self: end; white-space: nowrap; }
.finding-detail { grid-column: 2 / 4; color: var(--q-muted); font-size: 11px; line-height: 1.35; }
.tcptrace-conn-row .conn-warn { font-family: var(--mono); font-size: 10px; font-weight: 600; }
.tcptrace-conn-row .conn-warn-good { color: var(--q-good); }
.tcptrace-conn-row .conn-warn-look { color: var(--q-notable); }
.tcptrace-conn-row .conn-warn-bad  { color: var(--q-bad); }
.tcptrace-conn-row .conn-warn-crit { color: var(--q-crit); }

/* ---- main panel ---- */
.tcptrace-main { padding: 18px 22px; }
.tcptrace-title { font-size: 15px; color: var(--q-emph); font-weight: 500; margin-bottom: 4px; }
.tcptrace-subtitle { font-family: var(--mono); font-size: 12px; color: var(--q-muted); }
.tcptrace-context  { font-family: var(--mono); font-size: 11px; color: var(--q-dim); line-height: 1.45; }
.tcptrace-empty    { color: var(--q-dim); font-style: italic; text-align: center; margin-top: 64px; }

/* ---- output expansion + dialogs ---- */
.tcptrace-expansion .q-expansion-item__container {
    border: 1px solid var(--q-border);
    border-radius: 4px;
    background: var(--q-dark);
}
.tcptrace-expansion .q-item { background: var(--q-panel); }
.tcptrace-legend {
    font-family: var(--mono);
    font-size: 11px;
    padding: 6px 12px;
    color: var(--q-muted);
    border-bottom: 1px solid var(--q-border);
}
.tcptrace-legend .swatch { display: inline-block; margin-right: 12px; font-weight: 600; }
.tcptrace-legend .swatch.good { color: var(--q-good); }
.tcptrace-legend .swatch.look { color: var(--q-notable); }
.tcptrace-legend .swatch.bad  { color: var(--q-bad); }

/* tcptrace text output — load-bearing semantics from classifier.py */
pre.tcptrace-output {
    font-family: var(--mono);
    font-size: 12px;
    background: var(--q-dark-page);
    color: var(--q-body);
    padding: 12px;
    margin: 0;
    white-space: pre;
}
.tcptrace-output .good   { color: var(--q-good); }
.tcptrace-output .look   { color: var(--q-notable); }
.tcptrace-output .bad    { color: var(--q-bad); }
.tcptrace-output .normal { color: var(--q-body); }

/* raw-output + warning dialog cards */
.tcptrace-output-card {
    background: var(--q-dark) !important;
    color: var(--q-body) !important;
    max-width: 1100px; width: 95vw; max-height: 85vh; overflow: auto;
}
.tcptrace-rawout-btn {
    color: var(--q-muted) !important;
    text-transform: none !important; letter-spacing: 0;
    font-size: 11px; padding: 0 8px !important; min-height: 22px !important;
}
.tcptrace-warning-card {
    background: var(--q-dark) !important;
    color: var(--q-body) !important;
    max-width: 720px; width: 90vw; padding: 16px !important;
}
.tcptrace-warning-title { color: var(--q-warning); font-size: 13px; font-weight: 600; margin-bottom: 8px; }
.tcptrace-warning-body  { font-family: var(--mono); font-size: 12px; color: var(--q-body); line-height: 1.5; margin-bottom: 8px; }

/* warning chip — dim-amber bg, yellow text, tinted border via color-mix */
.tcptrace-warning-chip {
    font-family: var(--mono) !important;
    font-size: 11px !important;
    text-transform: none !important;
    letter-spacing: 0 !important;
    color: var(--q-warning) !important;
    border: 1px solid color-mix(in srgb, var(--q-warning) 45%, var(--q-panel)) !important;
    background:    color-mix(in srgb, var(--q-warning) 12%, var(--q-panel)) !important;
    padding: 0 8px !important; min-height: 22px !important;
}
.tcptrace-warning-chip:hover {
    background:    color-mix(in srgb, var(--q-warning) 20%, var(--q-panel)) !important;
}

/* ---- chip filter strip ---- */
.tcptrace-chip-row { flex-wrap: wrap; margin-bottom: 4px; }
.tcptrace-chip-row .q-chip { font-size: 10px !important; height: 20px; }

/* ---- misc ---- */
.tcptrace-cache-label { font-family: var(--mono); font-size: 11px; color: var(--q-muted); }

/* ---- sticky tab/title header ---- */
.tcptrace-sticky-head {
    position: sticky;
    top: 0;
    z-index: 5;
    background: var(--q-dark-page);
    padding-bottom: 4px;
}

/* ---- docked summary footer ---- *
 * Pins the per-tab summary panel to the viewport bottom when the user opts
 * in via the "dock" header toggle (which toggles `body.tt-dock`). Uses
 * `position: fixed` rather than sticky because sticky only catches an
 * element that's already scrolled past its anchor — initial load on a tall
 * plot leaves a sticky-bottom panel off-screen until the user scrolls down,
 * which is the opposite of what "docked" should feel like. The fixed left
 * offset matches the 300px tcptrace-sidebar. Quasar's tab_panels hides the
 * inactive panels via display:none, so only the active tab's grid renders.
 *
 * --tt-dock-h is the single source of truth for the dock's viewport budget:
 * it caps the panel's own height, reserves the padding-bottom under the
 * scroll content, and (via --tt-plot-h below) shrinks the plot so its
 * bottom 50px of margin (x-axis ticks + "time" title) clears the dock. */
:root { --tt-dock-h: 220px; }
body.tt-dock .tsg-stats {
    position: fixed;
    left: 300px;
    right: 0;
    bottom: 0;
    z-index: 10;
    background: var(--q-dark-page);
    border-top: 1px solid var(--q-border);
    box-shadow: 0 -4px 8px rgba(0,0,0,0.25);
    margin-top: 0;
    max-height: var(--tt-dock-h);
    overflow-y: auto;
}
body.tt-dock .tcptrace-main { padding-bottom: var(--tt-dock-h); }
/* Shrink the plot's container so its bottom edge clears the fixed dock.
 * The plot's inline height uses `var(--tt-plot-h, calc(100vh - 320px))` —
 * the var is unset when not docked (fallback wins), set here when docked.
 * 320 reserves header + tabs/chips/sticky-strip + base margins; subtract
 * --tt-dock-h on top of that so the chart never overlaps the fixed panel. */
body.tt-dock { --tt-plot-h: calc(100vh - 320px - var(--tt-dock-h)); }

/* ---- TSG viewport stats panel — 4-column grid below the chart ---- */
.tsg-stats {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 12px 24px;
    padding: 12px 16px;
    margin-top: 8px;
    border-top: 1px solid var(--q-border);
    font-family: var(--mono);
    font-size: 11px;
    color: var(--q-body);
    background: color-mix(in srgb, var(--q-panel) 50%, transparent);
}
.tsg-stats .col-title { color: var(--q-muted); font-weight: bold; margin-bottom: 4px; }
.tsg-stats .dir-label { grid-column: 1 / -1; color: var(--q-muted); margin-top: 8px; }
/* Severity tints — desaturated mix toward body text. Reading aids, not alerts. */
.tsg-stats .tt-ok      { color: color-mix(in srgb, var(--q-good)    70%, var(--q-body)); }
.tsg-stats .tt-notable { color: color-mix(in srgb, var(--q-notable) 70%, var(--q-body)); }
.tsg-stats .tt-bad     { color: color-mix(in srgb, var(--q-bad)     70%, var(--q-body)); }
@media (max-width: 800px) {
    .tsg-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
"""

FONT_FACES = """
<style>
@font-face {
    font-family: "DejaVu Sans Mono";
    src: url("/_tt/fonts/DejaVuSansMono.woff2") format("woff2");
    font-weight: 400;
    font-display: block;
}
@font-face {
    font-family: "DejaVu Sans Mono";
    src: url("/_tt/fonts/DejaVuSansMono-Bold.woff2") format("woff2");
    font-weight: 700;
    font-display: block;
}
:root {
    --mono: "DejaVu Sans Mono", "Fira Code", Menlo, Consolas, monospace;
    font-feature-settings: "liga" 0, "calt" 0;
}
body,
.tcptrace-output, .tcptrace-context, .tcptrace-subtitle,
.tsg-stats, .conn-meta-top, .conn-meta-bot, .conn-num,
.tcptrace-cache-label, .tcptrace-legend, .tcptrace-warning-body,
.tcptrace-filter input { font-family: var(--mono); }
</style>
"""
