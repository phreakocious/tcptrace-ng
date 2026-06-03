"""Dark theme — both the CSS and the Plotly palette constants.

The `.tcptrace-output` block and color classes are load-bearing: they style
the color-coded tcptrace text output that the classifier categorizes line by
line. Everything else is chrome (header, sidebar, conn rows, expansions).

The palette constants below feed the Plotly adapter so the chart grid/lines
share their dim shade with the CSS chrome.
"""

from __future__ import annotations

# Plotly line color: tcptrace's saturated white/green/yellow segment lines clobber
# the events the user is scanning for on a dark background; force them all to one
# dim gray. Markers/arrows/dots keep their semantic colors.
LINE_DIM_COLOR = "#555555"

# Axis grid + zero-line: plotly_dark's defaults are too bright and compete with
# data lines/markers. Both axes get the same dim shade.
GRID_COLOR = "#1c1c1c"
ZERO_LINE_COLOR = "#2a2a2a"

DARK_CSS = """
body, .nicegui-content, .q-page, .q-layout {
    background: #000 !important;
    color: #ddd !important;
}
.q-page {
    padding: 0 !important;
}

/* ---- top bar ---- */
.tcptrace-header {
    background: #0a0a0a !important;
    border-bottom: 1px solid #1f1f1f;
    box-shadow: none !important;
    min-height: 44px;
}
.tcptrace-brand {
    color: #e6e6e6;
    font-weight: 500;
    letter-spacing: 0.02em;
}
.tcptrace-sep { color: #555; }

/* ---- left drawer ---- */
.tcptrace-sidebar {
    background: #0a0a0a !important;
    border-right: 1px solid #1f1f1f !important;
}
.tcptrace-sidebar-header {
    border-bottom: 1px solid #1f1f1f;
}
.tcptrace-sidebar-footer {
    border-top: 1px solid #1f1f1f;
}
.tcptrace-filter input {
    color: #ddd !important;
    font-size: 12px !important;
}

/* ---- connection rows ---- */
.tcptrace-conn-row {
    cursor: pointer;
    padding: 6px 12px !important;
    min-height: 0 !important;
    border-left: 2px solid transparent;
    transition: background 80ms ease;
}
.tcptrace-conn-row:hover {
    background: #141414;
}
.tcptrace-conn-selected {
    background: #1a1a1a !important;
    border-left: 2px solid #00ff00 !important;
}
.tcptrace-conn-row .conn-num {
    color: #888;
    font-family: Menlo, monospace;
    font-size: 11px;
}
.tcptrace-conn-row .conn-host {
    color: #bbb;
    font-size: 12px;
}

/* ---- conn row v2 ---- */
.tcptrace-conn-row .conn-meta-top {
    display: flex; align-items: center; gap: 6px;
    font-family: Menlo, monospace; font-size: 10px;
    color: #777; margin-bottom: 2px;
}
.tcptrace-conn-row .conn-badges {
    letter-spacing: 0.04em;
    color: #aaa;
}
.tcptrace-conn-row .conn-meta-bot {
    font-family: Menlo, monospace; font-size: 10px;
    color: #666; margin-top: 2px;
}
.tcptrace-conn-dot {
    width: 6px; height: 6px; border-radius: 50%;
    display: inline-block;
    opacity: 0.9;
}
.tcptrace-dot-good   { background: #00ff00; }
.tcptrace-dot-look   { background: #ffff00; }
.tcptrace-dot-bad    { background: #ff5555; }
.tcptrace-dot-normal { background: #555; }
/* findings not computed yet (connection not opened): hollow neutral dot */
.tcptrace-dot-pending { background: transparent; box-shadow: inset 0 0 0 1.5px #555; }

/* ---- diagnosis findings ---- */
.tcptrace-findings { display: flex; flex-direction: column; gap: 7px; margin: 8px 0 4px; }
.finding-row { display: grid; grid-template-columns: 8px 1fr auto; gap: 2px 8px; align-items: baseline; }
.finding-row .tcptrace-conn-dot { margin-top: 5px; }
.finding-head { color: #ddd; font-size: 13px; }
.finding-scope { font-family: Menlo, monospace; font-size: 10px; color: #777; justify-self: end; white-space: nowrap; }
.finding-detail { grid-column: 2 / 4; color: #888; font-size: 11px; line-height: 1.35; }
.tcptrace-conn-row .conn-warn { font-family: Menlo, monospace; font-size: 10px; font-weight: 600; }
.tcptrace-conn-row .conn-warn-good { color: #00ff00; }
.tcptrace-conn-row .conn-warn-look { color: #ffff00; }
.tcptrace-conn-row .conn-warn-bad  { color: #ff5555; }

/* ---- main panel ---- */
.tcptrace-main {
    padding: 18px 22px;
}
.tcptrace-title {
    font-size: 15px;
    color: #e6e6e6;
    font-weight: 500;
    margin-bottom: 4px;
}
.tcptrace-subtitle {
    font-family: Menlo, monospace;
    font-size: 12px;
    color: #888;
}
.tcptrace-context {
    font-family: Menlo, monospace;
    font-size: 11px;
    color: #6a6a6a;
    line-height: 1.45;
}
.tcptrace-empty {
    color: #555;
    font-style: italic;
    text-align: center;
    margin-top: 64px;
}

/* ---- tabs ---- */
.q-tab--active { color: #e6e6e6 !important; }
.q-tab__indicator { background: #00ff00 !important; }
.q-tab { min-height: 32px !important; padding: 0 12px !important; }

/* ---- output expansion ---- */
.tcptrace-expansion .q-expansion-item__container {
    border: 1px solid #1f1f1f;
    border-radius: 4px;
    background: #050505;
}
.tcptrace-expansion .q-item {
    background: #0a0a0a;
}
.tcptrace-legend {
    font-family: Menlo, monospace;
    font-size: 11px;
    padding: 6px 12px;
    color: #777;
    border-bottom: 1px solid #1f1f1f;
}
.tcptrace-legend .swatch {
    display: inline-block;
    margin-right: 12px;
    font-weight: 600;
}
/* Legend swatches put the class on the same element as .swatch, so we need
   a compound selector — the .tcptrace-output descendant rule below only
   styles spans nested inside <pre class="tcptrace-output">. */
.tcptrace-legend .swatch.good { color: #00ff00; }
.tcptrace-legend .swatch.look { color: #ffff00; }
.tcptrace-legend .swatch.bad  { color: #ff5555; }

pre.tcptrace-output {
    font-family: Menlo, Monaco, Consolas, "Liberation Mono", "DejaVu Sans Mono",
                 "Bitstream Vera Sans Mono", "Courier New", monospace;
    font-size: 12px;
    background: #000;
    color: #ddd;
    padding: 12px;
    margin: 0;
    white-space: pre;
}
.tcptrace-output .good   { color: #00ff00; }
.tcptrace-output .bad    { color: #ff5555; }
.tcptrace-output .look   { color: #ffff00; }
.tcptrace-output .normal { color: #ddd; }

/* ---- raw-output dialog ---- */
.tcptrace-output-card {
    background: #050505 !important;
    color: #ddd !important;
    max-width: 1100px;
    width: 95vw;
    max-height: 85vh;
    overflow: auto;
}
.tcptrace-rawout-btn {
    color: #888 !important;
    text-transform: none !important;
    letter-spacing: 0;
    font-size: 11px;
    padding: 0 8px !important;
    min-height: 22px !important;
}

/* ---- chip filter strip ---- */
.tcptrace-chip-row {
    flex-wrap: wrap;
    margin-bottom: 4px;
}
.tcptrace-chip-row .q-chip {
    font-size: 10px !important;
    height: 20px;
}

/* ---- misc ---- */
.tcptrace-cache-label {
    font-family: Menlo, monospace;
    font-size: 11px;
    color: #888;
}
.tcptrace-warning-chip {
    font-family: Menlo, monospace !important;
    font-size: 11px !important;
    text-transform: none !important;
    letter-spacing: 0 !important;
    color: #f2c037 !important;
    border: 1px solid #5a4710 !important;
    background: #1a1407 !important;
    padding: 0 8px !important;
    min-height: 22px !important;
}
.tcptrace-warning-chip:hover {
    background: #2a1f0c !important;
}
.tcptrace-warning-card {
    background: #050505 !important;
    color: #ddd !important;
    max-width: 720px;
    width: 90vw;
    padding: 16px !important;
}
.tcptrace-warning-title {
    color: #f2c037;
    font-size: 13px;
    font-weight: 600;
    margin-bottom: 8px;
}
.tcptrace-warning-body {
    font-family: Menlo, monospace;
    font-size: 12px;
    color: #ddd;
    line-height: 1.5;
    margin-bottom: 8px;
}

/* ---- sticky tab/title header ---- */
.tcptrace-sticky-head {
    position: sticky;
    top: 0;
    z-index: 5;
    background: #000;
    padding-bottom: 4px;
}

/* TSG viewport stats panel — 4-column grid below the chart. */
.tsg-stats {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px 24px;
  padding: 12px 16px;
  margin-top: 8px;
  border-top: 1px solid #1f1f1f;
  font-family: Menlo, monospace;
  font-size: 11px;
  color: #cccccc;
  background: rgba(10, 10, 10, 0.5);
}
.tsg-stats .col-title {
  color: #888888;
  font-weight: bold;
  margin-bottom: 4px;
}
.tsg-stats .dir-label {
  grid-column: 1 / -1;
  color: #888888;
  margin-top: 8px;
}
/* Severity tints for stat tokens. Subtle on a dark background — these are
   reading aids, not alerts. */
.tsg-stats .tt-ok      { color: #7faa7f; }
.tsg-stats .tt-notable { color: #c8b56b; }
.tsg-stats .tt-bad     { color: #c97070; }
@media (max-width: 800px) {
  .tsg-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
"""
