"""Dark CSS for the NiceGUI page.

The `.tcptrace-output` block and color classes are load-bearing: they style
the color-coded tcptrace text output that the classifier categorizes line by
line. Everything else is chrome (header, sidebar, conn rows, expansions).
"""

from __future__ import annotations

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
.tcptrace-conn-analyzed .conn-host {
    color: #e6e6e6;
}
.tcptrace-conn-dot {
    width: 6px; height: 6px; border-radius: 50%;
    background: #00ff00;
    display: inline-block;
    margin-right: 6px;
    opacity: 0.85;
}

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
}

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
.tcptrace-output .bad    { color: #ff0000; }
.tcptrace-output .look   { color: #ffff00; }
.tcptrace-output .normal { color: #ddd; }

/* ---- misc ---- */
.tcptrace-cache-label {
    font-family: Menlo, monospace;
    font-size: 11px;
    color: #888;
}
"""
