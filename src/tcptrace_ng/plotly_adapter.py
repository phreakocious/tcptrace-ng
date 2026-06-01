"""Convert XplPlot dataclasses to Plotly figure dicts.

Pure module. Groups commands by (type, color) to keep trace counts low
even on busy plots — Plotly handles a few traces with thousands of
segments far better than thousands of single-segment traces.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .theme import GRID_COLOR, LINE_DIM_COLOR, ZERO_LINE_COLOR
from .xpl_parser import (
    Arrow,
    Box,
    DBox,
    Diamond,
    DLine,
    Dot,
    Line,
    Text,
    Tick,
    XplPlot,
)

# Map xplot named colors to hex that reads on a dark background.
COLOR_MAP: dict[str, str] = {
    "white": "#e6e6e6",
    "red": "#ff5555",
    "green": "#55ff55",
    "yellow": "#ffff55",
    "blue": "#5599ff",
    "magenta": "#ff77ff",
    "cyan": "#55ffff",
    "orange": "#ffaa55",
    "purple": "#bb99ff",
    "pink": "#ff99cc",
    "black": "#888888",  # black on black is invisible; lift to mid-gray
}


def _color(name: str) -> str:
    return COLOR_MAP.get(name, name)


_ARROW_SYMBOL = {
    "up": "triangle-up",
    "down": "triangle-down",
    "left": "triangle-left",
    "right": "triangle-right",
}

_TICK_SYMBOL = {
    "u": "triangle-up",
    "d": "triangle-down",
    "l": "triangle-left",
    "r": "triangle-right",
    "h": "line-ew",
    "v": "line-ns",
    "": "circle-open",
}

_SUBPLOT_LABEL_FONT = {"color": "#888888", "size": 11, "family": "Menlo, monospace"}


def _is_epoch_time_axis(plot: XplPlot) -> bool:
    """tcptrace emits `timeval double` when the x-axis is wall-clock epoch
    seconds; `dtime` variants are relative deltas that don't need date formatting."""
    tv = (plot.timeval or "").lower()
    return "timeval" in tv and "dtime" not in tv


def _epoch_to_iso(x: float) -> str:
    """Convert epoch seconds (with fractional µs) to ISO-8601 for Plotly's date axis."""
    return datetime.fromtimestamp(x, tz=UTC).isoformat()


def _build_traces(
    plot: XplPlot,
    xfmt: Callable[[float], Any],
    xaxis_ref: str = "x",
    yaxis_ref: str = "y",
    legend_seen: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Generate trace dicts for `plot`. Per-trace axis refs let callers stack
    multiple plots in subplots by passing different (xaxis_ref, yaxis_ref).

    Only Text-derived traces show up in the legend — those are the only
    primitives that carry semantic names (`ltext` in the xpl). Every other
    trace type is `showlegend=False` to keep auto-generated noise (e.g.
    "green solid", "yellow box") out of the legend. `legend_seen`, when
    passed, dedupes legend entries across the two directions of a paired
    figure — the second direction skips entries whose label already appeared.
    """

    if legend_seen is None:
        legend_seen = set()

    lines: dict[tuple[str, str], list[tuple[float, float, float, float]]] = defaultdict(list)
    boxes: dict[tuple[str, str], list[tuple[float, float, float, float]]] = defaultdict(list)
    markers: dict[tuple[str, str], list[tuple[float, float]]] = defaultdict(list)
    labels: dict[tuple[str, str], list[tuple[float, float]]] = defaultdict(list)

    for cmd in plot.commands:
        if isinstance(cmd, Line):
            lines[("solid", cmd.color)].append((cmd.x1, cmd.y1, cmd.x2, cmd.y2))
        elif isinstance(cmd, DLine):
            lines[("dash", cmd.color)].append((cmd.x1, cmd.y1, cmd.x2, cmd.y2))
        elif isinstance(cmd, Box):
            boxes[("solid", cmd.color)].append((cmd.x1, cmd.y1, cmd.x2, cmd.y2))
        elif isinstance(cmd, DBox):
            boxes[("dash", cmd.color)].append((cmd.x1, cmd.y1, cmd.x2, cmd.y2))
        elif isinstance(cmd, Arrow):
            markers[(f"arrow-{cmd.direction}", cmd.color)].append((cmd.x, cmd.y))
        elif isinstance(cmd, Dot):
            markers[("dot", cmd.color)].append((cmd.x, cmd.y))
        elif isinstance(cmd, Diamond):
            markers[("diamond", cmd.color)].append((cmd.x, cmd.y))
        elif isinstance(cmd, Tick):
            markers[(f"tick-{cmd.kind or 'plain'}", cmd.color)].append((cmd.x, cmd.y))
        elif isinstance(cmd, Text):
            labels[(cmd.color, cmd.label)].append((cmd.x, cmd.y))

    traces: list[dict[str, Any]] = []

    for (dash, color), segs in lines.items():
        xs: list[Any] = []
        ys: list[float | None] = []
        for x1, y1, x2, y2 in segs:
            xs.extend([xfmt(x1), xfmt(x2), None])
            ys.extend([y1, y2, None])
        traces.append(
            {
                "type": "scatter",
                "mode": "lines",
                "x": xs,
                "y": ys,
                "line": {"color": LINE_DIM_COLOR, "dash": dash, "width": 1},
                "legendgroup": color,
                "name": f"{color} ({dash})",
                "hoverinfo": "x+y",
                "showlegend": False,
                "xaxis": xaxis_ref,
                "yaxis": yaxis_ref,
            }
        )

    for (dash, color), rects in boxes.items():
        xs = []
        ys = []
        for x1, y1, x2, y2 in rects:
            xs.extend([xfmt(x1), xfmt(x2), xfmt(x2), xfmt(x1), xfmt(x1), None])
            ys.extend([y1, y1, y2, y2, y1, None])
        traces.append(
            {
                "type": "scatter",
                "mode": "lines",
                "x": xs,
                "y": ys,
                "fill": "toself",
                "fillcolor": _color(color),
                "line": {"color": _color(color), "dash": dash, "width": 1},
                "legendgroup": color,
                "name": f"{color} box ({dash})",
                "hoverinfo": "skip",
                "showlegend": False,
                "xaxis": xaxis_ref,
                "yaxis": yaxis_ref,
            }
        )

    for (kind, color), pts in markers.items():
        symbol = _marker_symbol(kind)
        traces.append(
            {
                "type": "scatter",
                "mode": "markers",
                "x": [xfmt(p[0]) for p in pts],
                "y": [p[1] for p in pts],
                "marker": {"color": _color(color), "symbol": symbol, "size": 6},
                "legendgroup": color,
                "name": f"{color} {kind}",
                "hoverinfo": "x+y",
                "showlegend": False,
                "xaxis": xaxis_ref,
                "yaxis": yaxis_ref,
            }
        )

    for (color, label), pts in labels.items():
        # legendgroup=label so paired-figure fwd+bwd toggle together; the
        # second occurrence (other direction) sets showlegend=False to keep
        # the legend a single line per label.
        show_in_legend = label not in legend_seen
        legend_seen.add(label)
        traces.append(
            {
                "type": "scatter",
                "mode": "markers",
                "x": [xfmt(p[0]) for p in pts],
                "y": [p[1] for p in pts],
                "hovertext": [label] * len(pts),
                "hoverinfo": "text",
                "marker": {
                    "color": _color(color),
                    "symbol": "circle",
                    "size": 4,
                    "opacity": 0.6,
                },
                "legendgroup": label,
                "name": label,
                "showlegend": show_in_legend,
                "xaxis": xaxis_ref,
                "yaxis": yaxis_ref,
            }
        )

    return traces


def _has_text(*plots: XplPlot | None) -> bool:
    """True iff any plot contains at least one Text command — i.e. the figure
    has something semantic to show in a legend."""
    return any(
        isinstance(cmd, Text)
        for plot in plots
        if plot is not None
        for cmd in plot.commands
    )


def _xaxis_config(plot: XplPlot, time_axis: bool) -> dict[str, Any]:
    xaxis: dict[str, Any] = {
        "title": {"text": plot.xlabel},
        "gridcolor": GRID_COLOR,
        "zerolinecolor": ZERO_LINE_COLOR,
    }
    if time_axis:
        xaxis["type"] = "date"
        xaxis["tickformat"] = "%H:%M:%S.%L"
        xaxis["hoverformat"] = "%Y-%m-%d %H:%M:%S.%6f"
    if plot.xunits and not time_axis:
        xaxis["title"]["text"] = f"{plot.xlabel} ({plot.xunits})"
    return xaxis


def _yaxis_config(plot: XplPlot) -> dict[str, Any]:
    yaxis: dict[str, Any] = {
        "title": {"text": plot.ylabel},
        "gridcolor": GRID_COLOR,
        "zerolinecolor": ZERO_LINE_COLOR,
    }
    if plot.yunits:
        yaxis["title"]["text"] = f"{plot.ylabel} ({plot.yunits})"
    return yaxis


def _base_layout(
    title: str, *, dragmode: str | None = None, showlegend: bool = False
) -> dict[str, Any]:
    """Layout fields common to both single and paired figures (background,
    title, margin, modebar). Callers add axes/annotations and set
    `showlegend=True` when the plot has Text-derived semantic labels worth
    surfacing — every other trace type is `showlegend=False` so this stays
    clean."""
    layout: dict[str, Any] = {
        "template": "plotly_dark",
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(0,0,0,0)",
        "title": {"text": _humanize_title(title)},
        "showlegend": showlegend,
        # Sit the legend just inside the top-right of the plot area. Plotly's
        # default `y=1` collides with the title; this slips it under the title
        # and keeps it out of the data unless the plot is bone-empty.
        "legend": {
            "orientation": "v",
            "xanchor": "right",
            "x": 1,
            "yanchor": "top",
            "y": 0.98,
            "bgcolor": "rgba(0,0,0,0.4)",
            "bordercolor": "#1f1f1f",
            "borderwidth": 1,
            "font": {"size": 11, "family": "Menlo, monospace"},
        },
        "margin": {"l": 60, "r": 20, "t": 70, "b": 50},
        "annotations": [],
        "modebar": {"orientation": "v"},
    }
    if dragmode is not None:
        layout["dragmode"] = dragmode
    return layout


def to_plotly_figure(plot: XplPlot) -> dict[str, Any]:
    """Render an XplPlot as a Plotly figure dict."""

    time_axis = _is_epoch_time_axis(plot)
    xfmt = _epoch_to_iso if time_axis else (lambda v: v)

    traces = _build_traces(plot, xfmt)

    layout = _base_layout(plot.title, showlegend=_has_text(plot))
    layout["xaxis"] = _xaxis_config(plot, time_axis)
    layout["yaxis"] = _yaxis_config(plot)
    return {"data": traces, "layout": layout}


# Subplot domain layout. Forward sits on top, backward below. A vertical gap
# leaves room for the bottom subplot's title without colliding with the top
# subplot's x-axis ticks (which we hide anyway).
_FWD_DOMAIN = (0.55, 1.0)
_BWD_DOMAIN = (0.0, 0.45)


def to_paired_plotly_figure(
    forward: XplPlot | None,
    backward: XplPlot | None,
    forward_label: str,
    backward_label: str,
) -> dict[str, Any]:
    """Stack two XplPlots vertically with a synced x-axis.

    Zoom/pan on either subplot drives both. When only one direction is
    populated, falls back to a single-figure layout (no subplot scaffolding).
    """
    if forward is not None and backward is None:
        return to_plotly_figure(forward)
    if backward is not None and forward is None:
        return to_plotly_figure(backward)
    if forward is None and backward is None:
        return to_plotly_figure(XplPlot())

    # Both plots present. Prefer epoch formatting if either side uses it; the
    # two should match in practice (same conn, same metric).
    time_axis = _is_epoch_time_axis(forward) or _is_epoch_time_axis(backward)
    xfmt = _epoch_to_iso if time_axis else (lambda v: v)

    # Share a `seen` set across the two _build_traces calls so each (color,
    # label) appears in the legend exactly once — the second direction
    # silently reuses the first's legendgroup.
    legend_seen: set[str] = set()
    fwd_traces = _build_traces(
        forward, xfmt, xaxis_ref="x", yaxis_ref="y", legend_seen=legend_seen
    )
    bwd_traces = _build_traces(
        backward, xfmt, xaxis_ref="x2", yaxis_ref="y2", legend_seen=legend_seen
    )

    fwd_xaxis = _xaxis_config(forward, time_axis)
    bwd_xaxis = _xaxis_config(backward, time_axis)
    # Top subplot hides its x ticks/title; bottom carries the label so the
    # axis reads only once between the two plots.
    fwd_xaxis["showticklabels"] = False
    fwd_xaxis["title"] = {"text": ""}
    fwd_xaxis["anchor"] = "y"
    # Sync: backward x-axis follows forward. anchor='y2' is load-bearing —
    # without it Plotly draws the matched axis's ticks/title at the master's
    # position (in the gap between subplots) rather than below the bottom one.
    bwd_xaxis["matches"] = "x"
    bwd_xaxis["anchor"] = "y2"
    bwd_xaxis["side"] = "bottom"

    fwd_yaxis = _yaxis_config(forward)
    fwd_yaxis["domain"] = list(_FWD_DOMAIN)
    fwd_yaxis["anchor"] = "x"
    bwd_yaxis = _yaxis_config(backward)
    bwd_yaxis["domain"] = list(_BWD_DOMAIN)
    bwd_yaxis["anchor"] = "x2"

    annotations = [
        {
            "text": text,
            "xref": "paper",
            "yref": "paper",
            "x": 0,
            "y": y,
            "xanchor": "left",
            "yanchor": "bottom",
            "showarrow": False,
            "font": _SUBPLOT_LABEL_FONT,
        }
        for text, y in (
            (forward_label, _FWD_DOMAIN[1]),
            (backward_label, _BWD_DOMAIN[1]),
        )
    ]

    # Both XplPlots come from the same metric/connection in practice (paired
    # by xpl_grouper), so titles match modulo direction arrow. Forward title
    # is canonical.
    layout = _base_layout(
        forward.title, dragmode="pan", showlegend=_has_text(forward, backward)
    )
    layout["xaxis"] = fwd_xaxis
    layout["yaxis"] = fwd_yaxis
    layout["xaxis2"] = bwd_xaxis
    layout["yaxis2"] = bwd_yaxis
    layout["annotations"] = annotations
    return {"data": fwd_traces + bwd_traces, "layout": layout}


def _marker_symbol(kind: str) -> str:
    if kind.startswith("arrow-"):
        direction = kind.split("-", 1)[1]
        return _ARROW_SYMBOL.get(direction, "circle")
    if kind.startswith("tick-"):
        return _TICK_SYMBOL.get(kind.split("-", 1)[1], "circle-open")
    if kind == "dot":
        return "circle"
    if kind == "diamond":
        return "diamond"
    return "circle"


def _humanize_title(raw: str) -> str:
    """Strip tcptrace's '_==>_' and trailing parenthetical from chart titles.

    The metric is already conveyed by the tab; we just keep the endpoints,
    arrow, and drop noise. Example:
      `100.99.98.97:80_==>_143.84.100.55:50526 (rtt samples)`
      → `100.99.98.97:80 → 143.84.100.55:50526`
    """
    cleaned = raw.replace("_==>_", " → ").replace("_<==_", " ← ")
    # Drop a single trailing `(...)` group.
    idx = cleaned.rfind(" (")
    if idx > 0 and cleaned.endswith(")"):
        cleaned = cleaned[:idx]
    return cleaned
