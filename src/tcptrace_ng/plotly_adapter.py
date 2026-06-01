"""Convert XplPlot dataclasses to Plotly figure dicts.

Pure module. Groups commands by (type, color) to keep trace counts low
even on busy plots — Plotly handles a few traces with thousands of
segments far better than thousands of single-segment traces.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

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


def _is_epoch_time_axis(plot: XplPlot) -> bool:
    """tcptrace emits `timeval double` when the x-axis is wall-clock epoch
    seconds; `dtime` variants are relative deltas that don't need date formatting."""
    tv = (plot.timeval or "").lower()
    return "timeval" in tv and "dtime" not in tv


def _epoch_to_iso(x: float) -> str:
    """Convert epoch seconds (with fractional µs) to ISO-8601 for Plotly's date axis."""
    return datetime.fromtimestamp(x, tz=timezone.utc).isoformat()


def to_plotly_figure(plot: XplPlot) -> dict[str, Any]:
    """Render an XplPlot as a Plotly figure dict."""

    time_axis = _is_epoch_time_axis(plot)
    xfmt = _epoch_to_iso if time_axis else (lambda v: v)

    # Group commands. Keys are (kind, color).
    lines: dict[tuple[str, str], list[tuple[float, float, float, float]]] = defaultdict(list)
    boxes: dict[tuple[str, str], list[tuple[float, float, float, float]]] = defaultdict(list)
    markers: dict[tuple[str, str], list[tuple[float, float]]] = defaultdict(list)
    annotations: list[dict[str, Any]] = []

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
            annotations.append(
                {
                    "x": xfmt(cmd.x),
                    "y": cmd.y,
                    "text": cmd.label,
                    "showarrow": False,
                    "font": {"color": _color(cmd.color)},
                }
            )

    traces: list[dict[str, Any]] = []

    # Lines: one trace per (dash, color), segments separated by None.
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
                "line": {"color": _color(color), "dash": dash, "width": 1},
                "legendgroup": color,
                "name": f"{color} ({dash})",
                "hoverinfo": "x+y",
            }
        )

    # Boxes: filled polygons, closed loop per box, separated by None.
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
            }
        )

    # Markers
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
            }
        )

    xaxis: dict[str, Any] = {"title": {"text": plot.xlabel}}
    if time_axis:
        xaxis["type"] = "date"
        xaxis["tickformat"] = "%H:%M:%S.%L"
        xaxis["hoverformat"] = "%Y-%m-%d %H:%M:%S.%6f"

    # xplot / jplot don't show a legend — the inline text annotations carry
    # the semantic labels for each color. Auto-generated "(color, kind)"
    # legends just add noise.
    layout: dict[str, Any] = {
        "template": "plotly_dark",
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(0,0,0,0)",
        "title": {"text": plot.title},
        "xaxis": xaxis,
        "yaxis": {"title": {"text": plot.ylabel}},
        "showlegend": False,
        "margin": {"l": 60, "r": 20, "t": 50, "b": 50},
        "annotations": annotations,
    }
    if plot.xunits and not time_axis:
        layout["xaxis"]["title"]["text"] = f"{plot.xlabel} ({plot.xunits})"
    if plot.yunits:
        layout["yaxis"]["title"]["text"] = f"{plot.ylabel} ({plot.yunits})"

    return {"data": traces, "layout": layout}


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
