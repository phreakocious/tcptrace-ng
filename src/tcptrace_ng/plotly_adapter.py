"""Convert XplPlot dataclasses to Plotly figure dicts.

Pure module. Groups commands by (type, color) to keep trace counts low
even on busy plots — Plotly handles a few traces with thousands of
segments far better than thousands of single-segment traces.
"""

from __future__ import annotations

import bisect
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .tcp_inspect import (
    SEVERITY_BY_KIND,
    Ack,
    Anomaly,
    Segment,
    TsgModel,
    TsgModelPair,
)
from .theme import GRID_COLOR, LINE_DIM_COLOR, ZERO_LINE_COLOR
from .throughput import RateSample, ThroughputModel, ThroughputModelPair
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

# Threshold above which label-per-trace mode (one legend entry per label)
# collapses into one-trace-per-color with the label exposed only via hovertext.
# Metrics like owin/ssize emit a handful of semantic labels ("owin", "rwin")
# that belong in the legend; tline emits a unique seq/ack string per packet
# and would otherwise spawn thousands of single-point traces — Plotly chokes
# building that many WebGL contexts long before render starts.
_LABEL_LEGEND_THRESHOLD = 32

# Synthetic legend hints for unlabeled marker colors in generic XPL plots, keyed by metric.
_MARKER_LEGEND_HINTS: dict[str, dict[str, str]] = {}


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
    marker_hints: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Generate trace dicts for `plot`. Per-trace axis refs let callers stack
    multiple plots in subplots by passing different (xaxis_ref, yaxis_ref).

    Text-derived traces always show up in the legend — those carry semantic
    names (`ltext` in the xpl). Marker traces whose color has no matching
    Text label also earn a synthetic legend entry (named from `marker_hints`
    if provided, else by color) so the user knows what otherwise-mystery dots
    represent. Box/line traces stay hidden from the legend — their (color,
    dash) tuples carry no user-facing meaning.

    `legend_seen`, when passed, dedupes legend entries across the two
    directions of a paired figure — the second direction skips entries whose
    label already appeared.
    """

    if legend_seen is None:
        legend_seen = set()
    if marker_hints is None:
        marker_hints = {}

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

    # Lines and markers use scattergl (WebGL) so dense captures (thousands of
    # segments per direction across multiple metrics) render without blocking
    # the browser's main thread. Boxes stay on scatter — scattergl ignores
    # `fill: toself`, which is load-bearing for filled-region rendering.
    for (dash, color), segs in lines.items():
        xs: list[Any] = []
        ys: list[float | None] = []
        for x1, y1, x2, y2 in segs:
            xs.extend([xfmt(x1), xfmt(x2), None])
            ys.extend([y1, y2, None])
        traces.append(
            {
                "type": "scattergl",
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

    # Marker colors that don't have a matching Text label AND have a known
    # semantic name in `marker_hints` get a synthetic legend entry on the
    # first emitted trace; subsequent traces of the same color stay hidden
    # but share the legendgroup so toggling collapses them all. Colors
    # without a hint stay out of the legend — "yellow" or "white" tells the
    # user nothing more than the marker's own color already does.
    text_colors_present = {color for (color, _label) in labels}
    orphan_legend_emitted: set[str] = set()

    for (kind, color), pts in markers.items():
        symbol = _marker_symbol(kind)
        show_in_legend = False
        legend_name = f"{color} {kind}"
        if (
            color not in text_colors_present
            and color not in orphan_legend_emitted
            and color in marker_hints
            and marker_hints[color] not in legend_seen
        ):
            legend_name = marker_hints[color]
            show_in_legend = True
            orphan_legend_emitted.add(color)
            legend_seen.add(legend_name)
        traces.append(
            {
                "type": "scattergl",
                "mode": "markers",
                "x": [xfmt(p[0]) for p in pts],
                "y": [p[1] for p in pts],
                "marker": {"color": _color(color), "symbol": symbol, "size": 6},
                "legendgroup": color,
                "name": legend_name,
                "hoverinfo": "x+y",
                "showlegend": show_in_legend,
                "xaxis": xaxis_ref,
                "yaxis": yaxis_ref,
            }
        )

    distinct_labels = {label for (_color, label) in labels}
    if len(distinct_labels) <= _LABEL_LEGEND_THRESHOLD:
        # Low cardinality: each label is a semantic category (owin, rwin, …)
        # that earns its own legend entry. legendgroup=label so paired-figure
        # fwd+bwd toggle together; the second occurrence sets showlegend=False
        # to keep the legend one line per label.
        for (color, label), pts in labels.items():
            show_in_legend = label not in legend_seen
            legend_seen.add(label)
            traces.append(
                {
                    "type": "scattergl",
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
    else:
        # High cardinality: labels are per-event data (tline emits a distinct
        # seq/ack string per packet). Bundle into one trace per color with the
        # label as hovertext only. Skips the legend dedup entirely — when every
        # label is unique there's nothing meaningful to legend.
        labels_by_color: dict[str, list[tuple[float, float, str]]] = defaultdict(list)
        for (color, label), pts in labels.items():
            for x, y in pts:
                labels_by_color[color].append((x, y, label))
        for color, items in labels_by_color.items():
            traces.append(
                {
                    "type": "scattergl",
                    "mode": "markers",
                    "x": [xfmt(it[0]) for it in items],
                    "y": [it[1] for it in items],
                    "hovertext": [it[2] for it in items],
                    "hoverinfo": "text",
                    "marker": {
                        "color": _color(color),
                        "symbol": "circle",
                        "size": 4,
                        "opacity": 0.6,
                    },
                    "name": color,
                    "showlegend": False,
                    "xaxis": xaxis_ref,
                    "yaxis": yaxis_ref,
                }
            )

    return traces


def _has_legend_content(*plots: XplPlot | None) -> bool:
    """True iff any plot would produce a trace with `showlegend=True` —
    i.e. a Text-derived label or any marker primitive (whose color may earn
    a synthetic legend entry when no matching Text label exists). Lines and
    boxes are always hidden from the legend, so they don't count."""
    return any(
        isinstance(cmd, Text | Dot | Diamond | Tick | Arrow)
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
        # Hover tooltip styling: match the dark chrome (header/sidebar) so the
        # tooltip doesn't punch a bright box through the dim grid. align=left
        # keeps multi-line hovertext (e.g. tline's per-packet labels) tidy.
        "hoverlabel": {
            "bgcolor": "#0a0a0a",
            "bordercolor": "#1f1f1f",
            "font": {
                "family": "Menlo, monospace",
                "color": "#ddd",
                "size": 11,
            },
            "align": "left",
            "namelength": -1,
        },
    }
    if dragmode is not None:
        layout["dragmode"] = dragmode
    return layout


def to_plotly_figure(plot: XplPlot, metric: str | None = None) -> dict[str, Any]:
    """Render an XplPlot as a Plotly figure dict.

    `metric` (when provided) selects per-metric semantic hints used to label
    otherwise-unlabeled marker colors in the legend — see _MARKER_LEGEND_HINTS.
    """

    time_axis = _is_epoch_time_axis(plot)
    xfmt = _epoch_to_iso if time_axis else (lambda v: v)
    marker_hints = _MARKER_LEGEND_HINTS.get(metric or "", {})

    traces = _build_traces(plot, xfmt, marker_hints=marker_hints)

    layout = _base_layout(plot.title, showlegend=_has_legend_content(plot))
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
    metric: str | None = None,
) -> dict[str, Any]:
    """Stack two XplPlots vertically with a synced x-axis.

    Zoom/pan on either subplot drives both. When only one direction is
    populated, falls back to a single-figure layout (no subplot scaffolding).
    `metric` (when provided) selects per-metric semantic hints for the
    legend — see _MARKER_LEGEND_HINTS.
    """
    if forward is not None and backward is None:
        return to_plotly_figure(forward, metric=metric)
    if backward is not None and forward is None:
        return to_plotly_figure(backward, metric=metric)
    if forward is None and backward is None:
        return to_plotly_figure(XplPlot(), metric=metric)

    # Both plots present. Prefer epoch formatting if either side uses it; the
    # two should match in practice (same conn, same metric).
    time_axis = _is_epoch_time_axis(forward) or _is_epoch_time_axis(backward)
    xfmt = _epoch_to_iso if time_axis else (lambda v: v)
    marker_hints = _MARKER_LEGEND_HINTS.get(metric or "", {})

    # Share a `seen` set across the two _build_traces calls so each (color,
    # label) appears in the legend exactly once — the second direction
    # silently reuses the first's legendgroup.
    legend_seen: set[str] = set()
    fwd_traces = _build_traces(
        forward,
        xfmt,
        xaxis_ref="x",
        yaxis_ref="y",
        legend_seen=legend_seen,
        marker_hints=marker_hints,
    )
    bwd_traces = _build_traces(
        backward,
        xfmt,
        xaxis_ref="x2",
        yaxis_ref="y2",
        legend_seen=legend_seen,
        marker_hints=marker_hints,
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
        forward.title, dragmode="pan", showlegend=_has_legend_content(forward, backward)
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


_NAN = float("nan")


def _seg_customdata(segments: list[Segment]) -> list[list[float]]:
    """Per-segment numeric tuple consumed by the hovertemplate.

    Index layout:
      0: 1-based segment index
      1: ms since previous segment
      2: seq_start
      3: length (bytes)
      4: in_flight_after (bytes)
      5: paired_rtt_ms (NaN when no pair)
    """
    out: list[list[float]] = []
    prev_time: float | None = None
    for i, s in enumerate(segments, start=1):
        dt_ms = (s.time - prev_time) * 1000.0 if prev_time is not None else _NAN
        out.append([
            float(i),
            dt_ms,
            float(s.seq_start),
            float(s.seq_end - s.seq_start),
            float(s.in_flight_after),
            float(s.paired_rtt_ms) if s.paired_rtt_ms is not None else _NAN,
        ])
        prev_time = s.time
    return out


_TSG_SEG_TEMPLATE = (
    "<b>Seg #%{customdata[0]:.0f}</b>"
    " · +%{customdata[1]:.1f} ms<br>"
    "seq %{customdata[2]:,.0f} (%{customdata[3]:.0f} B)<br>"
    "in-flight after: %{customdata[4]:,.0f} B<br>"
    "ACKed %{customdata[5]:.1f} ms later"
    "<extra></extra>"
)


def _data_segment_trace(
    model: TsgModel,
    *,
    name: str,
    color: str,
    xaxis_ref: str = "x",
    yaxis_ref: str = "y",
) -> dict[str, Any] | None:
    """Build one scattergl trace for non-retx data segments.

    Skip segments with ≤1 byte of payload (SYN/FIN consume 1 seq byte,
    keepalives are zero-length). They draw as 0-pixel verticals — invisible
    on the chart — yet still register hover targets that produce orphan
    "Seg #N · 0.0 ms" tooltips. Their semantic info lives on the matching
    handshake/keepalive annotation, which we enrich with seq/RTT below.
    """
    segs = [s for s in model.segments if s.rtx is None and s.seq_end - s.seq_start > 1]
    if not segs:
        return None
    xs: list[Any] = []
    ys: list[float | None] = []
    cd: list[list[float]] = []
    per_seg = _seg_customdata(segs)
    for s, row in zip(segs, per_seg):
        t_iso = _epoch_to_iso(s.time)
        xs.extend([t_iso, t_iso, None])
        ys.extend([s.seq_start, s.seq_end, None])
        # Customdata must align 1:1 with x/y points so Plotly can resolve
        # `%{customdata[N]}` placeholders on hover. Repeat for both endpoints
        # of the vertical line plus the None separator.
        cd.extend([row, row, row])
    return {
        "type": "scattergl",
        "mode": "lines",
        "x": xs,
        "y": ys,
        "line": {"color": color, "width": 1},
        "customdata": cd,
        "hovertemplate": _TSG_SEG_TEMPLATE,
        "name": name,
        "legendgroup": name,
        "showlegend": True,
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


_RTX_CODE = {None: 0.0, "rto": 1.0, "fast": 2.0, "spurious": 3.0}


def _retx_customdata(segments: list[Segment]) -> list[list[float]]:
    """Index layout:
      0: seq_start
      1: length
      2: in_flight_after
      3: rtx_code (1=rto, 2=fast, 3=spurious)
    """
    out: list[list[float]] = []
    for s in segments:
        out.append([
            float(s.seq_start),
            float(s.seq_end - s.seq_start),
            float(s.in_flight_after),
            _RTX_CODE.get(s.rtx, 0.0),
        ])
    return out


_TSG_RETX_TEMPLATE = (
    "<b>⚠ Retransmit</b><br>"
    "seq %{customdata[0]:,.0f} (%{customdata[1]:.0f} B)<br>"
    "in-flight after: %{customdata[2]:,.0f} B<br>"
    "rtx code: %{customdata[3]:.0f} (1=rto 2=fast 3=spurious)"
    "<extra></extra>"
)


def _retx_segment_trace(
    model: TsgModel,
    *,
    name: str,
    xaxis_ref: str = "x",
    yaxis_ref: str = "y",
) -> dict[str, Any] | None:
    segs = [s for s in model.segments if s.rtx is not None]
    if not segs:
        return None
    xs: list[Any] = []
    ys: list[float | None] = []
    cd: list[list[float]] = []
    for s, row in zip(segs, _retx_customdata(segs)):
        t_iso = _epoch_to_iso(s.time)
        xs.extend([t_iso, t_iso, None])
        ys.extend([s.seq_start, s.seq_end, None])
        cd.extend([row, row, row])
    return {
        "type": "scattergl",
        "mode": "lines",
        "x": xs,
        "y": ys,
        "line": {"color": COLOR_MAP["red"], "width": 2},
        "customdata": cd,
        "hovertemplate": _TSG_RETX_TEMPLATE,
        "name": name,
        "legendgroup": name,
        "showlegend": True,
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


def _ack_customdata(acks: list[Ack]) -> list[list[float]]:
    """Index layout:
      0: ack_seq
      1: rwin (scaled if known, else raw)
      2: rwin_scale_known (0/1)
      3: dup_count
    """
    out: list[list[float]] = []
    for a in acks:
        rwin = float(a.rwin_scaled if a.rwin_scaled is not None else a.rwin)
        scale_known = 1.0 if a.rwin_scaled is not None else 0.0
        out.append([float(a.ack_seq), rwin, scale_known, float(a.dup_count)])
    return out


_TSG_ACK_TEMPLATE = (
    "<b>ACK for seq %{customdata[0]:,.0f}</b><br>"
    "rwnd %{customdata[1]:,.0f}<br>"
    "dup-ACK #%{customdata[3]:.0f}"
    "<extra></extra>"
)


_TSG_RWIN_TEMPLATE = (
    "<b>rwnd %{customdata[1]:,.0f}</b><br>"
    "(scale known: %{customdata[2]:.0f})"
    "<extra></extra>"
)


def _ack_trace(
    model: TsgModel,
    *,
    name: str,
    xaxis_ref: str = "x",
    yaxis_ref: str = "y",
) -> dict[str, Any] | None:
    if not model.acks:
        return None
    xs: list[Any] = []
    ys: list[float | None] = []
    cd: list[list[float]] = []
    prev_seq: int | None = None
    prev_time: float | None = None
    rows = _ack_customdata(model.acks)
    for a, row in zip(model.acks, rows):
        # Horizontal hold then vertical step at each ack.
        if prev_seq is not None and prev_time is not None:
            xs.extend([_epoch_to_iso(prev_time), _epoch_to_iso(a.time), None])
            ys.extend([prev_seq, prev_seq, None])
            cd.extend([row, row, row])
        xs.extend([_epoch_to_iso(a.time), _epoch_to_iso(a.time), None])
        ys.extend([prev_seq if prev_seq is not None else a.ack_seq, a.ack_seq, None])
        cd.extend([row, row, row])
        prev_seq = a.ack_seq
        prev_time = a.time
    return {
        "type": "scattergl",
        "mode": "lines",
        "x": xs,
        "y": ys,
        "line": {"color": COLOR_MAP["green"], "width": 1},
        "customdata": cd,
        "hovertemplate": _TSG_ACK_TEMPLATE,
        "name": name,
        "legendgroup": name,
        "showlegend": True,
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


def _rwin_trace(
    model: TsgModel,
    *,
    name: str,
    xaxis_ref: str = "x",
    yaxis_ref: str = "y",
) -> dict[str, Any] | None:
    if not model.acks:
        return None
    xs: list[Any] = []
    ys: list[float | None] = []
    cd: list[list[float]] = []
    prev_top: int | None = None
    prev_time: float | None = None
    rows = _ack_customdata(model.acks)
    for a, row in zip(model.acks, rows):
        top = a.ack_seq + a.rwin
        if prev_top is not None and prev_time is not None:
            xs.extend([_epoch_to_iso(prev_time), _epoch_to_iso(a.time), None])
            ys.extend([prev_top, prev_top, None])
            cd.extend([row, row, row])
        xs.extend([_epoch_to_iso(a.time), _epoch_to_iso(a.time), None])
        ys.extend([prev_top if prev_top is not None else top, top, None])
        cd.extend([row, row, row])
        prev_top = top
        prev_time = a.time
    return {
        "type": "scattergl",
        "mode": "lines",
        "x": xs,
        "y": ys,
        "line": {"color": COLOR_MAP["yellow"], "width": 1},
        "customdata": cd,
        "hovertemplate": _TSG_RWIN_TEMPLATE,
        "name": name,
        "legendgroup": name,
        "showlegend": True,
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


_ANOMALY_GLYPH = {
    "rto": "⚠ RTO",
    "fast": "⚠ fast retx",
    "spurious": "⚠ spurious",
    "zero_win": "0w",
    "win_shrink": "↓rwin",
    "win_shrink_large": "↓rwin",
    "ooo": "ooo",
    "sack_gap": "sack gap",
    "keepalive": "keepalive",
    "syn": "S",
    "syn_ack": "SA",
    "handshake_ack": "A",
    "fin": "FA",
    "fin_retx": "R FA",
    "dup_ack": "DA",
    "dup_ack_drove_retx": "DA→retx",
    "partial_ack": "PA",
    "coalesced": "LRO",
    "bad_csum": "csum?",
    "bad_csum_acked": "csum~",
    "bad_csum_lost": "csum!",
}

# Color per severity tier. Drives chart annotation color; kind→severity lives
# in tcp_inspect.SEVERITY_BY_KIND so the data model is the source of truth.
_SEVERITY_COLOR = {
    "severe": "#ff5555",   # red — alarms (rto, fast, spurious, zero_win, …)
    "warn": "#ffaa00",     # amber — symptoms worth attention
    "handshake": "#55ddff",  # cyan — protocol markers (SYN/SA/A/FA/R FA)
    "info": "#888888",     # grey — diagnostic noise; hidden unless toggled
}
# Dim backgrounds for hover popovers — saturated severity tint at low alpha
# so the popover identifies its tier without overpowering the label text.
_SEVERITY_HOVER_BG = {
    "severe": "#220000",
    "warn": "#221800",
    "handshake": "#001b22",
    "info": "#1a1a1a",
}

_ANOMALY_CLUSTER_S = 0.050

# Vertical offset per kind (pixels). Different kinds at the same time stack
# instead of overlapping. Flag events go above the data line; dup_ack sits
# below; warning kinds keep the original mid offset.
_KIND_YSHIFT = {
    "syn": 14,
    "syn_ack": 14,
    "handshake_ack": 14,
    "fin": 14,
    "fin_retx": 28,
    "dup_ack": -14,
    "dup_ack_drove_retx": -14,
    "partial_ack": -14,
    "coalesced": 28,
    "win_shrink": -28,
    "win_shrink_large": -28,
    "bad_csum": -28,
    "bad_csum_acked": -28,
    "bad_csum_lost": -28,
}
_DEFAULT_YSHIFT = 12
# Two annotations within this many seconds get a per-rank xshift bump so their
# text doesn't sit on top of each other along the time axis either.
_ANOMALY_COLLISION_S = 0.030
_COLLISION_XSHIFT_PX = 36


def _cluster_anomalies(anomalies: list[Anomaly]) -> list[tuple[Anomaly, int]]:
    """Collapse adjacent same-kind anomalies within _ANOMALY_CLUSTER_S into one
    representative per cluster, paired with the count."""
    out: list[tuple[Anomaly, int]] = []
    current: Anomaly | None = None
    count = 0
    for a in anomalies:
        if (
            current is not None
            and a.kind == current.kind
            and a.time - current.time <= _ANOMALY_CLUSTER_S
        ):
            count += 1
        else:
            if current is not None:
                out.append((current, count))
            current = a
            count = 1
    if current is not None:
        out.append((current, count))
    return out


_SEG_BACKED_KINDS = {"syn", "syn_ack", "fin", "fin_retx"}


def _anomaly_hovertext(a: Anomaly, model: TsgModel) -> str:
    """Render the hover text for one anomaly as multi-line HTML.

    Handshake/teardown markers (SYN/SA/FA/R FA) get enriched with the seq +
    ACK-RTT from their backing segment, since we strip those 1-byte segs
    from the data trace to keep the chart anchor unambiguous. Other kinds
    fall through to the raw one_liner (split on its own ` · ` separators).

    Plotly renders `<br>` as a line break inside hover popovers — using it
    here lets a long detail string stack into a readable column instead of
    sprawling sideways across the chart.
    """
    if a.kind in _SEG_BACKED_KINDS:
        for s in model.segments:
            # Times are float epoch; an exact equality holds because both the
            # segment and the flag-text annotation are sourced from the same
            # xpl command's x coordinate (no rebinning happens between).
            if s.time != a.time:
                continue
            parts = [a.one_liner, f"seq {s.seq_start}"]
            if s.paired_rtt_ms is not None:
                parts.append(f"ACKed {s.paired_rtt_ms:.1f} ms later")
            return "<br>".join(parts)
    return a.one_liner.replace(" · ", "<br>")


def _anomaly_annotations(
    model: TsgModel,
    *,
    xref: str = "x",
    yref: str = "y",
    show_info: bool = False,
) -> list[dict[str, Any]]:
    visible = [
        a
        for a in model.anomalies
        if show_info or SEVERITY_BY_KIND.get(a.kind, "info") != "info"
    ]
    clusters = _cluster_anomalies(visible)
    anns: list[dict[str, Any]] = []
    last_time: float | None = None
    rank = 0
    for a, count in clusters:
        text = _ANOMALY_GLYPH.get(a.kind, a.kind)
        if count > 1:
            text = f"{text} ×{count}"  # noqa: RUF001 — intentional Unicode multiplication sign
        y = a.seq_lo if a.seq_lo is not None else 0
        yshift = _KIND_YSHIFT.get(a.kind, _DEFAULT_YSHIFT)
        if last_time is not None and (a.time - last_time) <= _ANOMALY_COLLISION_S:
            rank += 1
        else:
            rank = 0
        last_time = a.time
        xshift = rank * _COLLISION_XSHIFT_PX
        severity = SEVERITY_BY_KIND.get(a.kind, "info")
        color = _SEVERITY_COLOR[severity]
        anns.append(
            {
                "x": _epoch_to_iso(a.time),
                "y": y,
                "xref": xref,
                "yref": yref,
                "text": text,
                "showarrow": False,
                "font": {"color": color, "size": 10, "family": "Menlo, monospace"},
                "xshift": xshift,
                "yshift": yshift,
                # Hover is owned by `_anomaly_hover_trace` so each popover
                # gets per-severity styling and there's exactly one popover
                # per location. Setting hovertext + captureevents here would
                # produce a second, default-styled popover stacked on top of
                # the scatter trace's — the user saw both for SYN/SA/FA.
            }
        )
    return anns


def _info_strip(
    model: TsgModel,
    *,
    xref: str,
    y_domain_top: float,
) -> dict[str, Any] | None:
    """Top-of-subplot strip summarizing info-tier kinds.

    Always rendered so the user knows what's been hidden — counts replace the
    individual annotations the chart used to overlay. Multi-event kinds get a
    count ("143 PA"); single-event protocol-ish kinds appear as a bare label
    if present. Returns None when no info-tier anomalies exist.
    """
    counts: dict[str, int] = {}
    for a in model.anomalies:
        if SEVERITY_BY_KIND.get(a.kind, "info") != "info":
            continue
        counts[a.kind] = counts.get(a.kind, 0) + 1
    if not counts:
        return None
    parts: list[str] = []
    # Stable display order: bias toward sender-side then receiver-side, then
    # csum / keepalive trailers. Matches the order kinds appear in a flow.
    for kind in (
        "partial_ack",
        "coalesced",
        "dup_ack",
        "win_shrink",
        "keepalive",
        "bad_csum_acked",
    ):
        n = counts.get(kind)
        if not n:
            continue
        glyph = _ANOMALY_GLYPH.get(kind, kind)
        parts.append(f"{n} {glyph}")
    if not parts:
        return None
    return {
        "x": 0.0,
        "y": y_domain_top,
        "xref": f"{xref} domain",
        "yref": "paper",
        "text": "info: " + " · ".join(parts),
        "showarrow": False,
        "font": {"color": _SEVERITY_COLOR["info"], "size": 10, "family": "Menlo, monospace"},
        "xanchor": "left",
        "yanchor": "bottom",
        "yshift": 2,
    }


# Just the detail text — the visible glyph IS the header. Repeating it
# inside the popover wasted a line (e.g. a bold "S" above "SYN (initiator)").
_ANOMALY_HOVER_TEMPLATE = "%{customdata[0]}<extra></extra>"


def _anomaly_hover_trace(
    model: TsgModel,
    *,
    xaxis_ref: str = "x",
    yaxis_ref: str = "y",
    show_info: bool = False,
) -> dict[str, Any] | None:
    """Invisible scatter trace co-located with anomaly annotations, sized so
    Plotly's `hovermode: closest` picks it up before the nearest data segment.
    Captures the case where the user hovers near (not exactly on) a label.

    Per-point hoverlabel colors so a SYN's popover reads cyan, an RTO's reads
    red, etc. — a single hardcoded red bordercolor was making every anomaly
    tooltip look like an alarm. Filter info-tier anomalies when they're not
    inlined as annotations (mirrors the visibility filter in
    `_anomaly_annotations`) so hovering an empty region doesn't pull up an
    invisible info marker.
    """
    visible = [
        a
        for a in model.anomalies
        if show_info or SEVERITY_BY_KIND.get(a.kind, "info") != "info"
    ]
    if not visible:
        return None
    xs: list[Any] = []
    ys: list[float] = []
    cd: list[list[str]] = []
    border_colors: list[str] = []
    bg_colors: list[str] = []
    for a in visible:
        xs.append(_epoch_to_iso(a.time))
        ys.append(float(a.seq_lo) if a.seq_lo is not None else 0.0)
        cd.append([_anomaly_hovertext(a, model)])
        severity = SEVERITY_BY_KIND.get(a.kind, "info")
        border_colors.append(_SEVERITY_COLOR[severity])
        bg_colors.append(_SEVERITY_HOVER_BG[severity])
    return {
        "type": "scattergl",
        "mode": "markers",
        "x": xs,
        "y": ys,
        "marker": {"color": "rgba(255, 85, 85, 0.0)", "size": 18},
        "customdata": cd,
        "hovertemplate": _ANOMALY_HOVER_TEMPLATE,
        "name": "anomalies",
        "showlegend": False,
        "hoverlabel": {"bgcolor": bg_colors, "bordercolor": border_colors},
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


def _in_flight_overlay(
    model: TsgModel,
    *,
    name: str,
    xaxis_ref: str = "x",
    yaxis_ref: str = "y",
) -> dict[str, Any] | None:
    """In-flight area: y = current cumack + in_flight bytes. The area between
    this trace and the ACK staircase visualizes outstanding data.
    """
    if not model.in_flight:
        return None
    ack_times = [a.time for a in model.acks]
    ack_seqs = [a.ack_seq for a in model.acks]
    # Anchor pre-first-ack overlay points to the first ack's seq (or the first
    # segment's seq_start when there are no acks) so the overlay sits on the
    # data band, not at y=0 — which would force the y-axis to autorange down
    # to 0 and leave most of the chart empty.
    if ack_seqs:
        pre_first_baseline = ack_seqs[0]
    elif model.segments:
        pre_first_baseline = model.segments[0].seq_start
    else:
        pre_first_baseline = 0

    def _cumack_at(t: float) -> int:
        if not ack_times:
            return pre_first_baseline
        i = bisect.bisect_right(ack_times, t)
        return ack_seqs[i - 1] if i > 0 else pre_first_baseline

    xs = [_epoch_to_iso(t) for t, _ in model.in_flight]
    ys = [_cumack_at(t) + ifl for t, ifl in model.in_flight]
    return {
        "type": "scattergl",
        "mode": "lines",
        "x": xs,
        "y": ys,
        "fill": "tonexty",
        "fillcolor": "rgba(85, 255, 255, 0.10)",
        "line": {"color": "rgba(85, 255, 255, 0.0)", "width": 0},
        "name": name,
        "legendgroup": name,
        "showlegend": True,
        "hoverinfo": "skip",
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


def _build_direction_traces(
    model: TsgModel,
    *,
    prefix: str,
    xaxis_ref: str,
    yaxis_ref: str,
    show_info: bool = False,
) -> list[dict[str, Any]]:
    """Assemble all per-direction traces (data, retx, ack, rwin, in-flight)
    bound to the given subplot axes. Skips traces with no data."""
    out: list[dict[str, Any]] = []
    seg_tr = _data_segment_trace(
        model,
        name=f"{prefix} data",
        color=COLOR_MAP["white"],
        xaxis_ref=xaxis_ref,
        yaxis_ref=yaxis_ref,
    )
    if seg_tr is not None:
        out.append(seg_tr)
    rtx_tr = _retx_segment_trace(
        model, name=f"{prefix} retx", xaxis_ref=xaxis_ref, yaxis_ref=yaxis_ref
    )
    if rtx_tr is not None:
        out.append(rtx_tr)
    ack_tr = _ack_trace(
        model, name=f"{prefix} ack", xaxis_ref=xaxis_ref, yaxis_ref=yaxis_ref
    )
    if ack_tr is not None:
        out.append(ack_tr)
    rwin_tr = _rwin_trace(
        model, name=f"{prefix} rwin", xaxis_ref=xaxis_ref, yaxis_ref=yaxis_ref
    )
    if rwin_tr is not None:
        out.append(rwin_tr)
    ifl_tr = _in_flight_overlay(
        model, name=f"{prefix} in-flight", xaxis_ref=xaxis_ref, yaxis_ref=yaxis_ref
    )
    if ifl_tr is not None:
        out.append(ifl_tr)
    hover_tr = _anomaly_hover_trace(
        model, xaxis_ref=xaxis_ref, yaxis_ref=yaxis_ref, show_info=show_info
    )
    if hover_tr is not None:
        out.append(hover_tr)
    return out


def _tsg_xaxis(*, show_ticks: bool) -> dict[str, Any]:
    xaxis: dict[str, Any] = {
        "title": {"text": "time" if show_ticks else ""},
        "type": "date",
        "tickformat": "%H:%M:%S.%L",
        "hoverformat": "%Y-%m-%d %H:%M:%S.%6f",
        "gridcolor": GRID_COLOR,
        "zerolinecolor": ZERO_LINE_COLOR,
        "showticklabels": show_ticks,
    }
    return xaxis


def _tsg_yaxis() -> dict[str, Any]:
    return {
        "title": {"text": "sequence number"},
        "gridcolor": GRID_COLOR,
        "zerolinecolor": ZERO_LINE_COLOR,
    }


def _direction_label(model: TsgModel) -> str:
    if model.src and model.dst:
        return f"{model.src} → {model.dst}"
    return ""


def _capped_yaxis_range(model: TsgModel) -> list[float] | None:
    """Compute a y-axis range tight to the data band, capping how far rwin can
    push the upper bound. For small connections where the receiver advertises
    a window many times larger than the sender ever fills, autorange would
    stretch the axis up to (ack + rwin) and the data exchange would become a
    thin slice at the bottom. Cap rwin to extend at most `data_span` above the
    data top; rwin still renders and clips above the visible area when the
    window dwarfs the traffic. Returns None when there's no data to bound
    (caller leaves Plotly's default autorange in place)."""
    ys: list[float] = []
    for s in model.segments:
        ys.append(s.seq_start)
        ys.append(s.seq_end)
    for a in model.acks:
        ys.append(a.ack_seq)
    if not ys:
        return None
    data_lo = min(ys)
    data_hi = max(ys)
    data_span = max(1.0, data_hi - data_lo)
    margin = data_span * 0.05

    rwin_tops = [a.ack_seq + a.rwin for a in model.acks if a.rwin > 0]
    if rwin_tops:
        rwin_max = max(rwin_tops)
        cap_hi = data_hi + min(max(0, rwin_max - data_hi), data_span)
    else:
        cap_hi = data_hi
    return [data_lo - margin, cap_hi + margin]


def to_tsg_figure(pair: TsgModelPair, *, show_info: bool = False) -> dict[str, Any]:
    """Build a Plotly figure for the TSG metric from a TsgModelPair.

    Each direction lives in its own TCP sequence space (independent ISNs), so
    plotting both on a shared y-axis crams them into different bands with
    empty space between. When both directions are populated we stack them as
    subplots (forward top, backward bottom) with a matched x-axis; each
    subplot's y-axis auto-scales to its own data. When only one direction is
    populated we fall back to a single subplot.

    Tooltips use numeric customdata + hovertemplate so the JSON stays small;
    formatting happens JS-side.
    """
    fwd = pair.fwd
    bwd = pair.bwd

    # Title shows the canonical (forward) direction when available.
    if fwd is not None and fwd.src and fwd.dst:
        title = f"{fwd.src} → {fwd.dst}"
    elif bwd is not None and bwd.src and bwd.dst:
        title = f"{bwd.dst} → {bwd.src}"
    else:
        title = "time sequence graph"

    layout = _base_layout(title, dragmode="pan", showlegend=True)

    if fwd is None and bwd is None:
        layout["xaxis"] = _tsg_xaxis(show_ticks=True)
        layout["yaxis"] = _tsg_yaxis()
        layout["annotations"] = []
        return {"data": [], "layout": layout}

    # Single-direction figure: one subplot, no axis splitting.
    if fwd is None or bwd is None:
        only = fwd if fwd is not None else bwd
        prefix = "fwd" if fwd is not None else "bwd"
        layout["xaxis"] = _tsg_xaxis(show_ticks=True)
        yaxis = _tsg_yaxis()
        only_range = _capped_yaxis_range(only)
        if only_range is not None:
            yaxis["range"] = only_range
            yaxis["autorange"] = False
        layout["yaxis"] = yaxis
        traces = _build_direction_traces(
            only, prefix=prefix, xaxis_ref="x", yaxis_ref="y", show_info=show_info
        )
        annotations = _anomaly_annotations(
            only, xref="x", yref="y", show_info=show_info
        )
        strip = _info_strip(only, xref="x", y_domain_top=1.0)
        if strip is not None:
            annotations.append(strip)
        layout["annotations"] = annotations
        return {"data": traces, "layout": layout}

    # Both directions: stacked subplots. Forward top, backward bottom; x2
    # matches x so pan/zoom on either subplot drives both. Each y-axis
    # auto-scales to its own direction's sequence space.
    fwd_xaxis = _tsg_xaxis(show_ticks=False)
    fwd_xaxis["anchor"] = "y"
    fwd_yaxis = _tsg_yaxis()
    fwd_yaxis["domain"] = list(_FWD_DOMAIN)
    fwd_yaxis["anchor"] = "x"
    fwd_range = _capped_yaxis_range(fwd)
    if fwd_range is not None:
        fwd_yaxis["range"] = fwd_range
        fwd_yaxis["autorange"] = False

    bwd_xaxis = _tsg_xaxis(show_ticks=True)
    bwd_xaxis["matches"] = "x"
    bwd_xaxis["anchor"] = "y2"
    bwd_xaxis["side"] = "bottom"
    bwd_yaxis = _tsg_yaxis()
    bwd_yaxis["domain"] = list(_BWD_DOMAIN)
    bwd_yaxis["anchor"] = "x2"
    bwd_range = _capped_yaxis_range(bwd)
    if bwd_range is not None:
        bwd_yaxis["range"] = bwd_range
        bwd_yaxis["autorange"] = False

    layout["xaxis"] = fwd_xaxis
    layout["yaxis"] = fwd_yaxis
    layout["xaxis2"] = bwd_xaxis
    layout["yaxis2"] = bwd_yaxis

    traces = (
        _build_direction_traces(
            fwd, prefix="fwd", xaxis_ref="x", yaxis_ref="y", show_info=show_info
        )
        + _build_direction_traces(
            bwd, prefix="bwd", xaxis_ref="x2", yaxis_ref="y2", show_info=show_info
        )
    )

    annotations = _anomaly_annotations(
        fwd, xref="x", yref="y", show_info=show_info
    ) + _anomaly_annotations(
        bwd, xref="x2", yref="y2", show_info=show_info
    )
    for strip in (
        _info_strip(fwd, xref="x", y_domain_top=_FWD_DOMAIN[1]),
        _info_strip(bwd, xref="x2", y_domain_top=_BWD_DOMAIN[1]),
    ):
        if strip is not None:
            annotations.append(strip)
    # Subplot direction labels (top-left corner of each pane).
    for text, y in (
        (_direction_label(fwd), _FWD_DOMAIN[1]),
        (_direction_label(bwd), _BWD_DOMAIN[1]),
    ):
        if not text:
            continue
        annotations.append(
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
        )
    layout["annotations"] = annotations
    return {"data": traces, "layout": layout}


# ---------------------------------------------------------------------------
# Throughput figure
# ---------------------------------------------------------------------------

_STALL_ALPHA = {"info": 0.10, "warn": 0.15, "severe": 0.22}


def _throughput_direction_label(model: ThroughputModel) -> str:
    if model.src and model.dst:
        return f"{model.src} → {model.dst}"
    return ""


def _tput_xaxis(*, show_ticks: bool) -> dict[str, Any]:
    return {
        "type": "date",
        "tickformat": "%H:%M:%S.%L",
        "hoverformat": "%Y-%m-%d %H:%M:%S.%6f",
        "gridcolor": GRID_COLOR,
        "zerolinecolor": ZERO_LINE_COLOR,
        "showticklabels": show_ticks,
        "title": {"text": "time" if show_ticks else ""},
    }


def _tput_yaxis() -> dict[str, Any]:
    return {
        "title": {"text": "throughput"},
        "tickformat": ".3s",
        "ticksuffix": "B/s",
        "gridcolor": GRID_COLOR,
        "zerolinecolor": ZERO_LINE_COLOR,
    }


def _tput_yaxis_range(samples: tuple[RateSample, ...]) -> list[float]:
    if not samples:
        return [0.0, 1.0]
    data_max = max(
        (max(s.wire_Bps, s.goodput_Bps) for s in samples),
        default=0.0,
    )
    y_data = data_max * 1.3
    ceil_vals = sorted(s.max_Bps for s in samples if s.max_Bps is not None)
    if ceil_vals and data_max > 0:
        ceil_p50 = ceil_vals[len(ceil_vals) // 2]
        # Include the ceiling only when it's within an order of magnitude of
        # the data — otherwise it would dominate the axis and squash the
        # data into invisibility (rwin/RTT can legitimately be much higher
        # than achieved goodput on app-limited connections).
        if ceil_p50 <= data_max * 5:
            return [0.0, max(y_data, ceil_p50 * 1.1, 1.0)]
    return [0.0, max(y_data, 1.0)]


def _stall_traces(
    model: ThroughputModel,
    y_range: list[float],
    *,
    xaxis_ref: str,
    yaxis_ref: str,
    show_info: bool,
    legend_seen: set[str],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    y0, y1 = y_range
    for stall in model.stalls:
        if stall.severity == "info" and not show_info:
            continue
        alpha = _STALL_ALPHA[stall.severity]
        show = "stall" not in legend_seen
        if show:
            legend_seen.add("stall")
        dur_ms = stall.duration_s * 1000.0
        text = f"stall {dur_ms:.0f}ms ({stall.rtt_multiple:.1f}×RTT)"  # noqa: RUF001 — intentional Unicode multiplication sign for RTT-multiple display
        t0 = _epoch_to_iso(stall.t_start)
        t1 = _epoch_to_iso(stall.t_end)
        out.append({
            "type": "scatter",
            "mode": "lines",
            "x": [t0, t1, t1, t0, t0, None],
            "y": [y0, y0, y1, y1, y0, None],
            "fill": "toself",
            "fillcolor": f"rgba(255,119,255,{alpha})",
            "line": {"color": "rgba(0,0,0,0)", "width": 0},
            "text": text,
            "hoverinfo": "text",
            "name": "stall",
            "legendgroup": "stall",
            "showlegend": show,
            "xaxis": xaxis_ref,
            "yaxis": yaxis_ref,
        })
    return out


def _envelope_trace(
    model: ThroughputModel,
    *,
    xaxis_ref: str,
    yaxis_ref: str,
    legend_seen: set[str],
) -> dict[str, Any] | None:
    xs: list[Any] = []
    ys: list[Any] = []
    for s in model.samples:
        if s.max_Bps is None:
            if xs and xs[-1] is not None:
                xs.append(None)
                ys.append(None)
        else:
            xs.append(_epoch_to_iso(s.t))
            ys.append(s.max_Bps)
    while xs and xs[0] is None:
        xs.pop(0)
        ys.pop(0)
    while xs and xs[-1] is None:
        xs.pop()
        ys.pop()
    if not xs:
        return None
    show = "ceiling" not in legend_seen
    if show:
        legend_seen.add("ceiling")
    # scattergl OK here (no fill, unlike wire/goodput which need scatter for fill: tozeroy)
    return {
        "type": "scattergl",
        "mode": "lines",
        "x": xs,
        "y": ys,
        "line": {"color": "#888", "dash": "dot", "width": 1},
        "opacity": 0.6,
        "hovertemplate": "ceiling %{y:.3s}B/s (rwin/RTT)<extra></extra>",
        "name": "ceiling",
        "legendgroup": "ceiling",
        "showlegend": show,
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


def _wire_trace(
    model: ThroughputModel,
    *,
    xaxis_ref: str,
    yaxis_ref: str,
    legend_seen: set[str],
) -> dict[str, Any] | None:
    if not model.samples:
        return None
    xs = [_epoch_to_iso(s.t) for s in model.samples]
    ys = [s.wire_Bps for s in model.samples]
    show = "wire" not in legend_seen
    if show:
        legend_seen.add("wire")
    return {
        "type": "scatter",
        "mode": "lines",
        "x": xs,
        "y": ys,
        "fill": "tozeroy",
        "fillcolor": "rgba(85,153,255,0.25)",
        "line": {"color": "#5599ff", "width": 1},
        "hovertemplate": "wire %{y:.3s}B/s<extra></extra>",
        "name": "wire",
        "legendgroup": "wire",
        "showlegend": show,
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


def _goodput_trace(
    model: ThroughputModel,
    *,
    xaxis_ref: str,
    yaxis_ref: str,
    legend_seen: set[str],
) -> dict[str, Any] | None:
    if not model.samples:
        return None
    if all(s.goodput_Bps == 0.0 for s in model.samples):
        return None
    xs = [_epoch_to_iso(s.t) for s in model.samples]
    ys = [s.goodput_Bps for s in model.samples]
    show = "goodput" not in legend_seen
    if show:
        legend_seen.add("goodput")
    return {
        "type": "scatter",
        "mode": "lines",
        "x": xs,
        "y": ys,
        "fill": "tozeroy",
        "fillcolor": "rgba(85,255,85,0.45)",
        "line": {"color": "#55ff55", "width": 1},
        "hovertemplate": "goodput %{y:.3s}B/s<extra></extra>",
        "name": "goodput",
        "legendgroup": "goodput",
        "showlegend": show,
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


def _cliff_annotations(
    model: ThroughputModel,
    y_range: list[float],
    *,
    xref: str,
    yref: str,
    show_info: bool,
    legend_seen: set[str],
) -> list[dict[str, Any]]:
    anns: list[dict[str, Any]] = []
    y_top = y_range[1] if y_range[1] > 0 else 1.0
    # Three vertical positions to stagger clustered cliffs and prevent text
    # collisions. Cycle through them in temporal order.
    stagger = [0.92, 0.78, 0.64]
    visible_idx = 0
    for cliff in model.cliffs:
        if cliff.severity == "info" and not show_info:
            continue
        pct = cliff.drop_frac * 100.0
        color = _SEVERITY_COLOR[cliff.severity]
        y_pos = y_top * stagger[visible_idx % len(stagger)]
        visible_idx += 1
        anns.append({
            "x": _epoch_to_iso(cliff.t),
            "y": y_pos,
            "xref": xref,
            "yref": yref,
            "text": f"cliff -{pct:.0f}% ({cliff.cause_hint})",
            "showarrow": True,
            "arrowhead": 2,
            "arrowcolor": color,
            "font": {"color": color, "size": 10},
            "ax": 0,
            "ay": -20,
        })
    return anns


def _no_data_annotation(label: str, *, y_paper: float = 0.5) -> dict[str, Any]:
    return {
        "text": label,
        "xref": "paper",
        "yref": "paper",
        "x": 0.5,
        "y": y_paper,
        "xanchor": "center",
        "yanchor": "middle",
        "showarrow": False,
        "font": {"color": "#555", "size": 13},
    }


def _build_tput_direction(
    model: ThroughputModel,
    *,
    xaxis_ref: str,
    yaxis_ref: str,
    show_info: bool,
    legend_seen: set[str],
    y_paper: float = 0.5,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Returns (traces, annotations) for one direction."""
    if not model.samples:
        dir_label = _throughput_direction_label(model)
        label = f"(no data sent {dir_label})" if dir_label else "(no data)"
        return [], [_no_data_annotation(label, y_paper=y_paper)]

    y_range = _tput_yaxis_range(model.samples)
    traces: list[dict[str, Any]] = []
    anns: list[dict[str, Any]] = []

    traces.extend(_stall_traces(
        model, y_range,
        xaxis_ref=xaxis_ref, yaxis_ref=yaxis_ref,
        show_info=show_info, legend_seen=legend_seen,
    ))

    env = _envelope_trace(model, xaxis_ref=xaxis_ref, yaxis_ref=yaxis_ref, legend_seen=legend_seen)
    if env is not None:
        traces.append(env)

    wire = _wire_trace(model, xaxis_ref=xaxis_ref, yaxis_ref=yaxis_ref, legend_seen=legend_seen)
    if wire is not None:
        traces.append(wire)

    gput = _goodput_trace(model, xaxis_ref=xaxis_ref, yaxis_ref=yaxis_ref, legend_seen=legend_seen)
    if gput is not None:
        traces.append(gput)
    elif all(s.goodput_Bps == 0.0 for s in model.samples):
        anns.append({
            "text": "goodput unavailable — no ACK data",
            "xref": "paper",
            "yref": yaxis_ref,
            "x": 0.99,
            "y": y_range[1] * 0.95,
            "xanchor": "right",
            "yanchor": "top",
            "showarrow": False,
            "font": {"color": "#555", "size": 10},
        })

    anns.extend(_cliff_annotations(
        model, y_range,
        xref=xaxis_ref, yref=yaxis_ref,
        show_info=show_info, legend_seen=legend_seen,
    ))

    return traces, anns


def to_throughput_figure(pair: ThroughputModelPair, *, show_info: bool = False) -> dict[str, Any]:
    fwd = pair.fwd
    bwd = pair.bwd

    if fwd is not None and fwd.src and fwd.dst:
        title = f"{fwd.src} → {fwd.dst} throughput"
    elif bwd is not None and bwd.src and bwd.dst:
        title = f"{bwd.dst} → {bwd.src} throughput"
    else:
        title = "throughput"

    layout = _base_layout(title, dragmode="pan", showlegend=True)
    # Cliff annotations live near y_top, so the default top-right legend
    # collides with them. Float the legend horizontally below the title.
    layout["legend"] = {
        "orientation": "h",
        "xanchor": "right",
        "x": 1.0,
        "yanchor": "bottom",
        "y": 1.02,
        "bgcolor": "rgba(0,0,0,0)",
        "font": {"size": 11, "family": "Menlo, monospace"},
    }

    if fwd is None and bwd is None:
        layout["xaxis"] = _tput_xaxis(show_ticks=True)
        layout["yaxis"] = _tput_yaxis()
        layout["annotations"] = [_no_data_annotation("no throughput data")]
        return {"data": [], "layout": layout}

    if fwd is None or bwd is None:
        only = fwd if fwd is not None else bwd
        legend_seen: set[str] = set()
        yax = _tput_yaxis()
        yax["range"] = _tput_yaxis_range(only.samples)
        yax["autorange"] = False
        layout["xaxis"] = _tput_xaxis(show_ticks=True)
        layout["yaxis"] = yax
        traces, anns = _build_tput_direction(
            only, xaxis_ref="x", yaxis_ref="y",
            show_info=show_info, legend_seen=legend_seen,
        )
        layout["annotations"] = anns
        return {"data": traces, "layout": layout}

    # Both directions.
    legend_seen = set()

    fwd_xaxis = _tput_xaxis(show_ticks=False)
    fwd_xaxis["anchor"] = "y"
    fwd_yax = _tput_yaxis()
    fwd_yax["domain"] = list(_FWD_DOMAIN)
    fwd_yax["anchor"] = "x"
    fwd_yax["range"] = _tput_yaxis_range(fwd.samples)
    fwd_yax["autorange"] = False

    bwd_xaxis = _tput_xaxis(show_ticks=True)
    bwd_xaxis["matches"] = "x"
    bwd_xaxis["anchor"] = "y2"
    bwd_xaxis["side"] = "bottom"
    bwd_yax = _tput_yaxis()
    bwd_yax["domain"] = list(_BWD_DOMAIN)
    bwd_yax["anchor"] = "x2"
    bwd_yax["range"] = _tput_yaxis_range(bwd.samples)
    bwd_yax["autorange"] = False

    layout["xaxis"] = fwd_xaxis
    layout["yaxis"] = fwd_yax
    layout["xaxis2"] = bwd_xaxis
    layout["yaxis2"] = bwd_yax

    fwd_traces, fwd_anns = _build_tput_direction(
        fwd, xaxis_ref="x", yaxis_ref="y",
        show_info=show_info, legend_seen=legend_seen,
        y_paper=(_FWD_DOMAIN[0] + _FWD_DOMAIN[1]) / 2,
    )
    bwd_traces, bwd_anns = _build_tput_direction(
        bwd, xaxis_ref="x2", yaxis_ref="y2",
        show_info=show_info, legend_seen=legend_seen,
        y_paper=(_BWD_DOMAIN[0] + _BWD_DOMAIN[1]) / 2,
    )

    annotations = fwd_anns + bwd_anns
    for text, y in (
        (_throughput_direction_label(fwd), _FWD_DOMAIN[1]),
        (_throughput_direction_label(bwd), _BWD_DOMAIN[1]),
    ):
        if not text:
            continue
        annotations.append({
            "text": text,
            "xref": "paper", "yref": "paper",
            "x": 0, "y": y,
            "xanchor": "left", "yanchor": "bottom",
            "showarrow": False,
            "font": _SUBPLOT_LABEL_FONT,
        })
    layout["annotations"] = annotations
    return {"data": fwd_traces + bwd_traces, "layout": layout}
