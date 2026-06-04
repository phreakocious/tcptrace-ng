"""Convert XplPlot dataclasses to Plotly figure dicts.

Pure module. Groups commands by (type, color) to keep trace counts low
even on busy plots — Plotly handles a few traces with thousands of
segments far better than thousands of single-segment traces.
"""

from __future__ import annotations

import bisect
import re
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
from .theme import (
    GRID_COLOR,
    HOVER_BG,
    HOVER_BORDER,
    HOVER_TEXT,
    LEGEND_BG,
    LEGEND_BORDER,
    LINE_DIM_COLOR,
    PALETTE,
    PLOTLY_MONO_FAMILY,
    SUBPLOT_LABEL_COLOR,
    ZERO_LINE_COLOR,
    rgba,
)
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

# Map xplot named colors to palette hexes. See theme.Palette / design doc §5.
# xplot 'red' = per-event trouble; mapped to PALETTE.bad (orange) so individual
# ticks don't read as alarms — clusters do. PALETTE.crit (red) is reserved for
# findings-layer confirmations.
COLOR_MAP: dict[str, str] = {
    "white": PALETTE.text_emph,
    "red": PALETTE.bad,
    "green": PALETTE.good,
    "yellow": PALETTE.notable,
    "blue": PALETTE.info,
    "magenta": PALETTE.magenta,
    "cyan": PALETTE.accent,
    "orange": PALETTE.bad,
    "purple": PALETTE.rare,
    "pink": PALETTE.magenta,
    # black-on-dark is invisible — lift to dim.
    "black": PALETTE.text_dim,
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
}

_SUBPLOT_LABEL_FONT = {
    "color": SUBPLOT_LABEL_COLOR,
    "size": 11,
    "family": PLOTLY_MONO_FAMILY,
}

# Threshold above which label-per-trace mode (one legend entry per label)
# collapses into one-trace-per-color with the label exposed only via hovertext.
# Metrics like owin/ssize emit a handful of semantic labels ("owin", "rwin")
# that belong in the legend; tline emits a unique seq/ack string per packet
# and would otherwise spawn thousands of single-point traces — Plotly chokes
# building that many WebGL contexts long before render starts.
_LABEL_LEGEND_THRESHOLD = 32


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

    Text-derived traces always show up in the legend — those carry semantic
    names (`ltext` in the xpl). Marker and box/line traces stay hidden from the
    legend — their (color, kind/dash) tuples carry no user-facing meaning beyond
    the marker's own appearance.

    `legend_seen`, when passed, dedupes legend entries across the two
    directions of a paired figure — the second direction skips entries whose
    label already appeared.
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
            # tcptrace's box is a 2-coord point glyph (the FIN marker), not a
            # rectangle — render it as a square marker, like dot/diamond.
            markers[("box", cmd.color)].append((cmd.x, cmd.y))
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
                "hoverinfo": "y",
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

    # Marker traces stay out of the legend — a (color, kind) tuple carries no
    # user-facing meaning beyond the marker's own appearance. Semantic names
    # come from the Text-derived traces above.
    for (kind, color), pts in markers.items():
        symbol = _marker_symbol(kind)
        traces.append(
            {
                "type": "scattergl",
                "mode": "markers",
                "x": [xfmt(p[0]) for p in pts],
                "y": [p[1] for p in pts],
                "marker": {"color": _color(color), "symbol": symbol, "size": 6},
                "legendgroup": color,
                "name": f"{color} {kind}",
                "hoverinfo": "y",
                "showlegend": False,
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
            "bgcolor": LEGEND_BG,
            "bordercolor": LEGEND_BORDER,
            "borderwidth": 1,
            "font": {"size": 11, "family": PLOTLY_MONO_FAMILY, "color": HOVER_TEXT},
        },
        "margin": {"l": 60, "r": 20, "t": 70, "b": 50},
        "annotations": [],
        "modebar": {"orientation": "v"},
        # Hover tooltip styling: match the dark chrome (header/sidebar) so the
        # tooltip doesn't punch a bright box through the dim grid. align=left
        # keeps multi-line hovertext (e.g. tline's per-packet labels) tidy.
        "hoverlabel": {
            "bgcolor": HOVER_BG,
            "bordercolor": HOVER_BORDER,
            "font": {
                "family": PLOTLY_MONO_FAMILY,
                "color": HOVER_TEXT,
                "size": 11,
            },
            "align": "left",
            "namelength": -1,
        },
    }
    if dragmode is not None:
        layout["dragmode"] = dragmode
    return layout


def to_plotly_figure(plot: XplPlot) -> dict[str, Any]:
    """Render an XplPlot as a Plotly figure dict."""

    time_axis = _is_epoch_time_axis(plot)
    xfmt = _epoch_to_iso if time_axis else (lambda v: v)

    traces = _build_traces(plot, xfmt)

    layout = _base_layout(plot.title, showlegend=_has_legend_content(plot))
    layout["xaxis"] = _xaxis_config(plot, time_axis)
    layout["yaxis"] = _yaxis_config(plot)
    return {"data": traces, "layout": layout}


# Subplot domain layout. Forward sits on top, backward below. A vertical gap
# leaves room for the bottom subplot's title without colliding with the top
# subplot's x-axis ticks (which we hide anyway).
_FWD_DOMAIN = (0.55, 1.0)
_BWD_DOMAIN = (0.0, 0.45)
# When one direction carries no traffic, render its pane as a thin strip so the
# populated direction expands. The strip stays tall enough for one centered
# "no traffic" annotation; the populated side takes the rest of the canvas.
_FWD_DOMAIN_TALL = (0.15, 1.0)
_BWD_DOMAIN_THIN = (0.0, 0.10)
_FWD_DOMAIN_THIN = (0.90, 1.0)
_BWD_DOMAIN_TALL = (0.0, 0.85)


def _subplot_domains(
    fwd_empty: bool, bwd_empty: bool
) -> tuple[tuple[float, float], tuple[float, float]]:
    """Pick (fwd, bwd) y-axis domains based on which pane carries no data.

    Both empty / both populated → the symmetric 45/45 split. One side empty →
    that pane shrinks to a strip wide enough for the no-data annotation.
    """
    if fwd_empty and not bwd_empty:
        return _FWD_DOMAIN_THIN, _BWD_DOMAIN_TALL
    if bwd_empty and not fwd_empty:
        return _FWD_DOMAIN_TALL, _BWD_DOMAIN_THIN
    return _FWD_DOMAIN, _BWD_DOMAIN


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
        forward,
        xfmt,
        xaxis_ref="x",
        yaxis_ref="y",
        legend_seen=legend_seen,
    )
    bwd_traces = _build_traces(
        backward,
        xfmt,
        xaxis_ref="x2",
        yaxis_ref="y2",
        legend_seen=legend_seen,
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
        forward.title, dragmode="zoom", showlegend=_has_legend_content(forward, backward)
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
    if kind == "box":
        return "square"
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


def _seg_customdata(segments: list[Segment], baseline: int = 0) -> list[list[float | str]]:
    """Per-segment tuple consumed by the hovertemplate.

    Index layout:
      0: 1-based segment index
      1: inter-segment delta hover fragment — "" for the first segment (no
         previous), " · +N.N ms" otherwise. Prebuilt (L2): plotly templates
         can't branch, so a NaN delta would render "+NaN ms".
      2: seq_start  (relative to baseline when baseline != 0)
      3: length (bytes)
      4: in_flight_after (bytes)
      5: paired-RTT hover fragment — "" when unpaired, "<br>ACKed N.N ms later"
         otherwise (L2; avoids "ACKed NaN ms later").
    """
    out: list[list[float | str]] = []
    prev_time: float | None = None
    for i, s in enumerate(segments, start=1):
        delta = f" · +{(s.time - prev_time) * 1000.0:.1f} ms" if prev_time is not None else ""
        rtt = f"<br>ACKed {s.paired_rtt_ms:.1f} ms later" if s.paired_rtt_ms is not None else ""
        out.append(
            [
                float(i),
                delta,
                float(s.seq_start - baseline),
                float(s.seq_end - s.seq_start),
                float(s.in_flight_after),
                rtt,
            ]
        )
        prev_time = s.time
    return out


_TSG_SEG_TEMPLATE = (
    "<b>Seg #%{customdata[0]:.0f}</b>"
    "%{customdata[1]}<br>"
    "seq %{customdata[2]:,.0f} (%{customdata[3]:.0f} B)<br>"
    "in-flight after: %{customdata[4]:,.0f} B"
    "%{customdata[5]}"
    "<extra></extra>"
)


def _data_segment_trace(
    model: TsgModel,
    *,
    name: str,
    color: str,
    xaxis_ref: str = "x",
    yaxis_ref: str = "y",
    baseline: int = 0,
    showlegend: bool = True,
    legendgroup: str | None = None,
) -> dict[str, Any] | None:
    """Build one scattergl trace for non-retx data segments.

    Skip segments with ≤1 byte of payload (SYN/FIN consume 1 seq byte,
    keepalives are zero-length). They draw as 0-pixel verticals — invisible
    on the chart — yet still register hover targets that produce orphan
    "Seg #N · 0.0 ms" tooltips. Their semantic info lives on the matching
    handshake/keepalive annotation, which we enrich with seq/RTT below.
    """
    segs = [
        s
        for s in model.segments
        if s.rtx is None and not s.fabricated and s.seq_end - s.seq_start > 1
    ]
    if not segs:
        return None
    xs: list[Any] = []
    ys: list[float | None] = []
    cd: list[list[float | str]] = []
    per_seg = _seg_customdata(segs, baseline=baseline)
    for s, row in zip(segs, per_seg, strict=True):
        t_iso = _epoch_to_iso(s.time)
        xs.extend([t_iso, t_iso, None])
        ys.extend([s.seq_start - baseline, s.seq_end - baseline, None])
        cd.extend([row, row, row])
    return {
        "type": "scattergl",
        "mode": "lines",
        "x": xs,
        "y": ys,
        "line": {"color": color, "width": 2},
        "customdata": cd,
        "hovertemplate": _TSG_SEG_TEMPLATE,
        "name": name,
        "legendgroup": legendgroup or name,
        "showlegend": showlegend,
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


_TSG_FAB_TEMPLATE = "%{hovertext}<extra></extra>"


def _fabricated_hovertext(seg: Segment, coalesces: list) -> str:
    """Provenance for one fabricated piece: which coalesce it came from and that
    its per-piece timing was reconstructed (all pieces share the parent's stamp)."""
    for c in coalesces:
        if (
            c["time"] == seg.time
            and c["parent_seq_start"] <= seg.seq_start
            and seg.seq_end <= c["parent_seq_end"]
        ):
            mss = c.get("mss") or 1
            i = (seg.seq_start - c["parent_seq_start"]) // mss + 1
            kb = (c["parent_seq_end"] - c["parent_seq_start"]) / 1024.0
            # Tier-2 (modal-inferred) MSS is a guess, not the negotiated value, so
            # the piece boundaries are approximate — flag the lower confidence.
            confidence = (
                "<br>MSS inferred (no SYN) — piece boundaries approximate"
                if c.get("mss_source") == "inferred"
                else ""
            )
            return (
                f"<b>reconstructed piece {i}/{c['pieces']}</b><br>"
                f"from a {kb:.1f} KB de-coalesced offload segment<br>"
                f"timing inferred — all pieces share the captured timestamp"
                f"{confidence}"
            )
    return "<b>reconstructed segment</b><br>timing inferred (de-coalesced offload)"


def _fabricated_segment_trace(
    model: TsgModel,
    *,
    name: str,
    color: str,
    xaxis_ref: str = "x",
    yaxis_ref: str = "y",
    baseline: int = 0,
    showlegend: bool = True,
    legendgroup: str | None = None,
) -> dict[str, Any] | None:
    """One scattergl trace for fabricated (de-coalesced) data pieces, drawn
    dotted + muted so it's unmistakable their per-piece timing was reconstructed
    rather than observed. Hover is delegated to a paired marker trace built by
    `_fabricated_hover_trace` — sharing an x across N pieces, scattergl-line
    hovermode=x would always pick the first piece's vertex (`1/N` for every
    hover) instead of selecting by cursor-y."""
    segs = [s for s in model.segments if s.fabricated and s.seq_end - s.seq_start > 1]
    if not segs:
        return None
    xs: list[Any] = []
    ys: list[float | None] = []
    for s in segs:
        t_iso = _epoch_to_iso(s.time)
        xs.extend([t_iso, t_iso, None])
        ys.extend([s.seq_start - baseline, s.seq_end - baseline, None])
    return {
        "type": "scattergl",
        "mode": "lines",
        "x": xs,
        "y": ys,
        "line": {"color": color, "width": 1, "dash": "dot"},
        "hoverinfo": "skip",
        "name": name,
        "legendgroup": legendgroup or name,
        "showlegend": showlegend,
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


def _fabricated_hover_trace(
    model: TsgModel,
    *,
    color: str,
    xaxis_ref: str = "x",
    yaxis_ref: str = "y",
    baseline: int = 0,
) -> dict[str, Any] | None:
    """One invisible marker per de-coalesced parent (NOT per piece), placed at
    the parent's seq-midpoint. Hover shows the whole coalesce — its byte span
    and piece count — because hovermode=x picks a single point per trace at the
    cursor's xval and N coincident piece markers would always resolve to the
    same one (the user-reported `always 1/N` bug). One marker per parent makes
    the popup informative regardless of which slot the cursor lands on."""
    if not model.coalesces:
        return None
    fab_segs = [s for s in model.segments if s.fabricated and s.seq_end - s.seq_start > 1]
    if not fab_segs:
        return None
    # Group fabricated segments by their parent coalesce (matched on identical
    # timestamp + containment, the same key _tag_fabricated uses). MSS-inferred
    # coalesces are flagged with lower confidence in the hover.
    by_parent: dict[tuple[float, int, int], list[Segment]] = {}
    parent_meta: dict[tuple[float, int, int], dict] = {}
    for c in model.coalesces:
        key = (c["time"], c["parent_seq_start"], c["parent_seq_end"])
        parent_meta[key] = c
        by_parent.setdefault(key, [])
    for s in fab_segs:
        for key in by_parent:
            t, lo, hi = key
            if s.time == t and lo <= s.seq_start and s.seq_end <= hi:
                by_parent[key].append(s)
                break
    xs: list[Any] = []
    ys: list[float] = []
    ht: list[str] = []
    for key, segs in by_parent.items():
        if not segs:
            continue
        c = parent_meta[key]
        lo, hi = c["parent_seq_start"], c["parent_seq_end"]
        kb = (hi - lo) / 1024.0
        confidence = (
            "<br>MSS inferred (no SYN) — piece boundaries approximate"
            if c.get("mss_source") == "inferred"
            else ""
        )
        xs.append(_epoch_to_iso(c["time"]))
        ys.append(((lo + hi) / 2) - baseline)
        ht.append(
            f"<b>de-coalesced offload segment</b><br>"
            f"{kb:.1f} KB · {c['pieces']} pieces (MSS {c.get('mss', 0):,})<br>"
            f"timing inferred — all pieces share the captured timestamp"
            f"{confidence}"
        )
    if not xs:
        return None
    return {
        "type": "scattergl",
        "mode": "markers",
        "x": xs,
        "y": ys,
        "marker": {"size": 1, "color": "rgba(0,0,0,0)", "opacity": 0},
        "hovertext": ht,
        "hovertemplate": _TSG_FAB_TEMPLATE,
        "hoverlabel": {"bordercolor": color},
        "name": "reconstructed",
        "legendgroup": "reconstructed",
        "showlegend": False,
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


_RTX_CODE = {None: 0.0, "rto": 1.0, "fast": 2.0, "spurious": 3.0}


def _retx_customdata(segments: list[Segment], baseline: int = 0) -> list[list[float]]:
    """Index layout:
    0: seq_start  (relative to baseline when baseline != 0)
    1: length
    2: in_flight_after
    3: rtx_code (1=rto, 2=fast, 3=spurious)
    """
    out: list[list[float]] = []
    for s in segments:
        out.append(
            [
                float(s.seq_start - baseline),
                float(s.seq_end - s.seq_start),
                float(s.in_flight_after),
                _RTX_CODE.get(s.rtx, 0.0),
            ]
        )
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
    baseline: int = 0,
    showlegend: bool = True,
    legendgroup: str | None = None,
) -> dict[str, Any] | None:
    segs = [s for s in model.segments if s.rtx is not None]
    if not segs:
        return None
    xs: list[Any] = []
    ys: list[float | None] = []
    cd: list[list[float]] = []
    for s, row in zip(segs, _retx_customdata(segs, baseline=baseline), strict=True):
        t_iso = _epoch_to_iso(s.time)
        xs.extend([t_iso, t_iso, None])
        ys.extend([s.seq_start - baseline, s.seq_end - baseline, None])
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
        "legendgroup": legendgroup or name,
        "showlegend": showlegend,
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


def _ack_customdata(
    acks: list[Ack], window_scale: int | None, baseline: int = 0
) -> list[list[float | str]]:
    """Index layout:
    0: ack_seq  (relative to baseline when baseline != 0)
    1: rwin (scaled if known, else raw) — a length, never baselined
    2: window_scale shift as a string ("7" when known, "?" when unobserved).
       Pre-stringified because plotly hovertemplates can't branch between
       numeric and literal formats from a single field.
    3: dup-ACK hover fragment — "" for a non-dup ACK, "<br>dup-ACK #N" otherwise.
       Prebuilt because plotly hovertemplates can't branch; a literal
       "dup-ACK #%{customdata[3]}" would render "#0" on every healthy ACK.
    """
    scale_str = str(window_scale) if window_scale is not None else "?"
    out: list[list[float | str]] = []
    for a in acks:
        rwin = float(a.rwin_scaled if a.rwin_scaled is not None else a.rwin)
        dup = f"<br>dup-ACK #{a.dup_count}" if a.dup_count else ""
        out.append([float(a.ack_seq - baseline), rwin, scale_str, dup])
    return out


# rwnd lives on the yellow rwin line and is redundant on ACKs (TODO.md item 2).
_TSG_ACK_TEMPLATE = "<b>ACK for seq %{customdata[0]:,.0f}</b>%{customdata[3]}<extra></extra>"


_TSG_RWIN_TEMPLATE = "<b>rwnd %{customdata[1]:,.0f}</b><br>(scale: %{customdata[2]})<extra></extra>"


def _ack_trace(
    model: TsgModel,
    *,
    name: str,
    xaxis_ref: str = "x",
    yaxis_ref: str = "y",
    baseline: int = 0,
    showlegend: bool = True,
    legendgroup: str | None = None,
) -> dict[str, Any] | None:
    if not model.acks:
        return None
    xs: list[Any] = []
    ys: list[float | None] = []
    cd: list[list[float | str]] = []
    prev_seq: int | None = None
    prev_time: float | None = None
    rows = _ack_customdata(model.acks, model.window_scale, baseline=baseline)
    for a, row in zip(model.acks, rows, strict=True):
        ack_seq_disp = a.ack_seq - baseline
        if prev_seq is not None and prev_time is not None:
            xs.extend([_epoch_to_iso(prev_time), _epoch_to_iso(a.time), None])
            ys.extend([prev_seq, prev_seq, None])
            cd.extend([row, row, row])
        xs.extend([_epoch_to_iso(a.time), _epoch_to_iso(a.time), None])
        ys.extend([prev_seq if prev_seq is not None else ack_seq_disp, ack_seq_disp, None])
        cd.extend([row, row, row])
        prev_seq = ack_seq_disp
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
        "legendgroup": legendgroup or name,
        "showlegend": showlegend,
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


def _rwin_trace(
    model: TsgModel,
    *,
    name: str,
    xaxis_ref: str = "x",
    yaxis_ref: str = "y",
    baseline: int = 0,
    showlegend: bool = True,
    legendgroup: str | None = None,
    y_max: float | None = None,
) -> dict[str, Any] | None:
    if not model.acks:
        return None
    xs: list[Any] = []
    ys: list[float | None] = []
    cd: list[list[float | str]] = []
    prev_top: int | None = None
    prev_time: float | None = None
    rows = _ack_customdata(model.acks, model.window_scale, baseline=baseline)
    # Clamp the drawn rwin top to the subplot's y_max so a window that dwarfs
    # the data band can't overflow into the adjacent subplot (scattergl's WebGL
    # rendering doesn't honor the subplot clipPath that SVG mode would). Hover
    # still reports the true rwnd via customdata[1].
    for a, row in zip(model.acks, rows, strict=True):
        rwin = a.rwin_scaled if a.rwin_scaled is not None else a.rwin
        top = a.ack_seq + rwin - baseline
        if y_max is not None and top > y_max:
            top = y_max
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
        "legendgroup": legendgroup or name,
        "showlegend": showlegend,
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
    "dsack": "D-SACK",
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
# These are findings-layer confirmations (RTO/fast/spurious/zero_win, …), not
# per-event ticks — so `severe` maps to PALETTE.crit (red) rather than bad.
_SEVERITY_COLOR = {
    "severe": PALETTE.crit,  # red — alarms (rto, fast, spurious, zero_win, …)
    "warn": PALETTE.notable,  # amber — symptoms worth attention
    "handshake": PALETTE.accent,  # cyan — protocol markers (SYN/SA/A/FA/R FA)
    "info": PALETTE.text_dim,  # grey — diagnostic noise; hidden unless toggled
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

# Anomaly kinds whose one_liner text embeds absolute sequence numbers (and
# only sequence numbers — no byte counts, durations, or other comma-formatted
# values). In rel-seq mode every comma-formatted integer in the one_liner is
# subtracted by the baseline so the popup matches the on-chart axis. Kinds
# whose one_liners contain non-seq comma-formatted numbers (win_shrink's
# shrink_bytes, coalesced's size/mss) are deliberately omitted — rewriting
# those would corrupt the message.
_KINDS_WITH_EMBEDDED_SEQS = {
    "rto",
    "fast",
    "spurious",
    "ooo",
    "sack_gap",
    "keepalive",
    "dup_ack",
    "dup_ack_drove_retx",
    "partial_ack",
}

# Comma-formatted integer: a 1-3 digit group followed by one or more `,DDD`
# groups. Real TCP seqs are random 32-bit values so formatted via `{n:,}`
# they always carry at least one comma; small test-fixture seqs (e.g. 1000
# → "1,000") match the same pattern.
_COMMA_INT_RE = re.compile(r"\b\d{1,3}(?:,\d{3})+\b")


def _rebase_embedded_seqs(text: str, baseline: int) -> str:
    """Subtract `baseline` from every comma-formatted integer in `text` and
    re-format with commas. Used to retrofit baseline-awareness onto anomaly
    one_liners that were authored with absolute seqs.
    """

    def _sub(m: re.Match[str]) -> str:
        return f"{int(m.group(0).replace(',', '')) - baseline:,}"

    return _COMMA_INT_RE.sub(_sub, text)


def _anomaly_hovertext(a: Anomaly, model: TsgModel, baseline: int = 0) -> str:
    """Render the hover text for one anomaly as multi-line HTML.

    Handshake/teardown markers (SYN/SA/FA/R FA) get enriched with the seq +
    ACK-RTT from their backing segment, since we strip those 1-byte segs
    from the data trace to keep the chart anchor unambiguous.

    For other kinds whose one_liner embeds absolute seqs (rto/fast/spurious,
    ooo, sack_gap, keepalive, dup_ack[_drove_retx], partial_ack), rebase
    those seqs to the baseline so the popup matches the on-chart axis when
    seq_mode="rel". Kinds whose one_liner carries no seqs (or only non-seq
    numbers like byte counts) pass through unchanged.

    When the anomaly coincides with a fabricated (de-coalesced) segment, the
    popup notes that the timing was reconstructed.
    """
    caveat = (
        "<br>timing reconstructed"
        if any(s.fabricated and s.time == a.time for s in model.segments)
        else ""
    )
    if a.kind in _SEG_BACKED_KINDS:
        for s in model.segments:
            if s.time != a.time:
                continue
            parts = [a.one_liner, f"seq {s.seq_start - baseline:,}"]
            if s.paired_rtt_ms is not None:
                parts.append(f"ACKed {s.paired_rtt_ms:.1f} ms later")
            return "<br>".join(parts) + caveat
    text = a.one_liner
    if baseline and a.kind in _KINDS_WITH_EMBEDDED_SEQS:
        text = _rebase_embedded_seqs(text, baseline)
    return text.replace(" · ", "<br>") + caveat


def _anomaly_annotations(
    model: TsgModel,
    *,
    xref: str = "x",
    yref: str = "y",
    show_info: bool = False,
    baseline: int = 0,
) -> list[dict[str, Any]]:
    """Visible glyph annotations only. Hover popovers ride on the paired
    invisible marker trace built by `_anomaly_hover_trace`, because Plotly
    annotations don't respond to programmatic `Plotly.Fx.hover` — and the
    shared-cursor crossbar (see view/hover_crossbar.py) fires hover via that
    API on every panel. Direct mouseover the glyph still pops the tooltip
    because the crossbar's mousemove listener is active across the plot."""
    visible = [
        a for a in model.anomalies if show_info or SEVERITY_BY_KIND.get(a.kind, "info") != "info"
    ]
    clusters = _cluster_anomalies(visible)
    anns: list[dict[str, Any]] = []
    for a, count in clusters:
        text = _ANOMALY_GLYPH.get(a.kind, a.kind)
        if count > 1:
            text = f"{text} ×{count}"
        y = (a.seq_lo - baseline) if a.seq_lo is not None else 0
        yshift = _KIND_YSHIFT.get(a.kind, _DEFAULT_YSHIFT)
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
                "font": {"color": color, "size": 10, "family": PLOTLY_MONO_FAMILY},
                "yshift": yshift,
            }
        )
    return anns


def _anomaly_hover_trace(
    model: TsgModel,
    *,
    xaxis_ref: str = "x",
    yaxis_ref: str = "y",
    show_info: bool = False,
    baseline: int = 0,
) -> dict[str, Any] | None:
    """Invisible markers co-located with each anomaly cluster, carrying the
    hover popover. Drives both direct-mouseover hover AND the shared-cursor
    `Plotly.Fx.hover` xval call (annotations alone don't fire the latter, so
    SYN/SA/A/FA/R FA tooltips otherwise stay dark when the cursor isn't on the
    glyph itself)."""
    visible = [
        a for a in model.anomalies if show_info or SEVERITY_BY_KIND.get(a.kind, "info") != "info"
    ]
    clusters = _cluster_anomalies(visible)
    if not clusters:
        return None
    xs: list[Any] = []
    ys: list[float] = []
    htexts: list[str] = []
    border: list[str] = []
    for a, _count in clusters:
        y = (a.seq_lo - baseline) if a.seq_lo is not None else 0
        severity = SEVERITY_BY_KIND.get(a.kind, "info")
        xs.append(_epoch_to_iso(a.time))
        ys.append(y)
        htexts.append(_anomaly_hovertext(a, model, baseline=baseline))
        border.append(_SEVERITY_COLOR[severity])
    # bgcolor intentionally omitted — falls back to layout.hoverlabel.bgcolor
    # (HOVER_BG, the solid dark chrome). Earlier we tinted per-severity at
    # alpha 0.13, which composited over the transparent paper as a washed-out
    # light box on light displays. Border alone keeps the severity hint.
    return {
        "type": "scattergl",
        "mode": "markers",
        "x": xs,
        "y": ys,
        "marker": {"size": 1, "color": "rgba(0,0,0,0)", "opacity": 0},
        "hovertext": htexts,
        "hovertemplate": "%{hovertext}<extra></extra>",
        "hoverlabel": {"bordercolor": border},
        "name": "anomalies",
        "showlegend": False,
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


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
    # Anchor to the right edge of the subplot so the strip does not collide
    # with the direction label that sits at the top-left of every subplot.
    return {
        "x": 1.0,
        "y": y_domain_top,
        "xref": f"{xref} domain",
        "yref": "paper",
        "text": "info: " + " · ".join(parts),
        "showarrow": False,
        "font": {"color": _SEVERITY_COLOR["info"], "size": 10, "family": PLOTLY_MONO_FAMILY},
        "xanchor": "right",
        "yanchor": "bottom",
        "yshift": 2,
    }


def _in_flight_overlay(
    model: TsgModel,
    *,
    name: str,
    xaxis_ref: str = "x",
    yaxis_ref: str = "y",
    baseline: int = 0,
    showlegend: bool = True,
    legendgroup: str | None = None,
) -> dict[str, Any] | None:
    """In-flight band: the bytes outstanding (sent but not yet acked).

    Drawn as a self-closed polygon between the cumulative-ACK staircase (bottom
    edge, y = cumack) and cumack + in_flight (top edge). `fill: toself` keeps the
    shaded region correct regardless of trace order and even when the direction
    has no ACKs — the old `fill: tonexty` anchored against whatever trace
    happened to precede it (rwin in practice; nothing when ACKs were absent).
    """
    if not model.in_flight:
        return None
    ack_times = [a.time for a in model.acks]
    ack_seqs = [a.ack_seq for a in model.acks]
    if model.segments:
        # Before the first observed ACK nothing is acked yet, so the band's
        # floor is the ISN — the earliest sequence sent — not the first ACK's
        # cumack, which has already advanced past the initial burst. Matches the
        # baseline _compute_in_flight seeds from (earliest seq_start).
        pre_first_baseline = min(s.seq_start for s in model.segments)
    elif ack_seqs:
        pre_first_baseline = ack_seqs[0]
    else:
        pre_first_baseline = 0

    def _cumack_at(t: float) -> int:
        if not ack_times:
            return pre_first_baseline
        i = bisect.bisect_right(ack_times, t)
        return ack_seqs[i - 1] if i > 0 else pre_first_baseline

    times = [t for t, _ in model.in_flight]
    cumack = [_cumack_at(t) - baseline for t in times]
    top = [_cumack_at(t) + ifl - baseline for t, ifl in model.in_flight]
    # Closed ribbon: top edge left->right, then the cumack floor right->left.
    iso = [_epoch_to_iso(t) for t in times]
    xs = iso + iso[::-1]
    ys = top + cumack[::-1]
    # SVG (`scatter`), not WebGL (`scattergl`): plotly's scattergl path
    # tessellates `fill: toself` polygons recursively and blows the JS stack
    # once the vertex count grows past a few thousand (cleanPlot then errors
    # on `sizeBuffer`, which kills the socket.io session). De-coalesced LRO
    # captures routinely produce 10K+ in-flight vertices, well past that
    # threshold. SVG handles the same count without complaint at a slower
    # first paint — acceptable for an overlay the user can't interact with
    # (hoverinfo is skipped). The sibling `data` trace stays on scattergl
    # since it's lines, not a closed fill.
    return {
        "type": "scatter",
        "mode": "lines",
        "x": xs,
        "y": ys,
        "fill": "toself",
        "fillcolor": rgba(PALETTE.accent, 0.10),
        "line": {"color": rgba(PALETTE.accent, 0.0), "width": 0},
        "name": name,
        "legendgroup": legendgroup or name,
        "showlegend": showlegend,
        "hoverinfo": "skip",
        "xaxis": xaxis_ref,
        "yaxis": yaxis_ref,
    }


def _build_direction_traces(
    model: TsgModel,
    *,
    xaxis_ref: str,
    yaxis_ref: str,
    baseline: int = 0,
    legend_seen: set[str] | None = None,
    y_max: float | None = None,
    show_info: bool = False,
) -> list[dict[str, Any]]:
    """Assemble all per-direction traces bound to the given subplot axes.

    Order matters: Plotly draws lower-index traces first, so later traces sit
    on top. We want data sticks visible above the ack staircase (they share
    the same y-range), and retx visible above data. The in-flight band is a
    self-closed polygon (`fill: toself`), so its position here only affects
    layering, not which traces it fills between.

    Names are unprefixed ("data"/"ack"/...) and `legend_seen` dedupes across
    directions: the second direction's traces use `showlegend=False` while
    sharing the same `legendgroup`, so toggling one entry collapses both
    panels' lines for that role.
    """
    if legend_seen is None:
        legend_seen = set()
    out: list[dict[str, Any]] = []

    def _commit(role: str, tr: dict[str, Any] | None) -> None:
        # Claim the shared legend slot only when a trace is actually emitted, so
        # a direction that draws nothing for a role (e.g. the forward panel with
        # no ACKs) doesn't suppress the other direction's legend entry for it.
        # Builders are called with showlegend=False; we flip it on the first
        # direction that emits the role.
        if tr is None:
            return
        if role not in legend_seen:
            tr["showlegend"] = True
            legend_seen.add(role)
        out.append(tr)

    # Order matters for layering (later traces draw on top): ack staircase,
    # rwin, in-flight band, data sticks, then retx on top.
    _commit(
        "ack",
        _ack_trace(
            model,
            name="ack",
            xaxis_ref=xaxis_ref,
            yaxis_ref=yaxis_ref,
            baseline=baseline,
            showlegend=False,
            legendgroup="ack",
        ),
    )
    _commit(
        "rwin",
        _rwin_trace(
            model,
            name="rwin",
            xaxis_ref=xaxis_ref,
            yaxis_ref=yaxis_ref,
            baseline=baseline,
            showlegend=False,
            legendgroup="rwin",
            y_max=y_max,
        ),
    )
    _commit(
        "in-flight",
        _in_flight_overlay(
            model,
            name="in-flight",
            xaxis_ref=xaxis_ref,
            yaxis_ref=yaxis_ref,
            baseline=baseline,
            showlegend=False,
            legendgroup="in-flight",
        ),
    )
    _commit(
        "data",
        _data_segment_trace(
            model,
            name="data",
            color=COLOR_MAP["white"],
            xaxis_ref=xaxis_ref,
            yaxis_ref=yaxis_ref,
            baseline=baseline,
            showlegend=False,
            legendgroup="data",
        ),
    )
    # text_muted: fabricated piece — dotted line style carries the "synthetic"
    # semantic; color just stays out of the way of real data traces.
    _commit(
        "reconstructed",
        _fabricated_segment_trace(
            model,
            name="reconstructed",
            color=PALETTE.text_muted,
            xaxis_ref=xaxis_ref,
            yaxis_ref=yaxis_ref,
            baseline=baseline,
            showlegend=False,
            legendgroup="reconstructed",
        ),
    )
    fab_hover = _fabricated_hover_trace(
        model,
        color=PALETTE.text_muted,
        xaxis_ref=xaxis_ref,
        yaxis_ref=yaxis_ref,
        baseline=baseline,
    )
    if fab_hover is not None:
        out.append(fab_hover)
    _commit(
        "retx",
        _retx_segment_trace(
            model,
            name="retx",
            xaxis_ref=xaxis_ref,
            yaxis_ref=yaxis_ref,
            baseline=baseline,
            showlegend=False,
            legendgroup="retx",
        ),
    )
    hover = _anomaly_hover_trace(
        model,
        xaxis_ref=xaxis_ref,
        yaxis_ref=yaxis_ref,
        show_info=show_info,
        baseline=baseline,
    )
    if hover is not None:
        out.append(hover)
    return out


def _tsg_xaxis(*, show_ticks: bool) -> dict[str, Any]:
    # Hover crossbar isn't a Plotly spike — Plotly's spike stops at its own
    # subplot boundary, which leaves the bwd panel empty when hovering fwd
    # (and vice versa). A client-side script (see view/hover_crossbar.py)
    # draws a full-figure layout shape on plotly_hover instead, spanning
    # both panels. hovermode=x at the layout level is what arms plotly_hover.
    return {
        "title": {"text": "time" if show_ticks else ""},
        "type": "date",
        "tickformat": "%H:%M:%S.%L",
        "hoverformat": "%Y-%m-%d %H:%M:%S.%6f",
        "gridcolor": GRID_COLOR,
        "zerolinecolor": ZERO_LINE_COLOR,
        "showticklabels": show_ticks,
    }


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


def _reversed_direction_label(other: TsgModel | None) -> str:
    """Direction label for the *missing* side, derived by reversing the
    populated side's endpoints. tcptrace emits an xpl per observed
    direction; for a unidirectional capture the absent direction has no
    model of its own, so we pivot off whoever's there."""
    if other is None or not other.src or not other.dst:
        return ""
    return f"{other.dst} → {other.src}"


def _is_tsg_model_empty(model: TsgModel | None) -> bool:
    """`True` when the pane will render nothing: either the model never
    materialised (no xpl for that direction) or it materialised with no
    segments, no acks, AND no anomalies. An anomaly-only model is still
    visually populated — the glyphs and hover targets need their pane."""
    return model is None or (not model.segments and not model.acks and not model.anomalies)


def _baseline_seq(model: TsgModel | None, seq_mode: str) -> int:
    """Per-direction baseline for relative-seq display.

    Use the minimum seq seen in either segments or acks — acks reference
    this direction's own sent seqs, so they share the segment space.
    Returns 0 for absolute mode or when the model is empty.
    """
    if model is None or seq_mode != "rel":
        return 0
    lo = None
    for s in model.segments:
        lo = s.seq_start if lo is None or s.seq_start < lo else lo
    for a in model.acks:
        lo = a.ack_seq if lo is None or a.ack_seq < lo else lo
    return lo if lo is not None else 0


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


def to_tsg_figure(
    pair: TsgModelPair,
    *,
    show_info: bool = False,
    seq_mode: str = "abs",
) -> dict[str, Any]:
    """Build a Plotly figure for the TSG metric from a TsgModelPair.

    Each direction lives in its own TCP sequence space (independent ISNs), so
    plotting both on a shared y-axis crams them into different bands with
    empty space between. When both directions are populated we stack them as
    subplots (forward top, backward bottom) with a matched x-axis; each
    subplot's y-axis auto-scales to its own data. When only one direction is
    populated we fall back to a single subplot.

    `seq_mode="rel"` subtracts a per-direction baseline (min seq in segments
    or acks) so the y-axis reads 0..bytes_sent instead of raw uint32s.
    """
    fwd = pair.fwd
    bwd = pair.bwd

    # No figure title: the per-panel direction labels (top-left of each
    # subplot, set below) already convey direction. A top-of-figure title
    # was just duplicated text occupying the room the legend bar needs.
    layout = _base_layout("", dragmode="zoom", showlegend=True)
    layout["margin"]["t"] = 40
    layout["hovermode"] = "x"  # arms the full-height x-axis spike crossbar
    layout["legend"] = {
        "orientation": "h",
        "xanchor": "right",
        "x": 1.0,
        "yanchor": "bottom",
        "y": 1.02,
        "bgcolor": "rgba(0,0,0,0)",
        "font": {"size": 11, "family": PLOTLY_MONO_FAMILY, "color": HOVER_TEXT},
    }

    fwd_base = _baseline_seq(fwd, seq_mode)
    bwd_base = _baseline_seq(bwd, seq_mode)

    if fwd is None and bwd is None:
        # No xpl on either side — degenerate; keep a single-axis empty figure
        # for callers that special-case this (analyses with no synthesised
        # TSG at all). Anything with a model on either direction goes through
        # the dual-subplot path below.
        layout["xaxis"] = _tsg_xaxis(show_ticks=True)
        layout["yaxis"] = _tsg_yaxis()
        layout["annotations"] = []
        return {"data": [], "layout": layout}

    fwd_empty = _is_tsg_model_empty(fwd)
    bwd_empty = _is_tsg_model_empty(bwd)

    # Dual-subplot layout. When one direction carries no data, that pane is
    # compressed (`_subplot_domains`) into a thin strip with a no-traffic
    # annotation; the populated direction expands. Symmetric 45/45 split is
    # the both-populated case.
    fwd_domain, bwd_domain = _subplot_domains(fwd_empty, bwd_empty)

    fwd_xaxis = _tsg_xaxis(show_ticks=False)
    fwd_xaxis["anchor"] = "y"
    fwd_yaxis = _tsg_yaxis()
    fwd_yaxis["domain"] = list(fwd_domain)
    fwd_yaxis["anchor"] = "x"
    fwd_y_max: float | None = None
    if not fwd_empty:
        fwd_range = _capped_yaxis_range(fwd)
        if fwd_range is not None:
            fwd_yaxis["range"] = [fwd_range[0] - fwd_base, fwd_range[1] - fwd_base]
            fwd_yaxis["autorange"] = False
            fwd_y_max = fwd_range[1] - fwd_base
    else:
        fwd_yaxis["range"] = [0, 1]
        fwd_yaxis["autorange"] = False
        fwd_yaxis["showticklabels"] = False

    bwd_xaxis = _tsg_xaxis(show_ticks=True)
    bwd_xaxis["matches"] = "x"
    bwd_xaxis["anchor"] = "y2"
    bwd_xaxis["side"] = "bottom"
    bwd_yaxis = _tsg_yaxis()
    bwd_yaxis["domain"] = list(bwd_domain)
    bwd_yaxis["anchor"] = "x2"
    bwd_y_max: float | None = None
    if not bwd_empty:
        bwd_range = _capped_yaxis_range(bwd)
        if bwd_range is not None:
            bwd_yaxis["range"] = [bwd_range[0] - bwd_base, bwd_range[1] - bwd_base]
            bwd_yaxis["autorange"] = False
            bwd_y_max = bwd_range[1] - bwd_base
    else:
        bwd_yaxis["range"] = [0, 1]
        bwd_yaxis["autorange"] = False
        bwd_yaxis["showticklabels"] = False

    layout["xaxis"] = fwd_xaxis
    layout["yaxis"] = fwd_yaxis
    layout["xaxis2"] = bwd_xaxis
    layout["yaxis2"] = bwd_yaxis

    legend_seen: set[str] = set()
    traces: list[dict[str, Any]] = []
    if not fwd_empty:
        traces.extend(
            _build_direction_traces(
                fwd,
                xaxis_ref="x",
                yaxis_ref="y",
                baseline=fwd_base,
                legend_seen=legend_seen,
                y_max=fwd_y_max,
                show_info=show_info,
            )
        )
    if not bwd_empty:
        traces.extend(
            _build_direction_traces(
                bwd,
                xaxis_ref="x2",
                yaxis_ref="y2",
                baseline=bwd_base,
                legend_seen=legend_seen,
                y_max=bwd_y_max,
                show_info=show_info,
            )
        )

    annotations: list[dict[str, Any]] = []
    if not fwd_empty:
        annotations.extend(
            _anomaly_annotations(fwd, xref="x", yref="y", show_info=show_info, baseline=fwd_base)
        )
        strip = _info_strip(fwd, xref="x", y_domain_top=fwd_domain[1])
        if strip is not None:
            annotations.append(strip)
    if not bwd_empty:
        annotations.extend(
            _anomaly_annotations(bwd, xref="x2", yref="y2", show_info=show_info, baseline=bwd_base)
        )
        strip = _info_strip(bwd, xref="x2", y_domain_top=bwd_domain[1])
        if strip is not None:
            annotations.append(strip)

    # Direction labels (top-left of each pane). When a side has a model we use
    # its src/dst even if no traffic landed on the pane. When the model itself
    # is absent (no xpl for that direction) we reverse the other side's
    # endpoints — tcptrace gives us nothing else to read it from.
    fwd_label = _direction_label(fwd) if fwd is not None else _reversed_direction_label(bwd)
    bwd_label = _direction_label(bwd) if bwd is not None else _reversed_direction_label(fwd)
    for text, y in (
        (fwd_label, fwd_domain[1]),
        (bwd_label, bwd_domain[1]),
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

    # "no traffic this direction" overlay anchored at the empty pane's mid-y.
    if fwd_empty:
        annotations.append(_no_traffic_annotation("x", "y"))
    if bwd_empty:
        annotations.append(_no_traffic_annotation("x2", "y2"))

    layout["annotations"] = annotations
    return {"data": traces, "layout": layout}


def _no_traffic_annotation(xref: str, yref: str) -> dict[str, Any]:
    """Centered '(no traffic this direction)' label for a compressed empty
    subplot. y=0.5 against the placeholder [0, 1] yref puts it mid-pane."""
    return {
        "text": "(no traffic this direction)",
        "xref": f"{xref} domain",
        "yref": yref,
        "x": 0.5,
        "y": 0.5,
        "xanchor": "center",
        "yanchor": "middle",
        "showarrow": False,
        "font": {
            "color": SUBPLOT_LABEL_COLOR,
            "size": 10,
            "family": PLOTLY_MONO_FAMILY,
        },
    }


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


def _rate_scale_suffix(rate_unit: str) -> tuple[float, str]:
    """Convert Bps → display value. `bits` multiplies by 8 and uses `bps`;
    `bytes` keeps Bps and uses the legacy `B/s` suffix."""
    return (8.0, "bps") if rate_unit == "bits" else (1.0, "B/s")


def _tput_yaxis(rate_unit: str = "bytes") -> dict[str, Any]:
    _, suffix = _rate_scale_suffix(rate_unit)
    return {
        "title": {"text": "throughput"},
        "tickformat": ".3s",
        "ticksuffix": suffix,
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
        text = f"stall {dur_ms:.0f}ms ({stall.rtt_multiple:.1f}×RTT)"
        t0 = _epoch_to_iso(stall.t_start)
        t1 = _epoch_to_iso(stall.t_end)
        out.append(
            {
                "type": "scatter",
                "mode": "lines",
                "x": [t0, t1, t1, t0, t0, None],
                "y": [y0, y0, y1, y1, y0, None],
                "fill": "toself",
                "fillcolor": rgba(PALETTE.magenta, alpha),
                "line": {"color": "rgba(0,0,0,0)", "width": 0},
                "text": text,
                "hoverinfo": "text",
                "name": "stall",
                "legendgroup": "stall",
                "showlegend": show,
                "xaxis": xaxis_ref,
                "yaxis": yaxis_ref,
            }
        )
    return out


def _envelope_trace(
    model: ThroughputModel,
    *,
    xaxis_ref: str,
    yaxis_ref: str,
    legend_seen: set[str],
    rate_unit: str = "bytes",
    y_max: float | None = None,
) -> dict[str, Any] | None:
    """The BDP ceiling (rwin/RTT) — drawn as a dashed line. When the ceiling
    sits well above the data, _tput_yaxis_range sizes the axis to the data
    so the data band stays visible. To keep the ceiling discoverable rather
    than silently clipping it off-screen, pass `y_max` (scaled units) and the
    line is clamped at the axis top with the un-clamped value carried in
    customdata so hover always shows the real ceiling.
    """
    scale, suffix = _rate_scale_suffix(rate_unit)
    xs: list[Any] = []
    ys: list[Any] = []
    real_ys: list[Any] = []
    for s in model.samples:
        if s.max_Bps is None:
            if xs and xs[-1] is not None:
                xs.append(None)
                ys.append(None)
                real_ys.append(None)
        else:
            real = s.max_Bps * scale
            xs.append(_epoch_to_iso(s.t))
            ys.append(min(real, y_max) if y_max is not None else real)
            real_ys.append(real)
    while xs and xs[0] is None:
        xs.pop(0)
        ys.pop(0)
        real_ys.pop(0)
    while xs and xs[-1] is None:
        xs.pop()
        ys.pop()
        real_ys.pop()
    if not xs:
        return None
    show = "ceiling" not in legend_seen
    if show:
        legend_seen.add("ceiling")
    return {
        "type": "scattergl",
        "mode": "lines",
        "x": xs,
        "y": ys,
        "customdata": real_ys,
        "line": {"color": "#888", "dash": "dot", "width": 1},
        "opacity": 0.6,
        "hovertemplate": f"ceiling %{{customdata:.3s}}{suffix} (rwin/RTT)<extra></extra>",
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
    rate_unit: str = "bytes",
) -> dict[str, Any] | None:
    if not model.samples:
        return None
    scale, suffix = _rate_scale_suffix(rate_unit)
    xs = [_epoch_to_iso(s.t) for s in model.samples]
    ys = [s.wire_Bps * scale for s in model.samples]
    show = "wire" not in legend_seen
    if show:
        legend_seen.add("wire")
    return {
        "type": "scatter",
        "mode": "lines",
        "x": xs,
        "y": ys,
        "fill": "tozeroy",
        "fillcolor": rgba(PALETTE.info, 0.25),
        "line": {"color": PALETTE.info, "width": 1},
        "hovertemplate": f"wire %{{y:.3s}}{suffix}<extra></extra>",
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
    rate_unit: str = "bytes",
) -> dict[str, Any] | None:
    if not model.samples:
        return None
    if all(s.goodput_Bps == 0.0 for s in model.samples):
        return None
    scale, suffix = _rate_scale_suffix(rate_unit)
    xs = [_epoch_to_iso(s.t) for s in model.samples]
    ys = [s.goodput_Bps * scale for s in model.samples]
    show = "goodput" not in legend_seen
    if show:
        legend_seen.add("goodput")
    return {
        "type": "scatter",
        "mode": "lines",
        "x": xs,
        "y": ys,
        "fill": "tozeroy",
        "fillcolor": rgba(PALETTE.good, 0.45),
        "line": {"color": PALETTE.good, "width": 1},
        "hovertemplate": f"goodput %{{y:.3s}}{suffix}<extra></extra>",
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
        anns.append(
            {
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
            }
        )
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
    rate_unit: str = "bytes",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Returns (traces, annotations) for one direction."""
    if not model.samples:
        dir_label = _throughput_direction_label(model)
        label = f"(no data sent {dir_label})" if dir_label else "(no data)"
        return [], [_no_data_annotation(label, y_paper=y_paper)]

    scale, _ = _rate_scale_suffix(rate_unit)
    raw_range = _tput_yaxis_range(model.samples)
    y_range = [raw_range[0] * scale, raw_range[1] * scale]
    traces: list[dict[str, Any]] = []
    anns: list[dict[str, Any]] = []

    traces.extend(
        _stall_traces(
            model,
            y_range,
            xaxis_ref=xaxis_ref,
            yaxis_ref=yaxis_ref,
            show_info=show_info,
            legend_seen=legend_seen,
        )
    )

    env = _envelope_trace(
        model,
        xaxis_ref=xaxis_ref,
        yaxis_ref=yaxis_ref,
        legend_seen=legend_seen,
        rate_unit=rate_unit,
        y_max=y_range[1],
    )
    if env is not None:
        traces.append(env)

    wire = _wire_trace(
        model,
        xaxis_ref=xaxis_ref,
        yaxis_ref=yaxis_ref,
        legend_seen=legend_seen,
        rate_unit=rate_unit,
    )
    if wire is not None:
        traces.append(wire)

    gput = _goodput_trace(
        model,
        xaxis_ref=xaxis_ref,
        yaxis_ref=yaxis_ref,
        legend_seen=legend_seen,
        rate_unit=rate_unit,
    )
    if gput is not None:
        traces.append(gput)
    elif all(s.goodput_Bps == 0.0 for s in model.samples):
        anns.append(
            {
                "text": "goodput unavailable — no ACK data",
                "xref": "paper",
                "yref": yaxis_ref,
                "x": 0.99,
                "y": y_range[1] * 0.95,
                "xanchor": "right",
                "yanchor": "top",
                "showarrow": False,
                "font": {"color": "#555", "size": 10},
            }
        )

    anns.extend(
        _cliff_annotations(
            model,
            y_range,
            xref=xaxis_ref,
            yref=yaxis_ref,
            show_info=show_info,
            legend_seen=legend_seen,
        )
    )

    return traces, anns


def to_throughput_figure(
    pair: ThroughputModelPair,
    *,
    show_info: bool = False,
    rate_unit: str = "bytes",
) -> dict[str, Any]:
    fwd = pair.fwd
    bwd = pair.bwd

    # Title omitted: per-panel labels carry the direction, see to_tsg_figure.
    layout = _base_layout("", dragmode="zoom", showlegend=True)
    layout["margin"]["t"] = 40
    layout["hovermode"] = "x"
    layout["legend"] = {
        "orientation": "h",
        "xanchor": "right",
        "x": 1.0,
        "yanchor": "bottom",
        "y": 1.02,
        "bgcolor": "rgba(0,0,0,0)",
        "font": {"size": 11, "family": PLOTLY_MONO_FAMILY, "color": HOVER_TEXT},
    }

    scale, _ = _rate_scale_suffix(rate_unit)

    def _scaled_range(samples) -> list[float]:
        r = _tput_yaxis_range(samples)
        return [r[0] * scale, r[1] * scale]

    if fwd is None and bwd is None:
        layout["xaxis"] = _tput_xaxis(show_ticks=True)
        layout["yaxis"] = _tput_yaxis(rate_unit)
        layout["annotations"] = [_no_data_annotation("no throughput data")]
        return {"data": [], "layout": layout}

    fwd_empty = fwd is None or not fwd.samples
    bwd_empty = bwd is None or not bwd.samples
    fwd_domain, bwd_domain = _subplot_domains(fwd_empty, bwd_empty)

    fwd_xaxis = _tput_xaxis(show_ticks=False)
    fwd_xaxis["anchor"] = "y"
    fwd_yax = _tput_yaxis(rate_unit)
    fwd_yax["domain"] = list(fwd_domain)
    fwd_yax["anchor"] = "x"
    if not fwd_empty:
        fwd_yax["range"] = _scaled_range(fwd.samples)
        fwd_yax["autorange"] = False
    else:
        fwd_yax["range"] = [0, 1]
        fwd_yax["autorange"] = False
        fwd_yax["showticklabels"] = False

    bwd_xaxis = _tput_xaxis(show_ticks=True)
    bwd_xaxis["matches"] = "x"
    bwd_xaxis["anchor"] = "y2"
    bwd_xaxis["side"] = "bottom"
    bwd_yax = _tput_yaxis(rate_unit)
    bwd_yax["domain"] = list(bwd_domain)
    bwd_yax["anchor"] = "x2"
    if not bwd_empty:
        bwd_yax["range"] = _scaled_range(bwd.samples)
        bwd_yax["autorange"] = False
    else:
        bwd_yax["range"] = [0, 1]
        bwd_yax["autorange"] = False
        bwd_yax["showticklabels"] = False

    layout["xaxis"] = fwd_xaxis
    layout["yaxis"] = fwd_yax
    layout["xaxis2"] = bwd_xaxis
    layout["yaxis2"] = bwd_yax

    legend_seen: set[str] = set()
    fwd_traces: list[dict[str, Any]] = []
    bwd_traces: list[dict[str, Any]] = []
    annotations: list[dict[str, Any]] = []

    if not fwd_empty:
        fwd_traces, fwd_anns = _build_tput_direction(
            fwd,
            xaxis_ref="x",
            yaxis_ref="y",
            show_info=show_info,
            legend_seen=legend_seen,
            y_paper=(fwd_domain[0] + fwd_domain[1]) / 2,
            rate_unit=rate_unit,
        )
        annotations.extend(fwd_anns)
    if not bwd_empty:
        bwd_traces, bwd_anns = _build_tput_direction(
            bwd,
            xaxis_ref="x2",
            yaxis_ref="y2",
            show_info=show_info,
            legend_seen=legend_seen,
            y_paper=(bwd_domain[0] + bwd_domain[1]) / 2,
            rate_unit=rate_unit,
        )
        annotations.extend(bwd_anns)

    fwd_label = (
        _throughput_direction_label(fwd)
        if fwd is not None
        else _throughput_reversed_direction_label(bwd)
    )
    bwd_label = (
        _throughput_direction_label(bwd)
        if bwd is not None
        else _throughput_reversed_direction_label(fwd)
    )
    for text, y in (
        (fwd_label, fwd_domain[1]),
        (bwd_label, bwd_domain[1]),
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

    if fwd_empty:
        annotations.append(_no_traffic_annotation("x", "y"))
    if bwd_empty:
        annotations.append(_no_traffic_annotation("x2", "y2"))

    layout["annotations"] = annotations
    return {"data": fwd_traces + bwd_traces, "layout": layout}


def _throughput_reversed_direction_label(other: ThroughputModel | None) -> str:
    """Reverse the populated direction's endpoints for the absent side."""
    if other is None or not other.src or not other.dst:
        return ""
    return f"{other.dst} → {other.src}"
