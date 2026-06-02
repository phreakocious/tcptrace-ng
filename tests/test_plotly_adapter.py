from tcptrace_ng.plotly_adapter import (
    _humanize_title,
    to_paired_plotly_figure,
    to_plotly_figure,
)
from tcptrace_ng.theme import LINE_DIM_COLOR
from tcptrace_ng.xpl_parser import Arrow, Box, Diamond, Dot, Line, Text, Tick, XplPlot


def test_empty_plot_returns_dark_layout():
    plot = XplPlot(title="empty", xlabel="t", ylabel="seq")
    fig = to_plotly_figure(plot)
    assert fig["layout"]["title"]["text"] == "empty"
    assert fig["layout"]["xaxis"]["title"]["text"] == "t"
    assert fig["layout"]["yaxis"]["title"]["text"] == "seq"
    assert fig["layout"]["template"] == "plotly_dark"
    assert fig["data"] == []


def test_lines_grouped_into_one_trace_per_color():
    plot = XplPlot(
        commands=[
            Line(color="green", x1=0, y1=0, x2=1, y2=1),
            Line(color="green", x1=2, y1=2, x2=3, y2=3),
            Line(color="red", x1=4, y1=4, x2=5, y2=5),
        ]
    )
    fig = to_plotly_figure(plot)
    traces_by_color = {t["legendgroup"]: t for t in fig["data"] if t.get("mode") == "lines"}
    assert "green" in traces_by_color and "red" in traces_by_color
    # Green trace has two segments, separated by None: [0,1,None,2,3,None]
    assert traces_by_color["green"]["x"] == [0.0, 1.0, None, 2.0, 3.0, None]
    assert traces_by_color["green"]["y"] == [0.0, 1.0, None, 2.0, 3.0, None]


def test_diamonds_become_markers():
    plot = XplPlot(commands=[Diamond(color="white", x=1.0, y=10.0)])
    fig = to_plotly_figure(plot)
    markers = [t for t in fig["data"] if t.get("mode") == "markers"]
    assert len(markers) == 1
    assert markers[0]["marker"]["symbol"] == "diamond"


def test_text_becomes_hover_marker_not_inline_annotation():
    """Per user feedback: inline labels stack on top of each other in dense
    regions. Render them as hover-text on small scatter markers instead —
    visual density stays, overlap goes away.
    """
    plot = XplPlot(
        commands=[
            Text(color="green", x=1.0, y=2.0, label="ACK"),
            Text(color="yellow", x=1.05, y=2.0, label="rwin"),
        ]
    )
    fig = to_plotly_figure(plot)
    # No inline annotations — those were the source of overlap.
    assert fig["layout"].get("annotations", []) == []
    # Labels live in scatter traces with hovertext (one trace per color).
    label_traces = [
        t for t in fig["data"] if t.get("hovertext") and "ACK" in t["hovertext"] or
        t.get("hovertext") and "rwin" in t["hovertext"]
    ]
    assert label_traces, "expected hover-marker traces for labels"
    all_hover_text: list[str] = []
    for t in fig["data"]:
        ht = t.get("hovertext") or []
        if isinstance(ht, list):
            all_hover_text.extend(ht)
    assert "ACK" in all_hover_text
    assert "rwin" in all_hover_text


def test_text_hover_markers_grouped_by_color_and_label():
    """Each (color, label) pair gets its own trace so the legend reads one
    entry per semantic name (e.g. red owin, yellow rwin). Multiple points
    sharing one (color, label) still collapse into a single trace."""
    plot = XplPlot(
        commands=[
            Text(color="green", x=1.0, y=2.0, label="A"),
            Text(color="green", x=3.0, y=4.0, label="A"),
            Text(color="green", x=5.0, y=6.0, label="B"),
            Text(color="yellow", x=7.0, y=8.0, label="C"),
        ]
    )
    fig = to_plotly_figure(plot)
    label_traces = [t for t in fig["data"] if t.get("hovertext")]
    by_name = {t["name"]: t for t in label_traces}
    assert set(by_name) == {"A", "B", "C"}
    # Two "A" points (same color, same label) share one trace.
    assert by_name["A"]["x"] == [1.0, 3.0]
    assert by_name["A"]["hovertext"] == ["A", "A"]
    assert by_name["B"]["x"] == [5.0]
    assert by_name["C"]["x"] == [7.0]


def test_text_legend_entries_use_label_as_name():
    """Legend rendering: each Text label becomes its own legend entry. Lines
    and boxes stay hidden from the legend (no semantic name attached to them).
    Markers whose color overlaps with a Text label inherit that label's entry."""
    plot = XplPlot(
        commands=[
            Line(color="green", x1=0, y1=0, x2=1, y2=1),
            Dot(color="red", x=1.0, y=2.0),  # color matches Text → no extra legend
            Text(color="red", x=1.0, y=2.0, label="owin"),
            Text(color="yellow", x=1.0, y=3.0, label="rwin"),
        ]
    )
    fig = to_plotly_figure(plot)
    assert fig["layout"]["showlegend"] is True
    legend_names = [t["name"] for t in fig["data"] if t.get("showlegend")]
    assert sorted(legend_names) == ["owin", "rwin"]
    # Line traces are present but not in the legend.
    non_legend = [t for t in fig["data"] if not t.get("showlegend")]
    assert non_legend, "expected non-legend traces to remain (with showlegend=False)"


def test_boxes_become_filled_polygons():
    plot = XplPlot(commands=[Box(color="blue", x1=0, y1=0, x2=2, y2=3)])
    fig = to_plotly_figure(plot)
    polys = [t for t in fig["data"] if t.get("fill") == "toself"]
    assert len(polys) == 1
    # Closed polygon: 5 points (closing back to start) then None
    assert polys[0]["x"] == [0.0, 2.0, 2.0, 0.0, 0.0, None]
    assert polys[0]["y"] == [0.0, 0.0, 3.0, 3.0, 0.0, None]


def test_ticks_become_markers_with_directional_symbol():
    plot = XplPlot(commands=[Tick(color="green", x=1.0, y=100.0, kind="u")])
    fig = to_plotly_figure(plot)
    markers = [t for t in fig["data"] if t.get("mode") == "markers"]
    assert len(markers) == 1
    assert markers[0]["marker"]["symbol"] == "triangle-up"


def test_legend_hidden_when_no_text_labels():
    """Without `ltext` commands, no semantic names exist — the legend stays
    hidden so auto-generated (color, kind) noise doesn't leak through."""
    plot = XplPlot(commands=[Line(color="green", x1=0, y1=0, x2=1, y2=1)])
    fig = to_plotly_figure(plot)
    assert fig["layout"]["showlegend"] is False


def test_paired_figure_legend_dedupes_across_directions():
    """`ltext owin` on both sides yields one legend entry, not two. Same
    legendgroup means clicking the legend toggles both forward and backward
    in lockstep."""
    fwd = XplPlot(commands=[Text(color="red", x=0, y=1, label="owin")])
    bwd = XplPlot(commands=[Text(color="red", x=0, y=1, label="owin")])
    fig = to_paired_plotly_figure(fwd, bwd, "fwd", "bwd")
    legend_entries = [t for t in fig["data"] if t.get("showlegend")]
    assert [t["name"] for t in legend_entries] == ["owin"]
    # Both forward and backward Text traces share the legendgroup so they
    # toggle together — they're just visually separated by xaxis ref.
    text_traces = [t for t in fig["data"] if t.get("hovertext")]
    assert {t["legendgroup"] for t in text_traces} == {"owin"}
    assert {t["xaxis"] for t in text_traces} == {"x", "x2"}


def test_epoch_timeval_axis_uses_iso_date_strings():
    """`timeval double` means x-values are Unix epoch seconds — format as time."""
    plot = XplPlot(
        timeval="timeval double",
        commands=[
            Line(color="green", x1=1436561105.401428, y1=0, x2=1436561105.402775, y2=1),
            Text(color="white", x=1436561105.402, y=2, label="rwin"),
        ],
    )
    fig = to_plotly_figure(plot)
    assert fig["layout"]["xaxis"]["type"] == "date"
    line = next(t for t in fig["data"] if t.get("mode") == "lines")
    # Each segment x is ISO-8601 string, not raw float
    assert isinstance(line["x"][0], str)
    assert line["x"][0].startswith("2015-07-10T")
    # Label hover-markers get the same x-axis formatting.
    label_trace = next(t for t in fig["data"] if t.get("hovertext"))
    assert isinstance(label_trace["x"][0], str)
    assert label_trace["x"][0].startswith("2015-07-10T")


def test_dtime_relative_axis_stays_numeric():
    """`unsigned dtime` is a delta-time axis (seconds since start), not epoch."""
    plot = XplPlot(
        timeval="unsigned dtime",
        commands=[Line(color="green", x1=0.0, y1=0, x2=1.5, y2=1)],
    )
    fig = to_plotly_figure(plot)
    assert "type" not in fig["layout"]["xaxis"]
    line = next(t for t in fig["data"] if t.get("mode") == "lines")
    assert line["x"][0] == 0.0


def test_lines_render_in_dim_gray_regardless_of_source_color():
    """Per user feedback: line color is noise; events carry meaning.

    All Line/DLine commands render in a single dim gray. Markers, arrows,
    dots, and text annotations keep their semantic colors.
    """
    plot = XplPlot(
        commands=[
            Line(color="green", x1=0, y1=0, x2=1, y2=1),
            Line(color="yellow", x1=2, y1=2, x2=3, y2=3),
            Line(color="white", x1=4, y1=4, x2=5, y2=5),
        ]
    )
    fig = to_plotly_figure(plot)
    line_traces = [t for t in fig["data"] if t.get("mode") == "lines" and t.get("fill") != "toself"]
    assert line_traces, "expected at least one line trace"
    for trace in line_traces:
        assert trace["line"]["color"] == LINE_DIM_COLOR, (
            f"line trace {trace.get('name')} should use dim gray, got {trace['line']['color']}"
        )


def test_markers_preserve_event_color():
    """Arrows/dots/diamonds/ticks keep their semantic color — events are the signal."""
    plot = XplPlot(
        commands=[
            Arrow(color="green", x=1.0, y=1.0, direction="up"),
            Dot(color="yellow", x=2.0, y=2.0),
            Diamond(color="orange", x=3.0, y=3.0),
            Tick(color="red", x=4.0, y=4.0, kind="d"),
        ]
    )
    fig = to_plotly_figure(plot)
    marker_traces = [t for t in fig["data"] if t.get("mode") == "markers"]
    colors_used = {t["marker"]["color"] for t in marker_traces}
    # No marker should be coerced to the dim line color.
    assert LINE_DIM_COLOR not in colors_used


def test_paired_figure_stacks_forward_and_backward_with_matched_xaxis():
    """Both directions share one figure; x-axes are linked so zoom/pan syncs."""
    fwd = XplPlot(title="fwd", xlabel="time", ylabel="seq", commands=[
        Line(color="green", x1=0, y1=0, x2=1, y2=1),
    ])
    bwd = XplPlot(title="bwd", xlabel="time", ylabel="ack", commands=[
        Line(color="yellow", x1=0, y1=10, x2=1, y2=11),
    ])
    fig = to_paired_plotly_figure(fwd, bwd, "client → server", "server → client")
    # Two subplots: forward traces on (x, y), backward on (x2, y2).
    fwd_traces = [t for t in fig["data"] if t.get("xaxis", "x") == "x"]
    bwd_traces = [t for t in fig["data"] if t.get("xaxis") == "x2"]
    assert fwd_traces, "forward traces missing"
    assert bwd_traces, "backward traces missing"
    # x-axes synced.
    assert fig["layout"]["xaxis2"].get("matches") == "x"
    # Stacked: forward y-domain is the top half, backward is the bottom half.
    fwd_dom = fig["layout"]["yaxis"]["domain"]
    bwd_dom = fig["layout"]["yaxis2"]["domain"]
    assert fwd_dom[0] > bwd_dom[1] - 1e-6  # no overlap; forward sits above backward


def test_paired_figure_bottom_xaxis_anchored_to_bottom_subplot():
    """The bottom subplot's x-axis must render beneath the bottom subplot, not
    in the gap between subplots.

    Plotly's matches='x' linkage doesn't auto-position the matched axis; without
    explicit anchor='y2' the ticks/title overlay the master's position. This is
    the load-bearing fix for the user-visible regression where 'time' labels
    showed in the gap and a blank strip sat beneath the bottom subplot.
    """
    fwd = XplPlot(xlabel="time", commands=[Line(color="green", x1=0, y1=0, x2=1, y2=1)])
    bwd = XplPlot(xlabel="time", commands=[Line(color="green", x1=0, y1=0, x2=1, y2=1)])
    fig = to_paired_plotly_figure(fwd, bwd, "fwd", "bwd")
    bwd_xaxis = fig["layout"]["xaxis2"]
    assert bwd_xaxis["anchor"] == "y2"
    assert bwd_xaxis.get("side", "bottom") == "bottom"


def test_paired_figure_bottom_xaxis_keeps_title_and_ticks_visible():
    """The bottom subplot's x-axis title and tick labels must remain set.

    Regression guard: a future tweak that flips showticklabels=False or empties
    the title on bwd_xaxis would silently hide the time labels — only the top
    subplot's labels are intentionally hidden.
    """
    fwd = XplPlot(xlabel="time", commands=[Line(color="green", x1=0, y1=0, x2=1, y2=1)])
    bwd = XplPlot(xlabel="time", commands=[Line(color="green", x1=0, y1=0, x2=1, y2=1)])
    fig = to_paired_plotly_figure(fwd, bwd, "fwd", "bwd")
    bwd_xaxis = fig["layout"]["xaxis2"]
    # showticklabels missing or True is fine; explicitly False is a regression.
    assert bwd_xaxis.get("showticklabels", True) is not False
    assert bwd_xaxis.get("title", {}).get("text")  # non-empty
    # And the top subplot's title/ticks are intentionally hidden so the axis
    # reads only once between the two plots.
    fwd_xaxis = fig["layout"]["xaxis"]
    assert fwd_xaxis.get("showticklabels") is False
    assert fwd_xaxis.get("title", {}).get("text") == ""


def test_paired_figure_with_both_none_returns_consistent_empty_layout():
    """to_paired_plotly_figure(None, None) routes through to_plotly_figure so
    the returned stub has the same template/title/axes shape as every other
    branch, not a bare {data:[], layout:{template:...}}."""
    fig = to_paired_plotly_figure(None, None, "fwd", "bwd")
    assert fig["data"] == []
    assert fig["layout"]["template"] == "plotly_dark"
    # Same layout keys as a single-figure render.
    assert "xaxis" in fig["layout"]
    assert "yaxis" in fig["layout"]
    assert "margin" in fig["layout"]
    assert "modebar" in fig["layout"]


def test_paired_figure_labels_each_subplot_with_direction():
    """Each subplot carries the direction string so the user can tell them apart."""
    fwd = XplPlot(commands=[Line(color="green", x1=0, y1=0, x2=1, y2=1)])
    bwd = XplPlot(commands=[Line(color="yellow", x1=0, y1=0, x2=1, y2=1)])
    fig = to_paired_plotly_figure(fwd, bwd, "client → server", "server → client")
    annotation_texts = [a["text"] for a in fig["layout"].get("annotations", [])]
    assert any("client → server" in t for t in annotation_texts)
    assert any("server → client" in t for t in annotation_texts)


def test_paired_figure_falls_back_to_single_when_only_forward_present():
    """If one direction has no plot, return the single figure unchanged."""
    fwd = XplPlot(commands=[Line(color="green", x1=0, y1=0, x2=1, y2=1)])
    fig = to_paired_plotly_figure(fwd, None, "fwd", "bwd")
    # No subplot machinery — same shape as to_plotly_figure(fwd).
    assert "xaxis2" not in fig["layout"]
    assert all(t.get("xaxis", "x") == "x" for t in fig["data"])


def test_orphan_marker_color_gets_one_legend_entry_when_hinted():
    """A hinted marker color earns a single legend entry on its first trace.
    Subsequent traces of the same color (any kind: dots, ticks, etc.) stay
    hidden but share the legendgroup, so toggling collapses them all."""
    plot = XplPlot(
        commands=[
            Dot(color="yellow", x=1.0, y=10.0),
            Dot(color="yellow", x=2.0, y=20.0),
            Tick(color="yellow", x=3.0, y=30.0, kind="u"),
        ]
    )
    fig = to_plotly_figure(plot, metric="tput")
    yellow_traces = [t for t in fig["data"] if t.get("legendgroup") == "yellow"]
    assert yellow_traces, "expected at least one trace per orphan color"
    legend_entries = [t for t in yellow_traces if t.get("showlegend")]
    assert len(legend_entries) == 1, (
        "exactly one legend entry per orphan color, regardless of marker kind count"
    )
    assert legend_entries[0]["name"] == "per-packet (inst.)"


def test_tput_metric_hint_names_yellow_dots_per_packet():
    """tcptrace emits unlabeled yellow dots for per-packet instantaneous
    throughput (bytes_in_THIS_packet / time_since_LAST_packet) — a wire-speed
    number that often shows multi-MB/s spikes for tiny transfers. The metric
    hint surfaces this in the legend so users don't read it as transfer rate."""
    plot = XplPlot(commands=[Dot(color="yellow", x=1.0, y=9_360_000)])
    fig = to_plotly_figure(plot, metric="tput")
    legend_entries = [t for t in fig["data"] if t.get("showlegend")]
    assert [t["name"] for t in legend_entries] == ["per-packet (inst.)"]


def test_unhinted_orphan_color_stays_out_of_legend():
    """No fallback to the color name — "orange" or "white" alone doesn't tell
    the user anything the marker's color hasn't already shown. Only colors
    with a semantic hint earn a legend entry."""
    plot = XplPlot(commands=[Dot(color="orange", x=1.0, y=2.0)])
    fig = to_plotly_figure(plot, metric="some_unknown_metric")
    assert not any(t.get("showlegend") for t in fig["data"])
    # The trace is still rendered — the user can still see the marker; it
    # just doesn't earn a meaningless legend entry.
    assert any(t.get("legendgroup") == "orange" for t in fig["data"])


def test_paired_figure_passes_metric_to_both_directions():
    """A paired-figure tput render labels yellow dots in both subplots, but
    the legend stays one entry (dedup across directions via legend_seen)."""
    fwd = XplPlot(commands=[Dot(color="yellow", x=1.0, y=9e6)])
    bwd = XplPlot(commands=[Dot(color="yellow", x=2.0, y=8e6)])
    fig = to_paired_plotly_figure(fwd, bwd, "fwd", "bwd", metric="tput")
    legend_entries = [t for t in fig["data"] if t.get("showlegend")]
    assert [t["name"] for t in legend_entries] == ["per-packet (inst.)"]
    # Both directions still rendered; they just share the legendgroup.
    yellow_traces = [t for t in fig["data"] if t.get("legendgroup") == "yellow"]
    assert {t["xaxis"] for t in yellow_traces} == {"x", "x2"}


def test_high_cardinality_labels_collapse_to_one_trace_per_color():
    """tline emits a unique seq/ack label per packet. The old per-label-per-trace
    path produced thousands of single-point traces and froze the browser before
    Plotly could even start rendering. Bundle into one trace per color when
    distinct labels exceed _LABEL_LEGEND_THRESHOLD; the per-point label still
    survives as hovertext."""
    from tcptrace_ng.plotly_adapter import _LABEL_LEGEND_THRESHOLD

    cmds = [
        Text(color="green", x=float(i), y=float(i), label=f"seq {i}")
        for i in range(_LABEL_LEGEND_THRESHOLD + 1)
    ]
    cmds.append(Text(color="red", x=1.0, y=2.0, label="bad-pkt"))
    plot = XplPlot(commands=cmds)
    fig = to_plotly_figure(plot)

    label_traces = [t for t in fig["data"] if t.get("hovertext")]
    # One trace per color, regardless of the per-packet label cardinality.
    assert len(label_traces) == 2
    # No legend entries — the labels are per-event data, not categories.
    assert all(t.get("showlegend") is False for t in label_traces)
    green = next(t for t in label_traces if t["marker"]["color"] != "#ff5555")
    # Every original label survives as hovertext on the right point.
    assert len(green["hovertext"]) == _LABEL_LEGEND_THRESHOLD + 1
    assert "seq 0" in green["hovertext"]
    assert f"seq {_LABEL_LEGEND_THRESHOLD}" in green["hovertext"]


def test_low_cardinality_labels_keep_per_label_traces():
    """Sanity guard that the per-label semantic-legend behavior survives the
    high-cardinality branch — owin/rwin on ssize have to stay a useful legend."""
    plot = XplPlot(
        commands=[
            Text(color="red", x=0, y=1, label="owin"),
            Text(color="red", x=1, y=2, label="owin"),
            Text(color="yellow", x=0, y=1, label="rwin"),
        ]
    )
    fig = to_plotly_figure(plot)
    label_traces = [t for t in fig["data"] if t.get("hovertext")]
    names = {t["name"] for t in label_traces}
    assert names == {"owin", "rwin"}


def test_humanize_strips_arrow_and_suffix():
    raw = "100.99.98.97:80_==>_143.84.100.55:50526 (rtt samples)"
    assert _humanize_title(raw) == "100.99.98.97:80 → 143.84.100.55:50526"


def test_humanize_preserves_simple_title():
    assert _humanize_title("foo bar") == "foo bar"


def test_humanize_handles_empty():
    assert _humanize_title("") == ""


def test_humanize_no_suffix_with_arrow():
    assert _humanize_title("a_==>_b") == "a → b"


def test_humanize_preserves_unclosed_paren():
    assert _humanize_title("a (oops") == "a (oops"


def test_humanize_backward_arrow():
    assert _humanize_title("a_<==_b (x)") == "a ← b"


from tcptrace_ng.plotly_adapter import _epoch_to_iso, to_tsg_figure
from tcptrace_ng.tcp_inspect import Segment, TsgModel, TsgModelPair


def test_to_tsg_figure_empty_pair_returns_dark_layout():
    fig = to_tsg_figure(TsgModelPair())
    assert fig["layout"]["template"] == "plotly_dark"
    assert fig["data"] == []


def test_to_tsg_figure_uses_endpoints_in_title():
    model = TsgModel(src="1.2.3.4:80", dst="5.6.7.8:51234", direction="a2b")
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    assert "1.2.3.4:80" in fig["layout"]["title"]["text"]
    assert "5.6.7.8:51234" in fig["layout"]["title"]["text"]


def _model_with_segments() -> TsgModel:
    return TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        segments=[
            Segment(
                time=1538187584.750543,
                seq_start=3493560572,
                seq_end=3493560700,
                rtx=None,
                paired_ack_time=1538187584.784126,
                paired_rtt_ms=33.6,
                in_flight_after=128,
            ),
            Segment(
                time=1538187584.790505,
                seq_start=3493560736,
                seq_end=3493560864,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=128,
            ),
        ],
    )


def test_data_segment_trace_has_numeric_customdata_and_hovertemplate():
    fig = to_tsg_figure(TsgModelPair(fwd=_model_with_segments()))
    seg_traces = [t for t in fig["data"] if t.get("name") == "fwd data"]
    assert len(seg_traces) == 1
    t = seg_traces[0]
    # Customdata is per-point numeric arrays — no pre-formatted strings.
    assert "customdata" in t
    assert isinstance(t["customdata"], list)
    first = t["customdata"][0]
    assert isinstance(first, list)
    assert all(isinstance(v, (int, float)) for v in first)
    # Customdata must align 1:1 with x/y points so Plotly can resolve hovertemplate
    # placeholders. Each segment contributes 3 points (t, t, None separator).
    assert len(t["customdata"]) == len(t["x"])
    assert len(t["customdata"]) == 6  # 2 segments × 3 points each
    # First and second customdata entries (the two endpoints of seg 0) carry seg 0's row.
    assert t["customdata"][0] == t["customdata"][1]
    # Vertical line per segment: x has [t, t, None, ...]; y has [seq_start, seq_end, None, ...].
    assert t["x"][:3] == [
        _epoch_to_iso(1538187584.750543),
        _epoch_to_iso(1538187584.750543),
        None,
    ]
    assert t["y"][:3] == [3493560572, 3493560700, None]
    # Hovertemplate references customdata indices.
    assert "customdata" in t["hovertemplate"]


def test_retx_segment_trace_separate_from_data_with_rtx_kind_in_customdata():
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        segments=[
            Segment(
                time=1.0,
                seq_start=1000,
                seq_end=1100,
                rtx="rto",
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=200,
            ),
            Segment(
                time=2.0,
                seq_start=1100,
                seq_end=1200,
                rtx="fast",
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=100,
            ),
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    retx_traces = [t for t in fig["data"] if t.get("name") == "fwd retx"]
    assert len(retx_traces) == 1
    t = retx_traces[0]
    # Per-segment customdata includes a numeric retx code; customdata aligns 1:1
    # with points (3 per segment), so 2 segments → 6 entries with codes repeated.
    assert len(t["customdata"]) == len(t["x"])
    codes = [row[-1] for row in t["customdata"]]
    assert codes == [1.0, 1.0, 1.0, 2.0, 2.0, 2.0]
    assert "Retransmit" in t["hovertemplate"]


from tcptrace_ng.tcp_inspect import Ack


def test_ack_trace_has_step_geometry_and_dup_count_in_customdata():
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        acks=[
            Ack(
                time=1.5,
                ack_seq=1100,
                rwin=33576,
                rwin_scaled=None,
                sack_blocks=(),
                dup_count=0,
            ),
            Ack(
                time=2.5,
                ack_seq=1200,
                rwin=33576,
                rwin_scaled=None,
                sack_blocks=(),
                dup_count=3,
            ),
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    ack_traces = [t for t in fig["data"] if t.get("name") == "fwd ack"]
    rwin_traces = [t for t in fig["data"] if t.get("name") == "fwd rwin"]
    assert len(ack_traces) == 1
    assert len(rwin_traces) == 1
    a = ack_traces[0]
    # Customdata aligns 1:1 with points so hovertemplate can resolve placeholders.
    # First ack: 3 points (vertical step only). Second ack: 6 points (horizontal
    # hold + vertical step) = 9 total.
    assert len(a["customdata"]) == len(a["x"])
    assert len(a["customdata"]) == 9
    # Second ack's rows carry dup_count=3 in the last index.
    assert a["customdata"][-1][-1] == 3.0


def test_rwin_trace_tooltip_includes_window_value():
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        acks=[
            Ack(time=1.0, ack_seq=1000, rwin=64240, rwin_scaled=None, sack_blocks=(), dup_count=0),
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    rwin_traces = [t for t in fig["data"] if t.get("name") == "fwd rwin"]
    assert "rwnd" in rwin_traces[0]["hovertemplate"]


from tcptrace_ng.tcp_inspect import Anomaly


def test_annotations_emitted_for_each_anomaly_kind():
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        segments=[
            Segment(
                time=1.0,
                seq_start=1000,
                seq_end=1100,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=100,
            )
        ],
        anomalies=[
            Anomaly(time=1.0, kind="rto", one_liner="x", seq_lo=1000, seq_hi=1100),
            Anomaly(time=2.0, kind="zero_win", one_liner="y", seq_lo=None, seq_hi=None),
            Anomaly(
                time=3.0,
                kind="win_shrink_large",
                one_liner="z",
                seq_lo=None,
                seq_hi=None,
            ),
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    anns = fig["layout"]["annotations"]
    texts = [a["text"] for a in anns]
    assert any("RTO" in t or "⚠" in t for t in texts)
    assert any("0w" in t for t in texts)
    assert any("rwin" in t for t in texts)


def test_adjacent_same_kind_anomalies_collapse_with_count_suffix():
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        anomalies=[
            Anomaly(time=1.000, kind="rto", one_liner="a", seq_lo=None, seq_hi=None),
            Anomaly(time=1.020, kind="rto", one_liner="b", seq_lo=None, seq_hi=None),
            Anomaly(time=1.040, kind="rto", one_liner="c", seq_lo=None, seq_hi=None),
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    rto_anns = [a for a in fig["layout"]["annotations"] if "RTO" in a["text"] or "⚠" in a["text"]]
    assert len(rto_anns) == 1
    assert "×3" in rto_anns[0]["text"]


def test_tsg_figure_stacks_directions_as_subplots_when_both_populated():
    """Each direction has its own ISN; sharing a y-axis crams them into thin
    bands with empty space between. Both-populated should use stacked subplots
    so each y auto-scales to its own data."""
    fwd = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        segments=[
            Segment(
                time=1.0,
                seq_start=3_000_000_000,
                seq_end=3_000_000_100,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=100,
            )
        ],
    )
    bwd = TsgModel(
        src="2.2.2.2:2",
        dst="1.1.1.1:1",
        direction="b2a",
        segments=[
            Segment(
                time=1.0,
                seq_start=500,
                seq_end=600,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=100,
            )
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=fwd, bwd=bwd))
    layout = fig["layout"]
    # Two y-axes with disjoint domains (fwd top, bwd bottom).
    assert "yaxis" in layout and "yaxis2" in layout
    assert layout["yaxis"]["domain"] == [0.55, 1.0]
    assert layout["yaxis2"]["domain"] == [0.0, 0.45]
    # x2 matches x so pan/zoom drives both.
    assert layout["xaxis2"]["matches"] == "x"
    # fwd traces use (x, y); bwd traces use (x2, y2).
    fwd_data = next(t for t in fig["data"] if t.get("name") == "fwd data")
    bwd_data = next(t for t in fig["data"] if t.get("name") == "bwd data")
    assert fwd_data["xaxis"] == "x" and fwd_data["yaxis"] == "y"
    assert bwd_data["xaxis"] == "x2" and bwd_data["yaxis"] == "y2"
    # Subplot direction labels.
    label_texts = [a.get("text") for a in layout.get("annotations", [])]
    assert "1.1.1.1:1 → 2.2.2.2:2" in label_texts
    assert "2.2.2.2:2 → 1.1.1.1:1" in label_texts


def test_tsg_figure_caps_yaxis_when_rwin_far_above_data():
    """Receiver-advertised window can be many times larger than the bytes
    actually sent. Without a cap, the y-axis stretches up to (ack + rwin) and
    the data exchange becomes a thin slice at the bottom. The cap allows rwin
    to extend at most data_span above the data top."""
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        segments=[
            Segment(
                time=1.0,
                seq_start=1000,
                seq_end=1100,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=100,
            )
        ],
        acks=[
            Ack(
                time=1.5,
                ack_seq=1100,
                rwin=100_000,  # huge — without cap pushes axis up to ~101100
                rwin_scaled=None,
                sack_blocks=(),
                dup_count=0,
            )
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    yaxis = fig["layout"]["yaxis"]
    assert "range" in yaxis
    assert yaxis["autorange"] is False
    lo, hi = yaxis["range"]
    # data spans [1000, 1100], span 100. Cap allows rwin to extend at most 100
    # above data_top (=1100) → upper bound ≤ 1200 + margin.
    assert lo <= 1000
    assert 1100 <= hi <= 1300  # 1200 + 5% margin of data_span (100)


def test_tsg_figure_includes_rwin_when_close_to_data():
    """When the receiver's window tracks closely with the bytes sent, include
    rwin fully so users can see the window relationship to the data."""
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        segments=[
            Segment(
                time=1.0,
                seq_start=1000,
                seq_end=1500,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=500,
            )
        ],
        acks=[
            Ack(
                time=1.5,
                ack_seq=1500,
                rwin=200,  # data_span = 500, rwin = 200 → include fully
                rwin_scaled=None,
                sack_blocks=(),
                dup_count=0,
            )
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    yaxis = fig["layout"]["yaxis"]
    lo, hi = yaxis["range"]
    # rwin top at 1500 + 200 = 1700; should be within the range (plus margin).
    assert hi >= 1700


def test_tsg_figure_capping_applies_per_direction_in_stacked_subplots():
    """Each subplot computes its own cap from its own model."""
    fwd = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        segments=[
            Segment(time=1.0, seq_start=100, seq_end=200, rtx=None,
                    paired_ack_time=None, paired_rtt_ms=None, in_flight_after=100)
        ],
        acks=[
            Ack(time=1.5, ack_seq=200, rwin=50_000, rwin_scaled=None,
                sack_blocks=(), dup_count=0)
        ],
    )
    bwd = TsgModel(
        src="2.2.2.2:2",
        dst="1.1.1.1:1",
        direction="b2a",
        segments=[
            Segment(time=1.0, seq_start=3_000_000_000, seq_end=3_000_000_100,
                    rtx=None, paired_ack_time=None, paired_rtt_ms=None,
                    in_flight_after=100)
        ],
        acks=[
            Ack(time=1.5, ack_seq=3_000_000_100, rwin=10_000,
                rwin_scaled=None, sack_blocks=(), dup_count=0)
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=fwd, bwd=bwd))
    layout = fig["layout"]
    fwd_hi = layout["yaxis"]["range"][1]
    bwd_hi = layout["yaxis2"]["range"][1]
    # Forward cap: data_top 200, span 100 → upper bound ≤ 300 + margin.
    assert fwd_hi <= 320
    # Backward cap: data_top 3000000100, span 100 → upper bound ≤ 3000000200 + margin.
    assert bwd_hi <= 3_000_000_210


def test_tsg_figure_single_direction_uses_one_subplot():
    """When only fwd is populated, no subplot splitting — fall back to the
    single-axis layout so simple plots stay simple."""
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        segments=[
            Segment(
                time=1.0,
                seq_start=1000,
                seq_end=1100,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=100,
            )
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    layout = fig["layout"]
    # No yaxis2 when single direction.
    assert "yaxis2" not in layout
    assert "xaxis2" not in layout
    # No domain set on yaxis (full-height single subplot).
    assert "domain" not in layout["yaxis"]


def test_tsg_anomaly_annotations_bind_to_subplot_axes():
    """Anomalies in the backward direction should reference (x2, y2), not (x, y).
    Without xref/yref, the annotation pins to the forward subplot's axes."""
    fwd = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        anomalies=[
            Anomaly(time=1.0, kind="rto", one_liner="x", seq_lo=100, seq_hi=200),
        ],
    )
    bwd = TsgModel(
        src="2.2.2.2:2",
        dst="1.1.1.1:1",
        direction="b2a",
        anomalies=[
            Anomaly(time=2.0, kind="zero_win", one_liner="y", seq_lo=10, seq_hi=10),
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=fwd, bwd=bwd))
    anns = fig["layout"]["annotations"]
    # Find the anomaly annotations (not the subplot labels which use paper refs).
    rto_ann = next(a for a in anns if "RTO" in a.get("text", ""))
    zw_ann = next(a for a in anns if "0w" in a.get("text", ""))
    assert rto_ann["xref"] == "x" and rto_ann["yref"] == "y"
    assert zw_ann["xref"] == "x2" and zw_ann["yref"] == "y2"


def test_in_flight_overlay_trace_present_when_in_flight_nonempty():
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        acks=[
            Ack(time=1.0, ack_seq=1000, rwin=5000, rwin_scaled=None, sack_blocks=(), dup_count=0),
        ],
        in_flight=[(1.0, 100), (2.0, 200), (3.0, 0)],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    overlays = [t for t in fig["data"] if t.get("name") == "fwd in-flight"]
    assert len(overlays) == 1
    o = overlays[0]
    # Filled area trace.
    assert o.get("fill") in {"tozeroy", "tonexty", "toself"}
    # Toggleable via legend.
    assert o.get("showlegend") is True


def test_info_tier_annotations_hidden_by_default():
    """partial_ack / coalesced / dup_ack are info — hidden from chart by default
    so the timeline stays focused on alerts. The toggle reveals them."""
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        anomalies=[
            Anomaly(time=1.0, kind="rto", one_liner="r", seq_lo=100, seq_hi=200),
            Anomaly(time=2.0, kind="partial_ack", one_liner="p",
                    seq_lo=300, seq_hi=300),
            Anomaly(time=3.0, kind="coalesced", one_liner="c",
                    seq_lo=400, seq_hi=500),
        ],
    )
    fig_hidden = to_tsg_figure(TsgModelPair(fwd=model))
    inline_kinds = [
        a["text"]
        for a in fig_hidden["layout"]["annotations"]
        if a.get("yref") != "paper"
    ]
    assert any("RTO" in t for t in inline_kinds)
    assert not any("PA" in t for t in inline_kinds)
    assert not any("LRO" in t for t in inline_kinds)

    fig_shown = to_tsg_figure(TsgModelPair(fwd=model), show_info=True)
    inline_kinds = [
        a["text"]
        for a in fig_shown["layout"]["annotations"]
        if a.get("yref") != "paper"
    ]
    assert any("PA" in t for t in inline_kinds)
    assert any("LRO" in t for t in inline_kinds)


def test_info_strip_summarizes_hidden_kinds_above_subplot():
    """Even when info kinds are hidden, the strip above the chart counts them
    so nothing disappears silently."""
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        anomalies=[
            Anomaly(time=1.0, kind="partial_ack", one_liner="p",
                    seq_lo=100, seq_hi=100),
            Anomaly(time=2.0, kind="partial_ack", one_liner="p",
                    seq_lo=200, seq_hi=200),
            Anomaly(time=3.0, kind="coalesced", one_liner="c",
                    seq_lo=300, seq_hi=400),
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    paper_anns = [
        a for a in fig["layout"]["annotations"] if a.get("yref") == "paper"
    ]
    assert len(paper_anns) == 1
    text = paper_anns[0]["text"]
    assert "2 PA" in text
    assert "1 LRO" in text


def test_syn_segment_excluded_from_data_trace_to_avoid_orphan_hover():
    """SYN/FIN segments are 1 byte tall — invisible verticals — yet they
    still fire 'Seg #N · 0.0 ms' hover events with no visible anchor.
    Filter them from the data trace; their seq/RTT info lives on the
    handshake annotation tooltip instead."""
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        segments=[
            Segment(time=1.0, seq_start=1000, seq_end=1001, rtx=None,
                    paired_ack_time=1.5, paired_rtt_ms=500.0,
                    in_flight_after=0),  # SYN (1-byte)
            Segment(time=2.0, seq_start=1001, seq_end=2001, rtx=None,
                    paired_ack_time=None, paired_rtt_ms=None,
                    in_flight_after=1000),  # real data
        ],
        anomalies=[
            Anomaly(time=1.0, kind="syn", one_liner="SYN (initiator)",
                    seq_lo=1001, seq_hi=1001),
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    data_traces = [
        t for t in fig["data"]
        if t.get("name", "").endswith("data") and t.get("mode") == "lines"
    ]
    assert data_traces, "expected at least one data trace"
    seq_starts = set()
    for t in data_traces:
        for cd in t.get("customdata", []):
            seq_starts.add(int(cd[2]))
    assert 1001 in seq_starts            # the real data segment passes through
    assert 1000 not in seq_starts        # the SYN segment is filtered out


def test_syn_annotation_tooltip_enriched_with_seq_and_handshake_rtt():
    """Hover is owned by the scatter trace (single styled popover per spot).
    The annotation must NOT carry its own hovertext/captureevents — that
    would stack a second default-styled popover on top."""
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        segments=[
            Segment(time=1.0, seq_start=12345, seq_end=12346, rtx=None,
                    paired_ack_time=1.5, paired_rtt_ms=23.4,
                    in_flight_after=0),
        ],
        anomalies=[
            Anomaly(time=1.0, kind="syn", one_liner="SYN (initiator)",
                    seq_lo=12346, seq_hi=12346),
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    anns = [
        a for a in fig["layout"]["annotations"] if a.get("text") == "S"
    ]
    assert len(anns) == 1
    assert "hovertext" not in anns[0]
    assert not anns[0].get("captureevents")
    hover = next(t for t in fig["data"] if t.get("name") == "anomalies")
    tip = hover["customdata"][0][0]
    assert "SYN (initiator)" in tip
    assert "seq 12345" in tip
    assert "23.4 ms" in tip
    # Multi-line so dense detail doesn't sprawl horizontally.
    assert "<br>" in tip


def test_anomaly_hover_trace_border_color_matches_severity():
    """Hover popovers' bordercolor used to be hardcoded red, so a SYN hover
    looked like an alarm. Per-point arrays make handshake markers cyan, severe
    red, warn amber, info grey — matching the on-chart glyph color."""
    from tcptrace_ng.plotly_adapter import _SEVERITY_COLOR

    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        anomalies=[
            Anomaly(time=1.0, kind="syn", one_liner="s",
                    seq_lo=1000, seq_hi=1000),
            Anomaly(time=2.0, kind="rto", one_liner="r",
                    seq_lo=2000, seq_hi=2100),
            Anomaly(time=3.0, kind="ooo", one_liner="o",
                    seq_lo=2200, seq_hi=2200),
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    hover = next(t for t in fig["data"] if t.get("name") == "anomalies")
    borders = hover["hoverlabel"]["bordercolor"]
    assert borders == [
        _SEVERITY_COLOR["handshake"],
        _SEVERITY_COLOR["severe"],
        _SEVERITY_COLOR["warn"],
    ]


def test_anomaly_hover_trace_excludes_info_when_hidden():
    """When info kinds are hidden from the chart, their hover targets must
    also disappear — otherwise hovering an empty region fires a tooltip with
    no visible source."""
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        anomalies=[
            Anomaly(time=1.0, kind="rto", one_liner="r", seq_lo=100, seq_hi=200),
            Anomaly(time=2.0, kind="partial_ack", one_liner="p",
                    seq_lo=300, seq_hi=300),
        ],
    )
    fig_hidden = to_tsg_figure(TsgModelPair(fwd=model))
    hover_h = next(t for t in fig_hidden["data"] if t.get("name") == "anomalies")
    assert len(hover_h["x"]) == 1                   # rto only

    fig_shown = to_tsg_figure(TsgModelPair(fwd=model), show_info=True)
    hover_s = next(t for t in fig_shown["data"] if t.get("name") == "anomalies")
    assert len(hover_s["x"]) == 2                   # both


def test_handshake_kinds_render_in_handshake_color():
    from tcptrace_ng.plotly_adapter import _SEVERITY_COLOR

    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        anomalies=[
            Anomaly(time=1.0, kind="syn", one_liner="s",
                    seq_lo=1000, seq_hi=1000),
            Anomaly(time=2.0, kind="handshake_ack", one_liner="a",
                    seq_lo=1001, seq_hi=1001),
            Anomaly(time=3.0, kind="fin", one_liner="f",
                    seq_lo=2000, seq_hi=2000),
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    colors = {
        a["text"]: a["font"]["color"]
        for a in fig["layout"]["annotations"]
        if a.get("yref") != "paper"
    }
    assert colors["S"] == _SEVERITY_COLOR["handshake"]
    assert colors["A"] == _SEVERITY_COLOR["handshake"]
    assert colors["FA"] == _SEVERITY_COLOR["handshake"]
