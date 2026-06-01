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
    """Legend rendering: each label becomes its own legend entry; non-Text
    traces (lines/markers/boxes) are explicitly hidden from the legend."""
    plot = XplPlot(
        commands=[
            Line(color="green", x1=0, y1=0, x2=1, y2=1),
            Dot(color="green", x=1.0, y=2.0),
            Text(color="red", x=1.0, y=2.0, label="owin"),
            Text(color="yellow", x=1.0, y=3.0, label="rwin"),
        ]
    )
    fig = to_plotly_figure(plot)
    assert fig["layout"]["showlegend"] is True
    legend_names = [t["name"] for t in fig["data"] if t.get("showlegend")]
    assert sorted(legend_names) == ["owin", "rwin"]
    # Line + Dot traces are present but not in the legend.
    non_legend = [t for t in fig["data"] if not t.get("showlegend")]
    assert non_legend, "expected non-Text traces to remain (with showlegend=False)"


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
