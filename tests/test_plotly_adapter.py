import pytest

from tcptrace_ng.plotly_adapter import (
    _epoch_to_iso,
    _humanize_title,
    to_paired_plotly_figure,
    to_plotly_figure,
    to_throughput_figure,
    to_tsg_figure,
)
from tcptrace_ng.tcp_inspect import (
    Ack,
    Anomaly,
    Segment,
    TsgModel,
    TsgModelPair,
)
from tcptrace_ng.theme import LINE_DIM_COLOR
from tcptrace_ng.throughput import (
    Cliff,
    DirectionSummary,
    RateSample,
    Stall,
    ThroughputModel,
    ThroughputModelPair,
)
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
        t
        for t in fig["data"]
        if (t.get("hovertext") and "ACK" in t["hovertext"])
        or (t.get("hovertext") and "rwin" in t["hovertext"])
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


def test_box_becomes_square_marker():
    # tcptrace's box is a 2-coord FIN marker (not a rectangle); the generic
    # renderer draws it as a square marker, like dot/diamond.
    plot = XplPlot(commands=[Box(color="blue", x=1.0, y=3.0)])
    fig = to_plotly_figure(plot)
    markers = [t for t in fig["data"] if t.get("mode") == "markers"]
    assert len(markers) == 1
    assert markers[0]["marker"]["symbol"] == "square"
    assert markers[0]["x"] == [1.0]
    assert markers[0]["y"] == [3.0]


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
    fwd = XplPlot(
        title="fwd",
        xlabel="time",
        ylabel="seq",
        commands=[
            Line(color="green", x1=0, y1=0, x2=1, y2=1),
        ],
    )
    bwd = XplPlot(
        title="bwd",
        xlabel="time",
        ylabel="ack",
        commands=[
            Line(color="yellow", x1=0, y1=10, x2=1, y2=11),
        ],
    )
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


def test_unhinted_orphan_color_stays_out_of_legend():
    """No fallback to the color name — "orange" or "white" alone doesn't tell
    the user anything the marker's color hasn't already shown. Only colors
    with a semantic hint earn a legend entry."""
    plot = XplPlot(commands=[Dot(color="orange", x=1.0, y=2.0)])
    fig = to_plotly_figure(plot)
    assert not any(t.get("showlegend") for t in fig["data"])
    # The trace is still rendered — the user can still see the marker; it
    # just doesn't earn a meaningless legend entry.
    assert any(t.get("legendgroup") == "orange" for t in fig["data"])


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
    seg_traces = [t for t in fig["data"] if t.get("name") == "data"]
    assert len(seg_traces) == 1
    t = seg_traces[0]
    # Customdata is per-point: numeric for the fixed fields, prebuilt strings for
    # the optional delta/RTT fragments (so a missing value renders blank, not
    # "NaN"; plotly hovertemplates can't branch). See L2.
    assert "customdata" in t
    assert isinstance(t["customdata"], list)
    first = t["customdata"][0]
    assert isinstance(first, list)
    assert all(isinstance(first[i], (int, float)) for i in (0, 2, 3, 4))
    assert isinstance(first[1], str) and isinstance(first[5], str)
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


def test_seg_hover_blank_not_nan_for_first_and_unpaired_segment():
    """L2: the first segment has no previous (delta) and an unpaired segment has
    no paired RTT — those hover fields must render blank, not '+NaN ms' /
    'ACKed NaN ms later'. Prebuilt into customdata since plotly can't branch."""
    from tcptrace_ng.plotly_adapter import _data_segment_trace

    model = TsgModel(
        src="a",
        dst="b",
        direction="a2b",
        segments=[
            Segment(
                time=1.0,
                seq_start=0,
                seq_end=100,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=100,
            )
        ],
    )
    tr = _data_segment_trace(model, name="data", color="#ffffff")
    assert tr["customdata"][0][1] == ""  # first segment: no "+N ms" delta
    assert tr["customdata"][0][5] == ""  # unpaired: no "ACKed N ms later"
    # The optional fragments are rendered raw, not float-formatted (NaN-prone).
    assert "customdata[1]:" not in tr["hovertemplate"]
    assert "customdata[5]:" not in tr["hovertemplate"]


def test_tsg_figure_rel_seq_mode_subtracts_constant_baseline():
    """The UI defaults to seq_mode='rel'; the abs path is what's asserted above.
    rel must subtract one constant baseline from every plotted sequence number."""
    pair = TsgModelPair(fwd=_model_with_segments())
    abs_y = next(t for t in to_tsg_figure(pair, seq_mode="abs")["data"] if t.get("name") == "data")[
        "y"
    ]
    rel_y = next(t for t in to_tsg_figure(pair, seq_mode="rel")["data"] if t.get("name") == "data")[
        "y"
    ]
    deltas = {a - r for a, r in zip(abs_y, rel_y, strict=True) if a is not None}
    assert len(deltas) == 1  # one constant baseline subtracted from every point
    (baseline,) = deltas
    assert baseline > 1_000_000  # the large absolute ISN was removed
    assert all((a is None) == (r is None) for a, r in zip(abs_y, rel_y, strict=True))
    assert max(r for r in rel_y if r is not None) < 100_000


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
    retx_traces = [t for t in fig["data"] if t.get("name") == "retx"]
    assert len(retx_traces) == 1
    t = retx_traces[0]
    # Per-segment customdata includes a numeric retx code; customdata aligns 1:1
    # with points (3 per segment), so 2 segments → 6 entries with codes repeated.
    assert len(t["customdata"]) == len(t["x"])
    codes = [row[-1] for row in t["customdata"]]
    assert codes == [1.0, 1.0, 1.0, 2.0, 2.0, 2.0]
    assert "Retransmit" in t["hovertemplate"]


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
    ack_traces = [t for t in fig["data"] if t.get("name") == "ack"]
    rwin_traces = [t for t in fig["data"] if t.get("name") == "rwin"]
    assert len(ack_traces) == 1
    assert len(rwin_traces) == 1
    a = ack_traces[0]
    # Customdata aligns 1:1 with points so hovertemplate can resolve placeholders.
    # First ack: 3 points (vertical step only). Second ack: 6 points (horizontal
    # hold + vertical step) = 9 total.
    assert len(a["customdata"]) == len(a["x"])
    assert len(a["customdata"]) == 9
    # Second ack's rows carry the prebuilt dup-ACK hover fragment in the last
    # index (plotly templates can't branch, so the "#3" is baked in here).
    assert a["customdata"][-1][-1] == "<br>dup-ACK #3"


def test_ack_hover_omits_dup_line_for_non_dup_acks():
    """M7: a plain cumulative ACK must not hover 'dup-ACK #0'. plotly templates
    can't branch, so the dup line is prebuilt into customdata — empty for a
    non-dup ACK, '<br>dup-ACK #N' for a real one — and the template references it
    raw (no hardcoded 'dup-ACK #' prefix)."""
    from tcptrace_ng.plotly_adapter import _ack_trace

    model = TsgModel(
        src="a",
        dst="b",
        direction="a2b",
        acks=[
            Ack(time=1.0, ack_seq=1000, rwin=5000, rwin_scaled=None, sack_blocks=(), dup_count=0),
            Ack(time=2.0, ack_seq=1000, rwin=5000, rwin_scaled=None, sack_blocks=(), dup_count=3),
        ],
    )
    tr = _ack_trace(model, name="ack")
    # The template must not hardcode the "dup-ACK #" prefix (that renders "#0").
    assert "dup-ACK #%{customdata" not in tr["hovertemplate"]
    dup_fields = {row[3] for row in tr["customdata"]}
    assert "" in dup_fields  # non-dup ACK -> no dup line
    assert "<br>dup-ACK #3" in dup_fields  # real dup -> shown


def test_rwin_line_uses_scaled_window_when_known():
    """L7: the rwin line must plot the scaled window (what the hover shows), not
    the raw a.rwin — otherwise the line and tooltip disagree by the window-scale
    factor once rwin_scaled is wired in."""
    from tcptrace_ng.plotly_adapter import _rwin_trace

    model = TsgModel(
        src="a",
        dst="b",
        direction="a2b",
        acks=[Ack(time=1.0, ack_seq=1000, rwin=100, rwin_scaled=8000, sack_blocks=(), dup_count=0)],
    )
    tr = _rwin_trace(model, name="rwin")
    assert 9000 in tr["y"]  # ack_seq 1000 + scaled rwin 8000
    assert 1100 not in tr["y"]  # NOT ack_seq + raw rwin 100


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
    rwin_traces = [t for t in fig["data"] if t.get("name") == "rwin"]
    assert "rwnd" in rwin_traces[0]["hovertemplate"]


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
    data_traces = [t for t in fig["data"] if t.get("name") == "data"]
    fwd_data = next(t for t in data_traces if t.get("yaxis") == "y")
    bwd_data = next(t for t in data_traces if t.get("yaxis") == "y2")
    assert fwd_data["xaxis"] == "x" and fwd_data["yaxis"] == "y"
    assert bwd_data["xaxis"] == "x2" and bwd_data["yaxis"] == "y2"
    assert fwd_data["legendgroup"] == bwd_data["legendgroup"] == "data"
    assert fwd_data["showlegend"] and not bwd_data["showlegend"]
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
    _lo, hi = yaxis["range"]
    # rwin top at 1500 + 200 = 1700; should be within the range (plus margin).
    assert hi >= 1700


def test_tsg_figure_capping_applies_per_direction_in_stacked_subplots():
    """Each subplot computes its own cap from its own model."""
    fwd = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        segments=[
            Segment(
                time=1.0,
                seq_start=100,
                seq_end=200,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=100,
            )
        ],
        acks=[
            Ack(time=1.5, ack_seq=200, rwin=50_000, rwin_scaled=None, sack_blocks=(), dup_count=0)
        ],
    )
    bwd = TsgModel(
        src="2.2.2.2:2",
        dst="1.1.1.1:1",
        direction="b2a",
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
        acks=[
            Ack(
                time=1.5,
                ack_seq=3_000_000_100,
                rwin=10_000,
                rwin_scaled=None,
                sack_blocks=(),
                dup_count=0,
            )
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
    overlays = [t for t in fig["data"] if t.get("name") == "in-flight"]
    assert len(overlays) == 1
    o = overlays[0]
    # Self-closed band (order-independent), not a neighbor-anchored fill.
    assert o["fill"] == "toself"
    # Toggleable via legend.
    assert o.get("showlegend") is True
    # Band spans the cumack staircase (1000) up to cumack + peak in-flight
    # (1000 + 200) — outstanding bytes, not the rwin headroom.
    assert min(o["y"]) == 1000
    assert max(o["y"]) == 1200
    # Closed polygon: top edge + cumack floor for each of the 3 in-flight points.
    assert len(o["y"]) == 6


def test_in_flight_overlay_self_contained_without_acks():
    """With no ACKs the band still renders against the segment-seq floor; the
    old tonexty fill had no preceding trace to anchor against here."""
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
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
        in_flight=[(1.0, 100), (2.0, 50)],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    overlays = [t for t in fig["data"] if t.get("name") == "in-flight"]
    assert len(overlays) == 1
    o = overlays[0]
    assert o["fill"] == "toself"
    # No acks -> cumack floor is the first segment's seq_start (500).
    assert min(o["y"]) == 500
    assert max(o["y"]) == 600  # 500 + peak in-flight 100


def test_in_flight_overlay_pre_ack_floor_is_isn_not_first_cumack():
    """H1: before the first observed ACK nothing is acked yet, so the band's
    floor is the ISN (earliest segment seq_start), not the first ACK's cumack —
    which has already advanced past the initial burst. Using the first cumack
    floats the band above the data, implying outstanding bytes in a sequence
    range that was never transmitted."""
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        segments=[
            Segment(
                time=1.0,
                seq_start=500,
                seq_end=1500,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=1000,
            ),
        ],
        acks=[
            Ack(time=2.0, ack_seq=1000, rwin=5000, rwin_scaled=None, sack_blocks=(), dup_count=0),
        ],
        # First in-flight sample (t=1.0) is BEFORE the only ACK (t=2.0).
        in_flight=[(1.0, 1000), (2.0, 500)],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    o = next(t for t in fig["data"] if t.get("name") == "in-flight")
    # Pre-first-ACK floor is the ISN (500), not the first cumack (1000).
    assert min(o["y"]) == 500


def test_legend_slot_claimed_only_when_role_trace_emitted():
    """M6: the forward direction marking a role 'seen' even when it draws no
    trace for that role suppressed the backward direction's legend entry. The
    green ACK staircase (drawn only in the panel that carries the cumacks) then
    rendered with no toggleable legend label. Claim the slot only on emit."""
    from tcptrace_ng.plotly_adapter import _build_direction_traces

    legend_seen: set[str] = set()
    # Forward panel: data segments but NO acks -> no ack trace emitted.
    fwd = TsgModel(
        src="a",
        dst="b",
        direction="a2b",
        segments=[
            Segment(
                time=1.0,
                seq_start=0,
                seq_end=100,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=0,
            )
        ],
    )
    fwd_tr = _build_direction_traces(fwd, xaxis_ref="x", yaxis_ref="y", legend_seen=legend_seen)
    # Backward panel: carries the cumack staircase.
    bwd = TsgModel(
        src="b",
        dst="a",
        direction="b2a",
        acks=[Ack(time=2.0, ack_seq=100, rwin=5000, rwin_scaled=None, sack_blocks=(), dup_count=0)],
    )
    bwd_tr = _build_direction_traces(bwd, xaxis_ref="x2", yaxis_ref="y2", legend_seen=legend_seen)
    ack_traces = [t for t in fwd_tr + bwd_tr if t.get("legendgroup") == "ack"]
    assert len(ack_traces) == 1  # only the backward panel drew an ACK staircase
    assert ack_traces[0]["showlegend"] is True  # and it owns the legend entry


def test_info_tier_annotations_hidden_by_default():
    """partial_ack / coalesced / dup_ack are info — hidden from chart by default
    so the timeline stays focused on alerts. The toggle reveals them."""
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        anomalies=[
            Anomaly(time=1.0, kind="rto", one_liner="r", seq_lo=100, seq_hi=200),
            Anomaly(time=2.0, kind="partial_ack", one_liner="p", seq_lo=300, seq_hi=300),
            Anomaly(time=3.0, kind="coalesced", one_liner="c", seq_lo=400, seq_hi=500),
        ],
    )
    fig_hidden = to_tsg_figure(TsgModelPair(fwd=model))
    inline_kinds = [
        a["text"] for a in fig_hidden["layout"]["annotations"] if a.get("yref") != "paper"
    ]
    assert any("RTO" in t for t in inline_kinds)
    assert not any("PA" in t for t in inline_kinds)
    assert not any("LRO" in t for t in inline_kinds)

    fig_shown = to_tsg_figure(TsgModelPair(fwd=model), show_info=True)
    inline_kinds = [
        a["text"] for a in fig_shown["layout"]["annotations"] if a.get("yref") != "paper"
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
            Anomaly(time=1.0, kind="partial_ack", one_liner="p", seq_lo=100, seq_hi=100),
            Anomaly(time=2.0, kind="partial_ack", one_liner="p", seq_lo=200, seq_hi=200),
            Anomaly(time=3.0, kind="coalesced", one_liner="c", seq_lo=300, seq_hi=400),
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    paper_anns = [a for a in fig["layout"]["annotations"] if a.get("yref") == "paper"]
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
            Segment(
                time=1.0,
                seq_start=1000,
                seq_end=1001,
                rtx=None,
                paired_ack_time=1.5,
                paired_rtt_ms=500.0,
                in_flight_after=0,
            ),  # SYN (1-byte)
            Segment(
                time=2.0,
                seq_start=1001,
                seq_end=2001,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=1000,
            ),  # real data
        ],
        anomalies=[
            Anomaly(time=1.0, kind="syn", one_liner="SYN (initiator)", seq_lo=1001, seq_hi=1001),
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    data_traces = [
        t for t in fig["data"] if t.get("name", "").endswith("data") and t.get("mode") == "lines"
    ]
    assert data_traces, "expected at least one data trace"
    seq_starts = set()
    for t in data_traces:
        for cd in t.get("customdata", []):
            seq_starts.add(int(cd[2]))
    assert 1001 in seq_starts  # the real data segment passes through
    assert 1000 not in seq_starts  # the SYN segment is filtered out


def test_syn_annotation_tooltip_enriched_with_seq_and_handshake_rtt():
    """Hover lives directly on the annotation so the popover lands on the
    visible glyph (xshift/yshift applied) instead of the bare data point
    14 px below. Verifies the annotation carries the enriched hovertext."""
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        segments=[
            Segment(
                time=1.0,
                seq_start=12345,
                seq_end=12346,
                rtx=None,
                paired_ack_time=1.5,
                paired_rtt_ms=23.4,
                in_flight_after=0,
            ),
        ],
        anomalies=[
            Anomaly(time=1.0, kind="syn", one_liner="SYN (initiator)", seq_lo=12346, seq_hi=12346),
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    anns = [a for a in fig["layout"]["annotations"] if a.get("text") == "S"]
    assert len(anns) == 1
    tip = anns[0]["hovertext"]
    assert "SYN (initiator)" in tip
    # Seq is comma-formatted so it matches the segment/ack popovers.
    assert "seq 12,345" in tip
    assert "23.4 ms" in tip
    # Multi-line so dense detail doesn't sprawl horizontally.
    assert "<br>" in tip
    # No separate scatter hover trace — annotation owns the popover.
    assert not any(t.get("name") == "anomalies" for t in fig["data"])


def test_anomaly_hovertext_respects_rel_seq_mode():
    """The TSG's relative/absolute seq toggle was only honored by SYN/FIN-class
    popups; rto/ooo/sack_gap/keepalive/dup_ack/partial_ack popups always
    showed absolute seqs because their one_liner text is baked in tcp_inspect
    with embedded values. In rel mode those popups should display the
    baseline-subtracted seqs that match the on-chart axis."""
    baseline = 1_000_000
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        # The renderer's baseline is the minimum seq across segments+acks.
        # Seat a segment exactly at `baseline` so the subtraction math below
        # is in clean round numbers.
        segments=[
            Segment(
                time=1.0,
                seq_start=baseline,
                seq_end=baseline + 1500,
                rtx=None,
                paired_ack_time=None,
                paired_rtt_ms=None,
                in_flight_after=0,
            ),
        ],
        acks=[
            Ack(
                time=1.5,
                ack_seq=baseline + 1000,
                rwin=64000,
                rwin_scaled=None,
                sack_blocks=(),
                dup_count=0,
            ),
        ],
        anomalies=[
            Anomaly(
                time=1.0,
                kind="rto",
                one_liner=f"rto retransmit seq {baseline + 500:,}..{baseline + 1500:,}",
                seq_lo=baseline + 500,
                seq_hi=baseline + 1500,
            ),
            Anomaly(
                time=1.2,
                kind="ooo",
                one_liner=(
                    f"out-of-order seq {baseline + 200:,}..{baseline + 300:,} "
                    f"(below max seen {baseline + 1500:,})"
                ),
                seq_lo=baseline + 200,
                seq_hi=baseline + 300,
            ),
            Anomaly(
                time=1.5,
                kind="sack_gap",
                one_liner=(
                    f"SACK {baseline + 2000:,}..{baseline + 2500:,}; "
                    f"gap {baseline + 1000:,}..{baseline + 2000:,} unacked"
                ),
                seq_lo=baseline + 2000,
                seq_hi=baseline + 2500,
            ),
            Anomaly(
                time=1.7,
                kind="dup_ack",
                one_liner=f"duplicate ACK at seq {baseline + 1000:,}",
                seq_lo=baseline + 1000,
                seq_hi=baseline + 1000,
            ),
            Anomaly(
                time=1.8,
                kind="partial_ack",
                one_liner=(
                    f"partial ACK at seq {baseline + 800:,} (max sent {baseline + 1500:,})"
                ),
                seq_lo=baseline + 800,
                seq_hi=baseline + 800,
            ),
            Anomaly(
                time=1.9,
                kind="keepalive",
                one_liner=f"keepalive at seq {baseline + 1000:,}",
                seq_lo=baseline + 1000,
                seq_hi=baseline + 1000,
            ),
        ],
    )

    def _tips(seq_mode):
        fig = to_tsg_figure(TsgModelPair(fwd=model), show_info=True, seq_mode=seq_mode)
        return {
            a.get("text"): a.get("hovertext", "")
            for a in fig["layout"]["annotations"]
            if a.get("hovertext") and a.get("yref") != "paper"
        }

    abs_tips = _tips("abs")
    rel_tips = _tips("rel")

    # Absolute mode: the un-rewritten text leaks through (baseline=0, no
    # rewrite). Sanity check that the baseline-bearing seqs are visible.
    assert f"{baseline + 500:,}" in abs_tips["⚠ RTO"]
    assert f"{baseline + 200:,}" in abs_tips["ooo"]
    assert f"{baseline + 2000:,}" in abs_tips["sack gap"]
    assert f"{baseline + 1000:,}" in abs_tips["DA"]
    assert f"{baseline + 800:,}" in abs_tips["PA"]
    assert f"{baseline + 1000:,}" in abs_tips["keepalive"]

    # Relative mode: every seq is rewritten to its baseline-subtracted form.
    # Critically, NO absolute seq should remain.
    for key in ("⚠ RTO", "ooo", "sack gap", "DA", "PA", "keepalive"):
        assert f"{baseline:,}" not in rel_tips[key], (
            f"{key} popup still shows absolute baseline: {rel_tips[key]!r}"
        )
    # Spot-check a few rewrites.
    assert "500..1,500" in rel_tips["⚠ RTO"]
    assert "200..300" in rel_tips["ooo"]
    assert "max seen 1,500" in rel_tips["ooo"]
    assert "SACK 2,000..2,500" in rel_tips["sack gap"]
    assert "gap 1,000..2,000" in rel_tips["sack gap"]
    assert "seq 1,000" in rel_tips["DA"]
    assert "max sent 1,500" in rel_tips["PA"]
    assert "seq 1,000" in rel_tips["keepalive"]


def test_anomaly_annotation_border_color_matches_severity():
    """Hover popovers' bordercolor used to be hardcoded red, so a SYN hover
    looked like an alarm. Per-annotation hoverlabel makes handshake markers
    cyan, severe red, warn amber, info grey — matching the on-chart glyph
    color."""
    from tcptrace_ng.plotly_adapter import _SEVERITY_COLOR

    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        anomalies=[
            Anomaly(time=1.0, kind="syn", one_liner="s", seq_lo=1000, seq_hi=1000),
            Anomaly(time=2.0, kind="rto", one_liner="r", seq_lo=2000, seq_hi=2100),
            Anomaly(time=3.0, kind="ooo", one_liner="o", seq_lo=2200, seq_hi=2200),
        ],
    )
    fig = to_tsg_figure(TsgModelPair(fwd=model))
    glyph_anns = [a for a in fig["layout"]["annotations"] if a.get("text") in {"S", "⚠ RTO", "ooo"}]
    borders = [a["hoverlabel"]["bordercolor"] for a in glyph_anns]
    assert borders == [
        _SEVERITY_COLOR["handshake"],
        _SEVERITY_COLOR["severe"],
        _SEVERITY_COLOR["warn"],
    ]


def test_anomaly_annotations_exclude_info_when_hidden():
    """When info kinds are hidden from the chart, their hover targets must
    also disappear — otherwise hovering an empty region fires a tooltip with
    no visible source."""
    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        anomalies=[
            Anomaly(time=1.0, kind="rto", one_liner="r", seq_lo=100, seq_hi=200),
            Anomaly(time=2.0, kind="partial_ack", one_liner="p", seq_lo=300, seq_hi=300),
        ],
    )

    def hoverable_count(fig):
        return sum(
            1
            for a in fig["layout"]["annotations"]
            if a.get("hovertext") and a.get("yref") != "paper"
        )

    assert hoverable_count(to_tsg_figure(TsgModelPair(fwd=model))) == 1
    assert hoverable_count(to_tsg_figure(TsgModelPair(fwd=model), show_info=True)) == 2


def test_handshake_kinds_render_in_handshake_color():
    from tcptrace_ng.plotly_adapter import _SEVERITY_COLOR

    model = TsgModel(
        src="1.1.1.1:1",
        dst="2.2.2.2:2",
        direction="a2b",
        anomalies=[
            Anomaly(time=1.0, kind="syn", one_liner="s", seq_lo=1000, seq_hi=1000),
            Anomaly(time=2.0, kind="handshake_ack", one_liner="a", seq_lo=1001, seq_hi=1001),
            Anomaly(time=3.0, kind="fin", one_liner="f", seq_lo=2000, seq_hi=2000),
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


# ---------------------------------------------------------------------------
# TestThroughputFigure
# ---------------------------------------------------------------------------


def _dummy_summary() -> DirectionSummary:
    return DirectionSummary(
        total_payload_bytes=0,
        total_wire_bytes=0,
        retx_overhead_frac=0.0,
        peak_goodput_Bps=0.0,
        mean_goodput_Bps=0.0,
        p50_goodput_Bps=0.0,
        p95_goodput_Bps=0.0,
        bdp_utilization_frac=None,
        stall_count=0,
        total_stall_s=0.0,
        cliff_count=0,
    )


def _sample(
    t: float, goodput: float = 1000.0, wire: float = 1100.0, max_bps: float | None = 10000.0
) -> RateSample:
    return RateSample(t=t, goodput_Bps=goodput, wire_Bps=wire, max_Bps=max_bps, window_s=0.1)


def _tput_model(
    samples=(),
    stalls=(),
    cliffs=(),
    src="1.1.1.1:1",
    dst="2.2.2.2:2",
) -> ThroughputModel:
    return ThroughputModel(
        samples=samples,
        stalls=stalls,
        cliffs=cliffs,
        summary=_dummy_summary(),
        src=src,
        dst=dst,
    )


def _stall(severity="warn", t_start=1.0, duration_s=0.5) -> Stall:
    return Stall(
        t_start=t_start,
        t_end=t_start + duration_s,
        duration_s=duration_s,
        pending_bytes=100,
        rtt_multiple=6.0,
        severity=severity,
    )


def _cliff(severity="warn", t=2.0, drop_frac=0.7, cause_hint="post-loss") -> Cliff:
    return Cliff(
        t=t,
        goodput_before_Bps=10000.0,
        goodput_after_Bps=3000.0,
        drop_frac=drop_frac,
        cause_hint=cause_hint,
        severity=severity,
    )


class TestThroughputFigure:
    def test_returns_data_and_layout_keys(self):
        model = _tput_model(samples=(_sample(1.0),))
        fig = to_throughput_figure(ThroughputModelPair(fwd=model))
        assert "data" in fig
        assert "layout" in fig

    def test_paired_layout_has_two_axes(self):
        fwd = _tput_model(samples=(_sample(1.0),))
        bwd = _tput_model(samples=(_sample(2.0),), src="2.2.2.2:2", dst="1.1.1.1:1")
        fig = to_throughput_figure(ThroughputModelPair(fwd=fwd, bwd=bwd))
        assert "xaxis" in fig["layout"]
        assert "yaxis" in fig["layout"]
        assert "xaxis2" in fig["layout"]
        assert "yaxis2" in fig["layout"]

    def test_x_axis_matched_between_subplots(self):
        fwd = _tput_model(samples=(_sample(1.0),))
        bwd = _tput_model(samples=(_sample(2.0),), src="2.2.2.2:2", dst="1.1.1.1:1")
        fig = to_throughput_figure(ThroughputModelPair(fwd=fwd, bwd=bwd))
        assert fig["layout"]["xaxis2"]["matches"] == "x"

    def test_y_axis_format(self):
        fwd = _tput_model(samples=(_sample(1.0),))
        bwd = _tput_model(samples=(_sample(2.0),), src="2.2.2.2:2", dst="1.1.1.1:1")
        fig = to_throughput_figure(ThroughputModelPair(fwd=fwd, bwd=bwd))
        assert fig["layout"]["yaxis"]["tickformat"] == ".3s"
        assert fig["layout"]["yaxis"]["ticksuffix"] == "B/s"
        assert fig["layout"]["yaxis2"]["tickformat"] == ".3s"
        assert fig["layout"]["yaxis2"]["ticksuffix"] == "B/s"

    def test_bits_unit_scales_rates_by_8_and_switches_suffix(self):
        """The UI defaults to rate_unit='bits' (bytes is tested above). bits mode
        scales every rate by 8 and labels the axis bps."""
        model = _tput_model(
            samples=(
                _sample(1.0, goodput=1000.0, wire=1100.0),
                _sample(1.1, goodput=2000.0, wire=2200.0),
            )
        )
        pair = ThroughputModelPair(fwd=model)
        bytes_fig = to_throughput_figure(pair, rate_unit="bytes")
        bits_fig = to_throughput_figure(pair, rate_unit="bits")

        def _y(fig, name):
            t = next(tr for tr in fig["data"] if tr.get("name") == name)
            return [v for v in t["y"] if v is not None]

        assert _y(bits_fig, "goodput") == [v * 8.0 for v in _y(bytes_fig, "goodput")]
        assert _y(bits_fig, "wire") == [v * 8.0 for v in _y(bytes_fig, "wire")]
        assert bytes_fig["layout"]["yaxis"]["ticksuffix"] == "B/s"
        assert bits_fig["layout"]["yaxis"]["ticksuffix"] == "bps"

    def test_trace_order_per_direction(self):
        """Traces must appear in order: stalls, envelope, wire, goodput."""
        model = _tput_model(
            samples=(_sample(1.0), _sample(1.1)),
            stalls=(_stall(),),
        )
        fig = to_throughput_figure(ThroughputModelPair(fwd=model))
        traces = fig["data"]
        stall_idx = next(i for i, t in enumerate(traces) if t.get("name") == "stall")
        ceil_idx = next(i for i, t in enumerate(traces) if t.get("name") == "ceiling")
        wire_idx = next(i for i, t in enumerate(traces) if t.get("name") == "wire")
        gput_idx = next(i for i, t in enumerate(traces) if t.get("name") == "goodput")
        assert stall_idx < ceil_idx < wire_idx < gput_idx

    def test_stall_severity_alpha_tinting(self):
        model = _tput_model(
            samples=(_sample(1.0),),
            stalls=(
                _stall(severity="info", t_start=0.5),
                _stall(severity="warn", t_start=1.5),
                _stall(severity="severe", t_start=2.5),
            ),
        )
        fig = to_throughput_figure(ThroughputModelPair(fwd=model), show_info=True)
        stall_traces = [t for t in fig["data"] if t.get("name") == "stall"]
        assert len(stall_traces) == 3
        alphas = [float(t["fillcolor"].split(",")[-1].rstrip(")")) for t in stall_traces]
        assert alphas[0] == pytest.approx(0.10)
        assert alphas[1] == pytest.approx(0.15)
        assert alphas[2] == pytest.approx(0.22)

    def test_show_info_false_hides_info_stall(self):
        model = _tput_model(
            samples=(_sample(1.0),),
            stalls=(
                _stall(severity="info", t_start=0.5),
                _stall(severity="warn", t_start=1.5),
            ),
        )
        fig = to_throughput_figure(ThroughputModelPair(fwd=model), show_info=False)
        stall_traces = [t for t in fig["data"] if t.get("name") == "stall"]
        assert len(stall_traces) == 1

    def test_show_info_true_includes_info_stall(self):
        model = _tput_model(
            samples=(_sample(1.0),),
            stalls=(
                _stall(severity="info", t_start=0.5),
                _stall(severity="warn", t_start=1.5),
            ),
        )
        fig = to_throughput_figure(ThroughputModelPair(fwd=model), show_info=True)
        stall_traces = [t for t in fig["data"] if t.get("name") == "stall"]
        assert len(stall_traces) == 2

    def test_show_info_false_hides_info_cliff(self):
        model = _tput_model(
            samples=(_sample(1.0), _sample(1.1)),
            cliffs=(
                _cliff(severity="info", t=1.05),
                _cliff(severity="warn", t=1.08),
            ),
        )
        fig = to_throughput_figure(ThroughputModelPair(fwd=model), show_info=False)
        non_paper = [
            a
            for a in fig["layout"]["annotations"]
            if a.get("yref") != "paper" and "cliff" in a.get("text", "")
        ]
        assert len(non_paper) == 1
        assert "warn" not in non_paper[0]["text"]  # cause_hint, not severity

    def test_show_info_true_includes_info_cliff(self):
        model = _tput_model(
            samples=(_sample(1.0), _sample(1.1)),
            cliffs=(
                _cliff(severity="info", t=1.05),
                _cliff(severity="warn", t=1.08),
            ),
        )
        fig = to_throughput_figure(ThroughputModelPair(fwd=model), show_info=True)
        non_paper = [
            a
            for a in fig["layout"]["annotations"]
            if a.get("yref") != "paper" and "cliff" in a.get("text", "")
        ]
        assert len(non_paper) == 2

    def test_cliff_annotation_text_format(self):
        model = _tput_model(
            samples=(_sample(1.0), _sample(1.1)),
            cliffs=(_cliff(severity="warn", t=1.05, drop_frac=0.75, cause_hint="rwin-shrink"),),
        )
        fig = to_throughput_figure(ThroughputModelPair(fwd=model))
        cliff_anns = [a for a in fig["layout"]["annotations"] if "cliff" in a.get("text", "")]
        assert len(cliff_anns) == 1
        assert cliff_anns[0]["text"] == "cliff -75% (rwin-shrink)"

    def test_cliff_color_by_severity(self):
        model = _tput_model(
            samples=(_sample(1.0), _sample(1.1)),
            cliffs=(
                _cliff(severity="severe", t=1.02),
                _cliff(severity="warn", t=1.04),
            ),
        )
        fig = to_throughput_figure(ThroughputModelPair(fwd=model))
        cliff_anns = [a for a in fig["layout"]["annotations"] if "cliff" in a.get("text", "")]
        colors = {a["font"]["color"] for a in cliff_anns}
        assert "#ff5555" in colors  # severe
        assert "#ffaa00" in colors  # warn — unified with _SEVERITY_COLOR

    def test_legend_dedup_across_directions(self):
        samples = (_sample(1.0), _sample(1.1))
        fwd = _tput_model(
            samples=samples,
            stalls=(_stall(),),
            cliffs=(_cliff(),),
        )
        bwd = _tput_model(
            samples=samples,
            stalls=(_stall(t_start=1.5),),
            cliffs=(_cliff(t=1.6),),
            src="2.2.2.2:2",
            dst="1.1.1.1:1",
        )
        fig = to_throughput_figure(ThroughputModelPair(fwd=fwd, bwd=bwd))
        legend_traces = [t for t in fig["data"] if t.get("showlegend")]
        legend_names = [t["name"] for t in legend_traces]
        for name in ("ceiling", "wire", "goodput", "stall"):
            assert legend_names.count(name) == 1, (
                f"'{name}' should appear once, got {legend_names.count(name)}"
            )

    def test_no_rtt_drops_envelope(self):
        samples = tuple(_sample(float(i), max_bps=None) for i in range(5))
        model = _tput_model(samples=samples)
        fig = to_throughput_figure(ThroughputModelPair(fwd=model))
        ceiling_traces = [t for t in fig["data"] if t.get("name") == "ceiling"]
        assert ceiling_traces == []

    def test_no_ack_data_drops_goodput_and_adds_annotation(self):
        samples = tuple(_sample(float(i), goodput=0.0) for i in range(5))
        model = _tput_model(samples=samples)
        fig = to_throughput_figure(ThroughputModelPair(fwd=model))
        gput_traces = [t for t in fig["data"] if t.get("name") == "goodput"]
        assert gput_traces == []
        ann_texts = [a["text"] for a in fig["layout"]["annotations"]]
        assert any("goodput unavailable" in t for t in ann_texts)

    def test_no_segments_shows_blank_annotation(self):
        model = _tput_model(samples=())
        fig = to_throughput_figure(ThroughputModelPair(fwd=model))
        assert fig["data"] == []
        ann_texts = [a["text"] for a in fig["layout"]["annotations"]]
        assert any("no data sent" in t for t in ann_texts)

    def test_single_direction_pair_has_one_subplot(self):
        model = _tput_model(samples=(_sample(1.0),))
        fig = to_throughput_figure(ThroughputModelPair(fwd=model, bwd=None))
        assert "xaxis" in fig["layout"]
        assert "yaxis" in fig["layout"]
        assert "xaxis2" not in fig["layout"]
        assert "yaxis2" not in fig["layout"]

    def test_both_none_returns_no_data(self):
        fig = to_throughput_figure(ThroughputModelPair())
        assert fig["data"] == []
        ann_texts = [a["text"] for a in fig["layout"]["annotations"]]
        assert any("no throughput data" in t for t in ann_texts)

    def test_y_axis_range_clips_runaway_ceiling(self):
        # Ceiling 100x larger than data — would hide the data if it drove
        # the axis. y_range is driven by data instead.
        high_max = 1_000_000.0
        samples = (
            _sample(1.0, wire=10000.0, max_bps=high_max),
            _sample(1.1, wire=10000.0, max_bps=high_max),
        )
        model = _tput_model(samples=samples)
        fig = to_throughput_figure(ThroughputModelPair(fwd=model))
        y_range = fig["layout"]["yaxis"]["range"]
        assert y_range[0] == pytest.approx(0.0)
        assert y_range[1] == pytest.approx(13000.0)

    def test_y_axis_range_includes_ceiling_when_within_range(self):
        # Ceiling 2x data — fits within the 5x clip, drives the axis.
        samples = (
            _sample(1.0, wire=10000.0, max_bps=20000.0),
            _sample(1.1, wire=10000.0, max_bps=20000.0),
        )
        model = _tput_model(samples=samples)
        fig = to_throughput_figure(ThroughputModelPair(fwd=model))
        y_range = fig["layout"]["yaxis"]["range"]
        assert y_range[1] == pytest.approx(22000.0)

    def test_y_axis_range_falls_back_to_data_when_no_ceiling(self):
        samples = (
            _sample(1.0, wire=50000.0, max_bps=None),
            _sample(1.1, wire=80000.0, max_bps=None),
        )
        model = _tput_model(samples=samples)
        fig = to_throughput_figure(ThroughputModelPair(fwd=model))
        y_range = fig["layout"]["yaxis"]["range"]
        assert y_range[1] == pytest.approx(80000.0 * 1.3)

    def test_ceiling_pegged_at_y_top_when_runaway(self):
        """When BDP ceiling sits far above the data band — typical for
        app-limited connections — _tput_yaxis_range deliberately sizes the
        axis to the data so the data stays visible. The ceiling trace must
        still render: clamped to the y-axis top with the real value carried
        in customdata so hover reveals it. Silently dropping the line off-
        screen gave network engineers no indication a ceiling existed at
        all."""
        high_max = 1_000_000.0
        samples = (
            _sample(1.0, wire=10000.0, max_bps=high_max),
            _sample(1.1, wire=10000.0, max_bps=high_max),
        )
        model = _tput_model(samples=samples)
        fig = to_throughput_figure(ThroughputModelPair(fwd=model))
        y_max = fig["layout"]["yaxis"]["range"][1]
        ceil = next(t for t in fig["data"] if t.get("name") == "ceiling")
        # Every y value clamped at the y-axis top (real ceiling >> y_max).
        assert all(y == pytest.approx(y_max) for y in ceil["y"]), (
            f"expected all ceiling y at {y_max}; got {ceil['y']}"
        )
        # Real (un-clamped) values carried in customdata for the hover.
        assert list(ceil["customdata"]) == [high_max, high_max]
        # Hovertemplate references customdata, not y.
        assert "%{customdata" in ceil["hovertemplate"]

    def test_ceiling_uses_real_y_when_within_range(self):
        """Mixed case: ceiling stays inside the y-axis, so y values are the
        real ceiling values (no clamping). Customdata still mirrors y so
        the hovertemplate is consistent across both cases."""
        samples = (
            _sample(1.0, wire=10000.0, max_bps=20000.0),
            _sample(1.1, wire=10000.0, max_bps=20000.0),
        )
        model = _tput_model(samples=samples)
        fig = to_throughput_figure(ThroughputModelPair(fwd=model))
        ceil = next(t for t in fig["data"] if t.get("name") == "ceiling")
        assert ceil["y"] == [20000.0, 20000.0]
        assert list(ceil["customdata"]) == [20000.0, 20000.0]
