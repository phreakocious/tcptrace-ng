from tcptrace_ng.plotly_adapter import to_plotly_figure
from tcptrace_ng.xpl_parser import Box, Diamond, Line, Text, Tick, XplPlot


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


def test_text_becomes_annotation():
    plot = XplPlot(commands=[Text(color="green", x=1.0, y=2.0, label="R")])
    fig = to_plotly_figure(plot)
    annotations = fig["layout"]["annotations"]
    assert len(annotations) == 1
    assert annotations[0]["text"] == "R"
    assert annotations[0]["x"] == 1.0
    assert annotations[0]["y"] == 2.0


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


def test_legend_hidden_by_default():
    """Auto-generated (color, kind) legends are noise; xplot has no legend."""
    plot = XplPlot(commands=[Line(color="green", x1=0, y1=0, x2=1, y2=1)])
    fig = to_plotly_figure(plot)
    assert fig["layout"]["showlegend"] is False


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
    # Annotations get the same formatting so they stay aligned with the axis
    ann = fig["layout"]["annotations"][0]
    assert isinstance(ann["x"], str)
    assert ann["x"].startswith("2015-07-10T")


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
