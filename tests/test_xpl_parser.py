"""Tests for the xpl parser, using real tcptrace xpl format.

Real tcptrace xpl uses:
- Stateful color: a bare color word on its own line sets the current color
  for subsequent commands until changed.
- Optional trailing color: some commands carry a color name as the final
  token, overriding the current color for that one command.
- Direction baked into verb: uarrow/darrow/larrow/rarrow are up/down/left/right
  arrows. (Earlier tests treated `darrow` as a dashed arrow; that was wrong.)
- Tick variants: utick/dtick/ltick/rtick/htick/vtick and bare `tick`.
- Text variants: atext/btext/ltext/rtext/ctext (anchor) followed by a label
  line.
- `invisible x y` extends axis range without rendering — parser drops these.
"""

from tcptrace_ng.xpl_parser import (
    Arrow,
    Box,
    DBox,
    Diamond,
    DLine,
    Dot,
    Line,
    Text,
    Tick,
    parse_xpl,
)

HEADER_ONLY = """\
timeval double
title
time sequence graph
xlabel
time
ylabel
sequence number
go
"""


def test_parses_title():
    plot = parse_xpl(HEADER_ONLY)
    assert plot.title == "time sequence graph"


def test_parses_axis_labels():
    plot = parse_xpl(HEADER_ONLY)
    assert plot.xlabel == "time"
    assert plot.ylabel == "sequence number"


def test_empty_commands_for_header_only():
    plot = parse_xpl(HEADER_ONLY)
    assert plot.commands == []
    assert plot.unknown == []


def test_tolerates_unknown_header_directive():
    # tcptrace emits "unsigned dtime" on the first line of tline plots
    src = "unsigned dtime\ntitle\nfoo\ngo\n"
    plot = parse_xpl(src)
    assert plot.title == "foo"
    assert plot.unknown == []


def test_bare_color_sets_state_for_following_commands():
    src = "go\ngreen\nline 1.0 100 2.0 200\nline 3.0 300 4.0 400\n"
    plot = parse_xpl(src)
    assert plot.commands == [
        Line(color="green", x1=1.0, y1=100.0, x2=2.0, y2=200.0),
        Line(color="green", x1=3.0, y1=300.0, x2=4.0, y2=400.0),
    ]


def test_color_state_changes_on_subsequent_bare_color():
    src = "go\ngreen\nline 1 1 2 2\nred\nline 3 3 4 4\n"
    plot = parse_xpl(src)
    colors = [cmd.color for cmd in plot.commands]
    assert colors == ["green", "red"]


def test_trailing_color_overrides_state_for_one_command():
    src = "go\ngreen\ndot 1 1 white\ndot 2 2\n"
    plot = parse_xpl(src)
    assert plot.commands == [
        Dot(color="white", x=1.0, y=1.0),
        Dot(color="green", x=2.0, y=2.0),
    ]


def test_default_color_before_any_color_directive_is_white():
    # tcptrace files generally start with a color directive, but be defensive.
    src = "go\nline 1 1 2 2\n"
    plot = parse_xpl(src)
    assert plot.commands == [Line(color="white", x1=1.0, y1=1.0, x2=2.0, y2=2.0)]


def test_parses_dline():
    src = "go\nred\ndline 0.5 50 1.5 150\n"
    plot = parse_xpl(src)
    assert plot.commands == [DLine(color="red", x1=0.5, y1=50.0, x2=1.5, y2=150.0)]


def test_parses_box():
    src = "go\nblue\nbox 0 0 10 20\n"
    plot = parse_xpl(src)
    assert plot.commands == [Box(color="blue", x1=0.0, y1=0.0, x2=10.0, y2=20.0)]


def test_parses_dbox():
    src = "go\nyellow\ndbox 1 2 3 4\n"
    plot = parse_xpl(src)
    assert plot.commands == [DBox(color="yellow", x1=1.0, y1=2.0, x2=3.0, y2=4.0)]


def test_parses_uarrow():
    src = "go\ngreen\nuarrow 1.0 100\n"
    plot = parse_xpl(src)
    assert plot.commands == [Arrow(color="green", x=1.0, y=100.0, direction="up")]


def test_parses_darrow_as_down_arrow():
    src = "go\nmagenta\ndarrow 2.0 200\n"
    plot = parse_xpl(src)
    assert plot.commands == [Arrow(color="magenta", x=2.0, y=200.0, direction="down")]


def test_parses_larrow():
    src = "go\nwhite\nlarrow 3.0 300\n"
    plot = parse_xpl(src)
    assert plot.commands == [Arrow(color="white", x=3.0, y=300.0, direction="left")]


def test_parses_rarrow():
    src = "go\norange\nrarrow 4.0 400\n"
    plot = parse_xpl(src)
    assert plot.commands == [Arrow(color="orange", x=4.0, y=400.0, direction="right")]


def test_parses_dot():
    src = "go\nwhite\ndot 5.5 55\n"
    plot = parse_xpl(src)
    assert plot.commands == [Dot(color="white", x=5.5, y=55.0)]


def test_parses_diamond():
    src = "go\norange\ndiamond 7.0 70\n"
    plot = parse_xpl(src)
    assert plot.commands == [Diamond(color="orange", x=7.0, y=70.0)]


def test_parses_utick():
    src = "go\ngreen\nutick 1.0 100\n"
    plot = parse_xpl(src)
    assert plot.commands == [Tick(color="green", x=1.0, y=100.0, kind="u")]


def test_parses_dtick():
    src = "go\nred\ndtick 2.0 200\n"
    plot = parse_xpl(src)
    assert plot.commands == [Tick(color="red", x=2.0, y=200.0, kind="d")]


def test_parses_ltick():
    src = "go\nblue\nltick 3.0 300\n"
    plot = parse_xpl(src)
    assert plot.commands == [Tick(color="blue", x=3.0, y=300.0, kind="l")]


def test_parses_rtick():
    src = "go\nwhite\nrtick 4.0 400\n"
    plot = parse_xpl(src)
    assert plot.commands == [Tick(color="white", x=4.0, y=400.0, kind="r")]


def test_parses_htick():
    src = "go\nyellow\nhtick 5.0 500\n"
    plot = parse_xpl(src)
    assert plot.commands == [Tick(color="yellow", x=5.0, y=500.0, kind="h")]


def test_parses_vtick():
    src = "go\nmagenta\nvtick 6.0 600\n"
    plot = parse_xpl(src)
    assert plot.commands == [Tick(color="magenta", x=6.0, y=600.0, kind="v")]


def test_parses_bare_tick():
    src = "go\ngreen\ntick 7.0 700\n"
    plot = parse_xpl(src)
    assert plot.commands == [Tick(color="green", x=7.0, y=700.0, kind="")]


def test_parses_atext_two_lines():
    src = "go\norange\natext 1.5 150\nSYN\n"
    plot = parse_xpl(src)
    assert plot.commands == [Text(color="orange", x=1.5, y=150.0, label="SYN")]


def test_parses_btext():
    src = "go\nwhite\nbtext 2 20\nlabel-below\n"
    plot = parse_xpl(src)
    assert plot.commands == [Text(color="white", x=2.0, y=20.0, label="label-below")]


def test_parses_ltext():
    src = "go\nwhite\nltext 3 30\nleft-anchored\n"
    plot = parse_xpl(src)
    assert plot.commands == [Text(color="white", x=3.0, y=30.0, label="left-anchored")]


def test_parses_rtext():
    src = "go\nwhite\nrtext 4 40\nright-anchored\n"
    plot = parse_xpl(src)
    assert plot.commands == [Text(color="white", x=4.0, y=40.0, label="right-anchored")]


def test_parses_ctext():
    src = "go\nwhite\nctext 5 50\ncentered\n"
    plot = parse_xpl(src)
    assert plot.commands == [Text(color="white", x=5.0, y=50.0, label="centered")]


def test_text_with_trailing_color():
    # Real owin xpls emit: `ltext x y <color>\n<label>`
    src = "go\nwhite\nltext 1436561105.402114 114 red\nowin\n"
    plot = parse_xpl(src)
    assert plot.commands == [Text(color="red", x=1436561105.402114, y=114.0, label="owin")]
    assert plot.unknown == []


def test_text_label_with_spaces_kept_verbatim():
    # tcptrace emits labels like 'SYN 2067359459:2067359459(0) win 8192 '
    src = "go\nwhite\nltext 40 -0.000597\n2067359460:2067359460(0) ack 2150890571 win 65536 \n"
    plot = parse_xpl(src)
    assert len(plot.commands) == 1
    label = plot.commands[0].label
    assert label == "2067359460:2067359460(0) ack 2150890571 win 65536"


def test_text_label_quoted_strips_quotes():
    src = 'go\nwhite\natext 1 1\n"R"\n'
    plot = parse_xpl(src)
    assert plot.commands == [Text(color="white", x=1.0, y=1.0, label="R")]


def test_invisible_is_dropped_not_unknown():
    src = "go\norange\ninvisible 0 -0.000000\ninvisible 100 -0.000000\nline 40 0 60 0\n"
    plot = parse_xpl(src)
    assert plot.commands == [Line(color="orange", x1=40.0, y1=0.0, x2=60.0, y2=0.0)]
    assert plot.unknown == []


def test_unknown_verb_collected():
    src = "go\nred\nweirdthing 1 2 3\n"
    plot = parse_xpl(src)
    assert plot.commands == []
    assert plot.unknown == ["weirdthing 1 2 3"]


def test_full_tsg_excerpt():
    # Lifted from a real tcptrace a2b_tsg.xpl, including stateful color flips,
    # text-with-label, trailing-color on dot/diamond, and arrows.
    src = """\
timeval double
title
100.99.98.101:49405_==>_100.99.98.97:80 (time sequence graph)
xlabel
time
ylabel
sequence number
white
orange
diamond 1436561105.401428 2067359459
atext 1436561105.401428 2067359460
SYN
uarrow 1436561105.401428 2067359460
line 1436561105.401428 2067359459 1436561105.401428 2067359460
white
darrow 1436561105.402025 2067359460
diamond 1436561105.402204 2067359686 white
dot 1436561105.402204 2067359686 white
line 1436561105.402204 2067359460 1436561105.402204 2067359686
green
line 1436561105.401963 2067359460 1436561105.402775 2067359460
go
"""
    plot = parse_xpl(src)
    assert plot.unknown == []
    assert plot.title.startswith("100.99.98.101:49405")
    assert plot.xlabel == "time"
    assert plot.ylabel == "sequence number"

    # First diamond uses 'orange' state.
    assert plot.commands[0] == Diamond(color="orange", x=1436561105.401428, y=2067359459.0)
    # Text from atext consumes the next line as label.
    text_cmds = [c for c in plot.commands if isinstance(c, Text)]
    assert len(text_cmds) == 1
    assert text_cmds[0].label == "SYN"
    # uarrow + darrow produce Arrows with up/down direction.
    arrow_dirs = sorted(c.direction for c in plot.commands if isinstance(c, Arrow))
    assert arrow_dirs == ["down", "up"]
    # Trailing 'white' on diamond/dot overrides current color (was 'white' already).
    trailing_white = [
        c for c in plot.commands if isinstance(c, (Dot, Diamond)) and c.color == "white"
    ]
    assert len(trailing_white) == 2
    # Final green line picks up the green state.
    green_lines = [c for c in plot.commands if isinstance(c, Line) and c.color == "green"]
    assert len(green_lines) == 1
