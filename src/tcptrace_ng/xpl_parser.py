"""Parse xplot .xpl files emitted by tcptrace into XplPlot dataclasses.

Real tcptrace xpl format notes:

  - Header directives appear at the top as `<keyword>\\n<value>\\n` for
    title/xlabel/ylabel/xunits/yunits, plus a single inline directive line
    such as `timeval double` or `unsigned dtime` which we accept as
    metadata.
  - `go` (when present) marks the end of header.
  - Color is stateful: a bare color word on its own line sets the current
    color for subsequent commands until changed.
  - Commands may carry a trailing color token, overriding the current color
    for that one command (e.g. `dot 1 2 white`).
  - Direction is baked into arrow/text verbs:
      uarrow/darrow/larrow/rarrow      (up/down/left/right)
      atext/btext/ltext/rtext/ctext    (anchor; followed by label on next line)
  - Tick verbs: utick/dtick/ltick/rtick/htick/vtick plus bare `tick`.
  - `invisible x y` extends axis range without rendering — we drop these.

Pure module: input is text/bytes/path, output is data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Color = str
Direction = Literal["up", "down", "left", "right"]


@dataclass(frozen=True)
class Line:
    color: Color
    x1: float
    y1: float
    x2: float
    y2: float


@dataclass(frozen=True)
class DLine:
    color: Color
    x1: float
    y1: float
    x2: float
    y2: float


@dataclass(frozen=True)
class Box:
    color: Color
    x1: float
    y1: float
    x2: float
    y2: float


@dataclass(frozen=True)
class DBox:
    color: Color
    x1: float
    y1: float
    x2: float
    y2: float


@dataclass(frozen=True)
class Arrow:
    color: Color
    x: float
    y: float
    direction: Direction


@dataclass(frozen=True)
class Dot:
    color: Color
    x: float
    y: float


@dataclass(frozen=True)
class Diamond:
    color: Color
    x: float
    y: float


@dataclass(frozen=True)
class Tick:
    color: Color
    x: float
    y: float
    kind: Literal["u", "d", "l", "r", "h", "v", ""]


@dataclass(frozen=True)
class Text:
    color: Color
    x: float
    y: float
    label: str


XplCommand = Line | DLine | Box | DBox | Arrow | Dot | Diamond | Tick | Text


@dataclass
class XplPlot:
    title: str = ""
    xlabel: str = ""
    ylabel: str = ""
    xunits: str | None = None
    yunits: str | None = None
    timeval: str | None = None
    commands: list[XplCommand] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)


_HEADER_KEYS = {"title", "xlabel", "ylabel", "xunits", "yunits"}
_TIMEVAL_HEADS = {"timeval", "unsigned", "signed"}

_COLORS = {
    "white",
    "red",
    "green",
    "yellow",
    "blue",
    "magenta",
    "cyan",
    "orange",
    "purple",
    "pink",
    "black",
}

_LINE_LIKE: dict[str, type] = {"line": Line, "dline": DLine, "box": Box, "dbox": DBox}
_POINT_LIKE: dict[str, type] = {"dot": Dot, "diamond": Diamond}

_ARROW_DIRECTIONS: dict[str, Direction] = {
    "uarrow": "up",
    "darrow": "down",
    "larrow": "left",
    "rarrow": "right",
}

_TICK_KINDS = {
    "utick": "u",
    "dtick": "d",
    "ltick": "l",
    "rtick": "r",
    "htick": "h",
    "vtick": "v",
    "tick": "",
}

_TEXT_VERBS = {"atext", "btext", "ltext", "rtext", "ctext", "text"}


def parse_xpl(source: str | bytes | Path) -> XplPlot:
    """Parse an xpl source into XplPlot.

    Accepts a string, bytes, or a path. Bytes are decoded as utf-8 with errors
    replaced — xpl is ASCII in practice but be robust about it.
    """
    if isinstance(source, Path):
        text = source.read_text(encoding="utf-8", errors="replace")
    elif isinstance(source, bytes):
        text = source.decode("utf-8", errors="replace")
    else:
        text = source

    plot = XplPlot()
    lines = text.splitlines()
    n = len(lines)
    i = 0
    current_color: str = "white"

    while i < n:
        stripped = lines[i].rstrip("\r").strip()

        if not stripped:
            i += 1
            continue

        # Two-line header (keyword \n value)
        if stripped in _HEADER_KEYS:
            i += 1
            if i < n:
                value = lines[i].strip()
                setattr(plot, stripped, value)
                i += 1
            continue

        # Inline type/timeval directive at the top (e.g. "timeval double",
        # "unsigned dtime") — preserve raw text, don't treat as data.
        first = stripped.split(None, 1)[0]
        if first in _TIMEVAL_HEADS:
            plot.timeval = stripped
            i += 1
            continue

        # End-of-header marker (commands may also appear before `go`).
        if stripped == "go":
            i += 1
            continue

        # Bare color word — sets state for subsequent commands.
        if stripped in _COLORS:
            current_color = stripped
            i += 1
            continue

        parts = stripped.split()
        verb = parts[0]

        # Axis-range padding — drop silently.
        if verb == "invisible":
            i += 1
            continue

        # Text variants: `<verb> x y [color]` then a label line.
        if verb in _TEXT_VERBS:
            text_color = current_color
            text_parts = parts
            if len(text_parts) >= 2 and text_parts[-1] in _COLORS:
                text_color = text_parts[-1]
                text_parts = text_parts[:-1]
            cmd = _parse_text(text_parts, text_color, lines, i, n)
            if cmd is None:
                plot.unknown.append(stripped)
                i += 1
                continue
            plot.commands.append(cmd)
            i += 2
            continue

        # Other commands. Pop a trailing color if present.
        color = current_color
        if len(parts) >= 2 and parts[-1] in _COLORS:
            color = parts[-1]
            parts = parts[:-1]

        cmd = _parse_geometry(parts, color)
        if cmd is None:
            plot.unknown.append(stripped)
        else:
            plot.commands.append(cmd)
        i += 1

    return plot


def _parse_text(parts: list[str], color: str, lines: list[str], i: int, n: int) -> Text | None:
    if len(parts) != 3:
        return None
    try:
        x = float(parts[1])
        y = float(parts[2])
    except ValueError:
        return None
    if i + 1 >= n:
        return None
    raw = lines[i + 1].strip()
    label = raw[1:-1] if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2 else raw
    return Text(color=color, x=x, y=y, label=label)


def _parse_geometry(parts: list[str], color: str) -> XplCommand | None:
    verb = parts[0]
    rest = parts[1:]

    try:
        if verb in _LINE_LIKE and len(rest) == 4:
            cls = _LINE_LIKE[verb]
            return cls(color, float(rest[0]), float(rest[1]), float(rest[2]), float(rest[3]))
        if verb in _POINT_LIKE and len(rest) == 2:
            cls = _POINT_LIKE[verb]
            return cls(color, float(rest[0]), float(rest[1]))
        if verb in _ARROW_DIRECTIONS and len(rest) == 2:
            return Arrow(color, float(rest[0]), float(rest[1]), _ARROW_DIRECTIONS[verb])
        if verb in _TICK_KINDS and len(rest) == 2:
            return Tick(color, float(rest[0]), float(rest[1]), _TICK_KINDS[verb])
    except ValueError:
        return None
    return None
