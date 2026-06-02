"""Group tcptrace xpl files by metric and direction for the new tab layout.

tcptrace assigns letter pairs for direction labels: (a,b), (c,d), (e,f), …
through (y,z), then rolls over to two-letter pairs (aa,ab), (ac,ad), …
This module accepts any same-length letter pair and maps `<lo>2<hi>` →
forward, `<hi>2<lo>` → backward, `<lo>_<hi>_<metric>` → combined.

Pure module: input is Paths/strings, output is data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_METRICS = ("tsg", "tput", "rtt", "owin", "ssize", "tline")

_PAIR_RE = re.compile(r"^conn-\d+--([a-z]+)2([a-z]+)_(\w+)\.xpl$")
_COMBINED_RE = re.compile(r"^conn-\d+--([a-z]+)_([a-z]+)_(\w+)\.xpl$")


def parse_xpl_name(name: str) -> tuple[str, str] | None:
    """Return (metric, direction) or None for unknown shapes.

    direction is one of: "forward", "backward", "combined".
    """
    m = _PAIR_RE.match(name)
    if m:
        a, b, metric = m.group(1), m.group(2), m.group(3)
        if metric not in _METRICS:
            return None
        direction = "forward" if a < b else "backward"
        return (metric, direction)
    m = _COMBINED_RE.match(name)
    if m:
        metric = m.group(3)
        if metric not in _METRICS:
            return None
        return (metric, "combined")
    return None


@dataclass(frozen=True)
class GroupedXpl:
    metric: str
    forward: Path | None = None
    backward: Path | None = None
    combined: Path | None = None


def group_xpls(files: list[Path]) -> list[GroupedXpl]:
    by_metric: dict[str, dict[str, Path]] = {}
    for f in files:
        parsed = parse_xpl_name(f.name)
        if parsed is None:
            continue
        metric, direction = parsed
        by_metric.setdefault(metric, {})[direction] = f
    return [
        GroupedXpl(
            metric=m,
            forward=by_metric[m].get("forward"),
            backward=by_metric[m].get("backward"),
            combined=by_metric[m].get("combined"),
        )
        for m in _METRICS
        if m in by_metric
    ]
