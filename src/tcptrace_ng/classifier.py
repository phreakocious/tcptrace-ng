"""Classify tcptrace text-output lines for color-coding.

Faithful Python port of the Perl regex chain in the original tcptrace-cgi.
"""

from __future__ import annotations

import re
from enum import Enum


class Class(Enum):
    GOOD = "good"
    BAD = "bad"
    LOOK = "look"
    NORMAL = "normal"


_SUPPRESS = re.compile(
    r"urgent data|zwnd probe|truncated |ttl stream |initial window"
)

_GOOD_PATTERNS = [
    re.compile(r"complete conn: yes"),
    re.compile(r"(req sack:\s+Y\s+){2}"),
    re.compile(r"(sacks sent:\s+0\s+){2}"),
    re.compile(r"(rexmt data \w+:\s+0\s+){2}"),
    re.compile(r"(max sack blk.*:\s+0\s+){2}"),
    re.compile(r"(sack pkts sent:\s+0\s+){2}"),
    re.compile(r"(dsack pkts sent:\s+0\s+){2}"),
    re.compile(r"(outoforder pkts:\s+0\s+){2}"),
    re.compile(r"(req 1323 ws.ts:\s+Y.Y\s+){2}"),
    re.compile(r"(missed data:\s+0 bytes\s+){2}"),
    re.compile(r"(zero win adv:\s+0 times\s+){2}"),
    re.compile(r"(SYN.FIN pkts sent:\s+1.1\s+){2}"),
    re.compile(r"(missed data:\s+NA\s+){2}"),
    re.compile(r"mss requested:\s+(\d+) bytes\s+mss requested:\s+\1\s"),
]

_BAD_PATTERNS = [
    re.compile(r"rexmt"),
    re.compile(r"WARNING"),
    re.compile(r"outoforder"),
    re.compile(r"hardware dups"),
    re.compile(r"adv wind scale:\s+0\s+"),
    re.compile(r"(req 1323 ws.ts:\s+N.N\s+)"),
]

_LOOK_PATTERNS = [
    re.compile(r"SYNs: 0"),
    re.compile(r"FINs: 0"),
    re.compile(r"max sack"),
    re.compile(r"req sack"),
    re.compile(r"sacks sent"),
    re.compile(r"resets sent"),
    re.compile(r"zero win adv"),
    re.compile(r"complete conn"),
    re.compile(r"mss requested"),
    re.compile(r"sack pkts sent"),
    re.compile(r"SYN.FIN pkts sent:\s+0.0\s"),
    re.compile(r"SYN.FIN pkts sent:\s+1.0\s"),
    re.compile(r"SYN.FIN pkts sent:\s+0.1\s"),
]

_WIN_SCALE = re.compile(r"adv wind scale:\s+(\d+)\s+adv wind scale:\s+(\d+)\s+")


def classify(line: str) -> Class | None:
    """Return the class for a tcptrace output line, or None if suppressed.

    Order matches the original Perl: suppress filter first, then good, then bad,
    then look, then the window-scale special case, otherwise NORMAL.

    The Perl original received lines via backtick iteration, so each line
    carried a trailing newline.  Several patterns rely on ``\\s+`` anchoring
    after the final token — we append ``\\n`` here to replicate that behaviour
    faithfully regardless of whether the caller strips the line.
    """
    # Normalise: ensure a trailing newline so patterns match as in Perl.
    if not line.endswith("\n"):
        line = line + "\n"

    if _SUPPRESS.search(line):
        return None

    for pat in _GOOD_PATTERNS:
        if pat.search(line):
            return Class.GOOD

    for pat in _BAD_PATTERNS:
        if pat.search(line):
            return Class.BAD

    for pat in _LOOK_PATTERNS:
        if pat.search(line):
            return Class.LOOK

    m = _WIN_SCALE.search(line)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        if a > 7 or b > 7:
            return Class.BAD
        if a != b:
            return Class.LOOK
        return Class.GOOD

    return Class.NORMAL
