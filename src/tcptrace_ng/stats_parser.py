"""Parse `tcptrace -l <pcap>` multi-connection output into ConnStats.

Pure module: input is text, output is a list of dataclasses. Designed to
mirror xpl_parser.py — fixtures lifted verbatim from real tcptrace output,
no imagined formats.

tcptrace cycles its per-direction host labels (a/b, c/d, e/f, ...). The
parser detects the pair from each block's header lines (`host X: ...` /
`host Y: ...`) instead of hardcoding `a/b`.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from .classifier import Class, classify

_BLOCK_RE = re.compile(
    r"^TCP connection (\d+):\s*\n(.*?)(?=^TCP connection \d+:|\Z)",
    re.DOTALL | re.MULTILINE,
)
_HOST_RE = re.compile(r"^\s*host\s+([a-z]):\s+(\S+)\s*$", re.MULTILINE)
_TOTAL_PKTS_RE = re.compile(r"^\s*total packets:\s+(\d+)\s+total packets:\s+(\d+)", re.MULTILINE)
_UNIQUE_BYTES_RE = re.compile(
    r"^\s*unique bytes sent:\s+(\d+)\s+unique bytes sent:\s+(\d+)", re.MULTILINE
)
_ELAPSED_RE = re.compile(r"^\s*elapsed time:\s+(\d+):(\d+):(\d+\.\d+)", re.MULTILINE)
_REXMT_RE = re.compile(r"^\s*rexmt data pkts:\s+(\d+)\s+rexmt data pkts:\s+(\d+)", re.MULTILINE)
_RESETS_RE = re.compile(r"^\s*resets sent:\s+(\d+)\s+resets sent:\s+(\d+)", re.MULTILINE)
_COMPLETE_RE = re.compile(r"^\s*complete conn:\s+yes\b", re.MULTILINE)
_SYNFIN_RE = re.compile(r"^\s*SYN/FIN pkts sent:\s+1/1\s+SYN/FIN pkts sent:\s+1/1", re.MULTILINE)
_SYNFIN_PAIR_RE = re.compile(
    r"^\s*SYN/FIN pkts sent:\s+(\d+)/\d+\s+SYN/FIN pkts sent:\s+(\d+)/\d+",
    re.MULTILINE,
)

_MSS_RE = re.compile(
    r"^\s*mss requested:\s+(\d+)\s+bytes\s+mss requested:\s+(\d+)\s+bytes",
    re.MULTILINE,
)
_WS_RE = re.compile(r"^\s*adv wind scale:\s+(\d+)\s+adv wind scale:\s+(\d+)", re.MULTILINE)
_SACK_RE = re.compile(r"^\s*req sack:\s+([YN])\s+req sack:\s+([YN])", re.MULTILINE)
_MAXWIN_RE = re.compile(
    r"^\s*max win adv:\s+(\d+)\s+bytes\s+max win adv:\s+(\d+)\s+bytes", re.MULTILINE
)
_THROUGHPUT_RE = re.compile(
    r"^\s*throughput:\s+(\d+)\s+Bps\s+throughput:\s+(\d+)\s+Bps", re.MULTILINE
)


# Per-direction context fields rendered into the chart subtitle. Each entry is
# (regex matching the paired line, formatter from one captured group). Returning
# None from the formatter drops the field for that direction (e.g. SACK=N).
_CTX_FIELDS: list[tuple[re.Pattern[str], Callable[[str], str | None]]] = [
    (_MSS_RE, lambda v: f"MSS {v}"),
    (_WS_RE, lambda v: f"ws {v}"),
    (_SACK_RE, lambda v: "SACK" if v == "Y" else None),
    (_MAXWIN_RE, lambda v: f"max win {v}"),
    (_THROUGHPUT_RE, lambda v: f"{v} Bps"),
]


def _duration_seconds(body: str) -> float:
    m = _ELAPSED_RE.search(body)
    if not m:
        return 0.0
    h, mins, secs = int(m.group(1)), int(m.group(2)), float(m.group(3))
    return h * 3600 + mins * 60 + secs


def _sum_pair(pattern: re.Pattern[str], body: str) -> int:
    m = pattern.search(body)
    if not m:
        return 0
    return int(m.group(1)) + int(m.group(2))


def _has_rst(body: str) -> bool:
    m = _RESETS_RE.search(body)
    if not m:
        return False
    return (int(m.group(1)) + int(m.group(2))) > 0


def _complete_handshake(body: str) -> bool:
    # Honor `complete conn: yes` OR both directions showing SYN/FIN 1/1.
    return bool(_COMPLETE_RE.search(body)) or bool(_SYNFIN_RE.search(body))


def _client_is_a(body: str) -> bool | None:
    m = _SYNFIN_PAIR_RE.search(body)
    if not m:
        return None
    a_syns, b_syns = int(m.group(1)), int(m.group(2))
    if a_syns > b_syns:
        return True
    if b_syns > a_syns:
        return False
    return None


def _verdict(body: str) -> Class:
    # Severity ordering per spec: BAD > LOOK > NORMAL > GOOD.
    # NORMAL lines carry no informative signal (host headers, separators,
    # direction labels), so they're skipped alongside suppressed lines.
    # Only GOOD/LOOK/BAD contribute. Cascading checks let GOOD win over the
    # NORMAL default when only GOOD signals are present.
    seen: set[Class] = set()
    for line in body.splitlines():
        cls = classify(line)
        if cls is None or cls is Class.NORMAL:
            continue
        seen.add(cls)
    if Class.BAD in seen:
        return Class.BAD
    if Class.LOOK in seen:
        return Class.LOOK
    if Class.GOOD in seen:
        return Class.GOOD
    return Class.NORMAL


@dataclass(frozen=True)
class ConnStats:
    n: int
    host_a: str
    host_b: str
    client_is_a: bool | None
    total_bytes: int
    total_packets: int
    duration_s: float
    rexmt_packets: int
    has_rst: bool
    complete_handshake: bool
    verdict: Class
    fwd_ctx: str
    bwd_ctx: str


def build_context_lines(body: str) -> tuple[str, str]:
    """Render terse per-direction TCP parameter strings for chart subtitles.

    Format mirrors tcptrace vocabulary: `MSS 1460 · ws 5 · SACK · max win 137088 · 96 Bps`.
    Missing fields are silently dropped; SACK is shown only when negotiated.
    Returns (forward, backward) — the caller decides which direction is client→server.
    """
    fwd_parts: list[str] = []
    bwd_parts: list[str] = []
    for pattern, fmt in _CTX_FIELDS:
        m = pattern.search(body)
        if not m:
            continue
        if fwd := fmt(m.group(1)):
            fwd_parts.append(fwd)
        if bwd := fmt(m.group(2)):
            bwd_parts.append(bwd)
    return " · ".join(fwd_parts), " · ".join(bwd_parts)


def parse_stats(text: str) -> list[ConnStats]:
    rows: list[ConnStats] = []
    for m in _BLOCK_RE.finditer(text):
        n = int(m.group(1))
        body = m.group(2)
        rows.append(_parse_block(n, body))
    return rows


def _parse_block(n: int, body: str) -> ConnStats:
    host_matches = list(_HOST_RE.finditer(body))
    host_a = host_matches[0].group(2) if len(host_matches) >= 1 else ""
    host_b = host_matches[1].group(2) if len(host_matches) >= 2 else ""
    fwd_ctx, bwd_ctx = build_context_lines(body)
    return ConnStats(
        n=n,
        host_a=host_a,
        host_b=host_b,
        client_is_a=_client_is_a(body),
        total_bytes=_sum_pair(_UNIQUE_BYTES_RE, body),
        total_packets=_sum_pair(_TOTAL_PKTS_RE, body),
        duration_s=_duration_seconds(body),
        rexmt_packets=_sum_pair(_REXMT_RE, body),
        has_rst=_has_rst(body),
        complete_handshake=_complete_handshake(body),
        verdict=_verdict(body),
        fwd_ctx=fwd_ctx,
        bwd_ctx=bwd_ctx,
    )
