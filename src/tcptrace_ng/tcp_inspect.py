"""Synthesize a TsgModel from parsed xpl + tcptrace -l text.

Pure module — no IO, no subprocess. Inputs are already-parsed structures from
xpl_parser and stats_parser; output is a TsgModel (per direction) that both
plotly_adapter.to_tsg_figure() and app.py's viewport stats panel consume.

The xpl is a drawing; this module turns it back into facts: segment-by-segment
classification, paired-RTT pairs, bytes-in-flight series, and an anomaly
catalog. tcptrace's `-l` long output supplies connection-level context
(window scale, MSS, throughput, RTT min/avg/max when `-r` is on).
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field, replace
from typing import Literal

from .stats_parser import ConnStats, parse_stats
from .xpl_parser import Arrow, Line, Text, Tick, XplPlot


@dataclass(frozen=True)
class Segment:
    time: float
    seq_start: int
    seq_end: int
    rtx: Literal[None, "rto", "fast", "spurious"]
    paired_ack_time: float | None
    paired_rtt_ms: float | None
    in_flight_after: int


@dataclass(frozen=True)
class Ack:
    time: float
    ack_seq: int
    rwin: int
    rwin_scaled: int | None
    sack_blocks: tuple[tuple[int, int], ...]
    dup_count: int
    # Whether the advertised window is known — i.e. a yellow rwin line was
    # co-timed with this ACK. When False, `rwin` is a placeholder (0), NOT a
    # real zero window; rwin-derived anomalies (zero_win / win_shrink) must skip
    # it rather than fire a false severe.
    rwin_known: bool = True


AnomalyKind = Literal[
    "rto",
    "fast",
    "spurious",
    "zero_win",
    "win_shrink",
    "win_shrink_large",
    "ooo",
    "sack_gap",
    "keepalive",
    "syn",
    "syn_ack",
    "handshake_ack",
    "fin",
    "fin_retx",
    "dup_ack",
    "dup_ack_drove_retx",
    "partial_ack",
    "coalesced",
    "bad_csum",
    "bad_csum_acked",
    "bad_csum_lost",
]

# Triage tier per kind. Drives chart color and default visibility (info is
# hidden unless the "show info" toggle is on). Severity is a presentation
# concern, not a model property — kept in tcp_inspect because the kind set
# itself encodes the triage decisions (e.g. dup_ack vs dup_ack_drove_retx).
AnomalySeverity = Literal["severe", "warn", "handshake", "info"]
SEVERITY_BY_KIND: dict[str, AnomalySeverity] = {
    "rto": "severe",
    "fast": "severe",
    "spurious": "severe",
    "zero_win": "severe",
    "win_shrink_large": "severe",
    "bad_csum_lost": "severe",
    "dup_ack_drove_retx": "warn",
    "ooo": "warn",
    "sack_gap": "warn",
    "bad_csum": "warn",
    "syn": "handshake",
    "syn_ack": "handshake",
    "handshake_ack": "handshake",
    "fin": "handshake",
    "fin_retx": "handshake",
    "win_shrink": "info",
    "dup_ack": "info",
    "partial_ack": "info",
    "coalesced": "info",
    "keepalive": "info",
    "bad_csum_acked": "info",
}


@dataclass(frozen=True)
class Anomaly:
    time: float
    kind: AnomalyKind
    one_liner: str
    seq_lo: int | None
    seq_hi: int | None


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, round((pct / 100.0) * (len(s) - 1))))
    return s[k]


@dataclass
class TsgModel:
    src: str = ""
    dst: str = ""
    direction: str = ""  # "a2b" / "b2a"
    segments: list[Segment] = field(default_factory=list)
    acks: list[Ack] = field(default_factory=list)
    in_flight: list[tuple[float, int]] = field(default_factory=list)
    anomalies: list[Anomaly] = field(default_factory=list)
    # Times of zero-payload packets from this direction's sender. Used in
    # post-processing to classify dup-ACK / partial-ACK against the opposite
    # direction's cumack staircase — the ACK *field* of a pure-ACK packet from
    # X is X's cumack of Y's data, which is the green staircase in the Y→X xpl.
    pure_ack_times: list[float] = field(default_factory=list)
    # Times where tcptrace drew a zero-length green vertical on this model's
    # staircase — i.e., this direction's acker sent an ACK whose ACK field
    # equaled the previous one (no advance). Combined with the opposite
    # direction's pure-ACK marker times, this distinguishes a truly-stalled
    # pure-ACK from a coincident-timestamp pure-ACK that advanced alongside a
    # data packet's ACK.
    non_advancing_ack_times: list[float] = field(default_factory=list)
    window_scale: int | None = None
    # The MSS that limits this direction's sender (the peer's advertised MSS),
    # or None when tcptrace -l gave no value. Used by diagnose's coalesced gate
    # to know whether the precise `coalesced` anomaly was possible.
    mss: int | None = None
    summary: ConnStats | None = None

    def window_stats(self, t0: float | None, t1: float | None) -> WindowStats:
        """Aggregate model contents into a WindowStats for the time range.
        Open bounds (None) mean unbounded on that side."""
        seg_times = [s.time for s in self.segments]
        ack_times = [a.time for a in self.acks]
        anomaly_times = [a.time for a in self.anomalies]

        def _slice(times: list[float], items: list, lo: float | None, hi: float | None):
            i = bisect.bisect_left(times, lo) if lo is not None else 0
            j = bisect.bisect_right(times, hi) if hi is not None else len(items)
            return items[i:j]

        segs = _slice(seg_times, self.segments, t0, t1)
        acks = _slice(ack_times, self.acks, t0, t1)
        anomalies = _slice(anomaly_times, self.anomalies, t0, t1)

        bytes_sent = sum(s.seq_end - s.seq_start for s in segs)
        n_rto = sum(1 for s in segs if s.rtx == "rto")
        n_fast = sum(1 for s in segs if s.rtx == "fast")
        n_retx = sum(1 for s in segs if s.rtx is not None)
        n_dup_ack = sum(1 for a in anomalies if a.kind in ("dup_ack", "dup_ack_drove_retx"))
        n_partial_ack = sum(1 for a in anomalies if a.kind == "partial_ack")
        n_coalesced = sum(1 for a in anomalies if a.kind == "coalesced")
        n_ooo = sum(1 for a in anomalies if a.kind == "ooo")
        n_sack_regions = sum(len(a.sack_blocks) for a in acks)
        n_win_shrink = sum(1 for a in anomalies if a.kind in ("win_shrink", "win_shrink_large"))
        n_zero_win = sum(1 for a in anomalies if a.kind == "zero_win")
        n_bad_csum = sum(1 for a in anomalies if a.kind.startswith("bad_csum"))
        n_bad_csum_acked = sum(1 for a in anomalies if a.kind == "bad_csum_acked")
        n_bad_csum_lost = sum(1 for a in anomalies if a.kind == "bad_csum_lost")

        rtts = [s.paired_rtt_ms for s in segs if s.paired_rtt_ms is not None]
        rtt_p50 = _percentile(rtts, 50)
        rtt_p95 = _percentile(rtts, 95)
        rtt_min = min(rtts) if rtts else None
        rtt_max = max(rtts) if rtts else None
        jitter: float | None
        if len(rtts) >= 2:
            mean = sum(rtts) / len(rtts)
            jitter = sum(abs(r - mean) for r in rtts) / len(rtts)
        else:
            jitter = None

        duration = max(0.0, segs[-1].time - segs[0].time) if segs else 0.0
        throughput = bytes_sent / duration if duration > 0 else 0.0

        rwin_peak = max((a.rwin_scaled or a.rwin) for a in acks) if acks else None

        return WindowStats(
            n_segs=len(segs),
            bytes_sent=bytes_sent,
            throughput_eff_Bps=throughput,
            n_retx=n_retx,
            n_rto=n_rto,
            n_fast=n_fast,
            n_dup_ack=n_dup_ack,
            n_partial_ack=n_partial_ack,
            n_coalesced=n_coalesced,
            n_ooo=n_ooo,
            n_sack_regions=n_sack_regions,
            rtt_p50_ms=rtt_p50,
            rtt_p95_ms=rtt_p95,
            rtt_min_ms=rtt_min,
            rtt_max_ms=rtt_max,
            jitter_ms=jitter,
            rwin_peak=rwin_peak,
            rwin_scale=self.window_scale,
            n_win_shrink=n_win_shrink,
            n_zero_win=n_zero_win,
            n_bad_csum=n_bad_csum,
            n_bad_csum_acked=n_bad_csum_acked,
            n_bad_csum_lost=n_bad_csum_lost,
        )


@dataclass
class TsgModelPair:
    fwd: TsgModel | None = None
    bwd: TsgModel | None = None


@dataclass(frozen=True)
class WindowStats:
    n_segs: int
    bytes_sent: int
    throughput_eff_Bps: float
    n_retx: int
    n_rto: int
    n_fast: int
    n_dup_ack: int
    n_ooo: int
    n_sack_regions: int
    rtt_p50_ms: float | None
    rtt_p95_ms: float | None
    rtt_min_ms: float | None
    rtt_max_ms: float | None
    jitter_ms: float | None
    rwin_peak: int | None
    rwin_scale: int | None
    n_win_shrink: int
    n_zero_win: int
    n_bad_csum: int = 0
    n_bad_csum_acked: int = 0
    n_bad_csum_lost: int = 0
    n_partial_ack: int = 0
    n_coalesced: int = 0


_TITLE_ENDPOINTS_RE = re.compile(r"^\s*(\S+?)\s*(?:_==>_|==>|_<==_|<==)\s*(\S+?)\s*(?:\(|$)")


def _parse_endpoints(title: str) -> tuple[str, str]:
    """Extract (src, dst) from a tsg title like
    '1.2.3.4:5 ==> 6.7.8.9:10 (time sequence graph)'.
    Returns ('', '') if the title doesn't match."""
    m = _TITLE_ENDPOINTS_RE.match(title)
    if not m:
        return "", ""
    return m.group(1), m.group(2)


_DATA_COLORS = {"white"}  # white = normal data
_RTX_COLOR = "red"


def _is_vertical(cmd: Line) -> bool:
    return cmd.x1 == cmd.x2


def _extract_segments(xpl: XplPlot) -> list[Segment]:
    """Pull data segments out of an xpl. White verticals are data; red verticals
    are retransmits with rtx initially set to "rto" as a placeholder that the
    retx sub-classifier refines.

    Orange verticals (SYN/FIN) are skipped: they're 1-byte sequence-space
    control markers, not data. Including them as Segments fed phantom send
    events into _compute_in_flight (sub-pixel in-flight spikes at SYN/FIN
    time, polluted pre_first_baseline) and produced bogus SYN→data RTT pairs.
    The orange diamond/box glyphs still render on the chart from the xpl
    directly — that path doesn't go through Segments.
    """
    raw: list[tuple[float, int, int, str | None]] = []
    for cmd in xpl.commands:
        if not isinstance(cmd, Line) or not _is_vertical(cmd):
            continue
        if cmd.color in _DATA_COLORS:
            rtx: str | None = None
        elif cmd.color == _RTX_COLOR:
            rtx = "rto"  # placeholder; refined in retx sub-classification
        else:
            continue
        seq_lo, seq_hi = sorted((int(cmd.y1), int(cmd.y2)))
        raw.append((cmd.x1, seq_lo, seq_hi, rtx))
    raw.sort(key=lambda r: r[0])
    return [
        Segment(
            time=t,
            seq_start=s_lo,
            seq_end=s_hi,
            rtx=rtx,  # type: ignore[arg-type]
            paired_ack_time=None,
            paired_rtt_ms=None,
            in_flight_after=0,
        )
        for (t, s_lo, s_hi, rtx) in raw
    ]


def _extract_acks(xpl: XplPlot) -> list[Ack]:
    """Pull ACK events out of an xpl by matching green vertical (cumack jump)
    steps to the yellow vertical at the same time (rwin top).

    Dup-ACK counts come from green `atext` labels: when a green atext bearing a
    bare integer (e.g. "3") appears at the same (x, y) as the next ack step's
    *origin*, it's the dup count for that ack.

    SACK blocks come from purple vertical lines (sack_left..sack_right at the
    report time) — attach to the ack at that time.
    """
    green_steps: list[tuple[float, int]] = []  # (time, new_ack_seq)
    green_zero: list[tuple[float, int]] = []  # zero-len verticals — kept for dup-ACK matching
    yellow_at_time: dict[float, int] = {}  # time -> rwin top seq
    dup_labels: dict[tuple[float, int], int] = {}  # (time, seq) -> N from atext
    sack_by_time: dict[float, list[tuple[int, int]]] = {}  # time -> [(lo, hi), ...]

    for cmd in xpl.commands:
        if isinstance(cmd, Line):
            if cmd.color == "green":
                if _is_vertical(cmd):
                    if cmd.y2 != cmd.y1:
                        green_steps.append((cmd.x1, int(max(cmd.y1, cmd.y2))))
                    else:
                        green_zero.append((cmd.x1, int(cmd.y1)))
            elif cmd.color == "yellow":
                # The rwin track is a step function. tcptrace emits the
                # vertical as `line x OLD x NEW` (trace.c:2345), so y2 is the
                # post-step level — using max() returned OLD on shrinks. The
                # bracketing horizontal carries the OLD level at both
                # endpoints; record those via setdefault so a later vertical
                # at the same x can override with the new level. Horizontal
                # endpoints are also the only signal when the rwin doesn't
                # change between two ACKs (tcptrace omits the vertical then).
                if _is_vertical(cmd):
                    yellow_at_time[cmd.x1] = int(cmd.y2)
                else:
                    yellow_at_time.setdefault(cmd.x1, int(cmd.y1))
                    yellow_at_time.setdefault(cmd.x2, int(cmd.y2))
            elif cmd.color == "purple" and _is_vertical(cmd):
                # Each SACK block is a purple vertical line spanning
                # sack_left..sack_right at the report time (tcptrace draws it with
                # plotter_line + hticks, NOT a box — the box glyph is the 2-coord
                # FIN marker — and in purple, not yellow; trace.c:127,2398-2412).
                lo, hi = sorted((int(cmd.y1), int(cmd.y2)))
                sack_by_time.setdefault(cmd.x1, []).append((lo, hi))
        elif isinstance(cmd, Tick) and cmd.color == "yellow":
            # utick/dtick on the rwin track marks the level at a specific
            # time (one is emitted at every ACK, even when the rwin doesn't
            # change). Fallback when no Line endpoint already recorded it.
            yellow_at_time.setdefault(cmd.x, int(cmd.y))
        elif isinstance(cmd, Text) and cmd.color == "green":
            label = cmd.label.strip()
            if label.isdigit():
                dup_labels[(cmd.x, int(cmd.y))] = int(label)

    # Promote zero-length green verticals to ACK events when they carry a dup label.
    seen: set[tuple[float, int]] = set(green_steps)
    for t, seq in green_zero:
        if (t, seq) in dup_labels and (t, seq) not in seen:
            green_steps.append((t, seq))
            seen.add((t, seq))

    acks: list[Ack] = []
    for t, ack_seq in green_steps:
        rwin_top = yellow_at_time.get(t)
        rwin_known = rwin_top is not None
        rwin = rwin_top - ack_seq if rwin_known else 0
        dup = dup_labels.get((t, ack_seq), 0)
        acks.append(
            Ack(
                time=t,
                ack_seq=ack_seq,
                rwin=rwin,
                rwin_scaled=None,
                sack_blocks=tuple(sorted(sack_by_time.get(t, []))),
                dup_count=dup,
                rwin_known=rwin_known,
            )
        )
    acks.sort(key=lambda a: a.time)
    return acks


def _compute_in_flight(
    segments: list[Segment], acks: list[Ack]
) -> tuple[list[tuple[float, int]], list[Segment]]:
    """Walk segments + acks in time order, tracking max(seq_sent) and max(seq_acked).
    Returns the (time, in_flight) series and a new segments list with
    in_flight_after stamped.

    Pure replay — assumes inputs are already time-sorted.
    """
    events: list[tuple[float, str, int, int]] = []
    for i, s in enumerate(segments):
        events.append((s.time, "send", s.seq_end, i))
    for a in acks:
        events.append((a.time, "ack", a.ack_seq, -1))
    # Sends sort before acks at the same instant — a send at t followed by an
    # ack at t should show in_flight rising then falling.
    events.sort(key=lambda e: (e[0], 0 if e[1] == "send" else 1))

    series: list[tuple[float, int]] = []
    new_segs: list[Segment | None] = [None] * len(segments)
    # Seed max_acked with the baseline seq (earliest seq_start) so the initial
    # in-flight delta is relative to the connection's ISN+1, not absolute zero.
    baseline = min((s.seq_start for s in segments), default=0)
    max_sent = baseline
    max_acked = baseline

    for t, kind, val, idx in events:
        if kind == "send":
            max_sent = max(max_sent, val)
        else:
            max_acked = max(max_acked, val)
        in_flight = max(0, max_sent - max_acked)
        series.append((t, in_flight))
        if kind == "send":
            s = segments[idx]
            new_segs[idx] = Segment(
                time=s.time,
                seq_start=s.seq_start,
                seq_end=s.seq_end,
                rtx=s.rtx,
                paired_ack_time=s.paired_ack_time,
                paired_rtt_ms=s.paired_rtt_ms,
                in_flight_after=in_flight,
            )
    return series, [s for s in new_segs if s is not None]


def _pair_rtt(segments: list[Segment], acks: list[Ack]) -> list[Segment]:
    """Karn-safe seq-pair RTT: each non-retx segment pairs with the first ACK
    whose ack_seq >= seg.seq_end and whose time > seg.time. Returns a new
    segments list with paired_ack_time / paired_rtt_ms filled in.
    """
    if not acks:
        return segments
    ack_times = [a.time for a in acks]  # already sorted by Task 4 / 5
    out: list[Segment] = []
    for s in segments:
        if s.rtx is not None:
            out.append(s)
            continue
        # First ack with time strictly > s.time
        start = bisect.bisect_right(ack_times, s.time)
        matched: Ack | None = None
        for a in acks[start:]:
            if a.ack_seq >= s.seq_end:
                matched = a
                break
        if matched is None:
            out.append(s)
            continue
        rtt_ms = (matched.time - s.time) * 1000.0
        out.append(
            Segment(
                time=s.time,
                seq_start=s.seq_start,
                seq_end=s.seq_end,
                rtx=s.rtx,
                paired_ack_time=matched.time,
                paired_rtt_ms=rtt_ms,
                in_flight_after=s.in_flight_after,
            )
        )
    return out


_DEFAULT_RTT_WINDOW_S = 0.050


def _median_rtt_seconds(segments: list[Segment]) -> float:
    rtts = sorted(s.paired_rtt_ms for s in segments if s.paired_rtt_ms is not None)
    if not rtts:
        return _DEFAULT_RTT_WINDOW_S
    mid = rtts[len(rtts) // 2]
    return mid / 1000.0


def _classify_retx(segments: list[Segment], acks: list[Ack]) -> list[Segment]:
    """Refine each rtx="rto" placeholder to rto / fast / spurious."""
    if not segments:
        return segments

    rtt_window = _median_rtt_seconds(segments)
    ack_times = [a.time for a in acks]
    out: list[Segment] = []

    for s in segments:
        if s.rtx is None:
            out.append(s)
            continue

        # Spurious: any ACK earlier than the retx whose ack_seq >= seq_end.
        idx = bisect.bisect_left(ack_times, s.time)
        spurious = any(a.ack_seq >= s.seq_end for a in acks[:idx])

        if spurious:
            new_rtx: str = "spurious"
        else:
            # Fast: ≥3 dup-ACKs in (s.time - rtt_window, s.time).
            dup_sum = sum(a.dup_count for a in acks if s.time - rtt_window < a.time < s.time)
            new_rtx = "fast" if dup_sum >= 3 else "rto"

        out.append(
            Segment(
                time=s.time,
                seq_start=s.seq_start,
                seq_end=s.seq_end,
                rtx=new_rtx,  # type: ignore[arg-type]
                paired_ack_time=s.paired_ack_time,
                paired_rtt_ms=s.paired_rtt_ms,
                in_flight_after=s.in_flight_after,
            )
        )
    return out


def _detect_anomalies(
    segments: list[Segment], acks: list[Ack], mss: int | None = None
) -> list[Anomaly]:
    """Catalog anomalies from already-classified segments + acks.

    Rules per spec:
      rto / fast / spurious  ← from Segment.rtx
      zero_win               ← Ack.rwin == 0
      win_shrink / win_shrink_large
                             ← rwin_now < rwin_prev (after accounting for
                               delta_acked). Promoted to win_shrink_large
                               when the shrink amount is at least one MSS,
                               which is the threshold at which the receiver
                               loses room for a whole segment in flight.
                               Without MSS the cosmetic noise is unfiltered.
      ooo                    ← seg.seq_start < max(seq_end seen so far in time order)
      sack_gap               ← any sack block whose lo > current cumack
      keepalive              ← zero-payload seg whose seq_end < highest_acked
    """
    out: list[Anomaly] = []

    # rtx-derived
    for s in segments:
        if s.rtx is None:
            continue
        out.append(
            Anomaly(
                time=s.time,
                kind=s.rtx,  # type: ignore[arg-type]
                one_liner=f"{s.rtx} retransmit seq {s.seq_start:,}..{s.seq_end:,}",
                seq_lo=s.seq_start,
                seq_hi=s.seq_end,
            )
        )

    # rwin-derived
    prev_rwin: int | None = None
    prev_ack: int | None = None
    for a in acks:
        # rwin-derived anomalies only when the window is known (a yellow rwin
        # line was co-timed). An unknown window carries a placeholder rwin=0 —
        # treating that as a real zero/shrink fires a false severe. Unknown acks
        # also don't update the shrink baseline.
        if a.rwin_known:
            if a.rwin == 0:
                out.append(
                    Anomaly(
                        time=a.time,
                        kind="zero_win",
                        one_liner="receiver advertised zero window",
                        seq_lo=a.ack_seq,
                        seq_hi=a.ack_seq,
                    )
                )
            if prev_rwin is not None and prev_ack is not None:
                delta_acked = max(0, a.ack_seq - prev_ack)
                if a.rwin < prev_rwin - delta_acked:
                    # Position the annotation on the new rwin top (yellow line) at
                    # this time so the y-axis doesn't autorange down to 0 — there's
                    # no data there, just empty space.
                    rwin_top = a.ack_seq + a.rwin
                    shrink_bytes = prev_rwin - delta_acked - a.rwin
                    kind = (
                        "win_shrink_large"
                        if mss is not None and shrink_bytes >= mss
                        else "win_shrink"
                    )
                    out.append(
                        Anomaly(
                            time=a.time,
                            kind=kind,
                            one_liner=f"window shrunk by {shrink_bytes:,} B",
                            seq_lo=rwin_top,
                            seq_hi=rwin_top,
                        )
                    )
            prev_rwin = a.rwin
            prev_ack = a.ack_seq
        # SACK gap is seq-derived (independent of the rwin line) — applies to any ack.
        for lo, hi in a.sack_blocks:
            if lo > a.ack_seq:
                out.append(
                    Anomaly(
                        time=a.time,
                        kind="sack_gap",
                        one_liner=(f"SACK {lo:,}..{hi:,}; gap {a.ack_seq:,}..{lo:,} unacked"),
                        seq_lo=lo,
                        seq_hi=hi,
                    )
                )

    # OOO: walk segments in time order, track highest seq_end seen.
    max_seen = 0
    for s in segments:
        if s.rtx is not None:
            # Retx isn't OOO; skip.
            max_seen = max(max_seen, s.seq_end)
            continue
        if s.seq_start < max_seen:
            out.append(
                Anomaly(
                    time=s.time,
                    kind="ooo",
                    one_liner=(
                        f"out-of-order seq {s.seq_start:,}..{s.seq_end:,} (below max seen {max_seen:,})"
                    ),
                    seq_lo=s.seq_start,
                    seq_hi=s.seq_end,
                )
            )
        max_seen = max(max_seen, s.seq_end)

    # Keepalive: zero-payload (seq_end == seq_start) below highest cumack.
    highest_ack = max((a.ack_seq for a in acks), default=0)
    for s in segments:
        if s.seq_end == s.seq_start and s.seq_end < highest_ack:
            out.append(
                Anomaly(
                    time=s.time,
                    kind="keepalive",
                    one_liner=f"keepalive at seq {s.seq_start:,}",
                    seq_lo=s.seq_start,
                    seq_hi=s.seq_end,
                )
            )

    out.sort(key=lambda a: a.time)
    return out


_FLAG_LABELS = {
    "SYN": "syn",
    "FIN": "fin",
    "R FIN": "fin_retx",
}

_FLAG_ONE_LINER = {
    "syn": "SYN (initiator)",
    "syn_ack": "SYN/ACK (handshake reply)",
    "handshake_ack": "ACK (handshake completion)",
    "fin": "FIN/ACK",
    "fin_retx": "retransmitted FIN/ACK",
}


def _extract_flag_events(
    xpl: XplPlot, direction: str, client_is_a: bool | None = None
) -> list[Anomaly]:
    """Pull SYN/FIN/R FIN events out of `atext`/`btext`/… labels.

    tcptrace marks every SYN-bearing segment with an anchored text "SYN"
    above the segment top, every FIN with "FIN", and retransmitted FINs
    with "R FIN" (red color). The seq at the text label is the segment top
    (seq + 1 for SYN/FIN, since both consume one byte of sequence space).

    The "SYN" label in tcptrace's xpl is direction-agnostic; the SYN/ACK is the
    responder's (server's) SYN. The server's direction is b2a when the client is
    a, a2b when the client is b — so we promote the SYN to `syn_ack` on the
    server's direction, falling back to the common a-initiates assumption (b2a is
    the SYN/ACK) when the client side is unknown.
    """
    server_dir = "a2b" if client_is_a is False else "b2a"
    out: list[Anomaly] = []
    for cmd in xpl.commands:
        if not isinstance(cmd, Text):
            continue
        kind = _FLAG_LABELS.get(cmd.label.strip())
        if kind is None:
            continue
        if kind == "syn" and direction == server_dir:
            kind = "syn_ack"
        seq = int(cmd.y)
        out.append(
            Anomaly(
                time=cmd.x,
                kind=kind,  # type: ignore[arg-type]
                one_liner=_FLAG_ONE_LINER[kind],
                seq_lo=seq,
                seq_hi=seq,
            )
        )
    return out


def _extract_non_advancing_ack_times(xpl: XplPlot) -> list[float]:
    """Times where tcptrace marked an ACK event that did not advance cumack.

    In tcptrace's TSG xpl, each ACK arrival emits a `green` command pair: a
    horizontal segment at the prior cumack, then a vertical step (advancing
    if cumack moved, or a degenerate `line t y t y` "point" if it didn't).
    When multiple ACK events land at the same wall-clock timestamp, tcptrace
    chains them by also emitting a "point" between consecutive advancing
    verticals — purely a drawing connector, NOT a real non-advancing event.

    Distinguishing the two: a zero-length point is a real non-advancing ACK
    iff the *previous* green command was NOT an advancing vertical. The
    horizontal-then-point sequence means cumack was stable and another ACK
    just arrived at the same value; advance-then-point is the connector
    bridging two advancing ACKs at the same instant.
    """
    out: list[float] = []
    prev_was_advance = False
    for cmd in xpl.commands:
        if not (isinstance(cmd, Line) and cmd.color == "green"):
            continue
        is_zero = cmd.x1 == cmd.x2 and cmd.y1 == cmd.y2
        is_advance = cmd.x1 == cmd.x2 and cmd.y1 != cmd.y2
        if is_zero and not prev_was_advance:
            out.append(cmd.x1)
        prev_was_advance = is_advance
    out.sort()
    return out


def _extract_pure_ack_times(xpl: XplPlot) -> list[float]:
    """Times of zero-payload packets from this xpl's sender side.

    In tcptrace's TSG, a sender's pure-ACK packet (no payload) is drawn as a
    white `darrow X Y` + `uarrow X Y` at the *same* point, with no vertical
    white line attached — a zero-height "segment" at the sender's current seq.
    A darrow/uarrow pair that coincides with a white vertical line endpoint
    is the tip/tail of a data segment and is excluded.

    Multiple packets at the same wall-clock timestamp produce repeated
    darrow/uarrow pairs at the same (x, y). To preserve per-packet count we
    walk arrows in source order and pair each darrow with the next unmatched
    uarrow at the same point; each completed pair is one packet.
    """
    line_endpoints: set[tuple[float, int]] = set()
    for cmd in xpl.commands:
        if isinstance(cmd, Line) and cmd.color == "white" and cmd.x1 == cmd.x2:
            line_endpoints.add((cmd.x1, int(cmd.y1)))
            line_endpoints.add((cmd.x2, int(cmd.y2)))

    pending_up: dict[tuple[float, int], int] = {}
    pending_down: dict[tuple[float, int], int] = {}
    times: list[float] = []
    for cmd in xpl.commands:
        if not (isinstance(cmd, Arrow) and cmd.color == "white"):
            continue
        key = (cmd.x, int(cmd.y))
        if key in line_endpoints:
            continue
        if cmd.direction == "up":
            if pending_down.get(key, 0) > 0:
                pending_down[key] -= 1
                times.append(cmd.x)
            else:
                pending_up[key] = pending_up.get(key, 0) + 1
        else:  # "down"
            if pending_up.get(key, 0) > 0:
                pending_up[key] -= 1
                times.append(cmd.x)
            else:
                pending_down[key] = pending_down.get(key, 0) + 1
    times.sort()
    return times


def _classify_pure_acks(pure_ack_times: list[float], opp: TsgModel) -> list[Anomaly]:
    """Classify each pure-ACK marker time against the opposite direction's
    cumack staircase + data flow.

    Args:
        pure_ack_times: times of zero-payload packets sent by side X.
        opp: the Y→X model — `opp.acks` is X's cumack of Y's data (the green
            staircase the pure-ACK is updating), `opp.segments` is Y's data
            that's being acked.

    Returns anomalies of kind `dup_ack` or `partial_ack`:

      dup_ack: the pure-ACK is at a time where no advancing cumack event
        landed — its ACK field equals the previous ACK from this side.

      partial_ack: the pure-ACK advances cumack but the new value is still
        below the highest seq Y has sent — analog of Wireshark's
        `tcp.analysis.partial_ack`.

    The two are mutually exclusive (Wireshark's logic too).
    """
    if not pure_ack_times or not opp.acks:
        return []

    ack_times = [a.time for a in opp.acks]
    ack_seqs = [a.ack_seq for a in opp.acks]
    non_advancing = set(opp.non_advancing_ack_times)

    sorted_segs = sorted(opp.segments, key=lambda s: s.time)
    seg_times = [s.time for s in sorted_segs]
    running_max: list[int] = []
    cur = 0
    for s in sorted_segs:
        cur = max(cur, s.seq_end)
        running_max.append(cur)

    out: list[Anomaly] = []
    for t in sorted(pure_ack_times):
        if t in non_advancing:
            # Non-advancing green event at this time → ACK field equals the
            # previous one → duplicate ACK. The cumack value the sender saw
            # is the last advancing one strictly before t.
            prev_i = bisect.bisect_left(ack_times, t) - 1
            if prev_i < 0:
                continue
            cumack = ack_seqs[prev_i]
            out.append(
                Anomaly(
                    time=t,
                    kind="dup_ack",
                    one_liner=f"duplicate ACK at seq {cumack:,}",
                    seq_lo=cumack,
                    seq_hi=cumack,
                )
            )
            continue
        # Not a dup; check whether this pure-ACK advanced cumack and, if so,
        # whether it left data still outstanding (partial-ACK).
        i = bisect.bisect_right(ack_times, t) - 1
        if i < 0:
            continue
        cumack = ack_seqs[i]
        j = bisect.bisect_right(seg_times, t) - 1
        max_sent = running_max[j] if j >= 0 else 0
        # cumack trailing max_sent is the normal state of any pipelined transfer
        # (the sender stays ahead of the ACKs), so it is NOT on its own a
        # partial ACK. Wireshark's tcp.analysis.partial_ack fires only during
        # loss recovery; gate on a recovery context — an outstanding retransmit
        # (a rtx segment whose bytes aren't yet cumulatively acked) or an open
        # SACK gap at the governing ACK.
        in_recovery = bool(opp.acks[i].sack_blocks) or any(
            s.rtx is not None and s.time <= t and s.seq_end > cumack for s in opp.segments
        )
        if cumack < max_sent and in_recovery:
            out.append(
                Anomaly(
                    time=t,
                    kind="partial_ack",
                    one_liner=(f"partial ACK at seq {cumack:,} (max sent {max_sent:,})"),
                    seq_lo=cumack,
                    seq_hi=cumack,
                )
            )
    return out


def _detect_coalesced(segments: list[Segment], mss: int | None) -> list[Anomaly]:
    """Emit a `coalesced` anomaly for each segment whose payload exceeds MSS.

    On modern Linux/BSD stacks NIC offload (LSO/GSO/TSO on TX, LRO/GRO on RX)
    hands a single fat "segment" to the kernel before slicing it into MSS-sized
    frames on the wire. tcptrace sees the pre-slice frame and draws a tall
    white vertical — useful to surface because it distorts MSS-relative
    reasoning (retx detection, in-flight tracking, RTT pairing on per-MSS
    granularity).
    """
    if mss is None or mss <= 0:
        return []
    out: list[Anomaly] = []
    for s in segments:
        size = s.seq_end - s.seq_start
        if size > mss:
            out.append(
                Anomaly(
                    time=s.time,
                    kind="coalesced",
                    one_liner=f"coalesced segment {size:,} B (> MSS {mss:,})",
                    seq_lo=s.seq_start,
                    seq_hi=s.seq_end,
                )
            )
    return out


def _suppress_overlapping_retx(
    anomalies: list[Anomaly], fin_retx_times: set[float]
) -> list[Anomaly]:
    """Drop rto/spurious/fast anomalies whose time matches a fin_retx — those
    segments are FIN retransmits, better labeled as such. Without this we'd
    double-paint "⚠ RTO" and "R FIN" on the same point.
    """
    return [
        a
        for a in anomalies
        if not (a.kind in ("rto", "fast", "spurious") and a.time in fin_retx_times)
    ]


def _clear_suppressed_retx(segments: list[Segment], fin_retx_times: set[float]) -> list[Segment]:
    """Clear the generic retx flag on segments reclassified as fin_retx.

    A FIN retransmit is surfaced as a `fin_retx` anomaly, not an rto/fast. If we
    leave Segment.rtx set, window_stats (n_rto/n_retx) and throughput's
    retx-overhead still count it as a generic retransmit — so the stats panel
    shows a bad-colored "1 RTO" that the chart's fin_retx marker contradicts.
    """
    if not fin_retx_times:
        return segments
    return [
        replace(s, rtx=None)
        if s.rtx in ("rto", "fast", "spurious") and s.time in fin_retx_times
        else s
        for s in segments
    ]


_BAD_CSUM_ONE_LINER = {
    "bad_csum": "bad TCP checksum",
    "bad_csum_acked": "bad TCP checksum — seq ACKed (likely NIC offload)",
    "bad_csum_lost": "bad TCP checksum — seq retransmitted (likely lost)",
}


def _classify_bad_csum(t: float, segments: list[Segment], acks: list[Ack]) -> str:
    """Decide whether a bad-csum event at time `t` was a real drop or a
    harmless capture artifact (typically NIC TX checksum offload).

      acked  → there's an original (non-retx) segment at this time and the
               cumulative ack later covers its `seq_end` with no retx of the
               same range. The receiver got the data; whatever broke the
               on-wire checksum was upstream of where it counted.
      lost   → the segment at this time was followed by a retransmit covering
               the same seq range. The original was dropped.
      bad_csum (unknown) → no segment matches (pure ACK, SYN/FIN-only frame),
               or the connection ended before the cumack reached this seq.

    The time match has to be exact-ish — `bisect` on segment times rather than
    a tolerance, because each xpl seg's time comes from the same pcap reader
    timestamps that produced the CsumEvent. Off by μs would mean we're
    matching two different packets.
    """
    if not segments:
        return "bad_csum"
    seg_times = [s.time for s in segments]
    i = bisect.bisect_left(seg_times, t)
    seg: Segment | None = None
    if i < len(segments) and seg_times[i] == t:
        seg = segments[i]
    if seg is None or seg.rtx is not None:
        # No matching segment, or this event IS already a retransmit — fall
        # back to unknown rather than recursively classifying.
        return "bad_csum"
    # Was the same seq range retransmitted later?
    for other in segments:
        if (
            other.rtx is not None
            and other.time > seg.time
            and other.seq_start <= seg.seq_start
            and other.seq_end >= seg.seq_end
        ):
            return "bad_csum_lost"
    # Did the cumulative ack eventually cover it?
    max_ack = max((a.ack_seq for a in acks), default=0)
    if seg.seq_end <= max_ack:
        return "bad_csum_acked"
    return "bad_csum"


def _bad_csum_anomalies(
    times: list[float] | None, segments: list[Segment], acks: list[Ack]
) -> list[Anomaly]:
    """Build bad_csum anomalies anchored to the cumulative-ack seq at each
    event time so the label lands on the plotted data band rather than at
    sequence 0 (which would force the y-axis to autorange down to zero and
    push the actual data into a thin sliver at the top)."""
    if not times:
        return []
    ack_times = [a.time for a in acks]
    ack_seqs = [a.ack_seq for a in acks]
    # Pre-first-ack anchor: the lowest seq we've sent (≈ ISN+1). Falls back to
    # the first ack value when there's no segment data either, and finally 0.
    pre_ack_baseline = min(
        (s.seq_start for s in segments),
        default=(acks[0].ack_seq if acks else 0),
    )
    out: list[Anomaly] = []
    for t in times:
        if ack_times:
            i = bisect.bisect_right(ack_times, t) - 1
            seq = ack_seqs[i] if i >= 0 else pre_ack_baseline
        else:
            seq = pre_ack_baseline
        kind = _classify_bad_csum(t, segments, acks)
        out.append(
            Anomaly(
                time=t,
                kind=kind,  # type: ignore[arg-type]
                one_liner=_BAD_CSUM_ONE_LINER[kind],
                seq_lo=seq,
                seq_hi=seq,
            )
        )
    return out


def _build_model(
    xpl: XplPlot,
    direction: str,
    *,
    bad_csum_times: list[float] | None = None,
    mss: int | None = None,
    window_scale: int | None = None,
    summary: ConnStats | None = None,
) -> TsgModel:
    src, dst = _parse_endpoints(xpl.title)
    segs = _extract_segments(xpl)
    acks = _extract_acks(xpl)
    in_flight, segs = _compute_in_flight(segs, acks)
    segs = _pair_rtt(segs, acks)
    segs = _classify_retx(segs, acks)
    anomalies = _detect_anomalies(segs, acks, mss)
    flag_events = _extract_flag_events(
        xpl, direction, client_is_a=summary.client_is_a if summary else None
    )
    fin_retx_times = {a.time for a in flag_events if a.kind == "fin_retx"}
    anomalies = _suppress_overlapping_retx(anomalies, fin_retx_times)
    segs = _clear_suppressed_retx(segs, fin_retx_times)
    anomalies = sorted(
        anomalies
        + flag_events
        + _detect_coalesced(segs, mss)
        + _bad_csum_anomalies(bad_csum_times, segs, acks),
        key=lambda a: a.time,
    )
    return TsgModel(
        src=src,
        dst=dst,
        direction=direction,
        segments=segs,
        acks=acks,
        in_flight=in_flight,
        anomalies=anomalies,
        pure_ack_times=_extract_pure_ack_times(xpl),
        non_advancing_ack_times=_extract_non_advancing_ack_times(xpl),
        window_scale=window_scale,
        mss=mss,
        summary=summary,
    )


def synthesize(
    xpl_fwd: XplPlot | None,
    xpl_bwd: XplPlot | None,
    details_text: str,
    *,
    bad_csum_times_fwd: list[float] | None = None,
    bad_csum_times_bwd: list[float] | None = None,
) -> TsgModelPair:
    """Build a TsgModelPair from parsed xpl(s) and tcptrace -l text.

    Either direction may be None when tcptrace emitted no segments for it
    (e.g. a unidirectional flow). `details_text` may be empty when -l output
    was unavailable; the model degrades gracefully (summary stays None,
    MSS- and wscale-derived behavior turns off).

    `bad_csum_times_fwd`/`bad_csum_times_bwd` are wall-clock epoch times of
    packets whose TCP checksum failed verification — supplied by the caller
    (typically `csum.scan_pcap` post-filtered to the connection's endpoint
    pair). Each time becomes a `bad_csum` anomaly on the matching direction's
    TSG.

    Dup-ACK / partial-ACK classification needs both directions: the ACK
    *field* of a pure-ACK packet from side X is X's cumack of Y's data,
    visible only on the Y→X xpl's staircase. So pure-ACK times are stamped
    on the sender's model during the per-direction build, then a post-pass
    cross-classifies them and attaches resulting anomalies to the *opposite*
    model — the direction whose data flow is being acked. That keeps the
    annotations co-located with the data they describe (e.g., server's
    dup-ACKs of client data show up on the a→b TSG).
    """
    # MSS / wscale that LIMIT direction X→Y are what Y advertised (Y's
    # receive MSS / Y's rwin scale shift). tcptrace's `-l` reports each
    # host's *advertised* value per column.
    summary = next(iter(parse_stats(details_text)), None) if details_text else None
    mss_a = summary.mss_a if summary else None
    mss_b = summary.mss_b if summary else None
    wscale_a = summary.wscale_a if summary else None
    wscale_b = summary.wscale_b if summary else None
    fwd = (
        _build_model(
            xpl_fwd,
            "a2b",
            bad_csum_times=bad_csum_times_fwd,
            mss=mss_b,
            window_scale=wscale_b,
            summary=summary,
        )
        if xpl_fwd is not None
        else None
    )
    bwd = (
        _build_model(
            xpl_bwd,
            "b2a",
            bad_csum_times=bad_csum_times_bwd,
            mss=mss_a,
            window_scale=wscale_a,
            summary=summary,
        )
        if xpl_bwd is not None
        else None
    )
    if fwd is not None and bwd is not None:
        # b's pure-ACKs (in bwd) ack a's data (in fwd) → annotate fwd.
        b_pure_anoms = _classify_pure_acks(bwd.pure_ack_times, fwd)
        if b_pure_anoms:
            fwd.anomalies = sorted(fwd.anomalies + b_pure_anoms, key=lambda a: a.time)
        # a's pure-ACKs (in fwd) ack b's data (in bwd) → annotate bwd.
        a_pure_anoms = _classify_pure_acks(fwd.pure_ack_times, bwd)
        if a_pure_anoms:
            bwd.anomalies = sorted(bwd.anomalies + a_pure_anoms, key=lambda a: a.time)
        _escalate_dup_acks(fwd)
        _escalate_dup_acks(bwd)
        _emit_handshake_ack(fwd, bwd)
    elif fwd is not None:
        _escalate_dup_acks(fwd)
    elif bwd is not None:
        _escalate_dup_acks(bwd)
    return TsgModelPair(fwd=fwd, bwd=bwd)


def _escalate_dup_acks(model: TsgModel) -> None:
    """Promote `dup_ack` → `dup_ack_drove_retx` when the dup's cumack matches
    a fast-retx segment's seq_start on the same direction.

    A dup-ACK cluster at cumack=N drives a fast retransmit at seq_start=N
    when the third dup arrives — that's the canonical Reno/SACK fast-retx
    trigger. Wireshark differentiates "ACK to a segment we saw retransmitted"
    from "ACK that probably triggered the retransmit", which is the same
    distinction here: matching seq locates the dup as causally upstream.
    """
    fast_retx_seqs = {
        a.seq_lo for a in model.anomalies if a.kind == "fast" and a.seq_lo is not None
    }
    if not fast_retx_seqs:
        return
    replaced = False
    new_anoms: list[Anomaly] = []
    for a in model.anomalies:
        if a.kind == "dup_ack" and a.seq_lo in fast_retx_seqs:
            new_anoms.append(
                Anomaly(
                    time=a.time,
                    kind="dup_ack_drove_retx",
                    one_liner=f"{a.one_liner} (drove fast retx)",
                    seq_lo=a.seq_lo,
                    seq_hi=a.seq_hi,
                )
            )
            replaced = True
        else:
            new_anoms.append(a)
    if replaced:
        model.anomalies = new_anoms


def _emit_handshake_ack(fwd: TsgModel, bwd: TsgModel) -> None:
    """Mark the 3rd packet of the 3-way handshake on the forward model.

    The completer is fwd's bare ACK of the responder's ISN+1 — a zero-payload
    packet that does NOT advance fwd's cumack staircase, so it is absent from
    `fwd.acks` (which holds only cumack-advancing green steps). The first of
    those after the SYN/ACK is the first *data* ACK, ~1 RTT + server
    think-time later; reporting it fabricates a large handshake-completion
    delay. Take the completer from the pure-ACK stream instead: the first
    zero-payload packet fwd sent after the SYN/ACK arrived. Surface it as its
    own kind so the UI can color it as a protocol marker.
    """
    syn_ack_times = [a.time for a in bwd.anomalies if a.kind == "syn_ack"]
    if not syn_ack_times:
        return
    t_sa = syn_ack_times[0]
    completer = next((t for t in fwd.pure_ack_times if t > t_sa), None)
    if completer is None:
        return
    delta_ms = (completer - t_sa) * 1000.0
    # Position the glyph at fwd's handshake sequence (where the bare ACK sits on
    # the a-side TSG): prefer the forward SYN label's seq, else the ISN floor.
    syn_seqs = [a.seq_lo for a in fwd.anomalies if a.kind == "syn" and a.seq_lo is not None]
    seq = syn_seqs[0] if syn_seqs else min((s.seq_start for s in fwd.segments), default=0)
    fwd.anomalies = sorted(
        [
            *fwd.anomalies,
            Anomaly(
                time=completer,
                kind="handshake_ack",
                one_liner=f"ACK (handshake completion) · {delta_ms:.1f} ms after SYN/ACK",
                seq_lo=seq,
                seq_hi=seq,
            ),
        ],
        key=lambda a: a.time,
    )
