"""Pure formatters and HTML builders. No NiceGUI imports, no state reads.

Functions here take all inputs as arguments and return strings, lists, or
booleans. Easy to unit-test; consumed by view/header.py, view/sidebar.py,
and view/main.py (later phases).
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from pathlib import Path

from ..classifier import Class
from ..diagnose import Finding, severity_to_class
from ..state import _escape_html
from ..stats_parser import ConnStats
from ..throughput import DirectionSummary


def _humanize_delta(seconds: float) -> tuple[float, str]:
    """Pick the largest sensible unit for `seconds`. Returns (value, unit-suffix).

    Callers decide on precision: durations want one decimal (3.4s), relative
    timestamps want int (3s ago). ms is sub-second only; d is for spans ≥ a day.
    """
    if seconds < 1:
        return (seconds * 1000, "ms")
    if seconds < 60:
        return (seconds, "s")
    if seconds < 3600:
        return (seconds / 60, "m")
    if seconds < 86400:
        return (seconds / 3600, "h")
    return (seconds / 86400, "d")


def _format_mtime(stat_result: os.stat_result, now: float) -> str:
    """Terse relative time, ISO-date once we're past a week.

    Clamps a negative delta to zero so clock skew (NTP, dual-boot, VM snapshot)
    doesn't surface as a nonsense `-3s ago` label.
    """
    delta = max(0.0, now - stat_result.st_mtime)
    if delta >= 7 * 86400:
        return datetime.fromtimestamp(stat_result.st_mtime, tz=UTC).strftime("%Y-%m-%d")
    value, unit = _humanize_delta(delta)
    # mtime granularity for the user is seconds; sub-second deltas (clamped
    # future-mtime, just-written file) collapse to "0s ago" rather than "0ms".
    if unit == "ms":
        return "0s ago"
    return f"{int(value)}{unit} ago"


def _pcap_options(pcaps: list[tuple[Path, os.stat_result]], now: float) -> dict[str, str]:
    return {
        str(p): f"{p.name}  ({_format_size(st.st_size)} · {_format_mtime(st, now)})"
        for p, st in pcaps
    }


def _format_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    return f"{n / 1024 / 1024 / 1024:.2f} GB"


def _matches_filter(row, q: str) -> bool:
    if not q:
        return True
    needle = q.lower()
    return needle in str(row.n) or needle in row.host_a.lower() or needle in row.host_b.lower()


def _format_duration(s: float) -> str:
    value, unit = _humanize_delta(s)
    if unit == "ms":
        return f"{value:.0f}ms"
    return f"{value:.1f}{unit}"


def _split_endpoint(ep: str) -> tuple[str, int] | None:
    """Parse `1.2.3.4:5` into `("1.2.3.4", 5)`. Returns None if it doesn't split."""
    if ":" not in ep:
        return None
    ip, _, port = ep.rpartition(":")
    if not port.isdigit():
        return None
    return ip, int(port)


_VERDICT_CSS = {
    Class.GOOD: "tcptrace-dot-good",
    Class.LOOK: "tcptrace-dot-look",
    Class.BAD: "tcptrace-dot-bad",
    Class.NORMAL: "tcptrace-dot-normal",
}


def _issue_summary(findings: list[Finding]) -> tuple[int, Class] | None:
    """(#issues, worst Class) over interesting+bad findings, else None.

    'good' findings (e.g. capture_vantage) never drive the ⚠N badge.
    """
    issues = [f for f in findings if f.severity in ("interesting", "bad")]
    if not issues:
        return None
    worst = Class.BAD if any(f.severity == "bad" for f in issues) else Class.LOOK
    return (len(issues), worst)


def _verdict_dot_class(findings: list[Finding] | None) -> Class | None:
    """Verdict Class for the per-connection dot, driven by diagnose() findings.

    Returns None when findings aren't computed yet (connection not opened) — the
    caller renders a neutral 'pending' dot. We never fall back to the legacy
    line-color classifier (`classify`/`ConnStats.verdict`): it flags BAD on
    benign captures (a bare `rexmt` line, valid wscale; see L10) and contradicts
    the findings panel. Mirrors the ⚠N badge's worst-severity logic so the dot
    and badge always agree.
    """
    if findings is None:
        return None  # pending: not yet analyzed
    summary = _issue_summary(findings)
    if summary is not None:
        return summary[1]  # BAD or LOOK — worst of the interesting+bad issues
    if any(f.severity == "good" for f in findings):
        return Class.GOOD
    return Class.NORMAL  # computed, nothing notable


# _issue_summary only ever returns BAD or LOOK (issues are interesting+bad).
_WARN_CLASS = {Class.BAD: "conn-warn-bad", Class.LOOK: "conn-warn-look"}


def _warn_badge_html(findings: list[Finding]) -> str:
    """`<span>⚠N</span>` colored by worst severity, or '' when no issues."""
    summary = _issue_summary(findings)
    if summary is None:
        return ""
    count, worst = summary
    return f'<span class="conn-warn {_WARN_CLASS[worst]}">⚠{count}</span>'


def _build_conn_row_html(
    row,
    badges_str: str,
    findings: list[Finding],
) -> str:
    """Build the inner HTML of one connection row.

    Pure: takes a row (ConnStats or ConnRow), the pre-computed badges string
    (chip-equivalents like 'RX RST FIN CSUM 0/2'), and the findings list for
    this conn. Returns the HTML to assign to a `ui.html(...)` body.

    Splits on isinstance(row, ConnStats) — the stats-less fallback emits only
    the conn number + endpoints.
    """
    if isinstance(row, ConnStats):
        verdict = _verdict_dot_class(findings)
        dot_cls = "tcptrace-dot-pending" if verdict is None else _VERDICT_CSS[verdict]
        bytes_str = _format_size(row.total_bytes)
        dur_str = _format_duration(row.duration_s)
        return (
            f'<div class="conn-meta-top">'
            f'<span class="conn-num">{row.n}</span>'
            f'<span class="tcptrace-conn-dot {dot_cls}"></span>'
            f'<span class="conn-badges">{_escape_html(badges_str)}</span>'
            f"{_warn_badge_html(findings)}"
            f"</div>"
            f'<div class="conn-host">{_escape_html(row.host_a)}</div>'
            f'<div class="conn-host">↔ {_escape_html(row.host_b)}</div>'
            f'<div class="conn-meta-bot">'
            f"{bytes_str} · {dur_str} · {row.total_packets} pkts</div>"
        )
    return (
        f'<div class="conn-num">{row.n}</div>'
        f'<div class="conn-host">{_escape_html(row.host_a)}</div>'
        f'<div class="conn-host">↔ {_escape_html(row.host_b)}</div>'
    )


def _findings_panel_html(findings: list[Finding], fwd_label: str, bwd_label: str) -> str:
    """Stacked findings rows for the main-panel header. '' when empty.

    Findings arrive severity-sorted from diagnose(). Glyph reuses the sidebar
    dot (tcptrace-conn-dot + _VERDICT_CSS); scope tag uses the connection's
    direction labels when known.
    """
    if not findings:
        return ""
    scope_label = {"a2b": fwd_label or "a→b", "b2a": bwd_label or "b→a", "conn": "conn"}
    rows: list[str] = []
    for f in findings:
        dot_cls = _VERDICT_CSS[severity_to_class(f.severity)]
        rows.append(
            f'<div class="finding-row">'
            f'<span class="tcptrace-conn-dot {dot_cls}"></span>'
            f'<span class="finding-head">{_escape_html(f.headline)}</span>'
            f'<span class="finding-scope">{_escape_html(scope_label[f.scope])}</span>'
            f'<span class="finding-detail">{_escape_html(f.detail)}</span>'
            f"</div>"
        )
    return f'<div class="tcptrace-findings">{"".join(rows)}</div>'


_BULK_BYTES_THRESHOLD = 100 * 1024  # 100 KB; hardcoded per spec


def _matches_chips(row, chips: set[str]) -> bool:
    if not chips:
        return True
    if not isinstance(row, ConnStats):
        # Stats-less fallback rows never satisfy stats-based chips
        return False
    if "bad" in chips and row.verdict != Class.BAD:
        return False
    if "rst" in chips and not row.has_rst:
        return False
    if "rexmt" in chips and row.rexmt_packets == 0:
        return False
    if "incomplete" in chips and row.complete_handshake:
        return False
    if "uni" in chips and not row.unidirectional:
        return False
    return not ("bulk" in chips and row.total_bytes < _BULK_BYTES_THRESHOLD)


def _sort_rows(rows: list, key: str) -> list:
    def get(r, attr, default):
        return getattr(r, attr, default)

    if key == "n":
        return sorted(rows, key=lambda r: get(r, "n", 0))
    if key == "bytes":
        return sorted(rows, key=lambda r: get(r, "total_bytes", 0), reverse=True)
    if key == "duration":
        return sorted(rows, key=lambda r: get(r, "duration_s", 0.0), reverse=True)
    if key == "rexmt":
        return sorted(rows, key=lambda r: get(r, "rexmt_packets", 0), reverse=True)
    return rows


def _direction_labels(row) -> tuple[str, str]:
    """Return (forward_label, backward_label) using client/server when known."""
    if isinstance(row, ConnStats) and row.client_is_a is not None:
        return (
            ("client → server", "server → client")
            if row.client_is_a
            else ("server → client", "client → server")
        )
    return (
        f"{row.host_a} → {row.host_b}",
        f"{row.host_b} → {row.host_a}",
    )


def _coalesce_to_dict(c) -> dict:
    return {
        "time": c.time,
        "src": c.src,
        "dst": c.dst,
        "parent_seq_start": c.parent_seq_start,
        "parent_seq_end": c.parent_seq_end,
        "pieces": c.pieces,
        "mss": c.mss,
        "mss_source": c.mss_source,
    }


def _format_bytes(n: float | int | None) -> str:
    if n is None:
        return "—"
    n = float(n)
    if n < 1024:
        return f"{n:.0f} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.2f} GB"


def _format_ms(v: float | None) -> str:
    if v is None:
        return "—"
    return f"{v:.1f} ms"


def _format_count(v: int | None) -> str:
    if v is None:
        return "—"
    return f"{v:,}"


def _format_throughput_Bps(v: float | None) -> str:
    # SI (1000) prefixes — the convention for network rates, and what the chart
    # renders (d3 ".3s" axis) and the bits-mode formatter use. Binary (1024) here
    # made the same flow read "1.4 MB/s" in the grid vs "1.5 MB/s" on the chart
    # (L8). Byte *counts* stay binary (sizes are conventionally IEC).
    if v is None:
        return "—"
    if v < 1000:
        return f"{v:.0f} B/s"
    if v < 1000 * 1000:
        return f"{v / 1000:.1f} KB/s"
    if v < 1000 * 1000 * 1000:
        return f"{v / (1000 * 1000):.1f} MB/s"
    return f"{v / (1000 * 1000 * 1000):.2f} GB/s"


def _format_rate_bps(v_Bps: float | None) -> str:
    """Same shape as `_format_throughput_Bps` but bits-per-second, SI (1000s).

    Network engineers conventionally read line rates in decimal bits; matching
    that here avoids a silent IEC-vs-SI confusion when the user expects Mbps.
    """
    if v_Bps is None:
        return "—"
    v = v_Bps * 8.0
    if v < 1000:
        return f"{v:.0f} bps"
    if v < 1000 * 1000:
        return f"{v / 1000:.1f} kbps"
    if v < 1000 * 1000 * 1000:
        return f"{v / (1000 * 1000):.1f} Mbps"
    return f"{v / (1000 * 1000 * 1000):.2f} Gbps"


def _format_rate(v_Bps: float | None, unit: str) -> str:
    """Dispatch on `state.rate_unit` for any throughput display site."""
    return _format_rate_bps(v_Bps) if unit == "bits" else _format_throughput_Bps(v_Bps)


_CTX_RATE_RE = re.compile(r"(\d+)\s+Bps")


def _apply_rate_unit_to_ctx(ctx: str, unit: str) -> str:
    """Rewrite `NN Bps` substrings inside a conn-header context line.

    `ctx` is built by `stats_parser.build_context_lines` and embeds tcptrace's
    raw Bps integer; this re-renders it through `_format_rate` at view time so
    flipping the toggle doesn't require re-parsing the tcptrace output.
    """
    if unit == "bytes":
        return ctx
    return _CTX_RATE_RE.sub(lambda m: _format_rate_bps(float(m.group(1))), ctx)


def _format_bad_csum(ws) -> str:
    """Render the bad-csum slot for the Reliability column.

    Splits the count into `acked` (likely NIC offload) and `lost` (segment
    later retransmitted, so the original was dropped). When everything's
    acked we say so plainly; when nothing's acked we omit the split.
    """
    total = ws.n_bad_csum
    if ws.n_bad_csum_lost > 0 and ws.n_bad_csum_acked > 0:
        return f"{total} bad csum ({ws.n_bad_csum_lost} lost, {ws.n_bad_csum_acked} acked)"
    if ws.n_bad_csum_lost > 0:
        return f"{total} bad csum ({ws.n_bad_csum_lost} lost)"
    if ws.n_bad_csum_acked > 0:
        return f"{total} bad csum (all acked)"
    return f"{total} bad csum"


def _sev(value: str, severity: str) -> str:
    """Wrap a stat-token in a severity span. Severity in {ok, notable, bad}."""
    return f'<span class="tt-{severity}">{value}</span>' if severity else value


def _retx_severity(n_retx: int, n_segs: int) -> str:
    if n_retx == 0:
        return "ok"
    pct = (n_retx / n_segs) if n_segs else 0.0
    if pct >= 0.05:
        return "bad"
    if pct >= 0.01:
        return "notable"
    return ""


def _desegment_banner_text(
    desegment_kinds: set[str], desegment_coalesces: list[dict]
) -> str | None:
    """One-line provenance banner when analysis ran on a de-coalesced copy of the
    pcap. None when no offload was split. Counts come from the manifest in state."""
    if not desegment_kinds:
        return None
    frames = len(desegment_coalesces)
    segments = sum(c.get("pieces", 0) for c in desegment_coalesces)
    kinds = "/".join(sorted(desegment_kinds))
    return (
        f"analysis ran on a de-coalesced copy: {frames} offload "
        f"frame{'' if frames == 1 else 's'} → {segments} segments ({kinds})"
    )


def _stats_grid_html(label: str, ws, rate_unit: str = "bytes") -> str:
    pct = (100.0 * ws.n_retx / ws.n_segs) if ws.n_segs else 0.0
    retx_sev = _retx_severity(ws.n_retx, ws.n_segs)
    rto_sev = "bad" if ws.n_rto > 0 else "ok"
    fast_sev = "notable" if ws.n_fast > 0 else "ok"
    shrink_sev = "bad" if ws.n_win_shrink >= 1000 else "notable" if ws.n_win_shrink >= 100 else "ok"
    zerow_sev = "bad" if ws.n_zero_win >= 10 else "notable" if ws.n_zero_win >= 1 else "ok"
    csum_sev = "bad" if ws.n_bad_csum_lost > 0 else "notable" if ws.n_bad_csum > 0 else ""

    csum_text = _format_bad_csum(ws)
    other_anom = (
        f"{ws.n_dup_ack} dup · {ws.n_partial_ack} partial · {ws.n_coalesced} coal · {ws.n_ooo} OOO"
    )
    reliability_extras = (
        f"{other_anom} · {_sev(csum_text, csum_sev)}" if ws.n_bad_csum > 0 else other_anom
    )

    segs_cell = f"{_format_count(ws.n_segs)} segs"
    if getattr(ws, "n_fabricated", 0):
        segs_cell += f" · {_format_count(ws.n_fabricated)} reconstructed"

    rows = [
        (
            "Volume",
            segs_cell,
            f"{_format_bytes(ws.bytes_sent)} sent",
            f"{_format_rate(ws.throughput_eff_Bps, rate_unit)} eff",
            f"{_format_count(ws.n_sack_regions)} SACK",
        ),
        (
            "Reliability",
            _sev(f"{ws.n_retx} retx ({pct:.1f}%)", retx_sev),
            f" · {_sev(f'{ws.n_rto} RTO', rto_sev)}",
            f" · {_sev(f'{ws.n_fast} fast', fast_sev)}",
            reliability_extras,
        ),
        (
            "Latency",
            f"p50 {_format_ms(ws.rtt_p50_ms)}",
            f"p95 {_format_ms(ws.rtt_p95_ms)}",
            f"min/max {_format_ms(ws.rtt_min_ms)}/{_format_ms(ws.rtt_max_ms)}",
            f"jitter {_format_ms(ws.jitter_ms)}",
        ),
        (
            "Receiver",
            f"rwnd peak {_format_bytes(ws.rwin_peak)}",
            f"scale ×{ws.rwin_scale}" if ws.rwin_scale is not None else "scale unknown",
            _sev(f"shrinks: {ws.n_win_shrink}", shrink_sev),
            _sev(f"0-win: {ws.n_zero_win}", zerow_sev),
        ),
    ]
    parts = [f'<div class="dir-label">{label}</div>']
    # Render as four columns; each column is one category.
    titles = [r[0] for r in rows]
    values = [r[1:] for r in rows]
    for col_idx, title in enumerate(titles):
        parts.append(f'<div><div class="col-title">{title}</div>')
        for v in values[col_idx]:
            parts.append(f"<div>{v}</div>")
        parts.append("</div>")
    return "".join(parts)


def _phase_label_text(n: int, phase: str) -> str:
    if phase == "synthesizing":
        return "synthesizing time-sequence model"
    if phase == "diagnosing":
        return "computing diagnostics"
    return f"analyzing connection {n}"


def _throughput_stats_grid_html(
    label: str, summary: DirectionSummary, rate_unit: str = "bytes"
) -> str:
    bdp = (
        f"{summary.bdp_utilization_frac * 100:.1f}%"
        if summary.bdp_utilization_frac is not None
        else "—"
    )
    rows = [
        (
            "Goodput",
            f"avg {_format_rate(summary.mean_goodput_Bps, rate_unit)}",
            f"p50 {_format_rate(summary.p50_goodput_Bps, rate_unit)}",
            f"p95 {_format_rate(summary.p95_goodput_Bps, rate_unit)}",
            f"peak {_format_rate(summary.peak_goodput_Bps, rate_unit)}",
        ),
        (
            "Wire",
            f"{_format_bytes(summary.total_wire_bytes)} total",
            f"{summary.retx_overhead_frac * 100:.1f}% retx overhead",
        ),
        ("BDP utilization", bdp),
        (
            "Anomalies",
            f"{summary.stall_count} stalls ({summary.total_stall_s:.2f}s total)",
            f"{summary.cliff_count} cliffs",
        ),
    ]
    parts = [f'<div class="dir-label">{label}</div>']
    titles = [r[0] for r in rows]
    values = [r[1:] for r in rows]
    for col_idx, title in enumerate(titles):
        parts.append(f'<div><div class="col-title">{title}</div>')
        for v in values[col_idx]:
            parts.append(f"<div>{v}</div>")
        parts.append("</div>")
    return "".join(parts)
