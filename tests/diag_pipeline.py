# tests/diag_pipeline.py
"""Test helper: run a pcap through the full pipeline to Findings.

Mirrors app._build_tput_model's synthesis chain so end-to-end fixtures validate
the same TsgModelPair / ThroughputModelPair the UI consumes.

FIDELITY BOUNDARY: unlike the app, this does NOT thread per-direction bad-csum
times into synthesize_tsg (the app derives them via _csum_for_plots /
_csum_times_directed from the xpl plot titles). So checksum-driven model
anomalies (bad_csum_lost / bad_csum_acked) are absent here. No detector in this
plan consumes them; the checksum-finding plan (see Out of scope) must first
extract that mapping into a shared helper and wire it in here.
"""

from __future__ import annotations

from pathlib import Path

from tcptrace_ng.csum import scan_pcap
from tcptrace_ng.desegment import desegment_pcap
from tcptrace_ng.diagnose import Finding, diagnose
from tcptrace_ng.offload import detect_offload
from tcptrace_ng.runner import analyze_connection, list_connections
from tcptrace_ng.stats_parser import parse_stats
from tcptrace_ng.tcp_inspect import synthesize as synthesize_tsg
from tcptrace_ng.throughput import synthesize_throughput
from tcptrace_ng.xpl_grouper import group_xpls
from tcptrace_ng.xpl_parser import parse_xpl


def run_pipeline(pcap: Path, conn_n: int = 1, *, out_dir: Path | None = None) -> list[Finding]:
    out_dir = out_dir or pcap.parent / ".pipeline"
    # Mirror the app: de-coalesce NIC offload (LRO/GRO/TSO) before tcptrace, so
    # e2e fixtures exercise the same wire-plausible segments the UI analyzes.
    # Guarded on detect_offload so non-offload fixtures stay byte-identical.
    if detect_offload(pcap).oversized_segments > 0:
        deseg = out_dir / "desegment.pcap"
        deseg.parent.mkdir(parents=True, exist_ok=True)
        desegment_pcap(pcap, deseg)
        pcap = deseg
    res = analyze_connection(pcap, conn_n, out_dir, no_dns=True, with_rtt=True)

    tsg = next((g for g in group_xpls(res.xpl_files) if g.metric == "tsg"), None)
    fwd = parse_xpl(tsg.forward) if tsg and tsg.forward else None
    bwd = parse_xpl(tsg.backward) if tsg and tsg.backward else None

    # NB: bad_csum_times_* deliberately omitted — see the fidelity note above.
    tsg_pair = synthesize_tsg(fwd, bwd, res.details_text)
    # Parse stats directly (NOT reused from tsg_pair.*.summary): diagnose() must
    # still receive ConnStats — and its RTT-3WHS — even when tcptrace emitted no
    # tsg xpl, in which case both models (and thus .summary) are None.
    stats = next(iter(parse_stats(res.details_text)), None)
    summary = (
        tsg_pair.fwd.summary
        if tsg_pair.fwd is not None
        else tsg_pair.bwd.summary
        if tsg_pair.bwd is not None
        else None
    )
    tput_pair = synthesize_throughput(tsg_pair, summary)

    return diagnose(
        stats,
        tsg_pair,
        tput_pair,
        offload=detect_offload(pcap),
        csum_events=scan_pcap(pcap),
    )


def conn_count(pcap: Path) -> int:
    return len(list_connections(pcap, no_dns=True))
