"""Integration glue for the reorder classifier (Plan 3, data layer).

Sources the post-decap/pre-desegment per-connection slice, picks a bootstrap
RTT, runs `reorder.classify`, and summarises the spans. The single pickleable
entrypoint `classify_connection_pure` is shipped to a worker via run.cpu_bound.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .pcap_extract import extract_conversation
from .reorder import SpanObs, classify, seq_diff

_TIER_RANK = {"lo": 0, "med": 1, "hi": 2}
_BUCKET = {
    "retransmission": "retransmit_bytes",
    "original": "original_bytes",
    "probable_capture_duplicate": "capture_dup_bytes",
    "unknown": "unknown_bytes",
}


@dataclass(frozen=True)
class ReorderSummary:
    retransmit_bytes: int
    original_bytes: int
    capture_dup_bytes: int
    unknown_bytes: int
    spurious_retransmit_spans: int
    loss_episodes: int
    max_tier: str
    n_spans: int


def summarize_spans(spans: list[SpanObs]) -> ReorderSummary:
    bytes_by = {"retransmit_bytes": 0, "original_bytes": 0,
                "capture_dup_bytes": 0, "unknown_bytes": 0}
    spurious = 0
    episodes = 0
    best_tier = 0
    for sp in spans:
        bytes_by[_BUCKET[sp.copy_status]] += seq_diff(sp.hi, sp.lo)
        if sp.copy_status == "retransmission" and (
                sp.receiver_state == "already_had"
                or sp.receiver_duplicate_reported == "yes"):
            spurious += 1
        if sp.sequence_observation == "opens_gap":
            episodes += 1
        best_tier = max(best_tier, _TIER_RANK[sp.tier])
    max_tier = next(k for k, v in _TIER_RANK.items() if v == best_tier)
    return ReorderSummary(
        retransmit_bytes=bytes_by["retransmit_bytes"],
        original_bytes=bytes_by["original_bytes"],
        capture_dup_bytes=bytes_by["capture_dup_bytes"],
        unknown_bytes=bytes_by["unknown_bytes"],
        spurious_retransmit_spans=spurious,
        loss_episodes=episodes,
        max_tier=max_tier,
        n_spans=len(spans),
    )


def reorder_source_pcap(decap_pcap: Path, selected_pcap: Path) -> Path:
    """Post-decap, pre-desegment source for classification.

    `decap_pcap` exists on disk only when encapsulation was detected and
    stripped; otherwise the original `selected_pcap` is already pre-desegment.
    Never returns the effective (post-desegment) pcap.
    """
    return decap_pcap if decap_pcap.exists() else selected_pcap


def bootstrap_rtt(stats) -> float | None:
    """Single connection RTT in seconds for classify(): 3WHS first, then
    tcptrace -r averages, else None (engine abstains on timing). ConnStats
    holds RTT in milliseconds."""
    if stats is None:
        return None
    for a, b in ((getattr(stats, "rtt_3whs_a", None), getattr(stats, "rtt_3whs_b", None)),
                 (getattr(stats, "rtt_avg_a", None), getattr(stats, "rtt_avg_b", None))):
        vals = [v for v in (a, b) if v is not None and v > 0]
        if vals:
            return (sum(vals) / len(vals)) / 1000.0
    return None


@dataclass(frozen=True)
class ReorderResult:
    host_a: str
    host_b: str
    rtt_s: float | None
    spans: list[SpanObs]
    summary: ReorderSummary


def classify_connection_pure(decap_pcap: Path, selected_pcap: Path,
                             host_a: str, host_b: str, stats) -> ReorderResult | None:
    """Pickleable worker entrypoint: source the pre-desegment slice, extract
    the connection, pick a bootstrap RTT, classify, and summarise."""
    source = reorder_source_pcap(decap_pcap, selected_pcap)
    pcap_bytes = extract_conversation(source, host_a, host_b)
    if not pcap_bytes:
        return None
    rtt = bootstrap_rtt(stats)
    spans = classify(pcap_bytes, host_a, host_b, rtt=rtt)
    return ReorderResult(host_a=host_a, host_b=host_b, rtt_s=rtt,
                         spans=spans, summary=summarize_spans(spans))
