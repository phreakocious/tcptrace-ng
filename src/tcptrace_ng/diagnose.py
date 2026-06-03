# src/tcptrace_ng/diagnose.py
"""Pure connection-diagnosis layer.

Consumes the already-built models (ConnStats / TsgModelPair / ThroughputModelPair)
and emits named, severity-graded Findings. No pcap parsing, no subprocess — every
detection is synthesis of signals computed upstream, so this stays unit-testable
on hand-built models. Severity maps onto the existing classifier.Class vocabulary
(good/interesting/bad -> GOOD/LOOK/BAD).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from .classifier import Class
from .csum import CsumEvent
from .offload import OffloadReport
from .stats_parser import ConnStats
from .tcp_inspect import TsgModelPair
from .throughput import ThroughputModelPair

Severity = Literal["good", "interesting", "bad"]
Scope = Literal["a2b", "b2a", "conn"]

DIAGNOSE_VERSION = "1"  # reserved for invalidating cached diagnoses (mirrors STATS_PARSER_VERSION)

_SEVERITY_TO_CLASS: dict[str, Class] = {
    "good": Class.GOOD,
    "interesting": Class.LOOK,
    "bad": Class.BAD,
}
_SEVERITY_RANK: dict[str, int] = {"good": 0, "interesting": 1, "bad": 2}


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Severity
    scope: Scope
    headline: str
    detail: str
    # Mapping (not dict) signals read-only intent: `frozen=True` blocks
    # rebinding the field but not mutating a dict in place, so we type it as the
    # read-only ABC. Callers still build plain dict literals.
    evidence: Mapping[str, object] = field(default_factory=dict)


def severity_to_class(sev: Severity) -> Class:
    return _SEVERITY_TO_CLASS[sev]


def _host_only(hostport: str) -> str:
    return hostport.rsplit(":", 1)[0] if hostport else hostport


def _port(hostport: str) -> int | None:
    """Extract port number from 'host:port' string."""
    try:
        return int(hostport.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return None


def _client_is_a_port_heuristic(host_a: str, host_b: str) -> bool | None:
    """Infer client side by port number: the lower port is typically the server."""
    pa, pb = _port(host_a), _port(host_b)
    if pa is None or pb is None or pa == pb:
        return None
    # Lower port → server (well-known/registered); higher port → client (ephemeral)
    return pa > pb  # True = a is client (a has higher/ephemeral port)


def _capture_vantage(stats: ConnStats | None) -> list[Finding]:
    if stats is None or stats.rtt_3whs_a is None or stats.rtt_3whs_b is None:
        return []
    ra, rb = stats.rtt_3whs_a, stats.rtt_3whs_b
    near, far = min(ra, rb), max(ra, rb)
    if far < 1.0:
        return []  # LAN both directions — vantage undefined and irrelevant
    if near <= 1.0 and far >= 5.0 * max(near, 0.05):
        # The near-zero direction's ACKER is the adjacent endpoint: b->a near
        # => host a acks locally => tap next to a; a->b near => next to b.
        if rb <= ra:
            adj_letter, adj_host, adj_is_a = "A", _host_only(stats.host_a), True
        else:
            adj_letter, adj_host, adj_is_a = "B", _host_only(stats.host_b), False
        # Map adjacent host -> client/server ONLY when the handshake was fully
        # observed AND client_is_a is known (from tcptrace or port heuristic).
        role = None
        if stats.complete_handshake:
            client_is_a = stats.client_is_a
            if client_is_a is None:
                client_is_a = _client_is_a_port_heuristic(stats.host_a, stats.host_b)
            if client_is_a is not None:
                role = "client" if adj_is_a == client_is_a else "server"
        if role:
            headline = f"Capture taken {role}-side (next to {adj_host})"
        else:
            headline = f"Capture taken next to host {adj_letter} ({adj_host})"
        return [
            Finding(
                code="capture_vantage",
                severity="good",
                scope="conn",
                headline=headline,
                detail=(
                    f"3WHS RTT is {near:.1f} ms to {adj_host} and {far:.1f} ms to "
                    f"the far end — the {far:.1f} ms half is the network path."
                ),
                evidence={
                    "rtt_3whs_a_ms": ra,
                    "rtt_3whs_b_ms": rb,
                    "adjacent_host": adj_host,
                    "vantage": role or "endpoint",
                },
            )
        ]
    if near >= 2.0 and far <= 3.0 * near:
        return [
            Finding(
                code="capture_vantage",
                severity="interesting",
                scope="conn",
                headline="Capture taken at a midpoint",
                detail=(
                    f"Both path halves are substantial ({ra:.1f} ms / {rb:.1f} ms) — "
                    f"the tap sits between the hosts."
                ),
                evidence={"rtt_3whs_a_ms": ra, "rtt_3whs_b_ms": rb, "vantage": "midpoint"},
            )
        ]
    # Conservative gap (intentional): inputs with 1 < near < 2 ms, or an
    # asymmetric near >= 2 ms with far > 3x near, fall through both branches and
    # stay silent. We emit a vantage only on a clear-cut signal — a sub-ms
    # adjacent host, or two comparably-substantial halves — rather than risk a
    # mislabel in the ambiguous middle. Widening for intra-DC captures (1-2 ms
    # local RTT) needs real-capture validation; see the plan's Out of scope.
    return []


_MIN_STORM_SEGS = 20
_STORM_WARN_FRAC = 0.05
_STORM_BAD_FRAC = 0.15
_OVERSIZED_SEG_BYTES = 1500  # one Ethernet MTU; a wider data span ⇒ coalesced


def _direction_is_coalesced(model) -> bool:
    """True when THIS direction's retransmit signal can't be trusted.

    NIC offload (LRO/GRO/TSO) makes tcptrace both hide real retransmits and
    fabricate spurious ones — overlapping seq ranges inside coalesced
    super-segments trip the retx heuristic — so loss severity must be capped,
    never asserted as bad. Strictly per-direction (a clean direction is never
    gated by the other's coalescing) and model-only — pcap-wide offload is NOT
    consulted, so no other connection can leak in. Two signals: (1) a
    `coalesced` anomaly (MSS-relative, precise); (2) a data segment spanning
    more than one MTU — an MSS-free backstop that still fires when MSS was
    unavailable and so no anomaly was emitted.
    """
    if model is None:
        return False
    if any(a.kind == "coalesced" for a in model.anomalies):
        return True
    # MSS-free backstop: ONLY when MSS was unavailable (so no `coalesced` anomaly
    # could be emitted). With a known MSS the precise anomaly above already
    # covers real coalescing; applying a hardcoded 1500 here false-flags
    # jumbo-frame paths (MSS up to ~8960) as coalesced — capping a real loss
    # storm and appending a fabricated offload note. Jumbo is common in
    # DC/storage, the target audience's turf.
    if model.mss is not None:
        return False
    return any((s.seq_end - s.seq_start) > _OVERSIZED_SEG_BYTES for s in model.segments)


def _loss_storm(tsg: TsgModelPair | None) -> list[Finding]:
    if tsg is None:
        return []
    out: list[Finding] = []
    for model, scope in ((tsg.fwd, "a2b"), (tsg.bwd, "b2a")):
        if model is None:
            continue
        data_segs = [s for s in model.segments if s.seq_end > s.seq_start]
        if len(data_segs) < _MIN_STORM_SEGS:
            continue
        # Exclude <=1-byte retx: keepalives / zero-window probes are NOT loss.
        retx = [s for s in data_segs if s.rtx in ("rto", "fast") and (s.seq_end - s.seq_start) > 1]
        # Retransmission fraction over all data transmissions — NOT a true loss
        # rate: the denominator includes the retransmits themselves.
        frac = len(retx) / len(data_segs)
        if frac < _STORM_WARN_FRAC:
            continue
        # Benign-twin guard: a coalesced direction has an untrustworthy retransmit
        # signal, so cap severity (never assert 'bad'); we cap, never suppress.
        capped = _direction_is_coalesced(model)
        severity: Severity
        if capped:
            severity, note = (
                "interesting",
                " — NIC offload/coalescing present, retransmit counts unreliable",
            )
        elif frac >= _STORM_BAD_FRAC:
            severity, note = "bad", ""
        else:
            severity, note = "interesting", ""
        out.append(
            Finding(
                code="loss_storm",
                severity=severity,
                scope=scope,  # type: ignore[arg-type]
                headline=f"High retransmission rate{note}",
                detail=(
                    f"{len(retx)} of {len(data_segs)} data segments were "
                    f"retransmissions ({frac:.0%}); 1-byte keepalive/probe "
                    f"retransmits excluded."
                ),
                evidence={
                    "retx_segs": len(retx),
                    "data_segs": len(data_segs),
                    "retx_frac": frac,
                    "offload_capped": capped,
                },
            )
        )
    return out


def diagnose(
    stats: ConnStats | None,
    tsg: TsgModelPair | None,
    tput: ThroughputModelPair | None,
    *,
    offload: OffloadReport | None = None,
    csum_events: Sequence[CsumEvent] = (),
) -> list[Finding]:
    """Return the Findings for one connection, sorted by descending severity.

    `tput`, `offload`, and `csum_events` are accepted but not yet consumed — they
    are reserved for follow-on detectors (throughput pathologies; the
    `capture_quality` finding; checksum findings). NOTE the `loss_storm` offload
    *gate* is model-internal (`_direction_is_coalesced` reads the per-direction
    TsgModel); the `offload` param here is the pcap-wide report destined for the
    future capture-quality finding, NOT that gate.
    """
    findings: list[Finding] = []
    findings += _capture_vantage(stats)
    findings += _loss_storm(tsg)
    findings.sort(key=lambda f: _SEVERITY_RANK[f.severity], reverse=True)
    return findings
