# tests/test_diagnose_e2e.py
"""End-to-end: synthetic pcap -> real tcptrace -> diagnose()."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tcptrace_ng.runner import _VENDORED_TCPTRACE
from tests.diag_pipeline import run_pipeline
from tests.pcap_synth import TH_ACK, TcpFlow

pytestmark = pytest.mark.skipif(
    shutil.which("tcptrace") is None and not _VENDORED_TCPTRACE.is_file(),
    reason="tcptrace binary not available",
)


def _codes(findings):
    return {f.code for f in findings}


def test_e2e_client_vantage(tmp_path):
    fl = TcpFlow()
    t = fl.handshake(0.0, rtt=0.080)
    fl.send(t + 0.0001, "c", 50)
    fl.ack(t + 0.080, "s")
    st = t + 0.080
    for _ in range(3):
        fl.send(st, "s", 1448)
        fl.ack(st + 0.0001, "c")
        st += 0.0005
    fl.fin(st + 0.001, "s")
    fl.fin(st + 0.082, "c")
    p = fl.write(tmp_path / "v.pcap")

    findings = run_pipeline(p)
    vant = [f for f in findings if f.code == "capture_vantage"]
    assert len(vant) == 1
    assert vant[0].evidence["vantage"] == "client"


def _partial_ack(fl, t, ack_seq):
    """Client ACK with a specific ack_seq, without advancing fl.cumack.

    tcptrace's spurious-retransmit detector fires when any ACK *before* the
    retransmit already covers that seq range (ack_seq >= seq_end).  To keep
    dropped-segment retransmits classified as rto (not spurious), we must
    never advance the cumack past a dropped segment's end before its
    retransmit arrives.  Emitting per-segment partial ACKs here — instead of
    fl.ack() which always acknowledges everything the server has sent so far
    — ensures each retransmit arrives before any ACK advances past its range.
    """
    fl._emit(t, "c", fl.seq["c"], ack_seq, TH_ACK, fl.win["c"] >> fl.wscale)


def _bulk_transfer(tmp_path, name, *, n_drops, keepalive=False, coalesce=False):
    """Server streams 40 MSS segments to the client; the LAST `n_drops` of them
    are lost then RTO-retransmitted.

    Drops are at the END of the stream so that partial ACKs for non-dropped
    segments never advance the cumack past the dropped segments' seq ranges — a
    prerequisite for tcptrace to classify the retransmits as rto rather than
    spurious. Optionally inject a 1-byte keepalive, and/or one NIC-coalesced
    (oversized) segment to trip the offload gate.
    """
    n = 40
    # Always put drops at the end so no prior ACK covers their seq ranges.
    drop_idx = set(range(n - n_drops, n))
    fl = TcpFlow()
    t = fl.handshake(0.0, rtt=0.040)
    seq_lo_by_idx: dict[int, int] = {}
    seq_hi_by_idx: dict[int, int] = {}
    st = t + 0.001
    if coalesce:
        # One oversized (> MSS) segment so BOTH detect_offload (payload > 1500 B)
        # and the per-direction `coalesced` anomaly fire on this capture.
        lo, hi = fl.send(st, "s", 4344)  # 3x1448 — a plausible GRO/LRO merge
        _partial_ack(fl, st + 0.040, hi)
        st += 0.010
    for i in range(n):
        lo, hi = fl.send(st, "s", 1448)
        seq_lo_by_idx[i] = lo
        seq_hi_by_idx[i] = hi
        if i not in drop_idx:
            _partial_ack(fl, st + 0.040, hi)  # acked up to just past this seg
        st += 0.010
    if keepalive:
        fl.keepalive(st, "s")
        st += 0.010
    # RTO retransmits of the dropped segments, then their acks.
    # At this point no ACK has advanced past the end of the last non-dropped
    # segment, so all retransmits will be classified as rto by tcp_inspect.
    for i in sorted(drop_idx):
        fl.retransmit(st, "s", seq_lo_by_idx[i], 1448)
        _partial_ack(fl, st + 0.040, seq_hi_by_idx[i])
        st += 0.020
    fl.fin(st + 0.001, "s")
    fl.fin(st + 0.042, "c")
    return fl.write(tmp_path / name)


def test_e2e_loss_storm_fires_on_heavy_loss(tmp_path):
    p = _bulk_transfer(tmp_path, "loss.pcap", n_drops=12)
    findings = run_pipeline(p)
    storm = [f for f in findings if f.code == "loss_storm"]
    assert storm, f"expected loss_storm, got {_codes(findings)}"
    assert storm[0].severity == "bad"


def test_e2e_keepalive_is_not_loss(tmp_path):
    # No drops, but a 1-byte keepalive present -> must NOT be loss_storm.
    p = _bulk_transfer(tmp_path, "keep.pcap", n_drops=0, keepalive=True)
    findings = run_pipeline(p)
    assert "loss_storm" not in _codes(findings)


def test_e2e_loss_storm_capped_under_offload(tmp_path):
    # Heavy loss AND an oversized (coalesced) segment: detect_offload fires, so
    # loss_storm must cap at 'interesting' rather than assert 'bad' on a capture
    # whose retransmit counts are corrupted by NIC offload.
    p = _bulk_transfer(tmp_path, "lossoff.pcap", n_drops=12, coalesce=True)
    findings = run_pipeline(p)
    storm = [f for f in findings if f.code == "loss_storm"]
    assert storm, f"expected loss_storm, got {_codes(findings)}"
    assert storm[0].severity == "interesting"
    assert storm[0].evidence.get("offload_capped") is True


# --- real-capture regression anchor (local-only; np.pcap is gitignored) ---
_NP = Path(__file__).resolve().parents[1] / "np.pcap"


@pytest.mark.skipif(not _NP.is_file(), reason="np.pcap not present (gitignored)")
def test_np_pcap_keepalive_not_flagged_as_loss(tmp_path):
    """np.pcap has a 1-byte rexmt in both directions — a keepalive, not loss."""
    # out_dir in tmp so the run doesn't write .pipeline/ scratch into the repo
    # root (np.pcap lives there, and run_pipeline defaults out_dir to its parent).
    findings = run_pipeline(_NP, out_dir=tmp_path / ".pipeline")
    assert "loss_storm" not in _codes(findings)
    # And its asymmetric RTT should read as client-side vantage.
    vant = [f for f in findings if f.code == "capture_vantage"]
    assert vant and vant[0].evidence["vantage"] == "client"
