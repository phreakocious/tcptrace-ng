"""Positive anchors: captures with known trouble, from a netns/netem rig kept
with the captures in a separate repo (its `gen.sh` documents each scenario).
Point TCPTRACE_NG_PCAPS at that repo; unset, these tests skip.

Ground truth comes from the rig, never from an analyzer: `drops=` in each
manifest is the data-path drop count, and every drop forces exactly one more
retransmit. These expectations say what a correct analyzer must report; they
were committed before the first capture was generated; each later amendment
gives its reason in its commit. Known bugs are
xfail(strict), so a fix shows up as XPASS.
"""

from __future__ import annotations

import functools
import os
import re
import shutil
import tempfile
from pathlib import Path

import pytest

from tcptrace_ng.offload import detect_offload
from tcptrace_ng.runner import _VENDORED_TCPTRACE
from tests.diag_pipeline import build_models

PCAPS = Path(os.environ.get("TCPTRACE_NG_PCAPS", "/nonexistent"))

pytestmark = [
    pytest.mark.skipif(not PCAPS.is_dir(), reason="TCPTRACE_NG_PCAPS not set to the captures repo"),
    pytest.mark.skipif(
        shutil.which("tcptrace") is None and not _VENDORED_TCPTRACE.is_file(),
        reason="tcptrace binary not available",
    ),
]

# Linux TCP_RTO_MIN. The rig's RTT is ~20 ms, so any retransmit sent sooner
# than this after the previous copy of its bytes was not an RTO. This is a
# fact about the rig's Linux sender, never a rule for the analyzer: FreeBSD's
# minimum is 30 ms and RFC 6298 asks for 1 s. A fix that reuses it passes
# here, where every sender is Linux, and mislabels other stacks.
_RTO_MIN_S = 0.2

# _classify_retx calls a retransmit `fast` only after >= 3 dup-ACKs and `rto`
# otherwise, so SACK/RACK recovery with fewer dup-ACKs reads as an RTO.
_RTO_BUG = "SACK/RACK recovery with < 3 dup-ACKs labelled rto"
# The receiver's ACKs carry a D-SACK for each of reorder's retransmits, which
# proves them spurious; neither the label nor the loss findings use it.
_DSACK_BUG = "D-SACK-proven spurious retransmits read as loss"
# A receiver-side capture labels each late fill `ooo`, never rtx, so loss
# findings there hang on dup_count >= 3 alone (bottleneck's SACK ACKs: all 0).
_RX_LOSS = "loss detectors read s.rtx; a receiver-side capture never sets it"
_STALL_SPLIT = "each RTO of a backoff series ends a stall, so one blackout reads as several"
_CLIFF_RTO = "cliff cause looks for loss within 2 windows; an RTO's retransmit comes later"


def _xfail(reason: str, *values):
    return pytest.param(*values, marks=pytest.mark.xfail(strict=True, reason=reason))


@functools.cache
def _models(scen: str, vantage: str):
    """(data-direction tsg, data-direction tput, finding codes) for one capture."""
    pcap = PCAPS / scen / f"{vantage}.pcap"
    _, tsg, tput, findings = build_models(pcap, out_dir=Path(tempfile.mkdtemp()))
    # srv -> cli carries the data: the direction with the most payload.
    side = max(
        ("fwd", "bwd"),
        key=lambda k: (
            sum(s.seq_end - s.seq_start for s in getattr(tsg, k).segments)
            if getattr(tsg, k)
            else -1
        ),
    )
    return getattr(tsg, side), getattr(tput, side), {f.code for f in findings}


def _drops(scen: str) -> int:
    text = (PCAPS / scen / "manifest.txt").read_text()
    return int(re.search(r"^drops=(\d+)$", text, re.M).group(1))


def _retx(tsg):
    """Data retransmits that are not spurious, each with the gap since the
    previous send of its first byte."""
    segs = sorted(tsg.segments, key=lambda s: s.time)
    out = []
    for i, s in enumerate(segs):
        if s.rtx in ("rto", "fast") and s.seq_end > s.seq_start:
            prev = max(
                (p.time for p in segs[:i] if p.seq_start <= s.seq_start < p.seq_end),
                default=None,
            )
            out.append((s, None if prev is None else s.time - prev))
    return out


# scenario -> (codes that must appear, codes that must not), at both vantages.
# capture_vantage is informational and not asserted.
_FINDINGS = {
    "loss": ({"sack_confirmed_loss"}, {"loss_storm"}),
    "gro": ({"sack_confirmed_loss"}, {"loss_storm"}),
    "storm": ({"loss_storm"}, set()),
    "bottleneck": ({"sack_confirmed_loss"}, set()),
    "slow_rcv": ({"zero_window"}, {"loss_storm", "sack_confirmed_loss"}),
    "reorder": (set(), {"loss_storm", "sack_confirmed_loss"}),
}


@pytest.mark.parametrize(
    "scen,vantage",
    [
        ("loss", "sender"),
        ("loss", "receiver"),
        ("gro", "sender"),
        ("gro", "receiver"),
        ("storm", "sender"),
        _xfail(_RX_LOSS, "storm", "receiver"),
        ("bottleneck", "sender"),
        # tbf tail drops follow timing, not the seed: whether any SACK ACK
        # reaches dup_count 3 changes with each generation.
        pytest.param("bottleneck", "receiver", marks=pytest.mark.xfail(reason=_RX_LOSS)),
        ("slow_rcv", "sender"),
        ("slow_rcv", "receiver"),
        _xfail(_DSACK_BUG, "reorder", "sender"),
        _xfail(_DSACK_BUG, "reorder", "receiver"),
    ],
)
def test_findings(scen, vantage):
    present, absent = _FINDINGS[scen]
    codes = _models(scen, vantage)[2]
    assert present <= codes and not (absent & codes), codes


# Sender side: non-spurious retransmits == drops, or >= where a recovery may
# legitimately resend bytes that were not lost (go-back-N after an RTO).
@pytest.mark.parametrize(
    "scen,rel",
    [
        ("loss", "eq"),
        ("gro", "eq"),
        ("storm", "ge"),
        ("bottleneck", "ge"),
        ("blackout", "ge"),
        _xfail(_DSACK_BUG, "slow_rcv", "eq"),
        _xfail(_DSACK_BUG, "reorder", "eq"),
    ],
)
def test_retransmits_match_drops(scen, rel):
    n, drops = len(_retx(_models(scen, "sender")[0])), _drops(scen)
    assert n == drops if rel == "eq" else n >= drops, f"retx={n} drops={drops}"


@pytest.mark.parametrize(
    "scen",
    [
        _xfail(_RTO_BUG, "loss"),
        _xfail(_RTO_BUG, "gro"),
        _xfail(_RTO_BUG, "storm"),
        _xfail(_RTO_BUG, "bottleneck"),
        "blackout",
        _xfail(_RTO_BUG, "slow_rcv"),
        _xfail(_RTO_BUG, "reorder"),
    ],
)
def test_rto_label_needs_rto_gap(scen):
    early = [
        (round(s.time, 3), round(gap, 3))
        for s, gap in _retx(_models(scen, "sender")[0])
        if s.rtx == "rto" and gap is not None and gap < _RTO_MIN_S
    ]
    assert not early, (
        f"{len(early)} rto-labelled retransmits sooner than {_RTO_MIN_S}s: {early[:5]}"
    )


def test_blackout_has_true_rto():
    assert any(
        s.rtx == "rto" and gap is not None and gap >= _RTO_MIN_S
        for s, gap in _retx(_models("blackout", "sender")[0])
    )


# Sender side only: a receiver-side capture cannot tell a blackout from a
# sender that paused, because it never sees the lost data.
@pytest.mark.xfail(strict=True, reason=_STALL_SPLIT)
def test_blackout_stall():
    stalls = _models("blackout", "sender")[1].stalls
    assert max((s.duration_s for s in stalls), default=0) >= 2.0, stalls


# blackout is paced and loses nothing outside the 2 s window, so every goodput
# cliff in it comes from that loss.
@pytest.mark.xfail(strict=True, reason=_CLIFF_RTO)
def test_blackout_cliffs_are_post_loss():
    cliffs = _models("blackout", "sender")[1].cliffs
    assert cliffs and all(c.cause_hint == "post-loss" for c in cliffs), cliffs


def test_gro_rig_coalesced_only_the_receiver():
    # Rig precondition, not an analyzer claim: without it `gro` is just `loss`.
    assert detect_offload(PCAPS / "gro" / "receiver.pcap").needs_desegment
    assert not detect_offload(PCAPS / "gro" / "sender.pcap").needs_desegment
