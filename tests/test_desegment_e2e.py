# tests/test_desegment_e2e.py
"""End-to-end: a de-coalesced pcap makes real tcptrace read wire-plausible segments."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tcptrace_ng.desegment import desegment_pcap
from tcptrace_ng.offload import _tcp_payload_len
from tcptrace_ng.pcap_io import open_reader
from tcptrace_ng.runner import _VENDORED_TCPTRACE, analyze_connection
from tcptrace_ng.tcp_inspect import synthesize as synthesize_tsg
from tcptrace_ng.xpl_grouper import group_xpls
from tcptrace_ng.xpl_parser import parse_xpl
from tests.pcap_synth import TcpFlow

_HAVE_TCPTRACE = shutil.which("tcptrace") is not None or _VENDORED_TCPTRACE.is_file()


def _payloads(pcap: Path) -> list[int]:
    out = []
    with pcap.open("rb") as f:
        for _ts, buf in open_reader(f):
            n = _tcp_payload_len(buf)
            if n:
                out.append(n)
    return out


def _coalesced_flow(tmp_path: Path) -> Path:
    fl = TcpFlow()
    t = fl.handshake(0.0, rtt=0.04)
    for _ in range(10):  # 10 coalesced 8 KB super-segments server->client
        fl.send(t, "s", 8000)
        fl.ack(t + 0.001, "c")
        t += 0.02
    return fl.write(tmp_path / "tso.pcap")


def test_desegment_split_counts(tmp_path):
    """Pure: 10x8000 -> ceil(8000/1460)=6 pieces each = 60, none over MSS."""
    src = _coalesced_flow(tmp_path)
    out = tmp_path / "deseg.pcap"
    res = desegment_pcap(src, out)
    assert res.frames_split == 10 and res.pieces_emitted == 60
    sizes = _payloads(out)
    assert max(sizes) <= 1460 and sizes.count(1460) == 50 and sizes.count(700) == 10


@pytest.mark.skipif(not _HAVE_TCPTRACE, reason="tcptrace binary not available")
def test_desegment_tcptrace_reads_mss_sized_segments(tmp_path):
    """tcptrace, run on the de-coalesced copy, sees MSS-sized segments (not 8 KB)."""
    src = _coalesced_flow(tmp_path)
    out = tmp_path / "deseg.pcap"
    desegment_pcap(src, out)
    res = analyze_connection(out, 1, tmp_path / ".pipeline", no_dns=True, with_rtt=True)
    tsg = next((g for g in group_xpls(res.xpl_files) if g.metric == "tsg"), None)
    assert tsg is not None
    fwd = parse_xpl(tsg.forward) if tsg.forward else None
    bwd = parse_xpl(tsg.backward) if tsg.backward else None
    pair = synthesize_tsg(fwd, bwd, res.details_text)
    segs = []
    for m in (pair.fwd, pair.bwd):
        if m is not None:
            segs += [s for s in m.segments if s.seq_end > s.seq_start]
    assert segs, "expected data segments"
    assert max(s.seq_end - s.seq_start for s in segs) <= 1460
    assert len([s for s in segs if (s.seq_end - s.seq_start) > 1]) >= 50


@pytest.mark.skipif(not _HAVE_TCPTRACE, reason="tcptrace binary not available")
def test_fabricated_segments_tagged_through_pipeline(tmp_path):
    src = _coalesced_flow(tmp_path)  # 10x8000 B server->client, handshake MSS 1460
    out = tmp_path / "deseg.pcap"
    res = desegment_pcap(src, out)
    manifest = [
        {
            "time": c.time,
            "src": c.src,
            "dst": c.dst,
            "parent_seq_start": c.parent_seq_start,
            "parent_seq_end": c.parent_seq_end,
            "pieces": c.pieces,
            "mss": c.mss,
            "mss_source": c.mss_source,
        }
        for c in res.coalesces
    ]
    r = analyze_connection(out, 1, tmp_path / ".pipeline", no_dns=True, with_rtt=True)
    tsg = next((g for g in group_xpls(r.xpl_files) if g.metric == "tsg"), None)
    fwd = parse_xpl(tsg.forward) if tsg and tsg.forward else None
    bwd = parse_xpl(tsg.backward) if tsg and tsg.backward else None
    # Pass the manifest to BOTH directions; timestamp+seq matching tags only the
    # real data pieces (the ack-only direction has no matching segments).
    pair = synthesize_tsg(fwd, bwd, r.details_text, coalesces_fwd=manifest, coalesces_bwd=manifest)
    fab = [s for m in (pair.fwd, pair.bwd) if m for s in m.segments if s.fabricated]
    data = [s for m in (pair.fwd, pair.bwd) if m for s in m.segments if s.seq_end > s.seq_start]
    assert len(fab) == 60, f"expected all 60 pieces tagged, got {len(fab)}"
    assert len(fab) == len(data), "every data segment should be a fabricated piece"
