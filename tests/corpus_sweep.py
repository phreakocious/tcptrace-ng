# tests/corpus_sweep.py
"""Real-capture sweep: every finding, stall and cliff the pipeline reports, per
connection direction, across local pcaps. The before/after instrument for
detector false positives and blind spots. Not collected by pytest (the corpus is
gitignored and local); run from the repo root:

    PYTHONPATH=src python -m tests.corpus_sweep *.pcap *.pcapng
"""

from __future__ import annotations

import sys
import tempfile
from collections import Counter
from pathlib import Path

from tests.diag_pipeline import build_models, conn_count


def _direction(tag: str, tsg, tput) -> tuple[list[str], Counter]:
    kinds = Counter(a.kind for a in tsg.anomalies)
    tally = Counter(stalls=len(tput.stalls), cliffs=len(tput.cliffs), zero_win=kinds["zero_win"])
    rtx = Counter(s.rtx for s in tsg.segments if s.rtx)
    lines = [
        f"  {tag} {tsg.src}->{tsg.dst} segs={len(tsg.segments)} rtx={dict(rtx)} "
        f"zero_win={kinds['zero_win']} win_shrink={kinds['win_shrink']} "
        f"win_shrink_large={kinds['win_shrink_large']}"
    ]
    lines += [
        f"    stall {s.t_start:.3f}+{s.duration_s:.3f}s pending={s.pending_bytes} "
        f"x{s.rtt_multiple:.1f}rtt {s.severity}"
        for s in tput.stalls
    ]
    lines += [
        f"    cliff {c.t:.3f} -{c.drop_frac:.0%} {c.cause_hint} {c.severity}" for c in tput.cliffs
    ]
    return lines, tally


def main(pcaps: list[str]) -> None:
    total = Counter()
    with tempfile.TemporaryDirectory() as tmp:
        for p in map(Path, pcaps):
            for n in range(1, conn_count(p) + 1):
                _, tsg, tput, findings = build_models(p, n, out_dir=Path(tmp) / p.name / str(n))
                out = [f"{p.name} conn {n}"]
                for tag in ("fwd", "bwd"):
                    if getattr(tsg, tag) and getattr(tput, tag):
                        lines, tally = _direction(tag, getattr(tsg, tag), getattr(tput, tag))
                        out += lines
                        total += tally
                out += [
                    f"  finding {f.code} {f.severity} {f.scope}: {f.headline}" for f in findings
                ]
                total.update(f"finding:{f.code}:{f.severity}" for f in findings)
                total["conns"] += 1
                print("\n".join(out))
    print("TOTAL", dict(sorted(total.items())))


if __name__ == "__main__":
    main(sys.argv[1:])
