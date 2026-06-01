import shutil
from pathlib import Path

import pytest

from tcptrace_ng.runner import analyze_connection, list_connections

pytestmark = pytest.mark.skipif(
    shutil.which("tcptrace") is None,
    reason="tcptrace not installed",
)


def test_list_connections_returns_a_list(synthetic_pcap: Path):
    rows = list_connections(synthetic_pcap)
    assert isinstance(rows, list)
    # A 3-packet handshake should yield 1 connection. If tcptrace doesn't
    # detect any from the synthetic fixture, refine the byte layout in
    # `_build_synthetic_pcap` (most likely fix: correct IP/TCP checksums
    # or use scapy in the fixture).
    assert len(rows) >= 1


def test_analyze_connection_runs_against_synthetic(synthetic_pcap: Path, tmp_path: Path):
    rows = list_connections(synthetic_pcap)
    if not rows:
        pytest.skip("synthetic pcap produced no connections")
    out = tmp_path / "out"
    out.mkdir()
    result = analyze_connection(synthetic_pcap, conn_n=rows[0].n, output_dir=out)
    assert result.details_text  # non-empty
    # .xpl emission depends on tcptrace -G; tiny pcaps may produce zero plots.
    assert all(p.suffix == ".xpl" for p in result.xpl_files)
