# tests/test_diagnose_sweep.py
"""Cross-product false-positive sweep.

Each *pathology* detector must fire only on its own positive fixture, never on
another's. This is the structural guard for the no-false-positives goal; add one
row to _CASES per new detector. `capture_vantage` is informational (severity
'good') and may legitimately co-occur, so it is not a pathology and is ignored.
"""

from __future__ import annotations

import shutil

import pytest

from tcptrace_ng.runner import _VENDORED_TCPTRACE
from tests.diag_pipeline import run_pipeline
from tests.pcap_synth import TcpFlow
from tests.test_diagnose_e2e import _bulk_transfer, _codes

pytestmark = pytest.mark.skipif(
    shutil.which("tcptrace") is None and not _VENDORED_TCPTRACE.is_file(),
    reason="tcptrace binary not available",
)


def _vantage_clean(tmp_path, name):
    """Asymmetric-RTT transfer below the loss-storm floor — no pathology."""
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
    return fl.write(tmp_path / name)


def _loss_heavy(tmp_path, name):
    return _bulk_transfer(tmp_path, name, n_drops=12)


# (label, builder, the one pathology code it SHOULD raise — or None)
_CASES = [
    ("vantage_clean", _vantage_clean, None),
    ("loss_heavy", _loss_heavy, "loss_storm"),
]
_ALL_PATHOLOGIES = {code for _, _, code in _CASES if code}


@pytest.mark.parametrize("label,builder,own", _CASES)
def test_detector_fires_only_on_its_own_fixture(tmp_path, label, builder, own):
    codes = _codes(run_pipeline(builder(tmp_path, f"{label}.pcap")))
    if own:
        assert own in codes, f"{label}: expected {own}, got {codes}"
    spurious = (codes & _ALL_PATHOLOGIES) - ({own} if own else set())
    assert not spurious, f"{label}: spurious pathology findings {spurious}"
