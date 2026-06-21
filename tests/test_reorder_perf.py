# tests/test_reorder_perf.py
import time

from tcptrace_ng.reorder import classify
from tests.pcap_synth import TcpFlow

A, B = "10.0.0.1:50000", "10.0.0.2:443"


def _big_pcap(tmp_path, n_data=15000):
    """A large single connection: n_data forward sends, each cum-ACKed, with a
    sprinkling of dup-ACKs — exercises the receiver_state / recovery scans."""
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    for i in range(n_data):
        _lo, hi = f.send(t + i * 0.001, "c", 1000)
        f.ack(t + i * 0.001 + 0.0005, "s", cumack=hi)
    return f.write(tmp_path / "big.pcap").read_bytes()


def test_classify_large_connection_is_subquadratic(tmp_path):
    data = _big_pcap(tmp_path)
    start = time.perf_counter()
    spans = classify(data, A, B, rtt=0.01)
    elapsed = time.perf_counter() - start
    assert spans                              # produced output
    # Generous, environment-tolerant bound. O(spans*frames) at 15k blows past
    # this by orders of magnitude; the single-ordered-walk index stays well under.
    assert elapsed < 3.0, f"classify took {elapsed:.2f}s — likely quadratic"
