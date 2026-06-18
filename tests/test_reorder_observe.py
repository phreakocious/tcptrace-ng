import pytest

from tcptrace_ng.reorder import observe
from tests.pcap_synth import TcpFlow

A, B = "10.0.0.1:50000", "10.0.0.2:443"


def test_observe_end_to_end(tmp_path):
    f = TcpFlow()
    t = f.handshake(0.0, 0.01)
    f.send(t, "c", 1000)
    spans = observe(f.write(tmp_path / "e.pcap").read_bytes(), A, B)
    s = next(x for x in spans if x.src == A)
    assert s.sequence_observation == "in_order"
    assert s.receiver_state == "unknown"
    assert s.duplicate_observation is False


def test_observe_raises_on_multi_connection(tmp_path):
    f1 = TcpFlow(client=("10.0.0.1", 50000))
    f2 = TcpFlow(client=("10.0.0.9", 50009))

    t1 = f1.handshake(0.0, 0.01)
    f1.send(t1, "c", 100)
    f1.send(t1 + 0.005, "s", 100)

    t2 = f2.handshake(0.2, 0.01)
    f2.send(t2, "c", 100)
    f2.send(t2 + 0.005, "s", 100)

    # Merge both flows' packets by capture time and write as one pcap
    f1._pkts = sorted(f1._pkts + f2._pkts, key=lambda p: p[0])
    pcap_bytes = f1.write(tmp_path / "two_conns.pcap").read_bytes()

    with pytest.raises(ValueError, match="pre-filtered"):
        observe(pcap_bytes, A, B)
