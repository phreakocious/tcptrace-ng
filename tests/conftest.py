"""Shared test fixtures."""

import struct
from pathlib import Path

import pytest

pytest_plugins = ["nicegui.testing.user_plugin"]


SAMPLE_LISTING = """\
1 arg remaining, starting with 'test.pcap'
Ostermann's tcptrace -- version 6.6.7 -- Thu Nov  4, 2004

42367 packets seen, 42367 TCP packets traced
elapsed wallclock time: 0:00:00.123456, 343333 pkts/sec analyzed
trace file elapsed time: 0:00:30.000000
TCP connection info:
  1: 10.0.0.1:443 - 10.0.0.2:51234 (a2b)              42 ackpkts sent
  2: 10.0.0.3:80 - 10.0.0.4:39281 (c2d)               14 ackpkts sent
  3: 192.168.1.5:22 - 192.168.1.99:60001 (e2f)        99 ackpkts sent (complete)
"""


@pytest.fixture
def sample_listing():
    return SAMPLE_LISTING


def _build_synthetic_pcap() -> bytes:
    """Three packets forming a SYN/SYN-ACK/ACK handshake between 10.0.0.1:1234 and 10.0.0.2:5678."""

    # Global header: pcap magic, version, tz, sigfigs, snaplen, linktype=ethernet (1)
    pcap_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    def packet(ts_sec: int, ts_usec: int, flags: int, seq: int, ack: int) -> bytes:
        # Ethernet
        eth = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00"  # dst, src, type=IPv4
        # IPv4: ver/ihl, tos, total len, id, frag, ttl, proto, csum, src, dst
        ip_len = 20 + 20  # ip + tcp, no payload
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, ip_len, 0, 0, 64, 6, 0,
            b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02",
        )
        # TCP: sport, dport, seq, ack, off/reserved, flags, window, csum, urg
        tcp = struct.pack(
            "!HHIIBBHHH",
            1234, 5678, seq, ack, (5 << 4), flags, 65535, 0, 0,
        )
        payload = eth + ip + tcp
        rec_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(payload), len(payload))
        return rec_hdr + payload

    p1 = packet(1000, 0, 0x02, 0, 0)              # SYN client->server
    p2 = packet(1000, 1000, 0x12, 0, 1)           # SYN/ACK server->client (we keep src/dst simplified)
    p3 = packet(1000, 2000, 0x10, 1, 1)           # ACK client->server

    return pcap_hdr + p1 + p2 + p3


@pytest.fixture
def synthetic_pcap(tmp_path: Path) -> Path:
    pcap = tmp_path / "synthetic.pcap"
    pcap.write_bytes(_build_synthetic_pcap())
    return pcap
