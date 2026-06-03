"""Format-sniffing reader factory for classic pcap and pcapng captures.

tcptrace itself reads pcapng natively, but our pre-flight detectors (csum,
offload, decap) walk the capture with dpkt. dpkt's pcap and pcapng readers are
separate classes with no auto-detection: ``dpkt.pcap.Reader`` raises
``ValueError`` on a pcapng Section Header Block. Since pcapng is the modern
default (tshark / dumpcap / Wireshark all emit it), construct the reader by
sniffing the 4-byte magic so every detector handles both formats transparently.
"""

from __future__ import annotations

from typing import BinaryIO

import dpkt

# pcapng Section Header Block type. It is byte-order independent (it doubles as
# the format's byte-order magic), so a single value identifies pcapng. Classic
# pcap has four magics (big/little endian x us/ns), all handled by
# dpkt.pcap.Reader, so we only special-case pcapng here.
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def open_reader(fileobj: BinaryIO) -> dpkt.pcap.Reader | dpkt.pcapng.Reader:
    """Return a dpkt reader for `fileobj`, sniffing classic pcap vs pcapng.

    Peeks the first 4 bytes and rewinds, so the returned reader sees the full
    stream. A pcapng magic yields ``dpkt.pcapng.Reader``; anything else falls
    through to ``dpkt.pcap.Reader``, which handles all classic byte-order /
    timestamp variants and raises ``ValueError`` on an unreadable header.
    """
    magic = fileobj.read(4)
    fileobj.seek(0)
    if magic == _PCAPNG_MAGIC:
        return dpkt.pcapng.Reader(fileobj)
    return dpkt.pcap.Reader(fileobj)
