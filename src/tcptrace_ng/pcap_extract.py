"""Filter a pcap down to one TCP conversation, written as classic pcap.

The download-pcap button on the per-connection header feeds the effective pcap
(post-decap/desegment — the data tcptrace actually analyzed) through this
module, so what lands on disk matches what the user is staring at on screen.
Output is classic pcap (DLT preserved from the input) regardless of input
container, so the resulting file opens in tools that don't read pcapng.
"""

from __future__ import annotations

import io
import socket
from pathlib import Path

import dpkt

from .pcap_io import open_reader


def _split_endpoint(ep: str) -> tuple[str, int] | None:
    """Mirror of `app._split_endpoint`: rpartition on ':' for ip+port.

    Handles IPv4 (`1.2.3.4:80`) and tcptrace's IPv6 colon form (`fe80::1:80`).
    """
    if ":" not in ep:
        return None
    ip, _, port = ep.rpartition(":")
    if not port.isdigit():
        return None
    return ip, int(port)


def _canon(ip: str) -> str | None:
    """Canonicalize an IP literal so string compares are family-tolerant.

    `socket.inet_ntop(inet_pton(x))` normalizes case, zero-suppression, and
    embedded-v4 forms — `0001:0:0:0:0:0:0:1` and `::1` compare equal after.

    Tolerates one tcptrace quirk: its IPv6 formatter prints IPv4-mapped
    addresses as `:ffff:bc6f:049e` instead of `::ffff:bc6f:049e` (one
    leading colon). Retry with the colon restored before giving up.
    """
    s = ip.strip("[]")
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            return socket.inet_ntop(family, socket.inet_pton(family, s))
        except OSError:
            continue
    if s.startswith(":") and not s.startswith("::"):
        try:
            return socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, ":" + s))
        except OSError:
            pass
    return None


def extract_conversation(pcap_path: Path, host_a: str, host_b: str) -> bytes:
    """Classic-pcap bytes containing the TCP frames between host_a and host_b.

    Either endpoint is `ip:port` in tcptrace's format. The output preserves
    original L2/L3 framing and timestamps. Frames whose L2 doesn't reach IP, or
    whose L4 isn't TCP, are dropped. Returns `b""` if either endpoint can't be
    parsed.
    """
    ea = _split_endpoint(host_a)
    eb = _split_endpoint(host_b)
    if ea is None or eb is None:
        return b""
    a_ip, a_port = _canon(ea[0]), ea[1]
    b_ip, b_port = _canon(eb[0]), eb[1]
    if a_ip is None or b_ip is None:
        return b""

    out = io.BytesIO()
    with pcap_path.open("rb") as fin:
        reader = open_reader(fin)
        linktype = reader.datalink()
        writer = dpkt.pcap.Writer(out, linktype=linktype, snaplen=65535)
        for ts, frame in reader:
            if _matches(frame, linktype, a_ip, a_port, b_ip, b_port):
                writer.writepkt(frame, ts)
    return out.getvalue()


def _matches(
    frame: bytes,
    linktype: int,
    a_ip: str,
    a_port: int,
    b_ip: str,
    b_port: int,
) -> bool:
    """True iff `frame` is a TCP packet between the two endpoints (either way)."""
    try:
        if linktype == dpkt.pcap.DLT_EN10MB:
            ip = dpkt.ethernet.Ethernet(frame).data
        elif linktype == dpkt.pcap.DLT_RAW:
            if not frame:
                return False
            ver = (frame[0] >> 4) & 0xF
            if ver == 4:
                ip = dpkt.ip.IP(frame)
            elif ver == 6:
                ip = dpkt.ip6.IP6(frame)
            else:
                return False
        else:
            return False
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return False

    if isinstance(ip, dpkt.ip.IP):
        is_v6 = False
    elif isinstance(ip, dpkt.ip6.IP6):
        is_v6 = True
    else:
        return False

    tcp = ip.data
    if not isinstance(tcp, dpkt.tcp.TCP):
        return False

    family = socket.AF_INET6 if is_v6 else socket.AF_INET
    src_ip = socket.inet_ntop(family, ip.src)
    dst_ip = socket.inet_ntop(family, ip.dst)

    return (
        src_ip == a_ip and tcp.sport == a_port and dst_ip == b_ip and tcp.dport == b_port
    ) or (
        src_ip == b_ip and tcp.sport == b_port and dst_ip == a_ip and tcp.dport == a_port
    )
