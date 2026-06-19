# tests/pcap_synth.py
"""Deterministic TCP-flow -> pcap builder for detection fixtures.

Every packet carries an explicit wall-clock timestamp, so RTT, gaps and stalls
are fully scripted. Checksums are computed by dpkt via the object idiom (pass
the TCP *object* as IP data with sum=0). Writer snaplen is 65535 so full-MSS
frames are not read as truncated by tcptrace. Output is DLT_EN10MB classic pcap.

Timestamp convention = capture adjacent to the client: a SYN-ACK / server data
segment is stamped at the tap when it arrives at the client, and the client's
ACK is stamped ~immediately after. `handshake(t0, rtt)` therefore yields
`RTT from 3WHS` of ~rtt for a->b and ~0 for b->a.
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path

import dpkt

ETH_TYPE_IP = 0x0800
TH_FIN, TH_SYN, TH_RST, TH_PSH, TH_ACK = 0x01, 0x02, 0x04, 0x08, 0x10
_EPS = 1e-4  # local-stack turnaround at the tap


def _ip(addr: str) -> bytes:
    return socket.inet_aton(addr)


def _nop() -> bytes:
    return bytes([1])


def _pad4(o: bytes) -> bytes:
    while len(o) % 4:
        o += _nop()
    return o


def _syn_opts(mss: int, wscale: int) -> bytes:
    opts = bytes([2, 4]) + struct.pack("!H", mss)  # MSS
    opts += bytes([4, 2])  # SACK permitted
    opts += bytes([3, 3, wscale])  # window scale
    opts += bytes([8, 10]) + struct.pack("!II", 1, 0)  # timestamps
    return _pad4(opts)


class TcpFlow:
    """Script a bidirectional TCP flow, then `write(path)` a pcap.

    Sides are "c" (client) and "s" (server). Seq/ack bookkeeping is automatic;
    `retransmit`/`keepalive` deliberately reuse old seqs.
    """

    def __init__(
        self,
        *,
        client: tuple[str, int] = ("10.0.0.1", 50000),
        server: tuple[str, int] = ("10.0.0.2", 443),
        mss: int = 1460,
        wscale: int = 7,
        tsval_clock_hz: int = 1000,
    ) -> None:
        self.cli_ip, self.cli_port = _ip(client[0]), client[1]
        self.srv_ip, self.srv_port = _ip(server[0]), server[1]
        self.cli_mac = b"\x00\x11\x22\x33\x44\x55"
        self.srv_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        self.mss, self.wscale = mss, wscale
        self.seq = {"c": 1000, "s": 9000}  # next seq to send
        # NB: NOT named `ack` — that would shadow the ack() method below, and
        # `fl.ack(...)` would resolve to this dict and raise TypeError.
        self.cumack = {"c": 0, "s": 0}  # cumulative ack of the other side
        self.win = {"c": 64240, "s": 65160}
        self.tsval_clock_hz = tsval_clock_hz
        self._ipid = {"c": 1000, "s": 40000}
        self._pkts: list[tuple[float, bytes]] = []

    # --- packet emission -------------------------------------------------
    def _emit(self, t, frm, seq, ack, flags, win, opts=b"", data=b"", ip_id=None, tsval=None):
        if frm == "c":
            src, sport, dst, dport = self.cli_ip, self.cli_port, self.srv_ip, self.srv_port
            smac, dmac = self.cli_mac, self.srv_mac
        else:
            src, sport, dst, dport = self.srv_ip, self.srv_port, self.cli_ip, self.cli_port
            smac, dmac = self.srv_mac, self.cli_mac
        # Stamp a TS option onto data/ack frames that weren't given explicit opts.
        if not opts:
            v = tsval if tsval is not None else int(t * self.tsval_clock_hz) & 0xFFFFFFFF
            opts = struct.pack("!BBII", dpkt.tcp.TCP_OPT_TIMESTAMP, 10, v, 0)
        opts = _pad4(opts)
        if ip_id is None:
            ip_id = self._ipid[frm] & 0xFFFF
            self._ipid[frm] += 1
        tcp = dpkt.tcp.TCP(
            sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, win=win, sum=0, data=data
        )
        tcp.opts = opts
        tcp.off = 5 + len(opts) // 4
        ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_TCP, ttl=64, id=ip_id, sum=0, data=tcp)
        eth = dpkt.ethernet.Ethernet(src=smac, dst=dmac, type=ETH_TYPE_IP, data=ip)
        self._pkts.append((t, bytes(eth)))

    # --- scripting API ---------------------------------------------------
    def handshake(self, t0: float, rtt: float) -> float:
        """SYN, SYN-ACK (rtt later), ACK. Returns the time after the handshake."""
        o = _syn_opts(self.mss, self.wscale)
        self._emit(t0, "c", self.seq["c"], 0, TH_SYN, self.win["c"], o)
        self._emit(
            t0 + rtt, "s", self.seq["s"], self.seq["c"] + 1, TH_SYN | TH_ACK, self.win["s"], o
        )
        self._emit(
            t0 + rtt + _EPS,
            "c",
            self.seq["c"] + 1,
            self.seq["s"] + 1,
            TH_ACK,
            self.win["c"] >> self.wscale,
        )
        self.seq["c"] += 1
        self.seq["s"] += 1
        self.cumack["c"] = self.seq["s"]
        self.cumack["s"] = self.seq["c"]
        return t0 + rtt + _EPS

    def send(self, t: float, frm: str, nbytes: int, *, push: bool = True, ip_id=None, tsval=None) -> tuple[int, int]:
        """Send `nbytes` of data from `frm`. Returns the (seq_lo, seq_hi) sent."""
        flags = TH_ACK | (TH_PSH if push else 0)
        lo = self.seq[frm]
        self._emit(
            t, frm, lo, self.cumack[frm], flags, self.win[frm] >> self.wscale, data=b"X" * nbytes, ip_id=ip_id, tsval=tsval
        )
        self.seq[frm] += nbytes
        return lo, self.seq[frm]

    def ack(self, t: float, frm: str, *, rwin: int | None = None,
            sack=None, cumack: int | None = None) -> None:
        """Pure ACK from `frm`. By default cum-ACKs everything the other side
        has sent; pass `cumack` to hold it below a hole. `sack` is a list of
        (lo, hi) blocks emitted as a SACK option (a first block whose hi edge
        is <= cum-ACK is a D-SACK)."""
        other = "s" if frm == "c" else "c"
        self.cumack[frm] = self.seq[other] if cumack is None else cumack
        win_field = (rwin >> self.wscale) if rwin is not None else (self.win[frm] >> self.wscale)
        opts = b""
        if sack:
            tsv = int(t * self.tsval_clock_hz) & 0xFFFFFFFF
            opts = struct.pack("!BBII", dpkt.tcp.TCP_OPT_TIMESTAMP, 10, tsv, 0)
            blocks = b"".join(struct.pack("!II", lo, hi) for lo, hi in sack)
            opts += struct.pack("!BB", dpkt.tcp.TCP_OPT_SACK, 2 + len(blocks)) + blocks
        self._emit(t, frm, self.seq[frm], self.cumack[frm], TH_ACK, win_field, opts=opts)

    def retransmit(self, t: float, frm: str, seq: int, nbytes: int, *, ip_id=None, tsval=None) -> None:
        """Re-send an OLD seq range (loss recovery) without advancing seq."""
        self._emit(
            t,
            frm,
            seq,
            self.cumack[frm],
            TH_ACK | TH_PSH,
            self.win[frm] >> self.wscale,
            data=b"X" * nbytes,
            ip_id=ip_id,
            tsval=tsval,
        )

    def keepalive(self, t: float, frm: str) -> None:
        """1-byte sub-cumack keepalive probe (must NOT count as loss)."""
        self._emit(
            t,
            frm,
            self.seq[frm] - 1,
            self.cumack[frm],
            TH_ACK,
            self.win[frm] >> self.wscale,
            data=b"X",
        )

    def fin(self, t: float, frm: str) -> None:
        self._emit(
            t, frm, self.seq[frm], self.cumack[frm], TH_FIN | TH_ACK, self.win[frm] >> self.wscale
        )
        self.seq[frm] += 1

    def write(self, path: Path) -> Path:
        with open(path, "wb") as f:
            w = dpkt.pcap.Writer(f, snaplen=65535, linktype=1)
            for t, frame in sorted(self._pkts, key=lambda p: p[0]):
                w.writepkt(frame, ts=t)
        return Path(path)
