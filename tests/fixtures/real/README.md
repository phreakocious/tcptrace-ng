# Real-world TCP pcap fixtures

Curated, externally-sourced captures with **hand-labelable pathologies** that map
1:1 onto the detections in `docs/superpowers/specs/2026-06-02-auto-detection-heuristics-design.md`.

These are *regression anchors* (§III.3 layer 3 in the design doc), not unit
fixtures. The synthetic `dpkt`-built fixtures from `pcap_synth.py` are what drive
per-detection positive/negative tests; this directory's job is "does the
detector stay sane on actual traffic captured in the wild."

## How to populate

```sh
./fetch.sh
```

The script is idempotent — re-runs skip files already on disk. The sandbox in
which Cowork mode runs cannot reach `wiki.wireshark.org`, `cloudshark.org`, or
`raw.githubusercontent.com` (allowlist), so this has to run on a host with
unrestricted network. Roughly 1–2 MB total.

## What each file is for

| File | Source | Heuristic | Expected `Finding` set |
|---|---|---|---|
| `ws_win_scale_examples.pcapng` | Wireshark wiki — labeled "Window Scaling examples - available, no scaling and missing/unknown" | **D-NOWS / A10** | `wscale_missing` fires on the unscaled high-RTT flow, silent on scaled |
| `ws_tcp_ecn_sample.pcap` | Wireshark wiki — ECN sample, frame 48 has CE | **D-LIMIT / A2** | ECN-CE annotation; may also exercise A4 if no loss |
| `ws_nfs_bad_stalls.cap` | Wireshark wiki — NFS with ~38 ms stalls in read responses | **D-NAGLE / B1** (or **A3** app-limited if irregular) | `delayed_ack_stall` or `app_limited` — distinguishes the two |
| `ws_tcp_ethereal_file1.pcap` | Wireshark wiki — large POST, many segments | **D-LIMIT / A4** | `healthy` — anchor for "must not cry wolf on a clean bulk transfer" |
| `ws_http_redirects.pcapng` | Wireshark wiki — many short HTTP/302 hops | **D-OUTCOME / A8** | Each connection: clean close or RST-as-TIME_WAIT-skip → info, not bad |
| `pl_tcp.cap` | PacketLife — basic 3WHS+data+close | **D-OUTCOME** | Trivial: SYN/ACK/data/FIN; sanity baseline |
| `pl_http.cap` | PacketLife — short HTTP | **D-LIMIT / A4** | Small flow → below size gate → no D-LIMIT verdict |

## In-repo anchors (already present, listed here for the cross-product sweep)

| File | Heuristic | Truth |
|---|---|---|
| `../../../np.pcap` | **D-LOSSSTORM** negative; **D-CAPVANTAGE** positive | 1-byte "retx" is keepalive → loss_storm MUST NOT fire; vantage = client-adjacent (a→b 89.6 ms, b→a 0.4 ms) |
| `../../../example_8_dupe_acks.pcapng` | **B5** reordering / dup-ACKs | Dup-ACKs without sustained loss → reordering verdict, not loss storm |
| `../../../config_change.pcapng` | broad regression | Hand-reviewed expected finding set; any new finding ⇒ investigate |
| `../../../firmware_download.pcapng` | broad regression | Hand-reviewed expected finding set |
| `../../../firmware_flash.pcapng` | broad regression | Hand-reviewed expected finding set |

## Licensing

All fetched files are from publicly published sample-capture repositories
intended for educational/testing use. Original sources cited in `fetch.sh`.
Do not commit these binaries to git — `fetch.sh` is the source of truth.

## Adding a fixture

1. Add a `fetch ...` line to `fetch.sh` with the target detection code.
2. Add a row to the table above with the expected `Finding` set.
3. Add an entry in `tests/test_real_fixtures.py` (per §III.3) that asserts
   the exact finding set on this file. Failure ⇒ either a regression in
   `diagnose()` or the fixture changed upstream; investigate before "fixing."
