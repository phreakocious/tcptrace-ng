#!/usr/bin/env bash
# fetch.sh — pull curated real-world TCP pcaps for fixture testing.
#
# Run from anywhere; files land in this script's directory.
# Re-running is idempotent: existing files with matching sha256 are skipped.
#
# Each entry is annotated with the auto-detection-heuristics design code
# (D-LIMIT / D-NOWS / D-ZWIN / D-NAGLE / D-OUTCOME / D-CAPVANTAGE) it targets.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# fetch URL FILENAME EXPECTED_SHA256 TARGET_CODE PURPOSE
fetch() {
  local url="$1" fname="$2" want_sha="$3" code="$4" purpose="$5"
  if [[ -f "$fname" ]]; then
    have_sha=$(shasum -a 256 "$fname" | awk '{print $1}')
    if [[ "$want_sha" == "SKIP" || "$have_sha" == "$want_sha" ]]; then
      printf '  ok      %-45s [%s]\n' "$fname" "$code"
      return
    fi
    printf '  refetch %-45s [%s] (sha mismatch)\n' "$fname" "$code"
  fi
  printf '  fetch   %-45s [%s] %s\n' "$fname" "$code" "$purpose"
  curl -fsSL --retry 3 -o "$fname.tmp" "$url"
  mv "$fname.tmp" "$fname"
  got_sha=$(shasum -a 256 "$fname" | awk '{print $1}')
  if [[ "$want_sha" != "SKIP" && "$got_sha" != "$want_sha" ]]; then
    printf '\n  WARNING: %s sha mismatch\n    want %s\n    got  %s\n\n' \
      "$fname" "$want_sha" "$got_sha" >&2
  fi
}

echo "Fetching real-world TCP pcap fixtures into: $DIR"
echo

# --- Wireshark SampleCaptures wiki ----------------------------------------
WS="https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures"

fetch "$WS/200722_win_scale_examples_anon.pcapng" \
      "ws_win_scale_examples.pcapng" SKIP \
      D-NOWS "labeled wscale: present, absent, unknown"

fetch "$WS/tcp-ecn-sample.pcap" \
      "ws_tcp_ecn_sample.pcap" SKIP \
      D-LIMIT/A2 "ECN with labeled CE on frame 48 (congestion)"

fetch "$WS/nfs_bad_stalls.cap" \
      "ws_nfs_bad_stalls.cap" SKIP \
      D-NAGLE/B1 "~38ms stalls mid-response (staircase TSG)"

fetch "$WS/tcp-ethereal-file1.trace" \
      "ws_tcp_ethereal_file1.pcap" SKIP \
      D-LIMIT/A4 "large multi-segment POST — healthy bulk anchor"

fetch "$WS/http_redirects.pcapng" \
      "ws_http_redirects.pcapng" SKIP \
      D-OUTCOME/A8 "many short connections with clean closes"

# --- PacketLife.net (TCP fundamentals; tiny captures) ---------------------
# packetlife is allowlist-friendly; small (KB) files, hand-labeled by topic.
PL="https://packetlife.net/media/captures"

fetch "$PL/tcp.cap"         "pl_tcp.cap"          SKIP D-OUTCOME "3WHS + data + close"
fetch "$PL/http.cap"        "pl_http.cap"         SKIP D-LIMIT/A4 "short HTTP transfer"

# --- A handful of synth-friendly real captures from the repo --------------
# (already vendored, listed here for completeness in the manifest)
#   ../../../np.pcap                  — keepalive-as-loss negative anchor
#   ../../../example_8_dupe_acks.pcapng — dup-ACK/reordering
#   ../../../config_change.pcapng     — large real transfer
#   ../../../firmware_download.pcapng — large real transfer
#   ../../../firmware_flash.pcapng    — large real transfer

echo
echo "Done. Manifest in $DIR/README.md."
echo "Verify with vendored tcptrace:"
echo "  for f in $DIR/*.{pcap,pcapng,cap}; do echo \"=== \$f ===\"; \\"
echo "    ./vendor/tcptrace/tcptrace -l -r \"\$f\" 2>/dev/null | head -40; done"
