"""Subprocess wrappers around tcptrace and Wireshark CLI tools.

The only module in tcptrace_ng that shells out. Returns parsed structures,
never raw subprocess output.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .stats_parser import ConnStats, parse_stats


class RunnerError(RuntimeError):
    """Raised when an external tool fails or is missing."""


_VENDORED_TCPTRACE = (
    Path(__file__).resolve().parents[2] / "vendor" / "tcptrace" / "tcptrace"
)


def _resolve_tcptrace() -> str:
    """Locate the tcptrace binary: $TCPTRACE_BIN > vendored > PATH.

    The vendored copy lives at `<repo>/vendor/tcptrace/tcptrace` (a submodule
    of github.com/phreakocious/tcptrace, built via `make vendor-tcptrace`). Only
    findable when running from a source checkout — installed wheels fall back
    to PATH.
    """
    if env := os.environ.get("TCPTRACE_BIN"):
        return env
    if _VENDORED_TCPTRACE.is_file() and os.access(_VENDORED_TCPTRACE, os.X_OK):
        return str(_VENDORED_TCPTRACE)
    found = shutil.which("tcptrace")
    if found is None:
        raise RunnerError(
            "tcptrace not found (try: make vendor-tcptrace, or brew install tcptrace)"
        )
    return found


@dataclass(frozen=True)
class ConnRow:
    n: int
    host_a: str
    host_b: str
    raw_line: str


_CONN_RE = re.compile(r"^\s*(\d+):\s+(\S+)\s+-\s+(\S+)\s+\(")


def parse_listing(text: str) -> list[ConnRow]:
    """Extract ConnRow records from tcptrace's initial listing output."""
    rows: list[ConnRow] = []
    for raw in text.splitlines():
        m = _CONN_RE.match(raw)
        if not m:
            continue
        rows.append(
            ConnRow(
                n=int(m.group(1)),
                host_a=m.group(2),
                host_b=m.group(3),
                raw_line=raw,
            )
        )
    return rows


def list_connections(
    pcap: Path,
    timeout: float = 60.0,
    no_dns: bool = False,
) -> list[ConnRow]:
    """Run `tcptrace [-n] <pcap>` and parse the listing.

    `no_dns=True` adds `-n` so tcptrace prints raw IPs and port numbers instead
    of resolving them — much faster on pcaps with many distinct endpoints.

    Raises RunnerError on nonzero exit or if `tcptrace` is not on PATH.
    """
    tcptrace = _resolve_tcptrace()
    argv = [tcptrace]
    if no_dns:
        argv.append("-n")
    argv.append(str(pcap))

    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise RunnerError(f"tcptrace timed out after {timeout}s") from e

    if result.returncode != 0:
        raise RunnerError(f"tcptrace failed (exit {result.returncode}): {result.stderr.strip()}")

    return parse_listing(result.stdout)


@dataclass(frozen=True)
class AnalyzeResult:
    details_text: str
    xpl_files: list[Path]


def analyze_connection(
    pcap: Path,
    conn_n: int,
    output_dir: Path,
    timeout: float = 60.0,
    *,
    no_dns: bool = False,
    with_rtt: bool = False,
    with_warnings: bool = False,
    with_checksum: bool = False,
    zero_x_axis: bool = False,
) -> AnalyzeResult:
    """Run tcptrace for one connection: emit details text and .xpl files.

    `output_dir` is the working dir for tcptrace (where .xpl files land).
    Returns the stdout (for details.txt) and the list of produced .xpl files.

    Flags (all default-off):
      no_dns         — `-n`, skip hostname/port-name resolution
      with_rtt       — `-r`, include RTT statistics in long output
      with_warnings  — `-w`, include warning messages
      with_checksum  — `--checksum --warn_printbadcsum`, verify and report bad
                       IP/TCP checksums (off-by-default in tcptrace because
                       NIC csum offload is common — toggle this to surface it)
      zero_x_axis    — `-zx`, plot time axis from 0 instead of wallclock
    """
    tcptrace = _resolve_tcptrace()
    output_dir.mkdir(parents=True, exist_ok=True)
    prefix = f"conn-{conn_n}--"

    argv = [tcptrace, "-l", f"-o{conn_n}", "-G"]
    if no_dns:
        argv.append("-n")
    if with_rtt:
        argv.append("-r")
    if with_warnings:
        argv.append("-w")
    if with_checksum:
        argv += ["--checksum", "--warn_printbadcsum"]
    if zero_x_axis:
        argv.append("-zx")
    argv += [f"--output_prefix={prefix}", str(pcap)]

    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=output_dir,
        )
    except subprocess.TimeoutExpired as e:
        raise RunnerError(f"tcptrace timed out after {timeout}s") from e

    if result.returncode != 0:
        raise RunnerError(f"tcptrace failed: {result.stderr.strip()}")

    xpls = sorted(p for p in output_dir.glob(f"{prefix}*.xpl"))
    return AnalyzeResult(details_text=result.stdout, xpl_files=xpls)


def analyze_all(
    pcap: Path,
    timeout: float = 60.0,
    *,
    no_dns: bool = False,
    with_rtt: bool = False,
    with_warnings: bool = False,
    with_checksum: bool = False,
) -> list[ConnStats]:
    """Run `tcptrace -l <pcap>` once and parse stats for every connection.

    No `-o<n>` scope, no `-G` (no xpls). One subprocess call yields the long
    per-connection block for every connection in the pcap.

    Flags (all default-off): `no_dns` → `-n`; `with_rtt` → `-r`;
    `with_warnings` → `-w`; `with_checksum` → `--checksum --warn_printbadcsum`.

    Raises RunnerError on nonzero exit or if `tcptrace` is not on PATH.
    """
    tcptrace = _resolve_tcptrace()
    argv = [tcptrace, "-l"]
    if no_dns:
        argv.append("-n")
    if with_rtt:
        argv.append("-r")
    if with_warnings:
        argv.append("-w")
    if with_checksum:
        argv += ["--checksum", "--warn_printbadcsum"]
    argv.append(str(pcap))

    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise RunnerError(f"tcptrace timed out after {timeout}s") from e

    if result.returncode != 0:
        raise RunnerError(f"tcptrace failed (exit {result.returncode}): {result.stderr.strip()}")

    return parse_stats(result.stdout)


def try_convert_to_pcap(input_path: Path, timeout: float = 60.0) -> Path:
    """If `input_path` is already pcap, return it unchanged.

    Otherwise run `capinfos -t -E` to identify, then `editcap -d` to dedupe and
    convert to pcap. Returns the path to the (possibly new) pcap file.

    Raises RunnerError if `capinfos` or `editcap` is missing or fails.
    """
    if shutil.which("capinfos") is None:
        raise RunnerError("capinfos not found (install Wireshark CLI tools)")

    info = subprocess.run(
        ["capinfos", "-t", "-E", str(input_path)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if info.returncode != 0:
        raise RunnerError(f"capinfos failed: {info.stderr.strip()}")

    if "pcap" in info.stdout.lower() and "pcapng" not in info.stdout.lower():
        return input_path

    if shutil.which("editcap") is None:
        raise RunnerError("editcap not found (install Wireshark CLI tools)")

    converted = Path(str(input_path) + ".pcap")
    result = subprocess.run(
        ["editcap", "-d", str(input_path), str(converted)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RunnerError(f"editcap failed: {result.stderr.strip()}")

    return converted
