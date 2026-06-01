"""Subprocess wrappers around tcptrace and Wireshark CLI tools.

The only module in tcptrace_ng that shells out. Returns parsed structures,
never raw subprocess output.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class RunnerError(RuntimeError):
    """Raised when an external tool fails or is missing."""


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


def list_connections(pcap: Path, timeout: float = 60.0) -> list[ConnRow]:
    """Run `tcptrace <pcap>` and parse the listing.

    Raises RunnerError on nonzero exit or if `tcptrace` is not on PATH.
    """
    if shutil.which("tcptrace") is None:
        raise RunnerError("tcptrace not found on PATH (try: brew install tcptrace)")

    try:
        result = subprocess.run(
            ["tcptrace", str(pcap)],
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
) -> AnalyzeResult:
    """Run tcptrace for one connection: emit details text and .xpl files.

    `output_dir` is the working dir for tcptrace (where .xpl files land).
    Returns the stdout (for details.txt) and the list of produced .xpl files.
    """
    if shutil.which("tcptrace") is None:
        raise RunnerError("tcptrace not found on PATH (try: brew install tcptrace)")

    output_dir.mkdir(parents=True, exist_ok=True)
    prefix = f"conn-{conn_n}--"

    try:
        result = subprocess.run(
            ["tcptrace", "-l", f"-o{conn_n}", "-G", f"--output_prefix={prefix}", str(pcap)],
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
