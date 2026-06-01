"""Cache layout, freshness, and disk utilities.

All artifacts for a pcap live under `<pcap_dir>/.tcptrace/<pcap_name>/`.
A cache file is fresh iff its mtime > pcap mtime AND the version sentinel
matches the running tool version.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path


def pcap_cache_dir(pcap: Path) -> Path:
    """Return `.tcptrace/<pcap-name>/` next to the pcap."""
    return pcap.parent / ".tcptrace" / pcap.name


@dataclass(frozen=True)
class CacheLayout:
    pcap: Path

    @property
    def root(self) -> Path:
        return pcap_cache_dir(self.pcap)

    @property
    def listing_json(self) -> Path:
        return self.root / "listing.json"

    @property
    def version_file(self) -> Path:
        return self.root / "version"

    def conn_dir(self, n: int) -> Path:
        return self.root / f"conn-{n}"

    def conn_details(self, n: int) -> Path:
        return self.conn_dir(n) / "details.txt"

    def ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    def ensure_conn(self, n: int) -> None:
        self.conn_dir(n).mkdir(parents=True, exist_ok=True)


def is_fresh(cache_file: Path, pcap: Path, version: str, version_file: Path) -> bool:
    """True iff `cache_file` exists, is newer than `pcap`, and `version_file` matches `version`."""
    if not cache_file.exists():
        return False
    if not version_file.exists():
        return False
    if version_file.read_text().strip() != version:
        return False
    return cache_file.stat().st_mtime > pcap.stat().st_mtime


def write_version(layout: CacheLayout, version: str) -> None:
    layout.ensure_root()
    layout.version_file.write_text(version)


def invalidate_if_stale_version(pcap: Path, version: str) -> bool:
    """If the on-disk cache version differs from `version`, wipe the cache.

    Reads `<pcap-cache>/version` (if any), and if its trimmed content differs
    from `version`, calls `clear_pcap_cache(pcap)`. Returns True iff the cache
    was wiped. Safe to call when no cache exists yet (no-op, returns False).
    """
    cache = pcap_cache_dir(pcap)
    vfile = cache / "version"
    if not vfile.exists():
        return False
    if vfile.read_text().strip() == version:
        return False
    clear_pcap_cache(pcap)
    return True


def clear_pcap_cache(pcap: Path) -> None:
    """Remove `.tcptrace/<pcap-name>/` entirely."""
    cache = pcap_cache_dir(pcap)
    if cache.exists():
        shutil.rmtree(cache)


def load_listing(layout: CacheLayout, version: str) -> list[dict] | None:
    """Return parsed listing rows if the cached listing.json is fresh, else None."""
    if not is_fresh(layout.listing_json, layout.pcap, version, layout.version_file):
        return None
    return json.loads(layout.listing_json.read_text())


def save_listing(layout: CacheLayout, rows: list[dict]) -> None:
    """Persist a listing as JSON under the pcap's cache root."""
    layout.ensure_root()
    layout.listing_json.write_text(json.dumps(rows))


def total_cache_size(cwd: Path) -> int:
    """Bytes used by the .tcptrace tree under cwd. 0 if absent."""
    root = cwd / ".tcptrace"
    if not root.exists():
        return 0
    total = 0
    for p in root.rglob("*"):
        if p.is_file():
            total += p.stat().st_size
    return total
