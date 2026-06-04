"""Cache layout, freshness, and disk utilities.

All artifacts for a pcap live under `<pcap_dir>/.tcptrace/<pcap_name>/`.
A cache file is fresh iff its mtime > pcap mtime AND the version sentinel
matches the running tool version.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from .classifier import Class
from .stats_parser import ConnStats

# All ConnStats field names — used to filter loaded JSON so the round-trip stays
# robust to schema drift (extra keys ignored, new optional fields default).
_STATS_FIELDS = frozenset(f.name for f in fields(ConnStats))


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
    def stats_json(self) -> Path:
        return self.root / "stats.json"

    @property
    def version_file(self) -> Path:
        return self.root / "version"

    @property
    def decap_pcap(self) -> Path:
        """Decapsulated copy of the source pcap (if outer encaps were detected)."""
        return self.root / "decap.pcap"

    @property
    def decap_meta(self) -> Path:
        """JSON sidecar describing what was decapped: encaps, frame counts."""
        return self.root / "decap.json"

    @property
    def desegment_pcap(self) -> Path:
        """De-coalesced copy of the (already-decapped) pcap, if offload was split."""
        return self.root / "desegment.pcap"

    @property
    def desegment_meta(self) -> Path:
        """JSON sidecar: split frame counts + the coalesce manifest."""
        return self.root / "desegment.json"

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


def save_stats(layout: CacheLayout, rows: list[ConnStats]) -> None:
    """Persist the full ConnStats list as JSON (lossless).

    Every field is serialized so a warm-cache load is indistinguishable from a
    fresh parse. The typed RTT/MSS/wscale fields feed diagnose() (capture_vantage
    reads rtt_3whs) and the throughput/tcp_inspect models, so dropping them
    silently changed results between cold and warm cache. `verdict` (a Class enum)
    is the only field that isn't natively JSON-serializable.
    """
    layout.ensure_root()
    payload = []
    for r in rows:
        d = asdict(r)
        d["verdict"] = r.verdict.value
        payload.append(d)
    layout.stats_json.write_text(json.dumps(payload))


def load_stats(layout: CacheLayout, version: str) -> list[ConnStats] | None:
    """Return ConnStats list if stats.json is fresh, else None."""
    if not is_fresh(layout.stats_json, layout.pcap, version, layout.version_file):
        return None
    rows = json.loads(layout.stats_json.read_text())
    out: list[ConnStats] = []
    for r in rows:
        kw = {k: v for k, v in r.items() if k in _STATS_FIELDS}
        kw["verdict"] = Class(kw["verdict"])
        out.append(ConnStats(**kw))
    return out
