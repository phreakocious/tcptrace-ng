import json
import os
import time
from pathlib import Path

from tcptrace_ng.cache import (
    CacheLayout,
    clear_pcap_cache,
    invalidate_if_stale_version,
    is_fresh,
    load_listing,
    load_stats,
    pcap_cache_dir,
    save_listing,
    save_stats,
    total_cache_size,
    write_version,
)
from tcptrace_ng.classifier import Class
from tcptrace_ng.stats_parser import ConnStats


def test_pcap_cache_dir_is_relative_to_pcap(tmp_path: Path):
    pcap = tmp_path / "trace.pcap"
    pcap.write_bytes(b"\x00" * 24)
    cache = pcap_cache_dir(pcap)
    assert cache == tmp_path / ".tcptrace" / "trace.pcap"


def test_layout_paths(tmp_path: Path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"")
    layout = CacheLayout(pcap)
    assert layout.listing_json == tmp_path / ".tcptrace" / "x.pcap" / "listing.json"
    assert layout.version_file == tmp_path / ".tcptrace" / "x.pcap" / "version"
    assert layout.conn_dir(4) == tmp_path / ".tcptrace" / "x.pcap" / "conn-4"
    assert layout.conn_details(4) == tmp_path / ".tcptrace" / "x.pcap" / "conn-4" / "details.txt"


def test_is_fresh_false_when_file_missing(tmp_path: Path):
    pcap = tmp_path / "p.pcap"
    pcap.write_bytes(b"")
    missing = tmp_path / "nonexistent"
    assert is_fresh(missing, pcap, "0.1.0", tmp_path / "version") is False


def test_is_fresh_false_when_pcap_newer(tmp_path: Path):
    pcap = tmp_path / "p.pcap"
    cache_file = tmp_path / "out"
    version_file = tmp_path / "version"
    cache_file.write_bytes(b"x")
    version_file.write_text("0.1.0")
    pcap.write_bytes(b"y")  # written second → newer mtime
    os.utime(pcap, (cache_file.stat().st_mtime + 10, cache_file.stat().st_mtime + 10))
    assert is_fresh(cache_file, pcap, "0.1.0", version_file) is False


def test_is_fresh_false_when_version_mismatch(tmp_path: Path):
    pcap = tmp_path / "p.pcap"
    cache_file = tmp_path / "out"
    version_file = tmp_path / "version"
    pcap.write_bytes(b"y")
    cache_file.write_bytes(b"x")
    os.utime(cache_file, (pcap.stat().st_mtime + 10, pcap.stat().st_mtime + 10))
    version_file.write_text("0.0.9")
    assert is_fresh(cache_file, pcap, "0.1.0", version_file) is False


def test_is_fresh_true_when_newer_and_version_match(tmp_path: Path):
    pcap = tmp_path / "p.pcap"
    cache_file = tmp_path / "out"
    version_file = tmp_path / "version"
    pcap.write_bytes(b"y")
    cache_file.write_bytes(b"x")
    os.utime(cache_file, (pcap.stat().st_mtime + 10, pcap.stat().st_mtime + 10))
    version_file.write_text("0.1.0")
    assert is_fresh(cache_file, pcap, "0.1.0", version_file) is True


def test_clear_pcap_cache_removes_subdir_only(tmp_path: Path):
    pcap_a = tmp_path / "a.pcap"
    pcap_b = tmp_path / "b.pcap"
    pcap_a.write_bytes(b"")
    pcap_b.write_bytes(b"")
    (tmp_path / ".tcptrace" / "a.pcap").mkdir(parents=True)
    (tmp_path / ".tcptrace" / "b.pcap").mkdir(parents=True)
    (tmp_path / ".tcptrace" / "a.pcap" / "x").write_text("x")

    clear_pcap_cache(pcap_a)

    assert not (tmp_path / ".tcptrace" / "a.pcap").exists()
    assert (tmp_path / ".tcptrace" / "b.pcap").exists()


def test_total_cache_size_sums_bytes(tmp_path: Path):
    cache_root = tmp_path / ".tcptrace"
    (cache_root / "a").mkdir(parents=True)
    (cache_root / "a" / "f1").write_bytes(b"0123456789")
    (cache_root / "a" / "f2").write_bytes(b"ab")
    assert total_cache_size(tmp_path) == 12


def test_save_and_load_listing_roundtrip(tmp_path: Path):
    pcap = tmp_path / "trace.pcap"
    pcap.write_bytes(b"\x00")
    layout = CacheLayout(pcap)
    rows = [
        {"n": 1, "host_a": "a:1", "host_b": "b:2", "raw_line": "raw"},
        {"n": 2, "host_a": "c:3", "host_b": "d:4", "raw_line": "raw2"},
    ]
    save_listing(layout, rows)
    write_version(layout, "0.1.0")
    # listing.json must be newer than the pcap; if not, bump its mtime.
    pcap_mtime = pcap.stat().st_mtime
    os.utime(layout.listing_json, (pcap_mtime + 5, pcap_mtime + 5))
    os.utime(layout.version_file, (pcap_mtime + 5, pcap_mtime + 5))

    loaded = load_listing(layout, "0.1.0")
    assert loaded == rows
    # JSON-on-disk shape is a list of dicts.
    assert json.loads(layout.listing_json.read_text()) == rows


def test_load_listing_returns_none_when_stale(tmp_path: Path):
    pcap = tmp_path / "trace.pcap"
    layout = CacheLayout(pcap)
    save_listing(layout, [{"n": 1, "host_a": "a", "host_b": "b", "raw_line": "r"}])
    write_version(layout, "0.1.0")
    # Touch pcap *after* listing so it's newer.
    pcap.write_bytes(b"\x00")
    listing_mtime = layout.listing_json.stat().st_mtime
    os.utime(pcap, (listing_mtime + 10, listing_mtime + 10))
    assert load_listing(layout, "0.1.0") is None


def test_load_listing_returns_none_when_version_mismatch(tmp_path: Path):
    pcap = tmp_path / "trace.pcap"
    pcap.write_bytes(b"\x00")
    layout = CacheLayout(pcap)
    save_listing(layout, [{"n": 1, "host_a": "a", "host_b": "b", "raw_line": "r"}])
    write_version(layout, "0.0.9")
    pcap_mtime = pcap.stat().st_mtime
    os.utime(layout.listing_json, (pcap_mtime + 5, pcap_mtime + 5))
    os.utime(layout.version_file, (pcap_mtime + 5, pcap_mtime + 5))
    assert load_listing(layout, "0.1.0") is None


def test_invalidate_if_stale_version_wipes_cache_on_mismatch(tmp_path: Path):
    pcap = tmp_path / "trace.pcap"
    pcap.write_bytes(b"\x00")
    layout = CacheLayout(pcap)
    layout.ensure_root()
    write_version(layout, "0.0.9")
    (layout.root / "junk").write_text("stale")
    assert invalidate_if_stale_version(pcap, "0.1.0") is True
    assert not layout.root.exists()


def test_invalidate_if_stale_version_noop_when_versions_match(tmp_path: Path):
    pcap = tmp_path / "trace.pcap"
    pcap.write_bytes(b"\x00")
    layout = CacheLayout(pcap)
    layout.ensure_root()
    write_version(layout, "0.1.0")
    (layout.root / "keep").write_text("ok")
    assert invalidate_if_stale_version(pcap, "0.1.0") is False
    assert (layout.root / "keep").read_text() == "ok"


def test_invalidate_if_stale_version_noop_when_no_cache(tmp_path: Path):
    pcap = tmp_path / "trace.pcap"
    pcap.write_bytes(b"\x00")
    # No cache directory exists yet.
    assert invalidate_if_stale_version(pcap, "0.1.0") is False
    assert not (tmp_path / ".tcptrace").exists()


def _stats() -> list[ConnStats]:
    return [
        ConnStats(
            n=1,
            host_a="1.1.1.1:1",
            host_b="2.2.2.2:2",
            client_is_a=True,
            total_bytes=100,
            total_packets=4,
            duration_s=0.5,
            rexmt_packets=1,
            has_rst=False,
            complete_handshake=True,
            verdict=Class.LOOK,
            fwd_ctx="MSS 1460 · ws 5",
            bwd_ctx="MSS 1440 · ws 3",
        ),
    ]


def test_save_and_load_stats_round_trip(tmp_path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"")
    layout = CacheLayout(pcap)
    write_version(layout, "9.9.9")

    original = _stats()
    save_stats(layout, original)
    # Touch pcap-mtime backwards so the cache is "fresh"
    os.utime(pcap, (time.time() - 60, time.time() - 60))

    loaded = load_stats(layout, "9.9.9")
    assert loaded == original


def test_load_stats_returns_none_when_stale_version(tmp_path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"")
    layout = CacheLayout(pcap)
    write_version(layout, "old")
    save_stats(layout, _stats())
    assert load_stats(layout, "new") is None
