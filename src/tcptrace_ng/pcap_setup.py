"""Pre-flight pcap-processing helpers that wrap the cached decap/desegment
passes and the offload-warning scan.

Each helper mutates `state` and returns the pcap path the analysis flow
should use next (or None for `scan_for_warnings`). They isolate the
"side-effecting pcap pipeline" from app.py's intent layer so build_page
stays close to wiring-only.
"""

from __future__ import annotations

import json
from pathlib import Path

from nicegui import run, ui

from .cache import CacheLayout, is_fresh
from .decap import decap_pcap, detect_encaps
from .desegment import desegment_pcap
from .offload import detect_offload
from .state import _State, cache_version
from .view.format import _coalesce_to_dict


async def ensure_decapped(state: _State, src: Path, layout: CacheLayout) -> Path:
    """Detect outer encaps; if any, return path to a cached decap'd copy.

    Falls back to `src` on any error so a flaky decap can't break the
    normal analysis path. The decap output lives at `<cache>/decap.pcap`
    next to the other cached artifacts.
    """
    try:
        encaps = await run.io_bound(detect_encaps, src)
    except Exception:
        state.decap_encaps = set()
        return src
    if not encaps:
        state.decap_encaps = set()
        return src
    decap_path = layout.decap_pcap
    if is_fresh(decap_path, src, cache_version(state), layout.version_file):
        try:
            meta = json.loads(layout.decap_meta.read_text())
            state.decap_encaps = set(meta.get("encaps", []))
        except (OSError, json.JSONDecodeError):
            state.decap_encaps = encaps
        return decap_path
    layout.ensure_root()
    try:
        res = await run.io_bound(decap_pcap, src, decap_path)
    except Exception as exc:
        ui.notify(f"decap failed, analyzing original: {exc}", type="warning")
        state.decap_encaps = set()
        return src
    layout.decap_meta.write_text(
        json.dumps(
            {
                "encaps": sorted(res.encaps),
                "frames_total": res.frames_total,
                "frames_decapped": res.frames_decapped,
            }
        )
    )
    state.decap_encaps = res.encaps
    return decap_path


async def ensure_desegmented(state: _State, src: Path, layout: CacheLayout) -> Path:
    """Split offload-coalesced segments; return a cached de-coalesced copy.

    Mirrors `ensure_decapped`: cheap offload probe, fresh-cache check,
    run, write the `desegment.json` sidecar (meta + manifest), set state,
    fall back to `src` on any error so a flaky pass never breaks analysis.
    """
    state.desegment_kinds = set()
    state.desegment_coalesces = []
    try:
        rep = await run.io_bound(detect_offload, src)
    except Exception:
        return src
    if rep.oversized_segments == 0:
        return src
    out = layout.desegment_pcap
    if is_fresh(out, src, cache_version(state), layout.version_file):
        try:
            meta = json.loads(layout.desegment_meta.read_text())
            state.desegment_kinds = set(meta.get("kinds", []))
            state.desegment_coalesces = meta.get("coalesces", [])
            return out
        except (OSError, json.JSONDecodeError):
            pass
    layout.ensure_root()
    try:
        res = await run.io_bound(desegment_pcap, src, out)
    except Exception as exc:
        ui.notify(f"desegment failed, analyzing original: {exc}", type="warning")
        return src
    state.desegment_kinds = res.kinds
    state.desegment_coalesces = [_coalesce_to_dict(c) for c in res.coalesces]
    layout.desegment_meta.write_text(
        json.dumps(
            {
                "kinds": sorted(res.kinds),
                "frames_split": res.frames_split,
                "pieces_emitted": res.pieces_emitted,
                "coalesces": state.desegment_coalesces,
            }
        )
    )
    return out


async def scan_for_warnings(state: _State, pcap: Path) -> None:
    """Populate `state.pcap_warnings` with pre-flight findings.

    Currently: NIC offload (LSO/GSO/TSO/LRO/GRO) — TCP payloads larger
    than 1500 B mean coalescing distorts the MSS field, time-sequence
    staircases, and retransmit detection. Future detectors append to
    the same list.
    """
    state.pcap_warnings = []
    try:
        offload = await run.io_bound(detect_offload, pcap)
    except Exception:
        return
    state.pcap_warnings.extend(offload.warnings)
