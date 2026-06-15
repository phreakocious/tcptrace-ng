"""Top header: pcap dropdown, flag toggles, warning chip, cache controls.

`build(state, cwd)` constructs all header widgets and returns a `HeaderHandle`
exposing widget refs plus three refresh helpers. The handle is the only
public surface — callers (app.py) wire event handlers and timers to the
exposed widgets, never reach into module internals.

This module imports from `..state` and `..view.format` only; it MUST NOT
import from `..app` or any sibling view module (see spec §Module
decomposition for the dependency rule).
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from nicegui import ui

from ..cache import total_cache_size
from ..state import _State
from .format import _format_size, _pcap_options

PCAP_GLOBS = ("*.pcap", "*.pcapng", "*.cap")


def _scan_pcaps(cwd: Path) -> list[tuple[Path, os.stat_result]]:
    """Pcaps paired with their stat() result, sorted by mtime descending.

    One stat() per pcap; the result feeds both the sort key and the
    size/relative-time labels rendered into the dropdown.
    """
    found: list[tuple[Path, os.stat_result]] = []
    for pat in PCAP_GLOBS:
        for p in cwd.glob(pat):
            found.append((p, p.stat()))
    found.sort(key=lambda pair: pair[1].st_mtime, reverse=True)
    return found


@dataclass
class HeaderHandle:
    """Public surface of the header zone. Refresh helpers are bound at build time."""

    menu_btn: ui.button
    pcap_select: ui.select
    dns_check: ui.checkbox
    rtt_check: ui.checkbox
    warn_check: ui.checkbox
    zerox_check: ui.checkbox
    rate_toggle: ui.toggle
    seq_toggle: ui.toggle
    dock_check: ui.checkbox
    warning_chip: ui.button
    warning_dialog: ui.dialog
    cache_label: ui.label
    clear_btn: ui.button
    reanalyze_btn: ui.button
    initial_pcaps: list[tuple[Path, os.stat_result]]  # snapshot of _scan_pcaps(cwd) at page load
    refresh_cache_label: Callable[[], None]
    refresh_warnings: Callable[[], None]
    refresh_pcap_dropdown: Callable[[], None]


def build(state: _State, cwd: Path) -> HeaderHandle:
    """Build the header DOM once. Returns refresh hooks + widget refs."""
    pcaps = _scan_pcaps(cwd)
    pcap_options = _pcap_options(pcaps, time.time())

    with ui.header(elevated=False).classes("tcptrace-header items-center gap-3 px-4"):
        menu_btn = (
            ui.button(icon="menu")
            .props("flat dense round color=muted")
            .tooltip("toggle connection list")
        )
        ui.label("tcptrace-ng").classes("tcptrace-brand text-base")
        ui.label("›").classes("tcptrace-sep")
        pcap_select = (
            ui.select(
                options=pcap_options or {"": "no pcaps in this directory"},
                value=str(state.selected_pcap) if state.selected_pcap else None,
            )
            .props("dense dark outlined options-dense")
            .classes("min-w-[280px]")
        )
        with ui.row().classes("items-center gap-2 tcptrace-flag-strip"):
            dns_check = (
                ui.checkbox("DNS", value=state.dns)
                .props("dense dark")
                .tooltip(
                    "resolve hostnames and port names (slow on captures with"
                    " many distinct endpoints; off by default)"
                )
            )
            rtt_check = (
                ui.checkbox("RTT", value=state.with_rtt)
                .props("dense dark")
                .tooltip("-r: include RTT statistics in the long output")
            )
            warn_check = (
                ui.checkbox("warn", value=state.with_warnings)
                .props("dense dark")
                .tooltip("-w: include tcptrace warning messages")
            )
            zerox_check = (
                ui.checkbox("0-axis", value=state.zero_x_axis)
                .props("dense dark")
                .tooltip("-zx: plot graph time axis from 0 instead of wallclock")
            )
            rate_toggle = (
                ui.toggle(["bits", "bytes"], value=state.rate_unit)
                .props("dense dark unelevated toggle-color=primary")
                .tooltip("throughput display unit (default bits)")
            )
            seq_toggle = (
                ui.toggle(["rel", "abs"], value=state.seq_mode)
                .props("dense dark unelevated toggle-color=primary")
                .tooltip("sequence number display (default relative)")
            )
            dock_check = (
                ui.checkbox("dock", value=state.dock_summary)
                .props("dense dark")
                .tooltip(
                    "pin the per-tab summary panel to the viewport bottom"
                    " so a tall plot doesn't push it off-screen"
                )
            )
        ui.space()
        warning_chip = (
            ui.button("")
            .props("flat dense no-caps color=warning")
            .classes("tcptrace-warning-chip mr-2")
        )
        warning_chip.visible = False
        warning_dialog = ui.dialog()
        cache_label = ui.label().classes("tcptrace-cache-label mr-2")
        clear_btn = ui.button("Clear cache").props("flat dense no-caps color=muted")
        reanalyze_btn = ui.button("Reanalyze").props("flat dense no-caps color=muted")

    def refresh_cache_label() -> None:
        parts = [f"cache: {_format_size(total_cache_size(cwd))}"]
        if state.decap_encaps:
            parts.append(f"decap: {'+'.join(sorted(state.decap_encaps))}")
        if state.desegment_kinds:
            parts.append(f"desegment: {'+'.join(sorted(state.desegment_kinds))}")
        cache_label.set_text(" · ".join(parts))

    def refresh_warnings() -> None:
        """Refresh the warning chip + dialog from `state.pcap_warnings`.

        Enters the chip's own slot so we can safely create the Tooltip
        child element from a background task (e.g. when LRO surfaces
        mid-render of a TSG figure).
        """
        warnings = state.pcap_warnings
        if not warnings:
            warning_chip.visible = False
            return
        n = len(warnings)
        label = f"⚠ {n} warning" if n == 1 else f"⚠ {n} warnings"
        warning_chip.set_text(label)
        warning_chip.clear()
        with warning_chip:
            warning_chip.tooltip(warnings[0] if n == 1 else f"{warnings[0]}  (+{n - 1} more)")
        warning_chip.visible = True
        warning_dialog.clear()
        with warning_dialog, ui.card().classes("tcptrace-warning-card"):
            ui.label("Capture warnings").classes("tcptrace-warning-title")
            for w in warnings:
                ui.label(w).classes("tcptrace-warning-body")
            ui.button("close", on_click=warning_dialog.close).props("flat dense")

    def refresh_pcap_dropdown() -> None:
        """Rescan cwd and update the dropdown so new captures (and aging
        relative-time labels) surface without a full page reload."""
        fresh = _scan_pcaps(cwd)
        options = _pcap_options(fresh, time.time()) or {"": "no pcaps in this directory"}
        pcap_select.set_options(options, value=pcap_select.value)

    return HeaderHandle(
        menu_btn=menu_btn,
        pcap_select=pcap_select,
        dns_check=dns_check,
        rtt_check=rtt_check,
        warn_check=warn_check,
        zerox_check=zerox_check,
        rate_toggle=rate_toggle,
        seq_toggle=seq_toggle,
        dock_check=dock_check,
        warning_chip=warning_chip,
        warning_dialog=warning_dialog,
        cache_label=cache_label,
        clear_btn=clear_btn,
        reanalyze_btn=reanalyze_btn,
        initial_pcaps=pcaps,
        refresh_cache_label=refresh_cache_label,
        refresh_warnings=refresh_warnings,
        refresh_pcap_dropdown=refresh_pcap_dropdown,
    )
