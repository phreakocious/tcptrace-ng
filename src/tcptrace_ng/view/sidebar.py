"""Left drawer: chip filter, filter input, sort select, conn list, xpl-zip footer.

`build(state, on_conn_click, on_download_zip,
       csum_counts_for_endpoints) -> SidebarHandle`
constructs the sidebar DOM once. The returned handle exposes a per-row
registry (`_rows`) and surgical refresh methods that mutate existing
elements instead of rebuilding the list:

- `populate_rows(stats)` builds each row once and bumps state.stats_generation
- `refresh_selection(old, new)` toggles the selected class on two rows
- `apply_filter(q)` / `apply_chips(chips)` toggle `.row-hidden` on items
- `apply_sort(key)` assigns `style="order: i"` (CSS flex order)
- `refresh_row(n)` / `refresh_all_rows()` swap inner `ui.html.content`
- `refresh_count_label()` recomputes the header label

Chip toggle and sort select handlers call these methods directly so the
drawer stays self-contained.

This module imports from `..state` and `..view.format` only. It MUST NOT
import from `..app` or any sibling view module (see spec §Module
decomposition for the dependency rule).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from nicegui import ui

from ..runner import ConnRow
from ..state import _State
from ..stats_parser import ConnStats
from .format import (
    _build_conn_row_html,
    _matches_chips,
    _matches_filter,
    _sort_rows,
)


@dataclass
class _RowHandle:
    """Per-connection UI handle stored in the sidebar's row registry.

    `item` is the outer Quasar item — selection class and `row-hidden`
    class live there. `body` is the inner `ui.html` whose `.content` we
    swap when findings arrive or analysis updates the row.
    """

    item: ui.item
    body: ui.html


@dataclass
class SidebarHandle:
    """Public surface of the sidebar zone.

    Exposes a per-row registry and surgical refresh methods that mutate
    existing elements instead of rebuilding the list.
    """

    drawer: ui.left_drawer
    conn_count_label: ui.label
    filter_input: ui.input
    sort_select: ui.select
    chips: dict[str, ui.chip]
    conn_list_container: ui.column
    download_btn: ui.button
    refresh_download_btn: Callable[[], None]
    populate_rows: Callable[[list[ConnStats | ConnRow]], None]
    refresh_selection: Callable[[int | None, int | None], None]
    apply_filter: Callable[[str], None]
    apply_chips: Callable[[set[str]], None]
    apply_sort: Callable[[str], None]
    refresh_row: Callable[[int], None]
    refresh_all_rows: Callable[[], None]
    refresh_count_label: Callable[[], None]
    # Test-only: per-row registry, exposed read-only for assertions.
    _rows: dict[int, _RowHandle]


def build(
    state: _State,
    *,
    on_conn_click: Callable[[int], object],
    on_download_zip: Callable[[], None],
    csum_counts_for_endpoints: Callable[[str, str], tuple[int, int]],
) -> SidebarHandle:
    """Build the sidebar drawer once. Returns refresh hooks + widget refs."""

    _rows: dict[int, _RowHandle] = {}
    _stats_by_n: dict[int, ConnStats | ConnRow] = {}

    def _badges(stats: ConnStats) -> list[str]:
        out: list[str] = []
        if stats.rexmt_packets > 0:
            out.append("RX")
        if stats.has_rst:
            out.append("RST")
        if stats.complete_handshake:
            out.append("FIN")
        else:
            out.append("INC")
        if stats.unidirectional:
            out.append("UNI")
        a, b = csum_counts_for_endpoints(stats.host_a, stats.host_b)
        if a + b > 0:
            # The chip shows a→b/b→a totals. The acked-vs-lost split lives in the
            # per-direction summary block under the chart; the chip is for triage
            # at a glance.
            out.append(f"CSUM {a}/{b}")
        return out

    sidebar_drawer = (
        ui.left_drawer(fixed=True, value=True)
        .props("width=300 bordered")
        .classes("tcptrace-sidebar p-0")
    )
    chips: dict[str, ui.chip] = {}
    with sidebar_drawer, ui.column().classes("w-full h-full gap-0 no-wrap"):
        with ui.column().classes("w-full tcptrace-sidebar-header px-3 py-2 gap-1"):
            conn_count_label = ui.label("").classes("text-xs text-muted")
            with ui.row().classes("tcptrace-chip-row w-full gap-1"):
                for key, label in [
                    ("bad", "Bad"),
                    ("rst", "RST"),
                    ("rexmt", "Retransmits"),
                    ("incomplete", "Incomplete"),
                    ("uni", "Unidirectional"),
                    ("bulk", "Bulk ≥100K"),
                ]:
                    chip = ui.chip(label).props("dense outline clickable")

                    def _toggle(_, k=key, c=chip):
                        if k in state.chip_filters:
                            state.chip_filters.discard(k)
                        else:
                            state.chip_filters.add(k)
                        c.props("color=primary" if k in state.chip_filters else "color=dim")
                        apply_chips(state.chip_filters)

                    chip.on("click", _toggle)
                    chip.props("color=dim")
                    chips[key] = chip
            filter_input = (
                ui.input(placeholder="filter…")
                .props("dense dark borderless debounce=150")
                .classes("tcptrace-filter w-full")
            )
            sort_select = (
                ui.select(
                    options={
                        "n": "sort: #",
                        "bytes": "sort: bytes ↓",
                        "duration": "sort: duration ↓",
                        "rexmt": "sort: retransmits ↓",
                    },
                    value=state.sort_key,
                )
                .props("dense dark borderless options-dense")
                .classes("tcptrace-sort w-full")
            )

            def _on_sort_change(e):
                state.sort_key = e.value or "n"
                apply_sort(state.sort_key)

            sort_select.on_value_change(_on_sort_change)
        conn_list_container = ui.column().classes("w-full flex-grow overflow-auto gap-0")
        with ui.row().classes("w-full tcptrace-sidebar-footer px-3 py-2"):
            download_btn = (
                ui.button("↓ xpl zip")
                .props("flat dense no-caps color=muted disable")
                .classes("w-full")
            )

    def _should_show(row) -> bool:
        return _matches_filter(row, state.conn_filter) and _matches_chips(row, state.chip_filters)

    def _findings_for(row) -> list:
        return state.findings.get(row.n, [])

    def _row_html(row) -> str:
        return _build_conn_row_html(
            row,
            badges_str=" ".join(_badges(row)) if isinstance(row, ConnStats) else "",
            findings=_findings_for(row),
        )

    def populate_rows(stats: list[ConnStats | ConnRow]) -> None:
        """Build the registry from scratch. Bumps stats_generation."""
        state.stats_generation += 1
        conn_list_container.clear()
        _rows.clear()
        _stats_by_n.clear()
        if state.selected_pcap is None:
            refresh_count_label()
            return
        with conn_list_container, ui.list().props("dense").classes("w-full tcptrace-conn-flex"):
            for row in stats:
                selected = state.selected_conn == row.n
                cls = "tcptrace-conn-row"
                if selected:
                    cls += " tcptrace-conn-selected"
                item = ui.item(on_click=lambda r=row: on_conn_click(r.n)).classes(cls)
                with item, ui.item_section():
                    body = ui.html(_row_html(row))
                _rows[row.n] = _RowHandle(item=item, body=body)
                _stats_by_n[row.n] = row
                if not _should_show(row):
                    item.classes(add="row-hidden")
        apply_sort(state.sort_key)
        refresh_count_label()

    def refresh_selection(old: int | None, new: int | None) -> None:
        if old is not None and old in _rows:
            _rows[old].item.classes(remove="tcptrace-conn-selected")
        if new is not None and new in _rows:
            _rows[new].item.classes(add="tcptrace-conn-selected")

    def _recompute_visibility() -> None:
        for row_n, rh in _rows.items():
            row = _stats_by_n.get(row_n)
            if row is None:
                continue
            if _should_show(row):
                rh.item.classes(remove="row-hidden")
            else:
                rh.item.classes(add="row-hidden")
        refresh_count_label()

    def apply_filter(q: str) -> None:
        state.conn_filter = q
        _recompute_visibility()

    def apply_chips(chips_set: set[str]) -> None:
        """Recompute row visibility. `chips_set` accepted for API symmetry
        with apply_filter; the body reads state.chip_filters directly."""
        _recompute_visibility()

    def apply_sort(key: str) -> None:
        sorted_rows = _sort_rows(list(state.stats), key)
        for idx, row in enumerate(sorted_rows):
            rh = _rows.get(row.n)
            if rh is not None:
                rh.item.style(f"order: {idx}")

    def refresh_row(n: int) -> None:
        rh = _rows.get(n)
        row = _stats_by_n.get(n)
        if rh is None or row is None:
            return
        rh.body.content = _row_html(row)

    def refresh_all_rows() -> None:
        for n in list(_rows):
            refresh_row(n)

    def refresh_count_label() -> None:
        if state.selected_pcap is None:
            conn_count_label.set_text("pick a pcap")
            return
        if state.analyzing:
            conn_count_label.set_text("analyzing…")
            return
        total = len(state.stats)
        if total == 0:
            conn_count_label.set_text("no connections")
            return
        shown = sum(1 for r in state.stats if _should_show(r))
        if shown == total:
            conn_count_label.set_text(f"{total} connections")
        else:
            conn_count_label.set_text(f"{shown} of {total}")

    def _refresh_download_btn() -> None:
        if state.analyses:
            download_btn.props(remove="disable")
        else:
            download_btn.props("disable")

    download_btn.on("click", on_download_zip)

    return SidebarHandle(
        drawer=sidebar_drawer,
        conn_count_label=conn_count_label,
        filter_input=filter_input,
        sort_select=sort_select,
        chips=chips,
        conn_list_container=conn_list_container,
        download_btn=download_btn,
        refresh_download_btn=_refresh_download_btn,
        populate_rows=populate_rows,
        refresh_selection=refresh_selection,
        apply_filter=apply_filter,
        apply_chips=apply_chips,
        apply_sort=apply_sort,
        refresh_row=refresh_row,
        refresh_all_rows=refresh_all_rows,
        refresh_count_label=refresh_count_label,
        _rows=_rows,
    )
