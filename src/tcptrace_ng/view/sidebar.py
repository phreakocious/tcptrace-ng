"""Left drawer: chip filter, filter input, sort select, conn list, xpl-zip footer.

`build(state, on_conn_click, on_download_zip,
       csum_counts_for_endpoints) -> SidebarHandle`
constructs the sidebar DOM once. The conn list is one `ui.html` whose
content is a blob built by `_build_conn_list_html`; filtering, sorting,
selection, and row-updates run client-side via `window.ttConnList`:

- `populate_rows(stats)` renders the whole list as one blob and bumps
  state.stats_generation; sort and selection are baked inline.
- `refresh_selection(old, new)` runs JS to toggle the selected class.
- `apply_filter(q)` / `apply_chips(chips)` run JS filter.
- `apply_sort(key)` runs JS sort.
- `refresh_row(n)` / `refresh_all_rows()` re-render via JS or full blob.
- `refresh_count_label()` recomputes the header label (server-side).

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
    _build_conn_list_html,
    _build_conn_row_html,
    _conn_filter_js,
    _conn_select_js,
    _conn_set_row_js,
    _conn_sort_js,
    _matches_chips,
    _matches_filter,
    _sort_rows,
)


_CONN_LIST_JS = """
<script>
window.ttConnList = (function () {
  function row(n) { return document.querySelector('.tcptrace-conn-row[data-n="' + n + '"]'); }
  return {
    filter: function (query, flags) {
      var q = (query || '').toLowerCase();
      var fl = flags || [];
      var rows = document.querySelectorAll('.tcptrace-conn-row');
      for (var i = 0; i < rows.length; i++) {
        var el = rows[i];
        var text = (el.dataset.text || '').toLowerCase();
        var rf = (el.dataset.flags || '').split(' ');
        var show = (!q || text.indexOf(q) !== -1)
          && fl.every(function (k) { return rf.indexOf(k) !== -1; });
        el.style.display = show ? '' : 'none';
      }
    },
    sort: function (order) {
      (order || []).forEach(function (n, i) { var el = row(n); if (el) el.style.order = i; });
    },
    select: function (oldN, newN) {
      if (oldN !== null && oldN !== undefined) { var o = row(oldN); if (o) o.classList.remove('tcptrace-conn-selected'); }
      if (newN !== null && newN !== undefined) { var e = row(newN); if (e) e.classList.add('tcptrace-conn-selected'); }
    },
    setRow: function (n, html) { var el = row(n); if (el) el.innerHTML = html; }
  };
})();
document.addEventListener('click', function (ev) {
  var el = ev.target.closest ? ev.target.closest('.tcptrace-conn-row') : null;
  if (!el) return;
  var n = parseInt(el.dataset.n, 10);
  if (!isNaN(n)) emitEvent('conn_click', { n: n });
});
</script>
"""


@dataclass
class SidebarHandle:
    """Public surface of the sidebar zone."""

    drawer: ui.left_drawer
    conn_count_label: ui.label
    filter_input: ui.input
    sort_select: ui.select
    chips: dict[str, ui.chip]
    conn_list_container: ui.column
    conn_list_html: ui.html
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


def build(
    state: _State,
    *,
    on_conn_click: Callable[[int], object],
    on_download_zip: Callable[[], None],
    csum_counts_for_endpoints: Callable[[str, str], tuple[int, int]],
) -> SidebarHandle:
    """Build the sidebar drawer once. Returns refresh hooks + widget refs."""

    ui.add_head_html(_CONN_LIST_JS)
    ui.on("conn_click", lambda e: on_conn_click(int(e.args["n"])))

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
        with conn_list_container:
            conn_list_html = ui.html("").classes("w-full")
        with ui.row().classes("w-full tcptrace-sidebar-footer px-3 py-2"):
            download_btn = (
                ui.button("↓ xpl zip")
                .props("flat dense no-caps color=muted disable")
                .classes("w-full")
            )

    def _should_show(row) -> bool:
        return _matches_filter(row, state.conn_filter) and _matches_chips(row, state.chip_filters)

    def _render_blob(stats: list) -> None:
        badges_map = {
            r.n: " ".join(_badges(r)) if isinstance(r, ConnStats) else "" for r in stats
        }
        findings_map = {r.n: state.findings.get(r.n, []) for r in stats}
        ordered = _sort_rows(list(stats), state.sort_key)
        order_map = {r.n: i for i, r in enumerate(ordered)}
        conn_list_html.content = _build_conn_list_html(
            stats,
            selected_n=state.selected_conn,
            badges_map=badges_map,
            findings_map=findings_map,
            order_map=order_map,
        )

    def populate_rows(stats: list) -> None:
        """Render the whole list as one blob. Bumps stats_generation. Sort and
        selection are baked inline so the build-time render needs no client
        round-trip; an active filter is re-applied via JS (always in a handler)."""
        state.stats_generation += 1
        if state.selected_pcap is None:
            conn_list_html.content = ""
            refresh_count_label()
            return
        _render_blob(stats)
        if state.conn_filter or state.chip_filters:
            _run_js(_conn_filter_js(state.conn_filter, state.chip_filters))
        refresh_count_label()

    def _run_js(code: str) -> None:
        """Fire-and-forget JS. Silently no-ops when there is no client context
        (e.g., unit-test calls that exercise server state without a browser)."""
        try:
            ui.run_javascript(code)
        except RuntimeError:
            pass

    def refresh_selection(old: int | None, new: int | None) -> None:
        _run_js(_conn_select_js(old, new))

    def _recompute_visibility() -> None:
        _run_js(_conn_filter_js(state.conn_filter, state.chip_filters))
        refresh_count_label()

    def apply_filter(q: str) -> None:
        state.conn_filter = q
        _recompute_visibility()

    def apply_chips(chips_set: set[str]) -> None:
        _recompute_visibility()

    def apply_sort(key: str) -> None:
        ordered = _sort_rows(list(state.stats), key)
        _run_js(_conn_sort_js([r.n for r in ordered]))

    def refresh_row(n: int) -> None:
        row = next((r for r in state.stats if r.n == n), None)
        if row is None:
            return
        badges = " ".join(_badges(row)) if isinstance(row, ConnStats) else ""
        inner = _build_conn_row_html(row, badges, state.findings.get(n, []))
        # O(1) live-DOM patch. state.findings is canonical; the blob is a render
        # cache rebuilt from it on the next populate_rows. Re-rendering the whole
        # blob here would be O(N) and would reset the client-side filter (setting
        # .content replaces innerHTML, dropping the display:none state).
        _run_js(_conn_set_row_js(n, inner))

    def refresh_all_rows() -> None:
        _render_blob(state.stats)
        # Re-rendering replaces innerHTML and drops the client-side filter;
        # re-apply it (mirrors populate_rows).
        if state.conn_filter or state.chip_filters:
            _run_js(_conn_filter_js(state.conn_filter, state.chip_filters))

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
        conn_list_html=conn_list_html,
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
    )
