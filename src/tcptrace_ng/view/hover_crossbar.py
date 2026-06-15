"""Plotly hover-crossbar JS overlay.

A single page-level script that draws a hairline crossbar across all
plotly figures on the page when the user hovers any of them, plus
matching x-axis labels. Injected once into <head>; no per-figure
relayout cost.
"""

from __future__ import annotations

from ..theme import PALETTE

# Full-figure hover crossbar. Plotly's per-axis spike stops at its subplot
# boundary, so the bwd panel goes blank when hovering the fwd panel (and
# vice versa). On every mousemove over the plot area we:
#   1. position a 1px overlay <div> at the cursor's x, spanning both stacked
#      panels — a vertical line that tracks the cursor continuously (not
#      gated on landing on a data point) and stays visible the whole time;
#   2. fire Plotly.Fx.hover on every cartesian subplot at the same xval so
#      the per-trace tooltips pop on both panels simultaneously;
#   3. show ONE timestamp label, centred in the gap between the panels; the
#      accompanying <style> hides Plotly's native compare-mode axis label
#      (g.axistext), which hovermode=x otherwise draws once per x-axis (x and
#      x2) — a second and third timestamp that flicker as the cursor moves.
#
# The line is a plain absolutely-positioned element moved with CSS, NOT a
# Plotly layout shape: redrawing a shape via Plotly.relayout on every frame
# is a full-layout recompute that floods Plotly's async queue, so the bar
# never settles (reads as invisible) and the off-cursor panel's tooltip
# trails. CSS moves are free, so the bar is solid and both panels stay synced.
#
# Bottom panel is x2y2 (xaxis2 + yaxis2), NOT xy2 — the earlier mirror
# targeted a subplot that didn't exist, which is why cross-panel tooltips
# weren't appearing. subplotIds() reads the real ids off _fullLayout.
#
# Work is rAF-throttled so we touch the DOM at most once per frame even when
# mousemove fires faster.
#
# A MutationObserver wires this up on any .js-plotly-plot the app mounts,
# including ones swapped in by tab changes or update_figure(); the overlay is
# re-created if Plotly tears it out on rebuild. Debug counters live on
# window.tcpNgCrossbar so the console can confirm the script loaded.
#
# The trailing .replace() chain (not an f-string) injects palette hex values
# at module-import time. The JS body has ~150 lines with literal `{` / `}`
# everywhere (object literals, arrow bodies); f-string conversion would
# require doubling all of them. Each `__XXX__` token is a Python substitution
# — add a matching .replace() if you add a new color reference.

_HOVER_CROSSBAR_JS = """
<style>
  /* Plotly's compare-mode (hovermode:x) common axis label repeats the cursor
     timestamp once per x-axis. The overlay below owns the single timestamp,
     so suppress Plotly's native ones on every plot. */
  .js-plotly-plot .axistext { display: none !important; }
</style>
<script>
(function() {
  const debug = {loaded: true, attached: 0, draws: 0, lastX: null, lastErr: null};
  window.tcpNgCrossbar = debug;
  function subplotIds(gd) {
    const fl = gd._fullLayout;
    const sp = fl && fl._subplots && fl._subplots.cartesian;
    if (sp && sp.length) return sp.slice();
    const ids = [];
    if (fl && fl.xaxis && fl.yaxis) ids.push('xy');
    if (fl && fl.xaxis2 && fl.yaxis2) ids.push('x2y2');
    return ids;
  }
  function fmtDate(ms) {
    const d = new Date(ms);
    if (isNaN(d.getTime())) return String(ms);
    // YYYY-MM-DD HH:MM:SS.mmm in UTC — matches the xaxis hoverformat.
    const pad = (n, w) => String(n).padStart(w || 2, '0');
    return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate())
      + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds())
      + '.' + pad(d.getUTCMilliseconds(), 3);
  }
  function hostOf(gd) {
    // .plot-container is position:relative and shares the plot's top-left
    // origin, so axis _offset/_length line up with our absolute children.
    return gd.querySelector('.plot-container') || gd;
  }
  // Cursor geometry in plot-pixel space, or null when the cursor is over a
  // margin / outside both panels. px is the line's x; top/height the band it
  // spans; mid the gap centre for the single label; dataX feeds Fx.hover and
  // the timestamp.
  function geom(gd, ev) {
    const fl = gd._fullLayout;
    const xa = fl && fl.xaxis;
    if (!xa || xa._offset == null || xa._length == null) return null;
    const r = hostOf(gd).getBoundingClientRect();
    const px = ev.clientX - r.left;
    const lx = px - xa._offset;
    if (lx < 0 || lx > xa._length) return null;
    const ya = fl.yaxis;
    if (!ya || ya._offset == null) return null;
    const yb = (fl.yaxis2 && fl.yaxis2._offset != null) ? fl.yaxis2 : null;
    const top = ya._offset;
    const bottom = yb ? (yb._offset + yb._length) : (ya._offset + ya._length);
    const py = ev.clientY - r.top;
    if (py < top || py > bottom) return null;
    const mid = yb ? (ya._offset + ya._length + yb._offset) / 2 : top + 12;
    return {px: px, top: top, height: bottom - top, mid: mid, dataX: xa.p2c(lx)};
  }
  function overlayFor(gd) {
    let o = gd._tcpNgOverlay;
    if (o && o.root.isConnected) return o;
    const host = hostOf(gd);
    if (getComputedStyle(host).position === 'static') host.style.position = 'relative';
    const root = document.createElement('div');
    root.style.cssText =
      'position:absolute;top:0;left:0;pointer-events:none;display:none;z-index:1;';
    const line = document.createElement('div');
    line.style.cssText = 'position:absolute;width:0;border-left:1px dotted __LINE_COLOR__;';
    const label = document.createElement('div');
    label.style.cssText =
      'position:absolute;transform:translate(-50%,-50%);white-space:nowrap;'
      + 'color:__LABEL_COLOR__;font:10px/1.4 Menlo,monospace;'
      + 'background:rgba(20,20,20,0.85);padding:0 4px;border-radius:2px;';
    root.appendChild(line);
    root.appendChild(label);
    host.appendChild(root);
    o = {root: root, line: line, label: label};
    gd._tcpNgOverlay = o;
    return o;
  }
  function hide(gd) {
    const o = gd._tcpNgOverlay;
    if (o) o.root.style.display = 'none';
    try { Plotly.Fx.unhover(gd); } catch (e) { debug.lastErr = String(e); }
  }
  function update(gd, ev) {
    const g = geom(gd, ev);
    if (!g) { hide(gd); return; }
    debug.draws++;
    debug.lastX = g.dataX;
    try {
      const o = overlayFor(gd);
      o.line.style.left = g.px + 'px';
      o.line.style.top = g.top + 'px';
      o.line.style.height = g.height + 'px';
      o.label.style.left = g.px + 'px';
      o.label.style.top = g.mid + 'px';
      o.label.textContent = fmtDate(g.dataX);
      o.root.style.display = 'block';
      Plotly.Fx.hover(gd, {xval: g.dataX}, subplotIds(gd));
    } catch (e) {
      debug.lastErr = String(e);
    }
  }
  function attach(gd) {
    if (gd._tcpNgCrosshair) return;
    if (!gd._fullLayout) return;
    gd._tcpNgCrosshair = true;
    debug.attached++;
    let pending = false;
    let lastEv = null;
    gd.addEventListener('mousemove', function(ev) {
      lastEv = ev;
      if (pending) return;
      pending = true;
      requestAnimationFrame(function() {
        pending = false;
        update(gd, lastEv);
      });
    });
    gd.addEventListener('mouseleave', function() { hide(gd); });
  }
  function scan() {
    document.querySelectorAll('.js-plotly-plot').forEach(attach);
  }
  function start() {
    new MutationObserver(scan).observe(document.body, {childList: true, subtree: true});
    setInterval(scan, 1000);
    scan();
  }
  // The script runs in <head>, so document.body may not exist yet — defer
  // until the DOM is ready. (No-op if already past DOMContentLoaded.)
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
</script>
""".replace("__LINE_COLOR__", PALETTE.text_muted).replace("__LABEL_COLOR__", PALETTE.text_body)


def install(ui) -> None:
    """Inject the crossbar script into the page <head>. Call once inside
    `build_page()` before any plotly figures are built."""
    ui.add_head_html(_HOVER_CROSSBAR_JS)
