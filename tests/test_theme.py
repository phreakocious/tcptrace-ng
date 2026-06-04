from tcptrace_ng.theme import DARK_CSS


def test_dark_css_has_dark_background_rule():
    # Post-rewrite: surface backgrounds reference --q-dark-page / --q-panel,
    # which resolve to dark Palette values via quasar_colors(). The literal
    # "#000" / "black" rule was replaced by var(--q-…) references.
    assert "var(--q-dark-page)" in DARK_CSS or "var(--q-panel)" in DARK_CSS


def test_dark_css_has_class_colors():
    assert ".good" in DARK_CSS
    assert ".bad" in DARK_CSS
    assert ".look" in DARK_CSS


def test_dark_css_styles_tcptrace_output_pre():
    assert "pre.tcptrace-output" in DARK_CSS


def test_dark_css_styles_sidebar_and_header():
    assert ".tcptrace-header" in DARK_CSS
    assert ".tcptrace-sidebar" in DARK_CSS
    assert ".tcptrace-conn-row" in DARK_CSS


def test_dark_css_styles_findings_panel_and_warn_badge():
    assert ".tcptrace-findings" in DARK_CSS
    assert ".finding-row" in DARK_CSS
    assert ".finding-detail" in DARK_CSS
    assert ".conn-warn" in DARK_CSS
    assert ".conn-warn-bad" in DARK_CSS
