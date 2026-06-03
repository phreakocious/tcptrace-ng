from tcptrace_ng.theme import DARK_CSS


def test_dark_css_has_dark_background_rule():
    assert "#000" in DARK_CSS or "black" in DARK_CSS.lower()


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
