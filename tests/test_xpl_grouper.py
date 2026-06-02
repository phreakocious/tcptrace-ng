from tcptrace_ng.xpl_grouper import GroupedXpl, group_xpls, parse_xpl_name


def test_parse_xpl_name_a2b_tsg():
    assert parse_xpl_name("conn-1--a2b_tsg.xpl") == ("tsg", "forward")


def test_parse_xpl_name_b2a_owin():
    assert parse_xpl_name("conn-12--b2a_owin.xpl") == ("owin", "backward")


def test_parse_xpl_name_c2d_rtt():
    # Different host-pair letters used by tcptrace
    assert parse_xpl_name("conn-3--c2d_rtt.xpl") == ("rtt", "forward")


def test_parse_xpl_name_combined_tline():
    assert parse_xpl_name("conn-3--a_b_tline.xpl") == ("tline", "combined")


def test_parse_xpl_name_unknown_returns_none():
    assert parse_xpl_name("conn-9--weird_thing.xpl") is None


def test_parse_xpl_name_two_letter_host_labels():
    """tcptrace rolls over to two-letter labels (aa/ab, ac/ad, …) past
    conn 13; xpl filenames inherit them: `conn-14--aa2ab_tsg.xpl`,
    `conn-14--ab2aa_owin.xpl`, `conn-14--aa_ab_tline.xpl`."""
    assert parse_xpl_name("conn-14--aa2ab_tsg.xpl") == ("tsg", "forward")
    assert parse_xpl_name("conn-14--ab2aa_owin.xpl") == ("owin", "backward")
    assert parse_xpl_name("conn-14--aa_ab_tline.xpl") == ("tline", "combined")
    assert parse_xpl_name("conn-56--dg2dh_rtt.xpl") == ("rtt", "forward")


def test_group_xpls_orders_metrics_and_collapses_directions(tmp_path):
    files = [
        tmp_path / "conn-1--a2b_owin.xpl",
        tmp_path / "conn-1--b2a_owin.xpl",
        tmp_path / "conn-1--a2b_tsg.xpl",
        tmp_path / "conn-1--a_b_tline.xpl",
    ]
    for f in files:
        f.write_text("")
    grouped = group_xpls(files)

    # tsg first per fixed ordering, then owin (no rtt/tput/ssize present), then tline
    assert all(isinstance(g, GroupedXpl) for g in grouped)
    metrics = [g.metric for g in grouped]
    assert metrics == ["tsg", "owin", "tline"]

    tsg = grouped[0]
    assert tsg.forward is not None
    assert tsg.backward is None

    owin = grouped[1]
    assert owin.forward is not None
    assert owin.backward is not None

    tline = grouped[2]
    assert tline.combined is not None
