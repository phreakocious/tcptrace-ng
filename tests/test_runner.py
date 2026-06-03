from pathlib import Path
from unittest.mock import patch

import pytest

from tcptrace_ng.runner import (
    AnalyzeResult,
    ConnRow,
    RunnerError,
    _resolve_tcptrace,
    analyze_all,
    analyze_connection,
    list_connections,
    parse_listing,
    try_convert_to_pcap,
)
from tcptrace_ng.stats_parser import ConnStats


def test_parse_listing_extracts_three_rows(sample_listing):
    rows = parse_listing(sample_listing)
    assert len(rows) == 3
    assert rows[0] == ConnRow(
        n=1,
        host_a="10.0.0.1:443",
        host_b="10.0.0.2:51234",
        raw_line="  1: 10.0.0.1:443 - 10.0.0.2:51234 (a2b)              42 ackpkts sent",
    )
    assert rows[2].n == 3
    assert rows[2].host_a == "192.168.1.5:22"
    assert rows[2].host_b == "192.168.1.99:60001"


def test_parse_listing_empty_returns_empty():
    assert parse_listing("") == []


def test_parse_listing_ignores_non_conn_lines():
    text = "garbage\n  1: a:1 - b:2 (x)  stats\nmore garbage\n"
    rows = parse_listing(text)
    assert len(rows) == 1
    assert rows[0].n == 1


def test_list_connections_calls_tcptrace_subprocess(sample_listing, tmp_path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)

    with (
        patch("tcptrace_ng.runner._resolve_tcptrace", return_value="tcptrace"),
        patch("tcptrace_ng.runner.subprocess.run") as mock_run,
    ):
        mock_run.return_value.stdout = sample_listing
        mock_run.return_value.returncode = 0
        rows = list_connections(pcap)
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "tcptrace"
        assert str(pcap) in cmd
    assert len(rows) == 3


def test_list_connections_raises_on_nonzero_exit(tmp_path):
    pcap = tmp_path / "bad.pcap"
    pcap.write_bytes(b"")
    with (
        patch("tcptrace_ng.runner._resolve_tcptrace", return_value="tcptrace"),
        patch("tcptrace_ng.runner.subprocess.run") as mock_run,
    ):
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "not a pcap"
        mock_run.return_value.returncode = 1
        with pytest.raises(RunnerError):
            list_connections(pcap)


def test_try_convert_to_pcap_returns_existing_if_already_pcap(tmp_path):
    pcap = tmp_path / "good.pcap"
    pcap.write_bytes(b"")
    with patch("tcptrace_ng.runner.subprocess.run") as mock_run:
        mock_run.return_value.stdout = "File type:  pcap\n"
        mock_run.return_value.returncode = 0
        with patch("tcptrace_ng.runner.shutil.which", return_value="/usr/bin/capinfos"):
            result = try_convert_to_pcap(pcap)
    assert result == pcap


def test_try_convert_to_pcap_runs_editcap_when_not_pcap(tmp_path):
    cap = tmp_path / "weird.cap"
    cap.write_bytes(b"")
    converted = Path(str(cap) + ".pcap")

    def fake_run(cmd, **kw):
        from types import SimpleNamespace

        if cmd[0] == "capinfos":
            return SimpleNamespace(stdout="File type:  Sniffer\n", returncode=0, stderr="")
        if cmd[0] == "editcap":
            converted.write_bytes(b"")  # editcap "creates" the file
            return SimpleNamespace(stdout="", returncode=0, stderr="")
        raise AssertionError(f"unexpected {cmd}")

    with (
        patch("tcptrace_ng.runner.subprocess.run", side_effect=fake_run),
        patch("tcptrace_ng.runner.shutil.which", return_value="/usr/local/bin/x"),
    ):
        result = try_convert_to_pcap(cap)
    assert result == converted


def test_try_convert_raises_when_capinfos_missing(tmp_path):
    cap = tmp_path / "x.cap"
    cap.write_bytes(b"")
    with (
        patch("tcptrace_ng.runner.shutil.which", return_value=None),
        pytest.raises(RunnerError, match="capinfos"),
    ):
        try_convert_to_pcap(cap)


def test_analyze_connection_invokes_correct_tcptrace_command(tmp_path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "conn-4--a2b_tsg.xpl").write_text("go\n")

    with (
        patch("tcptrace_ng.runner._resolve_tcptrace", return_value="tcptrace"),
        patch("tcptrace_ng.runner.subprocess.run") as mock_run,
    ):
        mock_run.return_value.stdout = "long detail text"
        mock_run.return_value.stderr = ""
        mock_run.return_value.returncode = 0
        result = analyze_connection(pcap, conn_n=4, output_dir=out_dir)

    cmd = mock_run.call_args[0][0]
    assert cmd[0] == "tcptrace"
    assert "-l" in cmd
    assert "-o4" in cmd
    assert "-G" in cmd
    assert "--output_prefix=conn-4--" in cmd
    assert str(pcap) in cmd
    assert mock_run.call_args.kwargs.get("cwd") == out_dir

    assert isinstance(result, AnalyzeResult)
    assert result.details_text == "long detail text"
    assert result.xpl_files == [out_dir / "conn-4--a2b_tsg.xpl"]


def test_analyze_all_runs_tcptrace_l_and_parses(tmp_path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"")

    fixture = (Path(__file__).parent / "fixtures" / "tcptrace_l_two_conns.txt").read_text()

    with (
        patch("tcptrace_ng.runner._resolve_tcptrace", return_value="tcptrace"),
        patch("tcptrace_ng.runner.subprocess.run") as mock_run,
    ):
        mock_run.return_value.stdout = fixture
        mock_run.return_value.returncode = 0
        rows = analyze_all(pcap)

    cmd = mock_run.call_args[0][0]
    assert cmd[0] == "tcptrace"
    assert "-l" in cmd
    assert not any(a.startswith("-o") for a in cmd)  # no per-conn scope
    assert "-G" not in cmd  # no xpl generation
    assert str(pcap) in cmd
    assert len(rows) == 2
    assert all(isinstance(r, ConnStats) for r in rows)


def test_list_connections_adds_n_flag_when_no_dns_true(tmp_path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"")
    with (
        patch("tcptrace_ng.runner._resolve_tcptrace", return_value="tcptrace"),
        patch("tcptrace_ng.runner.subprocess.run") as mock_run,
    ):
        mock_run.return_value.stdout = ""
        mock_run.return_value.returncode = 0
        list_connections(pcap, no_dns=True)

    cmd = mock_run.call_args[0][0]
    assert "-n" in cmd
    assert cmd.index("-n") < cmd.index(str(pcap))  # flag before positional


def test_list_connections_omits_n_flag_by_default(tmp_path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"")
    with (
        patch("tcptrace_ng.runner._resolve_tcptrace", return_value="tcptrace"),
        patch("tcptrace_ng.runner.subprocess.run") as mock_run,
    ):
        mock_run.return_value.stdout = ""
        mock_run.return_value.returncode = 0
        list_connections(pcap)

    assert "-n" not in mock_run.call_args[0][0]


def test_analyze_all_passes_n_r_w_flags(tmp_path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"")
    fixture = (Path(__file__).parent / "fixtures" / "tcptrace_l_two_conns.txt").read_text()
    with (
        patch("tcptrace_ng.runner._resolve_tcptrace", return_value="tcptrace"),
        patch("tcptrace_ng.runner.subprocess.run") as mock_run,
    ):
        mock_run.return_value.stdout = fixture
        mock_run.return_value.returncode = 0
        analyze_all(pcap, no_dns=True, with_rtt=True, with_warnings=True)

    cmd = mock_run.call_args[0][0]
    assert "-n" in cmd
    assert "-r" in cmd
    assert "-w" in cmd
    # The pcap path is the final positional; flags come before it.
    assert cmd[-1] == str(pcap)


def test_analyze_connection_passes_all_flags_including_zx(tmp_path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    with (
        patch("tcptrace_ng.runner._resolve_tcptrace", return_value="tcptrace"),
        patch("tcptrace_ng.runner.subprocess.run") as mock_run,
    ):
        mock_run.return_value.stdout = ""
        mock_run.return_value.returncode = 0
        analyze_connection(
            pcap,
            conn_n=2,
            output_dir=out_dir,
            no_dns=True,
            with_rtt=True,
            with_warnings=True,
            zero_x_axis=True,
        )

    cmd = mock_run.call_args[0][0]
    assert "-n" in cmd
    assert "-r" in cmd
    assert "-w" in cmd
    assert "-zx" in cmd
    # output_prefix and pcap path stay at the tail.
    assert cmd[-2] == "--output_prefix=conn-2--"
    assert cmd[-1] == str(pcap)


def test_analyze_all_passes_checksum_flags(tmp_path):
    """with_checksum bundles --checksum + --warn_printbadcsum: verification
    plus the warning that actually surfaces bad ones."""
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"")
    fixture = (Path(__file__).parent / "fixtures" / "tcptrace_l_two_conns.txt").read_text()
    with (
        patch("tcptrace_ng.runner._resolve_tcptrace", return_value="tcptrace"),
        patch("tcptrace_ng.runner.subprocess.run") as mock_run,
    ):
        mock_run.return_value.stdout = fixture
        mock_run.return_value.returncode = 0
        analyze_all(pcap, with_checksum=True)

    cmd = mock_run.call_args[0][0]
    assert "--checksum" in cmd
    assert "--warn_printbadcsum" in cmd
    assert cmd[-1] == str(pcap)


def test_analyze_connection_passes_checksum_flags(tmp_path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    with (
        patch("tcptrace_ng.runner._resolve_tcptrace", return_value="tcptrace"),
        patch("tcptrace_ng.runner.subprocess.run") as mock_run,
    ):
        mock_run.return_value.stdout = ""
        mock_run.return_value.returncode = 0
        analyze_connection(pcap, conn_n=1, output_dir=out_dir, with_checksum=True)

    cmd = mock_run.call_args[0][0]
    assert "--checksum" in cmd
    assert "--warn_printbadcsum" in cmd


def test_analyze_all_omits_checksum_flags_by_default(tmp_path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"")
    fixture = (Path(__file__).parent / "fixtures" / "tcptrace_l_two_conns.txt").read_text()
    with (
        patch("tcptrace_ng.runner._resolve_tcptrace", return_value="tcptrace"),
        patch("tcptrace_ng.runner.subprocess.run") as mock_run,
    ):
        mock_run.return_value.stdout = fixture
        mock_run.return_value.returncode = 0
        analyze_all(pcap)

    cmd = mock_run.call_args[0][0]
    assert "--checksum" not in cmd
    assert "--warn_printbadcsum" not in cmd


def test_resolve_tcptrace_prefers_env_var(tmp_path, monkeypatch):
    custom = tmp_path / "tcptrace"
    custom.write_text("#!/bin/sh\n")
    custom.chmod(0o755)
    monkeypatch.setenv("TCPTRACE_BIN", str(custom))
    assert _resolve_tcptrace() == str(custom)


def test_resolve_tcptrace_raises_when_env_var_not_executable(tmp_path, monkeypatch):
    monkeypatch.setenv("TCPTRACE_BIN", str(tmp_path / "nope"))
    with pytest.raises(RunnerError, match="TCPTRACE_BIN"):
        _resolve_tcptrace()


def test_resolve_tcptrace_uses_vendored_when_present(tmp_path, monkeypatch):
    monkeypatch.delenv("TCPTRACE_BIN", raising=False)
    fake = tmp_path / "tcptrace"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    with (
        patch("tcptrace_ng.runner._VENDORED_TCPTRACE", fake),
        patch("tcptrace_ng.runner.shutil.which", return_value="/usr/bin/tcptrace"),
    ):
        assert _resolve_tcptrace() == str(fake)


def test_resolve_tcptrace_falls_back_to_path(tmp_path, monkeypatch):
    monkeypatch.delenv("TCPTRACE_BIN", raising=False)
    missing = tmp_path / "nonexistent"
    with (
        patch("tcptrace_ng.runner._VENDORED_TCPTRACE", missing),
        patch("tcptrace_ng.runner.shutil.which", return_value="/usr/bin/tcptrace"),
    ):
        assert _resolve_tcptrace() == "/usr/bin/tcptrace"


def test_resolve_tcptrace_raises_when_nothing_found(tmp_path, monkeypatch):
    monkeypatch.delenv("TCPTRACE_BIN", raising=False)
    missing = tmp_path / "nonexistent"
    with (
        patch("tcptrace_ng.runner._VENDORED_TCPTRACE", missing),
        patch("tcptrace_ng.runner.shutil.which", return_value=None),
        pytest.raises(RunnerError, match="tcptrace not found"),
    ):
        _resolve_tcptrace()


def test_analyze_all_raises_on_nonzero_exit(tmp_path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"")
    with (
        patch("tcptrace_ng.runner._resolve_tcptrace", return_value="tcptrace"),
        patch("tcptrace_ng.runner.subprocess.run") as mock_run,
    ):
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "boom"
        mock_run.return_value.returncode = 1
        with pytest.raises(RunnerError):
            analyze_all(pcap)
