from unittest.mock import patch

import pytest

from tcptrace_ng.cli import build_arg_parser, main


def test_arg_parser_defaults():
    p = build_arg_parser()
    args = p.parse_args([])
    assert args.dir == "."
    assert args.port is None
    assert args.no_browser is False
    assert args.timeout == 60.0


def test_arg_parser_overrides():
    p = build_arg_parser()
    args = p.parse_args(["/tmp/pcaps", "--port", "8765", "--no-browser", "--timeout", "120"])
    assert args.dir == "/tmp/pcaps"
    assert args.port == 8765
    assert args.no_browser is True
    assert args.timeout == 120.0


def test_main_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "tcptrace-ng" in captured.out


def test_main_calls_ui_run_with_resolved_args(tmp_path):
    with (
        patch("tcptrace_ng.cli.ui") as mock_ui,
        patch("tcptrace_ng.cli.build_page") as mock_build,
        patch("tcptrace_ng.cli.os.chdir") as mock_chdir,
    ):
        main([str(tmp_path), "--port", "9999", "--no-browser"])
    mock_chdir.assert_called_once_with(str(tmp_path))
    mock_build.assert_called_once()
    kwargs = mock_ui.run.call_args.kwargs
    assert kwargs["port"] == 9999
    assert kwargs["show"] is False
    assert kwargs["reload"] is False


def test_main_threads_runtime_flags_into_state(tmp_path):
    from tcptrace_ng.app import state

    # Capture and restore so test order independence is preserved.
    saved = (state.timeout, state.debug)
    try:
        with (
            patch("tcptrace_ng.cli.ui"),
            patch("tcptrace_ng.cli.build_page"),
            patch("tcptrace_ng.cli.os.chdir"),
        ):
            main(
                [
                    str(tmp_path),
                    "--no-browser",
                    "--timeout",
                    "12.5",
                    "--debug",
                ]
            )
        assert state.timeout == 12.5
        assert state.debug is True
    finally:
        state.timeout, state.debug = saved
