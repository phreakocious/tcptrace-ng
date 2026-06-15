"""Smoke tests for view/header.py — handle shape and refresh helpers."""

from __future__ import annotations

import pytest
from nicegui.testing import User

from tcptrace_ng.app import build_page


@pytest.fixture
def empty_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


async def test_header_renders_widgets(user: User, empty_cwd):
    build_page()
    await user.open("/")
    await user.should_see("tcptrace-ng")
    await user.should_see("DNS")
    await user.should_see("RTT")
    await user.should_see("Clear cache")
    await user.should_see("Reanalyze")
