"""The bundled wordlist and version metadata (issue #9)."""

from __future__ import annotations

from pathlib import Path

import pytest

import webrecon
from webrecon import config
from webrecon.modules import dns_enum

ROOT = Path(__file__).resolve().parent.parent


def test_bundled_wordlist_is_reachable_through_importlib_resources():
    words = dns_enum.load_wordlist(config.bundled_wordlist())
    assert "www" in words and len(words) > 100


def test_user_agent_carries_the_package_version():
    assert f"webrecon/{webrecon.__version__}" in config.USER_AGENT


@pytest.mark.skipif(not (ROOT / "pyproject.toml").exists(), reason="source checkout only")
def test_pyproject_reads_the_version_from_the_package():
    tomllib = pytest.importorskip("tomllib")
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "version" in meta["project"]["dynamic"]
    assert meta["tool"]["setuptools"]["dynamic"]["version"]["attr"] == "webrecon.__version__"
    assert "data/*.txt" in meta["tool"]["setuptools"]["package-data"]["webrecon"]
