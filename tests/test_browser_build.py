"""The published graph browser is built from the current sources and makes no network requests."""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_index_html_is_built_from_the_current_sources():
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_graph.py"), "--check"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_index_html_is_self_contained():
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script[^>]+src=", html)
    assert not re.search(r"<link[^>]+stylesheet", html)
