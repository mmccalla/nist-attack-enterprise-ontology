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


def test_each_node_label_is_the_identifier_of_its_entity():
    """Labels come from the entity's own identifier, never from a property value (a shadowed name once gave every technique a catalogue label)."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_graph  # noqa: PLC0415

    nodes, _ = build_graph.build_instances(build_graph.load())
    key = {"AttackTechnique": ":techniqueId", "SecurityControl": ":controlId", "CisSafeguard": ":controlId", "AtlasTechnique": ":techniqueId"}
    checked = 0
    for n in nodes:
        if n["t"] in key:
            assert n["l"] == n["p"][key[n["t"]]], n["id"]
            checked += 1
    assert checked > 1100
