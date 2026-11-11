"""Wording gate (release 2.8.1, docs/spec-2.8.1.md): each statement about what a result means, or about a source, must agree
with the data and must not say more than the data shows. Added on 2026-11-11."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
VIEWER = (ROOT / "src" / "viewer.html").read_text(encoding="utf-8")


def coverage_states():
    rows = re.findall(r"^\| (Covered|Gap|No mapped control) \| (.+?) \|$", README, re.M)
    assert [s for s, _ in rows] == ["Covered", "Gap", "No mapped control"]
    return dict(rows)


def test_page_and_readme_define_the_coverage_states_the_same_way():
    for state, meaning in coverage_states().items():
        assert meaning in VIEWER, f"the page does not define {state} as the README does"


def test_coverage_states_do_not_say_more_than_the_mapping_shows():
    states = coverage_states()
    assert states["Covered"] == "At least one of your controls is mapped as able to mitigate the technique."
    assert "This does not mean that no defence exists." in states["No mapped control"]
    for text in (README, VIEWER):
        assert "More NIST controls cannot cover it" not in text
        assert "Selecting more NIST controls cannot cover them" not in text
