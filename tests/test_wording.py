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


def test_ai_agent_statement_agrees_with_attack():
    """ATT&CK 16.1, the version that the mapping uses, has no technique for attacks on AI agents. ATT&CK 20.1 has some
    (prompt injection). The README must say both. Limit: the test finds these techniques by name only."""
    import sys  # noqa: PLC0415

    sys.path.insert(0, str(ROOT / "scripts"))
    import build_population  # noqa: PLC0415

    pattern = re.compile(r"Prompt Injection|AI Agent|Agentic|AI Result|AI-Enabled|Autonomous")

    def matching(key):
        out = {}
        for o in build_population.fetch(key)["objects"]:
            if o.get("type") == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
                tid = next(r["external_id"] for r in o["external_references"] if r.get("source_name") == "mitre-attack")
                if pattern.search(o["name"]):
                    out[tid] = o["name"]
        return out

    assert matching("attack") == {}
    later = matching("attack_latest")
    assert {"T1698", "T1699"} <= set(later)
    statement = ("ATT&CK 16.1, the version that the mapping uses, has no technique for attacks on AI agents. "
                 "NIST 800-53 has no control specifically for them. "
                 f"ATT&CK 20.1 has some, for example T1698 {later['T1698']} and T1699 {later['T1699']}. "
                 "The CTID mapping to NIST 800-53 does not include ATT&CK 20.1.")
    assert statement in README
    assert "do not describe attacks on AI agents" not in README


CHECKS_ON = __import__("json").loads((ROOT / "data" / "source-checks.json").read_text(encoding="utf-8"))["newestCheckedOn"]
ATLAS_NIST = (f"This tool uses no mapping from ATLAS to NIST 800-53. On {CHECKS_ON}, "
              "[CTID Mappings Explorer](https://ctid.mitre.org/mappings/external/) publishes none.")


def test_atlas_to_nist_statement_is_dated_and_names_its_source():
    """Evidence of the check is in docs/spec-2.8.1.md. A claim that no mapping exists anywhere cannot be examined."""
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", CHECKS_ON)
    assert ATLAS_NIST in README
    assert ATLAS_NIST in (ROOT / "docs" / "vocabulary-alignment.md").read_text(encoding="utf-8")
    for path in ("README.md", "docs/vocabulary-alignment.md"):
        assert "No published mapping exists" not in (ROOT / path).read_text(encoding="utf-8"), path
