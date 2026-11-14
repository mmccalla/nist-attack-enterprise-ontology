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


TRUST = ("Each claim shows the CTID source row that it comes from, on the page and in the API. "
         "The build checks each downloaded source against a pinned SHA-256 digest. "
         "[`SOURCE-MANIFEST.md`](SOURCE-MANIFEST.md) lists each source with its digest. "
         "Possible gaps in the CTID mapping are filed for investigation as "
         "[CTID issue #151](https://github.com/center-for-threat-informed-defense/mappings-explorer/issues/151).")


def test_trust_statement_is_in_the_readme():
    assert TRUST in README.split("## ", 1)[0], "the trust statement must be in the first section of the README"


def test_each_claim_gives_its_source_row():
    import json  # noqa: PLC0415

    files = sorted((ROOT / "api" / "v1" / "techniques").glob("*.json"))
    assert len(files) > 600
    checked = 0
    for path in files:
        doc = json.loads(path.read_text(encoding="utf-8"))
        for claim in doc.get("claims", []) + doc.get("cis_claims", []):
            records = [e.get("source_record") for e in claim["evidence"]]
            assert records and all(isinstance(r, int) for r in records), path.name
            checked += 1
    assert checked > 5000


def test_each_source_record_matches_the_raw_ctid_row():
    """Each NIST claim must cite the correct raw CTID row (audit item 2, M8).

    The source_record is a 1-based index into the raw mapping_objects array.
    This test verifies that the cited row has the same control and technique.
    """
    import json  # noqa: PLC0415
    import sys  # noqa: PLC0415

    sys.path.insert(0, str(ROOT / "scripts"))
    import build_population  # noqa: PLC0415

    ctid_rows = build_population.fetch("ctid")["mapping_objects"]
    files = sorted((ROOT / "api" / "v1" / "techniques").glob("*.json"))
    checked = 0
    for path in files:
        doc = json.loads(path.read_text(encoding="utf-8"))
        technique_id = doc["id"]
        for claim in doc.get("claims", []):
            control_id = claim["control"]["id"]
            for ev in claim["evidence"]:
                n = ev["source_record"]
                raw = ctid_rows[n - 1]
                assert raw["capability_id"] == control_id, (
                    f"{path.name}: row {n} has control {raw['capability_id']!r}, "
                    f"expected {control_id!r}"
                )
                assert raw["attack_object_id"] == technique_id, (
                    f"{path.name}: row {n} has technique {raw['attack_object_id']!r}, "
                    f"expected {technique_id!r}"
                )
                checked += 1
    assert checked > 5000, f"only {checked} NIST records checked"


def test_each_source_file_is_in_the_manifest_with_its_current_digest():
    import hashlib  # noqa: PLC0415

    manifest = (ROOT / "SOURCE-MANIFEST.md").read_text(encoding="utf-8")
    files = sorted((ROOT / "data" / "sources").glob("*.json"))
    assert len(files) >= 3
    for path in files:
        row = next((line for line in manifest.splitlines() if line.startswith(f"| `data/sources/{path.name}` |")), None)
        assert row, f"{path.name} is not in SOURCE-MANIFEST.md"
        assert hashlib.sha256(path.read_bytes()).hexdigest() in row, f"{path.name}: the manifest digest is not current"


def test_each_newest_release_statement_has_the_check_date():
    found = re.findall(r"the newest release( on \d{4}-\d{2}-\d{2})?", README)
    assert len(found) >= 2
    assert all(f == f" on {CHECKS_ON}" for f in found), found


def test_release_number_and_date_agree_everywhere():
    """CITATION.cff is the one place where the release is set. The newest released changelog heading, the API and
    llms.txt must agree with it."""
    import json  # noqa: PLC0415

    cff = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    version = re.search(r"^version:\s*(\S+)", cff, re.M).group(1)
    date = re.search(r"^date-released:\s*(\S+)", cff, re.M).group(1)
    heading = re.search(r"^## (\d+\.\d+\.\d+) \((\d{4}-\d{2}-\d{2})\)$", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.M)
    assert heading.groups() == (version, date)
    assert json.loads((ROOT / "api" / "v1" / "version.json").read_text(encoding="utf-8"))["versions"]["release"] == version
    assert f"Release {version}," in (ROOT / "llms.txt").read_text(encoding="utf-8")
