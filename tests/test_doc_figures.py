"""Doc figures gate: each figure that the README and the competency answers state is recomputed here from the raw sources
(tests/source_model.py) or from the built answers, and must appear in the text exactly. Added on 2026-11-08 after a review
found figures that no longer matched the data."""

import csv
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from source_model import sources  # noqa: E402

README = (ROOT / "README.md").read_text(encoding="utf-8")
CQ = (ROOT / "docs" / "competency-questions.md").read_text(encoding="utf-8")
CHECKS = json.loads((ROOT / "data" / "source-checks.json").read_text(encoding="utf-8"))


def answer(n):
    with open(ROOT / "exports" / "questions" / f"{n}.csv", newline="", encoding="utf-8") as h:
        return list(csv.DictReader(h))


@pytest.fixture(scope="module")
def src():
    return sources()


def fmt(n):
    return f"{n:,}"


def test_readme_source_figures(src):
    c = CHECKS["counts"]
    assert f"{fmt(c['sourceRows'])} NIST mapping rows and {fmt(len(src.cis_rows))} CIS mapping rows" in README
    assert f"{c['techniquesInAttackEnterprise']} techniques, {c['tactics']} tactics" in README
    assert f"The mapping covers {c['controls']} technical base controls in 11 families" in README
    no_row = len(set(src.techniques) - {r["attack_object_id"] for r in src.rows})
    assert f"{no_row} ATT&CK Enterprise techniques do not have a row in the mapping" in README


def test_readme_cis_figures(src):
    claims = sum(len(v) for v in src.cis_for.values())
    safeguards = len({s for v in src.cis_for.values() for s in v})
    non_mappable = len({r["capability_id"] for r in src.cis_rows if r["status"] == "non_mappable"})
    assert f"{fmt(claims)} claims from {safeguards} Safeguards on {len(src.cis_for)} techniques" in README
    assert f"The file marks the other {non_mappable} Safeguards as non_mappable" in README
    only19 = sum(1 for t in src.cis_for if t in src.active19 and t not in src.to16)
    assert f"{only19} techniques that CIS maps are only in 19.1" in README


def test_readme_atlas_and_attack_figures(src):
    subs = sum(1 for t in src.atlas_techniques.values() if "specializes" in t)
    v = src.atlas_version
    assert f"MITRE ATLAS {v}" in README and CHECKS["atlas"]["version"] == v
    assert f"{len(src.atlas_techniques) - subs} techniques, {subs} sub-techniques and {len(src.atlas_mitigations)} mitigations" in README
    assert f"{len(src.atlas_agent)} of them concern AI agents" in README
    later = CHECKS["laterVersion"]["version"]
    assert later == "20.1"
    assert f"ATT&CK {later}, the newest release on {CHECKS['newestCheckedOn']}, revokes, renames or moves 208 of its techniques" in README
    assert f"attack-16.1-to-{later}.csv" in README and (ROOT / "exports" / f"attack-16.1-to-{later}.csv").exists()
    assert len({r["technique_id"] for r in csv.DictReader(open(ROOT / "exports" / f"attack-16.1-to-{later}.csv", encoding="utf-8"))}) == 208


def test_competency_answer_figures():
    c14 = answer("cq14")
    assert f"{len(c14)} claimed techniques are revoked or renamed in ATT&CK 20.1" in CQ
    t = {r["technique"]: r for r in c14}
    assert t["T1070.001"]["laterId"] == "T1685.005" and t["T1070.001"]["claims"] == "21" and t["T1211"]["laterName"] == "Exploitation for Stealth"
    c15 = {(r["fromTactic"], r["toTactic"]): r["techniques"] for r in answer("cq15")}
    assert c15[("Defense Evasion", "Stealth (TA0005)")] == "134" and c15[("Defense Evasion", "Defense Impairment (TA0112)")] == "41"
    c16 = answer("cq16")
    assert f"{len(c16)} of the 39 ATLAS techniques against AI agents" in CQ and all(r[list(r)[0]] in CQ for r in c16)
    c17 = answer("cq17")
    top = max(int(r["agentTechniques"]) for r in c17)
    second = sorted({int(r["agentTechniques"]) for r in c17}, reverse=True)[1]
    tied = [r["mitigation"] for r in c17 if int(r["agentTechniques"]) == second]
    assert [r["mitigation"] for r in c17 if int(r["agentTechniques"]) == top] == ["AML.M0020"] and f"({top})" in CQ
    words = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six"}
    assert f"Next are {words[len(tied)]} mitigations with {second} each" in CQ and all(m in CQ for m in tied)
    c18 = answer("cq18")
    assert f"47 cite a technique in ATT&CK 16.1" in CQ and len(c18) == 47
    assert f"For {sum(1 for r in c18 if r[list(r)[-1]] not in ('0', ''))} of the 47" in CQ
    c19 = answer("cq19")
    assert len(c19) == 10 and [r[list(r)[1]] for r in c19 if not r[list(r)[-1]]] == ["AML.T0048.002"]
    c20 = answer("cq20")
    assert [(r["control"], r["sharedTechniques"]) for r in c20[:3]] == [("SI-03", "45"), ("SI-04", "43"), ("AC-06", "40")] and c20[9]["control"] == "SI-07"
    c21 = answer("cq21")
    sums = {k: sum(int(r[k]) for r in c21) for k in ("both", "onlyCis", "onlyNist")}
    assert f"{sums['both']} technique and tactic pairs have claims from both frameworks, {sums['onlyCis']} only from CIS and {sums['onlyNist']} only from NIST" in CQ
    c22 = answer("cq22")
    assert f"CIS maps {len(c22)} techniques" in CQ and f"{sum(1 for r in c22 if r['replaces16'])} of them replace" in CQ


def test_cq19_text_matches_the_owasp_and_atlas_data(src):
    llm = next(l for l in src.owasp["lists"] if l["id"] == "owasp-llm-top10-2025")
    ids = [a for i in llm["items"] for a in i.get("related_atlas", [])]
    risks = sum(1 for i in llm["items"] if i.get("related_atlas"))
    present = {a for a in ids if a in src.atlas_techniques}
    with_mit = sum(1 for a in present if src.atlas_mitigated_by[a])
    assert f"OWASP links {risks} of the 10 LLM risks to {len(set(ids))} ATLAS techniques, in {len(ids)} links" in CQ
    assert f"ATLAS {src.atlas_version} has {len(present)} of the {len(set(ids))} and gives mitigations for {with_mit} of them" in CQ


def test_oscal_release_statement_matches_the_catalogs():
    """The README and the page explain the title differences. They are not caused by the catalog release: catalog 5.2.0
    changes no title of a mapped control (checked against 5.1.1+u4, current when CTID last updated the file)."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import verify_upstream_findings as v  # noqa: PLC0415 - pinned by commit and digest

    def controls(name):
        cat = v.load(name)["catalog"]
        out, stack = {}, list(cat["groups"])
        while stack:
            g = stack.pop()
            for c in g.get("controls", []):
                label = next((p["value"] for p in c.get("props", []) if p["name"] == "label" and p.get("class") == "zero-padded"), None)
                if label:
                    out[label] = c["title"]
                stack.append(c)
        return out

    old, new = controls("oscal_2024_02.json"), controls("oscal_5_2_0.json")
    ctid = v.load("ctid_nist_16_1.json")
    mapped = {r["capability_id"] for r in ctid["mapping_objects"] if r["capability_id"]}
    assert ctid["metadata"]["mapping_framework_version"] == "rev5" and ctid["metadata"]["last_update"] == "04/16/2025"
    assert len(mapped) == 109 and not [c for c in mapped if old.get(c) != new.get(c)]
    added_base = sorted(k for k in new if k not in old and "(" not in k)
    assert added_base == ["SA-24"] and "SA-24" not in mapped
    statement = "Catalog 5.2.0 changes no title of the 109 mapped controls. It adds one base control, SA-24, which the mapping does not cover."
    assert statement in README and statement in (ROOT / "src" / "viewer.html").read_text(encoding="utf-8")
    assert "The mapping uses an older Rev. 5 release" not in README
