"""Competency gate: each competency question in queries/ must return the answer computed independently from
the raw sources (tests/source_model.py). See docs/competency-questions.md."""

import sys
from collections import Counter, defaultdict
from pathlib import Path

import pytest
from rdflib import Graph

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from source_model import sources  # noqa: E402

QUERIES = ROOT / "queries"


@pytest.fixture(scope="module")
def graph():
    g = Graph()
    g.parse(ROOT / "ontology" / "core.ttl")
    g.parse(ROOT / "data" / "population.ttl")
    return g


@pytest.fixture(scope="module")
def src():
    return sources()


def ask(graph, name):
    path = next(QUERIES.glob(f"{name}-*.rq"))
    return [tuple(None if v is None else v.toPython() for v in row) for row in graph.query(path.read_text())]


def test_every_query_has_a_catalogue_header():
    for path in sorted(QUERIES.glob("cq*.rq")):
        head = path.read_text().splitlines()[:5]
        for i, key in enumerate(("id", "persona", "question", "decision", "evidence")):
            assert head[i].startswith(f"# {key}: "), f"{path.name} line {i + 1}"


def test_cq01_controls_for_technique(graph, src):
    expected = {(c, src.oscal[c]["title"], tuple(sorted(src.baselines_of(c)))) for c in src.controls_for["T1078"]}
    actual = {(c, t, tuple(sorted(b.split()))) for c, t, b in ask(graph, "cq01")}
    assert actual == expected and len(actual) == 25
    # Figures quoted in docs/competency-questions.md.
    levels = [set(b) for _, _, b in actual]
    assert (sum("HIGH" in l for l in levels), sum("MODERATE" in l for l in levels), sum("LOW" in l for l in levels)) == (23, 22, 15)


def test_cq02_top_controls_for_initial_access(graph, src):
    counts = Counter()
    for tid, controls in src.controls_for.items():
        if "TA0001" in src.tactics_of[tid]:
            counts.update(controls)
    expected = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    assert [(c, n) for c, _, n in ask(graph, "cq02")] == expected


def test_cq03_techniques_without_low_baseline_cover(graph, src):
    expected = {t for t, controls in src.controls_for.items() if not any("LOW" in src.baselines_of(c) for c in controls)}
    assert {row[0] for row in ask(graph, "cq03")} == expected


def test_cq04_single_control_techniques(graph, src):
    expected = {(t, next(iter(c))) for t, c in src.controls_for.items() if len(c) == 1}
    assert {(t, c) for t, _, c in ask(graph, "cq04")} == expected


def test_cq05_non_mappable_against_attack_mitigations(graph, src):
    expected = {r["attack_object_id"]: src.attack_mitigations[r["attack_object_id"]] for r in src.rows if r["status"] == "non_mappable"}
    actual = {t: set(m.split()) for t, _, m, _ in ask(graph, "cq05")}
    assert actual == expected
    substantive = {t for t, m in actual.items() if m - {"M1055", "M1056"}}
    assert substantive == {"T1566.004", "T1598.004", "T1656"}


def test_cq06_attack_mitigations_and_controls_for_t1078(graph, src):
    rows = ask(graph, "cq06")
    assert {i for k, i, _ in rows if k == "ATT&CK mitigation"} == src.attack_mitigations["T1078"]
    assert {i for k, i, _ in rows if k == "NIST control"} == src.controls_for["T1078"]


def test_cq07_claim_evidence_is_traceable(graph, src):
    records = [n for n, r in enumerate(src.rows, 1) if r["capability_id"] == "AC-02" and r["attack_object_id"] == "T1556.009"]
    rows = ask(graph, "cq07")
    assert [r[1] for r in rows] == records
    row = rows[0]
    assert row[3] == "16.1" and row[2].startswith("Control AC-2")
    assert row[6] == "355ae97d309c00eb2428e5af07754ff4ca16cfe63928194081d0e883aed929c8"


def test_cq08_rows_outside_attack_enterprise(graph, src):
    expected = [(n, r["attack_object_id"]) for n, r in enumerate(src.rows, 1) if r["attack_object_id"] not in src.techniques]
    assert [(n, t) for n, _, t, _ in ask(graph, "cq08")] == expected == [(637, "T1521.003")]


def test_cq09_duplicate_rows(graph, src):
    pairs = Counter((r["capability_id"], r["attack_object_id"]) for r in src.rows if r["status"] == "complete")
    expected = {p: n for p, n in pairs.items() if n > 1}
    assert {(c, t): n for c, t, n, _ in ask(graph, "cq09")} == expected
    assert Counter(c for c, _ in expected) == {"CM-02": 47, "IA-09": 1, "SC-08": 1, "SI-12": 1}


def test_cq10_family_by_tactic(graph, src):
    cells = defaultdict(set)
    for tid, controls in src.controls_for.items():
        for c in controls:
            for ta in src.tactics_of[tid]:
                cells[(c[:2], src.tactic_names[ta])].add(tid)
    assert {(f, tac): n for f, tac, _, n in ask(graph, "cq10")} == {k: len(v) for k, v in cells.items()}


def test_cq11_iaas_techniques_with_thin_cover(graph, src):
    expected = {t: len(src.controls_for.get(t, ())) for t, o in src.techniques.items() if "IaaS" in o.get("x_mitre_platforms", []) and len(src.controls_for.get(t, ())) < 3}
    assert {t: n for t, _, n in ask(graph, "cq11")} == expected


def test_cq12_techniques_not_in_mapping(graph, src):
    mapped = {r["attack_object_id"] for r in src.rows}
    expected = set(src.techniques) - mapped
    assert {t for t, _ in ask(graph, "cq12")} == expected and len(expected) == 91


def test_cq13_naming_differences_from_oscal(graph, src):
    expected = {
        ("control", c): (r["capability_description"], src.oscal[c]["title"])
        for r in src.rows
        if (c := r["capability_id"]) and r["capability_description"] != src.oscal[c]["title"]
    }
    expected |= {("family", code): (name, src.families[code]) for code, name in src.family_names.items() if name != src.families[code]}
    assert {(k, i): (s, o) for k, i, s, o in ask(graph, "cq13")} == expected


def test_cq14_claims_on_techniques_revoked_or_renamed_in_20_0(graph, src):
    expected = {
        t: len(src.controls_for[t])
        for t, v in src.later.items()
        if (v["revoked"] or v["renamed"]) and src.controls_for.get(t)
    }
    rows = ask(graph, "cq14")
    assert {t: n for t, _, _, _, _, n in rows} == expected
    assert len(rows) == 25  # quoted in docs/competency-questions.md
    for t, _, statuses, later_id, _, _ in rows:
        if "revoked" in statuses:
            assert later_id in src.later[t]["replacement"]


def test_cq15_tactic_moves_from_16_1_to_20_0(graph, src):
    pairs = defaultdict(set)
    for t, v in src.later.items():
        if not v["tacticsChanged"]:
            continue
        lost = {x for x in v["oldTactics"] if not any(n.startswith(x + " (") for n in v["newTactics"])}
        gained = {n for n in v["newTactics"] if not any(n.startswith(x + " (") for x in v["oldTactics"])}
        for a in lost:
            for b in gained:
                pairs[(a, b)].add(t)
    assert {(a, b): n for a, b, n in ask(graph, "cq15")} == {k: len(v) for k, v in pairs.items()}
    top = {(f, t): n for f, t, n in ask(graph, "cq15")}
    assert top[("Defense Evasion", "Stealth (TA0005)")] == 134 and top[("Defense Evasion", "Defense Impairment (TA0112)")] == 41


def test_cq16_agent_techniques_without_atlas_mitigation(graph, src):
    def none(tid):
        parent = src.atlas_techniques[tid].get("specializes")
        return not src.atlas_mitigated_by[tid] and not (parent and src.atlas_mitigated_by[parent])
    expected = {t for t in src.atlas_agent if none(t)}
    assert {t for t, _, _ in ask(graph, "cq16")} == expected and len(expected) == 14
    assert len(src.atlas_agent) == 26  # quoted in the docs


def test_cq17_mitigations_for_agent_techniques(graph, src):
    expected = {m: sum(1 for t in src.atlas_agent if m in src.atlas_mitigated_by[t]) for m in src.atlas_mitigations}
    expected = {m: n for m, n in expected.items() if n}
    assert {m: n for m, _, _, n in ask(graph, "cq17")} == expected
    assert sorted(m for m, n in expected.items() if n == max(expected.values())) == ["AML.M0024", "AML.M0026", "AML.M0027", "AML.M0028", "AML.M0032"]


def test_cq18_atlas_techniques_derived_from_attack(graph, src):
    expected = {
        tid: (t["ATT&CK-reference"]["id"], len(src.controls_for.get(t["ATT&CK-reference"]["id"], ())))
        for tid, t in src.atlas_techniques.items() if t.get("ATT&CK-reference")
    }
    assert {a: (t, n) for a, _, t, _, n in ask(graph, "cq18")} == expected and len(expected) == 34
    assert sum(1 for _, n in expected.values() if n) == 18 and expected["AML.T0055"] == ("T1552", 32)


def test_cq19_owasp_llm_risks_to_atlas_mitigations(graph, src):
    llm = next(l for l in src.owasp["lists"] if l["id"] == "owasp-llm-top10-2025")
    expected = {}
    for item in llm["items"]:
        for aid in item["related_atlas"]:
            expected[(f"{item['id']} {item['title']}", aid)] = src.atlas_mitigated_by[aid]
    actual = {(r, a): set((m or "").split()) - {""} for r, a, _, m in ask(graph, "cq19")}
    assert actual == expected and len(expected) == 13
    assert sorted(a for (_, a), ms in expected.items() if not ms) == ["AML.T0048.002"]


def test_cq20_nist_controls_overlapping_cis_13_7(graph, src):
    techs16 = {src.to16[t] for t, cs in src.cis_for.items() if "CIS-13.7" in cs and t in src.to16}
    counts = Counter()
    for t in techs16:
        counts.update(src.controls_for.get(t, ()))
    expected = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    assert [(c, n) for c, _, n in ask(graph, "cq20")] == expected
    assert expected[0] == ("SI-03", 45)  # quoted in docs/competency-questions.md


def test_cq21_cis_and_nist_coverage_by_tactic(graph, src):
    both16 = set(src.to16.values())  # techniques active in 16.1 and 19.1
    cis16 = {src.to16[t] for t in src.cis_for if t in src.to16}
    cells = defaultdict(lambda: [0, 0, 0])
    for t in both16:
        cis, nist = t in cis16, bool(src.controls_for.get(t))
        for ta in src.tactics_of[t]:
            c = cells[src.tactic_names[ta]]
            if cis and nist: c[0] += 1
            elif cis: c[1] += 1
            elif nist: c[2] += 1
    assert {t: [b, c, n] for t, _, b, c, n in ask(graph, "cq21")} == {k: v for k, v in cells.items()}


def test_cq22_cis_techniques_only_in_19_1(graph, src):
    expected = {t: (len(cs), src.replaced_by19.get(t, set())) for t, cs in src.cis_for.items() if t not in src.to16}
    actual = {t: (n, set((r or "").split()) - {""}) for t, _, n, r in ask(graph, "cq22")}
    assert actual == expected and len(expected) == 29


def test_atlas_agent_counts_and_their_wording_agree(src):
    """26 agent techniques (derived), 19 with no direct ATLAS link, 14 with none on the technique or its parent (a project rule).
    The README must state the same figures and must not say that 14 have no ATLAS mitigation without the parent rule."""
    agent = src.atlas_agent
    no_direct = {t for t in agent if not src.atlas_mitigated_by.get(t)}
    parent = lambda t: src.atlas_techniques[t].get("specializes")  # noqa: E731
    no_direct_or_parent = {t for t in no_direct if not (parent(t) and src.atlas_mitigated_by.get(parent(t)))}
    assert (len(agent), len(no_direct), len(no_direct_or_parent)) == (26, 19, 14)
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "19 of the 26 agent techniques have no direct mitigation link" in readme
    assert "so 14 have none on the technique or its parent" in readme
    assert "14 of the 26 agent techniques have no ATLAS mitigation" not in readme
    assert "not current coverage" in readme
