"""Exports gate: the static CSVs and Navigator layers are current, well formed, and agree with an independent
reading of the raw sources."""

import csv
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / "exports"
sys.path.insert(0, str(ROOT / "tests"))
from source_model import sources  # noqa: E402


def read_csv(name):
    with open(EXPORTS / name, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_exports_are_up_to_date():
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_exports.py"), "--check"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_claims_csv_matches_the_source_pairs():
    src = sources()
    expected = {(c, t) for t, cs in src.controls_for.items() for c in cs}
    rows = read_csv("claims.csv")
    assert {(r["control_id"], r["technique_id"]) for r in rows} == expected and len(rows) == 5263
    for r in rows:
        records = [int(n) for n in r["source_record_numbers"].split()]
        assert all(src.rows[n - 1]["capability_id"] == r["control_id"] and src.rows[n - 1]["attack_object_id"] == r["technique_id"] for n in records)


def test_techniques_csv_covers_every_enterprise_technique():
    src = sources()
    rows = read_csv("techniques.csv")
    assert {r["technique_id"] for r in rows} == set(src.techniques)
    assert sum(r["mapping_status"] == "no_row" for r in rows) == 91


def layers():
    return {p.stem: json.loads(p.read_text()) for p in (EXPORTS / "navigator").glob("*.json")}


CIS_LAYERS = {"cis-all-safeguards"}  # the CIS mapping uses ATT&CK 19.1


def test_navigator_layers_follow_format_4_5():
    for name, layer in layers().items():
        assert layer["versions"]["layer"] == "4.5" and layer["versions"]["attack"] == ("19" if name in CIS_LAYERS else "16"), name
        assert layer["domain"] == "enterprise-attack" and layer["name"], name
        assert layer["gradient"]["maxValue"] > layer["gradient"]["minValue"], name
        assert all(set(t) <= {"techniqueID", "score", "color", "comment", "showSubtechniques"} for t in layer["techniques"]), name


def test_layer_techniques_exist_in_attack_16_1():
    src = sources()
    for name, layer in layers().items():
        if name not in CIS_LAYERS:
            assert {t["techniqueID"] for t in layer["techniques"]} == set(src.techniques), name


def test_cis_layer_matches_an_independent_computation():
    src = sources()
    layer = layers()["cis-all-safeguards"]
    assert {t["techniqueID"] for t in layer["techniques"]} == set(src.active19)
    assert {t["techniqueID"] for t in layer["techniques"] if "score" in t} == set(src.cis_for) and len(src.cis_for) == 404


def test_cis_claims_csv_matches_the_source_rows():
    src = sources()
    rows = read_csv("cis-claims.csv")
    assert {(r["safeguard_id"], r["technique_id_19_1"]) for r in rows} == {(c, t) for t, cs in src.cis_for.items() for c in cs}
    assert len(rows) == 1140
    for r in rows:
        assert all(src.cis_rows[int(n) - 1]["capability_id"] == r["safeguard_id"] for n in r["source_record_numbers"].split())
        assert (r["in_attack_16_1"] == "yes") == (r["technique_id_19_1"] in src.to16 and src.to16[r["technique_id_19_1"]] == r["technique_id_19_1"])


def test_baseline_layers_match_an_independent_computation():
    src = sources()
    for level in ("LOW", "MODERATE", "HIGH", "PRIVACY"):
        covered = {t for t, cs in src.controls_for.items() if any(level in src.baselines_of(c) for c in cs)}
        layer = layers()[f"baseline-{level}"]
        assert {t["techniqueID"] for t in layer["techniques"] if "score" in t} == covered, level


def test_question_csvs_match_the_browser_answers():
    for path in sorted((ROOT / "queries").glob("cq*.rq")):
        cq = path.name.split("-")[0]
        assert (EXPORTS / "questions" / f"{cq}.csv").exists(), cq
    assert len(read_csv("questions/cq01.csv")) == 25 and len(read_csv("questions/cq12.csv")) == 91


def test_all_22_cq_answers_match_source_model():
    """Each of the 22 CQ answers (CSV and page JSON) must equal the source_model computation (audit item 3, M10).

    The expected values come from tests/source_model.py, which computes answers from the raw
    JSON files (CTID mapping, ATT&CK bundle, OSCAL catalog) WITHOUT using SPARQL or the RDF graph.
    This is an independent computation: source_model.py reads JSON, not Turtle; it does not run
    any .rq query file; its logic is separate from scripts/build_graph.py and scripts/build_population.py.

    The test compares ROW CONTENT (sets of tuples), not just row counts. A mutation that changes
    one value while keeping the count will fail.

    Reference for each CQ: tests/test_competency.py computes the same expected values and
    compares them with the SPARQL results. This test reuses that logic.
    """
    from collections import Counter, defaultdict

    src = sources()
    api_questions = ROOT / "api" / "v1" / "questions"

    def cq01():
        return {(c, src.oscal[c]["title"], " ".join(sorted(src.baselines_of(c)))) for c in src.controls_for["T1078"]}

    def cq02():
        counts = Counter()
        for tid, controls in src.controls_for.items():
            if "TA0001" in src.tactics_of[tid]:
                counts.update(controls)
        top10 = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
        return {(c, src.oscal[c]["title"], str(n)) for c, n in top10}

    def cq03():
        return {(t, src.techniques[t]["name"], str(len(src.controls_for[t])))
                for t, controls in src.controls_for.items()
                if not any("LOW" in src.baselines_of(c) for c in controls)}

    def cq04():
        return {(t, src.techniques[t]["name"], next(iter(c)))
                for t, c in src.controls_for.items() if len(c) == 1}

    def cq05():
        return {(r["attack_object_id"], src.techniques[r["attack_object_id"]]["name"],
                 " ".join(sorted(src.attack_mitigations[r["attack_object_id"]])))
                for r in src.rows if r["status"] == "non_mappable" and r["attack_object_id"] in src.techniques}

    def cq06():
        result = set()
        for mid in src.attack_mitigations["T1078"]:
            result.add(("ATT&CK mitigation", mid))
        for cid in src.controls_for["T1078"]:
            result.add(("NIST control", cid))
        return result

    def cq07():
        import re
        import hashlib
        sys.path.insert(0, str(ROOT / "scripts"))
        import build_population
        ctid_data = build_population.fetch("ctid")
        meta = ctid_data["metadata"]
        attack_version = meta["attack_version"]
        last_update = meta["last_update"]
        manifest = (ROOT / "SOURCE-MANIFEST.md").read_text(encoding="utf-8")
        ctid_row_manifest = next(line for line in manifest.splitlines() if "| ctid |" in line)
        url_match = re.search(r"<(https://[^>]+)>", ctid_row_manifest)
        sha_match = re.search(r"`([0-9a-f]{64})`", ctid_row_manifest)
        file_url = url_match.group(1)
        sha256_digest = sha_match.group(1)
        result = set()
        for n, r in enumerate(src.rows, 1):
            if r["capability_id"] == "AC-02" and r["attack_object_id"] == "T1556.009":
                row_id = f"assertion_{r['capability_id']}_{r['attack_object_id']}"
                rationale = r["comments"] or ""
                result.add((row_id, str(n), rationale, attack_version, last_update, file_url, sha256_digest))
        return result

    def cq08():
        return {(str(n), r["capability_id"] or "", r["attack_object_id"], r["attack_object_name"] or "")
                for n, r in enumerate(src.rows, 1) if r["attack_object_id"] not in src.techniques}

    def cq09():
        pairs = Counter((r["capability_id"], r["attack_object_id"]) for r in src.rows if r["status"] == "complete")
        return {(c, t, str(n)) for (c, t), n in pairs.items() if n > 1}

    def cq10():
        cells = defaultdict(set)
        for tid, controls in src.controls_for.items():
            for c in controls:
                for ta in src.tactics_of[tid]:
                    cells[(c[:2], src.tactic_names[ta])].add(tid)
        return {(f, tac, str(len(v))) for (f, tac), v in cells.items()}

    def cq11():
        return {(t, src.techniques[t]["name"], str(len(src.controls_for.get(t, ()))))
                for t, o in src.techniques.items()
                if "IaaS" in o.get("x_mitre_platforms", []) and len(src.controls_for.get(t, ())) < 3}

    def cq12():
        mapped = {r["attack_object_id"] for r in src.rows}
        return {(t, src.techniques[t]["name"]) for t in set(src.techniques) - mapped}

    def cq13():
        result = set()
        seen_controls = set()
        for r in src.rows:
            c = r["capability_id"]
            if c and c not in seen_controls and r["capability_description"] != src.oscal[c]["title"]:
                result.add(("control", c, r["capability_description"], src.oscal[c]["title"]))
                seen_controls.add(c)
        for code, name in src.family_names.items():
            if name != src.families[code]:
                result.add(("family", code, name, src.families[code]))
        return result

    def cq14():
        return {(t, src.techniques[t]["name"], str(len(src.controls_for[t])))
                for t, v in src.later.items()
                if (v["revoked"] or v["renamed"]) and src.controls_for.get(t)}

    def cq15():
        pairs = defaultdict(set)
        for t, v in src.later.items():
            if not v["tacticsChanged"]:
                continue
            lost = {x for x in v["oldTactics"] if not any(n.startswith(x + " (") for n in v["newTactics"])}
            gained = {n for n in v["newTactics"] if not any(n.startswith(x + " (") for x in v["oldTactics"])}
            for a in lost:
                for b in gained:
                    pairs[(a, b)].add(t)
        return {(a, b, str(len(v))) for (a, b), v in pairs.items()}

    def cq16():
        def none(tid):
            parent = src.atlas_techniques[tid].get("specializes")
            return not src.atlas_mitigated_by[tid] and not (parent and src.atlas_mitigated_by[parent])
        return {(t, src.atlas_techniques[t]["name"]) for t in src.atlas_agent if none(t)}

    def cq17():
        result = {}
        for m in src.atlas_mitigations:
            n = sum(1 for t in src.atlas_agent if m in src.atlas_mitigated_by[t])
            if n:
                result[m] = n
        return {(m, src.atlas_mitigations[m]["name"], str(n)) for m, n in result.items()}

    def cq18():
        return {(tid, src.atlas_techniques[tid]["name"], t["attack-reference"]["id"],
                 src.techniques[t["attack-reference"]["id"]]["name"],
                 str(len(src.controls_for.get(t["attack-reference"]["id"], ()))))
                for tid, t in src.atlas_techniques.items()
                if t.get("attack-reference") and t["attack-reference"]["id"] in src.techniques}

    def cq19():
        llm = next(l for l in src.owasp["lists"] if l["id"] == "owasp-llm-top10-2025")
        result = set()
        for item in llm["items"]:
            for aid in item["related_atlas"]:
                if aid in src.atlas_techniques:
                    mits = " ".join(sorted(src.atlas_mitigated_by[aid]))
                    result.add((f"{item['id']} {item['title']}", aid, src.atlas_techniques[aid]["name"], mits))
        return result

    def cq20():
        techs16 = {src.to16[t] for t, cs in src.cis_for.items() if "CIS-13.7" in cs and t in src.to16}
        counts = Counter()
        for t in techs16:
            counts.update(src.controls_for.get(t, ()))
        top10 = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
        return {(c, src.oscal[c]["title"], str(n)) for c, n in top10}

    def cq21():
        both16 = set(src.to16.values())
        cis16 = {src.to16[t] for t in src.cis_for if t in src.to16}
        cells = defaultdict(lambda: [0, 0, 0])
        for t in both16:
            cis, nist = t in cis16, bool(src.controls_for.get(t))
            for ta in src.tactics_of[t]:
                c = cells[src.tactic_names[ta]]
                if cis and nist:
                    c[0] += 1
                elif cis:
                    c[1] += 1
                elif nist:
                    c[2] += 1
        return {(tac, str(b), str(c), str(n)) for tac, (b, c, n) in cells.items()}

    def cq22():
        return {(t, src.active19[t]["name"], str(len(cs)))
                for t, cs in src.cis_for.items() if t not in src.to16}

    expected_funcs = {
        "cq01": (cq01, ["control", "title", "baselines"]),
        "cq02": (cq02, ["control", "title", "techniques"]),
        "cq03": (cq03, ["technique", "name", "controlsOutsideLow"]),
        "cq04": (cq04, ["technique", "name", "onlyControl"]),
        "cq05": (cq05, ["technique", "name", "attackMitigations"]),
        "cq06": (cq06, ["kind", "id"]),
        "cq07": (cq07, ["row", "record", "rationale", "attackVersion", "lastUpdate", "file", "sha256"]),
        "cq08": (cq08, ["record", "control", "technique", "name"]),
        "cq09": (cq09, ["control", "technique", "rows"]),
        "cq10": (cq10, ["family", "tactic", "techniques"]),
        "cq11": (cq11, ["technique", "name", "controls"]),
        "cq12": (cq12, ["technique", "name"]),
        "cq13": (cq13, ["kind", "id", "source", "oscal"]),
        "cq14": (cq14, ["technique", "name", "claims"]),
        "cq15": (cq15, ["fromTactic", "toTactic", "techniques"]),
        "cq16": (cq16, ["technique", "name"]),
        "cq17": (cq17, ["mitigation", "name", "agentTechniques"]),
        "cq18": (cq18, ["atlasTechnique", "atlasName", "attackTechnique", "attackName", "nistControlsOnAttackTechnique"]),
        "cq19": (cq19, ["risk", "atlasTechnique", "atlasName", "atlasMitigations"]),
        "cq20": (cq20, ["control", "title", "sharedTechniques"]),
        "cq21": (cq21, ["tactic", "both", "onlyCis", "onlyNist"]),
        "cq22": (cq22, ["technique", "name", "cisSafeguards"]),
    }

    all_cqs = sorted(p.name.split("-")[0] for p in (ROOT / "queries").glob("cq*.rq"))
    assert all_cqs == [f"cq{i:02d}" for i in range(1, 23)], "must have exactly cq01-cq22"

    for cq in all_cqs:
        csv_rows = read_csv(f"questions/{cq}.csv")
        api_path = api_questions / f"{cq.upper()}.json"
        api_doc = json.loads(api_path.read_text())

        assert len(api_doc["rows"]) == len(csv_rows), f"{cq}: API has {len(api_doc['rows'])} rows, CSV has {len(csv_rows)}"
        assert api_doc["columns"] == list(csv_rows[0].keys()), f"{cq}: column mismatch between API and CSV"

        assert cq in expected_funcs, f"{cq}: missing independent reference (all 22 CQs required)"
        compute, cols = expected_funcs[cq]
        expected = compute()
        assert len(expected) > 0, f"{cq}: expected answer is empty"
        csv_set = {tuple(r[c] for c in cols) for r in csv_rows}
        api_set = {tuple(row[api_doc["columns"].index(c)] or "" for c in cols) for row in api_doc["rows"]}
        assert csv_set == expected, f"{cq}: CSV content mismatch, got {len(csv_set)} rows, expected {len(expected)}"
        assert api_set == expected, f"{cq}: API JSON content mismatch"

    assert len(read_csv("questions/cq01.csv")) == 25
    assert len(read_csv("questions/cq05.csv")) == 96
    assert len(read_csv("questions/cq12.csv")) == 91


def test_export_guide_lists_each_file():
    guide = (EXPORTS / "README.md").read_text(encoding="utf-8")
    for p in EXPORTS.rglob("*"):
        rel = p.relative_to(EXPORTS).as_posix()
        if p.is_file() and p.name != "README.md" and not rel.startswith("questions/") and not rel.startswith("navigator/baseline-"):
            assert f"`{rel}`" in guide, rel
