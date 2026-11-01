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


def test_navigator_layers_follow_format_4_5():
    for name, layer in layers().items():
        assert layer["versions"]["layer"] == "4.5" and layer["versions"]["attack"] == "16", name
        assert layer["domain"] == "enterprise-attack" and layer["name"], name
        assert layer["gradient"]["maxValue"] > layer["gradient"]["minValue"], name
        assert all(set(t) <= {"techniqueID", "score", "color", "comment", "showSubtechniques"} for t in layer["techniques"]), name


def test_layer_techniques_exist_in_attack_16_1():
    src = sources()
    for name, layer in layers().items():
        assert {t["techniqueID"] for t in layer["techniques"]} == set(src.techniques), name


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
