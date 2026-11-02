"""Build exports/: CSV tables and ATT&CK Navigator layers for people who want the data in their own tools.

Usage:
    python scripts/build_exports.py          write exports/
    python scripts/build_exports.py --check  fail if exports/ differs from a fresh build
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from rdflib import Graph, Literal
from rdflib.namespace import RDF, SKOS

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from gates import DATA, ONT  # noqa: E402

OUT = ROOT / "exports"
SITE = "https://mmccalla.github.io/nist-attack-enterprise-ontology/"
ATTACK_VERSION = "16"
BASELINES = ["LOW", "MODERATE", "HIGH", "PRIVACY"]

def load() -> Graph:
    g = Graph()
    g.parse(ROOT / "ontology" / "core.ttl")
    g.parse(ROOT / "data" / "population.ttl")
    return g


def model(g: Graph) -> dict:
    """Plain dictionaries the exports and the browser logic both work from."""
    techniques = {}
    for t in g.subjects(ONT.inAttackEnterprise, Literal(True)):
        tid = str(g.value(t, ONT.techniqueId))
        techniques[tid] = {
            "name": str(g.value(t, ONT.techniqueName)),
            "tactics": sorted(str(g.value(ta, ONT.tacticShortName)) for ta in g.objects(t, ONT.inTactic)),
            "nonMappable": any((r, RDF.type, ONT.NonMappableAssertion) in g for r in g.subjects(ONT.assertsTechnique, t)),
            "hasRow": (None, ONT.assertsTechnique, t) in g,
        }
    controls, mitigates = {}, defaultdict(set)
    for c in g.subjects(RDF.type, ONT.SecurityControl):
        cid = str(g.value(c, ONT.controlId))
        controls[cid] = {
            "title": str(g.value(c, ONT.controlTitle)),
            "oscal": str(g.value(c, ONT.oscalControlId)),
            "baselines": sorted(str(g.value(b, ONT.baselineLevel)) for b in g.objects(c, ONT.inBaseline)),
        }
        for t in g.objects(c, ONT.mitigatesTechnique):
            mitigates[cid].add(str(g.value(t, ONT.techniqueId)))
    rows = defaultdict(list)
    for claim in g.subjects(RDF.type, ONT.MitigationClaim):
        cid = str(g.value(g.value(claim, ONT.claimSubjectControl), ONT.controlId))
        tid = str(g.value(g.value(claim, ONT.claimObjectTechnique), ONT.techniqueId))
        rows[(cid, tid)] = sorted(int(g.value(a, ONT.sourceRecordNumber)) for a in g.objects(claim, ONT.supportedByAssertion))
    return {"techniques": techniques, "controls": controls, "mitigates": mitigates, "rows": rows}


def layers(m: dict, specs: list[dict]) -> dict:
    """Navigator layers from the shared logic in lib/coverage.cjs, so the browser and the exports agree."""
    model = {
        "techniques": [{"id": tid, "name": t["name"], "tactics": t["tactics"]} for tid, t in m["techniques"].items()],
        "controls": {cid: {"title": c["title"], "baselines": c["baselines"]} for cid, c in m["controls"].items()},
        "mitigates": {cid: sorted(m["mitigates"][cid]) for cid in m["controls"]},
    }
    result = subprocess.run(
        ["node", str(ROOT / "scripts" / "build_layers.cjs")],
        input=json.dumps({"model": model, "layers": specs}), capture_output=True, text=True, check=True,
    )
    return json.loads(result.stdout)


def write_csv(rows: list[list], header: list[str]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue()


def build() -> dict[str, str]:
    g = load()
    m = model(g)
    files: dict[str, str] = {}
    by = defaultdict(set)
    for cid, tids in m["mitigates"].items():
        for tid in tids:
            by[tid].add(cid)
    tkey = lambda t: [int(x) for x in re.findall(r"\d+", t)]  # noqa: E731

    files["claims.csv"] = write_csv(
        [
            [cid, m["controls"][cid]["title"], tid, m["techniques"][tid]["name"], " ".join(m["techniques"][tid]["tactics"]),
             " ".join(m["controls"][cid]["baselines"]), " ".join(map(str, m["rows"][(cid, tid)]))]
            for cid, tid in sorted(m["rows"], key=lambda k: (k[0], tkey(k[1])))
        ],
        ["control_id", "control_title", "technique_id", "technique_name", "tactics", "control_baselines", "source_record_numbers"],
    )
    files["controls.csv"] = write_csv(
        [[cid, c["title"], c["oscal"], " ".join(c["baselines"]), len(m["mitigates"][cid])] for cid, c in sorted(m["controls"].items())],
        ["control_id", "control_title", "oscal_id", "baselines", "techniques_mitigated"],
    )
    files["techniques.csv"] = write_csv(
        [
            [tid, t["name"], " ".join(t["tactics"]), len(by[tid]), " ".join(sorted(by[tid])),
             "claims" if by[tid] else ("non_mappable" if t["nonMappable"] else ("no_row" if not t["hasRow"] else "row_without_claim"))]
            for tid, t in sorted(m["techniques"].items(), key=lambda kv: tkey(kv[0]))
        ],
        ["technique_id", "technique_name", "tactics", "control_count", "controls", "mapping_status"],
    )
    later_rows = []
    for record in g.subjects(RDF.type, ONT.LaterVersionRecord):
        t = g.value(record, ONT.describesEntity)
        tid = str(g.value(t, ONT.techniqueId))
        later_rows.append([
            tid, str(g.value(t, ONT.techniqueName)),
            " ".join(sorted(str(x) for x in g.objects(record, ONT.versionStatus))),
            " ".join(sorted(str(x) for x in g.objects(record, ONT.laterId))),
            " | ".join(sorted(str(x) for x in g.objects(record, ONT.laterName))),
            " | ".join(sorted(str(x) for x in g.objects(record, ONT.laterTactic))),
            len(by[tid]),
        ])
    files["attack-16.1-to-20.0.csv"] = write_csv(
        sorted(later_rows, key=lambda r: tkey(r[0])),
        ["technique_id", "technique_name", "change_in_20_0", "replacement_ids", "name_in_20_0", "tactics_in_20_0", "claims"],
    )
    specs = [{"file": "navigator/all-controls.json", "name": "NIST 800-53: all mapped controls",
              "description": "Techniques mitigated by any NIST 800-53 Rev. 5 control in the CTID mapping. Score is the number of controls.",
              "selected": sorted(m["controls"])}]
    for level in BASELINES:
        specs.append({"file": f"navigator/baseline-{level}.json", "name": f"NIST 800-53B {level} baseline coverage",
                      "description": f"ATT&CK Enterprise techniques mitigated by the mapped controls in the SP 800-53B {level} baseline. Amber: a mapped control outside the baseline would mitigate it. Grey: no mapped control.",
                      "selected": sorted(cid for cid, c in m["controls"].items() if level in c["baselines"])})
    for name, layer in layers(m, specs).items():
        files[name] = json.dumps(layer, indent=2) + "\n"

    # Competency question answers, as computed for the browser.
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_graph  # noqa: PLC0415

    for q in build_graph.build_questions(build_graph.load()):
        files[f"questions/{q['id'].lower()}.csv"] = write_csv([[v if v is not None else "" for v in r] for r in q["rows"]], q["columns"])
        if q["total"] > len(q["rows"]):
            raise SystemExit(f"{q['id']}: browser rows are capped; export needs the full answer")
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    files = build()
    if args.check:
        stale = [name for name, text in files.items() if not (OUT / name).exists() or (OUT / name).read_text(encoding="utf-8") != text]
        extra = [p.relative_to(OUT).as_posix() for p in OUT.rglob("*") if p.is_file() and p.name != "README.md" and p.relative_to(OUT).as_posix() not in files]
        if stale or extra:
            print(f"exports out of date: {stale + extra}; run python scripts/build_exports.py", file=sys.stderr)
            return 1
        print(f"exports up to date ({len(files)} files)")
        return 0
    for name, text in files.items():
        path = OUT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    print(f"wrote {len(files)} files to exports/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
