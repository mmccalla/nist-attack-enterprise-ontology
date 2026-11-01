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

# Status colours (good, warning, neutral), the same as the browser's gap analysis. Covered techniques use a
# one-hue green gradient by number of controls; every cell also carries a comment, so colour is never alone.
GRADIENT = ["#d9f2d9", "#0ca30c"]
GAP = "#fab219"
SILENT = "#d5d9df"


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


def coverage(m: dict, selected: set[str]) -> dict:
    by = defaultdict(set)
    for cid, tids in m["mitigates"].items():
        for tid in tids:
            by[tid].add(cid)
    out = {}
    for tid in m["techniques"]:
        covering = sorted(by[tid] & selected)
        if covering:
            out[tid] = ("covered", covering)
        elif by[tid]:
            out[tid] = ("gap", sorted(by[tid]))
        else:
            out[tid] = ("silent", [])
    return out


def layer(m: dict, name: str, description: str, selected: set[str]) -> dict:
    cov = coverage(m, selected)
    techniques = []
    for tid in sorted(cov, key=lambda t: [int(x) for x in re.findall(r"\d+", t)]):
        status, controls = cov[tid]
        entry = {"techniqueID": tid}
        if status == "covered":
            entry["score"] = len(controls)
            entry["comment"] = "Mitigated by " + ", ".join(controls)
        elif status == "gap":
            entry["color"] = GAP
            entry["comment"] = "Not covered. Controls that would mitigate it: " + ", ".join(controls)
        else:
            entry["color"] = SILENT
            entry["comment"] = "The mapping has no mitigating control for this technique"
        if "." not in tid and any(t.startswith(tid + ".") for t in cov):
            entry["showSubtechniques"] = False
        techniques.append(entry)
    top = max([len(c) for s, c in cov.values() if s == "covered"] or [1])
    return {
        "name": name,
        "versions": {"attack": ATTACK_VERSION, "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description,
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True, "expandedSubtechniques": "none"},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": GRADIENT, "minValue": 1, "maxValue": max(top, 2)},
        "legendItems": [
            {"label": "Covered (darker = more controls)", "color": GRADIENT[1]},
            {"label": "Gap: a control exists in the mapping but is not selected", "color": GAP},
            {"label": "No mitigating control in the mapping", "color": SILENT},
        ],
        "links": [{"label": "NIST 800-53 to ATT&CK ontology", "url": SITE}],
        "metadata": [
            {"name": "Source", "value": "CTID NIST 800-53 Rev. 5 to ATT&CK 16.1 Enterprise, claims under rule R1"},
            {"name": "Controls selected", "value": str(len(selected))},
        ],
    }


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
    files["navigator/all-controls.json"] = json.dumps(
        layer(m, "NIST 800-53: all mapped controls", "Techniques mitigated by any NIST 800-53 Rev. 5 control in the CTID mapping. Score is the number of controls.", set(m["controls"])),
        indent=2,
    ) + "\n"
    for level in BASELINES:
        selected = {cid for cid, c in m["controls"].items() if level in c["baselines"]}
        files[f"navigator/baseline-{level}.json"] = json.dumps(
            layer(m, f"NIST 800-53B {level} baseline coverage", f"ATT&CK Enterprise techniques mitigated by the mapped controls in the SP 800-53B {level} baseline. Orange: a mapped control outside the baseline would mitigate it. Grey: no mapped control.", selected),
            indent=2,
        ) + "\n"

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
