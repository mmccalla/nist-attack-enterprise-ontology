"""Keeps docs/security.md true: every technique and control it names exists in the data, and the project's
own gap analysis of its threat techniques gives the result the document states."""

import csv
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = (ROOT / "docs" / "security.md").read_text(encoding="utf-8")


def rows(name):
    with open(ROOT / "exports" / name, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def block():
    text = re.search(r"```text\n(.*?)```", DOC, re.S).group(1)
    return {k.strip(): v.split() for k, v in (line.split(":", 1) for line in text.strip().splitlines())}


def test_named_techniques_and_controls_exist():
    techniques = {r["technique_id"] for r in rows("techniques.csv")}
    controls = {r["control_id"] for r in rows("controls.csv")}
    for t in set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", DOC)):
        assert t in techniques, t
    for c in set(re.findall(r"\b[A-Z]{2}-\d{2}\b", DOC)):
        assert c in controls, c


def test_self_assessment_matches_the_shared_gap_logic():
    b = block()
    threat = b["threat techniques"]
    mit = {}
    for r in rows("claims.csv"):
        if r["technique_id"] in threat:
            mit.setdefault(r["control_id"], []).append(r["technique_id"])
    model = {"techniques": [{"id": t, "name": t, "tactics": []} for t in threat],
             "controls": {c: {"title": "", "baselines": []} for c in mit}, "mitigates": mit}
    js = ("const C=require(process.argv[1]);let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{"
          "const {model,sel}=JSON.parse(s);process.stdout.write(JSON.stringify(C.counts(C.coverage(model,new Set(sel)))));});")
    out = subprocess.run(["node", "-e", js, str(ROOT / "lib" / "coverage.cjs")], input=json.dumps({"model": model, "sel": b["implemented"]}),
                         capture_output=True, text=True, check=True)
    assert json.loads(out.stdout) == {"covered": len(threat), "gap": 0, "none": 0}
    assert f"all {len(threat)} techniques are \"covered\"" in DOC.replace("\n", " ")
    assert not set(b["implemented"]) & set(b["partial"]), "a control cannot be both implemented and partial"
