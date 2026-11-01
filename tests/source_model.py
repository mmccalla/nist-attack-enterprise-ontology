"""An independent reading of the pinned source files, with no RDF involved.

The competency tests compare each SPARQL answer over the graph with the same answer computed here from the raw
JSON. Agreement between the two paths is the acceptance criterion for a competency question.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import build_population  # noqa: E402  - reuses only fetch() and its digest check


def _mitre_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _active(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


class Sources:
    def __init__(self):
        cache = ROOT / ".cache"
        if not (cache / "ctid.json").exists():
            raise RuntimeError("source files missing: run python scripts/build_population.py first")
        self.rows = build_population.fetch("ctid")["mapping_objects"]
        objects = build_population.fetch("attack")["objects"]
        catalog = build_population.fetch("catalog")["catalog"]
        self.baselines = {
            name: {i for imp in build_population.fetch(name)["profile"]["imports"] for inc in imp.get("include-controls", []) for i in inc.get("with-ids", [])}
            for name in build_population.BASELINES
        }
        self.techniques = {
            _mitre_id(o): o for o in objects
            if o["type"] == "attack-pattern" and _active(o) and "enterprise-attack" in o.get("x_mitre_domains", [])
        }
        tactics = {o["x_mitre_shortname"]: _mitre_id(o) for o in objects if o["type"] == "x-mitre-tactic"}
        self.tactic_names = {_mitre_id(o): o["name"] for o in objects if o["type"] == "x-mitre-tactic"}
        self.family_names = build_population.fetch("ctid")["metadata"]["capability_groups"]
        self.tactics_of = {
            tid: {tactics[p["phase_name"]] for p in o.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"}
            for tid, o in self.techniques.items()
        }
        by_stix = {o["id"]: tid for tid, o in self.techniques.items()}
        mitigations = {o["id"]: _mitre_id(o) for o in objects if o["type"] == "course-of-action" and _active(o) and (_mitre_id(o) or "").startswith("M")}
        self.attack_mitigations = defaultdict(set)
        for r in objects:
            if r["type"] == "relationship" and _active(r) and r["relationship_type"] == "mitigates" and r["source_ref"] in mitigations and r["target_ref"] in by_stix:
                self.attack_mitigations[by_stix[r["target_ref"]]].add(mitigations[r["source_ref"]])
        self.oscal = {}
        self.families = {}
        for group in catalog["groups"]:
            self.families[group["id"].upper()] = group["title"]
            for control in group.get("controls", []):
                for prop in control.get("props", []):
                    if prop["name"] == "label" and prop.get("class") == "zero-padded":
                        self.oscal[prop["value"]] = control
        # Rule R1: claims exist for distinct pairs whose technique is active in ATT&CK Enterprise.
        self.controls_for = defaultdict(set)
        for r in self.rows:
            if r["status"] == "complete" and r["attack_object_id"] in self.techniques:
                self.controls_for[r["attack_object_id"]].add(r["capability_id"])

    def baselines_of(self, control_id):
        oid = self.oscal[control_id]["id"]
        return {name for name, ids in self.baselines.items() if oid in ids}


@lru_cache(maxsize=1)
def sources() -> Sources:
    return Sources()
