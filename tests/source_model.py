"""An independent reading of the pinned source files, with no RDF involved.

The competency tests compare each SPARQL answer over the graph with the same answer computed here from the raw
JSON. Agreement between the two paths is the acceptance criterion for a competency question.
"""

from __future__ import annotations

import json
import re
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
        # The later ATT&CK release (20.1), matched by STIX id (independent of the build's reconcile()).
        later = build_population.fetch("attack_latest")["objects"]
        later_by_stix = {o["id"]: o for o in later if o["type"] == "attack-pattern"}
        later_tactics = {o["x_mitre_shortname"]: f"{o['name']} ({_mitre_id(o)})" for o in later if o["type"] == "x-mitre-tactic"}
        revoked_by = defaultdict(list)
        for r in later:
            if r["type"] == "relationship" and r["relationship_type"] == "revoked-by" and r["target_ref"] in later_by_stix:
                revoked_by[r["source_ref"]].append(_mitre_id(later_by_stix[r["target_ref"]]))
        phases = lambda o: {p["phase_name"] for p in o.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"}  # noqa: E731
        self.later = {}
        for tid, o in self.techniques.items():
            n = later_by_stix[o["id"]]
            self.later[tid] = {
                "revoked": bool(n.get("revoked")),
                "replacement": revoked_by.get(o["id"], []),
                "renamed": not n.get("revoked") and n["name"] != o["name"],
                "laterName": n["name"],
                "oldTactics": {self.tactic_names[tactics[x]] for x in phases(o)},
                "newTactics": {later_tactics[x] for x in phases(n)} if not n.get("revoked") else set(),
                "tacticsChanged": not n.get("revoked") and phases(n) != phases(o),
            }
        # Rule R1: claims exist for distinct pairs whose technique is active in ATT&CK Enterprise.
        self.controls_for = defaultdict(set)
        for r in self.rows:
            if r["status"] == "complete" and r["attack_object_id"] in self.techniques:
                self.controls_for[r["attack_object_id"]].add(r["capability_id"])

        # MITRE ATLAS and the curated OWASP extract, read directly.
        # ATLAS format 6, read here without the build's converter: techniques, mitigations and relationships keyed by ID.
        atlas = build_population.fetch("atlas")
        self.atlas_version = atlas["collection"]["version"]
        self.atlas_techniques = {tid: dict(t) for tid, t in atlas["techniques"].items()}
        self.atlas_mitigations = dict(atlas["mitigations"])
        self.atlas_tactics = dict(atlas["tactics"])
        self.atlas_mitigated_by = defaultdict(set)
        for groups in atlas["relationships"].values():
            for r in groups.get("specializes", []):
                self.atlas_techniques[r["source"]]["specializes"] = r["target"]
            for r in groups.get("achieves", []):
                self.atlas_techniques[r["source"]].setdefault("tactics", []).append(r["target"])
            for r in groups.get("mitigates", []):
                self.atlas_mitigated_by[r["target"]].add(r["source"])

        def agent(tid):
            t = self.atlas_techniques[tid]
            return bool(re.search(r"AI Agent|Agentic", t["name"])) or ("specializes" in t and agent(t["specializes"]))
        self.atlas_agent = {tid for tid in self.atlas_techniques if agent(tid)}
        self.owasp = json.loads((ROOT / "data" / "sources" / "owasp-genai.json").read_text())

        # CIS 8.1.2 on ATT&CK 19.1, matched to 16.1 by STIX id.
        objs19 = build_population.fetch("attack_19_1")["objects"]
        ap19 = {o["id"]: o for o in objs19 if o["type"] == "attack-pattern"}
        self.active19 = {_mitre_id(o): o for o in ap19.values() if _active(o) and "enterprise-attack" in o.get("x_mitre_domains", [])}
        stix16 = {o["id"]: tid for tid, o in self.techniques.items()}
        self.to16 = {tid: stix16[o["id"]] for tid, o in self.active19.items() if o["id"] in stix16}
        self.replaced_by19 = defaultdict(set)
        for r in objs19:
            if r["type"] == "relationship" and r["relationship_type"] == "revoked-by" and r["source_ref"] in stix16 and r["target_ref"] in ap19:
                self.replaced_by19[_mitre_id(ap19[r["target_ref"]])].add(stix16[r["source_ref"]])
        self.cis_rows = build_population.fetch("cis")["mapping_objects"]
        self.cis_for = defaultdict(set)
        for r in self.cis_rows:
            if r["status"] == "complete":
                self.cis_for[r["attack_object_id"]].add(r["capability_id"])

    def baselines_of(self, control_id):
        oid = self.oscal[control_id]["id"]
        return {name for name, ids in self.baselines.items() if oid in ids}


@lru_cache(maxsize=1)
def sources() -> Sources:
    return Sources()
