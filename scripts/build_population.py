"""Build data/population.ttl and data/source-checks.json from pinned authoritative sources.

Sources are downloaded once into .cache/ and checked against the SHA-256 digests below.
A digest mismatch stops the build: the population must come from exactly these files.

Usage:
    python scripts/build_population.py          write the population and the source-check report
    python scripts/build_population.py --check  fail if either file differs from a fresh build
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

from rdflib import XSD, Graph, Literal, Namespace, URIRef
from rdflib.namespace import DCTERMS, OWL, PROV, RDF, RDFS, SKOS

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache"
POPULATION = ROOT / "data" / "population.ttl"
OWASP = ROOT / "data" / "sources" / "owasp-genai.json"
CHECKS = ROOT / "data" / "source-checks.json"

ONT = Namespace("https://w3id.org/example/nist-attack-mapping/ontology/1.0#")
DATA = Namespace("https://w3id.org/example/nist-attack-mapping/data/1.0#")

GH = "https://raw.githubusercontent.com"
OSCAL = f"{GH}/usnistgov/oscal-content/5006f18c8047643eaa70e35dd0d20a58bcc41856/nist.gov/SP800-53/rev5/json"
SOURCES = {
    "ctid": (
        f"{GH}/center-for-threat-informed-defense/mappings-explorer/6bdc3ad33547d5fcb498eede1f07e7db681b00ee/"
        "mappings/nist_800_53/attack-16.1/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-16.1-enterprise.json",
        "355ae97d309c00eb2428e5af07754ff4ca16cfe63928194081d0e883aed929c8",
    ),
    "attack": (
        f"{GH}/mitre-attack/attack-stix-data/7eb3ca57f218e1d4f01afdb3e0cdc3b526556173/enterprise-attack/enterprise-attack-16.1.json",
        "8423d8dac3fc2feb825bb07d26e5f5d905e08a88f6fe4652cc20834cbe982813",
    ),
    "cis": (
        f"{GH}/center-for-threat-informed-defense/mappings-explorer/1b0b81e6fb21eaa3e741fe0f2d281b04eaa04afc/"
        "mappings/cis/attack-19.1/cis-8.1.2/enterprise/cis-8.1.2_attack-19.1-enterprise.json",
        "2a35123701e331954be59ee1ed15ee886a4913cd3bf912dbaf908f6f614dbd9a",
    ),
    "attack_19_1": (
        f"{GH}/mitre-attack/attack-stix-data/6c3719993d0401de199203ecc3f369544d9e091c/enterprise-attack/enterprise-attack-19.1.json",
        "bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3",
    ),
    "attack_latest": (
        f"{GH}/mitre-attack/attack-stix-data/20664a889568dce884a1dac0ec7b12ae3a199f51/enterprise-attack/enterprise-attack-20.0.json",
        "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352",
    ),
    "atlas": (
        f"{GH}/mitre-atlas/atlas-data/da9ebf9b66e6902ad97c267e2a20af0bd996a60f/dist/ATLAS.yaml",
        "c9c23971d0db07e2782423d795a20e78d5c2c9bcdc78fc67e24530657daaec41",
    ),
    "catalog": (
        f"{OSCAL}/NIST_SP-800-53_rev5_catalog.json",
        "64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb",
    ),
    "LOW": (f"{OSCAL}/NIST_SP-800-53_rev5_LOW-baseline_profile.json", "cfd4f5d9a192eb42dc04b745d82f95a85926a2a85a45418034a380a42bda9424"),
    "MODERATE": (f"{OSCAL}/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json", "e3a0f11237cfaac24dfcf1586e07683f17423757fd84208deb33196b12e8f590"),
    "HIGH": (f"{OSCAL}/NIST_SP-800-53_rev5_HIGH-baseline_profile.json", "d2ef340986b9f1ee820ad866a0f964d9a9d1088b24080c74b795ddb0148b9f83"),
    "PRIVACY": (f"{OSCAL}/NIST_SP-800-53_rev5_PRIVACY-baseline_profile.json", "c0e3d54d9f474bc6c33338a8e524bc52ad070f94f9274db7ec48242242fecacc"),
}
BASELINES = ["LOW", "MODERATE", "HIGH", "PRIVACY"]
LATER_ATTACK = "20.0"
MAX_SOURCE_BYTES = 200 * 1024 * 1024  # refuse anything larger than any expected source


def fetch(key: str) -> dict:
    url, digest = SOURCES[key]
    path = CACHE / f"{key}.json"
    if not path.exists():
        if not url.startswith("https://raw.githubusercontent.com/"):
            raise SystemExit(f"{key}: refusing a source outside the pinned host: {url}")
        CACHE.mkdir(exist_ok=True)
        print(f"downloading {key}", file=sys.stderr)
        with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 - pinned https URL
            body = response.read(MAX_SOURCE_BYTES + 1)
        if len(body) > MAX_SOURCE_BYTES:
            raise SystemExit(f"{key}: source is larger than {MAX_SOURCE_BYTES} bytes")
        path.write_bytes(body)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != digest:
        raise SystemExit(f"{key}: SHA-256 {actual} does not match the pinned {digest}; delete .cache/{key}.json")
    if url.endswith(".yaml"):
        import yaml  # noqa: PLC0415

        return yaml.safe_load(path.read_text(encoding="utf-8"))  # safe_load only: no object construction
    return json.loads(path.read_text(encoding="utf-8"))


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_")


def mitre_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def active(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def lit(value, datatype=None) -> Literal:
    return Literal(value, datatype=datatype) if datatype else Literal(value)


def build() -> tuple[Graph, dict]:
    ctid, attack, catalog = fetch("ctid"), fetch("attack"), fetch("catalog")["catalog"]
    attack_later = fetch("attack_latest")
    profiles = {name: fetch(name)["profile"] for name in BASELINES}
    g = Graph()
    g.bind("", ONT)
    g.bind("data", DATA)
    g.bind("skos", SKOS)
    g.bind("dcterms", DCTERMS)
    g.bind("prov", PROV)
    checks: dict = {}

    # Datasets
    meta = ctid["metadata"]
    ds, record = DATA.sourceDataset, DATA.datasetMetadataRecord
    g.add((ds, RDF.type, ONT.CybersecurityMappingDataset))
    g.add((ds, DCTERMS.title, lit("NIST 800-53 Rev.5 to MITRE ATT&CK Enterprise 16.1 source mapping dataset")))
    g.add((ds, DCTERMS.publisher, lit("MITRE Center for Threat-Informed Defense")))
    g.add((ds, DCTERMS.source, URIRef(SOURCES["ctid"][0])))
    g.add((ds, ONT.sha256, lit(SOURCES["ctid"][1])))
    g.add((ds, ONT.hasMetadataRecord, record))
    g.add((record, RDF.type, ONT.DatasetMetadataRecord))
    for prop, key in (
        ("frameworkId", "mapping_framework"),
        ("frameworkVersion", "mapping_framework_version"),
        ("attackVersion", "attack_version"),
        ("technologyDomain", "technology_domain"),
        ("sourceCreationDate", "creation_date"),
        ("sourceLastUpdate", "last_update"),
    ):
        g.add((record, ONT[prop], lit(meta[key])))
    g.add((record, DCTERMS.source, lit(SOURCES["ctid"][0].rsplit("/", 1)[1])))

    def reference_dataset(node, title, key, version):
        g.add((node, RDF.type, ONT.ReferenceDataset))
        g.add((node, DCTERMS.title, lit(title)))
        g.add((node, OWL.versionInfo, lit(version)))
        g.add((node, DCTERMS.source, URIRef(SOURCES[key][0])))
        g.add((node, ONT.sha256, lit(SOURCES[key][1])))

    reference_dataset(DATA.attackEnterpriseStix, "MITRE ATT&CK Enterprise STIX 2.1 bundle", "attack", "16.1")
    reference_dataset(DATA.oscalCatalog, catalog["metadata"]["title"], "catalog", catalog["metadata"]["version"])
    reference_dataset(DATA.attackEnterpriseStixLatest, f"MITRE ATT&CK Enterprise STIX 2.1 bundle {LATER_ATTACK}", "attack_latest", LATER_ATTACK)

    # Catalogues and frameworks
    catalogue = DATA["catalogue_attack-enterprise-16.1"]
    later_catalogue = DATA[f"catalogue_attack-enterprise-{LATER_ATTACK}"]
    for node, version, dataset in ((catalogue, "16.1", DATA.attackEnterpriseStix), (later_catalogue, LATER_ATTACK, DATA.attackEnterpriseStixLatest)):
        g.add((node, RDF.type, ONT.ThreatCatalogue))
        g.add((node, RDFS.label, lit(f"ATT&CK Enterprise {version}")))
        g.add((node, ONT.catalogueVersion, lit(version)))
        g.add((node, ONT.catalogueDomain, lit("enterprise-attack")))
        g.add((node, PROV.wasDerivedFrom, dataset))
    framework = DATA["framework_nist-800-53-rev5"]
    g.add((framework, RDF.type, ONT.ControlFramework))
    g.add((framework, RDFS.label, lit("NIST SP 800-53 Rev. 5")))
    g.add((framework, ONT.catalogueVersion, lit(catalog["metadata"]["version"])))
    g.add((framework, PROV.wasDerivedFrom, DATA.oscalCatalog))
    g.add((ds, ONT.mapsToCatalogue, catalogue))

    # OSCAL: families, controls, baselines
    families, controls_by_label = {}, {}
    for group in catalog["groups"]:
        families[group["id"].upper()] = group["title"]
        for control in group.get("controls", []):
            for prop in control.get("props", []):
                if prop["name"] == "label" and prop.get("class") == "zero-padded":
                    controls_by_label[prop["value"]] = control
    baseline_members = {}
    for name, profile in profiles.items():
        ids = {i for imp in profile["imports"] for inc in imp.get("include-controls", []) for i in inc.get("with-ids", [])}
        baseline_members[name] = ids
        node = DATA[f"baseline_{name}"]
        g.add((node, RDF.type, ONT.ControlBaseline))
        g.add((node, RDFS.label, lit(f"SP 800-53B {name} baseline")))
        g.add((node, ONT.baselineLevel, lit(name)))
        g.add((node, DCTERMS.title, lit(profile["metadata"]["title"])))
        g.add((node, DCTERMS.source, URIRef(SOURCES[name][0])))
        g.add((node, ONT.sha256, lit(SOURCES[name][1])))
        g.add((node, OWL.versionInfo, lit(profile["metadata"]["version"])))
        g.add((node, ONT.inFramework, framework))

    family_mismatch = {}
    for code, name in meta["capability_groups"].items():
        group = ONT[f"capabilityGroup_{code}"]
        g.add((group, ONT.inFramework, framework))
        title = families.get(code)
        if title:
            g.add((group, ONT.oscalFamilyTitle, lit(title)))
            if title != name:
                family_mismatch[code] = {"source": name, "oscal": title}
    checks["familyTitleDifferences"] = family_mismatch

    # ATT&CK: tactics, platforms, techniques, mitigations
    objects = attack["objects"]
    by_stix = {o["id"]: o for o in objects}
    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix")
    tactic_by_short = {}
    for order, ref in enumerate(matrix["tactic_refs"], start=1):
        tactic = by_stix[ref]
        tid = mitre_id(tactic)
        node = DATA[f"tactic_{tid}"]
        tactic_by_short[tactic["x_mitre_shortname"]] = node
        g.add((node, RDF.type, ONT.Tactic))
        g.add((node, SKOS.inScheme, ONT.TacticScheme))
        g.add((node, SKOS.prefLabel, lit(tactic["name"])))
        g.add((node, ONT.tacticId, lit(tid)))
        g.add((node, ONT.tacticShortName, lit(tactic["x_mitre_shortname"])))
        g.add((node, ONT.tacticOrder, lit(order, XSD.integer)))
        g.add((node, ONT.stixId, lit(tactic["id"])))
        g.add((node, PROV.wasDerivedFrom, DATA.attackEnterpriseStix))
        g.add((node, ONT.inCatalogue, catalogue))

    stix_techniques = {}
    for obj in objects:
        if obj["type"] == "attack-pattern" and active(obj) and "enterprise-attack" in obj.get("x_mitre_domains", []):
            stix_techniques[mitre_id(obj)] = obj

    rows = ctid["mapping_objects"]
    ctid_names = {r["attack_object_id"]: r["attack_object_name"] for r in rows}
    technique_ids = sorted(set(stix_techniques) | set(ctid_names))
    platforms = set()
    name_mismatch = {}
    not_in_bundle = []
    for tid in technique_ids:
        node = DATA[f"technique_{tid}"]
        obj = stix_techniques.get(tid)
        g.add((node, RDF.type, ONT.AttackTechnique))
        g.add((node, SKOS.inScheme, ONT.TechniqueScheme))
        g.add((node, ONT.techniqueId, lit(tid)))
        g.add((node, ONT.isSubTechnique, lit("." in tid, XSD.boolean)))
        g.add((node, ONT.inAttackEnterprise, lit(obj is not None, XSD.boolean)))
        name = obj["name"] if obj else ctid_names[tid]
        g.add((node, ONT.techniqueName, lit(name)))
        g.add((node, SKOS.prefLabel, lit(name)))
        if tid in ctid_names and ctid_names[tid] != name:
            g.add((node, ONT.sourceTechniqueName, lit(ctid_names[tid])))
            name_mismatch[tid] = {"source": ctid_names[tid], "attack": name}
        if obj is None:
            not_in_bundle.append(tid)
            continue
        g.add((node, ONT.stixId, lit(obj["id"])))
        g.add((node, PROV.wasDerivedFrom, DATA.attackEnterpriseStix))
        g.add((node, ONT.inCatalogue, catalogue))
        g.add((node, ONT.activeInCatalogue, catalogue))
        for phase in obj.get("kill_chain_phases", []):
            if phase["kill_chain_name"] == "mitre-attack":
                g.add((node, ONT.inTactic, tactic_by_short[phase["phase_name"]]))
        for platform in obj.get("x_mitre_platforms", []):
            platforms.add(platform)
            g.add((node, ONT.targetsPlatform, DATA[f"platform_{slug(platform)}"]))
    for platform in sorted(platforms):
        node = DATA[f"platform_{slug(platform)}"]
        g.add((node, RDF.type, ONT.Platform))
        g.add((node, SKOS.inScheme, ONT.PlatformScheme))
        g.add((node, SKOS.prefLabel, lit(platform)))
    checks["techniqueNameDifferences"] = name_mismatch
    checks["laterVersion"] = reconcile(g, stix_techniques, attack_later, later_catalogue)
    checks["techniquesNotInAttackEnterprise"] = not_in_bundle

    tech_by_stix = {o["id"]: tid for tid, o in stix_techniques.items()}
    mitigations = {}
    for obj in objects:
        if obj["type"] == "course-of-action" and active(obj) and (mitre_id(obj) or "").startswith("M"):
            mid = mitre_id(obj)
            node = DATA[f"mitigation_{mid}"]
            mitigations[obj["id"]] = node
            g.add((node, RDF.type, ONT.AttackMitigation))
            g.add((node, SKOS.prefLabel, lit(obj["name"])))
            g.add((node, ONT.mitigationId, lit(mid)))
            g.add((node, ONT.stixId, lit(obj["id"])))
            g.add((node, PROV.wasDerivedFrom, DATA.attackEnterpriseStix))
            g.add((node, ONT.inCatalogue, catalogue))
    for rel in objects:
        if rel["type"] != "relationship" or not active(rel):
            continue
        source, target = rel["source_ref"], rel["target_ref"]
        if rel["relationship_type"] == "subtechnique-of" and source in tech_by_stix and target in tech_by_stix:
            g.add((DATA[f"technique_{tech_by_stix[source]}"], ONT.subTechniqueOf, DATA[f"technique_{tech_by_stix[target]}"]))
        elif rel["relationship_type"] == "mitigates" and source in mitigations and target in tech_by_stix:
            g.add((mitigations[source], ONT.attackMitigationFor, DATA[f"technique_{tech_by_stix[target]}"]))

    # Controls
    control_ids = sorted({r["capability_id"] for r in rows if r["capability_id"]})
    title_mismatch, unresolved = {}, []
    ctid_titles = {r["capability_id"]: r["capability_description"] for r in rows if r["capability_id"]}
    ctid_groups = {r["capability_id"]: r["capability_group"] for r in rows if r["capability_id"]}
    for cid in control_ids:
        node = DATA[f"control_{cid}"]
        g.add((node, RDF.type, ONT.SecurityControl))
        g.add((node, RDF.type, ONT.Nist80053Control))
        g.add((node, ONT.inFramework, framework))
        g.add((node, ONT.controlId, lit(cid)))
        g.add((node, SKOS.prefLabel, lit(cid)))
        g.add((node, ONT.inCapabilityGroup, ONT[f"capabilityGroup_{ctid_groups[cid]}"]))
        oscal = controls_by_label.get(cid)
        if oscal is None:
            unresolved.append(cid)
            g.add((node, ONT.controlTitle, lit(ctid_titles[cid])))
            continue
        g.add((node, ONT.controlTitle, lit(oscal["title"])))
        g.add((node, ONT.oscalControlId, lit(oscal["id"])))
        g.add((node, PROV.wasDerivedFrom, DATA.oscalCatalog))
        if ctid_titles[cid] != oscal["title"]:
            g.add((node, ONT.sourceControlTitle, lit(ctid_titles[cid])))
            title_mismatch[cid] = {"source": ctid_titles[cid], "oscal": oscal["title"]}
        for name in BASELINES:
            if oscal["id"] in baseline_members[name]:
                g.add((node, ONT.inBaseline, DATA[f"baseline_{name}"]))
    checks["controlTitleDifferences"] = title_mismatch
    checks["controlsNotInOscalCatalog"] = unresolved

    # Source assertions, one per row
    seen = defaultdict(int)
    pairs = defaultdict(list)
    for number, row in enumerate(rows, start=1):
        tid, cid = row["attack_object_id"], row["capability_id"]
        if row["status"] == "complete":
            key = f"{cid}_{tid}"
            seen[key] += 1
            node = DATA[f"assertion_{key}" + (f"_{seen[key]}" if seen[key] > 1 else "")]
            g.add((node, RDF.type, ONT.MitigatesAssertion))
            g.add((node, ONT.assertsControl, DATA[f"control_{cid}"]))
            g.add((node, ONT.assertsCapabilityGroup, ONT[f"capabilityGroup_{row['capability_group']}"]))
            g.add((node, ONT.assertedMappingType, ONT[f"mappingType_{row['mapping_type']}"]))
            g.add((node, ONT.assertedStatus, ONT.mappingStatus_complete))
            pairs[(cid, tid)].append(node)
        elif row["status"] == "non_mappable":
            seen[tid] += 1
            node = DATA[f"nonmappable_{tid}" + (f"_{seen[tid]}" if seen[tid] > 1 else "")]
            g.add((node, RDF.type, ONT.NonMappableAssertion))
            g.add((node, ONT.assertedStatus, ONT.mappingStatus_nonMappable))
        else:
            raise SystemExit(f"row {number}: unexpected status {row['status']!r}")
        g.add((node, ONT.assertsTechnique, DATA[f"technique_{tid}"]))
        g.add((node, ONT.sourceRecordNumber, lit(number, XSD.integer)))
        g.add((node, PROV.wasDerivedFrom, ds))
        g.add((ds, ONT.containsAssertion, node))
        if row.get("comments"):
            g.add((node, ONT.rationaleText, lit(row["comments"])))
    checks["duplicateRows"] = sorted(f"{c} {t}" for (c, t), nodes in pairs.items() if len(nodes) > 1)

    # Mitigation claims under interpretation rule R1 (docs/semantic-decisions.md)
    withheld = []
    for (cid, tid), support in sorted(pairs.items()):
        if tid not in stix_techniques:
            withheld.append(f"{cid} {tid}")
            continue
        claim = DATA[f"claim_{cid}_{tid}"]
        g.add((claim, RDF.type, ONT.MitigationClaim))
        g.add((claim, ONT.claimSubjectControl, DATA[f"control_{cid}"]))
        g.add((claim, ONT.claimObjectTechnique, DATA[f"technique_{tid}"]))
        for node in support:
            g.add((claim, ONT.supportedByAssertion, node))
            g.add((claim, PROV.wasDerivedFrom, node))
        g.add((DATA[f"control_{cid}"], ONT.mitigatesTechnique, DATA[f"technique_{tid}"]))
    checks["claimsWithheld"] = withheld
    checks["atlas"] = add_atlas(g, fetch("atlas"), stix_techniques, mitigations)
    checks["cis"] = add_cis(g, fetch("cis"), fetch("attack_19_1"), stix_techniques)
    checks["owasp"] = add_owasp(g)
    checks["counts"] = {
        "sourceRows": len(rows),
        "mitigatesRows": sum(1 for r in rows if r["status"] == "complete"),
        "nonMappableRows": sum(1 for r in rows if r["status"] == "non_mappable"),
        "rowsWithComments": sum(1 for r in rows if r.get("comments")),
        "claims": len(pairs) - len(withheld),
        "controls": len(control_ids),
        "techniquesInMapping": len(ctid_names),
        "techniquesInAttackEnterprise": len(stix_techniques),
        "tactics": len(tactic_by_short),
        "platforms": len(platforms),
        "attackMitigations": len(mitigations),
        "triples": len(g),
    }
    checks["sources"] = {k: {"url": u, "sha256": d} for k, (u, d) in SOURCES.items()}
    return g, checks


def reconcile(g: Graph, techniques: dict, later: dict, later_catalogue) -> dict:
    """Record what the later ATT&CK version changed for each technique of the pinned version.

    The match uses the STIX id, which ATT&CK keeps stable across versions; the ATT&CK ID and the tactic IDs
    can change meaning (in 20.0, TA0005 is Stealth, not Defense Evasion).
    """
    objects = later["objects"]
    by_stix = {o["id"]: o for o in objects if o["type"] == "attack-pattern"}
    revoked_by = defaultdict(list)
    for rel in objects:
        if rel["type"] == "relationship" and rel["relationship_type"] == "revoked-by":
            revoked_by[rel["source_ref"]].append(rel["target_ref"])
    tactics = {o["x_mitre_shortname"]: f"{o['name']} ({mitre_id(o)})" for o in objects if o["type"] == "x-mitre-tactic"}
    old_tactics = lambda o: sorted(p["phase_name"] for p in o.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack")  # noqa: E731
    counts = defaultdict(int)
    for tid, obj in sorted(techniques.items()):
        new = by_stix.get(obj["id"])
        statuses = []
        if new is None:
            statuses = ["missing"]
        elif new.get("revoked"):
            statuses = ["revoked"]
        elif new.get("x_mitre_deprecated"):
            statuses = ["deprecated"]
        else:
            if new["name"] != obj["name"]:
                statuses.append("renamed")
            if old_tactics(new) != old_tactics(obj):
                statuses.append("tactics changed")
        if not statuses:
            counts["unchanged"] += 1
            continue
        record = DATA[f"laterversion_{tid}_{LATER_ATTACK}"]
        g.add((record, RDF.type, ONT.LaterVersionRecord))
        g.add((record, ONT.describesEntity, DATA[f"technique_{tid}"]))
        g.add((record, ONT.inCatalogue, later_catalogue))
        g.add((record, PROV.wasDerivedFrom, DATA.attackEnterpriseStixLatest))
        for status in statuses:
            counts[status] += 1
            g.add((record, ONT.versionStatus, lit(status)))
        if new is not None:
            if "renamed" in statuses:
                g.add((record, ONT.laterName, lit(new["name"])))
            if "tactics changed" in statuses:
                for t in old_tactics(new):
                    g.add((record, ONT.laterTactic, lit(tactics[t])))
            for target in revoked_by.get(obj["id"], []):
                g.add((record, ONT.laterId, lit(mitre_id(by_stix[target]))))
                g.add((record, ONT.laterName, lit(by_stix[target]["name"])))
    later_ids = {mitre_id(o) for o in by_stix.values() if active(o) and "enterprise-attack" in o.get("x_mitre_domains", [])}
    return {
        "version": LATER_ATTACK,
        "statusCounts": dict(sorted(counts.items())),
        "techniquesOnlyInLaterVersion": len(later_ids - set(techniques)),
    }


AGENT_NAME = re.compile(r"AI Agent|Agentic")


def add_atlas(g: Graph, atlas: dict, attack_techniques: dict, attack_mitigations: dict) -> dict:
    """MITRE ATLAS tactics, techniques and mitigations, and the ATT&CK references that ATLAS publishes."""
    g.add((DATA.atlasData, RDF.type, ONT.ReferenceDataset))
    g.add((DATA.atlasData, DCTERMS.title, lit(f"MITRE ATLAS {atlas['version']}")))
    g.add((DATA.atlasData, OWL.versionInfo, lit(atlas["version"])))
    g.add((DATA.atlasData, DCTERMS.source, URIRef(SOURCES["atlas"][0])))
    g.add((DATA.atlasData, ONT.sha256, lit(SOURCES["atlas"][1])))
    catalogue = DATA[f"catalogue_atlas-{atlas['version']}"]
    g.add((catalogue, RDF.type, ONT.ThreatCatalogue))
    g.add((catalogue, RDFS.label, lit(f"MITRE ATLAS {atlas['version']}")))
    g.add((catalogue, ONT.catalogueVersion, lit(atlas["version"])))
    g.add((catalogue, ONT.catalogueDomain, lit("atlas")))
    g.add((catalogue, PROV.wasDerivedFrom, DATA.atlasData))
    matrix = atlas["matrices"][0]
    for order, tactic in enumerate(matrix["tactics"], start=1):
        node = DATA[f"atlastactic_{tactic['id']}"]
        g.add((node, RDF.type, ONT.Tactic))
        g.add((node, SKOS.inScheme, ONT.TacticScheme))
        g.add((node, SKOS.prefLabel, lit(tactic["name"])))
        g.add((node, ONT.tacticId, lit(tactic["id"])))
        g.add((node, ONT.tacticOrder, lit(order, XSD.integer)))
        g.add((node, ONT.inCatalogue, catalogue))
        g.add((node, PROV.wasDerivedFrom, DATA.atlasData))
    by_id = {t["id"]: t for t in matrix["techniques"]}
    agent = {}

    def is_agent(tid):
        if tid not in agent:
            t = by_id[tid]
            agent[tid] = bool(AGENT_NAME.search(t["name"])) or ("specializes" in t and is_agent(t["specializes"]))
        return agent[tid]

    unresolved = []
    for t in matrix["techniques"]:
        node = DATA[f"atlastechnique_{t['id']}"]
        g.add((node, RDF.type, ONT.AtlasTechnique))
        g.add((node, ONT.techniqueId, lit(t["id"])))
        g.add((node, ONT.techniqueName, lit(t["name"])))
        g.add((node, SKOS.prefLabel, lit(t["name"])))
        g.add((node, ONT.isSubTechnique, lit("specializes" in t, XSD.boolean)))
        g.add((node, ONT.isAgentRelated, lit(is_agent(t["id"]), XSD.boolean)))
        g.add((node, ONT.atlasMaturity, lit(t["maturity"])))
        g.add((node, ONT.inCatalogue, catalogue))
        g.add((node, PROV.wasDerivedFrom, DATA.atlasData))
        if "specializes" in t:
            g.add((node, ONT.subTechniqueOf, DATA[f"atlastechnique_{t['specializes']}"]))
        for ta in t.get("tactics", []):
            g.add((node, ONT.inTactic, DATA[f"atlastactic_{ta}"]))
        ref = t.get("ATT&CK-reference")
        if ref:
            if ref["id"] in attack_techniques:
                g.add((node, ONT.derivedFromAttack, DATA[f"technique_{ref['id']}"]))
            else:
                g.add((node, ONT.attackReferenceId, lit(ref["id"])))
                unresolved.append(f"{t['id']} {ref['id']}")
    attack_mitigation_ids = {str(g.value(n, ONT.mitigationId)) for n in attack_mitigations.values()}
    links = 0
    for m in matrix["mitigations"]:
        node = DATA[f"atlasmitigation_{m['id']}"]
        g.add((node, RDF.type, ONT.AtlasMitigation))
        g.add((node, ONT.mitigationId, lit(m["id"])))
        g.add((node, SKOS.prefLabel, lit(m["name"])))
        for category in (m["category"] if isinstance(m["category"], list) else [m["category"]]):
            g.add((node, ONT.atlasCategory, lit(category)))
        g.add((node, ONT.inCatalogue, catalogue))
        g.add((node, PROV.wasDerivedFrom, DATA.atlasData))
        for use in m["techniques"]:
            g.add((node, ONT.atlasMitigationFor, DATA[f"atlastechnique_{use['id']}"]))
            links += 1
        ref = m.get("ATT&CK-reference")
        if ref and ref["id"] in attack_mitigation_ids:
            g.add((node, ONT.derivedFromAttackMitigation, DATA[f"mitigation_{ref['id']}"]))
        elif ref:
            g.add((node, ONT.attackReferenceId, lit(ref["id"])))
            unresolved.append(f"{m['id']} {ref['id']}")
    return {
        "version": atlas["version"],
        "tactics": len(matrix["tactics"]),
        "techniques": len(matrix["techniques"]),
        "agentRelatedTechniques": sum(agent.values()),
        "mitigations": len(matrix["mitigations"]),
        "mitigationLinks": links,
        "attackReferencesNotInGraph": sorted(unresolved),
    }


CIS_URL = "https://www.cisecurity.org/controls/cis-controls-list"
CIS_RIGHTS = ("CIS Controls content is licensed by the Center for Internet Security under CC BY-NC-ND 4.0. "
              "This graph keeps only CIS Safeguard and Control IDs and links. Read the titles and text at cisecurity.org.")


def cis_safe_text(text: str, titles: dict) -> str:
    """CTID rationale with each CIS title (three words or more) replaced by a marker (decision D25, modification noted in NOTICE.md)."""
    for cid, title in sorted(titles.items(), key=lambda kv: -len(kv[1])):
        if len(title.split()) >= 3:
            text = re.sub(re.escape(title), f"[title of {cid}]", text, flags=re.IGNORECASE)
    return text


def cis_safe_url(url: str) -> str:
    """Drop the fragment of a CIS URL: it is the Safeguard title as a slug (decision D25)."""
    return url.split("#", 1)[0] if "cisecurity.org" in url else url


def add_cis(g: Graph, cis: dict, attack: dict, attack16: dict) -> dict:
    """CIS Controls 8.1.2 mapped to ATT&CK 19.1, joined to the 16.1 graph by STIX id (decision D23)."""
    meta, rows = cis["metadata"], cis["mapping_objects"]
    version = meta["attack_version"]
    g.add((DATA.attackEnterpriseStix191, RDF.type, ONT.ReferenceDataset))
    g.add((DATA.attackEnterpriseStix191, DCTERMS.title, lit(f"MITRE ATT&CK Enterprise STIX 2.1 bundle {version}")))
    g.add((DATA.attackEnterpriseStix191, OWL.versionInfo, lit(version)))
    g.add((DATA.attackEnterpriseStix191, DCTERMS.source, URIRef(SOURCES["attack_19_1"][0])))
    g.add((DATA.attackEnterpriseStix191, ONT.sha256, lit(SOURCES["attack_19_1"][1])))
    catalogue = DATA[f"catalogue_attack-enterprise-{version}"]
    g.add((catalogue, RDF.type, ONT.ThreatCatalogue))
    g.add((catalogue, RDFS.label, lit(f"ATT&CK Enterprise {version}")))
    g.add((catalogue, ONT.catalogueVersion, lit(version)))
    g.add((catalogue, ONT.catalogueDomain, lit("enterprise-attack")))
    g.add((catalogue, PROV.wasDerivedFrom, DATA.attackEnterpriseStix191))

    objects = attack["objects"]
    patterns = {o["id"]: o for o in objects if o["type"] == "attack-pattern"}
    active19 = {o["id"]: o for o in patterns.values() if active(o) and "enterprise-attack" in o.get("x_mitre_domains", [])}
    stix16 = {o["id"]: tid for tid, o in attack16.items()}
    node_of = {}
    new_nodes = 0
    for sid, o in active19.items():
        tid = mitre_id(o)
        if sid in stix16:
            node = DATA[f"technique_{stix16[sid]}"]
            if stix16[sid] != tid:
                raise SystemExit(f"{tid} in {version} has the STIX id of {stix16[sid]} in 16.1")
        else:
            node = DATA[f"technique_{tid}"]
            if (node, RDF.type, ONT.AttackTechnique) in g:
                raise SystemExit(f"ID collision: {tid} in {version} is a different technique from {tid} in the graph")
            new_nodes += 1
            g.add((node, RDF.type, ONT.AttackTechnique))
            g.add((node, SKOS.inScheme, ONT.TechniqueScheme))
            g.add((node, ONT.techniqueId, lit(tid)))
            g.add((node, ONT.techniqueName, lit(o["name"])))
            g.add((node, SKOS.prefLabel, lit(o["name"])))
            g.add((node, ONT.isSubTechnique, lit("." in tid, XSD.boolean)))
            g.add((node, ONT.inAttackEnterprise, lit(False, XSD.boolean)))
            g.add((node, ONT.stixId, lit(sid)))
            g.add((node, ONT.inCatalogue, catalogue))
            g.add((node, PROV.wasDerivedFrom, DATA.attackEnterpriseStix191))
        g.add((node, ONT.activeInCatalogue, catalogue))
        node_of[tid] = node
    for rel in objects:
        if rel["type"] != "relationship" or not active(rel):
            continue
        src, tgt = rel["source_ref"], rel["target_ref"]
        if rel["relationship_type"] == "subtechnique-of" and src in active19 and tgt in active19 and src not in stix16:
            g.add((node_of[mitre_id(active19[src])], ONT.subTechniqueOf, node_of[mitre_id(active19[tgt])]))
        if rel["relationship_type"] == "revoked-by" and src in stix16 and tgt in active19:
            g.add((node_of[mitre_id(active19[tgt])], ONT.replacesTechnique, DATA[f"technique_{stix16[src]}"]))

    ds, record, framework = DATA.cisDataset, DATA.cisMetadataRecord, DATA["framework_cis-8.1.2"]
    g.add((ds, RDF.type, ONT.CybersecurityMappingDataset))
    g.add((ds, DCTERMS.title, lit(f"CIS Controls {meta['mapping_framework_version']} to MITRE ATT&CK Enterprise {version} source mapping dataset")))
    g.add((ds, DCTERMS.publisher, lit("MITRE Center for Threat-Informed Defense")))
    g.add((ds, DCTERMS.source, URIRef(SOURCES["cis"][0])))
    g.add((ds, ONT.sha256, lit(SOURCES["cis"][1])))
    g.add((ds, ONT.mapsToCatalogue, catalogue))
    g.add((ds, ONT.hasMetadataRecord, record))
    g.add((record, RDF.type, ONT.DatasetMetadataRecord))
    for prop, key in (("frameworkId", "mapping_framework"), ("frameworkVersion", "mapping_framework_version"), ("attackVersion", "attack_version"),
                      ("technologyDomain", "technology_domain"), ("sourceCreationDate", "creation_date"), ("sourceLastUpdate", "last_update")):
        g.add((record, ONT[prop], lit(meta[key])))
    g.add((framework, RDF.type, ONT.ControlFramework))
    g.add((framework, RDFS.label, lit(f"CIS Critical Security Controls {meta['mapping_framework_version']}")))
    g.add((framework, ONT.catalogueVersion, lit(meta["mapping_framework_version"])))
    g.add((framework, PROV.wasDerivedFrom, ds))
    # CIS licenses the CIS Controls under CC BY-NC-ND 4.0. Keep only IDs and links, not CIS text (decision D25).
    g.add((framework, DCTERMS.source, URIRef(CIS_URL)))
    g.add((framework, DCTERMS.license, URIRef("https://creativecommons.org/licenses/by-nc-nd/4.0/")))
    g.add((framework, DCTERMS.rights, lit(CIS_RIGHTS)))
    for code in meta["capability_groups"]:
        group = DATA[f"cisgroup_{code}"]
        g.add((group, RDF.type, ONT.CapabilityGroup))
        g.add((group, SKOS.inScheme, ONT.CapabilityGroupScheme))
        g.add((group, SKOS.prefLabel, lit(code)))
        g.add((group, ONT.groupCode, lit(code)))
        g.add((group, ONT.inFramework, framework))
    safeguards = {}
    for r in rows:
        if r["capability_id"] and r["capability_id"] not in safeguards:
            safeguards[r["capability_id"]] = r
            node = DATA[f"cis_{r['capability_id']}"]
            g.add((node, RDF.type, ONT.SecurityControl))
            g.add((node, RDF.type, ONT.CisSafeguard))
            g.add((node, ONT.controlId, lit(r["capability_id"])))
            g.add((node, SKOS.prefLabel, lit(r["capability_id"])))
            g.add((node, ONT.inCapabilityGroup, DATA[f"cisgroup_{r['capability_group']}"]))
            g.add((node, ONT.inFramework, framework))
            g.add((node, PROV.wasDerivedFrom, ds))
    cis_titles = {r["capability_id"]: r["capability_description"] for r in rows if r["capability_id"] and r["capability_description"]}
    cis_titles.update(meta["capability_groups"])
    seen, pairs = defaultdict(int), defaultdict(list)
    for number, r in enumerate(rows, start=1):
        cid, tid = r["capability_id"], r["attack_object_id"]
        if r["status"] == "complete":
            if tid not in node_of:
                raise SystemExit(f"CIS row {number}: {tid} is not an active technique in ATT&CK {version}")
            key = f"{cid}_{tid}"
            seen[key] += 1
            node = DATA[f"cisassertion_{key}" + (f"_{seen[key]}" if seen[key] > 1 else "")]
            g.add((node, RDF.type, ONT.MitigatesAssertion))
            g.add((node, ONT.assertsTechnique, node_of[tid]))
            g.add((node, ONT.assertedMappingType, ONT.mappingType_mitigates))
            g.add((node, ONT.assertedStatus, ONT.mappingStatus_complete))
            pairs[(cid, tid)].append(node)
        elif r["status"] == "non_mappable":
            seen[cid] += 1
            node = DATA[f"cisnonmappable_{cid}" + (f"_{seen[cid]}" if seen[cid] > 1 else "")]
            g.add((node, RDF.type, ONT.NonMappableControlAssertion))
            g.add((node, ONT.assertedStatus, ONT.mappingStatus_nonMappable))
            if r.get("mapping_type") == "non_mappable":
                g.add((node, ONT.assertedMappingType, ONT.mappingType_nonMappable))
        else:
            raise SystemExit(f"CIS row {number}: unexpected status {r['status']!r}")
        g.add((node, ONT.assertsControl, DATA[f"cis_{cid}"]))
        g.add((node, ONT.assertsCapabilityGroup, DATA[f"cisgroup_{r['capability_group']}"]))
        g.add((node, ONT.sourceRecordNumber, lit(number, XSD.integer)))
        g.add((node, PROV.wasDerivedFrom, ds))
        g.add((ds, ONT.containsAssertion, node))
        if r.get("comments"):
            g.add((node, ONT.rationaleText, lit(cis_safe_text(r["comments"], cis_titles))))
        for ref in sorted({cis_safe_url(u) for u in r.get("references") or []}):
            g.add((node, ONT.referenceUrl, lit(ref, XSD.anyURI)))
    for (cid, tid), support in sorted(pairs.items()):
        claim = DATA[f"claim_{cid}_{tid}"]
        g.add((claim, RDF.type, ONT.MitigationClaim))
        g.add((claim, ONT.claimSubjectControl, DATA[f"cis_{cid}"]))
        g.add((claim, ONT.claimObjectTechnique, node_of[tid]))
        for node in support:
            g.add((claim, ONT.supportedByAssertion, node))
            g.add((claim, PROV.wasDerivedFrom, node))
        g.add((DATA[f"cis_{cid}"], ONT.mitigatesTechnique, node_of[tid]))
    claimed = {tid for _, tid in pairs}
    return {
        "attackVersion": version,
        "rows": len(rows),
        "mitigatesRows": sum(1 for r in rows if r["status"] == "complete"),
        "nonMappableControlRows": sum(1 for r in rows if r["status"] == "non_mappable"),
        "rowsWithComments": sum(1 for r in rows if r.get("comments")),
        "safeguards": len(safeguards),
        "controls": len(meta["capability_groups"]),
        "claims": len(pairs),
        "duplicateRows": sorted(f"{c} {t}" for (c, t), n in pairs.items() if len(n) > 1),
        "techniquesClaimed": len(claimed),
        "techniquesClaimedOnlyInLaterVersion": sum(1 for t in claimed if (node_of[t], ONT.inAttackEnterprise, Literal(False, datatype=XSD.boolean)) in g),
        "nodesAddedForLaterVersion": new_nodes,
    }


def add_owasp(g: Graph) -> dict:
    """OWASP GenAI lists from the curated extract in data/sources/owasp-genai.json (CC BY-SA 4.0 parts)."""
    raw = OWASP.read_bytes()
    doc = json.loads(raw)
    dataset = DATA.owaspGenaiExtract
    g.add((dataset, RDF.type, ONT.ReferenceDataset))
    g.add((dataset, DCTERMS.title, lit("OWASP GenAI Security Project lists (curated extract)")))
    g.add((dataset, DCTERMS.source, URIRef("https://genai.owasp.org/")))
    g.add((dataset, ONT.sha256, lit(hashlib.sha256(raw).hexdigest())))
    g.add((dataset, OWL.versionInfo, lit(doc["retrieved"])))
    counts = {}
    for lst in doc["lists"]:
        catalogue = DATA[f"catalogue_{lst['id']}"]
        g.add((catalogue, RDF.type, ONT.ThreatCatalogue))
        g.add((catalogue, RDFS.label, lit(lst["title"])))
        g.add((catalogue, ONT.catalogueVersion, lit(lst.get("published", doc["retrieved"]))))
        g.add((catalogue, ONT.catalogueDomain, lit("owasp")))
        g.add((catalogue, DCTERMS.source, URIRef(lst["url"])))
        g.add((catalogue, DCTERMS.license, lit(lst["licence"])))
        g.add((catalogue, PROV.wasDerivedFrom, dataset))
        if lst.get("note"):
            g.add((catalogue, RDFS.comment, lit(lst["note"])))
        for item in lst["items"]:
            node = DATA[f"owasp_{slug(item['id'])}"]
            g.add((node, RDF.type, ONT.OwaspRisk))
            g.add((node, ONT.owaspId, lit(item["id"])))
            g.add((node, SKOS.prefLabel, lit(f"{item['id']} {item['title']}" if item.get("title") else item["id"])))
            g.add((node, DCTERMS.source, URIRef(item["url"])))
            g.add((node, ONT.inCatalogue, catalogue))
            g.add((node, PROV.wasDerivedFrom, dataset))
            for aid in item.get("related_atlas", []):
                g.add((node, ONT.relatedAtlasTechnique, DATA[f"atlastechnique_{aid}"]))
        counts[lst["id"]] = {"items": len(lst["items"]), "atlasLinks": sum(len(i.get("related_atlas", [])) for i in lst["items"])}
    return counts


HEADER = (
    "# Generated by scripts/build_population.py from the pinned sources in data/source-checks.json.\n"
    "# Do not edit by hand: change the generator and rebuild.\n"
)


def render() -> tuple[str, str]:
    graph, checks = build()
    turtle = HEADER + graph.serialize(format="turtle")
    return turtle, json.dumps(checks, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    turtle, report = render()
    if args.check:
        stale = [p.name for p, text in ((POPULATION, turtle), (CHECKS, report)) if not p.exists() or p.read_text(encoding="utf-8") != text]
        if stale:
            print(f"out of date: {', '.join(stale)}; run python scripts/build_population.py", file=sys.stderr)
            return 1
        print("population and source checks are up to date")
        return 0
    POPULATION.parent.mkdir(exist_ok=True)
    POPULATION.write_text(turtle, encoding="utf-8")
    CHECKS.write_text(report, encoding="utf-8")
    print(f"wrote {POPULATION.relative_to(ROOT)} ({len(turtle) // 1024} KB) and {CHECKS.relative_to(ROOT)}")
    print(json.dumps(json.loads(report)["counts"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
