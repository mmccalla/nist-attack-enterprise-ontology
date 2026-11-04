"""Build index.html, a standalone graph browser, from ontology/ and data/, with the competency answers.

Usage:
    python scripts/build_graph.py          write index.html
    python scripts/build_graph.py --check  fail if index.html is out of date
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import re

from rdflib import OWL, RDF, RDFS, SKOS, Graph, Literal, Namespace, URIRef
from rdflib.namespace import DCTERMS, PROV

ROOT = Path(__file__).resolve().parent.parent
ONTOLOGY = ROOT / "ontology" / "core.ttl"
ALIGNMENTS = [ROOT / "ontology" / f"alignment-{name}.ttl" for name in ("stix", "oscal", "uco")]
POPULATION = ROOT / "data" / "population.ttl"
SHAPES = ROOT / "ontology" / "shapes.ttl"
QUERIES = ROOT / "queries"
CHECKS = ROOT / "data" / "source-checks.json"
MAX_CQ_ROWS = 200
TEMPLATE = ROOT / "src" / "viewer.html"
D3 = ROOT / "vendor" / "d3.v7.min.js"
COVERAGE = ROOT / "lib" / "coverage.cjs"
CISFILE = ROOT / "lib" / "cisfile.cjs"
OUTPUT = ROOT / "index.html"

ONT = Namespace("https://w3id.org/example/nist-attack-mapping/ontology/1.0#")
DATA = Namespace("https://w3id.org/example/nist-attack-mapping/data/1.0#")
ONT_IRI = URIRef("https://w3id.org/example/nist-attack-mapping/ontology/1.0")
SH = Namespace("http://www.w3.org/ns/shacl#")
UCO = Namespace("https://ontology.unifiedcyberontology.org/uco/core/")

# Classes shown as nodes, most specific first so each node gets one display type.
NODE_TYPES = [
    "MitigatesAssertion",
    "NonMappableAssertion",
    "NonMappableControlAssertion",
    "MitigationClaim",
    "CisSafeguard",
    "SecurityControl",
    "AttackTechnique",
    "CapabilityGroup",
    "Tactic",
    "Platform",
    "AttackMitigation",
    "ControlBaseline",
    "CybersecurityMappingDataset",
    "ReferenceDataset",
    "DatasetMetadataRecord",
    "LaterVersionRecord",
    "AtlasTechnique",
    "AtlasMitigation",
    "OwaspRisk",
]
# Edges left out of the browser: they point at hub nodes (vocabularies, datasets) or restate another edge.
# Their values appear as properties instead.
SKIP_EDGES = {ONT.containsAssertion, ONT.assertsCapabilityGroup, PROV.wasDerivedFrom, SKOS.inScheme, ONT.inCatalogue, ONT.inFramework, ONT.activeInCatalogue}
AS_PROPERTY = {
    ONT.assertedMappingType: "mapping type", ONT.assertedStatus: "status", PROV.wasDerivedFrom: "derived from",
    ONT.inCatalogue: "catalogue", ONT.inFramework: "framework", DCTERMS.source: "source url", ONT.activeInCatalogue: "active in",
}
SKIP_LITERALS = {SKOS.prefLabel}
ALIGNMENT_ANNOTATIONS = ["stixObjectType", "stixRelationshipType", "stixProperty", "stixAlignmentNote", "oscalAssembly", "oscalPath"]


def local(term: URIRef) -> str:
    text = str(term)
    for ns in (str(ONT), str(DATA)):
        if text.startswith(ns):
            return text[len(ns) :]
    return text


def curie(graph: Graph, term: URIRef) -> str:
    try:
        return graph.namespace_manager.normalizeUri(term)
    except Exception:  # noqa: BLE001 - fall back to the full IRI
        return str(term)


def text(graph: Graph, subject, predicate) -> str | None:
    value = graph.value(subject, predicate)
    return str(value) if value is not None else None


def load() -> Graph:
    graph = Graph()
    graph.parse(ONTOLOGY)
    for path in ALIGNMENTS:
        graph.parse(path)
    graph.parse(POPULATION)
    graph.bind("", ONT)
    graph.bind("data", DATA)
    graph.bind("core", UCO)
    return graph


def node_label(graph: Graph, subject, kind: str) -> tuple[str, str | None]:
    pref = text(graph, subject, SKOS.prefLabel)
    if kind in ("SecurityControl", "CisSafeguard"):
        return text(graph, subject, ONT.controlId), text(graph, subject, ONT.controlTitle)
    if kind == "AttackTechnique":
        return text(graph, subject, ONT.techniqueId), text(graph, subject, ONT.techniqueName)
    if kind == "CapabilityGroup":
        return text(graph, subject, ONT.groupCode), text(graph, subject, ONT.oscalFamilyTitle) or text(graph, subject, ONT.groupName)
    if kind == "Tactic":
        return text(graph, subject, ONT.tacticId), pref
    if kind == "AttackMitigation":
        return text(graph, subject, ONT.mitigationId), pref
    if kind == "ControlBaseline":
        return text(graph, subject, ONT.baselineLevel), "SP 800-53B baseline"
    if kind == "MitigationClaim":
        control = graph.value(subject, ONT.claimSubjectControl)
        technique = graph.value(subject, ONT.claimObjectTechnique)
        return f"Claim {text(graph, control, ONT.controlId)} mitigates {text(graph, technique, ONT.techniqueId)}", None
    if kind == "AtlasTechnique":
        return text(graph, subject, ONT.techniqueId), text(graph, subject, ONT.techniqueName)
    if kind == "AtlasMitigation":
        return text(graph, subject, ONT.mitigationId), pref
    if kind == "OwaspRisk":
        oid = text(graph, subject, ONT.owaspId)
        title = pref[len(oid):].strip() if pref and pref.startswith(oid) else None
        return oid, title or None
    if kind == "LaterVersionRecord":
        catalogue = graph.value(subject, ONT.inCatalogue)
        statuses = ", ".join(sorted(str(x) for x in graph.objects(subject, ONT.versionStatus)))
        return f"{graph.value(catalogue, RDFS.label)}: {statuses}", None
    if kind in ("MitigatesAssertion", "NonMappableAssertion", "NonMappableControlAssertion"):
        technique = graph.value(subject, ONT.assertsTechnique)
        control = graph.value(subject, ONT.assertsControl)
        row = text(graph, subject, ONT.sourceRecordNumber)
        prefix = "CIS row" if (subject, PROV.wasDerivedFrom, DATA.cisDataset) in graph else "Row"
        if technique is None:
            return f"{prefix} {row}: {text(graph, control, ONT.controlId)} non_mappable", None
        tid = text(graph, technique, ONT.techniqueId)
        if control is None:
            return f"{prefix} {row}: {tid} non_mappable", None
        return f"{prefix} {row}: {text(graph, control, ONT.controlId)} mitigates {tid}", None
    return pref or text(graph, subject, DCTERMS.title) or text(graph, subject, RDFS.label) or local(subject), None


def build_instances(graph: Graph) -> tuple[list, list]:
    ids: dict[URIRef, str] = {}
    nodes = []
    for kind in NODE_TYPES:
        for subject in sorted(graph.subjects(RDF.type, ONT[kind])):
            if subject in ids:
                continue
            node_id = local(subject)
            ids[subject] = node_id
            label, subtitle = node_label(graph, subject, kind)
            props = {}
            for predicate, value in sorted(graph.predicate_objects(subject)):
                if isinstance(value, Literal) and predicate not in SKIP_LITERALS:
                    key = curie(graph, predicate)
                    props[key] = f"{props[key]} | {value}" if key in props else str(value)
                elif predicate in AS_PROPERTY and isinstance(value, URIRef):
                    if predicate == DCTERMS.source:
                        props[AS_PROPERTY[predicate]] = str(value)
                        continue
                    if predicate in (ONT.inCatalogue, ONT.inFramework, ONT.activeInCatalogue):
                        key, catalogue = AS_PROPERTY[predicate], str(graph.value(value, RDFS.label))
                        props[key] = f"{props[key]} | {catalogue}" if key in props else catalogue
                        continue
                    if predicate == PROV.wasDerivedFrom and not (
                        (value, RDF.type, ONT.ReferenceDataset) in graph or (value, RDF.type, ONT.CybersecurityMappingDataset) in graph
                    ):
                        continue
                    props[AS_PROPERTY[predicate]] = node_label(graph, value, "")[0]
            node = {"id": node_id, "t": kind, "l": label, "p": props}
            if subtitle:
                node["s"] = subtitle
            nodes.append(node)
    if len(set(ids.values())) != len(ids):
        raise SystemExit("duplicate local names")

    edges = set()
    for subject, predicate, value in graph:
        if predicate == RDF.type or predicate in SKIP_EDGES or subject not in ids or value not in ids:
            continue
        edges.add((ids[subject], curie(graph, predicate), ids[value]))
    return nodes, sorted(edges)


def alignments(graph: Graph, term) -> list:
    out = [f"{name}: {graph.value(term, ONT[name])}" for name in ALIGNMENT_ANNOTATIONS if graph.value(term, ONT[name]) is not None]
    for predicate, label in ((RDFS.subClassOf, "UCO superclass"), (RDFS.subPropertyOf, "UCO super-property")):
        out += [f"{label}: {curie(graph, o)}" for o in graph.objects(term, predicate) if str(o).startswith(str(UCO))]
    return sorted(out)


def build_schema(graph: Graph) -> dict:
    core = Graph().parse(ONTOLOGY)
    classes = []
    for cls in sorted(core.subjects(RDF.type, OWL.Class)):
        if not isinstance(cls, URIRef):
            continue
        supers = [curie(graph, s) for s in graph.objects(cls, RDFS.subClassOf) if isinstance(s, URIRef)]
        restrictions = []
        for restriction in graph.objects(cls, RDFS.subClassOf):
            if isinstance(restriction, URIRef):
                continue
            prop = graph.value(restriction, OWL.onProperty)
            for key, word in (
                (OWL.qualifiedCardinality, "exactly"),
                (OWL.cardinality, "exactly"),
                (OWL.minQualifiedCardinality, "at least"),
                (OWL.maxQualifiedCardinality, "at most"),
                (OWL.maxCardinality, "at most"),
            ):
                count = graph.value(restriction, key)
                if count is not None:
                    on_class = graph.value(restriction, OWL.onClass)
                    target = f" {curie(graph, on_class)}" if on_class is not None else ""
                    restrictions.append(f"{curie(graph, prop)} {word} {count}{target}")
            has_value = graph.value(restriction, OWL.hasValue)
            if has_value is not None:
                shown = curie(graph, has_value) if isinstance(has_value, URIRef) else repr(str(has_value).lower() if isinstance(has_value.toPython(), bool) else str(has_value))
                restrictions.append(f"{curie(graph, prop)} has value {shown}")
        classes.append(
            {
                "id": curie(graph, cls),
                "label": text(graph, cls, RDFS.label),
                "comment": text(graph, cls, SKOS.definition) or text(graph, cls, RDFS.comment),
                "deprecated": (cls, OWL.deprecated, Literal(True)) in graph,
                "alignments": alignments(graph, cls),
                "super": sorted(supers),
                "disjoint": sorted(
                    {curie(graph, d) for d in graph.objects(cls, OWL.disjointWith)}
                    | {curie(graph, d) for d in graph.subjects(OWL.disjointWith, cls)}
                ),
                "restrictions": sorted(restrictions),
            }
        )
    props = []
    for kind, rdf_type in (("object", OWL.ObjectProperty), ("datatype", OWL.DatatypeProperty)):
        for prop in sorted(core.subjects(RDF.type, rdf_type)):
            named = [i for i in (*graph.objects(prop, OWL.inverseOf), *graph.subjects(OWL.inverseOf, prop)) if isinstance(i, URIRef)]
            inverse = sorted(named)[0] if named else None
            props.append(
                {
                    "id": curie(graph, prop),
                    "kind": kind,
                    "label": text(graph, prop, RDFS.label),
                    "comment": text(graph, prop, SKOS.definition) or text(graph, prop, RDFS.comment),
                    "deprecated": (prop, OWL.deprecated, Literal(True)) in graph,
                    "alignments": alignments(graph, prop),
                    "domain": curie(graph, graph.value(prop, RDFS.domain)) if graph.value(prop, RDFS.domain) else None,
                    "range": curie(graph, graph.value(prop, RDFS.range)) if graph.value(prop, RDFS.range) else None,
                    "inverse": curie(graph, inverse) if inverse is not None else None,
                    "functional": (prop, RDF.type, OWL.FunctionalProperty) in graph,
                }
            )
    return {"classes": classes, "properties": props}


def build_shapes() -> list:
    shapes = Graph().parse(SHAPES)
    shapes.bind("", ONT)
    out = []
    for shape in sorted(shapes.subjects(RDF.type, SH.NodeShape)):
        rules = []
        for prop in shapes.objects(shape, SH.property):
            path = curie(shapes, shapes.value(prop, SH.path))
            parts = []
            for key in ("minCount", "maxCount", "datatype", "class", "pattern", "hasValue"):
                value = shapes.value(prop, SH[key])
                if value is not None:
                    shown = curie(shapes, value) if isinstance(value, URIRef) else str(value)
                    parts.append(f"{key} {shown}")
            in_list = shapes.value(prop, SH["in"])
            if in_list is not None:
                parts.append("in (" + ", ".join(str(v) for v in shapes.items(in_list)) + ")")
            rules.append(f"{path}: " + "; ".join(parts))
        for sparql in shapes.objects(shape, SH.sparql):
            rules.append("SPARQL: " + str(shapes.value(sparql, SH.message)))
        severity = shapes.value(shape, SH.severity)
        out.append(
            {
                "id": curie(shapes, shape),
                "target": curie(shapes, shapes.value(shape, SH.targetClass)) if shapes.value(shape, SH.targetClass) else "graph",
                "targets": sorted(curie(shapes, t) for t in shapes.objects(shape, SH.targetClass)),
                "severity": "warning" if severity == SH.Warning else "violation",
                "rules": sorted(rules),
            }
        )
    return out


ID_PATTERNS = [
    (re.compile(r"^[A-Z]{2}-[0-9]{2}$"), "control_"),
    (re.compile(r"^T[0-9]{4}([.][0-9]{3})?$"), "technique_"),
    (re.compile(r"^M[0-9]{4}$"), "mitigation_"),
    (re.compile(r"^TA[0-9]{4}$"), "tactic_"),
]


def cell(value) -> str | None:
    return None if value is None else (local(value) if isinstance(value, URIRef) else str(value))


def build_questions(graph: Graph) -> list:
    out = []
    for path in sorted(QUERIES.glob("cq*.rq")):
        text_ = path.read_text(encoding="utf-8")
        head = dict(re.findall(r"^# (id|persona|question|decision|evidence): (.+)$", text_, re.M))
        result = graph.query(text_)
        # SPARQL leaves GROUP_CONCAT order undefined; sort the tokens so the build is reproducible.
        concat = set(re.findall(r"GROUP_CONCAT\([^)]*\) AS \?(\w+)", text_))
        columns = [str(v) for v in result.vars]
        rows = [
            [" ".join(sorted(c.split(), key=lambda t: (0, int(t), "") if t.isdigit() else (1, 0, t))) if c and columns[i] in concat else c for i, c in enumerate(map(cell, row))]
            for row in result
        ]
        out.append({
            **head,
            "file": f"queries/{path.name}",
            "sparql": "\n".join(line for line in text_.splitlines() if not line.startswith("# ") and not line.startswith("PREFIX")).strip(),
            "columns": columns,
            "rows": rows[:MAX_CQ_ROWS],
            "total": len(rows),
        })
    return out


def build_meta(graph: Graph, nodes: list) -> dict:
    record = DATA.datasetMetadataRecord
    checks = json.loads(CHECKS.read_text(encoding="utf-8"))
    return {
        "title": text(graph, ONT_IRI, DCTERMS.title),
        "description": text(graph, ONT_IRI, DCTERMS.description),
        "version": text(graph, ONT_IRI, OWL.versionInfo),
        "versionIri": text(graph, ONT_IRI, OWL.versionIRI),
        "modified": text(graph, ONT_IRI, DCTERMS.modified),
        "license": text(graph, ONT_IRI, DCTERMS.license),
        "iri": str(ONT_IRI),
        "source": {
            "file": text(graph, record, DCTERMS.source),
            "framework": text(graph, record, ONT.frameworkId),
            "frameworkVersion": text(graph, record, ONT.frameworkVersion),
            "attackVersion": text(graph, record, ONT.attackVersion),
            "domain": text(graph, record, ONT.technologyDomain),
            "lastUpdate": text(graph, record, ONT.sourceLastUpdate),
        },
        "sources": checks["sources"],
        "checks": {k: v for k, v in checks.items() if k not in ("sources", "counts")},
        "sourceCounts": checks["counts"],
        "atlasVersion": checks["atlas"]["version"],
        "counts": dict(sorted(Counter(n["t"] for n in nodes).items())),
        "triples": len(graph),
    }


POISON = '<img src=x onerror="window.__xss=1"><script>window.__xss=2</script>'


def poison(payload: dict) -> None:
    """Test only: put HTML and script payloads into the data, as a compromised source would."""
    for node in payload["nodes"]:
        if node["id"] in ("technique_T1078", "control_AC-02", "claim_AC-02_T1556.009", "tactic_TA0001"):
            node["l"] = POISON + node["l"]
            node["s"] = POISON + node.get("s", "")
            node["p"] = {k: POISON + v for k, v in node["p"].items()}
    for q in payload["questions"]:
        q["question"] = POISON + q["question"]
        q["rows"] = [[POISON + str(v) if i == 1 else v for i, v in enumerate(r)] for r in q["rows"]]
    payload["meta"]["description"] = POISON + payload["meta"]["description"]


def render(poisoned: bool = False) -> str:
    graph = load()
    nodes, edges = build_instances(graph)
    index = {n["id"]: i for i, n in enumerate(nodes)}
    predicates = sorted({p for _, p, _ in edges})
    pindex = {p: i for i, p in enumerate(predicates)}
    payload = {
        "meta": build_meta(graph, nodes),
        "nodes": nodes,
        "predicates": predicates,
        "edges": [[index[s], pindex[p], index[o]] for s, p, o in edges],
        "schema": build_schema(graph),
        "shapes": build_shapes(),
        "questions": build_questions(graph),
        # Exact CIS text with its own licence (CC BY-NC-ND 4.0, D29). Kept apart from the CC BY graph.
        "cis": json.loads((ROOT / "data" / "sources" / "cis-controls-8.1.2.json").read_text(encoding="utf-8")),
    }
    if poisoned:
        poison(payload)
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    data = data.replace("</", "<\\/")
    # ISC licence: the copyright and permission notice must appear in all copies (NOTICE.md).
    d3_licence = (ROOT / "LICENSES" / "ISC-d3.txt").read_text(encoding="utf-8").replace("*/", "* /")
    d3 = f"/*! D3 7.9.0\n{d3_licence}*/\n" + D3.read_text(encoding="utf-8").replace("</script", "<\\/script")
    html = TEMPLATE.read_text(encoding="utf-8")
    coverage = COVERAGE.read_text(encoding="utf-8").replace("</script", "<\\/script")
    cisfile = CISFILE.read_text(encoding="utf-8").replace("</script", "<\\/script")
    for marker in ("/*__GRAPH_DATA__*/", "/*__D3__*/", "/*__COVERAGE__*/", "/*__CISFILE__*/"):
        if html.count(marker) != 1:
            raise SystemExit(f"template must contain {marker} exactly once")
    html = html.replace("/*__GRAPH_DATA__*/", data).replace("/*__D3__*/", d3).replace("/*__COVERAGE__*/", coverage).replace("/*__CISFILE__*/", cisfile)
    return html.replace("/*__CSP__*/", content_security_policy(html))


def content_security_policy(html: str) -> str:
    """Allow only the page's own inline scripts (by SHA-256) and no network access at all.

    connect-src 'none' is what makes "nothing is uploaded" a browser-enforced fact. style-src keeps
    'unsafe-inline' because the page sets style attributes; scripts cannot run from injected markup.
    frame-ancestors cannot be set from a meta element (see docs/security.md).
    """
    import base64
    import hashlib

    scripts = re.findall(r"<script>(.*?)</script>", html, flags=re.S)
    hashes = " ".join(f"'sha256-{base64.b64encode(hashlib.sha256(s.encode('utf-8')).digest()).decode()}'" for s in scripts)
    return (
        f"default-src 'none'; script-src {hashes}; style-src 'unsafe-inline'; img-src data: blob:; "
        "connect-src 'none'; font-src 'none'; object-src 'none'; media-src 'none'; frame-src 'none'; "
        "worker-src 'none'; manifest-src 'none'; base-uri 'none'; form-action 'none'"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if index.html is out of date")
    parser.add_argument("--poisoned", metavar="PATH", help="test only: write a page built from poisoned data to PATH")
    args = parser.parse_args()
    if args.poisoned:
        Path(args.poisoned).write_text(render(poisoned=True), encoding="utf-8")
        print(f"wrote poisoned test page to {args.poisoned}")
        return 0
    html = render()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != html:
            print("index.html is out of date: run python scripts/build_graph.py", file=sys.stderr)
            return 1
        print("index.html is up to date")
        return 0
    OUTPUT.write_text(html, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({len(html) // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
