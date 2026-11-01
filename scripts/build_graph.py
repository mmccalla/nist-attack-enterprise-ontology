"""Build index.html, a standalone graph browser, from the Turtle files in ontology/.

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

from rdflib import OWL, RDF, RDFS, SKOS, Graph, Literal, Namespace, URIRef
from rdflib.namespace import DCTERMS, PROV

ROOT = Path(__file__).resolve().parent.parent
ONTOLOGY = ROOT / "ontology" / "nist_attack_enterprise_ontology_v2.ttl"
POPULATION = ROOT / "ontology" / "nist_attack_enterprise_population_v2.ttl"
SHAPES = ROOT / "ontology" / "nist_attack_enterprise_shapes_v2.ttl"
TEMPLATE = ROOT / "src" / "viewer.html"
D3 = ROOT / "vendor" / "d3.v7.min.js"
OUTPUT = ROOT / "index.html"

ONT = Namespace("https://w3id.org/example/nist-attack-mapping/ontology/1.0#")
DATA = Namespace("https://w3id.org/example/nist-attack-mapping/data/1.0#")
ONT_IRI = URIRef("https://w3id.org/example/nist-attack-mapping/ontology/1.0")
SH = Namespace("http://www.w3.org/ns/shacl#")

# Classes shown as nodes, most specific first so each node gets one display type.
NODE_TYPES = [
    "MitigatesAssertion",
    "NonMappableAssertion",
    "MitigationClaim",
    "SecurityControl",
    "AttackTechnique",
    "CapabilityGroup",
    "MappingType",
    "CybersecurityMappingDataset",
    "DatasetMetadataRecord",
    "Reference",
]
SCHEMES = {ONT.CapabilityGroupScheme, ONT.MappingTypeScheme}
SKIP_LITERALS = {SKOS.prefLabel}


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
    graph.parse(POPULATION)
    graph.bind("", ONT)
    graph.bind("data", DATA)
    return graph


def node_label(graph: Graph, subject, kind: str) -> tuple[str, str | None]:
    if kind == "SecurityControl":
        return text(graph, subject, ONT.controlId), text(graph, subject, ONT.controlDescription)
    if kind == "AttackTechnique":
        return text(graph, subject, ONT.techniqueId), text(graph, subject, ONT.techniqueName)
    if kind == "CapabilityGroup":
        return text(graph, subject, ONT.groupCode), text(graph, subject, ONT.groupName)
    if kind == "MitigationClaim":
        control = graph.value(subject, ONT.claimSubjectControl)
        technique = graph.value(subject, ONT.claimObjectTechnique)
        return (
            f"Claim {text(graph, control, ONT.controlId)} mitigates {text(graph, technique, ONT.techniqueId)}",
            None,
        )
    if kind in ("MitigatesAssertion", "NonMappableAssertion"):
        technique = graph.value(subject, ONT.assertsTechnique)
        control = graph.value(subject, ONT.assertsControl)
        tid = text(graph, technique, ONT.techniqueId)
        if control is None:
            return f"Source row: {tid} non_mappable", None
        return f"Source row: {text(graph, control, ONT.controlId)} mitigates {tid}", None
    label = (
        text(graph, subject, SKOS.prefLabel)
        or text(graph, subject, DCTERMS.title)
        or text(graph, subject, RDFS.label)
        or local(subject)
    )
    return label, None


def build_instances(graph: Graph) -> tuple[list, list]:
    ids: dict[URIRef, str] = {}
    nodes = []
    for kind in NODE_TYPES:
        for subject in sorted(graph.subjects(RDF.type, ONT[kind])):
            if subject in ids:
                continue
            node_id = local(subject)
            if node_id in ids.values():
                raise SystemExit(f"duplicate local name {node_id}")
            ids[subject] = node_id
            label, subtitle = node_label(graph, subject, kind)
            props = {}
            for predicate, value in sorted(graph.predicate_objects(subject)):
                if isinstance(value, Literal) and predicate not in SKIP_LITERALS:
                    props[curie(graph, predicate)] = str(value)
            node = {"id": node_id, "t": kind, "l": label, "p": props}
            if subtitle:
                node["s"] = subtitle
            nodes.append(node)
    for scheme in sorted(SCHEMES):
        ids[scheme] = local(scheme)
        nodes.append(
            {"id": local(scheme), "t": "ConceptScheme", "l": text(graph, scheme, SKOS.prefLabel), "p": {}}
        )

    edges = set()
    for subject, predicate, value in graph:
        if predicate == RDF.type or subject not in ids or value not in ids:
            continue
        edges.add((ids[subject], curie(graph, predicate), ids[value]))
    return nodes, sorted(edges)


def build_schema(graph: Graph) -> dict:
    classes = []
    for cls in sorted(graph.subjects(RDF.type, OWL.Class)):
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
                restrictions.append(f"{curie(graph, prop)} has value {curie(graph, has_value)}")
        classes.append(
            {
                "id": curie(graph, cls),
                "label": text(graph, cls, RDFS.label),
                "comment": text(graph, cls, RDFS.comment),
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
        for prop in sorted(graph.subjects(RDF.type, rdf_type)):
            inverse = graph.value(prop, OWL.inverseOf) or graph.value(None, OWL.inverseOf, prop)
            props.append(
                {
                    "id": curie(graph, prop),
                    "kind": kind,
                    "label": text(graph, prop, RDFS.label),
                    "comment": text(graph, prop, RDFS.comment),
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
        out.append(
            {
                "id": curie(shapes, shape),
                "target": curie(shapes, shapes.value(shape, SH.targetClass)),
                "rules": sorted(rules),
            }
        )
    return out


def build_meta(graph: Graph, nodes: list) -> dict:
    record = DATA.datasetMetadataRecord
    with_rationale = sum(1 for _ in graph.subjects(ONT.rationaleText, None))
    return {
        "title": text(graph, ONT_IRI, DCTERMS.title),
        "description": text(graph, ONT_IRI, DCTERMS.description),
        "version": text(graph, ONT_IRI, OWL.versionInfo),
        "created": text(graph, ONT_IRI, DCTERMS.created),
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
        "counts": dict(sorted(Counter(n["t"] for n in nodes).items())),
        "withRationale": with_rationale,
        "triples": len(graph),
    }


def render() -> str:
    graph = load()
    nodes, edges = build_instances(graph)
    index = {n["id"]: i for i, n in enumerate(nodes)}
    payload = {
        "meta": build_meta(graph, nodes),
        "nodes": nodes,
        "edges": [[index[s], p, index[o]] for s, p, o in edges],
        "schema": build_schema(graph),
        "shapes": build_shapes(),
    }
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    data = data.replace("</", "<\\/")
    d3 = D3.read_text(encoding="utf-8").replace("</script", "<\\/script")
    html = TEMPLATE.read_text(encoding="utf-8")
    for marker in ("/*__GRAPH_DATA__*/", "/*__D3__*/"):
        if html.count(marker) != 1:
            raise SystemExit(f"template must contain {marker} exactly once")
    return html.replace("/*__GRAPH_DATA__*/", data).replace("/*__D3__*/", d3)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if index.html is out of date")
    args = parser.parse_args()
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
