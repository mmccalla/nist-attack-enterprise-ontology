"""Shared loaders for the evaluation gates in tests/ (consistency, conformance, alignment, competency)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from rdflib import Graph, Namespace
from rdflib.namespace import RDF

ROOT = Path(__file__).resolve().parent.parent
ONT = Namespace("https://w3id.org/example/nist-attack-mapping/ontology/1.0#")
DATA = Namespace("https://w3id.org/example/nist-attack-mapping/data/1.0#")
CORE = ROOT / "ontology" / "core.ttl"
SHAPES = ROOT / "ontology" / "shapes.ttl"
ALIGNMENTS = [ROOT / "ontology" / f"alignment-{name}.ttl" for name in ("stix", "oscal", "uco")]
POPULATION = ROOT / "data" / "population.ttl"
UCO_CORE = ROOT / "vendor" / "uco" / "core.ttl"

# The reasoning slice: every reference entity, every non-mappable row, and the full claim chains for these
# controls and techniques. owlrl is pure Python and does not finish on the whole population in useful time.
SLICE_CONTROLS = ("AC-02", "IA-02", "SC-12")
SLICE_TECHNIQUES = ("T1078", "T1556", "T1521.003")


@lru_cache(maxsize=1)
def _population() -> Graph:
    return Graph().parse(POPULATION)


def graph(*paths: Path, population: bool = True) -> Graph:
    """A fresh graph, safe to mutate, holding the given files plus (by default) the population."""
    g = Graph()
    g.namespace_manager.bind("", ONT)
    g.namespace_manager.bind("data", DATA)
    for path in paths:
        g.parse(path)
    if population:
        for triple in _population():
            g.add(triple)
    return g


def reasoning_slice() -> Graph:
    full = _population()
    keep_controls = {DATA[f"control_{c}"] for c in SLICE_CONTROLS}
    keep_techniques = {DATA[f"technique_{t}"] for t in SLICE_TECHNIQUES}
    keep_techniques |= set(full.subjects(ONT.subTechniqueOf, DATA.technique_T1556))
    dropped = set()
    for row in full.subjects(RDF.type, ONT.MitigatesAssertion):
        if full.value(row, ONT.assertsControl) not in keep_controls and full.value(row, ONT.assertsTechnique) not in keep_techniques:
            dropped.add(row)
    for claim in full.subjects(RDF.type, ONT.MitigationClaim):
        if full.value(claim, ONT.claimSubjectControl) not in keep_controls and full.value(claim, ONT.claimObjectTechnique) not in keep_techniques:
            dropped.add(claim)
    kept_pairs = {
        (full.value(c, ONT.claimSubjectControl), full.value(c, ONT.claimObjectTechnique))
        for c in full.subjects(RDF.type, ONT.MitigationClaim)
        if c not in dropped
    }
    g = graph(population=False)
    for s, p, o in full:
        if s in dropped or o in dropped:
            continue
        if p == ONT.mitigatesTechnique and (s, o) not in kept_pairs:
            continue
        g.add((s, p, o))
    return g


# ---- OWL DL reasoning (HermiT through owlready2; needs Java) ----

_HERMIT = r"""
import json, sys, owlready2
from owlready2 import default_world
path, infer = sys.argv[1], sys.argv[2] == "1"
world = owlready2.World()
onto = world.get_ontology("file://" + path).load()
try:
    owlready2.sync_reasoner_hermit(world, infer_property_values=infer, debug=0)
except owlready2.OwlReadyInconsistentOntologyError:
    print(json.dumps({"consistent": False})); sys.exit(0)
out = {"consistent": True, "unsatisfiable": sorted(c.iri for c in world.inconsistent_classes() if c is not owlready2.Nothing)}
if infer:
    out["mitigates"] = sorted(
        [s.iri, o.iri] for s, o in world.get_ontology("https://w3id.org/example/nist-attack-mapping/ontology/1.0#")
        .search_one(iri="*#mitigatesTechnique").get_relations()
    )
print(json.dumps(out))
"""


def hermit(g: Graph, timeout: int = 600, infer_property_values: bool = False) -> dict:
    """Run HermiT on a graph in a child process. Raises on timeout or reasoner failure: a gate that cannot
    run must fail, not pass."""
    import json
    import subprocess
    import sys
    import tempfile
    import warnings

    with tempfile.NamedTemporaryFile(suffix=".nt", delete=False) as handle:
        path = handle.name
    from rdflib.namespace import OWL

    # Every module is loaded from disk already; owlready2 would otherwise try to fetch the import IRIs.
    local = Graph()
    for t in owl_only(g):
        if t[1] != OWL.imports:
            local.add(t)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        local.serialize(path, format="nt", encoding="utf-8")
    import os
    import signal

    # Own process group, so a timeout also stops the Java process that owlready2 starts.
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", _HERMIT, path, "1" if infer_property_values else "0"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    try:
        stdout, stderr = child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.communicate()
        raise
    finally:
        Path(path).unlink(missing_ok=True)
    result = subprocess.CompletedProcess(child.args, child.returncode, stdout, stderr)
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(f"HermiT did not run: {result.stderr[-2000:]}")
    return json.loads(result.stdout.strip().splitlines()[-1])


def owl_only(g: Graph) -> Graph:
    """Drop SHACL triples and the blank-node structures under them. UCO core puns its classes as SHACL node
    shapes; HermiT would read those structures as anonymous individuals, and on the full population that made
    a 48-second check run for more than 15 minutes. Shapes are validated by pySHACL, not by the reasoner."""
    from rdflib import BNode

    shacl = "http://www.w3.org/ns/shacl#"
    drop, todo = set(), [o for _, p, o in g if str(p).startswith(shacl) and isinstance(o, BNode)]
    while todo:
        node = todo.pop()
        if node not in drop:
            drop.add(node)
            todo.extend(o for o in g.objects(node, None) if isinstance(o, BNode))
    out = Graph()
    for s, p, o in g:
        if s in drop or str(p).startswith(shacl) or str(o).startswith(shacl):
            continue
        out.add((s, p, o))
    return out


def reasoning_profile(g: Graph) -> Graph:
    """Remove number restrictions and owl:hasValue restrictions (decision D13). With thousands of individuals
    pointing at the same few vocabulary individuals, these make HermiT's tableau explode, and SHACL already
    enforces them as data constraints. Disjointness, domain and range, inverses, keys and the property chain stay."""
    from rdflib.namespace import OWL, RDFS

    out = Graph()
    for t in g:
        out.add(t)
    keys = (OWL.qualifiedCardinality, OWL.minQualifiedCardinality, OWL.maxQualifiedCardinality,
            OWL.cardinality, OWL.minCardinality, OWL.maxCardinality, OWL.hasValue)
    for key in keys:
        for restriction in list(out.subjects(key, None)):
            for cls in list(out.subjects(RDFS.subClassOf, restriction)):
                out.remove((cls, RDFS.subClassOf, restriction))
            out.remove((restriction, None, None))
    return out
