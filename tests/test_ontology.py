"""Checks on the ontology bundle: it parses, it conforms to its shapes, and the shapes reject bad data."""

import hashlib
import re
import subprocess
import sys
from pathlib import Path

import pytest
from pyshacl import validate
from rdflib import Graph, Literal, Namespace, URIRef
from rdflib.namespace import RDF

ROOT = Path(__file__).resolve().parent.parent
ONT_DIR = ROOT / "ontology"
ONT = Namespace("https://w3id.org/example/nist-attack-mapping/ontology/1.0#")
DATA = Namespace("https://w3id.org/example/nist-attack-mapping/data/1.0#")


@pytest.fixture(scope="module")
def shapes():
    return Graph().parse(ONT_DIR / "nist_attack_enterprise_shapes_v2.ttl")


@pytest.fixture()
def data():
    graph = Graph()
    graph.parse(ONT_DIR / "nist_attack_enterprise_ontology_v2.ttl")
    graph.parse(ONT_DIR / "nist_attack_enterprise_population_v2.ttl")
    return graph


def conforms(graph, shapes):
    ok, _, report = validate(graph, shacl_graph=shapes, advanced=True)
    return ok, report


def test_owl_file_parses():
    assert len(Graph().parse(ONT_DIR / "nist_attack_enterprise_ontology_v2.owl")) > 0


def test_bundle_conforms_to_shapes(data, shapes):
    ok, report = conforms(data, shapes)
    assert ok, report


def test_sample_counts_match_the_readme(data):
    count = lambda cls: len(set(data.subjects(RDF.type, ONT[cls])))
    assert count("SecurityControl") == 109
    assert count("AttackTechnique") == 566
    assert count("CapabilityGroup") == 11
    assert count("MitigatesAssertion") == 200
    assert count("MitigationClaim") == 200
    assert count("NonMappableAssertion") == 50


# Negative probes: each mutation must make validation fail, or the shapes are not doing their job.

def test_rejects_capability_group_that_differs_from_the_control(data, shapes):
    row = DATA.assertion_98  # AC-02, group AC
    data.set((row, ONT.assertsCapabilityGroup, ONT.capabilityGroup_SI))
    ok, report = conforms(data, shapes)
    assert not ok and "capability group must match" in report


def test_rejects_claim_not_backed_by_a_matching_assertion(data, shapes):
    claim = DATA["claim_AC-02_T1556.009"]
    data.set((claim, ONT.supportedByAssertion, DATA.assertion_97))  # CM-03 row
    ok, report = conforms(data, shapes)
    assert not ok and "same control and technique" in report


def test_rejects_malformed_technique_id(data, shapes):
    data.set((DATA.technique_T1001, ONT.techniqueId, Literal("T1")))
    assert not conforms(data, shapes)[0]


def test_rejects_non_mappable_row_with_a_control(data, shapes):
    data.add((DATA.nonmappable_1, ONT.assertsControl, DATA["control_AC-02"]))
    assert not conforms(data, shapes)[0]


def test_rejects_assertion_without_provenance(data, shapes):
    data.remove((DATA.assertion_98, URIRef("http://www.w3.org/ns/prov#wasDerivedFrom"), None))
    assert not conforms(data, shapes)[0]


def test_bundle_files_match_the_source_manifest():
    manifest = (ROOT / "SOURCE-MANIFEST.md").read_text(encoding="utf-8")
    rows = re.findall(r"\| `(ontology/[^`]+)` \| `([0-9a-f]{64})` \|", manifest)
    assert len(rows) == 5
    for path, digest in rows:
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == digest, path


def test_index_html_is_built_from_the_current_sources():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_graph.py"), "--check"], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_index_html_is_self_contained():
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script[^>]+src=", html)
    assert not re.search(r"<link[^>]+stylesheet", html)
