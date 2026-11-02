"""Alignment gate: aligned data must conform to UCO 1.5.0 core's own SHACL shapes, and the STIX and OSCAL
alignment modules must annotate every term they claim to cover."""

import re
import sys
from pathlib import Path

import pytest
from pyshacl import validate
from rdflib import Graph, Literal, URIRef
from rdflib.namespace import OWL, RDF

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import gates  # noqa: E402
from gates import DATA, ONT  # noqa: E402

UCO = "https://ontology.unifiedcyberontology.org/uco/core/"

# OWL RL rule cls-hv1 (an instance of a class restricted by owl:hasValue has that value), applied through
# rdfs:subClassOf*. RDFS inference in pySHACL does not cover owl:hasValue.
CLS_HV1 = """
PREFIX owl: <http://www.w3.org/2002/07/owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
CONSTRUCT { ?x ?p ?v }
WHERE { ?c rdfs:subClassOf ?r . ?r owl:onProperty ?p ; owl:hasValue ?v . ?sub rdfs:subClassOf* ?c . ?x a ?sub . }
"""


@pytest.fixture(scope="module")
def uco():
    return Graph().parse(gates.UCO_CORE)


def aligned_slice(apply_has_value=True):
    g = gates.reasoning_slice()
    g.parse(gates.CORE)
    g.parse(ROOT / "ontology" / "alignment-uco.ttl")
    if apply_has_value:
        for triple in list(g.query(CLS_HV1)):
            g.add(triple)
    return g


def check(g, uco):
    ok, _, report = validate(g, shacl_graph=uco, ont_graph=uco, inference="rdfs", allow_infos=True, allow_warnings=True)
    return ok, report


def test_aligned_data_conforms_to_uco_core_shapes(uco):
    ok, report = check(aligned_slice(), uco)
    assert ok, report[:3000]
    # The only results are UCO's advisory on UUID-suffixed IRIs (decision D10).
    shapes = set(re.findall(r"Source Shape: (\S+)", report))
    assert shapes <= {"core:UcoThing-identifier-regex-shape"}, shapes


def test_uco_shapes_do_target_the_claims(uco):
    # Without owl:hasValue applied, claims lack core:isDirectional, so UCO's Relationship shape must fail.
    ok, report = check(aligned_slice(apply_has_value=False), uco)
    assert not ok and "isDirectional" in report


def test_uco_rejects_a_relationship_without_a_uco_object_target(uco):
    g = aligned_slice()
    claim = DATA["claim_AC-02_T1556.009"]
    g.remove((claim, ONT.claimObjectTechnique, None))
    g.add((claim, URIRef(UCO + "target"), Literal("T1556.009")))
    ok, report = check(g, uco)
    assert not ok and "target" in report


def test_uco_module_imports_the_pinned_uco_version():
    g = Graph().parse(ROOT / "ontology" / "alignment-uco.ttl")
    assert URIRef(UCO + "1.5.0") in set(g.objects(None, OWL.imports))
    vendored = Graph().parse(gates.UCO_CORE)
    assert (URIRef(UCO.rstrip("/")), OWL.versionIRI, URIRef(UCO + "1.5.0")) in vendored


@pytest.mark.parametrize(
    "module,annotation,terms",
    [
        ("stix", "stixObjectType", ["AttackTechnique", "Tactic", "AttackMitigation", "SecurityControl", "MitigationClaim"]),
        ("stix", "stixRelationshipType", ["subTechniqueOf", "attackMitigationFor", "MitigationClaim"]),
        ("stix", "stixProperty", ["stixId", "techniqueId", "inTactic", "targetsPlatform", "inAttackEnterprise"]),
        ("oscal", "oscalAssembly", ["SecurityControl", "CapabilityGroup", "ControlBaseline"]),
        ("oscal", "oscalPath", ["oscalControlId", "controlId", "controlTitle", "oscalFamilyTitle", "inBaseline"]),
    ],
)
def test_alignment_modules_annotate_their_terms(module, annotation, terms):
    g = Graph().parse(ROOT / "ontology" / f"alignment-{module}.ttl")
    core = Graph().parse(gates.CORE)
    for term in terms:
        assert (ONT[term], None, None) in core, f"{term} is not defined in core.ttl"
        assert g.value(ONT[term], ONT[annotation]) is not None, f"{term} lacks {annotation}"


def test_every_technique_tactic_and_mitigation_in_attack_has_a_stix_id():
    g = gates.graph(gates.CORE)
    attack = DATA["catalogue_attack-enterprise-16.1"]
    tactics = [n for n in g.subjects(RDF.type, ONT.Tactic) if (n, ONT.inCatalogue, attack) in g]
    assert len(tactics) == 14 and all(g.value(n, ONT.stixId) for n in tactics)
    assert all(g.value(n, ONT.stixId) for n in g.subjects(RDF.type, ONT.AttackMitigation))
    for t in g.subjects(ONT.inAttackEnterprise, Literal(True)):
        assert str(g.value(t, ONT.stixId)).startswith("attack-pattern--")
