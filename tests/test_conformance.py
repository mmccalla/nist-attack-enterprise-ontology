"""Data conformance gate: the 2.0.0 population conforms to ontology/shapes.ttl, the shapes reject bad data,
and the generated files are in step with the pinned sources."""

import re
import subprocess
import sys
from pathlib import Path

import pytest
from pyshacl import validate
from rdflib import Graph, Literal
from rdflib.namespace import PROV, RDF

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import gates  # noqa: E402
from gates import DATA, ONT  # noqa: E402


@pytest.fixture(scope="module")
def shapes():
    return Graph().parse(gates.SHAPES)


def check(data, shapes):
    ok, _, report = validate(data, shacl_graph=shapes, advanced=True, allow_warnings=True)
    return ok, report


def test_population_is_up_to_date_with_the_pinned_sources():
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_population.py"), "--check"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_full_population_conforms_with_one_known_warning(shapes):
    ok, report = check(gates.graph(gates.CORE), shapes)
    assert ok, report
    warnings = re.findall(r"Value Node: (\S+)", report)
    assert warnings == ["data:technique_T1521.003"], report


@pytest.fixture()
def sample():
    g = gates.reasoning_slice()
    g.parse(gates.CORE)
    return g


def test_slice_conforms(sample, shapes):
    assert check(sample, shapes)[0]


# Negative probes. Each breaks one rule; validation must fail with that rule's message.
PROBES = {
    "capability group differs from the control's": (
        lambda g: g.set((DATA["assertion_AC-02_T1556.009"], ONT.assertsCapabilityGroup, ONT.capabilityGroup_SI)),
        "capability group must match",
    ),
    "claim supported by a row about another pair": (
        lambda g: g.add((DATA["claim_AC-02_T1556.009"], ONT.supportedByAssertion, DATA["assertion_IA-02_T1078"])),
        "same control and technique",
    ),
    "claim on a technique outside ATT&CK Enterprise": (
        lambda g: [g.add((DATA["claim_SC-12_T1521.003"], RDF.type, ONT.MitigationClaim)),
                   g.add((DATA["claim_SC-12_T1521.003"], ONT.claimSubjectControl, DATA["control_SC-12"])),
                   g.add((DATA["claim_SC-12_T1521.003"], ONT.claimObjectTechnique, DATA["technique_T1521.003"])),
                   g.add((DATA["claim_SC-12_T1521.003"], ONT.supportedByAssertion, DATA["assertion_SC-12_T1521.003"])),
                   g.add((DATA["control_SC-12"], ONT.mitigatesTechnique, DATA["technique_T1521.003"]))],
        "only name a technique that is active",
    ),
    "mitigates row with no claim (rule R1)": (
        lambda g: g.remove((DATA["claim_AC-02_T1556.009"], ONT.supportedByAssertion, None)),
        "must support a mitigation claim",
    ),
    "direct relation without a claim": (
        lambda g: g.add((DATA["control_AC-02"], ONT.mitigatesTechnique, DATA["technique_T1001"])),
        "backed by a mitigation claim",
    ),
    "claim without the direct relation": (
        lambda g: g.remove((DATA["control_AC-02"], ONT.mitigatesTechnique, DATA["technique_T1556.009"])),
        "must be materialised",
    ),
    "non-mappable row with a control": (
        lambda g: g.add((DATA["nonmappable_T1656"], ONT.assertsControl, DATA["control_AC-02"])),
        "Result Path: :assertsControl",
    ),
    "non-mappable row with a mapping type (v2 modelling)": (
        lambda g: g.add((DATA["nonmappable_T1656"], ONT.assertedMappingType, ONT.mappingType_nonMappable)),
        "Result Path: :assertedMappingType",
    ),
    "duplicate source record number": (
        lambda g: g.set((DATA["assertion_IA-02_T1078"], ONT.sourceRecordNumber, Literal(98))),
        "share a source record number",
    ),
    "row without provenance": (
        lambda g: g.remove((DATA["assertion_IA-02_T1078"], PROV.wasDerivedFrom, None)),
        "Result Path: prov:wasDerivedFrom",
    ),
    "malformed technique id": (
        lambda g: g.set((DATA["technique_T1078"], ONT.techniqueId, Literal("T78"))),
        "Result Path: :techniqueId",
    ),
    "OSCAL id that does not match the control id": (
        lambda g: g.set((DATA["control_AC-02"], ONT.oscalControlId, Literal("ac-3"))),
        "lower-case, unpadded form",
    ),
    "Enterprise technique without a tactic": (
        lambda g: g.remove((DATA["technique_T1078"], ONT.inTactic, None)),
        "at least one tactic",
    ),
    "Enterprise technique without its catalogue": (
        lambda g: g.remove((DATA["technique_T1078"], ONT.inCatalogue, None)),
        "and its catalogue",
    ),
    "control without its framework": (
        lambda g: g.remove((DATA["control_AC-02"], ONT.inFramework, None)),
        "Result Path: :inFramework",
    ),
    "revoked technique record without a replacement": (
        lambda g: g.remove((DATA["laterversion_T1070.001_20.0"], ONT.laterId, None)),
        "replacement of a revoked technique",
    ),
    "later-version record in the same catalogue as its technique": (
        lambda g: g.set((DATA["laterversion_T1070.001_20.0"], ONT.inCatalogue, DATA["catalogue_attack-enterprise-16.1"])),
        "different catalogue",
    ),
    "sub-technique whose parent is not its ID prefix": (
        lambda g: g.set((DATA["technique_T1556.009"], ONT.subTechniqueOf, DATA["technique_T1078"])),
        "parent whose id is the prefix",
    ),
}


@pytest.mark.parametrize("name", PROBES)
def test_shapes_reject(name, sample, shapes):
    mutate, expected = PROBES[name]
    mutate(sample)
    ok, report = check(sample, shapes)
    assert not ok and expected in report, report[:2000]
