"""Logical consistency gate (OWL 2 DL, HermiT). Needs Java; without it the gate fails rather than skips."""

import shutil
import sys
from pathlib import Path

import pytest
from rdflib import Graph, Literal
from rdflib.namespace import RDF

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import gates  # noqa: E402
from gates import DATA, ONT  # noqa: E402

TBOX = [gates.CORE, *gates.ALIGNMENTS, gates.UCO_CORE]


def test_java_is_available():
    assert shutil.which("java"), "HermiT needs a Java runtime"


def test_tbox_with_all_alignments_is_consistent_and_every_class_satisfiable():
    result = gates.hermit(gates.graph(*TBOX, population=False))
    assert result == {"consistent": True, "unsatisfiable": []}


def test_full_population_is_consistent_under_the_reasoning_profile():
    result = gates.hermit(gates.reasoning_profile(gates.graph(*TBOX)), timeout=900)
    assert result["consistent"] and result["unsatisfiable"] == []


def chain_slice() -> Graph:
    """One closed claim chain and one non-mappable row, with the full TBox including number restrictions.
    Closed means every object is a literal, a vocabulary individual or another node of the slice: each extra
    technique individual would bring its own number restrictions into the tableau."""
    full = gates._population()
    keep = {DATA["claim_AC-02_T1556.009"], DATA["assertion_AC-02_T1556.009"], DATA["control_AC-02"],
            DATA["technique_T1556.009"], DATA["nonmappable_T1656"], DATA["technique_T1656"], DATA.sourceDataset}
    g = gates.graph(*TBOX, population=False)
    for s, p, o in full:
        if s in keep and (isinstance(o, Literal) or o in keep or str(o).startswith(str(ONT))):
            g.add((s, p, o))
    return g


def test_chain_slice_is_consistent_with_the_full_tbox():
    assert gates.hermit(chain_slice())["consistent"]


def test_property_chain_infers_the_direct_relation():
    g = chain_slice()
    g.remove((None, ONT.mitigatesTechnique, None))
    result = gates.hermit(g, infer_property_values=True)
    assert [str(DATA["control_AC-02"]), str(DATA["technique_T1556.009"])] in result["mitigates"]


# Negative probes: each must make the ontology inconsistent.

def test_rejects_an_individual_that_is_both_control_and_technique():
    g = gates.reasoning_profile(gates.graph(*TBOX))
    g.add((DATA["control_AC-02"], RDF.type, ONT.AttackTechnique))
    assert not gates.hermit(g, timeout=900)["consistent"]


def test_rejects_a_technique_used_as_a_control_through_domain_and_range():
    g = chain_slice()
    g.add((DATA["technique_T1656"], ONT.inCapabilityGroup, ONT.capabilityGroup_AC))
    assert not gates.hermit(g)["consistent"]


def test_rejects_a_non_mappable_row_that_names_a_control():
    g = chain_slice()
    g.add((DATA["nonmappable_T1656"], ONT.assertsControl, DATA["control_AC-02"]))
    assert not gates.hermit(g)["consistent"]


def test_rejects_a_claim_that_is_also_a_source_assertion():
    g = chain_slice()
    g.add((DATA["claim_AC-02_T1556.009"], RDF.type, ONT.MitigatesAssertion))
    assert not gates.hermit(g)["consistent"]
