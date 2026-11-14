"""Coverage states gate: the per-tactic Covered, Gap and No mapped control counts
in the product output must equal the values that the source model computes
from the raw CTID and ATT&CK data (audit item 5).

This test reads the built API files (api/v1/tactics/*.json and
api/v1/techniques/*.json) and compares them with independently computed
values from tests/source_model.py.
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
API_TACTICS = ROOT / "api" / "v1" / "tactics"
API_TECHNIQUES = ROOT / "api" / "v1" / "techniques"

sys.path.insert(0, str(ROOT / "tests"))
from source_model import sources


@pytest.fixture(scope="module")
def src():
    return sources()


@pytest.fixture(scope="module")
def api_techniques():
    """Load all technique files from the built API."""
    out = {}
    for path in API_TECHNIQUES.glob("*.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        out[doc["id"]] = doc
    return out


@pytest.fixture(scope="module")
def api_tactics():
    """Load all tactic files from the built API."""
    out = {}
    for path in API_TACTICS.glob("*.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        out[doc["id"]] = doc
    return out


def test_per_tactic_coverage_states_match_source_model(src, api_tactics, api_techniques):
    """Each tactic's per-technique coverage states must match the source model.

    With no controls selected:
    - Gap: technique has at least one claim (from any control)
    - No mapped control: technique has no claims at all

    This test reads the product output (api/v1/tactics and api/v1/techniques)
    and computes the coverage states from that, then compares with the same
    computation from source_model.
    """
    enterprise_tactics = [t for t in api_tactics.values() if t["id"].startswith("TA")]
    assert len(enterprise_tactics) == 14, "expected 14 ATT&CK Enterprise tactics"

    for tactic in enterprise_tactics:
        tactic_id = tactic["id"]
        techniques_in_tactic = tactic["techniques"]

        api_gap = 0
        api_none = 0
        for tid in techniques_in_tactic:
            tech = api_techniques.get(tid)
            if tech and tech.get("in_attack_enterprise"):
                has_claims = tech["mapping_status"] == "claims"
                if has_claims:
                    api_gap += 1
                else:
                    api_none += 1

        src_gap = 0
        src_none = 0
        for tid in src.techniques:
            if tactic_id in src.tactics_of[tid]:
                if src.controls_for.get(tid):
                    src_gap += 1
                else:
                    src_none += 1

        assert api_gap == src_gap, f"{tactic_id}: API gap={api_gap}, source_model gap={src_gap}"
        assert api_none == src_none, f"{tactic_id}: API none={api_none}, source_model none={src_none}"


def test_covered_state_with_moderate_baseline(src, api_tactics, api_techniques):
    """With the MODERATE baseline selected, each tactic's Covered count must match.

    Covered: technique has at least one claim from a selected control.
    Gap: technique has claims, but none from a selected control.
    No mapped control: technique has no claims at all.
    """
    moderate_controls = src.baselines["MODERATE"]
    moderate_control_ids = {c for c, oscal in src.oscal.items() if oscal["id"] in moderate_controls}

    enterprise_tactics = [t for t in api_tactics.values() if t["id"].startswith("TA")]

    for tactic in enterprise_tactics:
        tactic_id = tactic["id"]

        api_covered = 0
        api_gap = 0
        api_none = 0
        for tid in tactic["techniques"]:
            tech = api_techniques.get(tid)
            if tech and tech.get("in_attack_enterprise"):
                has_claims = tech["mapping_status"] == "claims"
                if not has_claims:
                    api_none += 1
                else:
                    claim_controls = {c["control"]["id"] for c in tech.get("claims", [])}
                    if claim_controls & moderate_control_ids:
                        api_covered += 1
                    else:
                        api_gap += 1

        src_covered = 0
        src_gap = 0
        src_none = 0
        for tid in src.techniques:
            if tactic_id in src.tactics_of[tid]:
                controls = src.controls_for.get(tid, set())
                if not controls:
                    src_none += 1
                elif controls & moderate_control_ids:
                    src_covered += 1
                else:
                    src_gap += 1

        assert api_covered == src_covered, f"{tactic_id} MODERATE: API covered={api_covered}, source={src_covered}"
        assert api_gap == src_gap, f"{tactic_id} MODERATE: API gap={api_gap}, source={src_gap}"
        assert api_none == src_none, f"{tactic_id} MODERATE: API none={api_none}, source={src_none}"


def test_technique_claim_counts_match_source_model(src, api_techniques):
    """Each technique's claim count must match the source model."""
    for tid, tech in api_techniques.items():
        if not tech.get("in_attack_enterprise"):
            continue
        api_controls = len({c["control"]["id"] for c in tech.get("claims", [])})
        src_controls = len(src.controls_for.get(tid, set()))
        assert api_controls == src_controls, f"{tid}: API has {api_controls} controls, source has {src_controls}"
