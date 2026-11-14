"""Coverage states gate: the per-tactic Gap and No mapped control counts must match
the independently computed values from the raw source data (audit item 5, M9).

This test computes expected values from tests/source_model.py, not from the page
or the build pipeline. It proves the coverage state definitions in tests/test_wording.py
are correctly applied to the real data.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from source_model import sources  # noqa: E402


def test_per_tactic_gap_and_none_counts_from_source_model():
    """Each tactic's Gap and No mapped control counts must match the raw data.

    With no controls selected:
    - Gap: technique has at least one claim (from any control)
    - No mapped control: technique has no claims at all

    These values come from the CTID mapping (src.controls_for) and ATT&CK 16.1
    Enterprise tactics (src.tactics_of). The fixed baseline was computed from
    tests/source_model.py at commit 64badaa.
    """
    src = sources()

    baseline = {
        "TA0043": {"gap": 7, "none": 37},
        "TA0042": {"gap": 0, "none": 47},
        "TA0001": {"gap": 20, "none": 1},
        "TA0002": {"gap": 38, "none": 0},
        "TA0003": {"gap": 108, "none": 12},
        "TA0004": {"gap": 95, "none": 14},
        "TA0005": {"gap": 165, "none": 39},
        "TA0006": {"gap": 63, "none": 4},
        "TA0007": {"gap": 15, "none": 31},
        "TA0008": {"gap": 22, "none": 1},
        "TA0009": {"gap": 27, "none": 13},
        "TA0011": {"gap": 39, "none": 3},
        "TA0010": {"gap": 18, "none": 1},
        "TA0040": {"gap": 26, "none": 6},
    }

    computed = {}
    for tactic_id in sorted(src.tactic_names):
        if not tactic_id.startswith("TA"):
            continue
        gap = 0
        none = 0
        for tid in src.techniques:
            if tactic_id in src.tactics_of[tid]:
                if src.controls_for.get(tid):
                    gap += 1
                else:
                    none += 1
        computed[tactic_id] = {"gap": gap, "none": none}

    assert set(computed) == set(baseline), "tactic set mismatch"
    for tactic_id in baseline:
        exp = baseline[tactic_id]
        got = computed[tactic_id]
        assert got["gap"] == exp["gap"], f"{tactic_id}: gap={got['gap']}, expected {exp['gap']}"
        assert got["none"] == exp["none"], f"{tactic_id}: none={got['none']}, expected {exp['none']}"

    techniques_with_claims = len([t for t in src.techniques if src.controls_for.get(t)])
    techniques_without_claims = len([t for t in src.techniques if not src.controls_for.get(t)])
    assert techniques_with_claims == 469, f"expected 469 techniques with claims, got {techniques_with_claims}"
    assert techniques_without_claims == 187, f"expected 187 techniques without claims, got {techniques_without_claims}"
    assert techniques_with_claims + techniques_without_claims == len(src.techniques)
