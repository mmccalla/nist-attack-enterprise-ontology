"""Copy gate: user-facing text describes what the tool does. It does not say that the tool is unique, first or the only one.

On 2026-11-04 the owner found two other tools that make gap lists from ATT&CK data (A2Z ATT&CK heatmap, threatengine.sh), and
no check of all Mappings Explorer features was done. A claim of uniqueness is not verified, so copy must not make one.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COPY = ["README.md", "llms.txt", "src/viewer.html", "docs/api.md", "exports/README.md", "CITATION.cff", "SECURITY.md", "CONTRIBUTING.md", "NOTICE.md"]
COPY += [p.relative_to(ROOT).as_posix() for p in (ROOT / "docs").glob("*.md") if p.name not in ("retrospective.md",)]
CLAIM = re.compile(
    r"\b(unique(ly)?|one[- ]of[- ]a[- ]kind|first (free |open |public )?(tool|site|resource|of its kind)|the only (free |open )?(tool|site|resource|place|way)"
    r"|only (free |open )?(tool|site|resource) (that|to|which)|no other (tool|site|resource|project)|nothing else (does|offers|gives)"
    r"|not available (anywhere )?else(where)?|unlike (any|other|existing) (tool|site|resource)s?|best[- ]in[- ]class|unmatched|unrivalled)\b",
    re.I,
)
# Technical uses of the word that make no claim about other tools.
ALLOWED = re.compile(r"record-number uniqueness|uniqueness grouped|unique (id|key|identifier|pair|row|value)s?", re.I)


def test_copy_makes_no_claim_of_uniqueness():
    found = []
    for name in sorted(set(COPY)):
        for n, line in enumerate((ROOT / name).read_text(encoding="utf-8").splitlines(), 1):
            for m in CLAIM.finditer(line):
                if not ALLOWED.search(line[max(0, m.start() - 30): m.end() + 30]):
                    found.append(f"{name}:{n}: {line[max(0, m.start() - 40): m.end() + 40].strip()}")
    assert not found, "Describe what the tool does instead:\n" + "\n".join(found)


def test_the_gate_finds_a_claim():
    assert CLAIM.search("This is the only free tool that maps controls.") and CLAIM.search("What is unique: the graph.")
    assert not CLAIM.search("The gap analysis reads control IDs or an OSCAL SSP.")
