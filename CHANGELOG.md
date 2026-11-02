# Changelog

Repository releases are numbered separately from the ontology version (`owl:versionInfo` in `ontology/core.ttl`).

## 2.2.0 (2026-11-02)

Ontology 2.1.0 (backward compatible with 2.0.0).

- **ATT&CK version reconciliation.** Each technique that ATT&CK 20.0 revokes, renames or moves to other tactics has a later-version record, matched by STIX id. Technique pages show the change. New questions CQ14 and CQ15 and the export `exports/attack-16.1-to-20.0.csv`.
- **Catalogues and frameworks** in the model, ready for ATLAS and CIS.
- **One gap-analysis implementation** in `lib/coverage.cjs`, used by the browser and the exports, with unit tests.
- **Security baseline**: threat model and controls in `docs/security.md`, `SECURITY.md`, a Content Security Policy that blocks all network access from the page, XSS probes with poisoned data, hash-locked dependencies, Dependabot and supply-chain tests.
- Roadmap in `docs/roadmap.md`.

## 2.1.0 (2026-11-01)

Ontology 2.0.0, unchanged.

- **Gap analysis** in the browser: paste NIST 800-53 control ids, start from a baseline, or load an OSCAL SSP, component definition, profile or catalog. See covered techniques, gaps a mapped control would close, techniques with no mapped control, coverage per tactic and the controls that would close the most gaps. Nothing leaves the page. The selection is kept in the address bar for sharing.
- **ATT&CK Navigator layers** (format 4.5) from the gap analysis, from every control and baseline page, and as static files in `exports/navigator/`.
- **CSV exports**: `exports/claims.csv`, `techniques.csv`, `controls.csv` and every competency answer in `exports/questions/`, plus download buttons on each question.
- `CITATION.cff`, `CONTRIBUTING.md`, issue templates and a draft report of source findings for CTID (`docs/upstream-findings.md`).

## 2.0.0 (2026-11-01)

Ontology 2.0.0: competency questions, alignment to UCO, ATT&CK STIX and NIST OSCAL, full population from pinned sources, evaluation gates. Not backward compatible with 1.0.0: non-mappable rows carry a status instead of a mapping type. See `docs/semantic-decisions.md`.

## 1.0.0 (2026-11-01)

First publication of the uploaded v2 bundle with a graph browser. Kept unchanged in `ontology/v2/`.
