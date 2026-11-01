# Changelog

Repository releases are numbered separately from the ontology version (`owl:versionInfo` in `ontology/core.ttl`).

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
