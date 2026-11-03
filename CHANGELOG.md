# Changelog

Repository releases are numbered separately from the ontology version (`owl:versionInfo` in `ontology/core.ttl`).

## 2.6.0 (2026-11-03)

Ontology 2.3.0, unchanged. Licence and attribution release.

- **Notices**: `NOTICE.md` gives the exact copyright notice, licence and changes for each source. `LICENSES/` holds the full texts (Apache 2.0, the ATT&CK terms of use for 16.1 and for 19.1 and 20.0, ISC for D3). Each API file links to the notices (`links.notices`). Each Navigator layer holds the ATT&CK notice for its version. The page has a Notices link and the D3 licence text. Tests examine all of this.
- **CIS text**: a CIS title inside the CTID rationale (one row) is replaced by a marker, and the title slugs are removed from CIS URLs. The licence test now finds titles in any letter case, inside other text and as slugs.
- **CSA CCM**: no CSA content. The page links to the CTID CSA CCM page. Each technique page and API file links to the CTID page for the technique (`ctid_url`).
- The CIS gap analysis states that it does not assess compliance with the CIS Controls.

## 2.5.0 (2026-11-02)

Ontology 2.3.0. Read the compatibility notes.

- **CIS Controls 8.1.2**: the CTID mapping to ATT&CK Enterprise 19.1, with 1140 claims on 404 techniques from 70 Safeguards. The file marks the other 82 Safeguards as non_mappable. Techniques in both ATT&CK versions share one node (by STIX id). The 57 techniques that are only in 19.1 have their own nodes, with the 16.1 techniques that they replace.
- **Licence rule for CIS**: CIS licenses the CIS Controls under CC BY-NC-ND 4.0. The graph, API, exports and page keep only Safeguard and Control IDs, links and the CTID rationale. They do not copy CIS titles or text. SHACL and a test enforce this.
- **Gap analysis for CIS**: paste Safeguard numbers and see which ATT&CK 19.1 techniques stay open, with recommendations, a Navigator layer (ATT&CK 19) and CSV files.
- Questions CQ20 to CQ22 compare CIS and NIST. New export `cis-claims.csv` and layer `navigator/cis-all-safeguards.json`. New API endpoint `cis/safeguards/{id}.json`. Technique files have `cis_claims`, `in_attack_19_1` and `replaces`.
- `scripts/verify_upstream_findings.py` verifies each fact in `docs/upstream-findings.md` from the raw sources. The findings are filed as [CTID issue #151](https://github.com/center-for-threat-informed-defense/mappings-explorer/issues/151).
- Fixed: the export check compared text, so CRLF in source fields made it fail. It now compares bytes.

**Compatibility notes**

- `:SecurityControl` now has two subclasses, `:Nist80053Control` and `:CisSafeguard`. A SPARQL query that selects `:SecurityControl` now also gets CIS Safeguards. Select `:Nist80053Control` to get only NIST controls.
- `:SourceAssertion` no longer requires one technique. `:MitigatesAssertion` and `:NonMappableAssertion` require it. `:NonMappableControlAssertion` (CIS) has no technique.
- API: `mapping_status` has the new value `not_in_attack_16_1`, and `versions` has the new field `attack_cis`. A client that rejects unknown enum values must accept the new value. The NIST claims and their counts are the same.

## 2.4.0 (2026-11-02)

Ontology 2.2.0 (backward compatible).

- **MITRE ATLAS 5.6.0**: 16 tactics, 170 techniques and 35 mitigations, with the ATT&CK techniques that ATLAS says it adapts. An "AI agent" flag (derived from names) marks 26 techniques.
- **OWASP GenAI**: the LLM Top 10 (2025) with the 13 ATLAS links that OWASP publishes; the MCP Top 10 (IDs only) and the Agentic Top 10 (list only).
- **Gap analysis for AI systems**: select ATLAS mitigations and see which agent techniques stay open, with recommendations.
- Questions CQ16 to CQ19 for agent builders and LLM developers. New API endpoints (`atlas/techniques`, `atlas/mitigations`, `owasp`) and exports (`atlas-techniques.csv`, `atlas-mitigations.csv`, `owasp-llm-atlas-links.csv`).

## 2.3.0 (2026-11-02)

Ontology 2.1.0, unchanged.

- **Static agent API** in `api/v1/`: one JSON file for each technique, control, tactic, ATT&CK mitigation, baseline and competency question, with `index.json`, `version.json`, JSON Schemas (draft 2020-12) and an OpenAPI 3.1 description. Each file gives its evidence, versions, limits and the fields that hold untrusted upstream text.
- `llms.txt` at the site root and the API guide `docs/api.md`.

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
