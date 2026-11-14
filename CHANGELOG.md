# Changelog

Repository releases are numbered separately from the ontology version (`owl:versionInfo` in `ontology/core.ttl`).

## 2.8.3

Tests only. No product change.

- New test: each NIST claim's source_record matches the raw CTID row. The test loads the raw CTID file directly and verifies its SHA-256 digest against the manifest.
- New test: all 22 CQ answers (CSV and page JSON) match the SPARQL query results. The test loads the graph with the alignment modules and runs the same queries that the build runs.
- New test: each alignment annotation value matches the STIX 2.1 or OSCAL specification.
- New test: the 109 mapped controls, 11 families and 208 changed techniques come from the raw source files, not from data the build writes.
- New test: the per-tactic coverage states (Covered, Gap, No mapped control) in the built API match the values that the source model computes. Also tests the Covered column with the MODERATE baseline.

## 2.8.1 (2026-11-11)

Ontology 2.4.0, unchanged. Wording and trust release: the data, the claims and the API structure do not change. The spec and the source evidence are in `docs/spec-2.8.1.md`.

- Fixed: "Covered" now says that at least one of your controls is mapped as able to mitigate the technique. It no longer says that the control mitigates it. The page shows the same definitions as the README. A test keeps them the same.
- Fixed: "No mapped control" said that more NIST controls cannot cover the technique. Controls outside the mapping can still help. It now says that this does not mean that no defence exists.
- Fixed: the gap-analysis note said "No control in this mapping can cover them." It now says "is mapped to them" to agree with the README coverage table.
- Fixed: the README said that ATT&CK and NIST 800-53 do not describe attacks on AI agents. This is true for ATT&CK 16.1, the version of the mapping. But ATT&CK 20.1 has techniques such as T1698 Indirect Prompt Injection and T1699 Direct Prompt Injection. The README now says both. A test reads both ATT&CK bundles.
- Fixed: the README said that no published mapping exists from ATLAS to NIST 800-53. It now says that CTID Mappings Explorer publishes none on 2026-11-11, with a link.
- Each "newest release" statement has the date of the check. The date is stored once in the build (`newestCheckedOn` in `data/source-checks.json`).
- New: a trust statement at the top of the README. It says that each claim shows its CTID source row. It also says that the build checks each downloaded source against a pinned SHA-256 digest. Possible gaps in the CTID mapping are filed as CTID issue #151.
- Fixed: `SOURCE-MANIFEST.md` did not list `data/sources/cis-controls-8.1.2.json` or `data/sources/owasp-mcp-top10.json`, and gave an old digest for `data/sources/owasp-genai.json`. A test now compares each file in `data/sources/` with the manifest.
- New test: the release number and date agree in `CITATION.cff`, the changelog, the API and `llms.txt`.
- Fixed: the README and the page said that the mapping "uses an older Rev. 5 release" to explain three title differences. CTID's file names only "rev5". Catalog 5.2.0 changes no title of the 109 mapped controls, and adds one base control, SA-24, which the mapping does not cover. The three differences come from Rev. 4 wording (SC-32, CA family) and letter case (IA-08). A test checks the new text against both pinned catalogs.

## 2.8.0 (2026-11-08)

Ontology 2.4.0 (backward compatible): adds `:relatedAtlasIdNotInCatalogue`.

- **MITRE ATLAS 2026.10**, read from MITRE's format 6 file (`dist/v6/ATLAS-2026.10.yaml`). Until now the tool read the legacy `dist/ATLAS.yaml`, which MITRE left at version 5.6.0. ATLAS 2026.10 has 129 techniques, 92 sub-techniques, 44 mitigations and 16 tactics, as MITRE's release notes state. A test checks these counts.
- AI agent figures (agent flag derived by this project): 39 agent techniques, 8 with no direct ATLAS mitigation link, 4 with none on the technique or its parent (ATLAS 5.6.0: 26, 19 and 14). The README, page, API and CQ16 to CQ19 give the version and say that no link does not mean no mitigation.
- OWASP links LLM02:2025 to three ATLAS IDs that ATLAS 2026.10 no longer has (AML.T0024.000, .001 and .002). The tool keeps them as OWASP published them and marks them (`related_atlas_not_in_atlas` in the API, `in_atlas_2026_10` in the export). It does not map them to new IDs.
- ATLAS maturity values are kept as ATLAS writes them: Feasible, Demonstrated and Realized.
- **ATT&CK 20.1** is the later version for the comparison (released on 2026-11-05). The export is renamed to `attack-16.1-to-20.1.csv`, with columns for 20.1. The 208 changed techniques are the same as in 20.0.
- API: new field `versions.atlas`. The ATLAS limit statement names the release from the data.
- Fixed: combined answer cells were split on spaces, so CQ17 showed the ATLAS category "Technical - AI" as "- AI Technical". They are now split on the query's own separator, and CQ09 record numbers are sorted too.
- Fixed: the CQ19 answer said "7 of the 10 risks" and "13 techniques". The data gives 6 risks and 12 techniques (13 links).
- Fixed: the export guide did not list seven of the export files.
- New tests: ATLAS counts against MITRE's release notes, the figures in the README and the competency answers recomputed from the data, each pinned source listed in `SOURCE-MANIFEST.md`, each export file listed in the export guide, and iCloud copies inside `.git`.
- Security: two-factor authentication on the maintainer account is confirmed by the owner (IA-02).

## 2.7.0 (2026-11-04)

Ontology 2.3.0, unchanged.

- **CIS Controls 8.1.2 text**: the exact Safeguard and Control titles, asset classes, security functions and Implementation Groups from the CIS workbook, under CC BY-NC-ND 4.0, in `data/sources/cis-controls-8.1.2.json`. The page, the `cis_text` part of each Safeguard API file and `exports/cis-8.1.2-safeguards.csv` show them with the CIS notice. The graph and the claims stay IDs only.
- **Implementation Groups**: "Start from IG1, IG2 or IG3" in the CIS gap analysis, with no file needed.
- **CIS guidance for AI**: each Safeguard page, Safeguard API file (`cis_text.ai_guidance`) and `cis-8.1.2-safeguards.csv` has CIS's own guidance for AI LLM systems, AI agents and MCP, from the CIS Controls v8.1.2 AI Guidance workbook. The AI gap analysis points to it.
- **OWASP MCP Top 10 titles**: the exact 2025 titles and item links (CC BY-NC-SA 4.0) in `data/sources/owasp-mcp-top10.json`, the page and the API (`title_licence`).
- **Your own CIS file**: the CIS gap analysis reads a CIS Controls XLSX or CSV from the user's device, for users of another CIS version. The file stays on the device, in memory only. When it is loaded, the page uses it alone and does not mix it with the 8.1.2 data.
- The CTID rationale and the CIS reference URLs are no longer changed. CTID writes five Safeguard titles differently from CIS (CIS-3.11, 12.5, 12.7, 13.5 and 16.1). The tool uses the CIS titles.
- CI runs on GitHub on each push: Python 3.14 (the version of the hash lock), and the JavaScript test files are passed by name.

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
