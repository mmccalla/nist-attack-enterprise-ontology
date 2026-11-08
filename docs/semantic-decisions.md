# Scope, semantic inventory and decisions

This file holds the Stage 1 to 3 deliverables of the method in *A Practical Guide to Ontology Engineering*: the scope statement, the semantic inventory, the ambiguity register and the semantic decision log. Vocabulary reuse (Stage 4) is in [vocabulary-alignment.md](vocabulary-alignment.md). Competency questions are in [competency-questions.md](competency-questions.md). Gates and results (Stage 8) are in [evaluation.md](evaluation.md).

## Scope statement

**Purpose.** Answer questions that software engineers, security architects, GRC analysts, threat-informed defence analysts, auditors and data stewards ask about how NIST SP 800-53 Rev. 5 controls relate to MITRE ATT&CK Enterprise techniques, with every answer traceable to a published source.

**In scope.** Base controls and families of SP 800-53 Rev. 5; the SP 800-53B baselines; ATT&CK Enterprise 16.1 techniques, sub-techniques, tactics, platforms and mitigations; the CTID NIST 800-53 Rev. 5 to ATT&CK 16.1 mapping rows; the enterprise claims interpreted from those rows; provenance to the exact source files.

**Out of scope.** Control enhancements (the mapping source has none); implemented controls in a particular system (an SSP or assessment concern, OSCAL SSP and assessment layers); ATT&CK groups, software, campaigns and detections; ATT&CK Mobile and ICS; effectiveness scores. Each would need its own competency questions before it is modelled.

**Users.** Software engineers, security architects, GRC analysts, threat-informed defence analysts, auditors and data stewards. The personas are named on each competency question.

## Source inventory

| Source | Version | Pinned file | Role |
| --- | --- | --- | --- |
| CTID Mappings Explorer, NIST 800-53 Rev. 5 to ATT&CK 16.1 Enterprise | last update 04/16/2025 | `mappings-explorer@6bdc3ad` | The mapping rows (source assertions) |
| MITRE ATT&CK Enterprise STIX 2.1 bundle | 16.1 | `attack-stix-data@7eb3ca5` | Technique identity, names, tactics, platforms, sub-technique links, ATT&CK mitigations |
| NIST OSCAL SP 800-53 Rev. 5 catalog | 5.2.0 | `oscal-content@5006f18` | Control identity, titles, families |
| NIST OSCAL SP 800-53B baseline profiles | 5.2.0 | `oscal-content@5006f18` | LOW, MODERATE, HIGH and PRIVACY membership |
| UCO core | 1.5.0 | `vendor/uco/core.ttl` | Upper alignment for relationships and assertions |

Every file is checked against a SHA-256 digest in `scripts/build_population.py` before use. The digests are also in `data/source-checks.json` and on each dataset node in the graph.

## Semantic inventory

How each source term is interpreted. The guide warns against converting source columns into classes mechanically; the right-hand column records the decision for each.

| Source term | Source | Interpretation | Ontology term |
| --- | --- | --- | --- |
| mapping object (row) | CTID | A statement by the publisher, kept as stated | `:SourceAssertion` |
| `status` = complete | CTID | The row maps a control to a technique | `:assertedStatus :mappingStatus_complete` |
| `status` = non_mappable | CTID | The publisher found no control for the technique | `:NonMappableAssertion`, `:mappingStatus_nonMappable` |
| `mapping_type` = mitigates | CTID | The kind of mapping; null on non-mappable rows | `:assertedMappingType :mappingType_mitigates` |
| `capability_id` | CTID | A base control, zero-padded (AC-02) | `:SecurityControl`, `:controlId` |
| `capability_description` | CTID | The control **title**, not a description | compared with `:controlTitle`; kept as `:sourceControlTitle` where it differs |
| `capability_group` | CTID | A control family | `:CapabilityGroup` |
| `attack_object_id`, `attack_object_name` | CTID | An ATT&CK technique and its name | `:AttackTechnique`, `:techniqueName` |
| `comments` | CTID | Free-text rationale on 10 rows | `:rationaleText` |
| `references` | CTID | Citations; empty on every row | `:hasReference` (no data) |
| `attack-pattern` | STIX | A technique or sub-technique | `:AttackTechnique`, `:stixId` |
| `x-mitre-tactic`, `kill_chain_phases` | STIX | The tactics a technique serves | `:Tactic`, `:inTactic` |
| `subtechnique-of` | STIX | Parent technique | `:subTechniqueOf` (a `skos:broader`) |
| `course-of-action` (Mxxxx), `mitigates` | STIX | ATT&CK's own mitigation guidance | `:AttackMitigation`, `:attackMitigationFor` |
| `x_mitre_platforms` | STIX | Platforms a technique applies to | `:Platform`, `:targetsPlatform` |
| catalog `control`, `label` (zero-padded) | OSCAL | Authoritative control identity and title | `:oscalControlId`, `:controlTitle` |
| catalog `group` (class family) | OSCAL | Authoritative family title | `:oscalFamilyTitle` |
| profile `include-controls` | OSCAL | Baseline membership | `:ControlBaseline`, `:inBaseline` |

## Ambiguity register

| # | Ambiguity | Resolution |
| --- | --- | --- |
| A1 | Is a control a definition in the catalogue or a control implemented in a system? | A definition. Implementation belongs to an SSP or assessment and is out of scope. Recorded in the `:SecurityControl` definition. |
| A2 | Is "non_mappable" a mapping type or a status? | A status. The source sets `status` to non_mappable and leaves `mapping_type` null. v2 modelled it as a mapping type; 2.0.0 corrects this (D3). |
| A3 | Does a non-mappable row mean no control exists? | No. It records what the publisher found. Under open-world semantics the graph cannot conclude absence. CQ05 shows that ATT&CK lists substantive mitigations for 3 of the 96 techniques. |
| A4 | Does `capability_description` describe the control? | No. Its values are titles (Account Management). See D4. |
| A5 | Are two identical rows one assertion or two? | Two. The source repeats 50 rows exactly. Each row stays a separate assertion with its own record number, and both support one claim. CQ09 lists them. See D5. |
| A6 | Is a "capability group" the same as a control family? | Yes for this source: the 11 codes are SP 800-53 family codes. The CA family uses the Rev. 4 name; OSCAL Rev. 5 calls it Assessment, Authorization, and Monitoring. Both names are kept (CQ13). |
| A7 | Is the CTID "mitigates" the same relation as ATT&CK's own "mitigates"? | No. Different publishers, different subjects (NIST controls against ATT&CK mitigations) and different methods. They are separate properties, `:mitigatesTechnique` and `:attackMitigationFor` (D7). |
| A8 | Should every source row become an enterprise claim? | No. Rule R1 below governs which rows become claims. |
| A9 | Is "non_mappable" a mapping type or a status in the CIS file? | Both. Unlike the NIST file (A2), the CIS file sets `status` and `mapping_type` to non_mappable on its 82 non-mappable rows, and its metadata declares non_mappable as a mapping type. These rows name a Safeguard and no technique. The graph keeps both values as the file states them (D25). |

## Interpretation rule R1

A `:MitigationClaim` exists for each distinct control and technique pair that has at least one source row with status complete and mapping type mitigates, **where the technique is an active technique in the pinned ATT&CK Enterprise bundle**. The claim is supported by every such row. The direct relation `:mitigatesTechnique` holds exactly when a claim exists; `core.ttl` states this as an OWL property chain and the population materialises it.

R1 withholds one claim today: row 637 maps SC-12 to T1521.003 SSL Pinning, which is not an Enterprise technique (the source row itself carries `attack_version` `[UNKNOWN_VERSION]`). The row stays in the graph as a source assertion; SHACL reports it as a warning; CQ08 lists it.

## Decision log

| # | Decision | Rejected alternative and reason |
| --- | --- | --- |
| D1 | Keep the v2 term namespace `.../ontology/1.0#` and record the release in `owl:versionIRI` (`.../ontology/2.0.0`) with `owl:priorVersion`. | Moving terms to a new namespace per release: every consumer query and every stored triple would break on each release. Term IRIs should be stable; versions belong on the ontology. |
| D2 | Keep the `w3id.org/example` namespace. | Registering a real w3id: an organisational decision for the owner, not a modelling one. Listed under limitations. |
| D3 | Add `:MappingStatus` and `:assertedStatus`; deprecate `:mappingType_nonMappable`; relax the mapping type to at most one. Version 2.0.0 because this is not backward compatible. | Keeping non_mappable as a type: contradicts the source (A2). |
| D4 | Add `:controlTitle` from OSCAL; deprecate `:controlDescription`; keep the source wording as `:sourceControlTitle` only where it differs. | Keeping `:controlDescription`: mislabels the data (A4). |
| D5 | One assertion per source row, identified by `:sourceRecordNumber`; IRIs from the pair plus an occurrence suffix (`assertion_CM-02_T1021.001_2`). | Merging identical rows: loses what the source said. Row-number IRIs (v2 `assertion_97`): not stable across source releases. |
| D6 | Build the population from the full source (5410 rows) instead of the v2 sample (250 rows). | Keeping the sample: competency answers over 5 percent of the rows would mislead. The v2 sample stays in `ontology/v2/` unchanged. |
| D7 | Model ATT&CK mitigations and their links as separate terms from NIST controls and claims. | `owl:equivalentClass` between `:SecurityControl` and ATT&CK mitigations, or one shared mitigates property: different concepts and publishers (A7). |
| D8 | Model sub-techniques with `:subTechniqueOf`, a sub-property of `skos:broader`, read from STIX `subtechnique-of`. | `rdfs:subClassOf`: techniques are individuals, and the guide warns against treating SKOS broader as subclass. Deriving the parent from the ID pattern (the v1 viewer did): not authoritative. |
| D9 | Put each external alignment in its own module (`alignment-stix.ttl`, `alignment-oscal.ttl`, `alignment-uco.ttl`). | Folding alignments into `core.ttl`: couples the core to three external release cycles; NeOn favours networked modules. |
| D10 | Keep readable IRIs (`control_AC-02`) rather than UUID IRIs. UCO's `core:UcoThing-identifier-regex-shape` reports them at severity Info, and that shape's own comment allows deactivation where identifiers are controlled. | UUID IRIs: unreadable in the graph browser and in SPARQL, with no competency question that needs them. |
| D11 | Remove the per-node SPARQL constraints from class shapes and run them as whole-graph rules targeting the mapping dataset. | Per-node SPARQL: pySHACL runs it once per focus node; validation took 236 seconds against 22 seconds now. |
| D12 | Deprecate `:KnowledgeGraph`. | Keeping an unused class: the guide lists excessive scope as an anti-pattern. |
| D13 | Reason over the full population with a profile that drops number restrictions and `owl:hasValue` restrictions; reason with the full TBox on a slice (one claim chain and one non-mappable row) and enforce those restrictions with SHACL on the whole population. | Full TBox on the full population: with thousands of rows pointing at the same few vocabulary individuals, HermiT's tableau grew exponentially (30 subjects in 6 seconds, 120 subjects past 90 seconds). Under open-world semantics these restrictions add almost no detectable inconsistency that SHACL does not already catch. Dropping them altogether: they document intent and are tested on the slice. |
| D14 | Give the reasoner OWL only: remove SHACL triples and their blank-node structures before HermiT runs. UCO core's shapes are applied by pySHACL in the alignment gate instead. | Reasoning over UCO core as published: UCO puns each class as a SHACL node shape, and HermiT read those structures as anonymous individuals. The full-population check ran for more than 15 minutes; without the shapes it takes under a minute. |

| D15 | Add `:ThreatCatalogue` and `:ControlFramework` with `:inCatalogue` and `:inFramework`, and superclasses `:AdversaryTechnique` and `:ThreatMitigation` (ontology 2.1.0). | Separate class trees per catalogue: ATLAS and CIS would need copies of every property and shape. |
| D16 | Record what a later ATT&CK version changed as `:LaterVersionRecord` nodes (revoked, renamed, tactics changed), matched by STIX id. Keep the claims on ATT&CK 16.1, the version CTID mapped. | Moving every claim to a later ATT&CK version: that would change what the source says. Matching by tactic ID: since ATT&CK 19.1, TA0005 is Stealth, so tactic ID joins across versions are wrong. (The later version was 20.0 until 2026-11-08 and is 20.1 since then.) |
| D17 | One gap-analysis implementation in `lib/coverage.cjs`, inlined in the page and called from the exports through Node. | Separate JavaScript and Python copies: they can drift, and the MCP server would add a third. |
| D18 | A Content Security Policy with script hashes and `connect-src 'none'`. | No policy: the page would depend on escaping alone. A policy with `unsafe-inline` for scripts: it would not stop injected handlers. |

| D19 | Import MITRE ATLAS as its own catalogue (`:AtlasTechnique`, `:AtlasMitigation`), with technique and mitigation properties widened to every catalogue (ontology 2.2.0). | Typing ATLAS techniques as ATT&CK techniques: they are a different catalogue with different IDs; `owl:disjointWith` now prevents it. |
| D20 | Follow only published cross-references: ATLAS ATT&CK references (`ATT&CK-reference`, `attack-reference` since format 6) (`:derivedFromAttack`) and OWASP "Related Frameworks and Taxonomies" (`:relatedAtlasTechnique`). NIST claims do not transfer from ATT&CK to ATLAS. | Writing project NIST mappings for ATLAS: declined by the owner on 2026-11-02 for the same reason as D16 (claims stay CTID-only). |
| D21 | Derive an "AI agent" flag from ATLAS technique names ("AI Agent", "Agentic") and parents, and label it as derived everywhere. | No flag: agent builders could not filter. A flag presented as ATLAS data: it is not. |
| D22 | OWASP: copy IDs, titles and ATLAS links for the LLM Top 10 (CC BY-SA 4.0, kept in a separate, attributed file); only the list title and link for the Agentic Top 10 (the official document is behind a download form, and secondary sources were not used); only IDs and links for the MCP Top 10 (CC BY-NC-SA 4.0). | Titles from secondary sources: not authoritative. MCP titles: the NonCommercial licence does not permit them in a CC BY project. |
| D23 | Import the CTID CIS Controls 8.1.2 mapping on ATT&CK Enterprise 19.1, the version CTID mapped, and join it to the 16.1 graph by STIX id (release 2.5.0, ontology 2.3.0). A technique that is in both versions is one node. The 57 techniques that are active only in 19.1 get their own nodes with `:inAttackEnterprise` false. `:replacesTechnique` records the 19.1 `revoked-by` links. | Moving the CIS claims to ATT&CK 16.1: that would change what the source says. Joining by ATT&CK ID: IDs can move between versions (D16). |
| D24 | Add `:Nist80053Control` and `:CisSafeguard` as disjoint subclasses of `:SecurityControl`. NIST queries, exports and API files filter on `:Nist80053Control` and on rows derived from the NIST dataset. | One control class for both frameworks: every NIST answer, count and gap analysis would mix in CIS claims. |
| D25 | Keep only CIS Safeguard and Control IDs, links and the CTID rationale (Apache 2.0). Do not copy CIS titles or text. Replace a CIS title of three words or more inside the rationale with `[title of CIS-x.y]`, and remove the title slug after `#` from CIS URLs (2026-11-03). The test searches every output for each such title in any letter case and as a slug. SHACL rejects a `:controlTitle` on a Safeguard and a `:groupName` on a CIS Control, and a test searches every output for the CIS titles. Keep non_mappable as both type and status for CIS rows (A9), in `:NonMappableControlAssertion`. | Copying the titles from the CTID file: CIS licenses the CIS Controls under CC BY-NC-ND 4.0, and this project is CC BY 4.0. The same rule as the OWASP MCP Top 10 (D22). |
| D26 | Do not import the CIS fields `score_category` and `related_score`. They are on 37 of the 1225 rows, and no competency question needs them. | Importing them: no defined meaning in the file metadata, and no user task. |
| D27 | Include no CSA CCM content, not even IDs. Link to the CTID CSA CCM page and to the CTID page for each technique instead. On 2026-11-03 the owner asked for no risk of infringement. | Adding CCM IDs or the CTID mapping: the CSA terms do not permit redistribution or modification of the matrix. |
| D29 | Ship the exact CIS Controls 8.1.2 titles, asset classes, security functions and Implementation Groups from the CIS workbook, in a separate file with its own licence (`data/sources/cis-controls-8.1.2.json`, CC BY-NC-ND 4.0), with the CIS notice wherever they show. Keep them out of the CC BY graph and the claims. Undo the D25 masking of rationale text and URLs (2026-11-04). This replaces the "IDs only" part of D25. | IDs only: the workbook licence permits exact, non-commercial redistribution with credit, so users lost value for no reason. Titles from the CTID file: five differ from the CIS workbook. Paraphrased titles: an adaptation, which ND forbids. |
| D30 | Ship the exact OWASP MCP Top 10 (2025) titles and item links from the OWASP project index at a pinned commit, in a separate file with their own licence (CC BY-NC-SA 4.0). Also ship the CIS 8.1.2 AI LLM, AI Agent and MCP guidance under D29 (2026-11-04). This replaces the MCP part of D22. | IDs only: the NC licence permits exact, non-commercial copies with credit, so users lost value for no reason. Titles from secondary sources: not authoritative. |
| D31 | State ATLAS results with their version and their rules (2026-11-08): the agent flag is a project rule on names; "no mitigation" means no direct link in the pinned ATLAS release; counting a parent's mitigation for a sub-technique is a project rule. With ATLAS 2026.10: 39 agent techniques, 8 without a direct link, 4 with none on the technique or its parent (with ATLAS 5.6.0: 26, 19 and 14). | One figure, "14 have no ATLAS mitigation": it mixed a project rule with ATLAS data, and a reviewer could not reproduce it from the direct links. |
| D32 | Keep an OWASP link to an ATLAS ID that the pinned ATLAS release no longer has, as `:relatedAtlasIdNotInCatalogue`, and show it as not in that release (2026-11-08). With ATLAS 2026.10, this applies to the three LLM02:2025 links to AML.T0024.000, .001 and .002. | Dropping the links: they are what OWASP publishes. Mapping them to the IDs that the ATLAS release notes name: that is a mapping of this project, and the notes are prose, not data. |
| D33 | Pin the newest release of each source, and check each pin against the publisher at each release (2026-11-08). ATLAS is read from its format 6 file for the release (`dist/v6/ATLAS-2026.10.yaml`), not from the legacy `dist/ATLAS.yaml`, which stays at 5.6.0. The later ATT&CK version is 20.1. A test compares the ATLAS counts with MITRE's release notes, and a test recomputes the figures in the README and the competency answers. | Pinning once: ATLAS 5.6.0 stayed in the tool for two releases after MITRE moved to format 6, and ATT&CK 20.1 came out three days after 20.0 was pinned. |
| D28 | Keep a `NOTICE.md` with the exact copyright notice, licence and changes for each source, the full licence texts in `LICENSES/`, and a notices link in each API file, Navigator layer, export guide and page. The ATT&CK notice is in each layer. | A short attribution list: the ATT&CK terms require the copyright designation and the licence in each copy, and Apache 2.0 requires the licence and a statement of changes. |

## Deprecations in 2.0.0

`:mappingType_nonMappable` (replaced by `:mappingStatus_nonMappable`), `:controlDescription` (replaced by `:controlTitle`), `:KnowledgeGraph` (unused). Each carries `owl:deprecated true` and, where there is one, `dcterms:isReplacedBy`.
