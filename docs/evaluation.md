# Evaluation

The Stage 8 deliverable of *A Practical Guide to Ontology Engineering*. The guide asks for separate automated gates for logical consistency, data conformance and factual verification, and for competency coverage measured as expected against actual answers. Each gate below has negative probes: changes that break one rule and must make the gate fail. A gate that cannot run fails; it never passes by default.

## Gates

| Dimension | Gate | Test file | Negative probes |
| --- | --- | --- | --- |
| Logical consistency | HermiT (OWL 2 DL) on the TBox with all alignments and UCO core; on the full population under the reasoning profile (D13); on a slice with the full TBox; the property chain must infer the direct relation | `tests/test_consistency.py` | control typed as technique; technique used as a control through domain and range; non-mappable row naming a control; claim typed as a source assertion |
| Data conformance | SHACL (`ontology/shapes.ttl`) on the full population: no violations, exactly one warning (T1521.003) | `tests/test_conformance.py` | 14 probes, one per rule: family mismatch, claim supported by the wrong row, claim outside Enterprise, row without claim, direct relation without claim, claim without direct relation, non-mappable with control, non-mappable with mapping type, duplicate record number, row without provenance, malformed technique id, wrong OSCAL id, Enterprise technique without tactic, wrong parent technique |
| Alignment conformance | Aligned data validated against UCO 1.5.0 core's own SHACL shapes; alignment modules annotate every term they cover; every ATT&CK entity carries a STIX id | `tests/test_alignment.py` | claims without the `owl:hasValue` values; relationship target that is a literal |
| Factual verification | Population built only from pinned files with SHA-256 checks; cross-checks against ATT&CK STIX and the OSCAL catalog recorded in `data/source-checks.json` and surfaced by CQ08, CQ09 and CQ13 | `tests/test_conformance.py`, `tests/test_competency.py` | a changed source file fails the digest check |
| Competency coverage | Each of the 22 questions answered by SPARQL over the graph and, separately, from the raw JSON; the two must agree | `tests/test_competency.py` | the independent path is the probe: any modelling or population error shows up as disagreement |
| Provenance | Every row links to its dataset; every claim to its rows; every dataset to a pinned URL and digest (CQ07) | `tests/test_conformance.py`, CQ07 | row without provenance |
| Prior version | The original v2 bundle still parses, conforms to its own shapes and matches its digests | `tests/test_v2_bundle.py` | five probes from the first release |
| Published browser | `index.html` is rebuilt from the current sources, is reproducible across hash seeds and loads nothing from the network; browser checks (68 on 2026-11-08), including the gap analysis, OSCAL SSP import and downloads | `tests/test_browser_build.py`, `scripts/uat_browser.mjs` | unknown node falls back to the overview; a recommended control must close exactly the gaps it claims |
| Security | The page blocks network requests, runs only hashed scripts and shows poisoned data as text; dependencies are hash-locked and sources pinned; `docs/security.md` agrees with the shared gap logic | `scripts/uat_browser.mjs`, `tests/test_supply_chain.py`, `tests/test_security_doc.py`, `tests/js/coverage.test.cjs` | poisoned data and address-bar payloads; an unhashed pin; escaping and policy removed |
| Agent API | Each file is current, obeys a strict JSON Schema, agrees with the raw sources, resolves every reference, marks upstream prose as untrusted and is small | `tests/test_api.py`, `scripts/uat_browser.mjs` | six schema probes; the untrusted-text test found CQ07 |
| Exports | CSVs and Navigator layers are current, follow layer format 4.5, name only ATT&CK 16.1 techniques (the CIS layer only ATT&CK 19.1 techniques), and the baseline layers agree with an independent computation from the raw sources; the browser's layer equals the static one | `tests/test_exports.py`, `scripts/uat_browser.mjs` | the independent path |
| Licences and notices | Third-party text appears only where its licence is stated, exactly as published (CIS 8.1.2, OWASP MCP Top 10), and each output keeps the upstream notices | `tests/test_api.py`, `tests/test_notices.py` | a CIS or MCP title put into an export, a changed word in CIS guidance, a wrong ATT&CK notice year, a missing D3 licence |
| CIS file reader | The user's CIS XLSX or CSV is read in the page with size, row and zip-bomb limits; numbering by row position | `tests/js/cisfile.test.cjs`, browser checks | rows out of order, a non-numeric Safeguard, a zip bomb, a damaged file, a hostile title |
| Copy | User-facing text describes what the tool does and makes no comparison that is not verified | `tests/test_copy.py` | a false "only free tool" sentence in the README |

## Results on 2026-11-08 (release 2.7.0, ontology 2.3.0)

Run on the Apple M4 Mac at commit `b82e0fd` (`main`), with Python 3.14.5, rdflib 7.6.0, pySHACL 0.40.1, OpenJDK 17 and Node.js 26.8.1. The lock pins pySHACL 0.40.2. CI installs the lock exactly, on Python 3.14 and Node.js 24, and passed on the same commit (run 42479655299). On 2026-11-07, a clean install of the lock with pySHACL 0.40.2 also passed all 139 tests then present.

- `python -m pytest -q tests`: **140 passed** in 308 seconds.
- `npm run uat` with the poisoned page: **68 browser checks** pass. They include the CIS gap analysis, the IG buttons, the user's CIS file, the exact CIS and MCP titles with their notices, and the security probes.
- JavaScript unit tests: **25 pass** (`lib/coverage.cjs` and `lib/cisfile.cjs`).
- `pip-audit` (lock, hashes required) and `npm audit`: no known vulnerabilities.
- Population: 119,482 triples. Agent API: 1,300 files. Exports: 37 files.
- GitHub: CodeQL reports no open alert. The rule set on `main` requires the CI checks, CodeQL and signed commits.

## Results on 2026-11-02 (release 2.2.0, ontology 2.1.0)

Run on an Apple M4 Mac with Python 3.14, rdflib 7.6.0, pySHACL 0.40.1, owlready2 0.51 (HermiT), OpenJDK 17 and Node.js 26.

- `python -m pytest -q tests`: **84 passed** in 196 seconds.
- `npm run uat` with the poisoned page: **39 browser checks** pass.
- Data conformance: the full population (93,945 triples) conforms with 0 violations and 1 warning (T1521.003). 18 probes are rejected with the expected message.
- Logical consistency: HermiT finds the TBox, the full population (reasoning profile) and the chain slice consistent. The four inconsistency probes are detected.
- Competency coverage: all 15 questions agree with the independent computation from the raw sources, including ATT&CK 20.0 for CQ14 and CQ15.
- Shared logic: 8 unit tests for `lib/coverage.cjs` pass, with probes for prompt injection and HTML in OSCAL fields.
- Security: the page blocks a network request; script in the address bar and in poisoned data does not run. With escaping removed, the Content Security Policy alone stops the payloads. With escaping and the policy removed, the payload runs, which proves the checks can fail.
- Supply chain: 7 tests pass. An unhashed pin makes the hash test fail. `pip-audit` and `npm audit` find no known vulnerability.
- Reproducibility: builds with `PYTHONHASHSEED` 3 and 11 give identical files.

## Results on 2026-11-02 (release 2.3.0, phase 2)

- `python -m pytest -q tests`: **99 passed** in 204 seconds.
- `npm run uat` with the poisoned page: **41 browser checks** pass, including two that read the API files as an agent does.
- Agent API: 856 files. Each document obeys its JSON Schema. Six probes are rejected (unknown field, missing field, bad ID, unknown status, claim without evidence, link without https). Technique claims agree with the raw sources. Each reference resolves to a file. The largest file is less than 120 KB.
- Reproducibility: the API build is identical with `PYTHONHASHSEED` 5 and 9.

## Results on 2026-11-02 (release 2.4.0, phase 3)

- `python -m pytest -q tests`: **110 passed** in 222 seconds.
- `npm run uat` with the poisoned page: **47 browser checks** pass, including the ATLAS gap analysis and its agreement with CQ16.
- Data conformance: 0 violations and 1 warning. Five new probes cover ATLAS IDs, ATLAS mitigation links, OWASP links, ATT&CK tactic STIX ids and ATLAS parents.
- Competency coverage: all 19 questions agree with the independent reading of the raw ATLAS YAML and the curated OWASP file.
- Agent API: 1,088 files, all valid against their schemas.

## Semantic correctness

The guide lists domain expert verification as its own dimension, and no automated gate replaces it. The competency answers in [competency-questions.md](competency-questions.md) are as good as the CTID mapping and should be reviewed by a security architect before they drive a control decision. The alignment decisions in [vocabulary-alignment.md](vocabulary-alignment.md) should be reviewed by someone who maintains a UCO, STIX or OSCAL integration.

## Governance

- **Versioning.** `owl:versionInfo` and `owl:versionIRI` on the ontology, `owl:priorVersion` to 1.0, and the previous release kept unchanged in `ontology/v2/` (decision D1).
- **Deprecation.** Terms are deprecated with `owl:deprecated` and `dcterms:isReplacedBy`, not deleted.
- **Regression.** CI runs every gate on each push and pull request (`.github/workflows/ci.yml`).
- **Source updates.** A new CTID, ATT&CK or OSCAL release means new pinned URLs and digests in `scripts/build_population.py`, a rebuild, and a review of `data/source-checks.json` and the competency answers before release.
