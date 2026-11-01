# Evaluation

The Stage 8 deliverable of *A Practical Guide to Ontology Engineering*. The guide asks for separate automated gates for logical consistency, data conformance and factual verification, and for competency coverage measured as expected against actual answers. Each gate below has negative probes: changes that break one rule and must make the gate fail. A gate that cannot run fails; it never passes by default.

## Gates

| Dimension | Gate | Test file | Negative probes |
| --- | --- | --- | --- |
| Logical consistency | HermiT (OWL 2 DL) on the TBox with all alignments and UCO core; on the full population under the reasoning profile (D13); on a slice with the full TBox; the property chain must infer the direct relation | `tests/test_consistency.py` | control typed as technique; technique used as a control through domain and range; non-mappable row naming a control; claim typed as a source assertion |
| Data conformance | SHACL (`ontology/shapes.ttl`) on the full population: no violations, exactly one warning (T1521.003) | `tests/test_conformance.py` | 14 probes, one per rule: family mismatch, claim supported by the wrong row, claim outside Enterprise, row without claim, direct relation without claim, claim without direct relation, non-mappable with control, non-mappable with mapping type, duplicate record number, row without provenance, malformed technique id, wrong OSCAL id, Enterprise technique without tactic, wrong parent technique |
| Alignment conformance | Aligned data validated against UCO 1.5.0 core's own SHACL shapes; alignment modules annotate every term they cover; every ATT&CK entity carries a STIX id | `tests/test_alignment.py` | claims without the `owl:hasValue` values; relationship target that is a literal |
| Factual verification | Population built only from pinned files with SHA-256 checks; cross-checks against ATT&CK STIX and the OSCAL catalog recorded in `data/source-checks.json` and surfaced by CQ08, CQ09 and CQ13 | `tests/test_conformance.py`, `tests/test_competency.py` | a changed source file fails the digest check |
| Competency coverage | Each of the 13 questions answered by SPARQL over the graph and, separately, from the raw JSON; the two must agree | `tests/test_competency.py` | the independent path is the probe: any modelling or population error shows up as disagreement |
| Provenance | Every row links to its dataset; every claim to its rows; every dataset to a pinned URL and digest (CQ07) | `tests/test_conformance.py`, CQ07 | row without provenance |
| Prior version | The original v2 bundle still parses, conforms to its own shapes and matches its digests | `tests/test_v2_bundle.py` | five probes from the first release |
| Published browser | `index.html` is rebuilt from the current sources, is reproducible across hash seeds and loads nothing from the network; 33 browser checks, including the gap analysis, OSCAL SSP import and downloads | `tests/test_browser_build.py`, `scripts/uat_browser.mjs` | unknown node falls back to the overview; a recommended control must close exactly the gaps it claims |
| Exports | CSVs and Navigator layers are current, follow layer format 4.5, name only ATT&CK 16.1 techniques, and the baseline layers agree with an independent computation from the raw sources; the browser's layer equals the static one | `tests/test_exports.py`, `scripts/uat_browser.mjs` | the independent path |

## Results on 2026-11-01

Run on an Apple M4 Mac with Python 3.14, rdflib 7.6.0, pySHACL 0.40.1, owlready2 0.51 (HermiT) and OpenJDK 17.

- `python -m pytest -q tests`: **61 passed** in 181 seconds.
- Logical consistency: TBox with UCO core and all three alignments consistent, no unsatisfiable class (0.7 s). Full population (92,500 triples) consistent under the reasoning profile (55 s). Chain slice consistent with the full TBox; the property chain infers `control_AC-02 mitigatesTechnique technique_T1556.009` after the materialised triple is removed. All 4 inconsistency probes detected.
- Data conformance: full population conforms with 0 violations and 1 warning (T1521.003), in 22 s. All 14 probes rejected with the expected message.
- Alignment conformance: aligned slice conforms to UCO 1.5.0 core shapes; the only results are 1925 advisories from `core:UcoThing-identifier-regex-shape` (severity Info, decision D10). Both probes rejected.
- Competency coverage: all 13 questions agree with the independent computation from the raw sources.
- Reproducibility: `build_population.py --check` and `build_graph.py --check` pass, and three builds with different `PYTHONHASHSEED` values give identical files.
- Browser: 22 checks pass in Chromium; the page makes no network requests.

Two engineering findings shaped the gates. HermiT's tableau grew exponentially with number restrictions over thousands of individuals (decision D13), and UCO's punned SHACL shapes made full reasoning run past 15 minutes until the reasoner was given OWL only (decision D14).

## Semantic correctness

The guide lists domain expert verification as its own dimension, and no automated gate replaces it. The competency answers in [competency-questions.md](competency-questions.md) are as good as the CTID mapping and should be reviewed by a security architect before they drive a control decision. The alignment decisions in [vocabulary-alignment.md](vocabulary-alignment.md) should be reviewed by someone who maintains a UCO, STIX or OSCAL integration.

## Governance

- **Versioning.** `owl:versionInfo` and `owl:versionIRI` on the ontology, `owl:priorVersion` to 1.0, and the previous release kept unchanged in `ontology/v2/` (decision D1).
- **Deprecation.** Terms are deprecated with `owl:deprecated` and `dcterms:isReplacedBy`, not deleted.
- **Regression.** CI runs every gate on each push and pull request (`.github/workflows/ci.yml`).
- **Source updates.** A new CTID, ATT&CK or OSCAL release means new pinned URLs and digests in `scripts/build_population.py`, a rebuild, and a review of `data/source-checks.json` and the competency answers before release.
