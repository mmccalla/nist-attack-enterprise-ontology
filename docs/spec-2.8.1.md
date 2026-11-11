# Spec: release 2.8.1, wording and trust statements

Status: approved by the owner on 2026-11-11 ("execute the whole plan"). Evidence collected on 2026-11-11.

## Problem

Some statements in the README and on the page say more than the data shows:

- "Covered" can be read as "the control is effective". The mapping shows only that a control can mitigate a technique.
- "More NIST controls cannot cover it" is not true outside the mapping. Policy controls and control enhancements are not in the mapping.
- "ATT&CK and NIST 800-53 do not describe attacks on AI agents" is false for ATT&CK. ATT&CK has techniques about AI, for example T1588.007 Artificial Intelligence.
- "No published mapping exists from ATLAS to NIST 800-53" is a claim about all publishers. Nobody can examine all publishers.
- "The newest release" has no date, so it becomes false without notice.

New users also need to see quickly why they can trust the results.

## Users

- Security engineers, GRC analysts and threat modellers who read the README or the page before they use a result.
- Reviewers who examine the copy for fallacies and bias before the project is announced.

## Source evidence (2026-11-11)

| Fact | Source | Result |
| --- | --- | --- |
| CTID publishes no ATLAS mapping | CTID Mappings Explorer, <https://ctid.mitre.org/mappings/external/>, and the `mappings` folder of `center-for-threat-informed-defense/mappings-explorer` at commit `59f8d7230f672db0d4b197357561f47880478426` | 11 mapped frameworks: AWS, Azure, CIS, CRI Profile, CSA CCM, GCP, Intel vPro, KEV, M365, NIST 800-53 and VERIS. The NIST 800-53 mappings are to ATT&CK 8.2 to 16.1 only. No path, page or repository names ATLAS. |
| ATT&CK 20.1 is the newest release | `mitre-attack/attack-stix-data`, folder `enterprise-attack` | The newest file is `enterprise-attack-20.1.json`. |
| OSCAL catalog 5.2.0 is the newest release | `usnistgov/oscal-content`, history of `NIST_SP-800-53_rev5_catalog.json` on `main` | The newest commit for the file is `5006f18c`, the pinned commit. Its version is 5.2.0. |
| ATLAS 2026.10 is the newest release | `mitre-atlas/atlas-data`, folder `dist/v6` | The newest dated file is `ATLAS-2026.10.yaml`. |
| The page shows the source row of each claim | `scripts/build_graph.py` and `src/viewer.html` | Technique and control pages show "Row n" or "CIS row n" with the rationale. The API gives `evidence[].source_record`. |

## In scope

1. The README coverage table (Covered, Gap, No mapped control) and the same definitions on the gap analysis page.
2. The note on the page about techniques with no mapped control.
3. The README statements about AI agents (line 89) and about ATLAS and NIST 800-53 (line 99), and the same statement in `docs/vocabulary-alignment.md`.
4. Trust statements under the first README paragraph: source rows, pinned digests and the manifest, CTID issue #151.
5. A date on each "newest release" statement, from one stored value.
6. Corrections to `SOURCE-MANIFEST.md`, which the trust statement depends on (see Defects).
7. Release 2.8.1: version numbers and the changelog.

## Out of scope

- The data, the claims, the API structure and the ontology.
- LinkedIn copy, the review steps of other agents and Dependabot PRs #12 to #14.
- A GitHub release or tag. The owner publishes releases.

## Defects found during the evidence check

- `SOURCE-MANIFEST.md` does not list `data/sources/cis-controls-8.1.2.json` or `data/sources/owasp-mcp-top10.json`.
- `SOURCE-MANIFEST.md` gives an old digest for `data/sources/owasp-genai.json`. The file changed in release 2.7.0.
- No test compares the files in `data/sources/` with the manifest.

## Acceptance criteria

| # | Statement | Test |
| --- | --- | --- |
| A1 | The README and the page give the same definition of each coverage state. | The three definitions in the README table appear unchanged in `src/viewer.html`. |
| A2 | "Covered" says "mapped as able to mitigate". "No mapped control" says that no defence can still exist. | The README and the page contain the new definitions. The old sentence "More NIST controls cannot cover it" and "Selecting more NIST controls cannot cover them" are not present. |
| A3 | The AI agents statement agrees with the data. | If the pinned ATT&CK 16.1 data has a technique with "AI" or "Artificial Intelligence" in its name, the README says "do not specifically cover attacks on AI agents". The old sentence is not present. |
| A4 | The ATLAS statement is dated and names its source. | The README and `docs/vocabulary-alignment.md` say that CTID Mappings Explorer publishes no ATLAS mapping on the date in `data/source-checks.json`. "No published mapping exists" is not present. |
| A5 | Each claim has a source row. | Each claim in each technique API file has at least one `evidence[].source_record` that is an integer. |
| A6 | Each source file is in the manifest with its current digest. | Each file in `data/sources/` has a manifest row that contains its current SHA-256. |
| A7 | Each "newest release" statement has a date. | Each "the newest release" in the README is followed by "on" and the date in `data/source-checks.json` (`newestCheckedOn`). |
| A8 | The release is 2.8.1. | `CITATION.cff`, the changelog heading, `llms.txt` and `versions.release` in the API say 2.8.1. |

## Failure modes

- If a later check finds an ATLAS to NIST 800-53 mapping from CTID, the README must name it and link to it. The A4 statement becomes false. The date in the statement shows when it was true.
- A3 finds AI techniques by name. A technique about AI with no AI word in its name is not found. This is a limit of the test.
