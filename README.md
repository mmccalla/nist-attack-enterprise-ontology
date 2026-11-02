# NIST 800-53 to MITRE ATT&CK: free gap analysis and knowledge graph

This free tool shows which MITRE ATT&CK techniques your NIST SP 800-53 controls can mitigate. It also shows the gaps and the controls that close them.

**Open the tool: [mmccalla.github.io/nist-attack-enterprise-ontology](https://mmccalla.github.io/nist-attack-enterprise-ontology/)**

You do not need an account, an installation or a server. The tool runs in your browser. It does not send your data to a server.

![Gap analysis: coverage of ATT&CK techniques by the selected controls, per tactic](docs/images/gaps.png)

## What you can do

| Task | Where |
| --- | --- |
| Find the ATT&CK techniques that your controls do not cover | [Gap analysis](https://mmccalla.github.io/nist-attack-enterprise-ontology/#gaps) |
| Find the controls that close the most gaps | [Gap analysis](https://mmccalla.github.io/nist-attack-enterprise-ontology/#gaps) |
| Find the controls that mitigate one technique | Search, then open the technique |
| Find the techniques that one control mitigates | Search, then open the control |
| See the source row and the rationale for each claim | Open a claim |
| Get answers to 15 common questions | [Questions](https://mmccalla.github.io/nist-attack-enterprise-ontology/#questions) |
| Use the data in ATT&CK Navigator, a spreadsheet or a script | [Downloads](#downloads) |

## Find your gaps

1. Open [Gap analysis](https://mmccalla.github.io/nist-attack-enterprise-ontology/#gaps).
2. Type or paste the IDs of your implemented controls, for example `AC-2, IA-2(1), SI-4`.
3. If you use a baseline, click LOW, MODERATE, HIGH or PRIVACY instead.
4. If you have an OSCAL file, click **Load OSCAL JSON** instead.
5. Read the coverage per tactic and the list of gaps.
6. Read the list of controls that close the most gaps.
7. To keep the result, bookmark the page or copy the address.

The tool accepts these OSCAL files: a system security plan (SSP), a component definition, a profile or a catalog. The tool counts a control enhancement, for example AC-2(1), as its base control.

The tool shows each technique in one of three states:

| State | Meaning |
| --- | --- |
| Covered | One or more of your controls mitigate the technique. |
| Gap | No selected control mitigates the technique, but a different mapped control can. |
| No mapped control | No NIST 800-53 control in the mapping mitigates the technique. More NIST controls cannot cover it. |

## Use the result in ATT&CK Navigator

1. In Gap analysis, click **ATT&CK Navigator layer**.
2. Open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
3. Click **Open Existing Layer**, then **Upload from local**.
4. Select the file that you downloaded.

Each control page and each baseline page also has a **Navigator layer** button. In the layer, green is covered, amber is a gap and grey is no mapped control. A darker green shows more controls.

## Downloads

All files are free. Each file has a stable address. Thus, a script can get the most recent version.

| File | Content |
| --- | --- |
| [`claims.csv`](exports/claims.csv) | Each control and technique claim, with tactics, baselines and source row numbers |
| [`techniques.csv`](exports/techniques.csv) | Each ATT&CK Enterprise technique, with its controls and mapping status |
| [`controls.csv`](exports/controls.csv) | Each mapped control, with its OSCAL ID and baselines |
| [`navigator/`](exports/navigator) | Navigator layers for each baseline and for all controls |
| [`questions/`](exports/questions) | The answer to each of the 15 questions |
| [`attack-16.1-to-20.0.csv`](exports/attack-16.1-to-20.0.csv) | Each technique that ATT&CK 20.0 changes, with its replacement and its new tactics |
| [`ontology/core.ttl`](ontology/core.ttl), [`data/population.ttl`](data/population.ttl) | The full knowledge graph in RDF, for a graph database or SPARQL |

For a file address, add the path to `https://mmccalla.github.io/nist-attack-enterprise-ontology/`. For example: `https://mmccalla.github.io/nist-attack-enterprise-ontology/exports/claims.csv`.

## Where the data comes from

The tool joins three public sources. The build downloads exact versions of each source. It then compares each file with a known SHA-256 digest.

| Source | Version | Gives |
| --- | --- | --- |
| [MITRE CTID Mappings Explorer](https://ctid.mitre.org/mappings/) | NIST 800-53 Rev. 5 to ATT&CK 16.1, updated 16 April 2025 | 5,410 mapping rows |
| [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data) | Enterprise 16.1 | 656 techniques, 14 tactics, platforms and ATT&CK mitigations |
| [NIST OSCAL content](https://github.com/usnistgov/oscal-content) | SP 800-53 Rev. 5 catalog 5.2.0 | Control titles, families and the SP 800-53B baselines |

The tool keeps each source row separate from the claim that it supports. A claim is a statement that a control mitigates a technique. Each claim shows the source rows behind it.

The build found some errors in the source. For example, one row names a Mobile technique (T1521.003). The tool keeps that row but does not make a claim from it. The full list is in [`docs/upstream-findings.md`](docs/upstream-findings.md).

## Limits

Read these limits before you use a result in a decision.

- A claim shows that a control **can** mitigate a technique. It does not show that your implementation is effective.
- The mapping covers 109 technical base controls in 11 families. It does not include policy controls or control enhancements.
- Some control families are not in the mapping, for example Awareness and Training.
- The mapping uses ATT&CK 16.1. ATT&CK 20.0 revokes, renames or moves 208 of its techniques. Each technique page shows the change, and [`attack-16.1-to-20.0.csv`](exports/attack-16.1-to-20.0.csv) lists them.
- 91 ATT&CK Enterprise techniques do not have a row in the mapping. The tool shows these techniques as "no mapped control". That result does not mean that no defence exists.
- The control titles come from the OSCAL catalog 5.2.0. The mapping uses an older Rev. 5 release. Three titles are different.
- The IRIs in the knowledge graph use the `w3id.org/example` namespace. These IRIs do not resolve.

## Security and privacy

- The page cannot send data anywhere. Its Content Security Policy blocks all network requests.
- The page runs only its own scripts. It shows all source data as text.
- To report a vulnerability, read [`SECURITY.md`](SECURITY.md).
- The threat model and the controls are in [`docs/security.md`](docs/security.md).

## Get help or report a problem

- To report an incorrect claim or a claim that is not there, use the [mapping issue form](https://github.com/mmccalla/nist-attack-enterprise-ontology/issues/new/choose).
- To ask for a new question, use the competency question form on the same page.
- For other problems, open a [blank issue](https://github.com/mmccalla/nist-attack-enterprise-ontology/issues/new).

If the source row is incorrect, the project records the finding in [`docs/upstream-findings.md`](docs/upstream-findings.md). These findings are for a report to MITRE CTID.

## Cite this tool

Use the data in [`CITATION.cff`](CITATION.cff). GitHub shows a **Cite this repository** link for this file. The changes in each release are in [`CHANGELOG.md`](CHANGELOG.md).

## For maintainers and contributors

These documents give the design and the tests:

| Document | Content |
| --- | --- |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to build the tool and run the tests |
| [`docs/competency-questions.md`](docs/competency-questions.md) | The 13 questions, their personas and their answers |
| [`docs/semantic-decisions.md`](docs/semantic-decisions.md) | Scope, source terms, ambiguities and design decisions |
| [`docs/vocabulary-alignment.md`](docs/vocabulary-alignment.md) | The alignment to ATT&CK STIX, NIST OSCAL and UCO |
| [`docs/evaluation.md`](docs/evaluation.md) | The test gates and their most recent results |
| [`docs/security.md`](docs/security.md) | Threat model, controls and evidence |
| [`docs/roadmap.md`](docs/roadmap.md) | Planned work |

The original ontology bundle is in [`ontology/v2/`](ontology/v2). It has no changes.

## Licence and attribution

- The code has the MIT licence ([`LICENSE`](LICENSE)).
- The ontology files have the CC BY 4.0 licence.
- The mappings come from the MITRE Center for Threat-Informed Defense (Apache 2.0).
- MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
- The UCO core file has the Apache 2.0 licence.

The full attribution is in [`ATTRIBUTION.md`](ATTRIBUTION.md).
