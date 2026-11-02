# Retrospective, 2026-11-02

This retrospective covers the work from the first publication (1.0.0) to the user-focused README (release 2.1.0). Each item gives the evidence. "Project" items apply to this repository. "Generic" items apply to all projects.

## Summary

The project went from an uploaded bundle to a free, tested tool in four steps:

1. Publication of the v2 bundle with a graph browser.
2. Ontology 2.0.0: competency questions, alignment to STIX, OSCAL and UCO, full population and evaluation gates.
3. A market and segment analysis, which changed the goal to a free community tool.
4. Gap analysis, Navigator layers, CSV exports and a README for users.

The results are good. But the work used more time than necessary on three problems: reasoner scale, orphaned processes and figures from memory.

## Keep doing

| Practice | Evidence |
| --- | --- |
| Examine the raw source before you make the model. | The examination found that "non_mappable" is a status, 50 rows are duplicates and one row names a Mobile technique. The v2 bundle did not show these errors. |
| Compute expected answers through a second, independent path. | Each competency answer comes from SPARQL and also from the raw JSON. The browser layer for MODERATE must equal the static layer. |
| Write a negative probe for each rule. | 14 SHACL probes, 4 consistency probes and 2 UCO probes. A probe also showed that a test examined the wrong report text. |
| Pin each source to a commit and a SHA-256 digest. | Each build is repeatable. A changed source stops the build. |
| Build with three hash seeds and compare the output. | This test found two causes of non-determinism: a blank node read as an inverse property, and the order of GROUP_CONCAT values. |
| Read the primary specification before a format change. | The Navigator layer format 4.5, the OSCAL zero-padded label and the UCO shapes came from their sources. No format was a guess. |
| Make each gate fail when it cannot run. | The HermiT gate failed when owlready2 tried to download import IRIs. It did not pass by default. |
| Examine the live site after each deployment. | The browser checks ran against the published URL each time. |
| Give each finding with its evidence and its limits. | The market analysis gave sources and said where no evidence was found. |

## Stop doing

| Practice | Evidence | Better practice |
| --- | --- | --- |
| Figures from memory in documents. | Two figures in the competency document were incorrect (CQ01 baselines and CQ09 controls). A check count of 35 was really 33. | Get each figure from a query run at that time. Pin important figures with a test. |
| A heavy tool on the full data as the first test. | owlrl and HermiT each ran for more than 10 minutes on 92,000 triples. The cause showed only after small tests. | Time the tool on 10, 100 and 1,000 items before the full run. |
| A long job without a timeout that stops all child processes. | Three HermiT Java processes continued after their Python parent stopped. They slowed the next test run. | Start each long job in its own process group. Stop the group at the timeout. |
| More than one monitor for one job. | Several monitors watched the same test run and reported the same result. | Use one monitor for each job. |
| Bulk text edits to rules without a review of the result. | A bulk edit to the SHACL shapes removed the class target from rule R1. A review found it before a test ran. | Read each changed rule after a bulk edit. Then run its probe. |
| Placeholder code in a test. | Two competency tests had placeholder lines. These lines did not test a result. | Write the full assertion, or do not write the test yet. |
| A statement about an action before the action. | The first README draft said that the project "sends" findings to CTID. Nobody had sent them. | Describe only actions that are done. Describe planned actions as planned. |

## Start doing

| Practice | Reason |
| --- | --- |
| Identify the users and their task before the first build. | The segment analysis came after two releases. It changed the goal from "ontology" to "free tool that saves work". |
| Write documents for users first, in STE. | The first README was for maintainers. Users need the task, the steps and the limits first. |
| Examine the publication route at the start. | The SSH key failed, the token did not have the workflow scope and the release action needed permission. Each problem stopped work later. |
| Ask before each public action. | A public action (release, issue, topic) needs the owner's approval for that action. |
| Keep the reasoner profile small and named from the start. | Number restrictions and owl:hasValue make the tableau grow very fast with many individuals. SHACL enforces those rules better at scale. |
| Plan ATT&CK version reconciliation before a second framework. | The CTID sets use ATT&CK 15.1, 16.1, 17.1 and 19.1. A join without version reconciliation gives incorrect results. |

## Open items

- Push the CI and Pages workflow commit after `gh auth refresh -h github.com -s workflow`.
- Make the release v2.1.0 and add the repository topics (needs approval).
- Decide whether to send `docs/upstream-findings.md` to MITRE CTID.
- Add ATT&CK version reconciliation, then the CIS Controls 8.1.2 mapping.
- Register a w3id namespace and get a DOI for each release.
