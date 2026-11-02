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

# Retrospective, phase 1 (2026-11-02)

Phase 1 added catalogues and frameworks, ATT&CK version reconciliation, one shared gap-analysis module and a security baseline. The results: 84 tests and 39 browser checks pass, and the project applies its own controls to itself.

## Keep doing

| Practice | Evidence |
| --- | --- |
| Reconcile versions before a join. | The reconciliation found that ATT&CK 20.0 gives TA0005 to Stealth. A join on tactic IDs between CIS (ATT&CK 19.1) and NIST (16.1) would give wrong results without a warning. |
| Prove that each probe can fail. | A probe showed that the first hash test passed with a hash missing. The rewritten test fails correctly. |
| Test each defence layer alone. | With escaping removed, the policy alone stopped the payloads. With both removed, the payload ran. |
| Run the project's own tool on the project. | The self-assessment forced a list of controls with evidence. |

## Stop doing

| Practice | Evidence | Better practice |
| --- | --- | --- |
| Parse CSV with a split on commas. | The first self-assessment lost rows for titles with commas, for example SI-07. | Use a CSV parser, also in a short script. |
| Claim a control before you have its evidence. | The first list of implemented controls had SI-03 and CM-11, which the project does not implement. | Classify each control as implemented, partial, inherited or owner action. Link each to its evidence first. |
| Hard-code counts in tests. | A browser check expected 13 questions after the project had 15. | Count from the source, for example the files in `queries/`. |
| Long command chains. | An unrelated command failed at the start of a chain and stopped all later steps. | Keep each chain short. Run steps that do not depend on each other separately. |
| A second monitor for a job that has one. | This happened again in phase 1, after the first retrospective said to stop. | Before a new monitor, examine whether one already watches the job. |

## Start doing

| Practice | Reason |
| --- | --- |
| Examine the module system before you add shared code. | The repository declares ES modules, so the first shared file failed in Node. The `.cjs` extension solved it. |
| Use the reconciliation for each new catalogue. | ATLAS, CIS and the cloud sets use different ATT&CK versions. |
| Read the security exit criteria at the start of each phase. | `docs/roadmap.md` now gives them. |

## Owner actions found in this phase

Branch protection, private vulnerability reporting and Dependabot security updates are off. `docs/security.md` lists them with the CI workflow push.

# Retrospective, phase 2 (2026-11-02)

Phase 2 added the static agent API: 856 JSON files with schemas, an OpenAPI description and `llms.txt`. The results: 99 tests and 41 browser checks pass.

## Keep doing

| Practice | Evidence |
| --- | --- |
| A strict schema with probes for each output that a machine reads. | Six probes show that the schemas reject bad documents. |
| A test for each security rule, not only for each feature. | The untrusted-text test found that CQ07 gives CTID rationale without the mark. The build now marks all question rows. |
| Build twice with different hash seeds. | The API build is identical across seeds. |

## Stop doing

| Practice | Evidence | Better practice |
| --- | --- | --- |
| `git reset --hard` and stash churn in a folder that file sync watches. | The sync made 18 copies such as `SECURITY 2.md`. One build then read two copied query files, so the page had 17 questions. | Keep `main` without the workflow files. Build the workflow commit in a temporary worktree outside the synced folder. A test now fails on any copied file. |
| Tests that run from a copy of the repository. | Two runs used stale copies of the scripts. | Install the test tools in the repository (`npm ci`) and run the checks there. |

## Start doing

| Practice | Reason |
| --- | --- |
| Mark all upstream text that an agent reads as untrusted. | Prompt injection can come through source data as well as through user input. |
| Before git operations that rewrite files, examine whether a sync service watches the folder. | The copies appeared without an error message. |

# Retrospective, phase 3 (2026-11-02)

Phase 3 added MITRE ATLAS, the OWASP GenAI lists, a gap analysis for AI systems and four competency questions for agent builders.

## Keep doing

| Practice | Evidence |
| --- | --- |
| Use only published cross-references. | ATLAS publishes its ATT&CK origins and OWASP publishes its ATLAS links. The tool uses those and writes no mapping of its own. |
| Refuse secondary sources for official facts. | The Agentic Top 10 titles were available only from vendor blogs. The tool leaves them out and says why. |
| Test licence rules. | A test fails if an MCP Top 10 title appears. |
| Load a deep link in a real browser before you decide that it is broken. | ATLAS deep links answer 404 but render in a browser. |

## Stop doing

| Practice | Evidence | Better practice |
| --- | --- | --- |
| Tests that assume one catalogue. | A STIX-id test failed when ATLAS tactics arrived, because ATLAS has no STIX ids. | Scope each catalogue-specific test to its catalogue. |
| A loop variable with the same name as an outer variable. | `m` in a new loop replaced the model in `build_exports.py`. | Use a distinct name, and read the enclosing function before an insertion. |
| A first question that ignores the hierarchy. | CQ16 first counted 19 agent techniques without mitigation, but 5 have one on their parent. | Ask a domain expert question: "on the technique or its parent". Show both numbers where users see one view. |

## Start doing

| Practice | Reason |
| --- | --- |
| Label derived classifications as derived at each place where users see them. | The "AI agent" flag is useful, but ATLAS does not publish it. |
| Ask the owner for official documents that sit behind forms. | The Agentic Top 10 item titles can be added from the official document. |
