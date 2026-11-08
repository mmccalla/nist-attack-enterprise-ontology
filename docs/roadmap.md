# Roadmap

This roadmap gives the planned work after release 2.1.0. Each phase ends with these items:

1. The tests and the negative probes pass.
2. A live examination of the site passes.
3. A security review of the new attack surface is complete.
4. A retrospective adds its learnings to [`retrospective.md`](retrospective.md).

## Rules for all phases

- Claims stay CTID-only. The tool adds links only from published sources. It does not write mappings of its own.
- Each source has a pinned version and a SHA-256 digest.
- Each new rule has a negative probe.
- The licence of a source decides what the project can copy. Text under a non-commercial or no-derivatives licence is copied only exactly, in a separate file with its own licence and notice (CIS Controls, OWASP MCP Top 10). Content without a licence that permits redistribution is linked, not copied (CSA CCM).
- The project applies to itself the controls that it recommends. [`security.md`](security.md) gives the threat model and the controls.

## Phases

The sizes (S, M, L) are estimates.

| Phase | Work | Security exit criteria | Size | Depends on |
| --- | --- | --- | --- | --- |
| 0. Owner actions (done 2026-11-08) | CI workflow on `main`. Rule set "Protect Trunk" with pull requests, checks, CodeQL and signed commits. Private vulnerability reporting and Dependabot security updates. CTID report filed as issue #151. Release v2.7.0. | Branch protection and Pages HTTPS are on. | S | Owner |
| 1. Foundation (done 2026-11-02) | (a) Add "catalogue" and "framework" to the model. (b) Reconcile ATT&CK versions. (c) Move the gap logic into one shared module. (d) Apply the security baseline. | Threat model, Content Security Policy, XSS probes, pinned dependencies with hashes, `SECURITY.md`. | L | 0 (CI is useful) |
| 2. Agent API (done 2026-11-02) | Static JSON files for each technique, control, tactic, mitigation and baseline. JSON Schemas, OpenAPI, `version.json`, `llms.txt`. | Each file obeys its schema. No file holds free text from an untrusted input. | M | 1 |
| 3. Agentic threats (done 2026-11-02) | (a) Import MITRE ATLAS. (b) Add the OWASP lists for generative AI as reference concepts. (c) Gap analysis for ATLAS mitigations. (d) Competency questions for agent builders. | YAML read with a safe loader. Size limits on each source. Licence rules applied. | M to L | 1, 2 |
| 4a. CIS Controls (done 2026-11-04) | CIS Controls 8.1.2 on ATT&CK 19.1, CQ20 to CQ22, CIS gap analysis, API and exports. Exact CIS titles, Implementation Groups and AI guidance in a separate CC BY-NC-ND 4.0 file (D29, D30). | Same as phase 3. CIS text only exact and only with its notice. | M | 1 |
| 4b. CSA CCM 4.1 (closed 2026-11-03) | No CSA content. Links to the CTID CSA CCM page and to the CTID page of each technique (D27). | No third-party content without a licence that permits it. | S | Owner |
| 4c. KEV and cloud sets (not started) | KEV and the AWS, Azure, GCP and M365 sets. | Same as phase 3. Licence of each set examined first. | M each | 1 |
| 3b. ATLAS current release (done 2026-11-08) | ATLAS 2026.10 read from its format 6 file, pinned by commit and digest. Agent flag, CQ16 to CQ19 and the gap analysis recomputed. ATT&CK later version moved to 20.1. | A test compares the ATLAS counts with the release notes (129 techniques, 92 sub-techniques, 44 mitigations, 16 tactics). | M | 3 |
| T. Trust and discoverability (in progress) | Done: CI and CodeQL on each pull request, signed commits, release v2.7.0, `NOTICE.md`. Open: repository topics, a board summary for decision makers. | Copy describes what the tool does and its evidence, with no comparison that is not verified (`tests/test_copy.py`). | S | 0 |
| 5. Local MCP server | Tools for lookup, gap analysis, recommendations, claim evidence and the competency questions. | No network access. Input validation. No free text from an OSCAL file goes to the agent. Limits on input and output size. | M | 1, 3 |
| 6. Trust and freshness | Evaluation set for agents. Tests for invented IDs and prompt injection. Change feed. Scheduled update pull requests. | Workflow permissions at the minimum. Secret scan, dependency scan and OpenSSF Scorecard in CI. | M | 0, 2, 5 |

## Watch items

| Item | Trigger | Action |
| --- | --- | --- |
| NIST COSAiS overlays for AI agents | NIST publishes a draft of an agent overlay. | Import the overlays in the same way as the SP 800-53B baselines. |
| ATLAS to NIST 800-53 mapping | MITRE or CTID publishes a dataset that a machine can read. | Import it as source claims. |
| Classic OWASP links (ASVS, cheat sheets) | The OpenCRE data licence permits reuse. | Add guidance links for each NIST control. |
| w3id namespace and DOI | Owner decision. | Register the namespace. Connect Zenodo for a DOI for each release. |
