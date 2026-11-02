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
- The licence of a source decides what the project can copy. For example, the project gives only IDs and links for OWASP MCP Top 10 (CC BY-NC-SA).
- The project applies to itself the controls that it recommends. [`security.md`](security.md) gives the threat model and the controls.

## Phases

The sizes (S, M, L) are estimates.

| Phase | Work | Security exit criteria | Size | Depends on |
| --- | --- | --- | --- | --- |
| 0. Owner actions | Push the CI and Pages workflows. Make release v2.1.0 and the topics. Decide about the CTID report. | Branch protection and Pages HTTPS are on. | S | Owner |
| 1. Foundation (done 2026-11-02) | (a) Add "catalogue" and "framework" to the model. (b) Reconcile ATT&CK versions. (c) Move the gap logic into one shared module. (d) Apply the security baseline. | Threat model, Content Security Policy, XSS probes, pinned dependencies with hashes, `SECURITY.md`. | L | 0 (CI is useful) |
| 2. Agent API (done 2026-11-02) | Static JSON files for each technique, control, tactic, mitigation and baseline. JSON Schemas, OpenAPI, `version.json`, `llms.txt`. | Each file obeys its schema. No file holds free text from an untrusted input. | M | 1 |
| 3. Agentic threats (done 2026-11-02) | (a) Import MITRE ATLAS. (b) Add the OWASP lists for generative AI as reference concepts. (c) Gap analysis for ATLAS mitigations. (d) Competency questions for agent builders. | YAML read with a safe loader. Size limits on each source. Licence rules applied. | M to L | 1, 2 |
| 4. More frameworks | CIS Controls 8.1.2 and CSA CCM 4.1. Then KEV and the AWS, Azure, GCP and M365 sets. | Same as phase 3. | M each | 1 |
| 5. Local MCP server | Tools for lookup, gap analysis, recommendations, claim evidence and the competency questions. | No network access. Input validation. No free text from an OSCAL file goes to the agent. Limits on input and output size. | M | 1, 3 |
| 6. Trust and freshness | Evaluation set for agents. Tests for invented IDs and prompt injection. Change feed. Scheduled update pull requests. | Workflow permissions at the minimum. Secret scan, dependency scan and OpenSSF Scorecard in CI. | M | 0, 2, 5 |

## Watch items

| Item | Trigger | Action |
| --- | --- | --- |
| NIST COSAiS overlays for AI agents | NIST publishes a draft of an agent overlay. | Import the overlays in the same way as the SP 800-53B baselines. |
| ATLAS to NIST 800-53 mapping | MITRE or CTID publishes a dataset that a machine can read. | Import it as source claims. |
| Classic OWASP links (ASVS, cheat sheets) | The OpenCRE data licence permits reuse. | Add guidance links for each NIST control. |
| w3id namespace and DOI | Owner decision. | Register the namespace. Connect Zenodo for a DOI for each release. |
