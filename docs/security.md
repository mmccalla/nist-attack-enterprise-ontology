# Security of this project

This project tells people which controls mitigate which attacks. Thus, the project must apply those controls to itself. This document gives the threat model, the controls and the evidence for each control. It also gives the risks that stay.

Status: examined on 2026-11-02, phase 1.

## Assets

| Asset | Why it matters | Main property |
| --- | --- | --- |
| The claims, the exports and the competency answers | People make security decisions from them. | Integrity |
| The data that a user enters (control lists, OSCAL files) | An SSP can describe a system in detail. | Confidentiality |
| The source code, the build scripts and the pinned sources | A change here changes every output. | Integrity |
| The published site | Users run its JavaScript in their browser. | Integrity |
| The maintainer's GitHub account and tokens | They can change the site. | Confidentiality, integrity |

## Actors

- A user of the site or of the downloads.
- A contributor who opens an issue or a pull request.
- An attacker who sends a user a crafted link or a crafted OSCAL file.
- An attacker who compromises an upstream source (CTID, ATT&CK, OSCAL) or a dependency (Python, Node, GitHub Actions).
- An attacker who gets the maintainer's credentials.
- From phase 2: an AI agent that reads the API or calls the MCP server.

## Trust boundaries

1. **Upstream sources to the build.** The build downloads CTID, ATT&CK and OSCAL files.
2. **Dependencies to the build.** pip, npm and GitHub Actions supply the tools.
3. **Repository to the site.** GitHub Pages publishes the `main` branch.
4. **Site to the user's browser.** The browser runs the page's JavaScript.
5. **User's files to the page.** The user pastes text or loads an OSCAL file.

## Threats and controls

The ATT&CK techniques come from this project's own data. The controls are NIST SP 800-53 Rev. 5 controls that the CTID mapping links to each technique.

| Boundary | Threat (STRIDE) | ATT&CK technique | Controls applied | Implementation and evidence |
| --- | --- | --- | --- | --- |
| 1 | Tampered or substituted source file (Tampering) | T1565.001 Stored Data Manipulation | SI-07, SR-04, SR-11 | Each source URL names a commit. The build compares each file with a SHA-256 digest and stops on a difference. It accepts only the pinned host and refuses files above 200 MB. Evidence: `tests/test_supply_chain.py`. |
| 2 | Compromised dependency or build tool (Tampering) | T1195.001 Compromise Software Dependencies and Development Tools | SR-04, SR-11, CM-02, SA-11, SI-07 | Python dependencies install with `--require-hashes`. npm uses a lockfile with sha512 integrity. Actions are pinned to commits. D3 and UCO are vendored with digests. Evidence: `tests/test_supply_chain.py`. |
| 2 | Known-vulnerable dependency (Elevation of privilege) | T1195.002 Compromise Software Supply Chain | RA-05, SI-02, SA-22 (partial) | `pip-audit` and `npm audit` found no known vulnerability on 2026-11-02. Dependabot is configured. CI runs the audits after the workflow push (owner action). |
| 3 | Unauthorised change to the site (Tampering) | T1078.004 Cloud Accounts | IA-05, CM-07; CM-03 and IA-02 are owner actions | Secret scanning and push protection are on. The build needs no secret. Branch protection and two-factor authentication are owner actions (below). |
| 4 | Script injection through data or the address bar (Tampering, Elevation of privilege) | T1059.007 JavaScript, T1189 Drive-by Compromise | SC-18, SI-10, SI-07, CM-07 | The page escapes all data before it writes HTML. A Content Security Policy permits only the page's own scripts, by SHA-256 hash. Evidence: the browser checks put HTML and script payloads into the data and into the address bar, and none runs. A test with escaping removed showed that the policy alone stops the payloads. |
| 4, 5 | User data sent off the machine (Information disclosure) | T1557 Adversary-in-the-Middle | SC-08, CM-07, SC-07 (partial) | The policy has `connect-src 'none'`, so the page cannot send data anywhere. Pages enforces HTTPS. Evidence: a browser check tries a network request and the browser blocks it. |
| 5 | Malicious OSCAL file or pasted text (Tampering, Denial of service) | T1204.002 Malicious File | SI-10 | The page reads only control IDs that match a strict pattern. It never shows other text from the file. Text is limited to 200,000 characters, files to 20 MB and IDs to 5,000. Evidence: `tests/js/coverage.test.cjs`, including prompt injection and HTML in OSCAL fields. |
| 2, 3 | Secret in the repository (Information disclosure) | T1552.001 Credentials In Files | IA-05, SA-11 | The project uses no secret. GitHub secret scanning and push protection are on. The maintainer scans each commit with gitleaks before a push. |
| 3 | Added credential on the repository (Elevation of privilege) | T1098.001 Additional Cloud Credentials | IA-05, CM-07 | No deploy key and no token is stored in the repository or the workflows. The workflows request only the permissions each job needs. |

## The project's own gap analysis

The project ran its own gap logic (`lib/coverage.cjs`) over the 10 techniques above. With only the controls in the "Implemented" list, all 10 techniques are "covered". This result shows that each technique has one or more implemented mitigating controls. It does not show that the controls are sufficient. The tests and the probes give the stronger evidence.

The test `tests/test_security_doc.py` reads this block and runs the same analysis again:

```text
implemented: SA-08 SA-11 SI-07 SI-10 SC-08 SC-18 SR-04 SR-11 CM-02 CM-07 IA-05
partial: SA-10 SA-15 SA-22 SI-02 SC-07 SR-05 RA-05 CM-05 CM-06 AC-03 AC-06 CA-02 CA-07
owner actions: CM-03 IA-02
threat techniques: T1195.001 T1195.002 T1189 T1059.007 T1565.001 T1552.001 T1078.004 T1098.001 T1204.002 T1557
```

"Partial" means that part of the control is in place. For example, CI runs the audits only after the workflow push. SC-08 and part of AC-03 are inherited from GitHub.

## Owner actions

Only the repository owner can make these changes.

1. Turn on branch protection for `main`: no force push, and the CI checks must pass (CM-03, CM-05).
2. Turn on private vulnerability reporting, so that [`SECURITY.md`](../SECURITY.md) has a private channel.
3. Turn on Dependabot security updates (SI-02).
4. Push the CI and Pages workflows after `gh auth refresh -s workflow`. Then the gates run on each push (CA-07, RA-05, AC-06).
5. Use two-factor authentication on the maintainer account (IA-02).

## Risks that stay

| Risk | Reason | Mitigation |
| --- | --- | --- |
| `style-src 'unsafe-inline'` | The page sets style attributes. | Scripts cannot run from injected markup. All data is escaped. |
| No `frame-ancestors` | A meta element cannot set it, and Pages cannot set headers. | The page has no action that changes state. A frame cannot cause harm through a click. |
| Upstream content can be wrong | A digest shows that a file did not change. It does not show that the content is correct. | The cross-checks report source errors (`docs/upstream-findings.md`). |
| A compromised maintainer account | It can change the site. | Owner actions 1 and 5. |
| Gates run only on the maintainer's computer | The workflows are not pushed. | Owner action 4. |

## Rules for later phases

- **Phase 2 (agent API), done:** each file obeys a strict schema (`tests/test_api.py`, with six probes). No file holds text from a user. Fields with upstream prose are listed in `untrusted_text_fields`; a test found that CQ07 needed this. The API is static, with no server, and each file is below 120 KB.
- **Phase 3 (ATLAS and OWASP), done:** ATLAS is read with `yaml.safe_load` only, and a test fails on any other YAML loader. ATLAS is pinned to a commit and a digest, within the host and size limits. The curated OWASP file is in the repository with its digest recorded in the graph. The licence rules are tested: no MCP Top 10 title is copied. ATLAS mitigation "use" text is not imported.
- **Phase 4a (CIS Controls), done:** the CIS file and the ATT&CK 19.1 bundle are pinned to commits and digests, within the host and size limits. The build stops if a CIS row names a technique that is not active in 19.1, or if a 19.1 technique has the STIX id of a different 16.1 technique. The licence rule is tested: no CIS title is in any output, and SHACL rejects one in the graph. CTID rationale and the reference URLs are upstream text. The API lists them in `untrusted_text_fields`, and the page shows the URLs as escaped text, not as links. The CIS gap analysis reads only IDs of the form `CIS-6.3` or `6.3`, with the same input limits as the NIST gap analysis.
- **Phase 5 (MCP server):** no network access. Validate each input. Never return free text from an OSCAL file. Limit input and output size. Pin and document the server version.
- **Phase 6:** add OpenSSF Scorecard, the secret scan and the dependency scan to CI, with each workflow at minimum permissions.
