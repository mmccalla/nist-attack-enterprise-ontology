# Security policy

## Report a vulnerability

If you find a vulnerability in this project, do not open a public issue.

1. Open the [Security tab](https://github.com/mmccalla/nist-attack-enterprise-ontology/security) of the repository.
2. Click **Report a vulnerability**.
3. Give the steps to reproduce the problem and the effect.

If the **Report a vulnerability** button is not there, open an issue that asks for a private contact. Do not include the details.

## What is in scope

- The graph browser and the gap analysis on the published site.
- The build scripts, the pinned sources and the exports.
- Data integrity: a claim, an export or an answer that does not agree with the pinned sources.

An error in an upstream source (MITRE CTID, ATT&CK or NIST OSCAL) is not a vulnerability in this project. Report it with the mapping issue form.

## How the project responds

The maintainer examines each report, repairs a confirmed problem, adds a test that fails without the repair and records the change in [`CHANGELOG.md`](CHANGELOG.md). This is a volunteer project. Thus, there is no fixed response time.

## How the project protects itself

[`docs/security.md`](docs/security.md) gives the threat model, the controls, the evidence for each control and the risks that stay.
