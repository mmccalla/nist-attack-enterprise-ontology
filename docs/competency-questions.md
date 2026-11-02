# Competency questions

The Stage 1 deliverable of *A Practical Guide to Ontology Engineering*. A competency question states something the ontology and its populated graph must be able to answer. Following the guide's procedure, each question below names the decision it supports, the source evidence it needs and its acceptance test. The questions set the minimum requirement; they do not limit what else the graph can answer.

Every question is a SPARQL file in [`queries/`](../queries). The acceptance test in [`tests/test_competency.py`](../tests/test_competency.py) runs the query over the graph and compares the answer with the same answer computed independently from the raw source JSON ([`tests/source_model.py`](../tests/source_model.py)), with no RDF involved. Agreement on both paths is the acceptance criterion. Each question can also be opened in the [graph browser](https://mmccalla.github.io/nist-attack-enterprise-ontology/#questions), where the answer links into the graph.

Answers below were produced on 2026-11-01 from the pinned sources listed in [semantic-decisions.md](semantic-decisions.md).

## Catalogue

| ID | Persona | Question | Decision it supports | Evidence |
| --- | --- | --- | --- | --- |
| CQ01 | Software engineer | Which NIST 800-53 controls mitigate T1078 Valid Accounts, and which baselines include each control? | Which security requirements to put in the backlog for a system exposed to credential abuse | Claims (CTID); baselines (OSCAL) |
| CQ02 | Threat modeller | Which ten controls mitigate the most Initial Access techniques? | Which controls give the widest cover against how an adversary first gets in | Claims (CTID); tactics (STIX) |
| CQ03 | GRC analyst | Which techniques have mitigating controls in the mapping, but none of them in the LOW baseline? | What residual exposure a LOW-baseline system accepts | Claims (CTID); LOW profile (OSCAL) |
| CQ04 | Security architect | Which techniques depend on a single mitigating control? | Which controls are single points of failure and need assurance or compensation | Claims (CTID) |
| CQ05 | Threat-informed defence analyst | Which techniques does the source mark non-mappable, and does ATT&CK list a mitigation for any of them? | Whether "no NIST control" means no defence, or a defence that NIST 800-53 does not express | Non-mappable rows (CTID); ATT&CK mitigations (STIX) |
| CQ06 | Threat-informed defence analyst | For T1078, which ATT&CK mitigations apply next to the NIST controls? | How ATT&CK guidance and the control catalogue line up for one technique | ATT&CK mitigations (STIX); claims (CTID) |
| CQ07 | Auditor | What source evidence supports the claim that AC-02 mitigates T1556.009, and which exact file is it from? | Whether a claim can be traced before it is relied on in an assessment | Claim, rows, dataset metadata, file digest |
| CQ08 | Data steward | Which source rows name a technique that is not an active technique in ATT&CK Enterprise 16.1? | Which rows to raise with the publisher and keep out of enterprise claims | Rows (CTID); STIX bundle |
| CQ09 | Data steward | Which control and technique pairs are asserted by more than one source row? | Whether duplicate rows inflate counts | Rows (CTID) |
| CQ10 | Security architect | How many techniques does each control family mitigate in each tactic? | Which families carry the defence at each stage of an attack | Claims, families (CTID); tactics (STIX) |
| CQ11 | Cloud platform engineer | Which IaaS techniques are mitigated by fewer than three controls? | Where a cloud landing zone needs guardrails beyond the catalogue mapping | Platforms (STIX); claims (CTID) |
| CQ12 | Threat-informed defence analyst | Which active ATT&CK Enterprise 16.1 techniques does the mapping not address at all? | Where the mapping is silent, so silence is not read as "no control needed" | STIX bundle; rows (CTID) |
| CQ13 | GRC analyst | Where does the mapping name a control or family differently from the OSCAL catalog? | Which labels to correct before output goes into an OSCAL-based assessment | Rows (CTID); OSCAL catalog |
| CQ14 | GRC analyst | Which claimed techniques did ATT&CK 20.0 revoke or rename, what replaces them and how many claims does each carry? | Which claims to review before reports move to the current ATT&CK version | Claims (CTID); ATT&CK 16.1 and 20.0 STIX |
| CQ16 | AI agent builder | Which ATLAS techniques against AI agents have no ATLAS mitigation, on the technique or on its parent technique? | Where an agent design needs its own safeguards | MITRE ATLAS 5.6.0 |
| CQ17 | AI agent builder | Which ATLAS mitigations address the most techniques against AI agents? | Which safeguards to build first into an agent with tools, MCP servers or other agents | MITRE ATLAS 5.6.0 |
| CQ18 | Security architect for AI systems | Which ATLAS techniques adapt an ATT&CK technique, and how many NIST controls does CTID map to that ATT&CK technique? | Where existing NIST controls give a start for AI threats (indirect link) | ATLAS ATT&CK-reference; CTID claims |
| CQ19 | LLM application developer | Which OWASP LLM Top 10 (2025) risks does OWASP link to ATLAS techniques, and which ATLAS mitigations address them? | Which safeguards apply to a named OWASP risk | OWASP pages (CC BY-SA 4.0); MITRE ATLAS |
| CQ20 | GRC analyst | Which NIST 800-53 controls share the most ATT&CK techniques with CIS Safeguard 13.7? | Which NIST evidence a CIS-based programme can reuse | CTID CIS 8.1.2 and NIST claims, joined by STIX id |
| CQ21 | Security architect | For each ATT&CK 16.1 tactic, how many techniques do CIS 8.1.2 and NIST 800-53 both cover, how many only CIS and how many only NIST? | Where a programme that uses one framework has gaps that the other covers | CTID claims for both frameworks |
| CQ22 | Threat-informed defence analyst | Which techniques that CIS 8.1.2 maps exist only in ATT&CK 19.1, and which ATT&CK 16.1 techniques do they replace? | Which CIS claims have no NIST counterpart only because of the ATT&CK version | CTID CIS claims; ATT&CK 19.1 STIX |
| CQ15 | Security architect | Which ATT&CK 16.1 tactics lose techniques in ATT&CK 20.0, to which tactics, and how many? | Which coverage reports by tactic break on the move to the current version | ATT&CK 16.1 and 20.0 STIX |

## What the answers show

**CQ01.** 25 controls mitigate T1078. 23 are in the HIGH baseline, 22 in MODERATE and 15 in LOW. IA-13 (Identity Providers and Authorization Servers) and SC-43 are in no baseline, so a team that implements a baseline and stops there will not get them.

**CQ02.** SI-04 System Monitoring covers the most Initial Access techniques (15), then CM-06 (14), AC-06 and CA-07 (13 each), AC-03 and SC-07 (10 each).

**CQ03.** Six techniques have claims but no claim from a LOW-baseline control: T1090.004 Domain Fronting, T1535 Unused/Unsupported Cloud Regions, T1550.004 Web Session Cookie, T1595.003 Wordlist Scanning, T1657 Financial Theft and T1666 Modify Cloud Resource Hierarchy.

**CQ04.** Eleven techniques rest on one control. SI-03 Malicious Code Protection is the only control for four of them (T1027.013, T1027.014, T1055.015, T1564.012).

**CQ05.** The source marks 96 techniques non-mappable. ATT&CK links 82 of them only to M1056 Pre-compromise, a category for activity before initial access, which agrees with the source. One links only to M1055 Do Not Mitigate. Ten have no ATT&CK mitigation. Three have a substantive ATT&CK mitigation: T1566.004 and T1598.004 Spearphishing Voice (M1017 User Training) and T1656 Impersonation (M1017 User Training and M1019 Threat Intelligence Program). User training maps naturally to the SP 800-53 Awareness and Training family, which is not among the 11 families in the source, so these rows read better as "outside the mapping's scope" than as "no control".

**CQ06.** ATT&CK lists 8 mitigations for T1078 (M1013, M1015, M1017, M1018, M1026, M1027, M1032, M1036) next to the 25 NIST controls. The two sets come from different publishers and stay separate in the model.

**CQ07.** The claim rests on source row 98, which carries the rationale "Control AC-2 (Account Management) contains provisions for the monitoring of accounts for unusual activity...". The row comes from the CTID file for ATT&CK 16.1, last updated 04/16/2025, with SHA-256 `355ae97d...c8`.

**CQ08.** One row, record 637, maps SC-12 to T1521.003 SSL Pinning, which is not an Enterprise technique. Rule R1 withholds the claim and SHACL reports a warning.

**CQ09.** 50 pairs appear in two identical rows; 47 of them involve CM-02, the others IA-09, SC-08 and SI-12. Counting rows instead of distinct pairs would overstate cover by 50.

**CQ10.** Defense Evasion and Persistence draw the most family-technique links (648 and 472); Discovery (48) and Reconnaissance (27) the fewest. AC, CM and SI lead in almost every tactic.

**CQ11.** 17 IaaS techniques have fewer than three controls. 15 have none, mostly Discovery techniques such as T1526 Cloud Service Discovery, plus T1496 Resource Hijacking and T1578.004 Revert Cloud Instance.

**CQ12.** 91 active Enterprise techniques have no row in the mapping at all, including T1014 Rootkit and T1020 Automated Exfiltration. The graph records this as silence, not as a non-mappable statement.

**CQ13.** Three names differ from OSCAL: IA-08 (letter case only), SC-32 (the source uses the Rev. 4 title "Information System Partitioning") and the CA family (the source uses the Rev. 4 name; Rev. 5 calls it "Assessment, Authorization, and Monitoring").

**CQ14** (added 2026-11-02). 25 claimed techniques were revoked or renamed in ATT&CK 20.0. For example, T1070.001 Clear Windows Event Logs (21 claims) is replaced by T1685.005, and T1211 is renamed "Exploitation for Stealth".

**CQ15** (added 2026-11-02). ATT&CK 20.0 divides Defense Evasion. 134 of its techniques move to Stealth, which now has the ID TA0005, and 41 move to Defense Impairment (TA0112). A report that joins on tactic IDs across the two versions gives wrong results.

**CQ16** (added 2026-11-02). 14 of the 26 ATLAS techniques against AI agents have no ATLAS mitigation on the technique or on its parent. Examples are AML.T0104 Publish Poisoned AI Agent Tool, AML.T0083 Credentials from AI Agent Configuration and the four sub-techniques of AML.T0084 Discover AI Agent Configuration. The "AI agent" flag is derived from technique names; ATLAS does not publish it.

**CQ17** (added 2026-11-02). Five mitigations each address four agent techniques: AML.M0024 AI Telemetry Logging, AML.M0026 Privileged AI Agent Permissions Configuration, AML.M0027 Single-User AI Agent Permissions Configuration, AML.M0028 AI Agent Tools Permissions Configuration and AML.M0032 Segmentation of AI Agent Components.

**CQ18** (added 2026-11-02). 34 ATLAS techniques adapt an ATT&CK technique. For 18 of them, CTID maps NIST controls to the ATT&CK technique, for example 32 controls for T1552 Unsecured Credentials behind AML.T0055. The link is indirect: the claims stay on the ATT&CK technique.

**CQ19** (added 2026-11-02). OWASP links 7 of the 10 LLM risks to 13 ATLAS techniques. ATLAS gives mitigations for 12 of them. AML.T0048.002 Societal Harm (from LLM09 Misinformation) has none.

**CQ20** (added 2026-11-02). SI-03 Malicious Code Protection shares 45 techniques with CIS-13.7, SI-04 System Monitoring 43 and AC-06 Least Privilege 40. The tenth control, SI-07, shares 20. A shared technique is an overlap. It does not make two controls equivalent.

**CQ21** (added 2026-11-02). Over the 14 tactics, 503 technique and tactic pairs have claims from both frameworks, 16 only from CIS and 123 only from NIST. It counts only techniques that are active in both ATT&CK versions. Defense Evasion has the most in each group: 110 both, 7 only CIS and 40 only NIST. The CIS mapping has 1140 claims and the NIST mapping 5263, so this result is about mapping depth, not only about control content.

**CQ22** (added 2026-11-02). CIS maps 29 techniques that are active in ATT&CK 19.1 but not in 16.1. ATT&CK 19.1 says that 8 of them replace 16.1 techniques, for example T1685 Disable or Modify Tools replaces T1562, T1562.001 and T1562.006. The NIST mapping cannot have a claim on these 29 techniques because it uses 16.1.

## Open-world caution

OWL reads the graph under open-world semantics: a missing statement is not a false one. CQ03, CQ04, CQ11 and CQ12 use `FILTER NOT EXISTS` or counts, which are closed-world readings **of the pinned sources**. Their answers mean "the sources say nothing more", not "nothing more exists". The answers are as good as the mapping and should go to a domain expert before they drive a control decision.
