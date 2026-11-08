# Attribution

The exact copyright notices, licences and changes for each source are in [NOTICE.md](NOTICE.md). The licence texts are in [LICENSES/](LICENSES).

## Ontology

The files in `ontology/v2/` are the uploaded `nist_attack_enterprise_ontology_v2_bundle.zip`, unchanged (see [SOURCE-MANIFEST.md](SOURCE-MANIFEST.md)). Its header declares `dcterms:license` [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) and names OpenAI as `dcterms:creator`. Version 2.0.0 (`ontology/core.ttl`, `ontology/shapes.ttl`, the alignment modules and `data/population.ttl`) is a revision of that work by Mark McCalla under the same licence, with OpenAI kept as creator and Mark McCalla added as contributor. The MIT [LICENSE](LICENSE) covers the scripts, the graph browser, the queries and the tests.

## Source mappings

The sample population derives from `nist_800_53-rev5_attack-16.1-enterprise_json.json`. That file name and its fields match the NIST 800-53 Rev. 5 to ATT&CK Enterprise 16.1 mappings published by the MITRE Center for Threat-Informed Defense in [Mappings Explorer](https://ctid.io/mappings-explorer) ([repository](https://github.com/center-for-threat-informed-defense/mappings-explorer), Apache 2.0).

## CIS Controls

The population reads the CTID mapping of CIS Controls 8.1.2 to ATT&CK Enterprise 19.1 (`mappings/cis/attack-19.1/cis-8.1.2/enterprise/`, Mappings Explorer, Apache 2.0). The graph keeps the Safeguard and Control IDs, the ATT&CK technique IDs, the CTID rationale (`comments`) and the reference URLs.

CIS Controls® is a registered trademark of the Center for Internet Security, Inc. CIS licenses the CIS Controls under [CC BY-NC-ND 4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/) ([CIS terms of use](https://cas.docs.cisecurity.org/en/latest/source/terms-of-use/)). The CIS Controls 8.1.2 titles, asset classes, security functions and Implementation Groups come exactly from the CIS workbook, in `data/sources/cis-controls-8.1.2.json`. They keep the CIS licence: non-commercial use only, no changes, credit to CIS. They are not under the project licence, and they appear only in places that state the CIS licence (decision D29). The graph and the claims hold only CIS IDs. Read the CIS Controls at [cisecurity.org/controls](https://www.cisecurity.org/controls). This project is not affiliated with or endorsed by CIS.

## NIST OSCAL content

The 2.0.0 population reads control titles, families and SP 800-53B baseline membership from NIST's OSCAL content (`usnistgov/oscal-content`), a work of the US government.

## UCO

`vendor/uco/core.ttl` is UCO 1.5.0 core from the [Unified Cyber Ontology](https://github.com/ucoProject/UCO), Apache 2.0, with its licence in `vendor/uco/LICENSE`. It is used to validate the UCO alignment.

## MITRE ATLAS

The population reads tactics, techniques and mitigations from [MITRE ATLAS](https://github.com/mitre-atlas/atlas-data) 2026.10 (format 6), © MITRE, Apache 2.0.

## OWASP GenAI Security Project

`data/sources/owasp-genai.json` is a curated extract from the OWASP GenAI Security Project and the OWASP Foundation, retrieved on 2026-11-02:

- OWASP Top 10 for LLM Applications 2025: item IDs, titles and the MITRE ATLAS IDs that OWASP lists under "Related Frameworks and Taxonomies". Licence: [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). This extract, and the parts of the graph, API and exports derived from it, are shared under the same licence.
- OWASP Top 10 for Agentic Applications for 2026: the list title and link only.
- OWASP MCP Top 10 (2025): IDs, exact titles and item links, in a separate file with its own licence (CC BY-NC-SA 4.0, non-commercial, share alike). See [NOTICE.md](NOTICE.md) and decision D30.

Changes: extraction of IDs, titles and links. No OWASP text is copied beyond titles.

## MITRE ATT&CK

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. The 2.0.0 population reads technique, tactic, platform and mitigation data from the ATT&CK Enterprise 16.1 STIX bundle (`mitre-attack/attack-stix-data`), and technique IDs, names and revocations from the 19.1 bundle for the CIS mapping. ATT&CK content is © The MITRE Corporation and is used under the [ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

## NIST SP 800-53

Control identifiers and titles come from NIST SP 800-53 Rev. 5, a publication of the National Institute of Standards and Technology.

## D3

`vendor/d3.v7.min.js` is [D3](https://d3js.org) 7.9.0, © Mike Bostock, ISC licence. It is inlined into `index.html`.
