# Attribution

## Ontology

The files in `ontology/v2/` are the uploaded `nist_attack_enterprise_ontology_v2_bundle.zip`, unchanged (see [SOURCE-MANIFEST.md](SOURCE-MANIFEST.md)). Its header declares `dcterms:license` [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) and names OpenAI as `dcterms:creator`. Version 2.0.0 (`ontology/core.ttl`, `ontology/shapes.ttl`, the alignment modules and `data/population.ttl`) is a revision of that work by Mark McCalla under the same licence, with OpenAI kept as creator and Mark McCalla added as contributor. The MIT [LICENSE](LICENSE) covers the scripts, the graph browser, the queries and the tests.

## Source mappings

The sample population derives from `nist_800_53-rev5_attack-16.1-enterprise_json.json`. That file name and its fields match the NIST 800-53 Rev. 5 to ATT&CK Enterprise 16.1 mappings published by the MITRE Center for Threat-Informed Defense in [Mappings Explorer](https://ctid.io/mappings-explorer) ([repository](https://github.com/center-for-threat-informed-defense/mappings-explorer), Apache 2.0).

## NIST OSCAL content

The 2.0.0 population reads control titles, families and SP 800-53B baseline membership from NIST's OSCAL content (`usnistgov/oscal-content`), a work of the US government.

## UCO

`vendor/uco/core.ttl` is UCO 1.5.0 core from the [Unified Cyber Ontology](https://github.com/ucoProject/UCO), Apache 2.0, with its licence in `vendor/uco/LICENSE`. It is used to validate the UCO alignment.

## MITRE ATT&CK

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. The 2.0.0 population reads technique, tactic, platform and mitigation data from the ATT&CK Enterprise 16.1 STIX bundle (`mitre-attack/attack-stix-data`). ATT&CK content is © The MITRE Corporation and is used under the [ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

## NIST SP 800-53

Control identifiers and titles come from NIST SP 800-53 Rev. 5, a publication of the National Institute of Standards and Technology.

## D3

`vendor/d3.v7.min.js` is [D3](https://d3js.org) 7.9.0, © Mike Bostock, ISC licence. It is inlined into `index.html`.
