# Attribution

## Ontology bundle

The files in `ontology/` are the uploaded `nist_attack_enterprise_ontology_v2_bundle.zip`, unchanged (see [SOURCE-MANIFEST.md](SOURCE-MANIFEST.md)). The ontology header declares `dcterms:license` [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) and names OpenAI as `dcterms:creator`. Those terms apply to the files in `ontology/`. The MIT [LICENSE](LICENSE) in this repository covers the build script, the graph browser and the tests.

## Source mappings

The sample population derives from `nist_800_53-rev5_attack-16.1-enterprise_json.json`. That file name and its fields match the NIST 800-53 Rev. 5 to ATT&CK Enterprise 16.1 mappings published by the MITRE Center for Threat-Informed Defense in [Mappings Explorer](https://ctid.io/mappings-explorer) ([repository](https://github.com/center-for-threat-informed-defense/mappings-explorer), Apache 2.0).

## MITRE ATT&CK

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. ATT&CK technique identifiers and names are © The MITRE Corporation and are used under the [ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

## NIST SP 800-53

Control identifiers and titles come from NIST SP 800-53 Rev. 5, a publication of the National Institute of Standards and Technology.

## D3

`vendor/d3.v7.min.js` is [D3](https://d3js.org) 7.9.0, © Mike Bostock, ISC licence. It is inlined into `index.html`.
