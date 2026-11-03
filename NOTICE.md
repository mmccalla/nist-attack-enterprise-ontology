# Notices

This project combines its own work with content from other publishers. Each part keeps its own licence. The project licences (MIT for code, CC BY 4.0 for the ontology and the project's own data) apply only to the project's own contributions. They do not apply to the third-party content below.

The full licence texts are in [`LICENSES/`](LICENSES). This file is published with the site at `https://mmccalla.github.io/nist-attack-enterprise-ontology/NOTICE.md`. Each API file, Navigator layer and export refers to it.

This project is not affiliated with, sponsored by or endorsed by any publisher below.

## MITRE ATT&CK

Used: technique, tactic, platform and mitigation identifiers, names and relationships from the ATT&CK Enterprise STIX 2.1 bundles 16.1, 19.1 and 20.0 (`mitre-attack/attack-stix-data`). Licence: the ATT&CK terms of use, reproduced in full in [`LICENSES/MITRE-ATTACK-terms-16.1.txt`](LICENSES/MITRE-ATTACK-terms-16.1.txt) and [`LICENSES/MITRE-ATTACK-terms-19.1-20.0.txt`](LICENSES/MITRE-ATTACK-terms-19.1-20.0.txt).

ATT&CK 16.1:

> © 2024 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

ATT&CK 19.1 and 20.0:

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation. MITRE does not claim that ATT&CK lists all possible adversary behaviour. Coverage of ATT&CK techniques does not guarantee full defensive coverage.

Changes: the data is converted to RDF, JSON and CSV. Identifiers and names are not changed.

## MITRE Center for Threat-Informed Defense: Mappings Explorer

Used: the NIST SP 800-53 Rev. 5 to ATT&CK 16.1 mapping (commit `6bdc3ad`) and the CIS Controls 8.1.2 to ATT&CK 19.1 mapping (commit `1b0b81e`) from `center-for-threat-informed-defense/mappings-explorer`. Licence: Apache 2.0, in [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt).

> © 2024 MITRE Engenuity. Approved for public release. Document number(s) CT0104. (notice at commit `6bdc3ad`)

> © 2024 MITRE. Approved for public release. Document number(s) CT0104. (notice at commit `1b0b81e`)

Changes:

- Rows are converted to RDF assertions, claims, API files and CSV files. Each keeps its source record number.
- Control titles are replaced by the titles of the NIST OSCAL catalog. The source titles are kept where they differ.
- CIS mapping: CIS Safeguard and Control titles are not copied. In the CTID rationale text, a CIS title of three words or more is replaced by the marker `[title of CIS-x.y]` (one row on 2026-11-03). In CIS reference URLs, the part after `#` is removed, because it is the Safeguard title as a slug.

## MITRE ATLAS

Used: tactics, techniques, mitigations and their links from ATLAS 5.6.0 (`mitre-atlas/atlas-data`, commit `da9ebf9`). Licence: Apache 2.0, in [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt).

> Copyright 2021-2026 MITRE

Changes: converted to RDF, JSON and CSV. Mitigation "use" text is not imported. The "AI agent" flag is derived by this project and is labelled as derived.

## CIS Controls

CIS Controls® is a registered trademark of the Center for Internet Security, Inc. (CIS). CIS licenses the CIS Controls under [CC BY-NC-ND 4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/) ([CIS terms of use](https://cas.docs.cisecurity.org/en/latest/source/terms-of-use/)).

This project does not copy, change or distribute CIS Controls content. It uses only the Safeguard and Control numbers that the CTID mapping uses to identify them, and links to [cisecurity.org](https://www.cisecurity.org/controls/cis-controls-list). Read the CIS Controls there. The gap analysis shows which ATT&CK techniques the CTID mapping links to the Safeguards that you select. It does not represent or assess compliance with the CIS Controls.

## Cloud Security Alliance Cloud Controls Matrix

This project does not include any CSA CCM content. The CSA terms do not permit redistribution or modification of the CCM. The CTID mapping of CCM to ATT&CK 17.1 is at [ctid.mitre.org/mappings/external/csa_ccm](https://ctid.mitre.org/mappings/external/csa_ccm/).

## NIST OSCAL content and NIST SP 800-53

Used: control identifiers, titles, families and SP 800-53B baseline membership from `usnistgov/oscal-content`. As a work of the United States government, it is in the public domain in the United States, and NIST waives copyright worldwide through [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/). Source: NIST SP 800-53 Rev. 5 and SP 800-53B, National Institute of Standards and Technology. Use of this content does not imply endorsement by NIST.

## OWASP GenAI Security Project

Used: OWASP Top 10 for LLM Applications 2025 item IDs, titles and the ATLAS IDs that OWASP lists under "Related Frameworks and Taxonomies", in `data/sources/owasp-genai.json`, published by the OWASP GenAI Security Project of the OWASP Foundation. Licence: [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). This extract, and the parts of the graph, API and exports derived from it, are shared under CC BY-SA 4.0.

OWASP Top 10 for Agentic Applications for 2026: the list title and link only. OWASP MCP Top 10: IDs and the link only, because its CC BY-NC-SA 4.0 licence does not permit copying titles into this project.

Changes: extraction of IDs, titles and links only.

## Unified Cyber Ontology

`vendor/uco/core.ttl` is UCO 1.5.0 core. Licence: Apache 2.0, in [`vendor/uco/LICENSE`](vendor/uco/LICENSE). Not changed.

## D3

`vendor/d3.v7.min.js` is D3 7.9.0, © 2010-2023 Mike Bostock. Licence: ISC, in [`LICENSES/ISC-d3.txt`](LICENSES/ISC-d3.txt). Not changed. The page includes the file inline with its copyright line.

## The original ontology bundle

`ontology/v2/` is the uploaded bundle, not changed. Its header declares CC BY 4.0 and names OpenAI as creator. See [`ATTRIBUTION.md`](ATTRIBUTION.md).
