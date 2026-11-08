# Notices

This project combines its own work with content from other publishers. Each part keeps its own licence. The project licences (MIT for code, CC BY 4.0 for the ontology and the project's own data) apply only to the project's own contributions. They do not apply to the third-party content below.

The full licence texts are in [`LICENSES/`](LICENSES). This file is published with the site at `https://mmccalla.github.io/nist-attack-enterprise-ontology/NOTICE.md`. Each API file, Navigator layer and export refers to it.

This project is not affiliated with, sponsored by or endorsed by any publisher below.

## MITRE ATT&CK

Used: technique, tactic, platform and mitigation identifiers, names and relationships from the ATT&CK Enterprise STIX 2.1 bundles 16.1, 19.1 and 20.1 (`mitre-attack/attack-stix-data`). Licence: the ATT&CK terms of use, reproduced in full in [`LICENSES/MITRE-ATTACK-terms-16.1.txt`](LICENSES/MITRE-ATTACK-terms-16.1.txt) and [`LICENSES/MITRE-ATTACK-terms-19.1-20.1.txt`](LICENSES/MITRE-ATTACK-terms-19.1-20.1.txt).

ATT&CK 16.1:

> © 2024 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

ATT&CK 19.1 and 20.1:

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
- CIS mapping: the CTID file's Safeguard titles are not used. The exact titles come from the CIS workbook (see CIS Controls below). The CTID rationale and reference URLs are not changed.

## MITRE ATLAS

Used: tactics, techniques, mitigations, their links and their ATT&CK references from ATLAS 2026.10 (`mitre-atlas/atlas-data`, file `dist/v6/ATLAS-2026.10.yaml`, commit `f56c146`, tag `v2026.10`). Licence: Apache 2.0, in [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt).

> Copyright 2021-2026 MITRE

Changes: converted to RDF, JSON and CSV. Mitigation "use" text is not imported. The "AI agent" flag is derived by this project and is labelled as derived.

## CIS Controls

CIS Controls® is a registered trademark of the Center for Internet Security, Inc. (CIS).

> CIS Critical Security Controls® v8.1.2 © Center for Internet Security, Inc. Licensed under [CC BY-NC-ND 4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/). Exact text, not changed. Use for non-commercial purposes only. Commercial use needs the prior approval of CIS. Refer to [cisecurity.org/controls](https://www.cisecurity.org/controls/) for the most up-to-date guidance. CIS does not sponsor or endorse this project.

Used: the Control and Safeguard titles, asset classes, security functions, Implementation Groups and the AI LLM, AI Agent and MCP guidance from the CIS workbook `CIS_Controls_v8_1_2_AI_Guidance_Combined_Workbook_20260714.xlsx`, sheet "Controls v8.1.2 AI Guidance" (SHA-256 `4cba315d91eb2f22bff54492149058a6d862fbba9d7b906368feab341b792079`), retrieved on 2026-11-04. They are in `data/sources/cis-controls-8.1.2.json`, exact and not changed. The workbook licence permits copies and redistribution for non-commercial purposes, with credit to CIS and a link to the licence. This project is free and non-commercial.

This CIS text is not under the project licences. It appears only in places that state its licence: `data/sources/cis-controls-8.1.2.json`, the page, the `cis_text` part of each `api/v1/cis/safeguards/` file and `exports/cis-8.1.2-safeguards.csv`. The graph, the claims and the other exports hold only CIS IDs. The page shows the AI guidance as CIS text, apart from the project's own text. If you reuse the CIS text, keep the notice above, use it only for non-commercial purposes and do not change it.

The gap analysis shows which ATT&CK techniques the CTID mapping links to the Safeguards that you select. It does not represent or assess compliance with the CIS Controls.

## Cloud Security Alliance Cloud Controls Matrix

This project does not include any CSA CCM content. The CSA terms do not permit redistribution or modification of the CCM. The CTID mapping of CCM to ATT&CK 17.1 is at [ctid.mitre.org/mappings/external/csa_ccm](https://ctid.mitre.org/mappings/external/csa_ccm/).

## NIST OSCAL content and NIST SP 800-53

Used: control identifiers, titles, families and SP 800-53B baseline membership from `usnistgov/oscal-content`. As a work of the United States government, it is in the public domain in the United States, and NIST waives copyright worldwide through [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/). Source: NIST SP 800-53 Rev. 5 and SP 800-53B, National Institute of Standards and Technology. Use of this content does not imply endorsement by NIST.

## OWASP GenAI Security Project

Used: OWASP Top 10 for LLM Applications 2025 item IDs, titles and the ATLAS IDs that OWASP lists under "Related Frameworks and Taxonomies", in `data/sources/owasp-genai.json`, published by the OWASP GenAI Security Project of the OWASP Foundation. Licence: [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). This extract, and the parts of the graph, API and exports derived from it, are shared under CC BY-SA 4.0.

OWASP Top 10 for Agentic Applications for 2026: the list title and link only.

OWASP MCP Top 10 (2025): the IDs, the exact titles and the item links, in `data/sources/owasp-mcp-top10.json`, from the project index at commit `165fe0f` (SHA-256 `4d65ec4917c33b9196b2bc7d15c89935c2084509dbbadf2ec4debf9dcfac7ded`). © OWASP Foundation. Licence: [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/), as the project page links it. Change: one leading space removed from the MCP08 title; no word is changed. These titles are not under the project licence. They appear only in that file, the page, the `api/v1/owasp/MCP*` files and the API index, each with the licence. Non-commercial use only. A work that adapts them must use the same licence.

Changes: extraction of IDs, titles and links only.

## Unified Cyber Ontology

`vendor/uco/core.ttl` is UCO 1.5.0 core. Licence: Apache 2.0, in [`vendor/uco/LICENSE`](vendor/uco/LICENSE). Not changed.

## D3

`vendor/d3.v7.min.js` is D3 7.9.0, © 2010-2023 Mike Bostock. Licence: ISC, in [`LICENSES/ISC-d3.txt`](LICENSES/ISC-d3.txt). Not changed. The page includes the file inline with its copyright line.

## The original ontology bundle

`ontology/v2/` is the uploaded bundle, not changed. Its header declares CC BY 4.0 and names OpenAI as creator. See [`ATTRIBUTION.md`](ATTRIBUTION.md).
