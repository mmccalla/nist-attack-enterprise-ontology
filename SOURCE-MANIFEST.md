# Source manifest

## Original bundle

The five files in `ontology/v2/` are the uploaded bundle `nist_attack_enterprise_ontology_v2_bundle.zip`, unchanged. They are the prior version (1.0.0) of the ontology. The test suite checks these digests so that an edit to them is a deliberate change.

| File | SHA-256 |
| --- | --- |
| `ontology/v2/ONTOLOGY_V2_README.md` | `b4747b47b9dd95d9c792b29dc1aa418950e0897d6b7c75c7b95768baff377f25` |
| `ontology/v2/nist_attack_enterprise_ontology_v2.owl` | `c6f3256a7a0d9c647112fff56b71c79e7e3132540ecefd3dbbb58dcc04059fc4` |
| `ontology/v2/nist_attack_enterprise_ontology_v2.ttl` | `9a6e8c4e12922b99f10eaa58632de97db2fcbb54bde63bf80a778346292dfda3` |
| `ontology/v2/nist_attack_enterprise_population_v2.ttl` | `d14fcd0f23fca5e2f2a1d3875bd47212b565054065efdc27f756f3c4ff95094b` |
| `ontology/v2/nist_attack_enterprise_shapes_v2.ttl` | `b166a22a096f3099f8a6880d21c86113b34860f1db96e371c2767159e9ca57e2` |

## Pinned sources for the 2.0.0 population

`scripts/build_population.py` downloads these files into `.cache/` (not committed) and refuses to build if a digest differs. Each URL names a fixed commit.

| Key | URL | SHA-256 |
| --- | --- | --- |
| HIGH | <https://raw.githubusercontent.com/usnistgov/oscal-content/5006f18c8047643eaa70e35dd0d20a58bcc41856/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_HIGH-baseline_profile.json> | `d2ef340986b9f1ee820ad866a0f964d9a9d1088b24080c74b795ddb0148b9f83` |
| LOW | <https://raw.githubusercontent.com/usnistgov/oscal-content/5006f18c8047643eaa70e35dd0d20a58bcc41856/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_LOW-baseline_profile.json> | `cfd4f5d9a192eb42dc04b745d82f95a85926a2a85a45418034a380a42bda9424` |
| MODERATE | <https://raw.githubusercontent.com/usnistgov/oscal-content/5006f18c8047643eaa70e35dd0d20a58bcc41856/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json> | `e3a0f11237cfaac24dfcf1586e07683f17423757fd84208deb33196b12e8f590` |
| PRIVACY | <https://raw.githubusercontent.com/usnistgov/oscal-content/5006f18c8047643eaa70e35dd0d20a58bcc41856/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_PRIVACY-baseline_profile.json> | `c0e3d54d9f474bc6c33338a8e524bc52ad070f94f9274db7ec48242242fecacc` |
| attack | <https://raw.githubusercontent.com/mitre-attack/attack-stix-data/7eb3ca57f218e1d4f01afdb3e0cdc3b526556173/enterprise-attack/enterprise-attack-16.1.json> | `8423d8dac3fc2feb825bb07d26e5f5d905e08a88f6fe4652cc20834cbe982813` |
| catalog | <https://raw.githubusercontent.com/usnistgov/oscal-content/5006f18c8047643eaa70e35dd0d20a58bcc41856/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json> | `64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb` |
| ctid | <https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/6bdc3ad33547d5fcb498eede1f07e7db681b00ee/mappings/nist_800_53/attack-16.1/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-16.1-enterprise.json> | `355ae97d309c00eb2428e5af07754ff4ca16cfe63928194081d0e883aed929c8` |

## Vendored files

| File | Origin | Licence | SHA-256 |
| --- | --- | --- | --- |
| `vendor/uco/core.ttl` | UCO 1.5.0, `ucoProject/UCO` tag 1.5.0, `ontology/uco/core/core.ttl` | Apache 2.0 (`vendor/uco/LICENSE`) | `aaed3562001e4f5a6b42fde049267a869fff375b1d8f21931dfceae534c2b3c6` |
| `vendor/d3.v7.min.js` | D3 7.9.0, `https://cdn.jsdelivr.net/npm/d3@7.9.0/dist/d3.min.js` | ISC | `f2094bbf6141b359722c4fe454eb6c4b0f0e42cc10cc7af921fc158fceb86539` |

The build inlines D3 into `index.html`, so the page makes no network requests.
