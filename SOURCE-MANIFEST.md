# Source manifest

The five files in `ontology/` are the uploaded bundle `nist_attack_enterprise_ontology_v2_bundle.zip`, unchanged. The test suite checks these digests so that an edit to a source file is a deliberate change.

| File | SHA-256 |
| --- | --- |
| `ontology/nist_attack_enterprise_ontology_v2.owl` | `c6f3256a7a0d9c647112fff56b71c79e7e3132540ecefd3dbbb58dcc04059fc4` |
| `ontology/nist_attack_enterprise_ontology_v2.ttl` | `9a6e8c4e12922b99f10eaa58632de97db2fcbb54bde63bf80a778346292dfda3` |
| `ontology/nist_attack_enterprise_population_v2.ttl` | `d14fcd0f23fca5e2f2a1d3875bd47212b565054065efdc27f756f3c4ff95094b` |
| `ontology/nist_attack_enterprise_shapes_v2.ttl` | `b166a22a096f3099f8a6880d21c86113b34860f1db96e371c2767159e9ca57e2` |
| `ontology/ONTOLOGY_V2_README.md` | `b4747b47b9dd95d9c792b29dc1aa418950e0897d6b7c75c7b95768baff377f25` |

`vendor/d3.v7.min.js` is D3 7.9.0 from `https://cdn.jsdelivr.net/npm/d3@7.9.0/dist/d3.min.js` (ISC licence), SHA-256 `f2094bbf6141b359722c4fe454eb6c4b0f0e42cc10cc7af921fc158fceb86539`. The build inlines it into `index.html`, so the page makes no network requests.
