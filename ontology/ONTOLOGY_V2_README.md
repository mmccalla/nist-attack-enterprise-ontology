# Enterprise ontology v2

## Purpose
This version aligns the prior schema-first ontology to stronger information-engineering practice.

## Key changes
1. **Stable versioned ontology IRI pattern**
   - Ontology IRI: `https://w3id.org/example/nist-attack-mapping/ontology/1.0`
   - Data namespace: `https://w3id.org/example/nist-attack-mapping/data/1.0#`
   - This uses a best-practice pattern, though a real deployment should replace `example` with an organisationally governed namespace.

2. **External vocabulary alignment**
   - `skos:Concept` and `skos:ConceptScheme` for mapping types and capability groups.
   - `prov:Entity` and `prov:wasDerivedFrom` for provenance.
   - `dcterms:*` for ontology and dataset metadata.

3. **Clear semantic separation**
   - `SourceAssertion` preserves what the uploaded file says.
   - `MitigatesAssertion` represents source rows with `mapping_type = mitigates`.
   - `NonMappableAssertion` represents source rows with `mapping_type = non_mappable`.
   - `MitigationClaim` represents an enterprise semantic claim interpreted from one or more source assertions.
   - `mitigatesTechnique` is treated as a direct enterprise relation, not as a synonym for a raw source row.

4. **Stronger validation**
   - SHACL patterns for identifiers.
   - Conditional shapes for `MitigatesAssertion` and `NonMappableAssertion`.
   - SPARQL constraint to ensure the asserted capability group matches the control's capability group.
   - SPARQL constraint to ensure each `MitigationClaim` is backed by an assertion over the same control and technique.

5. **Controlled vocabularies**
   - Capability groups are modelled as SKOS concepts in a concept scheme.
   - Mapping types are modelled as SKOS concepts in a concept scheme.

## Source-derived facts
- mapping framework: nist_800_53
- mapping framework version: rev5
- ATT&CK version: 16.1
- technology domain: enterprise
- capability groups: 11
- mapping objects: 5410
- unique controls in source: 109
- unique techniques in source: 566

## Recommended usage
- Load `nist_attack_enterprise_ontology_v2.ttl` as the authoritative ontology schema.
- Load `nist_attack_enterprise_shapes_v2.ttl` for validation.
- Load `nist_attack_enterprise_population_v2.ttl` only as sample population or starting data.
- Replace the namespace with your controlled enterprise namespace before production release.

## Trade-off
This model is more correct and governable than the prior version, but more semantically explicit and therefore slightly heavier to operate.

## File list
- nist_attack_enterprise_ontology_v2.ttl
- nist_attack_enterprise_ontology_v2.owl
- nist_attack_enterprise_shapes_v2.ttl
- nist_attack_enterprise_population_v2.ttl
- ONTOLOGY_V2_README.md
