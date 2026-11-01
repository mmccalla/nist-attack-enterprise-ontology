# Vocabulary alignment register

The Stage 4 deliverable of *A Practical Guide to Ontology Engineering*. The guide's rule is that reuse needs semantic alignment, not similar names, and that `owl:equivalentClass` and `owl:sameAs` must not be used as loose synonyms. This register records, for every external term considered, the relation used, the strength of the match and the reason. Terms rejected on purpose are listed too.

## How each standard can be aligned

| Standard | Normative form | Consequence |
| --- | --- | --- |
| **UCO 1.5.0** | OWL 2 with SHACL shapes | OWL axioms are possible. The module `ontology/alignment-uco.ttl` uses `rdfs:subClassOf` and `rdfs:subPropertyOf`, and the gate validates the aligned data against UCO's own shapes. |
| **STIX 2.1** and the ATT&CK data model | JSON; no normative RDF or OWL | No OWL axiom can point at a STIX term. `ontology/alignment-stix.ttl` records the correspondence as annotations, and the population carries the STIX `id` of every technique, tactic and ATT&CK mitigation (`:stixId`), the identity link a STIX consumer needs. |
| **NIST OSCAL** | JSON, XML and YAML schemas; no normative RDF | Same approach. `ontology/alignment-oscal.ttl` records the assembly and path for each term, and the population carries `:oscalControlId` and baseline membership. |

## Register

Strength: **exact** means the formal meanings match and an OWL axiom or an identifier carries it; **close** means the meanings match within a stated context; **related** means a useful link that is not a match.

| Local term | External term | Relation used | Strength | Reason |
| --- | --- | --- | --- | --- |
| `:MitigationClaim` | `core:Relationship` (UCO) | `rdfs:subClassOf`, with `core:isDirectional` true and `core:kindOfRelationship` "mitigates" by `owl:hasValue` | exact | UCO defines a relationship as "an assertion that one or more objects are related to another object in some way". A claim is that, from a control to a technique. Subclass, not equivalence: not every UCO relationship is a mitigation claim. |
| `:claimSubjectControl`, `:claimObjectTechnique` | `core:source`, `core:target` | `rdfs:subPropertyOf` | exact | The claim's control is the relationship source and its technique the target, with the cardinalities UCO requires (source at least 1, target exactly 1). |
| `:SourceAssertion` | `core:Assertion` (UCO) | `rdfs:subClassOf` | exact | UCO: "a statement declared to be true". A source row is the publisher's declared statement. |
| `:SecurityControl`, `:AttackTechnique`, `:AttackMitigation` | `core:UcoObject` | `rdfs:subClassOf` | close | Needed because `core:source` and `core:target` require UCO objects. UCO objects represent concepts "inherent to or necessary for characterising the cyber domain", which covers all three. |
| `:controlTitle`, `:techniqueName` | `core:name` | `rdfs:subPropertyOf` | exact | Both are single names; `core:name` allows at most one. |
| `:AttackTechnique` | STIX `attack-pattern` | annotation `:stixObjectType`; `:stixId` on each technique | exact | ATT&CK publishes every technique as an `attack-pattern`. The STIX id is the authoritative identifier. |
| `:Tactic` | STIX `x-mitre-tactic` | annotation; `:stixId` | exact | ATT&CK extension object for tactics. |
| `:inTactic` | STIX `kill_chain_phases` (kill chain mitre-attack) | annotation `:stixProperty` | exact | Phase names match `x_mitre_shortname` of the tactic. |
| `:subTechniqueOf` | STIX relationship `subtechnique-of` | annotation `:stixRelationshipType` | exact | Read from the relationship objects, not inferred from the ID pattern. |
| `:AttackMitigation`, `:attackMitigationFor` | STIX `course-of-action` (Mxxxx), relationship `mitigates` | annotation; `:stixId` | exact | ATT&CK's own mitigation objects and links. |
| `:SecurityControl` | STIX `course-of-action` | annotation, with a note | close | ATT&CK has no NIST control objects. CTID's archived STIX release of the NIST 800-53 Rev. 5 mappings (`attack-control-framework-mappings`) represented each control as a `course-of-action` with `source_name` NIST 800-53 Revision 5. The match holds in that publication's context. |
| `:MitigationClaim` | STIX relationship `mitigates` | annotation | close | The CTID STIX release expressed each mapping as `course-of-action` mitigates `attack-pattern`. The claim adds what STIX lacks: the link to the supporting rows. |
| `:SecurityControl`, `:oscalControlId` | OSCAL catalog `control`, `id` | annotation `:oscalAssembly`, `:oscalPath`; `:oscalControlId` on each control | exact | Resolved through the catalog's own `label` property with class `zero-padded` (value AC-02), so the identity match is authoritative, not lexical. A SHACL rule checks the id form. |
| `:CapabilityGroup` | OSCAL catalog `group` (class family) | annotation; `:oscalFamilyTitle` | exact | The 11 codes are family ids. One title differs (CA; see CQ13). |
| `:ControlBaseline`, `:inBaseline` | OSCAL `profile`, `include-controls` | annotation; `:inBaseline` from `with-ids` | exact | Membership is read from the profile, not from the resolved catalog. |
| `prov:Entity`, `prov:wasDerivedFrom` | PROV-O | reused directly, as in v2 | exact | Provenance of rows, claims and enriched entities. |
| `skos:Concept`, `skos:ConceptScheme`, `skos:broader` | SKOS | reused directly | exact | Controlled vocabularies and the sub-technique hierarchy. |
| `dcterms:*` | DCMI Terms | reused directly | exact | Dataset and ontology metadata. |

## Considered and rejected

| Candidate | Why rejected |
| --- | --- |
| `uco-pattern:Pattern` for `:AttackTechnique` | Similar name only. UCO patterns are logical pattern expressions (regular expressions, query expressions), the kind STIX indicators use. An ATT&CK attack pattern is adversary behaviour. This is the lexical-similarity trap the guide warns about. |
| `uco-action:Action` for `:AttackTechnique` | A UCO action is an occurrence of something done. A technique is a type of behaviour, not an occurrence. |
| `owl:equivalentClass` between `:SecurityControl` and `:AttackMitigation` | Different concepts from different publishers (ambiguity A7). Equivalence would merge their instances under reasoning. |
| `owl:sameAs` between our technique IRIs and STIX ids | STIX ids are strings, not RDF resources. A literal `:stixId` carries the identity without a false identity axiom. |
| `core:ExternalReference` nodes for every STIX and OSCAL identifier | Would double the node count to restate identifiers already held as literals. No competency question needs them. Add a derived export if a UCO consumer requires them. |
| Community RDF renderings of STIX | None is normative or maintained by OASIS; aligning to one would tie the ontology to an unofficial model. |

## How the alignment is checked

- **UCO.** `tests/test_alignment.py` applies RDFS inference and OWL RL rule cls-hv1 (`owl:hasValue`), then validates the graph against UCO core's own SHACL shapes. Negative probes remove the `hasValue` values or break a relationship endpoint, and must fail.
- **STIX and OSCAL.** The population is built only from the pinned files, with digests checked. SHACL checks the identifier forms. The competency tests recompute answers from the raw STIX and OSCAL JSON.
