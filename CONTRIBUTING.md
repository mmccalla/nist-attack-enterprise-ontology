# Contributing

This is a free resource. Reports of wrong or missing mappings, ideas for competency questions and fixes are all welcome.

## Report a problem with a mapping or claim

Open an issue with the **Mapping or claim dispute** template. Give the control, the technique, what you think is wrong and your evidence. The claim pages in the [graph browser](https://mmccalla.github.io/nist-attack-enterprise-ontology/) show the source row number behind every claim, which helps.

The mappings come from the MITRE Center for Threat-Informed Defense. If the source row itself is wrong, the fix belongs upstream; this project will pass it on and record it in `docs/upstream-findings.md`.

## Propose a competency question

Open an issue with the **Competency question** template: who asks it, what decision it supports and what evidence answers it. Accepted questions become a SPARQL file in `queries/` with a test that checks the answer against the raw sources.

## Change code or data

```sh
python -m pip install -r requirements-dev.txt     # needs Java 11+ for the HermiT consistency gate
python scripts/build_population.py --check        # downloads the pinned sources once
python scripts/build_graph.py && python scripts/build_exports.py
python -m pytest -q tests
npm ci && npx playwright install chromium && npm run uat
```

- Never edit `data/population.ttl`, `index.html` or `exports/` by hand; change the generator and rebuild.
- Every rule needs a negative probe: a change that breaks it and a test that shows the gate fails.
- Writing style for docs: plain sentences, no Oxford comma, no em dashes.
