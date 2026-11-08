# Contributing

This is a free resource. Reports of wrong or missing mappings, ideas for competency questions and fixes are all welcome.

## Report a problem with a mapping or claim

Open an issue with the **Mapping or claim dispute** template. Give the control, the technique, what you think is wrong and your evidence. The claim pages in the [graph browser](https://mmccalla.github.io/nist-attack-enterprise-ontology/) show the source row number behind every claim, which helps.

The mappings come from the MITRE Center for Threat-Informed Defense. If the source row itself is wrong, the fix belongs upstream; this project will pass it on and record it in `docs/upstream-findings.md`.

## Propose a competency question

Open an issue with the **Competency question** template: who asks it, what decision it supports and what evidence answers it. Accepted questions become a SPARQL file in `queries/` with a test that checks the answer against the raw sources.

## Change code or data

Use Python 3.14 (the version that `requirements-dev.txt` is locked with, and the version CI uses), Java 11 or later (HermiT) and Node.js 24 or later.

```sh
python -m pip install --require-hashes -r requirements-dev.txt
python scripts/build_population.py --check        # downloads the pinned sources once
python scripts/build_exports.py && python scripts/build_api.py && python scripts/build_graph.py
python -m pytest -q tests
python scripts/build_graph.py --poisoned /tmp/poisoned.html
npm ci && npx playwright install chromium && POISONED_PAGE=/tmp/poisoned.html npm run uat
```

How a change reaches `main`:

1. Make the change on a branch and open a pull request.
2. Sign your commits. The rule set on `main` refuses unsigned commits.
3. The pull request needs the CI checks ("Ontology gates", "Browser acceptance") and CodeQL to pass. The branch must be up to date with `main`.
4. The maintainer merges with squash or rebase.

Rules:

- Never edit `data/population.ttl`, `index.html`, `api/` or `exports/` by hand. Change the generator and rebuild.
- Every rule needs a negative probe: a change that breaks it and a test that shows the gate fails.
- Gap analysis logic lives only in `lib/coverage.cjs`. The user's CIS file is read only by `lib/cisfile.cjs`. The browser, the exports and the tests all use these modules.
- Security rules are in `docs/security.md`. Do not add a network call, an external script or an unpinned dependency. To add or update a dependency, change `requirements-dev.in` and lock it on Python 3.14 with `pip-compile --generate-hashes --allow-unsafe --strip-extras --output-file requirements-dev.txt requirements-dev.in`.
- Third-party content keeps its own licence. Read the licence before you import a source, and keep its notice in `NOTICE.md`. Text under a non-commercial or no-derivatives licence goes in a separate file, exactly as published.
- Describe what the tool does and its evidence. Do not compare it with other tools unless you verified the comparison (`tests/test_copy.py`).
- Writing style for docs: Simplified Technical English, no Oxford comma, no em dashes.
