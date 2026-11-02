"""Agent API gate: the static files in api/v1/ are current, valid against their JSON Schemas, consistent with
the raw sources, fully linked and small; the schemas reject bad documents."""

import copy
import json
import re
import subprocess
import sys
from collections import Counter
from functools import lru_cache
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "api" / "v1"
SITE = "https://mmccalla.github.io/nist-attack-enterprise-ontology/"
sys.path.insert(0, str(ROOT / "tests"))
from source_model import sources  # noqa: E402


@lru_cache(maxsize=1)
def registry():
    resources = []
    for p in (API / "schemas").glob("*.json"):
        schema = json.loads(p.read_text())
        resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def validator(kind):
    schema = json.loads((API / "schemas" / f"{kind}.schema.json").read_text())
    return Draft202012Validator(schema, registry=registry())


def documents():
    for p in sorted(API.rglob("*.json")):
        if "schemas" in p.parts or p.name == "openapi.json":
            continue
        yield p, json.loads(p.read_text())


def test_api_is_up_to_date():
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_api.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_schemas_are_valid_json_schema():
    for p in (API / "schemas").glob("*.json"):
        Draft202012Validator.check_schema(json.loads(p.read_text()))


def test_every_document_obeys_its_schema():
    n = 0
    for p, doc in documents():
        kind = doc["type"]
        assert doc["$schema"] == f"{SITE}api/v1/schemas/{kind}.schema.json", p
        errors = list(validator(kind).iter_errors(doc))
        assert not errors, f"{p.relative_to(ROOT)}: {errors[0].message}"
        n += 1
    assert n > 800


BAD = {
    "an unknown field": lambda d: d.update({"injected": "x"}),
    "a missing required field": lambda d: d.pop("claims"),
    "a malformed technique id": lambda d: d.update({"id": "T78"}),
    "an unknown mapping status": lambda d: d.update({"mapping_status": "secure"}),
    "a claim without evidence": lambda d: d["claims"][0].update({"evidence": []}),
    "a link that is not https": lambda d: d["links"].update({"self": "http://example.org"}),
}


@pytest.mark.parametrize("name", BAD)
def test_schema_rejects(name):
    doc = json.loads((API / "techniques" / "T1078.json").read_text())
    bad = copy.deepcopy(doc)
    BAD[name](bad)
    assert list(validator("technique").iter_errors(bad)), f"schema accepted {name}"


def test_technique_claims_match_the_raw_sources():
    src = sources()
    statuses = Counter()
    for p in (API / "techniques").glob("*.json"):
        doc = json.loads(p.read_text())
        statuses[doc["mapping_status"]] += 1
        assert {c["control"]["id"] for c in doc["claims"]} == src.controls_for.get(doc["id"], set()), doc["id"]
    assert statuses == {"claims": 469, "non_mappable": 96, "no_row": 91, "outside_enterprise": 1}


def test_every_reference_resolves_to_a_file():
    have = {kind: {p.stem for p in (API / kind).glob("*.json")} for kind in ("techniques", "controls", "tactics", "mitigations")}
    for p, doc in documents():
        refs = []
        if doc["type"] == "technique":
            refs += [("controls", c["control"]["id"]) for c in doc["claims"]]
            refs += [("techniques", t) for t in doc["subtechniques"] + ([doc["parent"]] if doc["parent"] else [])]
            refs += [("tactics", t["id"]) for t in doc["tactics"]] + [("mitigations", m["id"]) for m in doc["attack_mitigations"]]
        elif doc["type"] == "control":
            refs += [("techniques", c["technique"]["id"]) for c in doc["claims"]]
        elif doc["type"] in ("tactic", "mitigation"):
            refs += [("techniques", t) for t in doc["techniques"]]
        elif doc["type"] == "baseline":
            refs += [("controls", c) for c in doc["controls"]]
        for kind, ref in refs:
            assert ref in have[kind], f"{p.name} refers to missing {kind}/{ref}"


def test_upstream_prose_is_marked_untrusted():
    for p, doc in documents():
        text = json.dumps(doc)
        if doc["type"] == "question":
            assert doc["untrusted_text_fields"] == ["rows"], p
        elif '"rationale"' in text:
            assert "claims[].evidence[].rationale" in doc["untrusted_text_fields"], p
        assert "<script" not in text.lower(), p


def test_files_are_small_enough_for_agents():
    sizes = {p.name: p.stat().st_size for p in API.rglob("*.json") if p.name != "index.json"}
    assert max(sizes.values()) < 120_000, max(sizes, key=sizes.get)


def test_index_openapi_and_llms_txt_point_at_real_files():
    index = json.loads((API / "index.json").read_text())
    for kind, template in index["url_templates"].items():
        listing = index[kind + "s"] if kind != "mitigation" else index["mitigations"]
        for item in listing:
            path = template.replace("{id}", item["id"]).replace(SITE, "")
            assert (ROOT / path).exists(), path
    spec = json.loads((API / "openapi.json").read_text())
    for path, op in spec["paths"].items():
        ref = op["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        assert (ROOT / ref.replace(SITE, "")).exists(), ref
    for url in re.findall(rf"\(({re.escape(SITE)}[^)]+)\)", (ROOT / "llms.txt").read_text()):
        assert (ROOT / url.replace(SITE, "")).exists(), url
