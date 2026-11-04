"""Agent API gate: the static files in api/v1/ are current, valid against their JSON Schemas, consistent with
the raw sources, fully linked and small; the schemas reject bad documents."""

import copy
import csv
import json
import re
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
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
    "a malformed CIS Safeguard id": lambda d: d["cis_claims"][0]["safeguard"].update({"id": "CIS 6.1"}),
    "a CIS claim without evidence": lambda d: d["cis_claims"][0].update({"evidence": []}),
    "no ATT&CK version for CIS": lambda d: d["versions"].pop("attack_cis"),
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
    assert statuses == {"claims": 469, "non_mappable": 96, "no_row": 91, "outside_enterprise": 1, "not_in_attack_16_1": 57}


def test_cis_files_match_the_raw_sources():
    src = sources()
    only19 = set(src.active19) - set(src.to16)
    assert len(only19) == 57
    for p in (API / "techniques").glob("*.json"):
        doc = json.loads(p.read_text())
        tid = doc["id"]
        assert {c["safeguard"]["id"] for c in doc["cis_claims"]} == src.cis_for.get(tid, set()), tid
        assert doc["in_attack_19_1"] == (tid in src.active19), tid
        assert (doc["mapping_status"] == "not_in_attack_16_1") == (tid in only19), tid
        assert set(doc["replaces"]) == src.replaced_by19.get(tid, set()), tid
    rows = defaultdict(set)
    for n, r in enumerate(src.cis_rows, 1):
        rows[r["capability_id"]].add(n)
    files = list((API / "cis" / "safeguards").glob("*.json"))
    assert {p.stem for p in files} == {r["capability_id"] for r in src.cis_rows} and len(files) == 152
    for p in files:
        doc = json.loads(p.read_text())
        sid = doc["id"]
        assert {c["technique"]["id"] for c in doc["claims"]} == {t for t, cs in src.cis_for.items() if sid in cs}, sid
        cited = {e["source_record"] for c in doc["claims"] for e in c["evidence"]} | set(doc["non_mappable_records"])
        assert cited == rows[sid], sid
        assert all(src.cis_rows[n - 1]["status"] == "non_mappable" for n in doc["non_mappable_records"]), sid
        assert all(c["technique"]["in_attack_16_1"] == (c["technique"]["id"] in src.techniques) for c in doc["claims"]), sid
    docs = [json.loads(p.read_text()) for p in files]
    assert sum(1 for d in docs if d["claims"]) == 70 and sum(1 for d in docs if d["non_mappable_records"]) == 82  # README and CHANGELOG


def test_every_reference_resolves_to_a_file():
    have = {kind: {p.stem for p in (API / kind).glob("*.json")} for kind in ("techniques", "controls", "tactics", "mitigations")}
    have["atlas_t"] = {p.stem for p in (API / "atlas" / "techniques").glob("*.json")}
    have["atlas_m"] = {p.stem for p in (API / "atlas" / "mitigations").glob("*.json")}
    have["cis"] = {p.stem for p in (API / "cis" / "safeguards").glob("*.json")}
    for p, doc in documents():
        refs = []
        if doc["type"] == "technique":
            refs += [("controls", c["control"]["id"]) for c in doc["claims"]]
            refs += [("techniques", t) for t in doc["subtechniques"] + ([doc["parent"]] if doc["parent"] else [])]
            refs += [("tactics", t["id"]) for t in doc["tactics"]] + [("mitigations", m["id"]) for m in doc["attack_mitigations"]]
            refs += [("cis", c["safeguard"]["id"]) for c in doc["cis_claims"]] + [("techniques", t) for t in doc["replaces"]]
        elif doc["type"] == "cis-safeguard":
            refs += [("techniques", c["technique"]["id"]) for c in doc["claims"]]
        elif doc["type"] == "control":
            refs += [("techniques", c["technique"]["id"]) for c in doc["claims"]]
        elif doc["type"] in ("tactic", "mitigation"):
            refs += [("techniques", t) for t in doc["techniques"]]
        elif doc["type"] == "baseline":
            refs += [("controls", c) for c in doc["controls"]]
        elif doc["type"] == "atlas-technique":
            refs += [("atlas_m", m["id"]) for m in doc["mitigations"]] + [("atlas_t", t) for t in doc["subtechniques"] + ([doc["parent"]] if doc["parent"] else [])]
            if doc["derived_from_attack"]:
                refs += [("techniques", doc["derived_from_attack"]["id"])] + [("controls", c) for c in doc["derived_from_attack"]["nist_controls_on_attack_technique"]]
        elif doc["type"] == "atlas-mitigation":
            refs += [("atlas_t", t) for t in doc["techniques"]]
        elif doc["type"] == "owasp-risk":
            refs += [("atlas_t", t) for t in doc["related_atlas"]]
        for kind, ref in refs:
            assert ref in have[kind], f"{p.name} refers to missing {kind}/{ref}"


def test_upstream_prose_is_marked_untrusted():
    for p, doc in documents():
        text = json.dumps(doc)
        if doc["type"] == "question":
            assert doc["untrusted_text_fields"] == ["rows"], p
        else:
            for key in ("claims", "cis_claims"):
                for field in ("rationale", "references"):
                    if any(field in e for c in doc.get(key, []) for e in c["evidence"]):
                        assert f"{key}[].evidence[].{field}" in doc["untrusted_text_fields"], (p, key, field)
        assert "<script" not in text.lower(), p


def test_files_are_small_enough_for_agents():
    sizes = {p.name: p.stat().st_size for p in API.rglob("*.json") if p.name != "index.json"}
    assert max(sizes.values()) < 120_000, max(sizes, key=sizes.get)


def test_index_openapi_and_llms_txt_point_at_real_files():
    index = json.loads((API / "index.json").read_text())
    for kind, template in index["url_templates"].items():
        for item in index[kind + "s"]:
            path = template.replace("{id}", item["id"]).replace("{key}", item.get("key", "")).replace(SITE, "")
            assert (ROOT / path).exists(), path
    spec = json.loads((API / "openapi.json").read_text())
    for path, op in spec["paths"].items():
        ref = op["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        assert (ROOT / ref.replace(SITE, "")).exists(), ref
    for url in re.findall(rf"\(({re.escape(SITE)}[^)]+)\)", (ROOT / "llms.txt").read_text()):
        assert (ROOT / url.replace(SITE, "")).exists(), url


def test_atlas_and_owasp_files_match_the_raw_sources():
    src = sources()
    files = {p.stem: json.loads(p.read_text()) for p in (API / "atlas" / "techniques").glob("*.json")}
    assert set(files) == set(src.atlas_techniques)
    for tid, doc in files.items():
        assert {m["id"] for m in doc["mitigations"]} == src.atlas_mitigated_by[tid], tid
        assert doc["agent_related"] == (tid in src.atlas_agent), tid
    owasp = {json.loads(p.read_text())["id"]: json.loads(p.read_text()) for p in (API / "owasp").glob("*.json")}
    llm = next(l for l in src.owasp["lists"] if l["id"] == "owasp-llm-top10-2025")
    for item in llm["items"]:
        assert owasp[item["id"]]["related_atlas"] == sorted(item["related_atlas"]), item["id"]
    mcp = [d for d in owasp.values() if d["id"].startswith("MCP")]
    mcp_text = {i["id"]: i for i in json.loads((ROOT / "data" / "sources" / "owasp-mcp-top10.json").read_text())["items"]}
    assert len(mcp) == 10 and all(d["title"] == mcp_text[d["id"]]["title"] and d["title_licence"]["licence"] == "CC BY-NC-SA 4.0" for d in mcp), \
        "MCP Top 10 titles are exact and carry their CC BY-NC-SA 4.0 attribution (D30)"


CIS_TEXT = json.loads((ROOT / "data" / "sources" / "cis-controls-8.1.2.json").read_text(encoding="utf-8"))
CIS_ALLOWED = {"data/sources/cis-controls-8.1.2.json", "index.html", "exports/cis-8.1.2-safeguards.csv"}


def cis_titles():
    titles = {t["title"] for t in CIS_TEXT["safeguards"].values()} | set(CIS_TEXT["controls"].values())
    nist = set(sources().family_names.values()) | {r["capability_description"] for r in sources().rows if r["capability_description"]}
    return {t for t in titles - nist if len(t.split()) >= 3}


def test_cis_text_appears_only_where_its_licence_is_stated():
    """CIS text (CC BY-NC-ND 4.0) stays out of the CC BY graph, the claims and the other API files (D29)."""
    titles = cis_titles()
    assert len(titles) > 150
    outputs = [ROOT / "llms.txt", ROOT / "data" / "population.ttl"] + list((ROOT / "api").rglob("*.json")) + [p for p in (ROOT / "exports").rglob("*") if p.is_file()]
    texts = {p: p.read_text(encoding="utf-8") for p in outputs if p.relative_to(ROOT).as_posix() not in CIS_ALLOWED and "cis/safeguards" not in p.as_posix()}
    texts[ROOT / "tests/fixtures/cis-synthetic.csv"] = (ROOT / "tests" / "fixtures" / "cis-synthetic.csv").read_text(encoding="utf-8")
    with zipfile.ZipFile(ROOT / "tests" / "fixtures" / "cis-synthetic.xlsx") as z:
        texts[ROOT / "tests/fixtures/cis-synthetic.xlsx"] = " ".join(z.read(n).decode("utf-8") for n in z.namelist())
    for p, text in texts.items():
        found = [t for t in titles if t in text]
        assert not found, f"{p.relative_to(ROOT)} holds CIS text outside its licensed places: {found[:3]}"


def test_cis_text_is_exact_and_attributed_where_it_appears():
    assert CIS_TEXT["licence"] == "CC BY-NC-ND 4.0"
    assert all(t in CIS_TEXT["attribution"] for t in ("© Center for Internet Security", "CC BY-NC-ND 4.0", "non-commercial purposes only", "not changed"))
    assert re.fullmatch(r"[0-9a-f]{64}", CIS_TEXT["source"]["sha256"]) and CIS_TEXT["source"]["sheet"] == "Controls v8.1.2 AI Guidance"
    for p in (API / "cis" / "safeguards").glob("*.json"):
        doc = json.loads(p.read_text())
        t, own = doc["cis_text"], CIS_TEXT["safeguards"][doc["id"]]
        assert (t["title"], t["implementation_groups"], t["attribution"]) == (own["title"], own["implementation_groups"], CIS_TEXT["attribution"]), p.name
        assert "cis_text.title" in doc["untrusted_text_fields"], p.name
    with open(ROOT / "exports" / "cis-8.1.2-safeguards.csv", newline="", encoding="utf-8") as h:
        rows = list(csv.DictReader(h))
    assert {r["safeguard_id"]: r["safeguard_title"] for r in rows} == {k: v["title"] for k, v in CIS_TEXT["safeguards"].items()}
    assert "CC BY-NC-ND 4.0" in (ROOT / "exports" / "README.md").read_text(encoding="utf-8")
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    assert "Center for Internet Security, Inc., <a href=\"https://creativecommons.org/licenses/by-nc-nd/4.0/\"" in html


def test_cis_text_covers_the_mapping_and_records_the_ctid_title_differences():
    """Each Safeguard in the CTID file is in the CIS 8.1.2 workbook. CTID writes five titles differently (D29)."""
    src = sources()
    ctid = {r["capability_id"]: r["capability_description"] for r in src.cis_rows if r["capability_id"]}
    assert set(ctid) <= set(CIS_TEXT["safeguards"]) and len(CIS_TEXT["safeguards"]) == 153 and len(CIS_TEXT["controls"]) == 18
    differ = sorted(k for k in ctid if CIS_TEXT["safeguards"][k]["title"] != ctid[k])
    assert differ == ["CIS-12.5", "CIS-12.7", "CIS-13.5", "CIS-16.1", "CIS-3.11"]
    assert [len([1 for t in CIS_TEXT["safeguards"].values() if g in t["implementation_groups"]]) for g in ("IG1", "IG2", "IG3")] == [56, 130, 153]


def build_population_fetch_cis_metadata():
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_population  # noqa: PLC0415

    return build_population.fetch("cis")["metadata"]


MCP_TEXT = json.loads((ROOT / "data" / "sources" / "owasp-mcp-top10.json").read_text(encoding="utf-8"))


def test_mcp_titles_appear_only_where_their_licence_is_stated():
    """OWASP MCP Top 10 titles (CC BY-NC-SA 4.0) stay out of the CC BY graph and exports (D30)."""
    # A title that is also part of an ATLAS name (Apache 2.0) is a shared term, for example "Tool Poisoning".
    atlas = " | ".join(t["name"] for t in sources().atlas_techniques.values()) + " | " + " | ".join(m["name"] for m in sources().atlas_mitigations.values())
    titles = [i["title"] for i in MCP_TEXT["items"]]
    assert len(titles) == 10 and MCP_TEXT["licence"] == "CC BY-NC-SA 4.0" and "Non-commercial use only" in MCP_TEXT["attribution"]
    assert re.fullmatch(r"[0-9a-f]{40}", MCP_TEXT["source"]["commit"]) and re.fullmatch(r"[0-9a-f]{64}", MCP_TEXT["source"]["sha256"])
    outputs = [ROOT / "llms.txt", ROOT / "data" / "population.ttl", ROOT / "data" / "sources" / "owasp-genai.json"]
    outputs += [p for p in (ROOT / "exports").rglob("*") if p.is_file()] + [p for p in (ROOT / "api").rglob("*.json") if "/owasp/MCP" not in p.as_posix() and p.name != "index.json"]
    for p in outputs:
        text = p.read_text(encoding="utf-8")
        found = [t for t in titles if len(t.split()) >= 2 and t in text and t not in atlas]
        assert not found, f"{p.relative_to(ROOT)} holds an MCP Top 10 title outside its licensed places: {found[:2]}"
    index = json.loads((API / "index.json").read_text())
    assert all(o.get("title_licence") == "CC BY-NC-SA 4.0" for o in index["owasp_risks"] if o["id"].startswith("MCP"))
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    assert "OWASP MCP Top 10 (2025) &copy; OWASP Foundation" in html


def test_cis_ai_guidance_is_exact_where_it_appears():
    for p in (API / "cis" / "safeguards").glob("*.json"):
        doc = json.loads(p.read_text())
        assert doc["cis_text"]["ai_guidance"] == CIS_TEXT["safeguards"][doc["id"]]["ai_guidance"], p.name
    with open(ROOT / "exports" / "cis-8.1.2-safeguards.csv", newline="", encoding="utf-8") as h:
        rows = {r["safeguard_id"]: r for r in csv.DictReader(h)}
    for sid, t in CIS_TEXT["safeguards"].items():
        assert (rows[sid]["cis_ai_llm_guidance"], rows[sid]["cis_ai_agent_guidance"], rows[sid]["cis_mcp_guidance"]) == (t["ai_guidance"]["llm"], t["ai_guidance"]["agent"], t["ai_guidance"]["mcp"]), sid
    filled = {k: sum(1 for t in CIS_TEXT["safeguards"].values() if t["ai_guidance"][k]) for k in ("llm", "agent", "mcp")}
    assert filled == {"llm": 152, "agent": 153, "mcp": 153}
