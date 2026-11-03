"""Notices gate: each output keeps the copyright notices and licences that its third-party content requires (D25, D27, D28)."""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTICE = (ROOT / "NOTICE.md").read_text(encoding="utf-8")
LICENSES = ROOT / "LICENSES"
SITE = "https://mmccalla.github.io/nist-attack-enterprise-ontology/"


def attack_notice(name):
    return re.search(r'"(© \d{4} The MITRE Corporation\. [^"]+)"', (LICENSES / name).read_text(encoding="utf-8")).group(1)


NOTICES = {"16": attack_notice("MITRE-ATTACK-terms-16.1.txt"), "19": attack_notice("MITRE-ATTACK-terms-19.1-20.0.txt")}


def test_licence_texts_are_present():
    assert (LICENSES / "Apache-2.0.txt").read_text().lstrip().startswith("Apache License\n                           Version 2.0, January 2004")
    assert "Permission to use, copy, modify, and/or distribute this software" in (LICENSES / "ISC-d3.txt").read_text()
    assert NOTICES["16"].startswith("© 2024") and NOTICES["19"].startswith("© 2026")


def test_notice_file_reproduces_each_upstream_notice():
    for notice in NOTICES.values():
        assert notice in NOTICE
    for text in ("© 2024 MITRE Engenuity. Approved for public release. Document number(s) CT0104.",
                 "© 2024 MITRE. Approved for public release. Document number(s) CT0104.", "Copyright 2021-2026 MITRE",
                 "CC BY-NC-ND 4.0", "does not include any CSA CCM content", "CC BY-SA 4.0", "CC0 1.0"):
        assert text in NOTICE, text
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_population  # noqa: PLC0415

    for key in ("ctid", "cis", "atlas"):
        commit = re.search(r"/([0-9a-f]{40})/", build_population.SOURCES[key][0]).group(1)
        assert f"`{commit[:7]}`" in NOTICE, key


def test_shared_logic_uses_the_published_notices():
    text = (ROOT / "lib" / "coverage.cjs").read_text(encoding="utf-8")
    assert all(n in text for n in NOTICES.values())


def test_each_api_file_links_the_notices():
    n = 0
    for p in (ROOT / "api" / "v1").rglob("*.json"):
        if "schemas" in p.parts or p.name == "openapi.json":
            continue
        assert json.loads(p.read_text())["links"]["notices"] == SITE + "NOTICE.md", p
        n += 1
    assert n > 1200


def test_each_navigator_layer_holds_the_attack_notice_for_its_version():
    for p in (ROOT / "exports" / "navigator").glob("*.json"):
        layer = json.loads(p.read_text())
        meta = {m["name"]: m["value"] for m in layer["metadata"]}
        assert meta["ATT&CK notice"] == NOTICES[layer["versions"]["attack"]], p.name
        assert any(link["url"] == SITE + "NOTICE.md" for link in layer["links"]), p.name


def test_page_and_guides_carry_the_notices():
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    assert "Permission to use, copy, modify, and/or distribute this software" in html  # D3, ISC
    assert 'href="NOTICE.md"' in html
    for name in ("README.md", "exports/README.md", "llms.txt", "ATTRIBUTION.md"):
        assert "NOTICE.md" in (ROOT / name).read_text(encoding="utf-8"), name


def test_cis_rationale_markers_are_counted_in_the_notice():
    markers = (ROOT / "data" / "population.ttl").read_text(encoding="utf-8").count("[title of CIS-")
    assert markers == 1 and "(one row on 2026-11-03)" in NOTICE
