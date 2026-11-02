"""Verify every fact in docs/upstream-findings.md from the raw sources, with no code from this project.

Each source is pinned to a commit and a SHA-256 digest. The script stops on the first fact that does not hold,
and also when the report text does not state the verified facts.

Usage: python scripts/verify_upstream_findings.py
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache" / "verify"
REPORT = (ROOT / "docs" / "upstream-findings.md").read_text(encoding="utf-8")
GH = "https://raw.githubusercontent.com"
SOURCES = {
    "ctid_nist_16_1.json": (f"{GH}/center-for-threat-informed-defense/mappings-explorer/6bdc3ad33547d5fcb498eede1f07e7db681b00ee/mappings/nist_800_53/attack-16.1/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-16.1-enterprise.json",
                            "355ae97d309c00eb2428e5af07754ff4ca16cfe63928194081d0e883aed929c8"),
    "enterprise_16_1.json": (f"{GH}/mitre-attack/attack-stix-data/7eb3ca57f218e1d4f01afdb3e0cdc3b526556173/enterprise-attack/enterprise-attack-16.1.json",
                             "8423d8dac3fc2feb825bb07d26e5f5d905e08a88f6fe4652cc20834cbe982813"),
    "mobile_16_1.json": (f"{GH}/mitre-attack/attack-stix-data/7eb3ca57f218e1d4f01afdb3e0cdc3b526556173/mobile-attack/mobile-attack-16.1.json",
                         "f84d5bb908c918aadf6cfbdfe0e801fce354e943d999c684b01eefa81da95941"),
    "oscal_2024_02.json": (f"{GH}/usnistgov/oscal-content/941c978d14c57379fbf6f7fb388f675067d5bff7/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
                           "81cf2de45ede9aef3de7ce09d65ea9d32f662c483bbf916f6e346292b22f7763"),
    "oscal_5_2_0.json": (f"{GH}/usnistgov/oscal-content/5006f18c8047643eaa70e35dd0d20a58bcc41856/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
                         "64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb"),
}
# Technique IDs listed in CTID issue #130 (body read with the GitHub API on 2026-11-02, 44 IDs), so the report does not repeat them as new.
ISSUE_130 = set("""T1006 T1007 T1010 T1012 T1014 T1018 T1033 T1039 T1049 T1057 T1069 T1074 T1082 T1083 T1113 T1115 T1120
T1123 T1124 T1125 T1140 T1202 T1207 T1217 T1496 T1497 T1518 T1526 T1529 T1531 T1534 T1600 T1608 T1614 T1615 T1620 T1667 T1668
T1669 T1671 T1672 T1673 T1674 T1675""".split())
assert len(ISSUE_130) == 44


def load(name):
    url, digest = SOURCES[name]
    path = CACHE / name
    if not path.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=120) as r:  # noqa: S310 - pinned https URL
            path.write_bytes(r.read(300 * 1024 * 1024))
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != digest:
        sys.exit(f"{name}: digest {actual} is not the pinned {digest}")
    return json.loads(path.read_text(encoding="utf-8"))


def check(ok, message):
    if not ok:
        sys.exit(f"FAILED: {message}")
    print(f"ok  {message}")


def mitre_id(o):
    return next((r.get("external_id") for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)


def active(o):
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def main():
    ctid = load("ctid_nist_16_1.json")
    rows, meta = ctid["mapping_objects"], ctid["metadata"]
    ent = load("enterprise_16_1.json")["objects"]
    mob = load("mobile_16_1.json")["objects"]
    ent_all = {mitre_id(o): o for o in ent if o["type"] == "attack-pattern"}
    ent_active = {k: o for k, o in ent_all.items() if active(o) and "enterprise-attack" in o.get("x_mitre_domains", [])}
    mob_all = {mitre_id(o): o for o in mob if o["type"] == "attack-pattern"}

    # 1. Mobile technique
    r = rows[636]
    check(r["capability_id"] == "SC-12" and r["attack_object_id"] == "T1521.003" and r["status"] == "complete", "record 637 maps SC-12 to T1521.003")
    check("T1521.003" not in ent_all, "T1521.003 is not an attack-pattern in Enterprise 16.1 in any state")
    check("T1521.003" in mob_all and active(mob_all["T1521.003"]) and mob_all["T1521.003"]["name"] == "SSL Pinning", "T1521.003 SSL Pinning is active in Mobile 16.1")
    check([i + 1 for i, x in enumerate(rows) if "attack_version" in x] == [637] and r["attack_version"] == "[UNKNOWN_VERSION]",
          "record 637 is the only row with attack_version, and its value is [UNKNOWN_VERSION]")

    # 2. Duplicates
    by = defaultdict(list)
    for i, x in enumerate(rows, 1):
        if x["status"] == "complete":
            by[(x["capability_id"], x["attack_object_id"])].append(i)
    dups = {k: v for k, v in by.items() if len(v) > 1}
    check(len(dups) == 50 and all(len(v) == 2 for v in dups.values()), "50 pairs each appear in exactly two rows")
    check(all(len({json.dumps(rows[i - 1], sort_keys=True) for i in v}) == 1 for v in dups.values()), "the two rows of each pair are identical in every field")
    check(all(f"| {c} {t} | {' and '.join(map(str, v))} |" in REPORT for (c, t), v in dups.items()), "the report lists every pair with the correct record numbers")
    check(len(re.findall(r"^\| [A-Z]{2}-\d{2} T\d{4}(?:\.\d{3})? \| \d+ and \d+ \|$", REPORT, re.M)) == 50, "the report table has no other pairs")

    # 3. Titles, in the catalog current when the file was published and in 5.2.0
    expected_controls = {"IA-08": "Identification and Authentication (Non-organizational Users)", "SC-32": "System Partitioning"}
    for name in ("oscal_2024_02.json", "oscal_5_2_0.json"):
        cat = load(name)["catalog"]
        titles, families = {}, {g["id"].upper(): g["title"] for g in cat["groups"]}
        stack = list(cat["groups"])
        while stack:
            g = stack.pop()
            for c in g.get("controls", []):
                label = next((p["value"] for p in c.get("props", []) if p["name"] == "label" and p.get("class") == "zero-padded"), None)
                if label:
                    titles[label] = c["title"]
                stack.append(c)
        source = {x["capability_id"]: x["capability_description"] for x in rows if x["capability_id"]}
        diffs = {c: titles.get(c) for c, t in source.items() if titles.get(c) != t}
        check(all(f"| {c} | {source[c]} | {t} |" in REPORT for c, t in diffs.items()), f"{cat['metadata']['version']}: the report states both titles of each control")
        check(diffs == expected_controls, f"{cat['metadata']['version']}: exactly IA-08 and SC-32 differ, with the titles in the report")
        fam = {g: families.get(g) for g, n in meta["capability_groups"].items() if families.get(g) != n}
        check(fam == {"CA": "Assessment, Authorization, and Monitoring"}, f"{cat['metadata']['version']}: only the CA family name differs")
    check(meta["last_update"] == "04/16/2025" and load("oscal_2024_02.json")["catalog"]["metadata"]["last-modified"].startswith("2024-02-04")
          and "5.1.1+u4" in REPORT, "the report names the catalog version of February 2024; the mapping file was updated on 16 April 2025")
    check(all(t in REPORT for t in ("Information System Partitioning", "System Partitioning", "Security Assessment and Authorization", "Assessment, Authorization, and Monitoring")),
          "the report states the source and catalog titles")

    # 4. Techniques with substantive ATT&CK mitigations but no row
    coa = {o["id"]: mitre_id(o) for o in ent if o["type"] == "course-of-action" and active(o) and (mitre_id(o) or "").startswith("M")}
    stix = {o["id"]: k for k, o in ent_active.items()}
    mits = defaultdict(set)
    for x in ent:
        if x["type"] == "relationship" and x["relationship_type"] == "mitigates" and active(x) and x["source_ref"] in coa and x["target_ref"] in stix:
            mits[stix[x["target_ref"]]].add(coa[x["source_ref"]])
    no_row = set(ent_active) - {x["attack_object_id"] for x in rows}
    substantive = {t for t in no_row if mits[t] - {"M1055", "M1056"}}
    new = substantive - ISSUE_130
    check(len(no_row) == 91 and len(substantive) == 8, "91 active Enterprise 16.1 techniques have no row; 8 have substantive ATT&CK mitigations")
    check(new == {"T1027.006", "T1484.001", "T1484.002", "T1542.002", "T1555.003", "T1564", "T1593"} and substantive - new == {"T1006"},
          "seven of them are not in issue #130; T1006 is")
    mit_names = {mitre_id(o): o["name"] for o in ent if o["type"] == "course-of-action" and active(o)}
    tactic_names = {o["x_mitre_shortname"]: o["name"] for o in ent if o["type"] == "x-mitre-tactic"}
    for t in sorted(new):
        o = ent_active[t]
        tactics = ", ".join(sorted(tactic_names[p["phase_name"]] for p in o["kill_chain_phases"] if p["kill_chain_name"] == "mitre-attack"))
        cells = "; ".join(f"{m} {mit_names[m]}" for m in sorted(mits[t]))
        check(f"| {t} {o['name']} | {tactics} | {cells} |" in REPORT, f"{t}: the report states its name, tactics and ATT&CK 16.1 mitigations exactly")
    o = ent_active["T1006"]
    check(f"T1006 {o['name']}, with {' and '.join(sorted(mits['T1006']))}" in REPORT, "the report states T1006 and its mitigations exactly")

    # 5. Observation
    nm = [x["attack_object_id"] for x in rows if x["status"] == "non_mappable"]
    subst_nm = {t: mits[t] - {"M1055", "M1056"} for t in nm if mits[t] - {"M1055", "M1056"}}
    check(len(set(nm)) == len(nm) == 96 and "3 of the 96 techniques marked non_mappable" in REPORT, "96 techniques are marked non_mappable, one row each")
    names = {t: ent_active[t]["name"] for t in subst_nm}
    check(names == {"T1566.004": "Spearphishing Voice", "T1598.004": "Spearphishing Voice", "T1656": "Impersonation"}
          and mit_names["M1017"] == "User Training" and mit_names["M1019"] == "Threat Intelligence Program", "the names in the observation are correct")
    check(subst_nm == {"T1566.004": {"M1017"}, "T1598.004": {"M1017"}, "T1656": {"M1017", "M1019"}}, "three non-mappable techniques have substantive ATT&CK mitigations, as stated")
    check(next(g["title"] for g in load("oscal_5_2_0.json")["catalog"]["groups"] if g["id"] == "at") == "Awareness and Training", "AT is the Awareness and Training family")
    check("AT" not in meta["capability_groups"], "the AT family is not among the capability groups of the file")
    print("all findings verified")


if __name__ == "__main__":
    main()
