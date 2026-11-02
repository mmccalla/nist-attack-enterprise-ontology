"""Supply chain gate (docs/security.md, controls SR-04, SR-11, SI-07, SA-15): every external input is pinned,
and every vendored file matches its recorded digest. Each test fails if a pin is removed."""

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import build_population  # noqa: E402

MANIFEST = (ROOT / "SOURCE-MANIFEST.md").read_text(encoding="utf-8")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_vendored_files_match_the_manifest():
    for rel in ("vendor/d3.v7.min.js", "vendor/uco/core.ttl"):
        assert digest(ROOT / rel) in MANIFEST, f"{rel} does not match SOURCE-MANIFEST.md"


def test_every_source_is_pinned_to_a_commit_and_a_digest():
    for key, (url, sha) in build_population.SOURCES.items():
        assert url.startswith("https://raw.githubusercontent.com/"), key
        assert re.search(r"/[0-9a-f]{40}/", url), f"{key} is not pinned to a commit"
        assert re.fullmatch(r"[0-9a-f]{64}", sha), f"{key} has no SHA-256 digest"


def requirement_blocks(text):
    """One block per requirement: the 'name==version' line and its indented continuation lines."""
    blocks, current = [], None
    for line in text.splitlines():
        if re.match(r"^[A-Za-z0-9_.-]+==", line):
            current = [line]
            blocks.append(current)
        elif current is not None and line.startswith(" "):
            current.append(line)
        else:
            current = None
    return blocks


def test_python_dependencies_are_locked_with_hashes():
    blocks = requirement_blocks((ROOT / "requirements-dev.txt").read_text())
    assert len(blocks) > 10
    for block in blocks:
        assert any("--hash=sha256:" in l for l in block[1:]), f"{block[0].split()[0]} has no hash"


def test_the_hash_check_catches_an_unhashed_pin():
    blocks = requirement_blocks("rdflib==7.6.0\n    # via pyshacl\npyshacl==0.40.1 \\\n    --hash=sha256:" + "0" * 64 + "\n")
    assert [any("--hash=sha256:" in l for l in b[1:]) for b in blocks] == [False, True]


def test_node_dependencies_are_locked_with_integrity():
    lock = json.loads((ROOT / "package-lock.json").read_text())
    for name, pkg in lock.get("packages", {}).items():
        if name:
            assert pkg.get("integrity", "").startswith("sha512-"), name


def test_github_actions_are_pinned_to_commits():
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        for ref in re.findall(r"uses:\s*([^\s#]+)", wf.read_text()):
            assert re.search(r"@[0-9a-f]{40}$", ref), f"{wf.name}: {ref} is not pinned to a commit"


def test_downloads_are_limited_to_the_pinned_host_and_size():
    src = (ROOT / "scripts" / "build_population.py").read_text()
    assert "MAX_SOURCE_BYTES" in src and 'startswith("https://raw.githubusercontent.com/")' in src


def test_no_file_sync_duplicates_in_the_tree():
    """File sync (for example iCloud) makes copies such as 'name 2.md'. They must never reach a commit."""
    dups = [p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*")
            if re.search(r" \d+(\.[^/]+)?$", p.name) and not {".git", "node_modules", ".cache"} & set(p.parts)]
    assert not dups, dups


def test_yaml_is_only_read_with_the_safe_loader():
    for path in list((ROOT / "scripts").glob("*.py")) + list((ROOT / "tests").glob("*.py")):
        text = path.read_text()
        assert not re.search(r"yaml\.(load|unsafe_load|full_load)\(", text), f"{path.name} uses an unsafe YAML loader"
    assert "yaml.safe_load(" in (ROOT / "scripts" / "build_population.py").read_text()
