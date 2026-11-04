"""Writes data/sources/owasp-mcp-top10.json: the exact OWASP MCP Top 10 (2025) IDs, titles and item links.

The titles keep their own licence, CC BY-NC-SA 4.0 (decision D30). They are not under the project licence.
Source: the OWASP project index at a pinned commit, checked against its SHA-256 digest.

Usage: python scripts/import_owasp_mcp.py
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMMIT = "165fe0f78ef104459237b4a8e0f6e78db9b02391"
URL = f"https://raw.githubusercontent.com/OWASP/www-project-mcp-top-10/{COMMIT}/index.md"
SHA256 = "4d65ec4917c33b9196b2bc7d15c89935c2084509dbbadf2ec4debf9dcfac7ded"
SITE = "https://owasp.org/www-project-mcp-top-10/"


def main() -> int:
    with urllib.request.urlopen(URL, timeout=60) as r:  # noqa: S310 - pinned https URL on the allowed host
        raw = r.read(1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != SHA256:
        sys.exit(f"index.md digest is not the pinned {SHA256}")
    text = raw.decode("utf-8")
    items = []
    for m in re.finditer(r"^\* (MCP\d{2}:2025) - \[([^\]]+)\]\(([^)]+)\)$", text, re.M):
        # Only the space inside the brackets of MCP08 is removed. No word is changed.
        items.append({"id": m.group(1), "title": m.group(2).strip(), "url": SITE + urllib.parse.quote(m.group(3), safe="/&")})
    if [i["id"] for i in items] != [f"MCP{n:02d}:2025" for n in range(1, 11)]:
        sys.exit("expected MCP01:2025 to MCP10:2025")
    licence = re.search(r"licensed under the \[(CC BY-NC-SA 4\.0)\]\((https://creativecommons\.org/licenses/by-nc-sa/4\.0/)\)", text)
    if not licence:
        sys.exit("the licence statement in index.md has changed")
    out = {
        "title": "OWASP MCP Top 10 (2025): IDs, titles and links",
        "publisher": "OWASP Foundation, OWASP MCP Top 10 project",
        "licence": licence.group(1),
        "licence_url": licence.group(2),
        "attribution": "OWASP MCP Top 10 (2025), OWASP Foundation, licensed under CC BY-NC-SA 4.0. Titles copied exactly; only a leading space in one title is removed. Non-commercial use only. Shares alike: a work that adapts these titles must use the same licence.",
        "source": {"url": URL, "commit": COMMIT, "sha256": SHA256, "page": SITE},
        "items": items,
    }
    path = ROOT / "data" / "sources" / "owasp-mcp-top10.json"
    path.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(items)} items to {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
