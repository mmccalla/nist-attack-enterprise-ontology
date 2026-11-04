"""Writes synthetic CIS-like spreadsheets for the tests. The titles are invented: no CIS text is in the repository (D25).

Usage: python tests/fixtures/make_cis_fixtures.py
"""

import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
STAMP = (2026, 1, 1, 0, 0, 0)  # fixed, so the files are the same on each run
HEADER = ["CIS Control", "CIS Safeguard", "Asset Type", "Security Function", "Title", "Description", "IG1", "IG2", "IG3"]
# (control, stored safeguard value, title, ig1, ig2, ig3). 3.10 is stored as 3.1, as Excel does.
ROWS = [("3", None, "Synthetic control three", "", "", "")]
ROWS += [("3", f"3.{i}" if i != 10 else "3.1", f"Synthetic safeguard 3.{i}", "x" if i <= 2 else "", "x" if i <= 5 else "", "x") for i in range(1, 15)]
ROWS += [("6", None, "Synthetic control six", "", "", ""), ("6", "6.1", "Synthetic safeguard 6.1", "x", "x", "x"), ("6", "6.2", "Synthetic safeguard 6.2", "", "x", "x"), ("6", "6.3", 'Synthetic <img src=x onerror="window.__xss=3"> & "quoted"', "", "x", "x")]


def col(i):
    return "ABCDEFGHI"[i]


def xml_escape(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def full(row):
    c, s, t, a, b, d = row
    return [c, s, "Devices" if s else "", "Protect" if s else "", t, "Text with a semicolon; and a comma", a, b, d]


def workbook(rows, inline_last=False):
    rows = [full(r) for r in rows]
    strings, index = [], {}

    def sid(s):
        if s not in index:
            index[s] = len(strings)
            strings.append(s)
        return index[s]

    out = []
    for n, row in enumerate([HEADER] + rows, start=1):
        cells = []
        for i, v in enumerate(row):
            if v in (None, ""):
                continue
            ref = f"{col(i)}{n}"
            if i == 1 and n > 1:
                cells.append(f'<c r="{ref}"><v>{v}</v></c>')
            elif inline_last and n == len(rows) + 1 and i == 4:
                cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{xml_escape(v)}</t></is></c>')
            else:
                cells.append(f'<c r="{ref}" t="s"><v>{sid(v)}</v></c>')
        out.append(f'<row r="{n}">{"".join(cells)}</row>')
    sheet = f'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{"".join(out)}</sheetData></worksheet>'
    # The first string uses rich text runs and a phonetic run, which the reader must skip.
    si = [f"<si><t>{xml_escape(s)}</t></si>" for s in strings]
    si[0] = "<si><r><t>CIS </t></r><r><t>Control</t></r><rPh><t>ignored</t></rPh></si>"
    shared = f'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">{"".join(si)}</sst>'
    book = '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Introduction" sheetId="1"/><sheet name="Controls V8.1" sheetId="2"/></sheets></workbook>'
    intro = '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Synthetic</t></is></c></row></sheetData></worksheet>'
    return {"xl/workbook.xml": book, "xl/sharedStrings.xml": shared, "xl/worksheets/sheet1.xml": intro, "xl/worksheets/sheet2.xml": sheet}


def write_zip(path, parts):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(zipfile.ZipInfo("[Content_Types].xml", STAMP), "<Types/>")
        for name, text in parts.items():
            info = zipfile.ZipInfo(name, STAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, text)


def main():
    write_zip(HERE / "cis-synthetic.xlsx", workbook(ROWS, inline_last=True))
    lines = [",".join(HEADER)]
    for c, s, t, a, b, d in ROWS:
        desc = "Text with a semicolon; and a comma, in quotes"
        lines.append(",".join([c, s or "", "Devices", "Protect", '"' + t.replace('"', '""') + '"', f'"{desc}"', a, b, d]))
    (HERE / "cis-synthetic.csv").write_bytes(("﻿" + "\r\n".join(lines) + "\r\n").encode("utf-8"))
    bomb = workbook(ROWS)
    bomb["xl/sharedStrings.xml"] = "<sst>" + " " * (30 * 1024 * 1024) + "</sst>"
    write_zip(HERE / "cis-bomb.xlsx", bomb)


if __name__ == "__main__":
    main()
