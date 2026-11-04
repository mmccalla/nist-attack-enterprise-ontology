/*
 * Reads a CIS Controls spreadsheet that the user downloaded from CIS (XLSX, or CSV saved from it), in the page.
 * The project distributes no CIS text (decision D25). The user's own copy stays on the user's device and in memory.
 * No dependencies, no network, no DOM, no eval. Works as a browser global (NistAttackCisFile) and as a CommonJS module.
 *
 * Result: {version, sheet, controls: {"CIS-6": title}, safeguards: {"CIS-6.3": {title, assetType, securityFunction, ig: ["IG1", "IG2", "IG3"]}}}
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.NistAttackCisFile = api;
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // Limits for untrusted input. The CIS v8 file is 390 KB, with 153 Safeguards.
  const LIMITS = {fileBytes: 5 * 1024 * 1024, partBytes: 20 * 1024 * 1024, entries: 500, rows: 2000, cellChars: 4000};
  const WANTED = /^xl\/(workbook\.xml|sharedStrings\.xml|worksheets\/sheet\d{1,3}\.xml)$/;

  async function inflateRaw(bytes, cap) {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
    const reader = stream.getReader(), chunks = [];
    let total = 0;
    for (;;) {
      const {done, value} = await reader.read();
      if (done) break;
      total += value.length;
      if (total > cap) { await reader.cancel(); throw new Error("A part of the file is too large when decompressed"); }
      chunks.push(value);
    }
    const out = new Uint8Array(total);
    let at = 0;
    for (const c of chunks) { out.set(c, at); at += c.length; }
    return out;
  }

  /* The parts of an XLSX (a ZIP file) that the reader needs, as text. Reads the central directory only. */
  async function readZipParts(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let eocd = -1;
    for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 22 - 65535); i--) {
      if (view.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error("Not an XLSX file");
    const count = view.getUint16(eocd + 10, true);
    let p = view.getUint32(eocd + 16, true);
    if (count > LIMITS.entries) throw new Error("The file has too many parts");
    const parts = {}, decoder = new TextDecoder("utf-8", {fatal: false});
    for (let n = 0; n < count; n++) {
      if (p + 46 > bytes.length || view.getUint32(p, true) !== 0x02014b50) throw new Error("The XLSX file is damaged");
      const method = view.getUint16(p + 10, true), size = view.getUint32(p + 20, true);
      const nameLen = view.getUint16(p + 28, true), extraLen = view.getUint16(p + 30, true), commentLen = view.getUint16(p + 32, true);
      const local = view.getUint32(p + 42, true);
      const name = decoder.decode(bytes.subarray(p + 46, p + 46 + nameLen));
      p += 46 + nameLen + extraLen + commentLen;
      if (!WANTED.test(name)) continue;
      if (local + 30 > bytes.length || view.getUint32(local, true) !== 0x04034b50) throw new Error("The XLSX file is damaged");
      const start = local + 30 + view.getUint16(local + 26, true) + view.getUint16(local + 28, true);
      if (start + size > bytes.length) throw new Error("The XLSX file is damaged");
      const data = bytes.subarray(start, start + size);
      let raw;
      if (method === 0) raw = data;
      else if (method === 8) raw = await inflateRaw(data, LIMITS.partBytes);
      else throw new Error("The XLSX file uses an unsupported compression method");
      if (raw.length > LIMITS.partBytes) throw new Error("A part of the file is too large");
      parts[name] = decoder.decode(raw);
    }
    return parts;
  }

  const unescapeXml = s => s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (m, e) => {
    const k = e.toLowerCase();
    if (k === "amp") return "&"; if (k === "lt") return "<"; if (k === "gt") return ">"; if (k === "quot") return '"'; if (k === "apos") return "'";
    const code = k.startsWith("#x") ? parseInt(k.slice(2), 16) : parseInt(k.slice(1), 10);
    return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : "";
  });
  const textOf = xml => [...xml.replace(/<rPh\b[\s\S]*?<\/rPh>/g, "").matchAll(/<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g)].map(m => unescapeXml(m[1])).join("");
  const clip = s => String(s).slice(0, LIMITS.cellChars);

  function sharedStrings(xml) {
    return xml ? [...xml.matchAll(/<si>([\s\S]*?)<\/si>/g)].map(m => clip(textOf(m[1]))) : [];
  }

  /* Rows of a worksheet as arrays of {column letter: text}. Numbers stay as the stored text, for example "3.1". */
  function sheetRows(xml, shared) {
    const rows = [];
    for (const r of xml.matchAll(/<row\b[^>]*>([\s\S]*?)<\/row>/g)) {
      if (rows.length >= LIMITS.rows) throw new Error("The sheet has too many rows");
      const row = {};
      for (const c of r[1].matchAll(/<c\b([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)) {
        const ref = /\br="([A-Z]{1,3})\d+"/.exec(c[1]), type = /\bt="([a-zA-Z]+)"/.exec(c[1])?.[1], body = c[2] ?? "";
        if (!ref) continue;
        let value = null;
        if (type === "inlineStr") value = textOf(body);
        else {
          const v = /<v>([\s\S]*?)<\/v>/.exec(body);
          if (v) value = type === "s" ? (shared[Number(v[1])] ?? "") : unescapeXml(v[1]);
        }
        if (value !== null) row[ref[1]] = clip(value);
      }
      rows.push(row);
    }
    return rows;
  }

  /* CSV saved from the CIS spreadsheet: rows as arrays of {column letter: text}, like sheetRows. */
  function csvRows(text) {
    const rows = [];
    let row = [], cell = "", quoted = false;
    // One delimiter for the file, from the first line: descriptions can hold semicolons.
    const first = text.split(/\r?\n/, 1)[0], delim = [",", ";", "\t"].sort((a, b) => first.split(b).length - first.split(a).length)[0];
    const letters = i => { let s = ""; for (i++; i > 0; i = Math.floor((i - 1) / 26)) s = String.fromCharCode(65 + (i - 1) % 26) + s; return s; };
    const push = () => {
      if (rows.length >= LIMITS.rows) throw new Error("The file has too many rows");
      rows.push(Object.fromEntries(row.map((v, i) => [letters(i), clip(v)]).filter(([, v]) => v !== "")));
      row = [];
    };
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (quoted) {
        if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; }
        else if (ch === '"') quoted = false;
        else cell += ch;
      } else if (ch === '"') quoted = true;
      else if (ch === delim) { row.push(cell); cell = ""; }
      else if (ch === "\n" || ch === "\r") {
        if (ch === "\r" && text[i + 1] === "\n") i++;
        row.push(cell); cell = ""; push();
      } else cell += ch;
    }
    if (cell !== "" || row.length) { row.push(cell); push(); }
    return rows;
  }

  const norm = s => String(s ?? "").replace(/\s+/g, " ").trim().toLowerCase();

  /*
   * Safeguards from the rows of the "Controls" sheet. Excel stores Safeguard 3.10 as the number 3.1, so the number
   * is taken from the position of the row in its Control. The file is refused if a stored value disagrees.
   */
  function safeguardsFromRows(rows) {
    const h = rows.findIndex(r => Object.values(r).some(v => norm(v) === "cis safeguard") && Object.values(r).some(v => norm(v) === "title"));
    if (h < 0) throw new Error("No header row with \"CIS Safeguard\" and \"Title\" was found");
    const col = {};
    for (const [letter, v] of Object.entries(rows[h])) col[norm(v)] = letter;
    const C = col["cis control"], S = col["cis safeguard"], T = col["title"];
    if (!C) throw new Error("No \"CIS Control\" column was found");
    const igCols = ["IG1", "IG2", "IG3"].map(g => [g, col[g.toLowerCase()]]).filter(([, c]) => c);
    const position = {}, safeguards = {}, controls = {};
    for (const r of rows.slice(h + 1)) {
      const control = String(r[C] ?? "").replace(/\u00a0/g, "").trim(), stored = String(r[S] ?? "").trim();
      if (!stored) {
        if (/^\d{1,2}$/.test(control) && r[T]) controls[`CIS-${control}`] = String(r[T]).trim();
        continue;
      }
      if (!/^\d{1,2}$/.test(control) || !/^\d{1,2}(\.\d+)?$/.test(stored)) throw new Error(`Row with Safeguard "${stored.slice(0, 20)}" is not a CIS Safeguard number`);
      position[control] = (position[control] ?? 0) + 1;
      const id = `${control}.${position[control]}`;
      if (Math.abs(Number(stored) - Number(id)) > 1e-6) throw new Error(`Safeguard ${id} is stored as ${stored.slice(0, 20)}: the rows are not in CIS order`);
      safeguards[`CIS-${id}`] = {
        title: String(r[T] ?? "").trim(),
        assetType: String(r[col["asset type"] ?? col["asset class"]] ?? "").trim(),  // "Asset Class" in 8.1
        securityFunction: String(r[col["security function"]] ?? "").trim(),
        ig: igCols.filter(([, c]) => norm(r[c]) !== "").map(([g]) => g),
      };
    }
    if (!Object.keys(safeguards).length) throw new Error("The file has no Safeguards");
    return {safeguards, controls};
  }

  async function readCisFile(input) {
    const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    if (bytes.length > LIMITS.fileBytes) throw new Error(`The file is larger than ${LIMITS.fileBytes / 1048576} MB`);
    if (bytes[0] === 0x50 && bytes[1] === 0x4b) {
      const parts = await readZipParts(bytes);
      const wb = parts["xl/workbook.xml"];
      if (!wb) throw new Error("Not an XLSX workbook");
      const names = [...wb.matchAll(/<sheet\b[^>]*\bname="([^"]*)"/g)].map(m => unescapeXml(m[1]));
      const shared = sharedStrings(parts["xl/sharedStrings.xml"]);
      const sheets = Object.keys(parts).filter(n => n.startsWith("xl/worksheets/")).sort((a, b) => a.localeCompare(b, "en", {numeric: true}));
      for (const name of sheets) {
        let found;
        try { found = safeguardsFromRows(sheetRows(parts[name], shared)); } catch (e) { if (/header row/.test(e.message)) continue; throw e; }
        const label = names.find(n => /^controls\s+v\d/i.test(n)) ?? null;
        return {version: label ? /^controls\s+v(\d+(?:\.\d+)*)/i.exec(label)[1] : null, sheet: label, ...found};
      }
      throw new Error("No sheet with \"CIS Safeguard\" and \"Title\" columns was found");
    }
    const text = new TextDecoder("utf-8").decode(bytes).replace(/^﻿/, "");
    return {version: null, sheet: null, ...safeguardsFromRows(csvRows(text))};
  }

  return {readCisFile, readZipParts, sharedStrings, sheetRows, csvRows, safeguardsFromRows, LIMITS};
});
