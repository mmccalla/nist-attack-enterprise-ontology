// Unit tests for lib/cisfile.cjs: the reader for the user's own CIS Controls file. Fixtures are synthetic (no CIS text).
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const C = require("../../lib/cisfile.cjs");

const fixture = name => fs.readFileSync(path.join(__dirname, "..", "fixtures", name));
const csv = lines => new TextEncoder().encode(lines.join("\n"));
const HEADER = "CIS Control,CIS Safeguard,Asset Type,Security Function,Title,Description,IG1,IG2,IG3";

test("XLSX and CSV give the same Safeguards", async () => {
  const x = await C.readCisFile(fixture("cis-synthetic.xlsx")), c = await C.readCisFile(fixture("cis-synthetic.csv"));
  assert.deepEqual(x.safeguards, c.safeguards);
  assert.equal(x.version, "8.1.2");
  assert.equal(x.sheet, "Controls v8.1.2 AI Guidance");
  assert.equal(Object.keys(x.safeguards).length, 17);
});

test("Safeguard 3.10, stored as the number 3.1, is numbered by its position", async () => {
  const s = (await C.readCisFile(fixture("cis-synthetic.xlsx"))).safeguards;
  assert.equal(s["CIS-3.1"].title, "Synthetic safeguard 3.1");
  assert.equal(s["CIS-3.10"].title, "Synthetic safeguard 3.10");
  assert.equal(s["CIS-3.11"].title, "Synthetic safeguard 3.11");
});

test("Implementation Groups come from the IG columns", async () => {
  const s = (await C.readCisFile(fixture("cis-synthetic.xlsx"))).safeguards;
  assert.deepEqual(s["CIS-3.1"].ig, ["IG1", "IG2", "IG3"]);
  assert.deepEqual(s["CIS-3.10"].ig, ["IG3"]);
  assert.deepEqual(["IG1", "IG2", "IG3"].map(g => Object.values(s).filter(x => x.ig.includes(g)).length), [3, 8, 17]);
});

test("rich text runs are joined and phonetic runs are left out", () => {
  assert.deepEqual(C.sharedStrings("<sst><si><r><t>CIS </t></r><r><t>Control</t></r><rPh><t>no</t></rPh></si></sst>"), ["CIS Control"]);
});

test("XML entities are decoded once, and markup stays text", () => {
  const rows = C.sheetRows('<row r="1"><c r="A1" t="inlineStr"><is><t>&lt;b&gt; &amp;amp; &#x41;&#66;</t></is></c></row>', []);
  assert.deepEqual(rows, [{A: "<b> &amp; AB"}]);
});

test("a title with HTML is returned as plain text, for the page to escape", async () => {
  const t = (await C.readCisFile(fixture("cis-synthetic.xlsx"))).safeguards["CIS-6.3"].title;
  assert.equal(typeof t, "string");
  assert.ok(t.includes("<img src=x"));
});

test("rows out of CIS order are refused", async () => {
  await assert.rejects(C.readCisFile(csv([HEADER, "3,3.2,Devices,Protect,A,B,x,x,x"])), /not in CIS order/);
});

test("a value that is not a Safeguard number is refused", async () => {
  await assert.rejects(C.readCisFile(csv([HEADER, "3,=cmd|' /C calc'!A0,Devices,Protect,A,B,x,x,x"])), /not a CIS Safeguard number/);
});

test("a file without the CIS columns is refused", async () => {
  await assert.rejects(C.readCisFile(csv(["a,b,c", "1,2,3"])), /No header row/);
});

test("a semicolon CSV is read, and semicolons inside quotes stay in the text", async () => {
  const r = await C.readCisFile(csv([HEADER.replace(/,/g, ";"), '6;6.1;Users;Protect;"Title; with semicolon";"D";x;x;x']));
  assert.equal(r.safeguards["CIS-6.1"].title, "Title; with semicolon");
});

test("a zip bomb is refused", async () => {
  await assert.rejects(C.readCisFile(fixture("cis-bomb.xlsx")), /too large when decompressed/);
});

test("a damaged XLSX is refused", async () => {
  const bytes = new Uint8Array(fixture("cis-synthetic.xlsx"));
  await assert.rejects(C.readCisFile(bytes.subarray(0, 400)), /Not an XLSX file|damaged/);
});

test("a file above the size limit is refused", async () => {
  await assert.rejects(C.readCisFile(new Uint8Array(C.LIMITS.fileBytes + 1)), /larger than/);
});

test("too many rows are refused", async () => {
  const lines = [HEADER]; for (let i = 0; i < C.LIMITS.rows + 1; i++) lines.push("");
  await assert.rejects(C.readCisFile(csv(lines)), /too many rows/);
});

test("Control titles come from the rows without a Safeguard number", async () => {
  const r = await C.readCisFile(fixture("cis-synthetic.xlsx"));
  assert.deepEqual(r.controls, {"CIS-3": "Synthetic control three", "CIS-6": "Synthetic control six"});
});
