// Writes data/sources/cis-controls-8.1.2.json from a CIS Controls 8.1.2 workbook that the owner downloaded from CIS.
// Exact CIS text only, unchanged: Control and Safeguard titles, asset classes, security functions, Implementation Groups and the
// AI LLM, AI Agent and MCP guidance of the AI Guidance workbook.
// The file has its own licence (CC BY-NC-ND 4.0, decision D29). The workbook itself is not in the repository.
// Usage: node scripts/import_cis_workbook.cjs <workbook.xlsx> <retrieved YYYY-MM-DD>
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const C = require("../lib/cisfile.cjs");

const [file, retrieved] = process.argv.slice(2);
if (!file || !/^\d{4}-\d{2}-\d{2}$/.test(retrieved ?? "")) { console.error("usage: import_cis_workbook.cjs <workbook.xlsx> <YYYY-MM-DD>"); process.exit(2); }
const bytes = fs.readFileSync(file);
const byId = (a, b) => a.localeCompare(b, "en", {numeric: true});
C.readCisFile(bytes).then(r => {
  if (r.version !== "8.1.2") throw new Error(`expected CIS Controls 8.1.2, found ${r.version}`);
  for (const [id, s] of Object.entries(r.safeguards)) if (s.aiLlm === undefined || s.aiAgent === undefined || s.mcp === undefined) throw new Error(`${id} has no AI guidance columns`);
  const out = {
    title: "CIS Critical Security Controls v8.1.2: Control and Safeguard titles, asset classes, security functions, Implementation Groups and AI guidance (AI LLM, AI Agent, MCP)",
    publisher: "Center for Internet Security, Inc. (CIS)",
    licence: "CC BY-NC-ND 4.0",
    licence_url: "https://creativecommons.org/licenses/by-nc-nd/4.0/",
    attribution: "CIS Critical Security Controls® v8.1.2 © Center for Internet Security, Inc. Licensed under CC BY-NC-ND 4.0. Exact text, not changed. Use for non-commercial purposes only. Commercial use needs the prior approval of CIS. Refer to https://www.cisecurity.org/controls/ for the most up-to-date guidance. CIS does not sponsor or endorse this project.",
    source: {workbook: path.basename(file).replace(/^[0-9a-f]{8}-/, ""), sheet: r.sheet, sha256: crypto.createHash("sha256").update(bytes).digest("hex"), retrieved},
    controls: Object.fromEntries(Object.entries(r.controls).sort(([a], [b]) => byId(a, b))),
    safeguards: Object.fromEntries(Object.entries(r.safeguards).sort(([a], [b]) => byId(a, b)).map(([id, s]) =>
      [id, {title: s.title, asset_class: s.assetType, security_function: s.securityFunction, implementation_groups: s.ig,
            ai_guidance: {llm: s.aiLlm, agent: s.aiAgent, mcp: s.mcp}}])),
  };
  fs.writeFileSync(path.join(__dirname, "..", "data", "sources", "cis-controls-8.1.2.json"), JSON.stringify(out, null, 1) + "\n");
  console.log(`wrote ${Object.keys(out.controls).length} Controls and ${Object.keys(out.safeguards).length} Safeguards`);
}).catch(e => { console.error(e.message); process.exit(1); });
