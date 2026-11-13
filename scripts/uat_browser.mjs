// Browser acceptance check for index.html.
// Usage: node scripts/uat_browser.mjs [path-or-url] [screenshot-dir]
// Fails on any page error, console error or missing navigation result.
import { chromium } from "playwright";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { readdirSync, readFileSync } from "node:fs";

const target = process.argv[2] ?? "index.html";
const shots = process.argv[3];
const url = /^https?:/.test(target) ? target : pathToFileURL(resolve(target)).href;
const launch = process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {};
const browser = await chromium.launch(launch);
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
const errors = [];
page.on("pageerror", e => errors.push(`pageerror: ${e.message}`));
const PROBE_HOST = "csp-probe.invalid";
page.on("console", m => { if (m.type() === "error" && !m.text().includes(PROBE_HOST)) errors.push(`console: ${m.text()}`); });
page.on("request", r => { const u = r.url(); if (!u.startsWith("file:") && !u.startsWith("data:") && !u.startsWith("blob:") && !u.includes(PROBE_HOST) && !u.startsWith(url.split("#")[0])) errors.push(`external request: ${u}`); });
page.on("dialog", d => { errors.push(`dialog opened: ${d.message()}`); d.dismiss(); });

const failures = [];
const check = (ok, message) => { if (!ok) failures.push(message); else console.log(`ok  ${message}`); };
const settle = () => page.waitForTimeout(1200);
const nodes = () => page.locator("#graph .node").count();

await page.goto(url);
await settle();
check((await nodes()) === 120, "overview draws 11 groups and 109 controls");

// AC-3: Overview shows 11 NIST families, computed from the data (CIS groups excluded)
// Compute NIST family count inline: CapabilityGroup nodes whose id does not start with "cisgroup_"
const overviewText = await page.locator("#detail").textContent();
const familyCountMatch = overviewText.match(/in their (\d+) families/);
const displayedFamilyCount = familyCountMatch ? parseInt(familyCountMatch[1], 10) : 0;
const nistFamilyCount = await page.evaluate(() => ofType("CapabilityGroup").filter(g => !g.id.startsWith("cisgroup_")).length);
check(displayedFamilyCount === 11, `overview shows 11 families (displayed: ${displayedFamilyCount})`);
check(displayedFamilyCount === nistFamilyCount, `displayed count ${displayedFamilyCount} equals computed NIST families ${nistFamilyCount} (CIS groups excluded)`);

if (shots) await page.screenshot({ path: `${shots}/overview.png` });

await page.fill("#q", "valid accounts");
check(await page.locator("#browse a", { hasText: "T1078" }).first().isVisible(), "search finds T1078 Valid Accounts");
await page.locator("#browse a", { hasText: "T1078" }).first().click();
await settle();
check((await page.locator("#detail h2").textContent()) === "T1078", "selecting a search hit opens the technique");
check(page.url().endsWith("#n/technique_T1078"), "the hash records the selection");

await page.goto(url.split("#")[0] + "#n/claim_AC-02_T1556.009");
await settle();
const claim = await page.locator("#detail").textContent();
check(claim.includes("supported by assertion"), "a claim lists its supporting source row");
check(claim.includes("dynamic account management"), "a claim shows the rationale text from its source row");
check((await nodes()) >= 4, "the claim neighbourhood shows control, technique and source row");
if (shots) await page.screenshot({ path: `${shots}/claim.png` });

await page.goto(url.split("#")[0] + "#n/control_AC-02");
await settle();
const total = async () => +(await page.locator("#crumb").textContent()).match(/of (\d+) neighbours/)[1];
const withProv = await total();
await page.uncheck("#prov");
await settle();
const withoutProv = await total();
check(withoutProv < withProv, `hiding source rows and claims shrinks AC-02 from ${withProv} to ${withoutProv} neighbours`);
await page.check("#prov");

await page.goBack();
await settle();
check((await page.locator("#detail h2").textContent()).startsWith("Claim AC-02"), "back returns to the previous node");

await page.goto(url.split("#")[0] + "#schema");
await settle();
check((await nodes()) >= 11, "schema view draws the OWL classes");
await page.goto(url.split("#")[0] + "#class/:MitigationClaim");
await settle();
const cls = await page.locator("#detail").textContent();
check(cls.includes("SHACL shape") && cls.includes("supportedByAssertion"), "class view shows its SHACL shape");
check(cls.includes("UCO superclass: core:Relationship") && cls.includes("stixObjectType: relationship"), "class view shows the UCO and STIX alignments");
if (shots) await page.screenshot({ path: `${shots}/schema.png` });

await page.goto(url.split("#")[0] + "#questions");
await settle();
const cqCount = readdirSync(new URL("../queries/", import.meta.url)).filter(f => /^cq\d+-.*\.rq$/.test(f)).length;
check((await page.locator("#detail .list a").count()) === cqCount, `questions view lists all ${cqCount} competency questions`);
await page.locator("#detail .list a", { hasText: "CQ01" }).click();
await settle();
const q1 = await page.locator("#detail").textContent();
check(q1.includes("Software engineer") && q1.includes("AC-02") && q1.includes("HIGH LOW MODERATE"), "CQ01 shows persona and answer with baselines");
check((await nodes()) >= 20, "CQ01 draws its answer subgraph");
if (shots) await page.screenshot({ path: `${shots}/question.png` });
await page.locator("#detail table a", { hasText: "IA-02" }).first().click();
await settle();
check(page.url().endsWith("#n/control_IA-02"), "an answer cell opens the node");

await page.goto(url.split("#")[0] + "#n/technique_T1556.009");
await settle();
const t = await page.locator("#detail").textContent();
check(t.includes("sub-technique of") && t.includes("T1556"), "parent technique comes from the STIX subtechnique-of relation");
check(t.includes("in tactic") && t.includes("Credential Access"), "technique shows its tactics");
check((await page.locator('#detail a[href^="https://attack.mitre.org/versions/v16/techniques/T1556/009/"]').count()) === 1, "technique links to ATT&CK version 16");

await page.goto(url.split("#")[0] + "#n/technique_T1070.001");
await settle();
check((await page.locator("#detail").textContent()).includes("Replaced by T1685.005"), "a technique revoked in ATT&CK 20.1 shows its replacement");

await page.goto(url.split("#")[0] + "#n/technique_T1521.003");
await settle();
check((await page.locator("#detail .warn").textContent()).includes("Not an active technique"), "a technique outside Enterprise is flagged");

// Gap analysis
const fixtures = new URL("../tests/fixtures/", import.meta.url);
const exported = name => JSON.parse(readFileSync(new URL(`../exports/navigator/${name}.json`, import.meta.url), "utf8"));
const stats = async () => (await page.locator("#report .stat b").allTextContents()).map(Number);
await page.goto(url.split("#")[0] + "#gaps");
await settle();

// AC-1: The gap-analysis table lists ATT&CK Enterprise tactics, not ATLAS tactics
// Read tactic ids from the rendered table (independent of any helper under test)
const gapTacticRows = await page.locator("#report table.cov tbody tr").all();
const gapTacticIds = await Promise.all(gapTacticRows.map(r => r.locator("td a").first().getAttribute("href").then(h => h?.split("/").pop())));
// (a) No id starts with "atlastactic_" (ATLAS tactics have this prefix in the data)
const hasAtlasTactic = gapTacticIds.some(id => id?.startsWith("atlastactic_"));
check(!hasAtlasTactic, "gap table has no ATLAS tactics (no id starts with atlastactic_)");
// (b) Row count equals the number of ATT&CK Enterprise tactics: 14 (ATT&CK 16.1 has 14 tactics in Enterprise)
check(gapTacticIds.length === 14, `gap table has 14 rows (ATT&CK 16.1 Enterprise tactics), got ${gapTacticIds.length}`);
// (c) No row has all three counts (covered, gap, none) at zero
const rowCounts = await Promise.all(gapTacticRows.map(async r => {
  const cells = await r.locator("td.num").allTextContents();
  return cells.slice(0, 3).map(Number);  // covered, gap, none
}));
const hasAllZeroRow = rowCounts.some(([cov, gap, none]) => cov === 0 && gap === 0 && none === 0);
check(!hasAllZeroRow, "no gap table row has all-zero counts (covered=0, gap=0, none=0)");

// AC-2: Per-tactic counts match 64badaa baseline and sum to technique count
// Baseline values from 64badaa viewer (commit 64badaa6cc8e1f6c2fc3af68bc9fd32db3c79b54) with no controls selected:
// Each row shows [gap, none] because covered=0 when no controls are selected.
// The baseline was captured by running the 64badaa viewer and reading the table.
const baseline64badaa = {
  tactic_TA0043: { gap: 7, none: 37, total: 44 },
  tactic_TA0042: { gap: 0, none: 47, total: 47 },
  tactic_TA0001: { gap: 20, none: 1, total: 21 },
  tactic_TA0002: { gap: 38, none: 0, total: 38 },
  tactic_TA0003: { gap: 108, none: 12, total: 120 },
  tactic_TA0004: { gap: 95, none: 14, total: 109 },
  tactic_TA0005: { gap: 165, none: 39, total: 204 },
  tactic_TA0006: { gap: 63, none: 4, total: 67 },
  tactic_TA0007: { gap: 15, none: 31, total: 46 },
  tactic_TA0008: { gap: 22, none: 1, total: 23 },
  tactic_TA0009: { gap: 27, none: 13, total: 40 },
  tactic_TA0011: { gap: 39, none: 3, total: 42 },
  tactic_TA0010: { gap: 18, none: 1, total: 19 },
  tactic_TA0040: { gap: 26, none: 6, total: 32 },
};
const tacticMismatches = [];
for (let i = 0; i < gapTacticIds.length; i++) {
  const id = gapTacticIds[i];
  const [cov, gap, none] = rowCounts[i];
  const expected = baseline64badaa[id];
  if (!expected) { tacticMismatches.push(`${id}: not in baseline`); continue; }
  if (gap !== expected.gap || none !== expected.none) {
    tacticMismatches.push(`${id}: gap=${gap} none=${none}, expected gap=${expected.gap} none=${expected.none}`);
  }
  if (cov + gap + none !== expected.total) {
    tacticMismatches.push(`${id}: sum=${cov + gap + none}, expected total=${expected.total}`);
  }
}
check(tacticMismatches.length === 0, `gap table per-tactic counts match 64badaa baseline${tacticMismatches.length ? ": " + tacticMismatches.join("; ") : ""}`);

await page.locator('[data-baseline="MODERATE"]').click();
await settle();
const [covM, gapM, noneM, totalM] = await stats();
const moderate = exported("baseline-MODERATE");
const expectedCovered = moderate.techniques.filter(t => "score" in t).length;
check(covM === expectedCovered && totalM === moderate.techniques.length, `MODERATE preset covers ${covM} of ${totalM} techniques, as in the static layer`);
check(page.url().includes("#gaps/AC-02,"), "the selection is kept in the address bar");
const clientLayer = await page.evaluate(() => navigatorLayer("x", "x", gapSelected));
const strip = l => JSON.stringify(l.techniques);
check(strip(clientLayer) === strip(moderate), "the browser's layer matches the static MODERATE layer technique for technique");
const [download] = await Promise.all([page.waitForEvent("download"), page.locator("#gap-layer").click()]);
check(download.suggestedFilename() === "nist-800-53-coverage-layer.json", "the Navigator layer downloads");

await page.locator('[data-baseline="LOW"]').click();
await settle();
const [, gapL] = await stats();
const firstRec = page.locator("#gap-recs li").first();
const recControl = (await firstRec.locator("a").textContent()).trim();
const recGain = +(await firstRec.locator(".count").textContent()).replace("+", "");
check(gapL > 0 && recGain > 0, `LOW leaves ${gapL} gaps; top recommendation ${recControl} closes ${recGain}`);
const input = page.locator("#gap-input");
await input.fill((await input.inputValue()) + ", " + recControl);
await page.waitForTimeout(800);
const [, gapAfter] = await stats();
check(gapAfter === gapL - recGain, `adding ${recControl} closes exactly ${recGain} gaps (${gapL} to ${gapAfter})`);

await page.locator("#gap-file").setInputFiles(new URL("ssp-sample.json", fixtures).pathname);
await page.waitForTimeout(800);
const status = await page.locator("#gap-status").textContent();
check(status.startsWith("2 mapped controls recognised") && status.includes("PM-01") && status.includes("1 enhancement"), "an OSCAL SSP loads: AC-02 and SI-04 mapped, PM-01 reported, the enhancement counted");
check((await input.inputValue()).includes("ac-2.1"), "the SSP control ids appear in the input");
if (shots) await page.screenshot({ path: `${shots}/gaps.png` });

await page.goto(url.split("#")[0] + "#gaps/AC-02");
await settle();
const ac02 = await page.evaluate(() => [...coverage(new Set(["AC-02"])).values()].filter(([st]) => st === "covered").length);
check((await page.locator("#gap-input").inputValue()) === "AC-02" && (await stats())[0] === ac02, `a shared link restores the selection (AC-02 covers ${ac02})`);

await page.goto(url.split("#")[0] + "#q/CQ01");
await settle();
const [csv] = await Promise.all([page.waitForEvent("download"), page.locator("#q-csv").click()]);
check(csv.suggestedFilename() === "cq01.csv", "a question answer downloads as CSV");
await page.goto(url.split("#")[0] + "#n/control_AC-02");
await settle();
const [ctl] = await Promise.all([page.waitForEvent("download"), page.locator("#node-layer").click()]);
check(ctl.suggestedFilename().startsWith("nist-800-53-ac-02"), "a control page downloads its Navigator layer");

// AI and agents: ATLAS, OWASP and the ATLAS gap analysis
await page.goto(url.split("#")[0] + "#n/atlastechnique_AML.T0053");
await settle();
const atl = await page.locator("#detail").textContent();
check(atl.includes("AI Agent Tool Invocation") && atl.includes("Related to AI agents"), "an ATLAS agent technique shows its name and the derived agent flag");
check((await page.locator('#detail a[href="https://atlas.mitre.org/techniques/AML.T0053"]').count()) === 1, "an ATLAS technique links to atlas.mitre.org");
await page.goto(url.split("#")[0] + "#n/owasp_LLM01_2025");
await settle();
const ow = await page.locator("#detail").textContent();
check(ow.includes("Prompt Injection") && ow.includes("AML.T0051.000"), "an OWASP risk shows its published ATLAS links");
await page.goto(url.split("#")[0] + "#gaps-atlas");
await settle();
await page.locator("#atlas-all").click();
await settle();
const [aCov, aGap, aNone, aTotal] = (await page.locator("#report .stat b").allTextContents()).map(Number);
const agentCount = await page.evaluate(() => ofType("AtlasTechnique").filter(n => n.p[":isAgentRelated"] === "true").length);
check(aGap === 0 && aCov + aNone === aTotal && aTotal === agentCount, `with all ATLAS mitigations, ${aCov} of ${aTotal} agent techniques are covered and ${aNone} have no mitigation`);
check(page.url().includes("#gaps-atlas/AML.M"), "the ATLAS selection is kept in the address bar");
check(aNone === 8 && (await page.locator("#detail .warn").first().textContent()).includes("MITRE ATLAS 2026.10, released on 2026-10-28"), "the ATLAS view counts 8 agent techniques with no direct link and names the ATLAS release and its date");
if (shots) await page.screenshot({ path: `${shots}/gaps-atlas.png` });
const parentNote = await page.locator("#report").textContent();
const noParent = await page.evaluate(() => ofType("AtlasTechnique").filter(n => n.p[":isAgentRelated"] === "true" && !atlasMitigationsOf(n.id).length && !atlasParentMitigated(n.id)).length);
check(parentNote.includes(`${aNone - noParent} of these have a mitigation on their parent technique`) && noParent === 4, "the ATLAS view explains parent mitigations and agrees with CQ16 (4)");

// CIS Controls on ATT&CK 19.1 (phase 4a)
const cisLayer = exported("cis-all-safeguards");
await page.goto(url.split("#")[0] + "#gaps-cis");
await settle();
await page.locator("#cis-all").click();
await settle();
const [cCov, cGap, cNone, cTotal] = await stats();
check(cGap === 0 && cCov === cisLayer.techniques.filter(t => "score" in t).length && cTotal === cisLayer.techniques.length,
  `with all CIS Safeguards, ${cCov} of ${cTotal} ATT&CK 19.1 techniques are covered, as in the static layer`);
const cisClient = await page.evaluate(() => C2.navigatorLayer(cisModel(), "x", "x", cisSelected, {attack: "19"}));
check(strip(cisClient) === strip(cisLayer) && cisClient.versions.attack === "19", "the browser's CIS layer matches the static CIS layer technique for technique");
if (shots) await page.screenshot({ path: `${shots}/gaps-cis.png` });
await page.locator("#cis-input").fill("6.3, CIS-99.9");
await settle();
const cisStatus = await page.locator("#cis-status").textContent();
check(cisStatus.startsWith("1 mapped Safeguard recognised") && cisStatus.includes("CIS-99.9"), "a bare Safeguard number is recognised and an unknown ID is reported");
check(page.url().endsWith("#gaps-cis/CIS-6.3"), "the CIS selection is kept in the address bar");
// Implementation Groups from the shipped CIS 8.1.2 data, with no file loaded
await page.goto(url.split("#")[0] + "#gaps-cis");
await settle();
await page.locator('[data-ig="IG1"]').click();
await settle();
const ig1 = (await page.locator("#cis-input").inputValue()).split(", ");
const cis812 = JSON.parse(readFileSync(new URL("../data/sources/cis-controls-8.1.2.json", import.meta.url), "utf8"));
const ig1Expected = await page.evaluate(ids => ids.filter(id => cisModel().mitigates[id]?.length), Object.entries(cis812.safeguards).filter(([, t]) => t.implementation_groups.includes("IG1")).map(([id]) => id));
check(JSON.stringify([...ig1].sort()) === JSON.stringify([...ig1Expected].sort()) && ig1.length > 20, `without a file, IG1 selects the ${ig1.length} mapped Safeguards that CIS 8.1.2 puts in IG1`);

// The user's own CIS file (lib/cisfile.cjs), with synthetic fixtures: no CIS text in the repository
await page.goto(url.split("#")[0] + "#gaps-cis");
await settle();
await page.setInputFiles("#cis-file", new URL("cis-synthetic.xlsx", fixtures).pathname);
await settle();
const fileStatus = await page.locator("#cis-file-status").textContent();
check(fileStatus.startsWith("Read 17 Safeguards from cis-synthetic.xlsx (CIS Controls version 8.1.2)") && !fileStatus.includes("can differ"), "a CIS 8.1.2 file loads, with no version warning");
const igBefore = await page.evaluate(() => cisIg("CIS-1.1"));
check(igBefore.length === 0, "with a file loaded, Safeguards that are not in the file get no Implementation Group from the shipped 8.1.2 data");
await page.locator('[data-ig="IG2"]').click();
await settle();
const ig2 = (await page.locator("#cis-input").inputValue()).split(", ");
const ig2Expected = await page.evaluate(() => Object.entries(CIS_USER.safeguards).filter(([id, sg]) => sg.ig.includes("IG2") && cisModel().mitigates[id]?.length).map(([id]) => id).sort());
check(ig2.length > 0 && JSON.stringify([...ig2].sort()) === JSON.stringify(ig2Expected), `the IG2 button selects the ${ig2.length} mapped Safeguards that the file puts in IG2`);
check((await page.locator("#report").textContent()).includes("Synthetic safeguard") || (await page.locator("#cis-recs").textContent()).includes("Synthetic safeguard"), "titles from the file appear next to the Safeguard IDs");
const [cisCsv] = await Promise.all([page.waitForEvent("download"), page.locator("#cis-recs-csv").click()]);
const cisCsvText = readFileSync(await cisCsv.path(), "utf8");
check(cisCsvText.split("\n")[0] === "rank,safeguard_id,gaps_closed,safeguard_title_from_your_cis_file,implementation_groups", "the recommendations CSV adds the title and the Implementation Groups from the file");
await page.goto(url.split("#")[0] + "#n/cis_CIS-6.3");
await settle();
const own = await page.locator("#detail").textContent();
check(own.includes('Synthetic <img src=x onerror="window.__xss=3">') && await page.evaluate(() => window.__xss === undefined), "a hostile title from the file shows as text and does not run");
await page.goto(url.split("#")[0] + "#gaps-cis");
await settle();
await page.setInputFiles("#cis-file", new URL("cis-bomb.xlsx", fixtures).pathname);
await settle();
check((await page.locator("#cis-file-status").textContent()).includes("too large when decompressed") && await page.evaluate(() => CIS_USER === null), "a zip bomb is refused and no data is kept");
await page.reload();
await settle();
check(await page.evaluate(() => CIS_USER === null && localStorage.length === 0 && sessionStorage.length === 0), "after a reload the page holds no CIS data and stores nothing");

await page.goto(url.split("#")[0] + "#n/cis_CIS-6.3");
await settle();
const sg = await page.locator("#detail").textContent();
const cisText = JSON.parse(readFileSync(new URL("../data/sources/cis-controls-8.1.2.json", import.meta.url), "utf8"));
check(sg.includes(cisText.safeguards["CIS-6.3"].title) && sg.includes("CIS Critical Security Controls® v8.1.2 © Center for Internet Security, Inc., CC BY-NC-ND 4.0"),
  "a Safeguard page shows the exact CIS 8.1.2 title with the CIS notice");
check((await page.locator('#detail a[href="https://www.cisecurity.org/controls/cis-controls-list"]').count()) === 1, "a Safeguard page links to cisecurity.org");
const g63 = cisText.safeguards["CIS-6.3"].ai_guidance;
check(sg.includes("CIS guidance for AI agents") && sg.includes(g63.agent.slice(0, 60)) && sg.includes(g63.mcp.slice(0, 60)), "a Safeguard page shows CIS's own AI agent and MCP guidance");
const mcpText = JSON.parse(readFileSync(new URL("../data/sources/owasp-mcp-top10.json", import.meta.url), "utf8"));
await page.goto(url.split("#")[0] + "#n/owasp_MCP03_2025");
await settle();
const mcp3 = await page.locator("#detail").textContent();
check(mcp3.includes(mcpText.items[2].title) && mcp3.includes("CC BY-NC-SA 4.0") && (await page.locator(`#detail a[href="${mcpText.items[2].url}"]`).count()) === 1,
  "an OWASP MCP risk shows its exact title, its licence and its own OWASP page");
await page.goto(url.split("#")[0] + "#n/technique_T1685");
await settle();
check((await page.locator("#detail .warn").first().textContent()).includes("Only in ATT&CK Enterprise 19.1"), "a technique that is only in ATT&CK 19.1 is flagged");
await page.goto(url.split("#")[0] + "#n/technique_T1562");
await settle();
check((await page.locator("#detail").textContent()).includes("replaces it with T1685"), "a 16.1 technique shows its 19.1 replacement");
await page.goto(url.split("#")[0] + "#n/cisassertion_CIS-2.3_T1021.005");
await settle();
const refHosts = ((await page.locator("#detail").textContent()).match(/https:\/\/[^\s"<>|]+/g) ?? []).map(u => new URL(u).hostname);
const refLinks = await page.locator("#detail a[href]").evaluateAll(as => as.map(a => new URL(a.href, location.href).hostname));
const CIS_DOCS = "cas.docs.cisecurity.org";
check(refHosts.some(h => h === CIS_DOCS) && !refLinks.some(h => h === CIS_DOCS), "a CIS reference URL shows as text, not as a link");

// Security probes (docs/security.md)
const base = url.split("#")[0];
const blocked = await page.evaluate(h => fetch(`https://${h}/x`).then(() => "sent", () => "blocked"), PROBE_HOST);
check(blocked === "blocked", "the Content Security Policy blocks all network requests from the page");
const csp = await page.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute("content");
check(/connect-src 'none'/.test(csp) && !/unsafe-eval/.test(csp) && /script-src 'sha256-/.test(csp), "the policy allows only hashed scripts and no connections");
for (const payload of ['n/<img src=x onerror="window.__xss=1">', 'q/<svg onload="window.__xss=2">', 'gaps/"><img src=x onerror="window.__xss=3">', "class/<img src=x onerror=window.__xss=4>"]) {
  const [route, ...rest] = payload.split("/");  // keep the route separator, encode the value
  await page.goto(`${base}#${route}/${encodeURIComponent(rest.join("/"))}`);
  await settle();
}
check(await page.evaluate(() => window.__xss === undefined), "script in the address bar does not run (four payloads)");
const poisoned = process.env.POISONED_PAGE;
if (poisoned) {
  const probe = await browser.newPage();
  probe.on("dialog", d => { errors.push(`dialog in poisoned page: ${d.message()}`); d.dismiss(); });
  const pageUrl = pathToFileURL(resolve(poisoned)).href;
  for (const h of ["#overview", "#n/technique_T1078", "#n/control_AC-02", "#q/CQ01", "#gaps/AC-02,SI-04", "#n/claim_AC-02_T1556.009", "#about"]) {
    await probe.goto(pageUrl + h);
    await probe.waitForTimeout(700);
  }
  const visible = await probe.locator("#detail").textContent();
  check(await probe.evaluate(() => window.__xss === undefined), "script in poisoned source data does not run");
  check(/<img src=x/.test(visible) || /onerror/.test(visible), "poisoned data shows as text, not as markup");
  await probe.close();
}

await page.goto(url.split("#")[0] + "#n/does_not_exist");
await settle();
check((await page.locator("#detail h2").textContent()) === "Overview", "an unknown id falls back to the overview");

await page.goto(url.split("#")[0] + "#overview");
await settle();
await page.keyboard.press("Tab");
await page.locator("#graph .node").first().focus();
await page.keyboard.press("Enter");
await settle();
check(page.url().includes("#n/"), "a graph node opens with the keyboard");

// Agent API: the files behind the page, read the way an agent reads them (outside the page)
const apiBase = url.split("#")[0].replace(/index\.html$/, "").replace(/\?.*$/, "");
const getJson = async rel => /^https?:/.test(apiBase) ? (await fetch(apiBase + rel)).json() : JSON.parse(readFileSync(new URL(rel, apiBase), "utf8"));
const t1078 = await getJson("api/v1/techniques/T1078.json");
check(t1078.claims.length === 25 && t1078.mapping_status === "claims" && t1078.limits.length > 0, "the API gives T1078 with its 25 claims and its limits");
const apiIndex = await getJson("api/v1/index.json");
check(apiIndex.techniques.length === 714 && apiIndex.url_templates.control.includes("{id}"), "the API index lists every technique (656 in 16.1, 57 only in 19.1, 1 outside Enterprise) and gives URL templates");
const cis63 = await getJson("api/v1/cis/safeguards/CIS-6.3.json");
check(cis63.claims.length > 0 && !("title" in cis63) && cis63.rights.includes("CC BY-NC-ND 4.0"), "the API gives a CIS Safeguard with its claims, its rights statement and no CIS title");

await browser.close();
for (const e of errors) failures.push(e);
if (failures.length) {
  console.error(failures.map(f => `FAIL ${f}`).join("\n"));
  process.exit(1);
}
console.log("all browser checks passed");
