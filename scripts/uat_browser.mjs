// Browser acceptance check for index.html.
// Usage: node scripts/uat_browser.mjs [path-or-url] [screenshot-dir]
// Fails on any page error, console error or missing navigation result.
import { chromium } from "playwright";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const target = process.argv[2] ?? "index.html";
const shots = process.argv[3];
const url = /^https?:/.test(target) ? target : pathToFileURL(resolve(target)).href;
const launch = process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {};
const browser = await chromium.launch(launch);
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const errors = [];
page.on("pageerror", e => errors.push(`pageerror: ${e.message}`));
page.on("console", m => { if (m.type() === "error") errors.push(`console: ${m.text()}`); });
page.on("request", r => { if (!r.url().startsWith("file:") && !r.url().startsWith("data:") && !r.url().startsWith(url.split("#")[0])) errors.push(`external request: ${r.url()}`); });

const failures = [];
const check = (ok, message) => { if (!ok) failures.push(message); else console.log(`ok  ${message}`); };
const settle = () => page.waitForTimeout(1200);
const nodes = () => page.locator("#graph .node").count();

await page.goto(url);
await settle();
check((await nodes()) === 120, "overview draws 11 groups and 109 controls");
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
const withProv = await nodes();
await page.uncheck("#prov");
await settle();
const withoutProv = await nodes();
check(withoutProv < withProv, `hiding source rows and claims shrinks AC-02 from ${withProv} to ${withoutProv} nodes`);
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
check(cls.includes("SHACL shape") && cls.includes("same control and technique"), "class view shows its SHACL shape");
if (shots) await page.screenshot({ path: `${shots}/schema.png` });

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

await browser.close();
for (const e of errors) failures.push(e);
if (failures.length) {
  console.error(failures.map(f => `FAIL ${f}`).join("\n"));
  process.exit(1);
}
console.log("all browser checks passed");
