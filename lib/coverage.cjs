/*
 * Gap analysis logic shared by the graph browser, the static exports and (later) the MCP server.
 * One implementation, no dependencies, no network, no DOM. Works as a browser global
 * (NistAttackCoverage) and as a CommonJS module.
 *
 * The model it works on:
 *   { techniques: [{id, name, tactics: [shortname]}],
 *     controls: {"AC-02": {title, baselines: ["LOW", ...]}},
 *     mitigates: {"AC-02": ["T1078", ...]} }
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.NistAttackCoverage = api;
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const STATUS_COLOURS = {covered: "#0ca30c", gap: "#fab219", none: "#d5d9df"};
  const GRADIENT = ["#d9f2d9", "#0ca30c"];
  const LAYER_VERSIONS = {attack: "16", navigator: "4.9.0", layer: "4.5"};
  const SITE = "https://mmccalla.github.io/nist-attack-enterprise-ontology/";
  // Limits for untrusted input (pasted text and OSCAL files).
  const LIMITS = {textChars: 200000, oscalBytes: 20 * 1024 * 1024, controlIds: 5000};

  const tnum = t => t.match(/\d+/g).map(Number);
  const byTechniqueId = (a, b) => {
    const x = tnum(a), y = tnum(b);
    return x[0] - y[0] || (x[1] ?? -1) - (y[1] ?? -1);
  };

  function controlsByTechnique(model) {
    const by = new Map(model.techniques.map(t => [t.id, []]));
    for (const [cid, tids] of Object.entries(model.mitigates))
      for (const tid of tids) if (by.has(tid)) by.get(tid).push(cid);
    for (const list of by.values()) list.sort();
    return by;
  }

  /* Status of every technique for a set of selected control ids: covered, gap or none. */
  function coverage(model, selected) {
    const by = controlsByTechnique(model);
    const out = new Map();
    for (const t of model.techniques) {
      const all = by.get(t.id), covering = all.filter(c => selected.has(c));
      out.set(t.id, covering.length ? ["covered", covering] : all.length ? ["gap", all] : ["none", []]);
    }
    return out;
  }

  function counts(cov) {
    const c = {covered: 0, gap: 0, none: 0};
    for (const [s] of cov.values()) c[s]++;
    return c;
  }

  /* Greedy: each control ranked by the gaps it closes after the ones above it are added. */
  function recommendations(model, selected, limit = 10) {
    const cov = coverage(model, selected);
    const gaps = new Set([...cov].filter(([, [s]]) => s === "gap").map(([t]) => t));
    const picked = [], chosen = new Set(selected);
    while (picked.length < limit && gaps.size) {
      let best = null, bestGain = 0;
      for (const cid of Object.keys(model.controls).sort()) {
        if (chosen.has(cid)) continue;
        const gain = (model.mitigates[cid] ?? []).filter(t => gaps.has(t)).length;
        if (gain > bestGain) { best = cid; bestGain = gain; }
      }
      if (!best) break;
      picked.push([best, bestGain]);
      chosen.add(best);
      for (const t of model.mitigates[best]) gaps.delete(t);
    }
    return picked;
  }

  /* ATT&CK Navigator layer, format 4.5. */
  function navigatorLayer(model, name, description, selected) {
    const cov = coverage(model, selected);
    const ids = [...cov.keys()].sort(byTechniqueId);
    const techniques = ids.map(tid => {
      const [status, controls] = cov.get(tid), e = {techniqueID: tid};
      if (status === "covered") { e.score = controls.length; e.comment = "Mitigated by " + controls.join(", "); }
      else if (status === "gap") { e.color = STATUS_COLOURS.gap; e.comment = "Not covered. Controls that would mitigate it: " + controls.join(", "); }
      else { e.color = STATUS_COLOURS.none; e.comment = "The mapping has no mitigating control for this technique"; }
      if (!tid.includes(".") && ids.some(t => t.startsWith(tid + "."))) e.showSubtechniques = false;
      return e;
    });
    const top = Math.max(1, ...[...cov.values()].filter(([s]) => s === "covered").map(([, c]) => c.length));
    return {
      name, versions: {...LAYER_VERSIONS}, domain: "enterprise-attack", description,
      sorting: 3, layout: {layout: "side", showID: true, showName: true, expandedSubtechniques: "none"}, hideDisabled: false,
      techniques, gradient: {colors: [...GRADIENT], minValue: 1, maxValue: Math.max(top, 2)},
      legendItems: [
        {label: "Covered (darker = more controls)", color: STATUS_COLOURS.covered},
        {label: "Gap: a control exists in the mapping but is not selected", color: STATUS_COLOURS.gap},
        {label: "No mitigating control in the mapping", color: STATUS_COLOURS.none},
      ],
      links: [{label: "NIST 800-53 to ATT&CK ontology", url: SITE}],
      metadata: [
        {name: "Source", value: "CTID NIST 800-53 Rev. 5 to ATT&CK 16.1 Enterprise, claims under rule R1"},
        {name: "Controls selected", value: String(selected.size)},
      ],
    };
  }

  /* Control ids from free text. Enhancements (AC-2(1), ac-2.1) count towards the base control.
     Only ids are kept; nothing else from the text is used. */
  function parseControls(text, known) {
    const found = new Set(), unmapped = new Set();
    let enhancements = 0;
    const input = String(text ?? "").slice(0, LIMITS.textChars);
    for (const m of input.matchAll(/\b([A-Za-z]{2})[-\s]0*(\d{1,2})(?!\d)(?:\s*(?:\(\s*\d+\s*\)|\.\d+))?/g)) {
      if (found.size + unmapped.size >= LIMITS.controlIds) break;
      const id = `${m[1].toUpperCase()}-${m[2].padStart(2, "0")}`;
      if (/[(.]/.test(m[0])) enhancements++;
      (known.has(id) ? found : unmapped).add(id);
    }
    return {found, unmapped: [...unmapped].sort(), enhancements};
  }

  /* IDs of a fixed form (for example ATLAS mitigations, AML.M0024) from free text. Only IDs are kept. */
  function parseIds(text, known, pattern) {
    const found = new Set(), unmapped = new Set();
    const input = String(text ?? "").slice(0, LIMITS.textChars);
    const re = new RegExp(pattern.source, "gi");
    for (const m of input.matchAll(re)) {
      if (found.size + unmapped.size >= LIMITS.controlIds) break;
      const id = m[0].toUpperCase();
      (known.has(id) ? found : unmapped).add(id);
    }
    return {found, unmapped: [...unmapped].sort()};
  }

  /* Control ids from an OSCAL SSP, component definition, profile or catalog. Reads only id fields;
     never returns free text from the document. */
  function controlIdsFromOscal(doc) {
    if (!doc || typeof doc !== "object") throw new Error("Not a JSON object");
    const ids = [];
    const push = v => { if (typeof v === "string" && /^[a-z]{2}-\d{1,2}(\.\d{1,2})?$/i.test(v) && ids.length < LIMITS.controlIds) ids.push(v); };
    const ssp = doc["system-security-plan"], cd = doc["component-definition"], prof = doc.profile, cat = doc.catalog;
    if (ssp) for (const r of ssp["control-implementation"]?.["implemented-requirements"] ?? []) push(r?.["control-id"]);
    if (cd) for (const c of cd.components ?? []) for (const ci of c?.["control-implementations"] ?? []) for (const r of ci?.["implemented-requirements"] ?? []) push(r?.["control-id"]);
    if (prof) for (const imp of prof.imports ?? []) for (const inc of imp?.["include-controls"] ?? []) for (const v of inc?.["with-ids"] ?? []) push(v);
    if (cat) {
      const stack = [cat];
      while (stack.length) {
        const g = stack.pop();
        for (const c of g?.controls ?? []) { push(c?.id); stack.push(c); }
        for (const x of g?.groups ?? []) stack.push(x);
      }
    }
    if (!ssp && !cd && !prof && !cat) throw new Error("Not an OSCAL SSP, component definition, profile or catalog");
    return ids;
  }

  return {coverage, counts, recommendations, navigatorLayer, parseControls, parseIds, controlIdsFromOscal, byTechniqueId, STATUS_COLOURS, LIMITS};
});
