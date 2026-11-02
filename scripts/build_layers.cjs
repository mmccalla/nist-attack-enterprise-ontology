// Builds ATT&CK Navigator layers with the shared logic in lib/coverage.cjs.
// Input on stdin: {"model": {...}, "layers": [{"file", "name", "description", "selected": [ids]}]}
// Output on stdout: {"<file>": <layer>}
const coverage = require("../lib/coverage.cjs");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", chunk => { input += chunk; });
process.stdin.on("end", () => {
  const {model, layers} = JSON.parse(input);
  const out = {};
  for (const l of layers) out[l.file] = coverage.navigatorLayer(model, l.name, l.description, new Set(l.selected));
  process.stdout.write(JSON.stringify(out));
});
