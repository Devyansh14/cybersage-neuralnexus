const fs = require("fs");
const path = require("path");
const { analyze } = require("./engine.js");
const SEV = { Low: 0, Medium: 1, High: 2, Critical: 3 };
const cases = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "test-data", "test_cases.json"), "utf8"));
let pass = 0;
for (const c of cases) {
  const r = analyze(c.input), e = c.expect, problems = [];
  if (r.status !== e.status) problems.push("status=" + r.status);
  if (e.no_findings && r.findings.length) problems.push("unexpected findings");
  if (e.title_contains) {
    const hit = r.findings.find(f => f.title.toLowerCase().includes(e.title_contains.toLowerCase()));
    if (!hit) problems.push("finding missing");
    else if (e.min_severity && SEV[hit.severity] < SEV[e.min_severity]) problems.push("severity low");
    else if (!hit.evidence_verified) problems.push("evidence unverified");
  }
  if (e.min_redactions && (r.redactions || 0) < e.min_redactions) problems.push("redaction missing");
  if (e.output_must_not_contain && JSON.stringify(r).includes(e.output_must_not_contain)) problems.push("leak");
  if (!problems.length) pass++; else console.log("FAIL", c.id, problems.join("; "));
}
console.log(pass + "/" + cases.length + " passed (JS engine)");
