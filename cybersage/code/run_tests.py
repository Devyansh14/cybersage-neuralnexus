"""Run the CyberSage test table.

Usage:  python code/run_tests.py            (uses the LLM if OPENAI_API_KEY is set)
        python code/run_tests.py --offline  (force the offline heuristic engine)

Writes test-data/results.csv, test-data/results.md and test-data/outputs/*.json.
Pass/Fail is computed against the "expect" rules in test-data/test_cases.json.
Record which engine produced the results in your Milestone 2 PDF.
"""
import csv
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyzer  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "test-data"
SEV = {s: i for i, s in enumerate(analyzer.SEVERITIES)}


def check(result, expect):
    problems = []
    if result.get("status") != expect["status"]:
        problems.append(f"status={result.get('status')}")
    findings = result.get("findings", [])
    if expect.get("no_findings") and findings:
        problems.append(f"{len(findings)} unexpected finding(s)")
    if "title_contains" in expect:
        hit = [f for f in findings if expect["title_contains"].lower() in f["title"].lower()]
        if not hit:
            problems.append("expected finding missing")
        elif "min_severity" in expect and SEV[hit[0]["severity"]] < SEV[expect["min_severity"]]:
            problems.append(f"severity {hit[0]['severity']} below {expect['min_severity']}")
        elif not hit[0].get("evidence_verified"):
            problems.append("evidence not verified")
    if "min_redactions" in expect and result.get("redactions", 0) < expect["min_redactions"]:
        problems.append("redaction missing")
    if "output_must_not_contain" in expect and expect["output_must_not_contain"] in json.dumps(result):
        problems.append("secret leaked in output")
    return problems


def short(result):
    if result.get("status") == "invalid_input":
        return "invalid_input: " + result.get("message", "")
    titles = "; ".join(f"{f['title']} ({f['severity']})" for f in result.get("findings", [])) or "no findings"
    return f"{result.get('status')}: {titles}"


def main():
    offline = "--offline" in sys.argv
    cases = json.loads((DATA / "test_cases.json").read_text(encoding="utf-8"))
    (DATA / "outputs").mkdir(exist_ok=True)
    rows = []
    for c in cases:
        result = analyzer.analyze(c["input"], use_llm=False if offline else None)
        (DATA / "outputs" / f"test_{c['id']:02d}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        problems = check(result, c["expect"])
        rows.append({"Test no.": c["id"], "Input (short)": c["name"], "Type": c["type"],
                     "Expected output": c["expected"], "Actual output (short)": short(result),
                     "Pass / Fail": "Pass" if not problems else "Fail", "Notes": "; ".join(problems),
                     "Engine": result.get("engine")})
    with open(DATA / "results.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    md = ["| Test no. | Input (short) | Type | Expected output | Actual output (short) | Pass / Fail |",
          "|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['Test no.']} | {r['Input (short)']} | {r['Type']} | {r['Expected output']} | {r['Actual output (short)']} | {r['Pass / Fail']} |")
    (DATA / "results.md").write_text("\n".join(md) + f"\n\nEngine: {rows[0]['Engine']}\n", encoding="utf-8")
    passed = sum(r["Pass / Fail"] == "Pass" for r in rows)
    print(f"{passed}/{len(rows)} passed (engine: {rows[0]['Engine']})")
    for r in rows:
        if r["Pass / Fail"] == "Fail":
            print(f"  FAIL test {r['Test no.']}: {r['Notes']}")


if __name__ == "__main__":
    main()
