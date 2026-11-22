# Module status

Observed status when this was written. Tested with the offline engine (Python and in-browser JS). The LLM path could not be run in the sandbox (no network), so it is marked Not verified; do not list it as Working in the form until you have run it with your key.

| Module | What it does | Status | Notes |
|---|---|---|---|
| Input validation and redaction | Rejects empty/oversized/non-log input; masks secrets and emails | Working | Tests 9, 11, 12 pass |
| Knowledge retrieval (RAG) | Ranks knowledge-base sections against the logs | Working | Unit-run only; feeds the LLM prompt, so full effect is not verified |
| Offline analysis engine | Rule-based detection of 4 patterns (failed logins, spraying, port scan, privilege change) | Working | Tests 1 to 10 pass (12/12 overall) |
| Evidence verification | Checks quoted evidence appears verbatim in input | Working | Findings in tests 1 to 6 verified |
| Web app (Python server and UI) | Paste logs, view findings | Working | Smoke-tested: `/`, `/api/health`, `/api/analyze` respond |
| In-browser demo page | Same engine in JavaScript plus live test table | Working | 12/12 in Node; published as a claude.ai artifact |
| LLM analysis (OpenAI) | Sends final prompt, parses JSON | Not verified | Needs API key; update after running |

Q19 suggestion: "Some modules working" until the LLM module is verified, then "All modules working".
Q20 working modules (exact names from this table):
```
1. Input validation and redaction
2. Knowledge retrieval (RAG)
3. Offline analysis engine
4. Evidence verification
5. Web app (Python server and UI)
6. In-browser demo page
```
