# CyberSage

**Team:** Neural Nexus (Team ID PE-B49-29) · **Course:** SCSE4041 Prompt Engineering · **Batch:** B49-64

CyberSage is a prompt-engineered AI system that analyzes security log entries and explains suspicious activity in plain language. For each finding it returns the exact evidence lines, a possible threat, severity, confidence with reasoning, defensive actions, and a limitations note. It targets cybersecurity students, beginner analysts and small IT teams.

- Problem source: self-defined (observation that interpreting security logs is hard for beginners)
- Reference: OWASP Logging Cheat Sheet, https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

## How it works

1. **Validate**: rejects empty, oversized or non-log input.
2. **Redact**: masks passwords, tokens, API keys and emails before anything is analyzed.
3. **Retrieve (RAG)**: finds the most relevant notes in `code/knowledge/` (brute force, spraying, port scans, privilege changes, logging basics).
4. **Prompt**: builds the final prompt from `prompts/final/` (system prompt + user template).
5. **Analyze**: calls the OpenAI chat API (temperature 0.2, JSON mode). If no API key is set, or the call fails, an **offline rule-based engine** runs instead so the app can still be demonstrated. The `engine` field in every response says which one ran.
6. **Verify**: every quoted evidence line is checked verbatim against the input; unverified findings are downgraded to Low confidence.
7. **Display**: the web page shows findings as cards.

See `docs/architecture.md` for diagrams.

## Run it

Requires Python 3.9+. No packages to install (standard library only).

```bash
# optional: use the real LLM
export OPENAI_API_KEY=your_key_here        # never commit this
export CYBERSAGE_MODEL=gpt-4o-mini         # optional

python code/app.py
# open http://localhost:8000
```

Run the test table:

```bash
python code/run_tests.py            # uses the LLM if a key is set
python code/run_tests.py --offline  # force offline engine
```

Results are written to `test-data/results.csv`, `test-data/results.md` and `test-data/outputs/`.

## Deploy

See `DEPLOY.md`. `web/index.html` is a single-file static demo (offline engine, live test table) that can be dropped onto Netlify or GitHub Pages; `render.yaml` and `Dockerfile` deploy the full Python app.

## Repository layout

```
README.md
CHANGELOG.md
prompts/
  v1/  v2/  v3/       older prompt versions
  final/              final prompt (system + user template)
code/
  app.py              web server
  analyzer.py         pipeline: validate, redact, retrieve, prompt, analyze, verify
  rag.py              retrieval over code/knowledge
  knowledge/          reference notes
  static/index.html   web UI
  run_tests.py        test runner
web/                  single-file in-browser demo (build.py makes index.html)
test-data/            test inputs and saved outputs
docs/                 diagrams, iteration log, test table, module status, contribution table
DEPLOY.md  Dockerfile  render.yaml  Procfile
```

## Data handling

Use only synthetic or sanitized logs. The app redacts secrets automatically, but do not paste real credentials or confidential logs.

## Team

| Name | Enrollment no. |
|---|---|
| Divyanshu Jashoriya (leader) | S24CSEU0802 |
| Devyansh | S24CSEU1973 |
| Ansh Kumar Bhatt | S24CSEU1736 |
| Shivansh Bhatt | S24CSEU2663 |
| Mayank Sharma | S24CSEU2613 |

Prototype link: _add your deployed/shared link here_
