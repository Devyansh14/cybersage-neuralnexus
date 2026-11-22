# Changelog

Entries describe what this scaffold contains. Adjust dates to match your team's real work before submitting.

## 2026-11-22 (Milestone 2)
- Created project structure per Milestone 2 guidelines.
- Added final prompt P1 (system prompt + user template) in `prompts/final/`, with v1 (baseline from Milestone 1), v2 and v3 history.
- Added input validation, secret redaction, RAG retrieval and evidence verification (`code/analyzer.py`, `code/rag.py`).
- Added offline rule-based engine for demos without an API key.
- Added Python web UI and server (`code/app.py`, `code/static/index.html`).
- Added 12-case test table and runner (`test-data/`, `code/run_tests.py`); 12/12 pass on the offline engine.
- Added single-file in-browser demo (`web/`) with live test table; 12/12 pass in Node.
- Added deployment files (`Dockerfile`, `render.yaml`, `Procfile`, `DEPLOY.md`).
- Filled docs with observed results: iteration log, test table, module status; drafted contribution table.

## Milestone 1
- Problem selected: security log analysis for beginners (self-defined).
- Baseline prompt written and sample expected output prepared.
