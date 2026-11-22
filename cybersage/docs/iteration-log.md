# Prompt iteration log (P1)

Full text of each version is in `prompts/`. The Result column only contains what was actually observed when this log was written. The sandbox had no network access, so **no LLM was called**: anything about model behaviour is marked NOT RUN and must be replaced with your own numbers from running each version on `test-data/test_cases.json` with your API key.

| Version | What changed | Why it was changed | Result after the change (observed) |
|---|---|---|---|
| v1 | Baseline prompt from Milestone 1 (`prompts/v1/P1_baseline.txt`, 231 characters). Free-text answer, no schema, no examples. | Starting point | Observed by inspection: no output schema, so nothing in the code can parse or verify its answer. Model behaviour: NOT RUN (replace with e.g. "x of 12 acceptable, format varied"). |
| v2 | Added a beginner-analyst role, a JSON output schema and a "never claim a confirmed attack" rule (`prompts/v2/P1_role_and_json.txt`, 528 characters). | v1 output could not be parsed or checked automatically. | Observed by inspection: output now maps to the schema that `analyzer.py` validates (status, summary, findings with evidence, severity, confidence, rationale, actions, limitations). Model behaviour: NOT RUN (replace with e.g. "JSON valid in x of 12 runs"). |
| v3 (final) | Added retrieved reference notes block, 2 worked examples (one benign, one suspicious), prompt-injection rule, secret-handling rule, defensive-only rule; run at temperature 0.2 with JSON mode (`prompts/final/`, system 3,484 + user template 155 characters). | v2 had no grounding in documents, no protection against instructions hidden in logs, and nothing stopping invented evidence. | Observed: the surrounding pipeline passes 12 of 12 tests on its offline engine (6 normal, 4 edge, 2 invalid) and 12 of 12 on the in-browser JS port. These runs do not use the prompts, so they say nothing about prompt quality. Model behaviour of v3: NOT RUN. |

## What the pipeline checks regardless of the prompt (observed)

- Evidence verification: findings whose quoted lines are not found verbatim in the input are downgraded to Low confidence. Covered by the verify step in all 12 runs; every finding raised in tests 1 to 6 had `evidence_verified = true`.
- Redaction: in test 9 three password values were masked before analysis and none appeared in the output.
- Input rejection: empty input (test 11) and plain English (test 12) were rejected with a message; a single log line (test 7) returned `insufficient_information`.

## For the form

Prompt versions (Q18) = **3** (v1, v2, v3/final). Add rows if you save more versions and update Q18.
