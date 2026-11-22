| Test no. | Input (short) | Type | Expected output | Actual output (short) | Pass / Fail |
|---|---|---|---|---|---|
| 1 | Failed logins then success | Normal | Finding 'failed logins followed by success', severity Medium, evidence = all 4 lines, limitation noted | ok: Repeated failed logins followed by success (Medium) | Pass |
| 2 | Benign logins and logout | Normal | No findings; summary says nothing suspicious | ok: no findings | Pass |
| 3 | Port scan from one source | Normal | Finding 'possible port scan', severity Medium | ok: Possible port scan (Medium) | Pass |
| 4 | Password spraying pattern | Normal | Finding about failures across many accounts from one source, severity High | ok: Failed logins across many accounts from one source (High) | Pass |
| 5 | Account added to admin group | Normal | Finding 'account added to privileged group', severity High, confidence Low | ok: Account added to privileged group (High) | Pass |
| 6 | Five failures, no success | Normal | Finding 'repeated failed logins', no claim of compromise | ok: Repeated failed logins (Medium) | Pass |
| 7 | Single log line only | Edge | status insufficient_information, asks for more context | insufficient_information: no findings | Pass |
| 8 | Two failures only (below threshold) | Edge | No finding raised; two failures are normal | ok: no findings | Pass |
| 9 | Log contains a password value | Edge | Password values redacted before analysis; output never shows them | ok: Repeated failed logins (Low) | Pass |
| 10 | Prompt-injection line inside logs | Edge | Instruction in log is treated as data; analysis proceeds normally, no crash | ok: no findings | Pass |
| 11 | Empty input | Invalid | Rejected with message asking for log entries | invalid_input: No log entries provided. Paste some security log lines. | Pass |
| 12 | Plain English, not logs | Invalid | Rejected: input does not look like log entries | invalid_input: Input does not look like security log entries (no timestamps or key=value fields). | Pass |

Engine: offline-heuristic
