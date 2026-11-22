"""CyberSage analysis pipeline.

Steps: validate input -> redact secrets -> retrieve knowledge (RAG) -> build
prompt -> LLM call (OpenAI) or offline heuristic engine -> verify evidence.

Set OPENAI_API_KEY to use the LLM. Without a key the offline heuristic engine
runs so the app can still be demonstrated; it is NOT the LLM and the response
says so in "engine".
"""
import json
import os
import re
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

import rag

ROOT = Path(__file__).resolve().parent.parent
PROMPT_DIR = ROOT / "prompts" / "final"
MAX_LINES = 200
MAX_CHARS = 20000
SEVERITIES = ["Low", "Medium", "High", "Critical"]
CONFIDENCES = ["Low", "Medium", "High"]
ADMIN_GROUPS = {"admin", "administrators", "sudo", "wheel", "root"}

TIME_RE = re.compile(r"\b\d{1,2}:\d{2}:\d{2}\b")
KV_RE = re.compile(r"\b[A-Za-z_]+=\S+")
SECRET_RE = re.compile(r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)\s*[=:]\s*\S+")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


# ---------- step 1: validation and redaction ----------
def validate_input(raw):
    """Return (ok, message, lines)."""
    if raw is None or not raw.strip():
        return False, "No log entries provided. Paste some security log lines.", []
    if len(raw) > MAX_CHARS:
        return False, f"Input too long (limit {MAX_CHARS} characters).", []
    lines = [l.rstrip() for l in raw.splitlines() if l.strip()]
    if len(lines) > MAX_LINES:
        return False, f"Too many lines (limit {MAX_LINES}).", []
    loglike = sum(1 for l in lines if TIME_RE.search(l) or KV_RE.search(l))
    if loglike / len(lines) < 0.5:
        return False, "Input does not look like security log entries (no timestamps or key=value fields).", []
    return True, "", lines


def redact(lines):
    out, count = [], 0
    for l in lines:
        new, n1 = SECRET_RE.subn(lambda m: m.group(1) + "=[REDACTED]", l)
        new, n2 = EMAIL_RE.subn("[EMAIL]", new)
        count += n1 + n2
        out.append(new)
    return out, count


# ---------- parsing ----------
def parse_line(line):
    fields = dict(m.split("=", 1) for m in KV_RE.findall(line))
    tokens = line.split()
    event, tsec = None, None
    m = TIME_RE.search(line)
    if m:
        h, mi, s = (int(x) for x in m.group(0).split(":"))
        tsec = h * 3600 + mi * 60 + s
        after = line[m.end():].split()
        for tok in after:
            if "=" not in tok:
                event = tok.upper()
                break
    elif tokens:
        event = tokens[0].upper()
    return {"raw": line, "event": event, "t": tsec, "f": fields}


def _span(rows):
    ts = [r["t"] for r in rows if r["t"] is not None]
    return (max(ts) - min(ts)) if len(ts) > 1 else None


def _fmt_span(sec):
    if sec is None:
        return "an unknown time span"
    return f"{sec} seconds" if sec < 120 else f"about {round(sec / 60)} minutes"


# ---------- offline heuristic engine ----------
def heuristic_analyze(lines):
    rows = [parse_line(l) for l in lines]
    if len(rows) < 3:
        return {"status": "insufficient_information",
                "summary": "Too few log entries to judge. Provide more context (at least a few related lines).",
                "findings": []}
    findings = []
    auth = [r for r in rows if r["event"] and ("LOGIN" in r["event"] or "AUTH" in r["event"])]
    fails_by_pair = defaultdict(list)
    fails_by_src = defaultdict(list)
    succ = []
    for r in auth:
        res = r["f"].get("result", "").upper()
        src, user = r["f"].get("src"), r["f"].get("user")
        if res in ("FAIL", "FAILED", "FAILURE"):
            fails_by_pair[(src, user)].append(r)
            fails_by_src[src].append(r)
        elif res in ("SUCCESS", "OK"):
            succ.append(r)

    for (src, user), fl in fails_by_pair.items():
        if len(fl) < 3:
            continue
        later = [s for s in succ if s["f"].get("src") == src and s["f"].get("user") == user
                 and s["t"] is not None and fl[-1]["t"] is not None and s["t"] >= fl[-1]["t"]]
        ev = [r["raw"] for r in fl] + [later[0]["raw"]] if later else [r["raw"] for r in fl]
        span = _span(fl + later[:1])
        if later:
            findings.append({
                "title": "Repeated failed logins followed by success",
                "evidence": ev,
                "possible_threat": "Repeated authentication failures may indicate a password-guessing attempt that eventually succeeded.",
                "severity": "High" if len(fl) >= 5 else "Medium",
                "confidence": "Medium",
                "rationale": f"{len(fl)} failures for user {user} from {src} within {_fmt_span(span)}, then a success. Could also be the real user mistyping.",
                "recommended_actions": ["Verify with the account owner that the successful login was theirs",
                                        "Review other activity from this address",
                                        "Consider a password reset and enabling MFA"],
                "limitations": "These events alone do not confirm an attack."})
        else:
            findings.append({
                "title": "Repeated failed logins",
                "evidence": ev,
                "possible_threat": "Repeated failures may indicate a password-guessing attempt.",
                "severity": "Medium" if len(fl) >= 5 else "Low",
                "confidence": "Medium" if len(fl) >= 5 else "Low",
                "rationale": f"{len(fl)} failures for user {user} from {src} within {_fmt_span(span)}, with no success shown.",
                "recommended_actions": ["Check whether the user is locked out or forgot their password",
                                        "Consider rate limiting or temporary blocking of the source"],
                "limitations": "Failed logins have many innocent causes; no success is visible in the provided logs."})

    for src, fl in fails_by_src.items():
        users = {r["f"].get("user") for r in fl}
        if len(users) >= 3:
            findings.append({
                "title": "Failed logins across many accounts from one source",
                "evidence": [r["raw"] for r in fl][:10],
                "possible_threat": "Failures against many different accounts from one address may indicate password spraying.",
                "severity": "High",
                "confidence": "Medium",
                "rationale": f"{len(users)} different users failed from {src} within {_fmt_span(_span(fl))}.",
                "recommended_actions": ["Block or rate-limit the source address", "Require MFA",
                                        "Check whether any targeted account later shows a successful login"],
                "limitations": "A shared office or proxy address could produce similar patterns."})

    deny = defaultdict(list)
    for r in rows:
        ev = r["event"] or ""
        if ("DENY" in ev or "BLOCK" in ev or "DROP" in ev or "CONN" in ev) and r["f"].get("dport") and r["f"].get("src"):
            if "ALLOW" in r["f"].get("action", "").upper() or r["f"].get("result", "").upper() == "ALLOW":
                continue
            deny[r["f"]["src"]].append(r)
    for src, dl in deny.items():
        ports = {r["f"]["dport"] for r in dl}
        if len(ports) >= 5:
            findings.append({
                "title": "Possible port scan",
                "evidence": [r["raw"] for r in dl][:10],
                "possible_threat": "Blocked connections to many different ports from one address may indicate port scanning.",
                "severity": "Medium",
                "confidence": "Medium",
                "rationale": f"{len(ports)} distinct destination ports probed by {src} within {_fmt_span(_span(dl))}.",
                "recommended_actions": ["Block or rate-limit the source", "Confirm only required ports are exposed",
                                        "Watch for later successful connections from this address"],
                "limitations": "Scans are common internet background noise; the logs show no successful access."})

    for r in rows:
        if r["event"] in ("GROUP_ADD", "PRIV_ESC", "ROLE_GRANT") and \
                r["f"].get("group", r["f"].get("role", "")).lower() in ADMIN_GROUPS:
            findings.append({
                "title": "Account added to privileged group",
                "evidence": [r["raw"]],
                "possible_threat": "Granting administrative rights may indicate privilege escalation, or an approved admin change.",
                "severity": "High",
                "confidence": "Low",
                "rationale": "Privilege changes are high impact, but the logs do not show whether the change was approved.",
                "recommended_actions": ["Confirm the change with its owner", "Review who made it and when",
                                        "Remove the privilege if unapproved"],
                "limitations": "Cannot tell from this line whether the change was authorised."})

    if findings:
        return {"status": "ok", "summary": f"{len(findings)} possible issue(s) found; verify each before acting.", "findings": findings}
    return {"status": "ok", "summary": "No suspicious pattern found in the provided entries.", "findings": []}


# ---------- LLM engine ----------
def build_messages(lines, context_chunks):
    system = (PROMPT_DIR / "P1_system.txt").read_text(encoding="utf-8")
    tmpl = (PROMPT_DIR / "P1_user_template.txt").read_text(encoding="utf-8")
    ctx = "\n\n".join(c["text"] for c in context_chunks) or "(no reference notes retrieved)"
    user = tmpl.replace("{knowledge_context}", ctx).replace("{log_entries}", "\n".join(lines))
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def call_openai(messages, timeout=60):
    key = os.environ["OPENAI_API_KEY"]
    body = json.dumps({
        "model": os.environ.get("CYBERSAGE_MODEL", "gpt-4o-mini"),
        "messages": messages,
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }).encode()
    req = urllib.request.Request(
        os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1") + "/chat/completions",
        data=body, headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.load(resp)
    return json.loads(data["choices"][0]["message"]["content"])


# ---------- step: verify and normalise ----------
def _norm(s):
    return re.sub(r"\s+", " ", s).strip()


def verify_output(result, lines):
    if not isinstance(result, dict):
        raise ValueError("model output is not a JSON object")
    result.setdefault("status", "ok")
    if result["status"] not in ("ok", "insufficient_information"):
        result["status"] = "ok"
    result.setdefault("summary", "")
    findings = result.get("findings")
    if not isinstance(findings, list):
        findings = []
    haystack = {_norm(l) for l in lines}
    clean = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        f["severity"] = f.get("severity") if f.get("severity") in SEVERITIES else "Low"
        f["confidence"] = f.get("confidence") if f.get("confidence") in CONFIDENCES else "Low"
        ev = f.get("evidence") if isinstance(f.get("evidence"), list) else []
        verified = bool(ev) and all(_norm(str(e)) in haystack for e in ev)
        f["evidence_verified"] = verified
        if not verified:
            f["confidence"] = "Low"
            f["limitations"] = (f.get("limitations", "") + " Some quoted evidence was not found verbatim in the input.").strip()
        f.setdefault("recommended_actions", [])
        clean.append(f)
    result["findings"] = clean
    return result


# ---------- public entry point ----------
def analyze(raw, use_llm=None):
    ok, msg, lines = validate_input(raw)
    if not ok:
        return {"status": "invalid_input", "message": msg, "findings": [], "engine": "none"}
    lines, redactions = redact(lines)
    if use_llm is None:
        use_llm = bool(os.environ.get("OPENAI_API_KEY"))
    engine, note = "offline-heuristic", None
    if use_llm:
        chunks = rag.retrieve(" ".join(lines), k=3)
        messages = build_messages(lines, chunks)
        result = None
        for attempt in range(2):
            try:
                result = verify_output(call_openai(messages), lines)
                engine = f"llm:{os.environ.get('CYBERSAGE_MODEL', 'gpt-4o-mini')}"
                result["sources"] = sorted({c["source"] for c in chunks})
                break
            except (urllib.error.URLError, ValueError, KeyError, json.JSONDecodeError) as e:
                note = f"LLM call failed ({type(e).__name__}); used offline engine."
        if result is None:
            result = verify_output(heuristic_analyze(lines), lines)
    else:
        result = verify_output(heuristic_analyze(lines), lines)
    result["engine"] = engine
    if note:
        result["note"] = note
    if redactions:
        result["redactions"] = redactions
    return result
