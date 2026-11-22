/* CyberSage in-browser engine: validation, redaction, offline rule-based analysis, evidence verification.
   Mirrors code/analyzer.py (offline path). No network, no LLM. */
(function (root) {
  const MAX_LINES = 200, MAX_CHARS = 20000;
  const SEVERITIES = ["Low", "Medium", "High", "Critical"];
  const ADMIN_GROUPS = ["admin", "administrators", "sudo", "wheel", "root"];
  const TIME_RE = /\b\d{1,2}:\d{2}:\d{2}\b/;
  const KV_ONE = /\b[A-Za-z_]+=\S+/;
  const KV_ALL = /\b[A-Za-z_]+=\S+/g;

  function validate(raw) {
    if (raw == null || !raw.trim()) return { ok: false, message: "No log entries provided. Paste some security log lines." };
    if (raw.length > MAX_CHARS) return { ok: false, message: "Input too long (limit " + MAX_CHARS + " characters)." };
    const lines = raw.split(/\r?\n/).map(l => l.replace(/\s+$/, "")).filter(l => l.trim());
    if (lines.length > MAX_LINES) return { ok: false, message: "Too many lines (limit " + MAX_LINES + ")." };
    const loglike = lines.filter(l => TIME_RE.test(l) || KV_ONE.test(l)).length;
    if (loglike / lines.length < 0.5) return { ok: false, message: "Input does not look like security log entries (no timestamps or key=value fields)." };
    return { ok: true, lines };
  }

  function redact(lines) {
    let count = 0;
    const out = lines.map(l => {
      let s = l.replace(/\b(password|passwd|pwd|token|secret|api[_-]?key)\s*[=:]\s*\S+/gi, (m, k) => { count++; return k + "=[REDACTED]"; });
      s = s.replace(/\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g, () => { count++; return "[EMAIL]"; });
      return s;
    });
    return { lines: out, count };
  }

  function parse(line) {
    const f = {};
    (line.match(KV_ALL) || []).forEach(p => { const i = p.indexOf("="); f[p.slice(0, i)] = p.slice(i + 1); });
    let event = null, t = null;
    const m = line.match(TIME_RE);
    if (m) {
      const [h, mi, s] = m[0].split(":").map(Number);
      t = h * 3600 + mi * 60 + s;
      const after = line.slice(m.index + m[0].length).trim().split(/\s+/);
      for (const tok of after) if (tok && tok.indexOf("=") < 0) { event = tok.toUpperCase(); break; }
    } else {
      const tok = line.trim().split(/\s+/)[0];
      event = tok ? tok.toUpperCase() : null;
    }
    return { raw: line, event, t, f };
  }

  function span(rows) {
    const ts = rows.map(r => r.t).filter(t => t != null);
    return ts.length > 1 ? Math.max(...ts) - Math.min(...ts) : null;
  }
  function fmtSpan(s) { return s == null ? "an unknown time span" : s < 120 ? s + " seconds" : "about " + Math.round(s / 60) + " minutes"; }

  function group(rows, keyFn) {
    const m = new Map();
    rows.forEach(r => { const k = keyFn(r); if (!m.has(k)) m.set(k, []); m.get(k).push(r); });
    return m;
  }

  function heuristic(lines) {
    const rows = lines.map(parse);
    if (rows.length < 3) return { status: "insufficient_information", summary: "Too few log entries to judge. Provide more context (at least a few related lines).", findings: [] };
    const findings = [];
    const auth = rows.filter(r => r.event && (r.event.includes("LOGIN") || r.event.includes("AUTH")));
    const failed = [], succ = [];
    auth.forEach(r => {
      const res = (r.f.result || "").toUpperCase();
      if (["FAIL", "FAILED", "FAILURE"].includes(res)) failed.push(r);
      else if (["SUCCESS", "OK"].includes(res)) succ.push(r);
    });

    group(failed, r => r.f.src + "\u0000" + r.f.user).forEach(fl => {
      if (fl.length < 3) return;
      const src = fl[0].f.src, user = fl[0].f.user, last = fl[fl.length - 1];
      const later = succ.filter(s => s.f.src === src && s.f.user === user && s.t != null && last.t != null && s.t >= last.t);
      const ev = fl.map(r => r.raw).concat(later.length ? [later[0].raw] : []);
      const sp = span(fl.concat(later.slice(0, 1)));
      if (later.length) {
        findings.push({ title: "Repeated failed logins followed by success", evidence: ev,
          possible_threat: "Repeated authentication failures may indicate a password-guessing attempt that eventually succeeded.",
          severity: fl.length >= 5 ? "High" : "Medium", confidence: "Medium",
          rationale: fl.length + " failures for user " + user + " from " + src + " within " + fmtSpan(sp) + ", then a success. Could also be the real user mistyping.",
          recommended_actions: ["Verify with the account owner that the successful login was theirs", "Review other activity from this address", "Consider a password reset and enabling MFA"],
          limitations: "These events alone do not confirm an attack." });
      } else {
        findings.push({ title: "Repeated failed logins", evidence: ev,
          possible_threat: "Repeated failures may indicate a password-guessing attempt.",
          severity: fl.length >= 5 ? "Medium" : "Low", confidence: fl.length >= 5 ? "Medium" : "Low",
          rationale: fl.length + " failures for user " + user + " from " + src + " within " + fmtSpan(sp) + ", with no success shown.",
          recommended_actions: ["Check whether the user is locked out or forgot their password", "Consider rate limiting or temporary blocking of the source"],
          limitations: "Failed logins have many innocent causes; no success is visible in the provided logs." });
      }
    });

    group(failed, r => r.f.src).forEach((fl, src) => {
      const users = new Set(fl.map(r => r.f.user));
      if (users.size >= 3) findings.push({ title: "Failed logins across many accounts from one source", evidence: fl.slice(0, 10).map(r => r.raw),
        possible_threat: "Failures against many different accounts from one address may indicate password spraying.",
        severity: "High", confidence: "Medium",
        rationale: users.size + " different users failed from " + src + " within " + fmtSpan(span(fl)) + ".",
        recommended_actions: ["Block or rate-limit the source address", "Require MFA", "Check whether any targeted account later shows a successful login"],
        limitations: "A shared office or proxy address could produce similar patterns." });
    });

    const denies = rows.filter(r => {
      const ev = r.event || "";
      if (!(ev.includes("DENY") || ev.includes("BLOCK") || ev.includes("DROP") || ev.includes("CONN"))) return false;
      if (!r.f.dport || !r.f.src) return false;
      if ((r.f.action || "").toUpperCase().includes("ALLOW") || (r.f.result || "").toUpperCase() === "ALLOW") return false;
      return true;
    });
    group(denies, r => r.f.src).forEach((dl, src) => {
      const ports = new Set(dl.map(r => r.f.dport));
      if (ports.size >= 5) findings.push({ title: "Possible port scan", evidence: dl.slice(0, 10).map(r => r.raw),
        possible_threat: "Blocked connections to many different ports from one address may indicate port scanning.",
        severity: "Medium", confidence: "Medium",
        rationale: ports.size + " distinct destination ports probed by " + src + " within " + fmtSpan(span(dl)) + ".",
        recommended_actions: ["Block or rate-limit the source", "Confirm only required ports are exposed", "Watch for later successful connections from this address"],
        limitations: "Scans are common internet background noise; the logs show no successful access." });
    });

    rows.forEach(r => {
      if (["GROUP_ADD", "PRIV_ESC", "ROLE_GRANT"].includes(r.event) && ADMIN_GROUPS.includes((r.f.group || r.f.role || "").toLowerCase()))
        findings.push({ title: "Account added to privileged group", evidence: [r.raw],
          possible_threat: "Granting administrative rights may indicate privilege escalation, or an approved admin change.",
          severity: "High", confidence: "Low",
          rationale: "Privilege changes are high impact, but the logs do not show whether the change was approved.",
          recommended_actions: ["Confirm the change with its owner", "Review who made it and when", "Remove the privilege if unapproved"],
          limitations: "Cannot tell from this line whether the change was authorised." });
    });

    return findings.length
      ? { status: "ok", summary: findings.length + " possible issue(s) found; verify each before acting.", findings }
      : { status: "ok", summary: "No suspicious pattern found in the provided entries.", findings: [] };
  }

  const norm = s => String(s).replace(/\s+/g, " ").trim();
  function verify(result, lines) {
    const hay = new Set(lines.map(norm));
    result.findings.forEach(f => {
      if (!SEVERITIES.includes(f.severity)) f.severity = "Low";
      const ev = Array.isArray(f.evidence) ? f.evidence : [];
      f.evidence_verified = ev.length > 0 && ev.every(e => hay.has(norm(e)));
      if (!f.evidence_verified) { f.confidence = "Low"; f.limitations = ((f.limitations || "") + " Some quoted evidence was not found verbatim in the input.").trim(); }
    });
    return result;
  }

  function analyze(raw) {
    const v = validate(raw);
    if (!v.ok) return { status: "invalid_input", message: v.message, findings: [], engine: "none" };
    const r = redact(v.lines);
    const result = verify(heuristic(r.lines), r.lines);
    result.engine = "offline-heuristic (in browser)";
    if (r.count) result.redactions = r.count;
    return result;
  }

  const api = { analyze, validate, redact };
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.CyberSage = api;
})(typeof window !== "undefined" ? window : globalThis);
