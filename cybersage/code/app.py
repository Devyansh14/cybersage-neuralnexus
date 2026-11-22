"""CyberSage web server (standard library only).

Run:  python code/app.py     then open http://localhost:8000
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import analyzer

STATIC = Path(__file__).resolve().parent / "static"
MAX_BODY = 100_000


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/health":
            self._send(200, json.dumps({"ok": True, "llm_configured": bool(os.environ.get("OPENAI_API_KEY"))}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if self.path != "/api/analyze":
            return self._send(404, json.dumps({"error": "not found"}))
        try:
            n = int(self.headers.get("Content-Length", 0))
            if n > MAX_BODY:
                return self._send(413, json.dumps({"error": "payload too large"}))
            payload = json.loads(self.rfile.read(n) or b"{}")
            result = analyzer.analyze(payload.get("logs", ""))
            self._send(200, json.dumps(result))
        except (ValueError, json.JSONDecodeError):
            self._send(400, json.dumps({"error": "invalid JSON body"}))

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"CyberSage running on http://localhost:{port}  (LLM {'ON' if os.environ.get('OPENAI_API_KEY') else 'OFF - offline engine'})")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
