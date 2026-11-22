"""Build web/index.html (single self-contained page) from the template, engine and test cases."""
import json
from pathlib import Path

web = Path(__file__).resolve().parent
root = web.parent
tpl = (web / "index.template.html").read_text(encoding="utf-8")
engine = (web / "engine.js").read_text(encoding="utf-8")
cases = json.dumps(json.loads((root / "test-data" / "test_cases.json").read_text(encoding="utf-8")))
cases = cases.replace("</", "<\\/")
engine = engine.replace("</", "<\\/")
out = tpl.replace("/*ENGINE*/", engine).replace("/*CASES*/", cases)
(web / "index.html").write_text(out, encoding="utf-8")
print("built", len(out), "bytes")
