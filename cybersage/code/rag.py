"""Tiny retrieval layer (RAG) over the markdown notes in code/knowledge.

Pure standard library: notes are split into sections, tokenised, and ranked
by weighted keyword overlap. Good enough for a small curated knowledge base.
"""
import math
import re
from collections import Counter
from pathlib import Path

KNOWLEDGE_DIR = Path(__file__).resolve().parent / "knowledge"
STOP = set("a an the of to in on is are was were and or for with by at from as it this that be can may".split())


def _tokens(text):
    return [t for t in re.findall(r"[a-z0-9_]+", text.lower()) if t not in STOP and len(t) > 2]


def load_chunks():
    chunks = []
    for path in sorted(KNOWLEDGE_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for part in re.split(r"\n(?=## )", text):
            part = part.strip()
            if part:
                chunks.append({"source": path.name, "text": part, "tokens": Counter(_tokens(part))})
    return chunks


def retrieve(query, k=3):
    chunks = load_chunks()
    q = Counter(_tokens(query))
    if not q or not chunks:
        return []
    df = Counter()
    for c in chunks:
        for t in c["tokens"]:
            df[t] += 1
    n = len(chunks)
    scored = []
    for c in chunks:
        score = 0.0
        for t, qc in q.items():
            if t in c["tokens"]:
                score += (1 + math.log(c["tokens"][t])) * math.log(1 + n / df[t]) * min(qc, 3)
        if score > 0:
            scored.append((score, c))
    scored.sort(key=lambda x: -x[0])
    return [{"source": c["source"], "text": c["text"], "score": round(s, 2)} for s, c in scored[:k]]
