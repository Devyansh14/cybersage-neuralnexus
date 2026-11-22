# Architecture and prompt design

Mermaid diagrams (render on GitHub, or paste into https://mermaid.live). Redraw them in your own style for the PDF and make sure they match what you built.

## 1. Prompt workflow

```mermaid
flowchart LR
  A[User pastes logs] --> B[Validate input]
  B -->|invalid| X[Show error]
  B --> C[Redact secrets]
  C --> D[Retrieve notes - RAG]
  D --> E[Build prompt P1]
  E --> F[LLM call]
  F --> G[Verify evidence]
  G --> H[Findings cards]
```

## 2. Task decomposition

```mermaid
flowchart TD
  T[Explain suspicious activity in logs] --> T1[Input safety: validate and redact]
  T --> T2[Grounding: retrieve reference notes]
  T --> T3[Reasoning: detect patterns, cite evidence]
  T --> T4[Judgement: severity and confidence]
  T --> T5[Advice: defensive actions and limitations]
  T --> T6[Checking: verify quoted evidence]
```

## 3. Input-output flow

```mermaid
flowchart LR
  I[Input: log lines text] --> P[Pipeline]
  P --> O[Output JSON: status, summary, findings]
  O --> F[finding: title, evidence, possible_threat, severity, confidence, rationale, actions, limitations]
```

## 4. System architecture

```mermaid
flowchart LR
  UI[Browser UI index.html] -->|POST /api/analyze| S[app.py server]
  S --> A[analyzer.py]
  A --> R[rag.py]
  R --> K[(code/knowledge/*.md)]
  A --> L[OpenAI chat API]
  A --> H[Offline heuristic engine]
  A --> S
```

## 5. RAG pipeline

```mermaid
flowchart LR
  K[Knowledge .md files] --> C[Split by section]
  C --> T[Tokenize]
  Q[Log text] --> QT[Tokenize]
  T --> M[Weighted keyword match]
  QT --> M
  M --> TOP[Top 3 sections]
  TOP --> PR[Inserted into prompt as knowledge block]
```

## Final prompt count

This scaffold has **1 final prompt**: P1 (log analysis), split into a system file and a user template. If you add more prompts, update the count (form Q10) and add one prompt sheet per prompt to the PDF.
