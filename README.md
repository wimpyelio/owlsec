# 🦉 OwlSec — OWASP LLM Top 10 Security Scanner

> **Static triage for AI systems.** Paste a system prompt, agent config, or code — get a scored, evidence-backed report mapped to the [OWASP LLM Top 10 (2025)](https://genai.owasp.org/llm-top-10/) in under a minute.

![status](https://img.shields.io/badge/status-active-brightgreen) ![license](https://img.shields.io/badge/license-MIT-blue) ![stack](https://img.shields.io/badge/stack-TanStack%20Start%20%7C%20React%20%7C%20TypeScript-informational)

---

## ✨ What it does

OwlSec analyzes AI application artifacts — **system prompts**, **tool/agent configs**, **architecture descriptions**, and **code files** — and returns a deterministic (`temperature: 0`) security report covering **all 10 OWASP LLM categories**:

| Code  | Category                         | Code  | Category                      |
| ----- | -------------------------------- | ----- | ----------------------------- |
| LLM01 | Prompt Injection                 | LLM06 | Excessive Agency              |
| LLM02 | Sensitive Information Disclosure | LLM07 | System Prompt Leakage         |
| LLM03 | Supply Chain                     | LLM08 | Vector & Embedding Weaknesses |
| LLM04 | Data & Model Poisoning           | LLM09 | Misinformation                |
| LLM05 | Improper Output Handling         | LLM10 | Unbounded Consumption         |

Every finding ships with **exact evidence, a severity score, and a remediation** — reviewable, editable, and exportable to Markdown.

## 🚀 Quick start

```bash
git clone <your-repo-url>
cd owlsec
bun install
cp .env.example .env   # add your model provider credentials
bun run dev
```

## 🔑 Configuration

OwlSec talks to **any OpenAI-compatible endpoint** — swap providers with zero code changes:

```env
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.openai.com/v1   # or your own gateway / local server
SCAN_MODEL=gpt-4o-mini                      # or any compatible model
```

> ⚠️ Requires the target endpoint to support `response_format: json_schema` (structured output).

## 🛡️ Built-in hardening

- **Rate limiting** — sliding-window, per-IP, in-memory
- **Prompt-injection defense** — all user-supplied artifacts are wrapped in explicit untrusted-data delimiters before reaching the model
- **Safe parsing** — malformed model output auto-retries once, then fails gracefully
- **Structured logging** — JSON-line logs, pipe-ready for any log aggregator

## 🧱 Tech stack

- **[TanStack Start](https://tanstack.com/start)** — full-stack React framework
- **TypeScript** — strict mode, zero `any` in core logic
- **Tailwind CSS v4** + **shadcn/ui** — component system
- **Zero client-side secrets** — all model calls run server-side

## 📄 License

MIT — use it, fork it, ship it.

---

_Not a substitute for dynamic red-teaming or a professional penetration test. This is triage, not a guarantee._
