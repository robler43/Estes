# SkillBouncer

*The AI-powered bouncer for third-party AI agent skills.*

## The Problem

Third-party agent skills routinely print secrets — API keys, tokens, passwords — to stdout while debugging. Frameworks like Antigravity capture that output and inject it directly into the LLM context. Once a secret reaches the model, anyone who shares or resumes the chat can read it back out.

SkillBouncer stands at the door. Skills get checked before they run, and their output gets cleaned before it reaches the model.

## Architecture

- **Auditor** — `app.py` (Streamlit UI) + `auditor.py` (scan library). Upload a skill, get a 0–100 risk score and an itemized list of findings.
- **Runtime Wrapper** — `wrapper.py` (FastAPI). Local proxy that intercepts skill stdout/stderr and redacts secrets before they reach the LLM.
- Both share the regex ruleset in `auditor.py` so "what counts as a secret" is defined exactly once.
- Primary integration target: Antigravity (Claude).

## Install

```bash
pip install -r requirements.txt
```

## Run

Auditor (Streamlit UI — main entry point):

```bash
streamlit run app.py
```

Runtime Wrapper (FastAPI service):

```bash
uvicorn wrapper:app --reload
```

## Demo

A deliberately leaky example skill lives in `demo/weather_tool/`. Zip the folder and upload it through the Auditor to see findings light up, or POST a sample of its debug output to `wrapper`'s `/redact` endpoint to see redaction in action.

## Status

Phase 0 — minimal regex scanner, Streamlit UI, FastAPI redact endpoint, and a leaky demo skill. No live Antigravity integration yet; entropy and AST passes land in Phase 1.
