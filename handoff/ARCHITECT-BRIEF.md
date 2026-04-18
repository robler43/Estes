# Architect Brief
*Written by Architect. Read by Builder and Reviewer.*
*Overwrite this file each step — it is not a log, it is the current active brief.*

---

## Project Context

**SkillBouncer** — *The AI-powered bouncer for third-party AI agent skills.*

Third-party agent skills leak secrets (API keys, tokens, passwords) via debug prints. The agent framework captures stdout and injects it into the LLM context (especially in Antigravity with Claude). Once leaked, secrets can be retrieved by anyone continuing or sharing the chat.

SkillBouncer ships two cooperating subsystems backed by a single shared detection ruleset:

- **Auditor** — pre-flight, static. Streamlit UI accepts a skill upload, runs regex + entropy + AST checks, returns a risk score (0–100) and itemized findings.
- **Runtime Wrapper** — in-flight, dynamic. FastAPI local proxy that intercepts skill stdout/stderr and redacts secrets before they reach the LLM context. Primary integration target: Antigravity (Claude).

---

## Step 0 — Project Skeleton

### Decisions
- Language: Python 3.11+
- Auditor UI: Streamlit
- Wrapper service: FastAPI + Uvicorn
- Detection (future): regex + Shannon entropy + Python AST. Out of scope for Step 0.
- Primary integration target: Antigravity (Claude model)
- Phase 0 ships placeholder files only — flat layout at the repo root. Subpackages (`auditor/`, `wrapper/`, `shared/`, `tests/`) are deferred to later phases.
- Pin exact dependency versions in `requirements.txt`. No version ranges.
- No detection logic, no integration code, no secrets in any file this step.

### Build Order
1. `requirements.txt`
2. `README.md`
3. `app.py`
4. `auditor.py`
5. `wrapper.py`

### Flags
- Flag: do NOT implement real secret detection in Step 0. Placeholders only.
- Flag: do NOT introduce any subdirectories under the repo root in Step 0 (other than the existing `handoff/`).
- Flag: do NOT add example API keys, tokens, or any secret-shaped strings — even as test fixtures.
- Flag: pin exact versions in `requirements.txt` (use `==`, not `>=` or `~=`).
- Flag: do NOT create a virtualenv, do NOT run `pip install`, do NOT commit. Build files only.

### File Specifications

**`requirements.txt`** — pinned dependencies, one per line, no comments:
- `streamlit==1.39.0`
- `fastapi==0.115.0`
- `uvicorn==0.30.6`
- `pydantic==2.9.2`
- `python-multipart==0.0.12`

**`README.md`** — must contain, in order:
1. `# SkillBouncer` heading
2. Tagline: *The AI-powered bouncer for third-party AI agent skills.*
3. `## The Problem` — 2–3 sentence summary of the secret-leak problem.
4. `## Architecture` — bullet list naming Auditor and Runtime Wrapper with one-line descriptions and the Antigravity/Claude target.
5. `## Install` — `pip install -r requirements.txt`
6. `## Run` — two fenced bash blocks: `streamlit run auditor.py` and `uvicorn wrapper:app --reload`
7. `## Status` — single line: `Phase 0 — scaffolding only. No detection logic yet.`

**`app.py`** — unified launcher placeholder. When run with `python app.py`, prints a help message listing the two subcommands and how to invoke each (`streamlit run auditor.py`, `uvicorn wrapper:app --reload`). No `argparse` required; a `print()` block inside `if __name__ == "__main__":` is sufficient. Must be importable without side effects.

**`auditor.py`** — Streamlit placeholder. At module top level (Streamlit's execution model):
- `st.set_page_config(page_title="SkillBouncer Auditor")`
- `st.title("SkillBouncer Auditor")`
- `st.caption("The AI-powered bouncer for third-party AI agent skills.")`
- `st.file_uploader("Upload a skill (.zip)", type=["zip"], disabled=True)`
- `st.info("Phase 0 placeholder — scanner not yet implemented.")`

**`wrapper.py`** — FastAPI placeholder:
- `app = FastAPI(title="SkillBouncer Runtime Wrapper")`
- `GET /health` -> `{"status": "ok"}`
- `GET /` -> `{"name": "SkillBouncer Runtime Wrapper", "phase": 0}`

### Definition of Done
- [ ] `requirements.txt` exists with the five pinned dependencies listed above, exact versions, no extras.
- [ ] `README.md` contains all seven sections in the specified order.
- [ ] `app.py` runs via `python app.py` and prints launcher help; imports cleanly.
- [ ] `auditor.py` imports cleanly; `streamlit run auditor.py` would render a titled page with a disabled uploader.
- [ ] `wrapper.py` imports cleanly; `uvicorn wrapper:app` would expose `GET /health` returning `{"status":"ok"}`.
- [ ] `python -c "import app, auditor, wrapper"` succeeds with no errors after dependencies are installed (Builder need not actually install — just guarantee the files are syntactically importable).
- [ ] No subdirectories created beyond pre-existing `handoff/` and `.git/`.
- [ ] No secret-shaped strings anywhere in the repo.

---

## Builder Plan
*Builder adds their plan here before building. Architect reviews and approves.*

[Builder writes plan here]

Architect approval: [ ] Approved / [ ] Redirect — see notes below
