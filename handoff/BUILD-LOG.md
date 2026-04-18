# Build Log
*Owned by Architect. Updated by Builder after each step.*

---

## Current Status

**Active step:** 0 — Project skeleton (placeholders + requirements + README + demo)
**Last cleared:** none
**Pending deploy:** NO (awaiting REVIEWER)

---

## Step History

### Step 0 — Project Skeleton — READY FOR REVIEW
*Date: 2026-04-18*

Files changed:
- `requirements.txt` — pinned dependency list (7 packages)
- `auditor.py` — minimal regex ruleset, `Finding` / `ScanResult` dataclasses, `scan_text` / `scan_path` / `redact_text`
- `app.py` — Streamlit frontend; uploads a file or .zip, calls `auditor.scan_path`, renders score + findings table
- `wrapper.py` — FastAPI service exposing `GET /`, `GET /health`, `POST /redact`, `POST /scan`
- `README.md` — project overview, install/run, demo pointer, status
- `demo/weather_tool/weather.py` — deliberately leaky example skill (3 credential leaks via `print` and `logger.debug`; obvious fake placeholder values)
- `demo/weather_tool/SKILL.md` — describes the demo skill and why it is unsafe
- `handoff/BUILD-LOG.md` — this update
- `handoff/REVIEW-REQUEST.md` — populated for REVIEWER

Decisions made:
- Project Owner revised the brief mid-step. Followed the new brief verbatim. Deviations from the original Architect brief, all explicitly directed by the Project Owner:
  - **D-1** — `requirements.txt` packages changed: dropped `python-multipart`; added `python-dotenv`, `requests`, `PyYAML`. All pinned per AD-5 (Architect did not say not to pin; pinning preserved).
  - **D-2** — File roles swapped: `app.py` is now the Streamlit UI (entry point: `streamlit run app.py`); `auditor.py` is now the pure scan library imported by both `app.py` and `wrapper.py`. Original brief had `app.py` as a launcher and `auditor.py` as the Streamlit page.
  - **D-3** — Real (minimal) detection logic shipped in Step 0 instead of pure placeholders, because the demo skill needs something to detect. Six regex rules; no entropy, no AST.
  - **D-4** — New `demo/weather_tool/` subdirectory created. Original brief flag prohibited new subdirectories.
  - **D-5** — Demo skill contains obvious-fake credential strings (`wx_fake_demo_key_...`, `tok_fake_demo_token_...`) so the scanner has something to match. They are not real secrets, but they technically violate the "no secret-shaped strings" flag from the original brief. Necessary for the demo to function.
- Shared ruleset lives in `auditor.SECRET_PATTERNS` and is consumed by both the Streamlit UI (via `scan_path`) and the FastAPI service (via `redact_text` and `scan_text`). AD-4 honored.

Reviewer findings: pending
Deploy: pending

---

## Known Gaps
*Logged here instead of fixed. Addressed in a future step.*

- **KG-1** — No Shannon entropy pass yet. Generic high-entropy strings will be missed unless they match a named pattern. Plan: add in Phase 1.
- **KG-2** — No Python AST pass. `eval`, `exec`, `subprocess.run(shell=True)`, dynamic `__import__`, and `os.system` calls are not flagged. Plan: add in Phase 1.
- **KG-3** — Wrapper has no actual Antigravity integration. `/redact` is a manual POST endpoint. The hook into Antigravity's tool runner is a Phase 2 spike.
- **KG-4** — No automated tests. Demo skill is the only smoke test. Plan: pytest + a `tests/fixtures/` set in Phase 1.
- **KG-5** — Risk score formula is naive (`min(100, n_findings * 20)`). Needs severity-weighted rules in Phase 1.
- **KG-6** — Streamlit `.zip` upload trusts the archive — no zip-bomb or path-traversal guard. Acceptable for a local dev tool in Phase 0; harden before any hosted deploy.

---

## Architecture Decisions
*Locked decisions that cannot be changed without breaking the system.*

- **AD-1 (2026-04-18)** — Two-component architecture: Auditor (pre-flight static scanner) and Runtime Wrapper (in-flight redacting proxy). Both consume a shared detection ruleset.
- **AD-2 (2026-04-18)** — Auditor frontend is Streamlit; Wrapper service is FastAPI on Uvicorn.
- **AD-3 (2026-04-18)** — Primary integration target is Antigravity using the Claude model. Other agent frameworks are out of scope until Phase 2+.
- **AD-4 (2026-04-18)** — Detection rules are the single source of truth shared between Auditor and Wrapper. Any new rule must work in both contexts. (Honored in Step 0: both sides import from `auditor.SECRET_PATTERNS`.)
- **AD-5 (2026-04-18)** — Python 3.11+ is the minimum supported runtime. Dependencies are pinned with exact versions in `requirements.txt`.
- **AD-6 (2026-04-18)** — `app.py` is the canonical user-facing entry point (`streamlit run app.py`). `auditor.py` is a pure library with no Streamlit dependency. (Supersedes the original Step 0 brief.)
