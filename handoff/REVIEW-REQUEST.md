# Review Request — Step 0
*Written by Builder. Read by Reviewer.*

Ready for Review: YES

---

## What Was Built

A working Phase 0 SkillBouncer skeleton: a Streamlit Auditor (`app.py`) that uploads and scans a skill, a shared scan library (`auditor.py`) with six regex rules, a FastAPI Runtime Wrapper (`wrapper.py`) exposing `/health`, `/redact`, and `/scan`, a top-level `README.md`, a pinned `requirements.txt`, and a deliberately-leaky demo skill at `demo/weather_tool/` so the scanner has something obvious to find. All modules parse cleanly (`python3 -m ast` over the four `.py` files passes).

## Files Changed

| File | Lines | Change |
|---|---|---|
| `requirements.txt` | 1-7 | Pinned: streamlit, fastapi, uvicorn, pydantic, python-dotenv, requests, PyYAML. |
| `auditor.py` | 1-117 | New: `SECRET_PATTERNS` regex pack, `Finding`/`ScanResult` dataclasses, `scan_text`/`scan_path`/`redact_text` helpers, risk score + label. |
| `app.py` | 1-79 | New: Streamlit UI; accepts file or `.zip`, extracts to a temp dir, calls `scan_path`, renders score/files/verdict + findings table. |
| `wrapper.py` | 1-68 | New: FastAPI app; `GET /`, `GET /health`, `POST /redact`, `POST /scan`. Imports ruleset from `auditor`. |
| `README.md` | 1-44 | New: problem, architecture, install, run, demo pointer, status. |
| `demo/weather_tool/weather.py` | 1-37 | New: leaky example skill (3 credential leaks: 2x `print`, 1x `logger.debug`). Fake placeholder values only. |
| `demo/weather_tool/SKILL.md` | 1-28 | New: describes the demo skill and the three leak vectors. |
| `handoff/BUILD-LOG.md` | full rewrite | Step 0 set to READY FOR REVIEW; added D-1..D-5 deviation notes; added KG-1..KG-6; added AD-6. |

## Open Questions

1. **Project Owner override of original brief.** Five deviations are logged as D-1..D-5 in BUILD-LOG. The most material:
   - Real (minimal) detection logic shipped in Step 0 instead of pure placeholders, because the demo needs something to detect.
   - `demo/` subdirectory created (original brief flagged "no new subdirectories").
   - Demo skill contains fake-but-secret-shaped strings (original brief flagged "no secret-shaped strings"). Strings are obvious dummies (`wx_fake_demo_key_...`).
   Reviewer: please confirm the deviations are acceptable or escalate to Architect.
2. **Risk score formula** is `min(100, n_findings * 20)` — naive, no severity weighting. KG-5 logged.
3. **No tests.** Demo skill is the only smoke test. KG-4 logged.
4. **`zipfile.extractall` in `app.py` is unguarded** — no path-traversal or zip-bomb defense. Acceptable for local dev tool? KG-6 logged.

## Known Gaps Logged

- KG-1 — No Shannon entropy pass.
- KG-2 — No Python AST pass (`eval`, `exec`, `os.system`, etc. not flagged).
- KG-3 — No live Antigravity hook; `/redact` is a manual POST.
- KG-4 — No automated tests.
- KG-5 — Naive risk score formula.
- KG-6 — `zipfile.extractall` is unguarded.
