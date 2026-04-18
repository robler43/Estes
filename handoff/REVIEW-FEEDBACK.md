# Review Feedback — Step 0
*Written by Reviewer. Read by Builder and Architect.*

Date: 2026-04-18
Ready for Builder: YES

---

## Audit Checklist

| Check | Result |
|---|---|
| All paths inside `/Users/robinhoesli/Desktop/projects/SkillBouncer` | PASS — 11 files, no escapes |
| Clean, logical folder structure | PASS — flat root + `handoff/` + `demo/weather_tool/` |
| `requirements.txt` includes all 7 listed packages | PASS — streamlit, fastapi, uvicorn, pydantic, python-dotenv, requests, PyYAML (all pinned) |
| `README.md` has project name, tagline, and "How to run" instructions | PASS — title, tagline, Install, Run (both components), Demo, Status |
| Leaky demo skill properly added | PASS — `demo/weather_tool/weather.py` with three leak vectors; live scan returns score=100, label=high, 6 findings |
| End-to-end smoke test (`auditor.scan_path('demo/weather_tool')`) | PASS — 6 findings detected as expected |
| All `.py` files parse cleanly | PASS — confirmed in BUILD-LOG |
| Project Owner deviations from original Architect brief | ACCEPTABLE — D-1..D-5 are coherent, serve the demo, and are documented in BUILD-LOG |

## Must Fix

*None. Step 0 is buildable, runnable, and matches the Project Owner's revised brief.*

## Should Fix

- `SkillBouncer/` (repo root) — no `.gitignore` exists and `.DS_Store` is already untracked. Recommendation: add a `.gitignore` containing at minimum `.DS_Store`, `__pycache__/`, `*.pyc`, `.venv/`, `.pytest_cache/`. Trivial; do inline.
- `requirements.txt:3` — `uvicorn==0.30.6` is pinned without the `[standard]` extra. The `README.md:35` command `uvicorn wrapper:app --reload` will work but uvicorn emits a warning recommending `watchfiles`. Recommendation: change line 3 to `uvicorn[standard]==0.30.6` so the documented dev command runs clean. Inline fix.
- `demo/weather_tool/SKILL.md:13-15` — the documentation quotes the three leaky lines verbatim, so the Auditor flags them too (3 extra findings). Not wrong (the bytes do contain the patterns) but it inflates the demo's score from 60 to 100. Two acceptable paths: (a) wrap the quoted lines so they don't match (e.g., insert a zero-width break inside `print` — fragile), or (b) accept it and add KG-7 to BUILD-LOG noting "scanner currently flags documentation that quotes leak code; needs an `# skillbouncer: ignore` opt-out comment in Phase 1." Recommend (b) — log to BUILD-LOG as KG-7, no code change.

## Escalate to Architect

- The original Architect brief flagged "no new subdirectories" and "no secret-shaped strings." The Project Owner's revised brief explicitly required `demo/` and a leaky example, and Builder followed the revision. BUILD-LOG records this as D-4 / D-5. Architect should formally supersede the original flags so future steps don't re-litigate the decision (proposed: add an AD-7 locking the `demo/` directory and the dummy-secret convention as legitimate). Not a code question — requires Architect's call.

## Cleared

Step 0 is clear. Demo scanner end-to-end works (`scan_path('demo/weather_tool')` returns score=100, label=high, 6 findings). README install/run instructions are correct (subject to the uvicorn `[standard]` Should Fix). Folder structure is clean and self-contained inside the project root.
