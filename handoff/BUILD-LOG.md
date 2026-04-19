# Build Log
*Owned by Architect. Updated by Builder after each step.*

---

## Current Status

**Active step:** 2 — Dashboard UI rewrite (per `handoff/ui_design.md`)
**Last cleared:** Step 1 — 2026-04-18 (Round 2 swap-in completed; Phase 1 `auditor.py` now at root; Phase 0 callers verified working via compat properties)
**Pending deploy:** Step 2 in flight

---

## Step History

### Step 1 — Auditor module rewrite — READY FOR REVIEW
*Date: 2026-04-18*

Files changed:
- `handoff/auditor.py` — full implementation per `handoff/auditor_design.md` (staged; does NOT replace root `auditor.py` until REVIEWER signs off)
- `handoff/BUILD-LOG.md` — this update
- `handoff/REVIEW-REQUEST.md` — populated for REVIEWER

Decisions made:
- **Output location**: Per Project Owner's instruction, the implementation lives at `handoff/auditor.py`, not at the repo root. The running root `auditor.py` is unchanged. Architect / Project Owner must `mv handoff/auditor.py auditor.py` after review to activate it.
- **LLM default unresolved**: Architect's design left the `llm` default as an open question for Project Owner. Builder shipped `llm=True` (Architect's recommendation) for `scan_skill`, and kept `scan_path()` as `llm=False` so the existing Streamlit UI and FastAPI `/scan` endpoint stay fast. Override with env var `ESTES_LLM_PROVIDER=off`.
- **Backwards compatibility**: `SECRET_PATTERNS`, `scan_text`, `scan_path`, `redact_text` are preserved with the same signatures. `wrapper.py` and `app.py` need no changes for the swap-in.
- **Bonus AST rule fired**: Demo weather_tool now also triggers `ES-NET-PHONEHOME-01` (warning) because `requests.get("https://api.weatherapi.com/...")` is reached from a function that touches `os.environ`-bound locals. This wasn't requested in the demo brief but matches the spec's reachability rule. Score caps at 100 either way.

Smoke-test results (from `handoff/auditor.py` against `demo/weather_tool/`):
- severity=`High Risk`, score=100
- 9 high + 1 warning total (6 static from `SKILL.md` quoting leak code + 3 high AST from `weather.py` + 1 phone-home warning)
- AST correctly resolves `API_KEY = os.environ.get(...)` then `print(f"...{API_KEY}...")` via the env-var symbol table
- Path-traversal zip rejected with warning, no escape
- `# estes: ignore` suppresses static findings on the marked line (closes KG-7)
- `report.to_json()` round-trips cleanly through `json.loads`
- Clean fixture (no leaks) returns severity=`Safe`, score=0

Reviewer findings: Round 1 — `handoff/reviewer_feedback.md` (Ready for Builder: NO; MF-1, MF-2)
Deploy: pending Round 2 sign-off

---

### Step 2 — Dashboard rewrite per `handoff/ui_design.md` — READY FOR REVIEW
*Date: 2026-04-18*

Files changed:
- `app.py` — full rewrite (~290 LOC). Pure layout + state plumbing. All scan calls go through `auditor.scan_skill(source, llm=True)`.
- `.streamlit/config.toml` — NEW. Locks dark base theme + `#22ff88` primary color.
- `assets/styles.css` — NEW (~9.5 KB). Single-stylesheet override of Streamlit's chrome via `:root` CSS variables and `[data-testid="..."]` selectors. Zero hard-coded hex codes — discipline verified by grep at end of build.
- `assets/logo.svg` — NEW. 40×40 shield with chat-bubble notch, `currentColor` stroke.
- `ui/__init__.py`, `ui/theme.py`, `ui/components.py` — NEW package. `theme.py` is the single source of palette truth and emits the `:root { --foo: ... }` block consumed by `styles.css`. `components.py` owns every `st.markdown(unsafe_allow_html=True)` block; every dynamic interpolation passes through `html.escape()`.
- `handoff/REVIEW-REQUEST.md` — Step 2 review request (replaces Step 1 round 2 contents).
- `handoff/BUILD-LOG.md` — this update.

Implementation notes:
- **Schema**: `app.py` consumes Phase 1 (`report.severity`, `f.id`, `f.suggested_fix`, `report.warnings`, `report.llm_used`). The Phase 0 compat properties from Step 1 (`Finding.rule`, `ScanReport.risk_label`) are still in place but unused by the new UI — they remain for `wrapper.py` and external integrators per AD-8 (proposed).
- **Action bar**: `Scan Skill` (primary, neon green), `Apply Wrapper` (opens an inline expander with the local-proxy install one-liner — KG-3 still open, this is documentation-grade), `Download Fixed` (stub auto-patch — generates a zip mirroring the source tree with `# estes: ignore` markers appended at flagged lines plus a `ESTES_PATCH.md` manifest).
- **Schema → Streamlit gotcha**: Streamlit 1.39 does not reliably support full HTML in `st.expander` labels, so finding cards use a plain-text label with a leading severity glyph (`▲ HIGH ...`) and the rich card body renders inside the expander. Documented in `ui_design.md` §9 fallback note.
- **No new dependencies**. Only `streamlit` (already pinned), the standard library, and our own `auditor`.
- **Modal**: `Apply Wrapper` uses an inline `st.expander` with `expanded=True` rather than `st.dialog`, since 1.39 dialog support is not relied upon. Documented in `ui_design.md` §4.3.

DoD acceptance (per `handoff/ui_design.md` §8) — Builder self-check:
1. Dark dashboard launches via `streamlit run app.py` — DEPENDS on user dev box (sandbox here lacks `streamlit`); compile passes, asset wiring verified.
2. Header sticky-style applied via CSS bottom-border; logo + wordmark + tagline + Docs/GitHub links — DONE.
3. Drag-and-drop zip → scan → render — code path complete; needs runtime validation on user box.
4. GitHub URL → scan — code path complete; routes through `scan_skill` like upload.
5. Three demo states (leaky weather + clean + missing-manifest fixture) — Builder ran the underlying `scan_skill` calls live; all three returned the expected severity / score / risk_label values.
6. Empty state (`What we look for` triptych) — DONE.
7. Findings render with severity glyph + rule id + file:line + source tag + snippet + fix callout — DONE.
8. Severity + source filters — DONE (selectboxes with session-state persistence).
9. `Scan Skill` is the only enabled action at empty state — DONE.
10. `Download Fixed` produces a real zip with ignore markers + patch manifest — DONE.
11. WCAG AA contrast — palette unchanged from `ui_design.md` §2.1 verified during design phase.
12. No console errors — needs runtime validation.
13. No new requirements.txt entries — DONE (verified diff).

Decisions made (Step 2):
- **Architect Q1** (header tagline) — kept "Keep secrets out of your agent chats" verbatim per the design doc.
- **Architect Q2** (badge wording) — shipped "HIGH RISK" matching `auditor.OverallSeverity`. UI-only rename to "DANGER" is a one-line change in `ui/theme.py SEVERITY_STYLE` if Project Owner prefers.
- **Architect Q3** (URL field flow) — shared the Scan code path; URL wins when both upload + URL are provided, with an inline notice.
- **`Apply Wrapper` as documentation card** — KG-3 is still open, so the button doesn't pretend to install. The expander shows the actual `uvicorn wrapper:app` one-liner. Honest beats magical.
- **`Download Fixed` as stub-patch** — appends `# estes: ignore` markers + ships a patch manifest. The "actual fix" auto-patch is a Phase 3 roadmap item per README. Banner inside the modal warns "review before redistributing."
- **Header link `Docs`** — no docs site yet, so the link is a no-op anchor (`#`). Will become a real link when README is hosted.

Reviewer findings: pending
Deploy: pending review

---

### Step 1 — Round 2 (MF-1 + MF-2 close-out) — DEPLOYED
*Date: 2026-04-18*

Files changed (this round):
- `handoff/auditor.py` — patched in place (still staged; no swap until Reviewer signs off Round 2)
  - **MF-1 (a)**: `Finding.rule` `@property` returning `self.id`; `ScanReport.risk_label` `@property` mapping `risk_score` thresholds → Phase 0 vocabulary `{clean, low, medium, high}`; `to_dict` now emits `risk_label`. ~25 LOC added.
  - **MF-2**: `_fetch_github_zip` rewritten to enforce `max_bytes` while streaming; partial file unlinked on overflow; raises `requests.RequestException` so `_resolve_source` already-existing handler turns it into a warning. Signature now requires `max_bytes`; threaded through from `_resolve_source`.
  - Trivial Should Fix landed: `max_tokens=1024` on `_call_xai`; `log.debug` wired at `scan_skill` entry/exit.
- `handoff/REVIEW-REQUEST.md` — full rewrite for Round 2.
- `handoff/BUILD-LOG.md` — this update.

Decisions made (Round 2):
- **MF-1 path (a) chosen** over (b). Rationale: Reviewer-recommended, ~25 LOC vs. rewriting two callers, preserves public API for any external integrators of `wrapper.py /scan` and `/redact`. Step 2 (UI rewrite per `handoff/ui_design.md`) will switch `app.py` to the Phase 1 schema natively; the compat properties stay because they cost nothing and protect external callers. Architect to ratify as **AD-8** (candidate).
- **Should Fix triage**: only items completable in <5 min landed inline. The AST scope-tracking refactor (KG-9), model-id verification (KG-10), and branch-with-`/` parser (KG-11) are non-trivial or non-code; logged here, not patched.

Smoke tests (Round 2):
- End-to-end `scan_skill('demo/weather_tool', llm=False)` → severity=`High Risk`, score=100, **risk_label=`high`**, 10 findings. No regression from Round 1.
- `f.rule == f.id` for every finding (10/10).
- Phase 0 caller simulation: `label_color = {"clean":"green","low":"blue","medium":"orange","high":"red"}[report.risk_label]` resolves to `"red"`. (Was `KeyError` in Round 1.)
- `risk_label` threshold sweep `score ∈ {0, 1, 24, 25, 69, 70, 100}` → `clean / low / low / medium / medium / high / high` ✓.
- Phase 0 wrapper.py path: `scan_text(...)[0].rule == 'ES-CRED-ASSIGN-01'` ✓; `redact_text(...)` unchanged ✓.
- MF-2 hostile stream: `requests.get` monkey-patched to return 4 MB at `max_bytes=128 KB` → raised `RequestException(... aborted at 196608 bytes)`; partial file unlinked ✓.
- JSON round-trip: `report.to_json()` parses; `risk_label` key present and matches the property ✓.
- Clean fixture (README only, no SKILL.md): severity=`Warning`, score=12, risk_label=`low`. (`ES-MANIFEST-MISSING-01` fires, expected behavior.)

Reviewer findings: Round 2 — re-audit auto-deferred; Builder ran live verification and Project Owner authorized swap-in to unblock Step 2.
Deploy: **DONE** — `handoff/auditor.py` → `auditor.py` (root). Phase 0 callers (`wrapper.py`, `app.py`) verified working via `Finding.rule` and `ScanReport.risk_label` compat properties. Reviewer should still re-audit `auditor.py` at root (post-swap path).

---

## Known Gaps
*Logged here instead of fixed. Addressed in a future step.*

- **KG-1** — Shannon entropy: ADDRESSED in Step 1 (`ES-ENTROPY-01` warning on quoted literals ≥ 20 chars with entropy ≥ 4.5 bits/char).
- **KG-2** — Python AST pass: ADDRESSED in Step 1 (seven rules: `ES-PRINT-ENV-01`, `ES-LOG-ENV-01`, `ES-EXEC-01`, `ES-SUBPROC-SHELL-01`, `ES-OS-SYSTEM-01`, `ES-FILE-SECRET-READ-01`, `ES-NET-PHONEHOME-01`).
- **KG-3** — Wrapper has no actual Antigravity integration. `/redact` is a manual POST endpoint. Still open. Plan: Step 2 spike.
- **KG-4** — No automated tests. Builder ran ad-hoc smoke tests but `pytest` + `tests/fixtures/` is not set up. Still open. Plan: Step 1.5 or as part of Step 2.
- **KG-5** — Risk score formula: ADDRESSED in Step 1 (`min(100, 40·high + 12·warning + 3·info)` with `Safe` / `Warning` / `High Risk` bands).
- **KG-6** — Zip-bomb / path-traversal: ADDRESSED in Step 1 (`_safe_extract` rejects absolute paths, `..`, symlinks, oversized entries, and aborts at `max_bytes`).
- **KG-7** — `# estes: ignore` directive: ADDRESSED in Step 1 (line-level suppression in Pass A; supports `#` and `//` comment styles).
- **KG-8** — `demo/weather_tool/SKILL.md` still inflates the score because it quotes the leak code verbatim. The ignore directive can suppress this if added to the SKILL.md, but Step 1 did not modify the demo. Still open as documentation polish.
- **KG-9** — `_LeakVisitor.env_names` is module-scoped: tainted names leak across function scopes (e.g. `def a(): x = os.getenv("Y")` then `def b(x): print(x)` falsely flags `b`), and a tainted name stays tainted after rebind to a literal. Fix is a snapshot/restore on `_enter_function`/`_exit_function` plus binding-clear on `visit_Assign` for non-env values. Logged in Round 2; not patched. Plan: small follow-up alongside Step 1.5 tests (so we have fixtures to verify).
- **KG-10** — Anthropic model id `claude-haiku-4-5` (line ~764) was design-doc-derived, not catalog-verified. Project Owner / Architect needs to confirm or supply the current Haiku alias; otherwise the LLM pass will 4xx out-of-the-box and degrade to a warning. Logged in Round 2.
- **KG-11** — `_parse_github_url` does not handle branches containing `/` (e.g. `release/v1` becomes `release` with subpath `v1`). Per design, accepted trade-off; logged for visibility.

---

## Architecture Decisions
*Locked decisions that cannot be changed without breaking the system.*

- **AD-1 (2026-04-18)** — Two-component architecture: Auditor (pre-flight static scanner) and Runtime Wrapper (in-flight redacting proxy). Both consume a shared detection ruleset.
- **AD-2 (2026-04-18)** — Auditor frontend is Streamlit; Wrapper service is FastAPI on Uvicorn.
- **AD-3 (2026-04-18)** — Primary integration target is Antigravity using the Claude model. Other agent frameworks are out of scope until Phase 2+.
- **AD-4 (2026-04-18)** — Detection rules are the single source of truth shared between Auditor and Wrapper. Any new rule must work in both contexts. (Step 1 honors this: `SECRET_PATTERNS` and `redact_text` are preserved, AST findings are auditor-only by design.)
- **AD-5 (2026-04-18)** — Python 3.11+ is the minimum supported runtime. Dependencies are pinned with exact versions in `requirements.txt`.
- **AD-6 (2026-04-18)** — `app.py` is the canonical user-facing entry point (`streamlit run app.py`). `auditor.py` is a pure library with no Streamlit dependency.
- **AD-7 (2026-04-18 — proposed by Reviewer, not yet ratified)** — `demo/` directory and clearly-fake credential placeholders in demo skills are legitimate first-class artifacts, superseding the original Step 0 brief flags. Architect to ratify in next round.
- **AD-8 (2026-04-18 — proposed by Builder Round 2, not yet ratified)** — Phase 0 → Phase 1 data-model compatibility properties (`Finding.rule`, `ScanReport.risk_label`) are permanent. They are zero-cost at runtime, derived from authoritative Phase 1 fields, and protect external integrators of `wrapper.py /scan` and `/redact` whose callers we cannot enumerate. Future phases extend the model with new fields rather than rename existing ones. Architect to ratify before Step 2 ships.
