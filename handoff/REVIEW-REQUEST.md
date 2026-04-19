# Review Request — Step 2 (Dashboard rewrite)
*Written by Builder. Read by Reviewer.*

Ready for Review: YES

---

## What Was Built

A complete dark-mode dashboard implementing `handoff/ui_design.md` end-to-end. The surface area:

- `app.py` — full rewrite. Layout + state plumbing only; no scan logic in this file.
- `.streamlit/config.toml` — dark theme + `#22ff88` primary color baseline.
- `assets/styles.css` — single 9.5 KB stylesheet, zero hard-coded hex codes (every color resolves through `:root` CSS variables emitted by `ui/theme.py`).
- `assets/logo.svg` — 40×40 shield + chat-bubble notch (single-color stroke).
- `ui/theme.py` — palette + severity tokens + `theme_css_variables()` for the CSS-var emitter.
- `ui/components.py` — every render helper (`render_header`, `render_empty_state`, `render_score_panel`, `render_fix_banner`, `render_warnings`, `render_findings_list`, `render_finding_card`, `inject_styles`). All HTML interpolations go through `html.escape()`.

Step 1 (auditor close-out) is also fully deployed in this turn: MF-1 and MF-2 cleared, `handoff/auditor.py` swapped to `auditor.py` at root, Phase 0 callers (`wrapper.py`, `app.py`) verified working post-swap. See `handoff/BUILD-LOG.md` Step 1 Round 2 section.

## Files Changed

| File | Change | Notes |
|---|---|---|
| `app.py` | Full rewrite | ~290 LOC; Phase 1 schema; primary CTA + 2 secondary; modal-equivalent `Apply Wrapper`; `Download Fixed` zip generator. |
| `.streamlit/config.toml` | NEW | Dark base, primary `#22ff88`. |
| `assets/styles.css` | NEW | Imports Inter + JetBrains Mono; resets Streamlit chrome; styles dropzone, expanders, buttons, cards. |
| `assets/logo.svg` | NEW | Shield + chat-bubble notch, `currentColor` stroke. |
| `ui/__init__.py` | NEW | Package marker. |
| `ui/theme.py` | NEW | `BG_*`, `TEXT_*`, `ACCENT*`, `WARN`, `DANGER`, `INFO`; `SEVERITY_STYLE` for the three Phase 1 buckets; `FINDING_SEVERITY_STYLE` for `info/warning/high`; `SOURCE_STYLE` for `static/ast/llm`; `theme_css_variables()` emitter. |
| `ui/components.py` | NEW | All `unsafe_allow_html=True` lives here, scoped to constants + `html.escape()`-wrapped interpolations. |

## Smoke Tests Run

The sandbox env doesn't have `streamlit` installed, so the dashboard cannot boot here. What was verified:

1. `py_compile` passes on every file in the project (`app.py`, `auditor.py`, `wrapper.py`, `ui/*.py`).
2. `auditor.scan_skill('demo/weather_tool', llm=False)` → severity=`High Risk`, score=100, risk_label=`high`, 10 findings (unchanged from Step 1 Round 2).
3. `from auditor import scan_text, redact_text, scan_path` — Phase 0 surface still works.
4. CSS palette discipline: `grep '#[0-9a-fA-F]{6}' assets/styles.css` returns no hits — every color comes from a `--token` variable.
5. `ui/theme.theme_css_variables()` emits valid CSS for all 13 tokens.
6. `ui/components.LOGO_SVG` shield path matches `assets/logo.svg` source of truth.
7. No new entries in `requirements.txt`.

What needs runtime validation on the Reviewer's dev box (with `streamlit` installed):

- `streamlit run app.py` boots without console errors.
- Drag-and-drop a `.zip` from Finder into the dropzone produces a scan and renders the Results panel.
- Pasting `https://github.com/RobinHo-coder/Estes` into the URL field and clicking Scan Skill produces a scan.
- The empty state ("What we look for" triptych) renders before any scan and disappears after.
- Severity + source filters narrow the visible findings list without re-scanning.
- `Apply Wrapper` opens the install-instructions expander; `Download Fixed` produces a real zip.
- WCAG AA contrast holds on a real screen.

## Open Questions

1. **Architect Q2 ("Danger" vs "High Risk")** — kept "HIGH RISK" matching `auditor.OverallSeverity`. UI-only rename to "DANGER" is a one-line change in `ui/theme.py SEVERITY_STYLE`. Project Owner / Architect: confirm which?
2. **Header `Docs` link** — no docs site exists yet, so the link is `#`. Acceptable?
3. **`Apply Wrapper` UX** — currently shows install instructions in an inline expander since KG-3 is open and we can't actually install. Is "honest documentation" acceptable, or does the demo for judges need this to *look* like a one-click install (lie quietly)?
4. **`Download Fixed` patch quality** — current implementation is Reviewer-flagged "stub" by design (appends `# estes: ignore` markers, doesn't fix the underlying leak). Generates a `ESTES_PATCH.md` manifest alongside. Acceptable for Phase 1?
5. **Streamlit 1.39 expander HTML labels** — code uses plain-text labels with leading severity glyphs. If 1.39 actually supports HTML in expander labels reliably, we can upgrade to colored severity dots in the label. Worth verifying on the dev box.

## Known Gaps Status

- KG-3 (Antigravity hook) — still open. `Apply Wrapper` button surfaces the manual `uvicorn` install path until this lands.
- KG-4 (pytest suite) — still open. Step 2 added more code that isn't covered.
- KG-8 (demo SKILL.md self-flags) — still open. The new dashboard renders the noise faithfully.
- KG-9, KG-10, KG-11 — Step 1 carryovers, not addressed in Step 2.

## Re-audit Checklist for Reviewer

- [ ] Dashboard boots cleanly (`streamlit run app.py`) on a 1280px+ viewport.
- [ ] Drag-and-drop a `.zip` (use `demo/weather_tool` zipped) → produces severity badge, score, suggested-fix banner, expandable findings.
- [ ] Filters (severity, source) narrow findings without re-scanning.
- [ ] `Scan Skill` is the only enabled action with no source provided; secondary actions enable only after a non-Safe report.
- [ ] `Download Fixed` zip extracts and contains `ESTES_PATCH.md` plus the original tree with markers appended at the right line numbers.
- [ ] `Apply Wrapper` expander shows the install one-liner.
- [ ] No regressions in `wrapper.py` (`POST /scan`, `POST /redact`) — Phase 0 attribute access via `f.rule` still works.
- [ ] CSS palette discipline (no hard-coded hex) holds.
- [ ] `html.escape()` applied to every dynamic interpolation in `ui/components.py`.

Write findings to `handoff/reviewer_feedback.md` (lowercase, underscore — matches Round 1 convention).
