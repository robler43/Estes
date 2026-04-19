# Estes Dashboard — UI Design (Step 2)
*Owned by Architect. Implemented by Builder.*

Date: 2026-04-18
Status: DRAFT — for Builder consumption after MF-1 lands

---

## 0. Why this exists

Step 0 shipped a default-themed Streamlit skeleton. It works but does not look like a security tool — it looks like a notebook. The Step 1 auditor now produces a rich `ScanReport` (severity bands, suggested fixes, per-rule categories, LLM commentary). The UI needs to surface that information at glance and convince a developer to *trust the verdict*.

Goals:
- A judge / first-time user sees the verdict in under 2 seconds.
- The dashboard reads as a security console, not a data viewer.
- All claims in the README's demo flow ("upload skill → see High Risk → see exact findings → apply wrapper") are clickable here.

Non-goals (locked out of Step 2):
- Multi-user accounts, history, persistence — Phase 3.
- Live runtime telemetry from the Wrapper — Phase 2.
- In-browser code editing of the patched skill — Phase 3.

---

## 1. Hard prerequisite

This design targets the **Phase 1 `ScanReport` schema** (`severity` ∈ {`Safe`, `Warning`, `High Risk`}, `Finding.id`, `Finding.suggested_fix`, etc.). It will not work against the Phase 0 `ScanResult`/`risk_label` schema.

Before Step 2 starts, **Reviewer's MF-1 from `handoff/reviewer_feedback.md` must be cleared** — either:
- (a) Phase 1 `auditor.py` adds backwards-compat shims so the old schema keeps working AND the new one is reachable, or
- (b) `app.py` is rewritten against the new schema as part of this Step 2 work.

This design assumes **(b)**: Step 2 owns the rewrite. If Architect rules (a), drop the schema-rewrite section below; everything else still applies.

---

## 2. Visual system

### 2.1 Color tokens

| Token | Hex | Use |
|---|---|---|
| `--bg-0` | `#0a0e14` | Page background |
| `--bg-1` | `#111821` | Card / panel background |
| `--bg-2` | `#1a232f` | Elevated surfaces (hover, expanded card) |
| `--border` | `#1f2a37` | Panel hairlines |
| `--text-0` | `#e6edf3` | Primary text |
| `--text-1` | `#9aa7b4` | Secondary text |
| `--text-2` | `#5a6573` | Tertiary / metadata |
| `--accent` | `#22ff88` | Brand neon green — logo, primary CTA, "Safe" |
| `--accent-dim` | `#22ff8833` | Accent glow / borders at 20% alpha |
| `--warn` | `#ffb454` | "Warning" severity |
| `--danger` | `#ff4d6d` | "High Risk" severity, destructive CTA |
| `--info` | `#5fb5ff` | Informational badges, LLM source tag |

**Contrast contract**: every text/background pairing must hit WCAG AA (4.5:1) at minimum. `--accent` on `--bg-0` = 12.4:1, `--danger` on `--bg-1` = 5.8:1. Pass.

### 2.2 Typography

- **Display / numbers**: `JetBrains Mono`, 600 weight. Used for the risk score, rule IDs, code snippets. Reinforces "console" vibe.
- **UI text**: `Inter`, 400 / 500 / 600. Used for everything else.
- Both loaded from Google Fonts via the injected stylesheet — no extra dependency.

Type scale:
- Risk score numeric: 72px
- Section headings (`Findings`, `Actions`): 20px / 600
- Card title: 15px / 600
- Body: 14px / 400
- Metadata / tags: 12px / 500 / uppercase / 0.6px tracking

### 2.3 Spacing & corners

8px base grid. Card radius 12px, button radius 8px, badge radius 999px (pill).
Panels have a 1px `--border` hairline plus a soft inner glow (`box-shadow: inset 0 0 0 1px rgba(34,255,136,0.04)`) for the "circuit board" feel.

---

## 3. Layout

### 3.1 Wireframe (1440px viewport)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  [◇ logo]  Estes                                          [docs] [gh] │  ← header (sticky)
│            Keep secrets out of your agent chats                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  ╔══════════════════════════════════════════════════════════════════╗  │ │
│  │  ║                                                                  ║  │ │
│  │  ║                          ⬆  Drop a third-party skill             ║  │ │
│  │  ║                          (.zip or GitHub link)                   ║  │ │
│  │  ║                                                                  ║  │ │
│  │  ║                  or  [ paste GitHub URL …                    ]   ║  │ │  ← upload area
│  │  ║                                                                  ║  │ │
│  │  ╚══════════════════════════════════════════════════════════════════╝  │ │
│  │                                                                        │ │
│  │             [ Scan Skill ]    [ Apply Wrapper ]  [ Download Fixed ]   │ │  ← action bar (disabled until report)
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌────────── Results ────────────────────────────────────────────────────┐ │
│  │                                                                        │ │
│  │   ┌──────────┐    ┌─────────────┐   ┌─────────────────────────────┐  │ │
│  │   │   78     │    │ ● HIGH RISK │   │  9 findings · 4 files · 1.2s│  │ │  ← score + badge + meta
│  │   │  /100    │    └─────────────┘   └─────────────────────────────┘  │ │
│  │   └──────────┘                                                        │ │
│  │                                                                        │ │
│  │   ▸ Recommended action: Remove credential leaks before installing.    │ │  ← suggested_fix banner
│  │                                                                        │ │
│  ├────────── Findings (9) ───────────────────── [filter: all▾] [src▾]──┤ │
│  │                                                                        │ │
│  │   ▾ ● HIGH    ES-PRINT-ENV-01    weather.py:14         [ast]         │ │  ← expandable card
│  │     print() exposes environment variable contents.                    │ │
│  │     ┌──────────────────────────────────────────────────────────────┐│ │
│  │     │ print(f"[DEBUG] Calling weather API with api_key={API_KEY}") ││ │
│  │     └──────────────────────────────────────────────────────────────┘│ │
│  │     Suggested fix: Remove the print or redact the env value.         │ │
│  │                                                                        │ │
│  │   ▸ ● HIGH    ES-LOG-ENV-01      weather.py:16         [ast]         │ │
│  │   ▸ ● WARN    ES-NET-PHONEHOME   weather.py:21         [ast]         │ │
│  │   ▸ ● WARN    ES-CRED-ASSIGN-01  weather.py:8          [static]      │ │
│  │   ▸ ● INFO    ES-FILE-OVERSIZE   data.bin              [static]      │ │
│  │                                                                        │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Streamlit primitives

| Region | Primitive | Notes |
|---|---|---|
| Header | `st.markdown(html, unsafe_allow_html=True)` | Single inline block; logo as inline SVG, links open in new tab |
| Upload area | `st.file_uploader` + `st.text_input` (URL) | Style the dropzone with CSS targeting `[data-testid="stFileUploaderDropzone"]` |
| Action bar | 3 × `st.button` in a `st.columns([1,1,1,3])` | Right column is empty spacer to keep buttons left-aligned |
| Score panel | `st.columns([1,1,2])` with custom HTML in each | Avoid `st.metric` — its visual weight is wrong; build custom card |
| Suggested fix banner | `st.markdown(html)` | Yellow-on-dark callout card, single line max-2-lines truncated |
| Findings list | `st.expander(label_html, expanded=False)` per finding | Label is HTML for the colored severity dot (Streamlit 1.39 supports markdown in labels — verify) |
| Filters | `st.selectbox` ×2 | "All / High / Warning / Info" and "All / static / ast / llm" |
| Empty state | `st.markdown(html)` with the dropzone-only layout | No "Awaiting upload" plain text — design a real empty state (see §6) |

---

## 4. Component spec

### 4.1 Header

- Sticky to top of viewport. 64px tall.
- Left: logo (40×40, neon green outline) + wordmark (`Estes`, 18px / 600) + tagline below (`Keep secrets out of your agent chats`, 12px / `--text-1`).
- Right: two ghost buttons (`Docs`, `GitHub`) — text-only, 13px, hover tint = `--accent` at 80% alpha. These open `README.md` and the repo URL.
- Background: `--bg-0` with a 1px bottom border = `--border`.

Logo asset: `assets/logo.svg` — a stylized shield outline (security) crossed with a chat bubble corner (LLM context). Inline the SVG into `app.py` so there is no static-file-serving dependency. Spec attached in §9.

### 4.2 Upload area

- Outer container: 320px tall on first paint, `--bg-1` background, dashed 2px border in `--border`.
- On drag-over: border color → `--accent`, background → `--accent-dim`, scale(1.005). Streamlit emits `data-testid="stFileUploaderDropzone"` with a `:hover` state — extend with `:has(input:focus)` for keyboard, and use a Streamlit theme override for the drag state if available; otherwise accept the static look as a known limitation.
- Inner content (centered):
  - 40px upload glyph (inline SVG, `--accent`)
  - Headline: **"Drop a third-party skill"** (18px / 600 / `--text-0`)
  - Subline: **".zip archive or GitHub link"** (13px / `--text-1`)
  - Divider: thin `or` row at 60% width
  - URL input: full-width `st.text_input(label_visibility="collapsed", placeholder="https://github.com/owner/repo")` styled to `--bg-2` background and 1px `--border`

When **either** an upload OR a non-empty URL is present, the action bar's primary button (`Scan Skill`) becomes enabled. Mutually exclusive — if both are filled, the URL wins and a small inline notice ("Using URL; uploaded file ignored") appears.

### 4.3 Action bar

Three buttons, left-aligned, equal width (160px each):

| Button | State machine | Behavior |
|---|---|---|
| **Scan Skill** | enabled iff source provided AND not currently scanning | Calls `auditor.scan_skill(source, llm=True)`. Spinner overlays the panel during scan. On error → toast (`st.error`). |
| **Apply Wrapper** | enabled iff `report` exists AND `report.severity != "Safe"` | Opens a modal-equivalent (Streamlit has no native modal in 1.39 — use an `st.expander` styled as a side-sheet, or a `st.dialog` if Builder confirms 1.39 ships it). Modal contents: a one-liner `pip install estes && estes start` plus a copy-to-clipboard button. **No actual install is performed** — KG-3 still open. Tooltip on hover when disabled: "Wrapper is only useful when findings exist." |
| **Download Fixed Skill** | enabled iff `report` exists AND `report.severity != "Safe"` AND source was a `.zip` or directory (not a single file) | Generates an in-memory zip that is the original tree with `# estes: ignore` comments inserted at every flagged line, then `st.download_button` triggers the download. **This is a stub-grade auto-patch**, not the full roadmap auto-fix. Builder must add a banner inside the modal: "Stub patch — review before redistributing." |

Visual:
- Primary (`Scan Skill`): solid `--accent` background, `--bg-0` text, no border, 8px radius. Hover: 10% lighter. Focus: 2px `--accent` outline at 50% alpha.
- Secondary (`Apply Wrapper`, `Download Fixed Skill`): transparent background, 1px `--border`, `--text-0` text. Hover: `--bg-2` background.
- Disabled: 40% opacity, `cursor: not-allowed`, no hover state.

### 4.4 Results panel — score + badge

Three-column row. Avoid `st.metric` (its label-on-top, value-below layout isn't punchy enough).

**Score card** (left, 200px wide):
```
┌──────────┐
│   78     │   ← 72px JetBrains Mono, color = severity color
│  /100    │   ← 14px text-1, vertically baseline-aligned
└──────────┘
```
The numeric color follows severity: `--accent` for Safe, `--warn` for Warning, `--danger` for High Risk. Background = `--bg-1`, 12px radius, 24px internal padding.

**Status badge** (middle, intrinsic width):
- Pill, 999px radius, 8px vertical / 16px horizontal padding.
- Layout: `● TEXT` where the dot is 8px and matches the severity color.
- Backgrounds: severity color at 12% alpha. Text + dot at full severity color.
- Three states: `● SAFE` / `● WARNING` / `● HIGH RISK`. (User asked for "Danger"; we keep `High Risk` to match `auditor.py` and the README. If Project Owner insists on "Danger", that becomes a one-line `OverallSeverity` rename in `auditor.py` — Architect call needed.)

**Meta strip** (right, fills remaining width):
- One row, `--text-1`, 13px:
  `9 findings  ·  4 files scanned  ·  1.2 s  ·  llm: claude-haiku ✓`
- The `llm: ...` segment shows `llm: off` in `--text-2` if `report.llm_used == False`, and `llm: skipped` with a tooltip if `report.warnings` contains the LLM-skipped message.

### 4.5 Suggested-fix banner

Below the score row, full-width single-line callout:
- Background `--bg-2`, 1px `--border`, 8px radius, 12px padding.
- Left edge: 4px solid bar in severity color.
- Content: `report.suggested_fix`, truncated to 2 lines with `text-overflow: ellipsis`. Click → expands inline to full text.

### 4.6 Findings list

Section header: `Findings (N)` with two right-aligned filter dropdowns:
- **Severity filter**: All / High / Warning / Info
- **Source filter**: All / static / ast / llm

Each finding renders as an `st.expander` whose label is HTML:

```
[●] HIGH    ES-PRINT-ENV-01    weather.py:14    [ast]
```

Where:
- `[●]` is an 8px dot in severity color
- `HIGH` / `WARNING` / `INFO` is a 12px uppercase tag
- `ES-PRINT-ENV-01` is the rule id, JetBrains Mono 13px, `--text-0`
- `weather.py:14` is `--text-1` 13px, click would seek to file (Phase 3 — for now non-interactive)
- `[ast]` is a tiny capsule tag in `--info` color

Expanded body:
- Top: `f.message` (full text, 14px `--text-0`)
- Middle: code snippet inside a `st.code(snippet, language="python")` block, but wrapped in a `<div class="es-snippet">` with our own background (`--bg-0`) so it pops against the card surface.
- Bottom: a horizontal callout bar, `--accent`-tinted at 8% alpha:
  ```
  ✓ Suggested fix:  Remove the print or redact the env value before printing.
  ```
- Right side, vertically centered: a "Copy rule ID" small ghost button (clipboard glyph) for users filing an issue.

Sort order: severity desc, then file asc, then line asc.

Cap rendered count at 50; show a "+ N more findings — adjust filters to drill down" footer when more exist.

### 4.7 Empty state (no scan yet)

Suppress the Results panel entirely. The upload area expands to fill the lower area. Below the dropzone, show a 3-card "What we look for" trio:

```
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  ⓘ env-var      │  │  ⓘ semantic     │  │  ⓘ secret       │
│    leaks        │  │    mismatches   │  │    file reads   │
│                 │  │                 │  │                 │
│  print() / log  │  │  SKILL.md says  │  │  .env, ssh keys,│
│  of os.environ  │  │  X, code does Y │  │  AWS creds      │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

Style: matches `--bg-1` cards, 1px `--border`, neon-green icon glyph, 14px text. Static — no behavior. This sells the product before the user uploads anything.

### 4.8 Loading state

While `scan_skill` is running:
- Disable the action bar.
- Cover the upload area with a centered animated row: a 24px spinner in `--accent` plus the text `Scanning skill — running static, AST, and LLM passes…`. Use `st.spinner` inside an explicit container; do not block the page with `st.spinner` at the top level (the dropzone should stay visible underneath).

If the scan takes > 8s, append a sub-line: `LLM call in flight (Anthropic Claude Haiku)…`. This requires the Builder to either run the scan in a thread with a progress hook, or accept the simpler "single message, no progress" fallback. Recommend the simpler version for Step 2; thread later.

### 4.9 Error states

| Condition | UI |
|---|---|
| `scan_skill` raises an exception | Red toast top-right: "Scan failed — see logs." Replace the Results panel with a single error card showing the exception class and message. |
| `report.warnings` is non-empty | Yellow inline strip above the Findings section, collapsible: "N warnings during scan ▸". Expanded: bulleted list of the warning strings verbatim. |
| `report.findings` is empty AND `severity == "Safe"` | Green hero card replacing the findings list: "✓ No issues found. This skill is clean against the current ruleset." Plus a fine-print disclaimer that static analysis is not proof of safety. |

---

## 5. State machine

```
        ┌─────────┐  user provides source   ┌──────────┐
        │  IDLE   ├────────────────────────►│ READY    │
        └─────────┘                         └────┬─────┘
            ▲                                    │ click Scan Skill
            │ user clears                        ▼
            │                              ┌──────────┐
            │                              │ SCANNING │
            │                              └────┬─────┘
            │                ┌──────────────────┴──────────────────┐
            │                │                                     │
            │                ▼                                     ▼
            │          ┌──────────┐                          ┌──────────┐
            └──────────┤  ERROR   │                          │  REPORT  │
                       └──────────┘                          └──────────┘
                                                              │     │     │
                                                              │     │     │
                                              click new source│     │     │ click Apply / Download
                                                              ▼     ▼     ▼
                                                            (back to READY)  (modal opens, REPORT stays)
```

Persist `report` in `st.session_state` so re-runs (Streamlit's auto-rerender on widget change) don't drop it.

---

## 6. File layout

New / changed files for Step 2:

```
Estes/
├── app.py                           # rewritten end-to-end
├── .streamlit/
│   └── config.toml                  # NEW — locks dark base theme + accent
├── assets/
│   ├── logo.svg                     # NEW — inline-loaded by app.py
│   └── styles.css                   # NEW — read at startup, injected via st.markdown
├── ui/                              # NEW — pure-render helpers, no business logic
│   ├── __init__.py
│   ├── components.py                # render_header, render_upload, render_results, render_finding_card, render_empty_state, render_action_bar
│   └── theme.py                     # color tokens as Python constants (single source of truth — must match styles.css)
└── auditor.py                       # unchanged from Step 1 (post-MF-1)
```

`auditor.py` stays a pure library (AD-6 holds). `ui/` exists so `app.py` reduces to layout + state plumbing — easier to test (KG-4) and easier for a Builder to iterate on without touching scan logic.

### 6.1 `.streamlit/config.toml`

```toml
[theme]
base = "dark"
primaryColor = "#22ff88"
backgroundColor = "#0a0e14"
secondaryBackgroundColor = "#111821"
textColor = "#e6edf3"
font = "sans serif"
```

This handles the bulk of the dark mode work; the injected stylesheet only overrides the ~10 components Streamlit's theme can't reach (file uploader, expander, code block).

### 6.2 `assets/styles.css`

A single ~150-line stylesheet, scoped via class names we add ourselves (`es-card`, `es-badge`, `es-snippet`, etc.) plus a small set of `[data-testid="..."]` overrides for built-in widgets. Loaded once at app startup:

```python
st.markdown(f"<style>{(Path('assets')/'styles.css').read_text()}</style>",
            unsafe_allow_html=True)
```

Builder must keep CSS small and readable. **No CSS-in-JS. No Tailwind. No build step.**

### 6.3 `assets/logo.svg`

Inline-friendly SVG, 40×40, single-color stroke at `currentColor` so it inherits `--accent`. Spec:

- A rounded shield outline (the "bouncer")
- A small chat-bubble notch in the lower-right corner (the "agent chat")
- Stroke 2px, no fill

Builder: produce this hand-crafted; do not generate via image model. If pressed for time, ship a 40×40 placeholder rectangle with the letters `SB` — file an issue to swap later.

---

## 7. Schema rewrite (consequence of MF-1 path b)

Replace the relevant section of the rewritten `app.py` to consume Phase 1:

| Old (Phase 0) | New (Phase 1) |
|---|---|
| `result.risk_label` (`clean`/`low`/`medium`/`high`) | `report.severity` (`Safe`/`Warning`/`High Risk`) |
| `label_color[result.risk_label]` (4 keys) | `SEVERITY_STYLE[report.severity]` (3 keys, defined in `ui/theme.py`) |
| `f.rule` | `f.id` |
| `f.snippet` | `f.snippet` (unchanged) |
| `result.files_scanned` | `report.files_scanned` (unchanged) |
| n/a | `report.suggested_fix` (new — render in §4.5 banner) |
| n/a | `report.warnings` (new — render in §4.9) |
| n/a | `report.llm_used` (new — render in §4.4 meta strip) |
| `scan_path(target)` | `scan_skill(source, llm=True)` |

`scan_path` stays in `auditor.py` for the FastAPI wrapper, but `app.py` switches to `scan_skill` directly so the LLM pass actually runs.

---

## 8. Definition of Done

Step 2 is complete when:

1. `streamlit run app.py` launches a dark-themed dashboard matching §3.1 within ±10% spacing.
2. The header (logo + wordmark + tagline + 2 right-side links) is visible and sticky.
3. Drag-and-drop a `.zip` from the OS file manager into the dropzone produces a scan and renders the Results panel.
4. Pasting `https://github.com/owner/repo` into the URL field and clicking Scan Skill produces a scan (assuming the repo exists).
5. The 3 demo skills (existing `demo/weather_tool` + at least 1 clean fixture + 1 missing-manifest fixture) each render a coherent Results panel with the correct severity color across the score, badge, and suggested-fix bar.
6. Empty state (§4.7) renders before any scan runs and disappears once a report exists.
7. Findings render as expandable cards per §4.6, with severity dot, rule id, file:line, source tag, code snippet, and suggested-fix callout.
8. Severity and source filters narrow the visible findings list without re-scanning.
9. `Scan Skill` is the only action enabled at the empty-state. `Apply Wrapper` and `Download Fixed Skill` enable only after a non-Safe report exists.
10. `Download Fixed Skill` produces a real `.zip` whose flagged lines have `# estes: ignore` appended (or the equivalent comment for non-Python files).
11. WCAG AA contrast holds for the 8 color/background pairings tabulated in §2.1, verified with a contrast checker.
12. No console errors in Chrome DevTools after a full happy-path run.
13. `app.py` imports nothing from `streamlit.components` and uses no third-party Streamlit add-ons. No new entries in `requirements.txt`.

Out of scope for Step 2 (do not let scope creep eat these):
- Real Wrapper installation flow (KG-3, Phase 2).
- Real auto-patched skill (the stub from item 10 is enough).
- Multi-file diff viewer.
- Persisted scan history.
- Mobile / narrow-viewport layout — desktop-first, 1280px min.

---

## 9. Implementation hand-off notes for Builder

- **Styling discipline**: every CSS rule lives in `assets/styles.css`. No `<style>` tags scattered through `app.py`. The only inline HTML in `app.py` is structure (divs with class names) — colors and spacing are CSS-only. This makes the Reviewer's job tractable.
- **`unsafe_allow_html=True` is contained**: only inside the helpers in `ui/components.py`. Never accept user-supplied strings into one of these blocks without escaping — every variable interpolated into HTML must go through `html.escape(...)`. Treat finding `snippet`, `message`, `file`, `id` as untrusted input. (Yes, even though we generated them — the LLM pass produces some of them and a malicious skill can poison the LLM output.)
- **No background threads** in Step 2. Scans run synchronously inside the Streamlit run. If this proves too slow during the demo, add a thread + `st.session_state` poll loop in Step 2.5 — not now.
- **Verify Streamlit version supports HTML in expander labels** before relying on it (Streamlit 1.39 — Builder to confirm). If it does not, fall back to plain-text labels with a leading character (`▲` for high, `△` for warning, `·` for info) so the visual hierarchy survives.
- **Logo SVG** — inline as a Python string constant in `ui/components.py` so there is no static-asset routing dependency. The `assets/logo.svg` file in §6 is the source of truth; the inlined copy is a generated artifact (committed for convenience).
- **Severity → color mapping** lives in exactly one place (`ui/theme.py`) and is consumed by both Python (badge / score color) and CSS (via CSS variables set in a `<style>` block written from theme.py at startup). Do not duplicate the hex codes in `styles.css`.

Open questions for Project Owner (do not block Builder; ship the design's defaults if no answer):
- **Q1**: Brand language — header tagline is "Keep secrets out of your agent chats" per request. Confirm wording. (We could also ship a longer subline like "Static + AST + LLM scanning for third-party AI agent skills" — let me know.)
- **Q2**: Status badge wording — request asked for "Danger"; spec says "High Risk" to match `auditor.py`'s `OverallSeverity`. If you want "Danger" in the UI, tell me whether to also rename in the auditor (consistency) or alias only in the UI.
- **Q3**: GitHub URL field — is it acceptable that it shares the same "scan" code path as upload, or do you want a separate "Scan from GitHub" button? Spec assumes shared path.

---

## 10. Out-of-band: file-naming convention

`handoff/` now contains both `REVIEW-FEEDBACK.md` (template) and `reviewer_feedback.md` (Step 1 actual feedback). Architect ruling needed (proposed in next round). Until then, design docs use lowercase-with-underscores (`auditor_design.md`, `ui_design.md`). Step 2 review feedback should land at `handoff/reviewer_feedback.md` to match the live precedent.

---

## 11. Resume prompts

For the Builder, after MF-1 and MF-2 from Step 1 are cleared:

> You are Bob (Builder) on Estes. Read `handoff/ui_design.md` from the Architect. Implement Step 2 exactly as designed. Do not introduce new dependencies. Scope guard: items in §8 "Out of scope" must NOT ship. Output `app.py` (rewritten), `.streamlit/config.toml`, `assets/styles.css`, `assets/logo.svg`, `ui/components.py`, `ui/theme.py`. Update `handoff/BUILD-LOG.md` and `handoff/REVIEW-REQUEST.md`.

For the Reviewer:

> You are Richard (Reviewer) on Estes. Read `handoff/REVIEW-REQUEST.md` then audit Step 2 against the §8 Definition of Done in `handoff/ui_design.md`. Verify color contrast, spec adherence, and the prerequisite from §1. Write findings to `handoff/reviewer_feedback.md`.
