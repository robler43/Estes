# Reviewer Feedback — Step 1
*Written by Reviewer. Read by Builder and Architect.*

Date: 2026-04-18
Ready for Builder: NO

---

## Audit Summary

| Check | Result |
|---|---|
| Implements Architect design (`auditor_design.md`) | MOSTLY — all sections present, only one design promise broken (see Must Fix #1) |
| Public `scan_skill(source, *, llm, timeout_s, max_bytes)` signature matches spec | PASS |
| Three passes (static, AST, LLM) all wired through `scan_skill` | PASS |
| Risk score formula `min(100, 40·high + 12·warning + 3·info)` | PASS — line 1105-1107 |
| Severity bands `Safe` / `Warning` / `High Risk` | PASS — line 1110-1117 |
| `# estes: ignore` directive (closes KG-7) | PASS — line 270 |
| `_safe_extract` defenses (closes KG-6) | PASS — traversal, absolute, symlink, oversize, runtime-stream all blocked |
| Static + AST end-to-end against `demo/weather_tool` returns 3 high AST findings | PASS — verified live (`ES-PRINT-ENV-01` ×2 + `ES-LOG-ENV-01`) |
| LLM pass is fail-soft and degrades to a warning when no key configured | PASS — line 757, 762, 768, 781-784 |
| `report.to_json()` round-trips through `json.loads` | PASS |
| .zip handling | PASS — local zip and GitHub zip both go through `_safe_extract` |
| GitHub URL handling — owner/repo, /tree/branch, /tree/branch/subpath, default-branch lookup, optional `GITHUB_TOKEN` | PASS — `_parse_github_url` + `_github_default_branch` + `_fetch_github_zip` |
| LLM prompt design | PASS — clear role, scoped focus areas, strict JSON schema, empty-result fallback, tolerates fenced output |
| `pytest -q` green for 5 fixture cases (design DoD #10) | NOT MET — only ad-hoc smoke tests run; KG-4 still open |
| Backwards-compat claim ("wrapper.py and app.py need no changes") | **FAIL** — verified live, three breakage points |
| No real secrets in tree | PASS |

---

## Must Fix

### MF-1 — Backwards-compat claim is broken; swap will crash both `app.py` and `wrapper.py` at runtime

`handoff/REVIEW-REQUEST.md` claims: *"`wrapper.py` and `app.py` need no changes for the swap-in."* This is false. Verified by import:

| Caller | Code | Phase 1 result |
|---|---|---|
| `wrapper.py` line 65 | `f.rule` | `AttributeError: 'Finding' object has no attribute 'rule'` |
| `app.py` line 70 | `f.rule` | same `AttributeError` |
| `app.py` line 56 | `result.risk_label` | `AttributeError: 'ScanReport' object has no attribute 'risk_label'` |
| `app.py` line 56 | `label_color = {"clean", "low", "medium", "high"}[risk_label]` | `KeyError` even after aliasing — Phase 1 returns `"Safe" / "Warning" / "High Risk"`, not `"clean" / ... / "high"` |

The `mv handoff/auditor.py auditor.py` step from REVIEW-REQUEST.md will deploy a broken Streamlit UI and a broken `POST /scan` endpoint. Two acceptable fixes:

- **(a)** Add backwards-compat shims to the new module:
  - On `Finding`, expose `rule` as a `@property` returning `self.id` (or store the human rule name and add `rule` as a real field). [`handoff/auditor.py`](handoff/auditor.py) lines 155-165.
  - On `ScanReport`, expose `risk_label` as a `@property` returning a Phase-0-shaped value. The Phase 0 vocabulary was `"clean" / "low" / "medium" / "high"` — map from `risk_score` thresholds, not from `severity`, so the existing `label_color` dict in `app.py` keeps working. [`handoff/auditor.py`](handoff/auditor.py) lines 175-188.
- **(b)** Update [`app.py`](app.py) and [`wrapper.py`](wrapper.py) in the same step to use the new schema (`f.id`, `report.severity`, new `label_color` keyed on Phase 1 values).

Recommend **(a)** — it preserves the swap-in promise Builder made, keeps `wrapper.py /redact` and `/scan` stable for any external callers, and is ~15 lines of code. Either way, this blocks the swap-in.

### MF-2 — `_fetch_github_zip` does not enforce `max_bytes` while streaming

[`handoff/auditor.py`](handoff/auditor.py) line 855-860 streams the zip to disk in 64 KB chunks but never checks total bytes written. A hostile `Content-Length` (or none at all) can fill the user's disk before `_safe_extract` is even called. The function takes a `timeout_s` but no size cap.

Fix: track running total and abort when it exceeds `max_bytes`, deleting the partial file. Surface as a `warnings_out` entry from `_resolve_source`.

```python
total = 0
for chunk in resp.iter_content(chunk_size=64 * 1024):
    if not chunk:
        continue
    total += len(chunk)
    if total > max_bytes:
        f.close()
        dest_zip.unlink(missing_ok=True)
        raise requests.RequestException(
            f"Archive exceeded max_bytes={max_bytes}; aborted at {total}."
        )
    f.write(chunk)
```

`_resolve_source` already catches `requests.RequestException` and turns it into a warning, so the higher-level error path is in place.

---

## Should Fix

- [`handoff/auditor.py`](handoff/auditor.py) lines 327-396 — `_LeakVisitor.env_names` is module-scoped and sticky. (1) tainted name stays tainted after re-binding to a literal: `key = os.getenv("X"); key = "literal"; print(key)` is a false positive; (2) names leak across function scopes: `def a(): x = os.getenv("Y")` then `def b(x): print(x)` flags `b`. Recommendation: snapshot/restore `env_names` on `_enter_function` / `_exit_function`, and clear the binding when `visit_Assign` sees a non-env value bound to a tainted name.
- [`handoff/auditor.py`](handoff/auditor.py) line 673-696 — `_call_xai` does not pass `max_tokens`. A model that goes off-script can run up cost. Add `"max_tokens": 1024` to mirror the Anthropic call (line 657).
- [`handoff/auditor.py`](handoff/auditor.py) line 764 — model id `claude-haiku-4-5` came from the design doc, not a verified Anthropic catalog entry. Confirm with Project Owner that this is the current Anthropic alias for the Haiku tier; otherwise default to a known-good id (`claude-3-5-haiku-20241022` or whatever the April 2026 catalog publishes) so the LLM pass works out of the box.
- Design DoD item 10 (`pytest -q` green) is unmet. Builder ran the equivalent five cases as ad-hoc smoke tests, so the *coverage* exists but it is not reproducible. Add `tests/test_auditor.py` with the five fixtures called out in the design (zip-bomb, traversal, demo weather, clean, missing-manifest) — closes KG-4 and locks the design's promise. Recommend logging as Step 1.5 if Project Owner does not want to block deploy.
- [`handoff/auditor.py`](handoff/auditor.py) line 808-830 — GitHub URL parser does not handle branches that contain `/` (e.g. `release/v1`). Design doc explicitly accepted this trade-off, so log as a known gap (KG-9) rather than fix in Step 1.
- [`handoff/auditor.py`](handoff/auditor.py) line 47 — `log = logging.getLogger("estes.auditor")` is allocated but never written to. Either remove or wire up `log.debug(...)` at the pass boundaries.

---

## Escalate to Architect

- **Backwards-compat policy**. AD-4 says the ruleset is the single source of truth shared between Auditor and Wrapper. The new Step 1 module honors that for `SECRET_PATTERNS` / `redact_text`, but the data model breakage in MF-1 is a Phase 0 → Phase 1 contract break that needs an explicit ruling: do we add `Finding.rule` and `ScanReport.risk_label` as permanent compatibility properties (and lock that as AD-8), or do we declare Phase 0 callers must update on the swap (and update `app.py` / `wrapper.py` in this same step)? Either is fine; pick one and lock it.
- **Open Question 5 from REVIEW-REQUEST**. Builder asks whether the missing pytest suite blocks Step 1 deploy. This is not a code question — it is a project-discipline call. Recommend NO (deploy now, file Step 1.5) **only if** MF-1 and MF-2 are fixed in this round.

---

## Cleared

The architecture, the three-pass implementation, the LLM prompt, and the `_safe_extract` hardening all match the design. The end-to-end behavior on `demo/weather_tool` matches the design's expected output (3 high AST findings + High Risk verdict). The LLM pass is genuinely optional and never raises. Once MF-1 and MF-2 land, the module is deployable.

---

## Process Note

Project Owner asked Reviewer to write to `handoff/reviewer_feedback.md` (lowercase, underscore). Team convention from `claude_skills/handoff/` is `REVIEW-FEEDBACK.md` (uppercase, hyphen). Recommend Architect picks one canonical name and either renames the file or symlinks it. Otherwise the next Reviewer round may write to the wrong path and Architect / Builder will read stale feedback.
