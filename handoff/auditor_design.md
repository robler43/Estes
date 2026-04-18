# Auditor Module Design — Step 1
*Written by Architect. Read by Builder and Reviewer. Supersedes the Phase 0 `auditor.py` placeholder for Step 1.*

---

## Goal

Replace the Phase 0 regex-only `auditor.py` with a layered scanner that:

1. Accepts a local skill (file, folder, or `.zip`) **or** a public GitHub URL.
2. Extracts the skill into an isolated workspace.
3. Runs three passes — static regex, Python AST, and an LLM semantic check — against the same shared ruleset.
4. Returns a single structured `ScanReport` (also serializable to JSON) consumed by both the Streamlit UI (`app.py`) and the FastAPI wrapper (`wrapper.py`).

This step closes Phase 0 known gaps **KG-1** (entropy), **KG-2** (AST), **KG-5** (severity-weighted score), and **KG-6** (zip-bomb / path-traversal hardening). KG-7 (`# skillbouncer: ignore` opt-out comment) is also addressed by the line-level ignore directive defined below.

---

## Public Function Signature

```python
def scan_skill(
    source: str | Path,
    *,
    llm: bool = True,
    timeout_s: float = 30.0,
    max_bytes: int = 5 * 1024 * 1024,
) -> ScanReport:
    """Scan a skill from a local path, archive, or public GitHub URL.

    Parameters
    ----------
    source
        One of:
          - a path to a local file or directory
          - a path to a `.zip` archive
          - an `https://github.com/<owner>/<repo>` URL (optionally with
            `/tree/<branch>` or `/tree/<branch>/<subpath>`)
    llm
        If True, run the LLM semantic pass when an API key is configured.
        If False, run static + AST passes only. Always falls back to
        static-only on LLM error.
    timeout_s
        Hard cap on each network call (GitHub fetch, LLM request).
    max_bytes
        Hard cap on total bytes read into memory across all scanned files.
        Protects against zip bombs and oversized repos.

    Returns
    -------
    ScanReport
        Fully populated report. Always returns — never raises on a bad
        skill. Errors during fetch/extract are logged into
        `report.warnings` and the report is still emitted.
    """
```

A thin convenience wrapper preserves backwards compatibility with the existing Streamlit code and FastAPI wrapper:

```python
def scan_path(root: str | Path) -> ScanReport:
    """Compatibility shim. Equivalent to scan_skill(root, llm=False)."""
    return scan_skill(root, llm=False)
```

---

## Data Model

All dataclasses are defined with `@dataclass(slots=True)` and exposed as Pydantic-compatible via a single `to_dict()` / `to_json()` method on `ScanReport`. Builder may use `pydantic.BaseModel` instead if it simplifies the FastAPI surface — they must remain JSON-equivalent.

```python
Severity = Literal["info", "warning", "high"]
OverallSeverity = Literal["Safe", "Warning", "High Risk"]
FindingSource = Literal["static", "ast", "llm"]

@dataclass(slots=True)
class Finding:
    id: str                     # rule id, e.g. "SB-PRINT-ENV-01"
    severity: Severity
    category: str               # e.g. "credential_leak", "semantic_mismatch"
    file: str                   # path relative to skill root
    line: int                   # 1-indexed; 0 if file-level
    message: str
    snippet: str                # truncated to 200 chars
    source: FindingSource
    suggested_fix: str          # short, actionable; may be empty for "info"

@dataclass(slots=True)
class SkillManifest:
    name: str | None
    description: str | None     # raw text from SKILL.md / SKILL.yaml
    declared_capabilities: list[str]   # parsed if present, else []

@dataclass(slots=True)
class ScanReport:
    source: str                 # original `source` argument as a string
    skill_root: str             # extracted root path (relative to tmpdir)
    manifest: SkillManifest
    files_scanned: int
    bytes_scanned: int
    findings: list[Finding]
    risk_score: int             # 0-100
    severity: OverallSeverity   # "Safe" / "Warning" / "High Risk"
    suggested_fix: str          # rolled-up high-level remediation summary
    warnings: list[str]         # non-fatal extraction/LLM errors
    llm_used: bool
    duration_ms: int

    def to_dict(self) -> dict: ...
    def to_json(self, indent: int | None = 2) -> str: ...
```

### Risk score formula

Replaces KG-5's naive `n_findings * 20`:

```
score = min(100,
            40 * count(high)
          + 12 * count(warning)
          +  3 * count(info))
```

### Severity bands

| Condition | Overall severity |
|---|---|
| `count(high) >= 1` OR `score >= 70` | `High Risk` |
| `count(warning) >= 1` OR `score >= 25` | `Warning` |
| otherwise | `Safe` |

Severity is the user-facing verdict; `risk_score` is the numeric backing.

---

## Source Resolution & Workspace Layout

`scan_skill` always operates inside a `tempfile.TemporaryDirectory()` context. Layout:

```
<tmpdir>/
  source/         # raw artifact (zip, downloaded archive, or copied dir)
  skill/          # extracted, sanitized skill root — this is `skill_root`
```

Resolution rules in order:

| Input shape | Behavior |
|---|---|
| Path is a file ending in `.zip` | Copy to `source/skill.zip`, safe-extract to `skill/` |
| Path is a directory | Symlink-copy contents to `skill/` (no walk into symlinks) |
| Path is any other single file | Copy as `skill/<basename>` |
| String matches `^https?://github\.com/...` | Resolve owner/repo/branch/subpath, download `https://codeload.github.com/<owner>/<repo>/zip/refs/heads/<branch>` (with `Authorization: Bearer $GITHUB_TOKEN` if set), safe-extract to `skill/` |
| String starts with `git@github.com:` | Reject in Step 1; log a warning. SSH cloning is out of scope. |
| Anything else | `report.warnings.append("unsupported source")` and return an empty Safe report |

### Safe-extract (closes KG-6)

A single helper `_safe_extract(zip_path, dest_dir, max_bytes)`:

- Rejects entries whose `Path(name).is_absolute()` is true.
- Rejects entries whose resolved target escapes `dest_dir` (`os.path.commonpath` check).
- Rejects symlinks (`zinfo.external_attr >> 28 == 0o12`).
- Tracks running uncompressed total; aborts with a `warnings` entry if `max_bytes` is exceeded.
- Caps individual file uncompressed size at `max_bytes / 4`.

### GitHub URL parser

Accept these forms:

- `https://github.com/<owner>/<repo>`
- `https://github.com/<owner>/<repo>/tree/<branch>`
- `https://github.com/<owner>/<repo>/tree/<branch>/<subpath>`

If branch is omitted, hit `GET https://api.github.com/repos/<owner>/<repo>` to read `default_branch`. If subpath is given, after extraction set `skill_root = <extracted_root>/<subpath>` and ignore everything outside it.

---

## File Discovery

Inside `skill_root`:

- **Manifest**: first match of `SKILL.md`, `SKILL.yaml`, `SKILL.yml`, `SKILL.json`, `manifest.yaml`, `manifest.json`. Parsed loosely — markdown frontmatter or first H1 paragraph for description; YAML/JSON `name`, `description`, `capabilities` keys when present.
- **Code files**: extension-based, the existing `SCANNABLE_SUFFIXES` set extended with `.mjs`, `.cjs`, `.tsx`, `.jsx`. Hard-skip: anything under `node_modules/`, `.git/`, `dist/`, `build/`, `__pycache__/`, `.venv/`, `venv/`.
- **Per-file size cap**: 500 KB. Files larger than that contribute a single `info` finding (`SB-FILE-OVERSIZE-01`) and are not scanned further.

---

## Detection Passes

Each pass returns `list[Finding]`. Results are concatenated and de-duplicated by `(file, line, id)`.

### Pass A — Static (regex + entropy)

- Reuses the existing `SECRET_PATTERNS` ruleset; each regex maps to a stable `Finding.id` (e.g. `SB-PRINT-CRED-01`, `SB-AWS-KEY-01`, `SB-PRIVKEY-01`).
- Adds Shannon-entropy check on quoted string literals ≥ 20 chars: entropy ≥ 4.5 bits/char emits `SB-ENTROPY-01` at `severity="warning"`.
- Honors a line-level opt-out: any line containing `# skillbouncer: ignore` (or `// skillbouncer: ignore` for JS/TS) is skipped. (Closes KG-7.)

### Pass B — Python AST (closes KG-2)

For every `*.py` file, parse with `ast.parse(..., type_comments=True)`. Visitor flags:

| Rule id | Trigger | Severity |
|---|---|---|
| `SB-PRINT-ENV-01` | `print(...)` whose args reference `os.environ`, `os.getenv`, or any `Name` whose definition came from those | `high` |
| `SB-LOG-ENV-01` | `logger.{debug,info,warning,error}(...)` with the same env-var argument shape | `high` |
| `SB-EXEC-01` | call to `eval`, `exec`, or `__import__` with a non-literal argument | `high` |
| `SB-SUBPROC-SHELL-01` | `subprocess.{run,call,Popen,...}` with `shell=True` | `warning` |
| `SB-OS-SYSTEM-01` | `os.system(...)` | `warning` |
| `SB-FILE-SECRET-READ-01` | `open(...)` whose path matches `~/.aws/credentials`, `~/.ssh/id_*`, `*.pem`, `*.key`, `.env` | `high` |
| `SB-NET-PHONEHOME-01` | `requests.{get,post}` / `urllib.request.urlopen` whose URL is a literal pointing at a non-allowlisted host **and** the call is reached from a function that also touches `os.environ` | `warning` |

The AST visitor maintains a small symbol table tracking which local names are bound to env-var reads, so `key = os.getenv("X"); print(key)` is caught.

### Pass C — LLM semantic check (optional)

Compares declared `manifest.description` against the actual code surface to surface mismatches no rule can spot:

- Skill says "fetch weather" but code reads `~/.ssh/id_rsa` → `SB-SEM-MISMATCH-01` (`high`)
- Skill says "local-only" but code makes outbound HTTP → `SB-SEM-NETWORK-01` (`high`)
- Skill description is empty / missing → `SB-MANIFEST-MISSING-01` (`warning`)

Provider config via env vars (loaded with `python-dotenv` at module import):

| Env var | Purpose |
|---|---|
| `SKILLBOUNCER_LLM_PROVIDER` | `anthropic` (default), `xai`, or `off` |
| `SKILLBOUNCER_LLM_MODEL` | overrides default model id |
| `ANTHROPIC_API_KEY` | required when provider is `anthropic` |
| `XAI_API_KEY` | required when provider is `xai` |
| `GITHUB_TOKEN` | optional; used for higher GitHub API rate limits |

Default models:

- `anthropic` → `claude-haiku-4-5` (fast, cheap, deterministic with `temperature=0`)
- `xai` → `grok-4-mini`

Both providers are called over plain HTTPS using the existing `requests` dependency — no SDK is added in Step 1.

#### Anthropic call shape

```python
resp = requests.post(
    "https://api.anthropic.com/v1/messages",
    headers={
        "x-api-key": os.environ["ANTHROPIC_API_KEY"],
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    },
    json={
        "model": model,
        "max_tokens": 1024,
        "temperature": 0,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": user_prompt}],
    },
    timeout=timeout_s,
)
```

#### xAI call shape

```python
resp = requests.post(
    "https://api.x.ai/v1/chat/completions",
    headers={
        "Authorization": f"Bearer {os.environ['XAI_API_KEY']}",
        "Content-Type": "application/json",
    },
    json={
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    },
    timeout=timeout_s,
)
```

#### Prompt contract

`SYSTEM_PROMPT` instructs the model to return **only** a JSON object matching:

```json
{
  "findings": [
    {
      "id": "SB-SEM-...",
      "severity": "high|warning|info",
      "category": "semantic_mismatch|...",
      "file": "<relative path or empty>",
      "line": 0,
      "message": "<one sentence>",
      "snippet": "<≤200 chars>",
      "suggested_fix": "<one sentence>"
    }
  ],
  "summary": "<one sentence overall remediation>"
}
```

`user_prompt` template:

```
SKILL MANIFEST:
---
{manifest_text_truncated_4k}
---

FILE TREE:
{tree}

CODE (concatenated, truncated 32k chars total, file headers prefixed):
{code_dump}

Identify any mismatches between the manifest's stated behavior and what the
code actually does. Focus on credential handling, network calls, file system
access, and capabilities the skill did not declare. Respond with the JSON
schema above. If nothing is off, return {"findings": [], "summary": ""}.
```

Builder must:

- Validate the response with `json.loads` then a strict allowlist of keys; drop unknown fields.
- On any HTTP error, JSON parse error, or schema mismatch: append a single string to `report.warnings` (e.g. `"LLM check skipped: <reason>"`) and continue. Never raise.
- Set `report.llm_used = True` only when the LLM actually returned a parseable response.

---

## Suggested-fix Roll-up

`ScanReport.suggested_fix` is generated deterministically from the findings (no extra LLM call):

- If any `high` findings exist: `"Remove credential leaks before installing this skill. See the {N} high-severity findings."`
- Else if any `warning` exist: `"Review the {N} warnings; this skill may exceed its declared capabilities."`
- Else: `"No actionable issues detected."`

The LLM `summary` field, when present, is appended verbatim after a single line break.

---

## Module Layout

The new `auditor.py` stays a single file — no subpackage yet — but is internally organized:

```
auditor.py
├── constants & dataclasses
├── _safe_extract / _resolve_source / _fetch_github_zip
├── _discover_manifest / _discover_files
├── pass A — _scan_static (regex + entropy + ignore directive)
├── pass B — _scan_ast
├── pass C — _llm_semantic_check
│       └── _call_anthropic / _call_xai
├── _aggregate (score + severity + suggested_fix roll-up)
└── public API: scan_skill, scan_path, scan_text, redact_text, SECRET_PATTERNS
```

`SECRET_PATTERNS` and `redact_text` from Phase 0 stay exported unchanged — `wrapper.py` continues to consume them for the `/redact` endpoint. **AD-4 is preserved.**

---

## Dependencies

No new mandatory packages. All passes use the stack already pinned in `requirements.txt`:

- `requests` — GitHub fetch + LLM HTTPS calls
- `PyYAML` — manifest parse
- `python-dotenv` — `.env` loading at import
- stdlib `ast`, `zipfile`, `tempfile`, `pathlib`, `re`, `math` (entropy)

If Builder feels the AST visitor warrants `libcst` or the LLM call warrants the `anthropic` SDK, escalate before adding.

---

## Definition of Done

- [ ] `scan_skill(...)` accepts all three input shapes (file, dir, GitHub URL) and never raises on bad input.
- [ ] `_safe_extract` rejects path traversal, absolute paths, symlinks, and over-budget archives. Unit-tested with at least one zip-bomb fixture and one `../etc/passwd` fixture.
- [ ] All Phase 0 regex rules still fire; existing `wrapper.py` `/redact` endpoint still passes its smoke test.
- [ ] AST pass detects all three leak vectors in `demo/weather_tool/weather.py` as `high` severity.
- [ ] LLM pass is fully optional. With `SKILLBOUNCER_LLM_PROVIDER=off` (or no API key), `scan_skill` runs static + AST only and `report.llm_used == False`.
- [ ] `report.to_json()` is valid JSON and round-trips through `json.loads` cleanly.
- [ ] `# skillbouncer: ignore` (and `// skillbouncer: ignore`) suppresses static findings on that line. Closes KG-7.
- [ ] Risk score formula and severity bands match this spec exactly.
- [ ] No real API key, token, or other secret committed anywhere — including in test fixtures.
- [ ] `pytest -q` green for at least: zip-bomb rejection, path-traversal rejection, demo weather skill (3 high, severity = `High Risk`), clean skill (0 findings, severity = `Safe`), missing-manifest (1 warning).

---

## Out of Scope for Step 1 (logged as future work)

- Auto-patch generation (rewrite the offending file).
- Private-repo GitHub URLs (would need OAuth flow beyond `GITHUB_TOKEN`).
- `.tar.gz` / `.tgz` archives.
- Caching of LLM responses or downloaded archives.
- The `skillbouncer` CLI — Step 2 spike.
- Antigravity tool-runner hook — Step 2 spike (KG-3).

---

## Open Question for Project Owner

The LLM pass adds latency (typically 1–4s) and a per-scan cost. Default `llm=True` makes the Streamlit UX feel slow on first use; default `llm=False` makes the demo less impressive. Recommend defaulting to `True` in `app.py` with a sidebar toggle, and `False` in the FastAPI `wrapper.py` redact path (runtime must stay fast). Confirm before Builder starts.
