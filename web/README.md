# Estes — Web Frontend

A premium dark-themed dashboard / marketing page that wraps the real
`auditor.scan_skill` engine.

It's three files:

| File              | Purpose                                                        |
| ----------------- | -------------------------------------------------------------- |
| `index.html`      | Single-file Tailwind page (no build step)                      |
| `server.py`       | FastAPI bridge that serves `index.html` and exposes `/api/scan/*` |
| `README.md`       | This document                                                  |

## Run it

```bash
# 1. Install dependencies (adds python-multipart on top of the existing reqs)
pip install -r requirements.txt

# 2. Start the web server (serves the page AND the API)
uvicorn web.server:app --port 5173

# 3. Open the page
open http://localhost:5173
```

Drop a `.zip` into the upload zone, or paste a public GitHub URL. The page
calls into `auditor.scan_skill(...)` and renders the real findings.

## Endpoints

| Method | Path                       | Body                          | Returns                |
| ------ | -------------------------- | ----------------------------- | ---------------------- |
| GET    | `/`                        | —                             | `index.html`           |
| GET    | `/api/health`              | —                             | `{ "status": "ok" }`   |
| POST   | `/api/scan/file`           | `multipart/form-data` (`file`)| Scan payload (JSON)    |
| POST   | `/api/scan/url`            | `{ "url": "https://..." }`    | Scan payload (JSON)    |
| GET    | `/api/download/{scan_id}`  | —                             | `skill_fixed.zip`      |

### Scan payload shape

```jsonc
{
  "scan_id":      "b7708720…",
  "label":        "weather_tool.zip",
  "risk_score":   100,
  "severity":     "Critical",      // "Safe" | "Warning" | "High Risk" | "Critical"
  "files_scanned": 2,
  "bytes_scanned": 1234,
  "duration_ms":  4131,
  "warnings":     [],
  "manifest":     { "name": "...", "description": "..." },
  "counts":       { "critical": 0, "high": 8, "warning": 2, "info": 0 },
  "suggested_fix": "Top-line remediation guidance.",
  "can_download": true,            // false for URL scans (temp dir is gone)
  "findings": [
    {
      "id":       "ES-PRINT-CRED-01",
      "severity": "high",          // "critical" | "high" | "warning" | "info"
      "source":   "static",        // "static" | "ast"
      "category": "credential",
      "file":     "weather_tool/weather.py",
      "line":     23,
      "message":  "Debug print emits a credential to stdout.",
      "snippet":  "print(f\"DEBUG key={api_key}\")",
      "suggested_fix": "Replace with structured logging…",
      "weight":   30                // _SEVERITY_WEIGHT × _CATEGORY_MULTIPLIER from auditor.py
    }
  ]
}
```

## What the frontend does with each finding

The Skill Checkup section reveals after a scan and renders one card per
finding with three labelled blocks:

1. **Evidence** — the `snippet` from the auditor with the offending line
   highlighted (red bar + tinted background).
2. **Why this lowers your score** — the `message` plus a neon
   `Severity weight: +N` callout, where `N = severity_weight × category_multiplier`
   (mirrors `auditor._compute_score`).
3. **Suggested fix** — `suggested_fix` from the auditor.

Plus the action bar at the top:

- **Apply Wrapper** — toasts the install snippet for `wrapper.py`.
- **Download Fixed** — calls `/api/download/{scan_id}`, which rebuilds a
  patched `.zip` with `# estes: ignore` markers on every flagged line,
  exactly mirroring `app._build_fixed_zip` from the Streamlit UI. Disabled
  automatically for URL scans (the temp tree is gone after `scan_skill` returns).

## State

`server.py` keeps an in-memory `_STORE` keyed by `scan_id`:
```python
{ "report": ScanReport, "root": Path | None, "label": str, "created": float }
```
Entries TTL after **30 minutes** (`_TTL_S = 30 * 60`) and the materialized
upload directory is `shutil.rmtree`-d on expiry.

## Styling notes

- Single neon-green accent (`#00ff9d`); risk colours (green/amber/red) only
  appear in the gauge and severity pills.
- All animations honour `prefers-reduced-motion`.
- Background canvas + hero constellation throttle to ~30fps and pause when
  off-screen / when the tab is hidden.
- No `backdrop-filter`, no decorative gradients.
- shadcn-style: hairline borders, glass-on-dark, mono eyebrows.
