"""Estes — small FastAPI bridge between the marketing/dashboard page
(`web/index.html`) and the real `auditor.scan_skill` engine.

Run with:

    uvicorn web.server:app --reload --port 5173

Endpoints
---------
GET  /                       → serves `web/index.html`
POST /api/scan/file          → multipart upload, runs scan_skill on it
POST /api/scan/url           → JSON `{url: "..."}`, runs scan_skill on it
GET  /api/download/{scan_id} → patched .zip with `estes: ignore` markers
GET  /api/health             → liveness probe

Both scan endpoints return the same JSON shape (`scan_to_payload`). The
frontend renders findings dynamically from this payload.
"""
from __future__ import annotations

import base64
import io
import shutil
import sys
import tempfile
import time
import uuid
import zipfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

# Allow `import auditor` when running from anywhere.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, File, HTTPException, UploadFile  # noqa: E402
from fastapi.responses import FileResponse, Response  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from auditor import Finding, ScanReport, redact_text, scan_skill  # noqa: E402

WEB_DIR = Path(__file__).resolve().parent
INDEX = WEB_DIR / "index.html"

# ---------------------------------------------------------------------------
# Score weights — mirrors auditor._SEVERITY_WEIGHT / _CATEGORY_MULTIPLIER so
# the UI can show *why* each finding moved the gauge.
# ---------------------------------------------------------------------------

_SEV_WEIGHT = {"critical": 80, "high": 30, "warning": 10, "info": 2}
_CAT_MULT = {
    "wallet_secret": 2.0, "wallet_action": 1.5, "ssh_key": 1.5,
    "cloud_credential": 1.3, "db_credential": 1.2, "high_value_token": 1.2,
}


def _finding_weight(f: Finding) -> int:
    return int(round(_SEV_WEIGHT.get(f.severity, 0) * _CAT_MULT.get(f.category, 1.0)))


# ---------------------------------------------------------------------------
# In-memory scan store. Key = scan_id (uuid). Holds the materialized upload
# dir so the /api/download endpoint can rebuild a patched zip on demand.
# Entries TTL after 30 minutes.
# ---------------------------------------------------------------------------

_TTL_S = 30 * 60
_STORE: dict[str, dict[str, Any]] = {}


def _gc() -> None:
    now = time.time()
    expired = [sid for sid, ent in _STORE.items() if now - ent["created"] > _TTL_S]
    for sid in expired:
        ent = _STORE.pop(sid, None)
        if ent and ent.get("root"):
            shutil.rmtree(ent["root"], ignore_errors=True)


# ---------------------------------------------------------------------------
# Payload shaping
# ---------------------------------------------------------------------------


def scan_to_payload(scan_id: str, label: str, report: ScanReport,
                    can_download: bool) -> dict[str, Any]:
    """Turn a ScanReport into the JSON shape consumed by index.html."""

    counts = {
        "critical": sum(1 for f in report.findings if f.severity == "critical"),
        "high":     sum(1 for f in report.findings if f.severity == "high"),
        "warning":  sum(1 for f in report.findings if f.severity == "warning"),
        "info":     sum(1 for f in report.findings if f.severity == "info"),
    }

    return {
        "scan_id": scan_id,
        "label": label,
        "risk_score": report.risk_score,
        "severity": report.severity,
        "files_scanned": report.files_scanned,
        "bytes_scanned": report.bytes_scanned,
        "duration_ms": report.duration_ms,
        "warnings": list(report.warnings),
        "manifest": asdict(report.manifest),
        "counts": counts,
        "suggested_fix": report.suggested_fix,
        "can_download": can_download,
        "findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "source": f.source,
                "category": f.category,
                "file": f.file,
                "line": f.line,
                "message": f.message,
                "snippet": f.snippet,
                "suggested_fix": f.suggested_fix,
                "weight": _finding_weight(f),
            }
            for f in report.findings
        ],
    }


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="Estes Web Bridge", version="1.0.0")


class UrlRequest(BaseModel):
    url: str


class RedactRequest(BaseModel):
    text: str
    scan_id: str | None = None


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/wrapper/redact")
def wrapper_redact(req: RedactRequest) -> dict[str, Any]:
    """Run the runtime wrapper's redaction pipeline on raw text.

    This is the same `redact_text` powering `wrapper.py /redact`, exposed
    here so the dashboard can offer a live "Apply Wrapper" demo without
    requiring a second process.
    """
    text = req.text or ""
    redacted, count = redact_text(text)
    return {
        "input": text,
        "output": redacted,
        "redactions": count,
        "input_chars": len(text),
        "output_chars": len(redacted),
    }


@app.get("/api/wrapper/sample/{scan_id}")
def wrapper_sample(scan_id: str) -> dict[str, Any]:
    """Return a representative chunk of risky text from a prior scan, so
    the wrapper modal can prefill with the user's own findings instead of
    a synthetic sample.
    """
    _gc()
    ent = _STORE.get(scan_id)
    if not ent:
        raise HTTPException(404, "unknown or expired scan_id")
    report: ScanReport = ent["report"]

    sev_rank = {"critical": 0, "high": 1, "warning": 2, "info": 3}
    picks = sorted(
        (f for f in report.findings if f.snippet),
        key=lambda f: (sev_rank.get(f.severity, 4), -len(f.snippet or "")),
    )[:6]

    if not picks:
        return {"text": "", "from_scan": False}

    lines = []
    for f in picks:
        loc = f.file or "<input>"
        if f.line:
            loc += f":{f.line}"
        lines.append(f"# {loc}  ({f.severity})")
        lines.append(f.snippet.strip())
        lines.append("")
    return {"text": "\n".join(lines).rstrip() + "\n", "from_scan": True}


@app.get("/")
def index() -> FileResponse:
    if not INDEX.exists():
        raise HTTPException(404, "web/index.html missing")
    return FileResponse(INDEX, media_type="text/html")


@app.post("/api/scan/file")
async def scan_file(file: UploadFile = File(...)) -> dict[str, Any]:
    """Persist the upload, run scan_skill on it, return the payload."""
    _gc()
    if not file.filename:
        raise HTTPException(400, "missing filename")

    scan_id = uuid.uuid4().hex
    root = Path(tempfile.mkdtemp(prefix=f"estes_web_{scan_id}_"))
    target = root / file.filename
    target.write_bytes(await file.read())

    try:
        report = scan_skill(target, llm=False)
    except Exception as exc:  # noqa: BLE001
        shutil.rmtree(root, ignore_errors=True)
        raise HTTPException(500, f"scan failed: {exc.__class__.__name__}: {exc}")

    _STORE[scan_id] = {
        "report": report, "root": root, "label": file.filename, "created": time.time(),
    }
    payload = scan_to_payload(scan_id, file.filename, report, can_download=True)

    # Eagerly build the patched bundle and embed it as base64 in the
    # response. This makes the "Download Fixed" button work on stateless
    # deploys (Vercel) where /api/download/{scan_id} can hit a different
    # cold instance with no _STORE entry.
    try:
        zip_bytes = _build_patched_zip(report, root)
        payload["patched_zip_b64"] = base64.b64encode(zip_bytes).decode("ascii")
        payload["patched_zip_name"] = "skill_fixed.zip"
    except Exception:  # noqa: BLE001
        payload["patched_zip_b64"] = None

    return payload


@app.post("/api/scan/url")
def scan_url(req: UrlRequest) -> dict[str, Any]:
    """Run scan_skill on a public GitHub URL."""
    _gc()
    if not req.url.strip():
        raise HTTPException(400, "url is required")

    scan_id = uuid.uuid4().hex
    try:
        report = scan_skill(req.url.strip(), llm=False)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"scan failed: {exc.__class__.__name__}: {exc}")

    # GitHub scans don't keep a materialized tree (scan_skill cleans up its
    # own temp dir), so download is unavailable for those.
    _STORE[scan_id] = {
        "report": report, "root": None, "label": req.url, "created": time.time(),
    }
    return scan_to_payload(scan_id, req.url, report, can_download=False)


# ---------------------------------------------------------------------------
# Patch builder — applies real safety transformations, not just suppression.
# ---------------------------------------------------------------------------

# Categories that cannot be safely "redacted in place" (the dangerous thing
# is the *action itself*, not a literal secret string). For these we comment
# out the entire line.
_BLOCK_CATEGORIES = {
    "wallet_action",          # eth_sendRawTransaction, .sendSignedTransaction(...
    "network_call",           # off-allowlist outbound traffic
    "unsafe_subprocess",
}


def _comment_prefix(suffix: str) -> str:
    """Pick the right line-comment syntax for the file extension."""
    if suffix in {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".go",
                  ".java", ".c", ".cpp", ".h", ".rs", ".swift", ".kt"}:
        return "//"
    return "#"


def _statement_span(lines: list[str], start_idx: int) -> int:
    """Return the inclusive end index of the statement starting at start_idx,
    extending forward across multi-line constructs by counting bracket depth.

    Heuristic — not full lexer: ignores brackets inside strings if they're on
    the same line (we strip simple string literals before counting). Good
    enough for the realistic shape of skill source: function calls, dict
    literals, etc.
    """
    import re as _re
    _STRIP_STRINGS = _re.compile(
        r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    )
    depth = 0
    end_idx = start_idx
    for i in range(start_idx, len(lines)):
        stripped = _STRIP_STRINGS.sub("", lines[i])
        for ch in stripped:
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
        end_idx = i
        # Backslash-continuation also extends the statement.
        cont = lines[i].rstrip("\n").endswith("\\")
        if depth <= 0 and not cont:
            break
    return end_idx


def _patch_lines(
    lines: list[str],
    findings_by_line: dict[int, list[Finding]],
    suffix: str,
) -> tuple[list[str], list[tuple[int, list[str]]]]:
    """Walk the file once and apply per-line safety fixes.

    Returns the new line list and a [(line_no, [change_descriptions])] log.
    Block-strategy fixes consume contiguous statement spans (so multi-line
    `requests.get(\n  ...\n)` calls don't leave orphan lines).
    """
    cmt = _comment_prefix(suffix)
    out: list[str] = []
    log: list[tuple[int, list[str]]] = []

    consumed_until = -1   # inclusive index of the last block-consumed line
    i = 0
    while i < len(lines):
        ln = i + 1
        on_line = findings_by_line.get(ln, [])
        already_marked = "estes:" in lines[i]

        if i <= consumed_until or already_marked or not on_line:
            out.append(lines[i])
            i += 1
            continue

        block_fs = [
            f for f in on_line
            if f.source == "ast" or f.category in _BLOCK_CATEGORIES
        ]
        redact_fs = [f for f in on_line if f not in block_fs]

        if block_fs:
            end_idx = _statement_span(lines, i)
            indent_src = lines[i].rstrip("\n")
            indent = indent_src[: len(indent_src) - len(indent_src.lstrip())]
            ids = ",".join(sorted({f.id for f in block_fs}))
            cats = ",".join(sorted({f.category for f in block_fs}))
            out.append(
                f"{indent}{cmt} estes: blocked unsafe code [{ids}] "
                f"({cats}) — see ESTES_PATCH.md\n"
            )
            for k in range(i, end_idx + 1):
                raw = lines[k].rstrip("\n")
                # Preserve original indentation visually inside the comment.
                out.append(f"{indent}{cmt} {raw[len(indent):] if raw.startswith(indent) else raw.lstrip()}\n")
            log.append((ln, [f"blocked [{ids}] ({cats}) "
                              f"— commented {end_idx - i + 1} line(s)"]))
            consumed_until = end_idx
            i = end_idx + 1
            continue

        if redact_fs:
            raw = lines[i].rstrip("\n")
            redacted, n = redact_text(raw)
            ids = ",".join(sorted({f.id for f in redact_fs}))
            nl = "\n" if lines[i].endswith("\n") else ""
            if n > 0 and redacted != raw:
                tail = f"  {cmt} estes: secret literal redacted [{ids}] — rotate the original"
                out.append(redacted + tail + nl)
                log.append((ln, [f"redacted [{ids}]"]))
            else:
                tail = f"  {cmt} estes: review [{ids}]"
                out.append(raw + tail + nl)
                log.append((ln, [f"flagged [{ids}] — manual review"]))
            i += 1
            continue

        out.append(lines[i])
        i += 1

    return out, log


def _build_patch_sheet(report: ScanReport,
                       per_file: dict[str, list[tuple[int, list[str]]]]) -> str:
    out = [
        "# Estes — fixed bundle",
        "",
        f"- **Source:**   `{report.source}`",
        f"- **Severity:** {report.severity}  ·  **Score:** {report.risk_score}/100",
        f"- **Findings:** {len(report.findings)}",
        "",
        "## What was changed",
        "",
        "Estes applies safety transformations directly to the source so the "
        "downloaded bundle is materially safer than the input:",
        "",
        "| Strategy | When it fires | Effect |",
        "|---|---|---|",
        "| **Redact literal** | A regex pass found a secret string baked into source | The literal is replaced with `[REDACTED by Estes]` and a `# estes: secret literal redacted` marker is appended |",
        "| **Block call** | An AST taint flow, wallet broadcast, or off-allowlist network call was detected | The offending line is commented out with a `# estes: blocked unsafe code` marker; the original is preserved as a comment for review |",
        "| **Review** | A finding fired that the auto-patcher can't safely transform on its own | A `# estes: review` marker is appended so the line shows up in code review |",
        "",
        "## Per-file change log",
        "",
    ]
    if not per_file:
        out.append("_No transformations were applied (no actionable findings)._\n")
    else:
        for fname in sorted(per_file):
            out.append(f"### `{fname}`")
            for ln, entries in sorted(per_file[fname]):
                for entry in entries:
                    out.append(f"- line {ln}: {entry}")
            out.append("")
    out.extend([
        "## Important — what this bundle does NOT do",
        "",
        "1. **Rotate credentials for you.** Every secret that was redacted in source "
        "is still valid wherever it was originally provisioned (AWS, OpenAI, your "
        "wallet, etc.). Treat all redacted secrets as compromised and revoke them now.",
        "2. **Guarantee runtime safety.** Blocked calls remove a known leak path, but "
        "the surrounding logic may still need refactoring. Review every `estes: blocked` "
        "marker in this bundle before redistributing.",
        "3. **Replace human review.** This is a deterministic patch produced by rule "
        "matching. Treat it as a starting point, not a sign-off.",
        "",
    ])
    return "\n".join(out)


def _build_patched_zip(report: ScanReport, root: Path) -> bytes:
    """Materialize the in-place safety patch as a zip blob.

    Pure function → safe to call from both /api/scan/file (eager, embedded
    base64 in the payload for stateless deploys like Vercel) and from
    /api/download/{scan_id} (legacy stateful download).
    """
    by_file: dict[str, dict[int, list[Finding]]] = {}
    for f in report.findings:
        if f.file and f.line:
            by_file.setdefault(f.file, {}).setdefault(f.line, []).append(f)

    # Determine the source root (extracted .zip vs raw single file vs dir).
    zips = list(root.glob("*.zip"))
    if zips:
        src_root = root / "_extracted"
        if not src_root.exists():
            src_root.mkdir()
            with zipfile.ZipFile(zips[0]) as zf:
                zf.extractall(src_root)
    else:
        src_root = root

    change_log: dict[str, list[tuple[int, list[str]]]] = {}

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in src_root.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(src_root).as_posix()
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                zf.write(path, arcname=rel)
                continue

            findings_for_file = by_file.get(rel, {})
            if not findings_for_file:
                zf.writestr(rel, text)
                continue

            suffix = path.suffix.lower()
            lines = text.splitlines(keepends=True)
            new_lines, file_changes = _patch_lines(lines, findings_for_file, suffix)
            if file_changes:
                change_log[rel] = file_changes
            zf.writestr(rel, "".join(new_lines))

        zf.writestr("ESTES_PATCH.md", _build_patch_sheet(report, change_log))

    return buf.getvalue()


@app.get("/api/download/{scan_id}")
def download(scan_id: str) -> Response:
    """Legacy stateful download — works only when the scan store still
    holds the materialized upload tree (i.e. same process, within TTL).
    Stateless deploys (Vercel) should use the `patched_zip_b64` field
    that /api/scan/file embeds directly in the response."""
    _gc()
    ent = _STORE.get(scan_id)
    if not ent:
        raise HTTPException(404, "unknown or expired scan_id")
    report: ScanReport = ent["report"]
    root: Path | None = ent["root"]
    if root is None or not root.exists():
        raise HTTPException(409, "download not available for URL scans")

    payload = _build_patched_zip(report, root)
    return Response(
        content=payload,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="skill_fixed.zip"'},
    )
